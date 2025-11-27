use futures_util::TryStreamExt;
use nix::sched::{setns, CloneFlags};
use rtnetlink::{packet_route::link::MacVlanMode, LinkMacVlan, LinkUnspec};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NetOpsError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("netlink error: {0}")]
    Netlink(#[from] rtnetlink::Error),
    #[error("permission denied or operation unsupported: {0}")]
    Permission(String),
}

// RAII guard for automatic link cleanup on failure
struct LinkGuard {
    handle: rtnetlink::Handle,
    index: Option<u32>,
}

impl LinkGuard {
    fn new(handle: rtnetlink::Handle, index: u32) -> Self {
        Self {
            handle,
            index: Some(index),
        }
    }

    // Call on success to prevent cleanup
    fn disarm(mut self) {
        self.index = None;
    }
}

impl Drop for LinkGuard {
    fn drop(&mut self) {
        if let Some(index) = self.index {
            let handle = self.handle.clone();
            // Spawn cleanup task (best effort, don't block)
            tokio::spawn(async move {
                if let Err(e) = handle.link().del(index).execute().await {
                    tracing::warn!("failed to cleanup link {}: {}", index, e);
                }
            });
        }
    }
}

// Guard for restoring network namespace
struct NetnsGuard {
    original_fd: File,
}

impl NetnsGuard {
    fn new(original_fd: File) -> Self {
        Self { original_fd }
    }
}

impl Drop for NetnsGuard {
    fn drop(&mut self) {
        if let Err(e) = setns(&self.original_fd, CloneFlags::CLONE_NEWNET) {
            tracing::error!("failed to restore network namespace: {}", e);
        }
    }
}

#[async_trait::async_trait]
pub trait NetOperator: Send + Sync {
    async fn delegate_ip_to_container(
        &self,
        ip: &str,
        container_pid: u32,
        parent_if: &str,
        child_if: &str,
        host_proc_path: &Path,
    ) -> Result<(), NetOpsError>;
}

pub struct RealNetOps {}

impl RealNetOps {
    pub fn new() -> Self {
        RealNetOps {}
    }

    async fn create_macvlan(
        &self,
        handle: &rtnetlink::Handle,
        parent: &str,
        name: &str,
    ) -> Result<u32, NetOpsError> {
        let mut parent_links = handle.link().get().match_name(parent.to_string()).execute();
        if let Some(parent) = parent_links.try_next().await? {
            let parent_index = parent.header.index;
            let builder = LinkMacVlan::new(name, parent_index, MacVlanMode::Passthrough);
            let link_msg = builder.build();

            handle
                .link()
                .add(link_msg)
                .execute()
                .await
                .map_err(NetOpsError::Netlink)?;
        } else {
            return Err(NetOpsError::Permission(format!(
                "parent interface {} not found",
                parent
            )));
        }
        // Check if the macvlan interface was created successfully
        let mut new_links = handle.link().get().match_name(name.to_string()).execute();
        if let Some(msg) = new_links.try_next().await.map_err(NetOpsError::Netlink)? {
            return Ok(msg.header.index);
        }
        Err(NetOpsError::Permission(format!(
            "failed to create macvlan {}",
            name
        )))
    }

    async fn set_link_up_by_name(
        &self,
        handle: &rtnetlink::Handle,
        name: &str,
    ) -> Result<(), NetOpsError> {
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        if let Some(msg) = links.try_next().await.map_err(NetOpsError::Netlink)? {
            handle
                .link()
                .set(LinkUnspec::new_with_index(msg.header.index).up().build())
                .execute()
                .await
                .map_err(NetOpsError::Netlink)?;
        } else {
            return Err(NetOpsError::Permission(format!(
                "interface {} not found",
                name
            )));
        }
        Ok(())
    }

    async fn move_link_to_ns_by_fd(
        &self,
        handle: &rtnetlink::Handle,
        name: &str,
        fd: i32,
    ) -> Result<(), NetOpsError> {
        let mut links = handle.link().get().match_name(name.to_string()).execute();
        if let Some(msg) = links.try_next().await.map_err(NetOpsError::Netlink)? {
            handle
                .link()
                .set(
                    LinkUnspec::new_with_index(msg.header.index)
                        .setns_by_fd(fd)
                        .build(),
                )
                .execute()
                .await
                .map_err(NetOpsError::Netlink)?;
            return Ok(());
        }
        Err(NetOpsError::Permission(format!("link {} not found", name)))
    }

    async fn add_addr_by_name(
        &self,
        handle: &rtnetlink::Handle,
        ifname: &str,
        addr: std::net::IpAddr,
        prefix: u8,
    ) -> Result<(), NetOpsError> {
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
        if let Some(msg) = links.try_next().await.map_err(NetOpsError::Netlink)? {
            handle
                .address()
                .add(msg.header.index, addr, prefix)
                .execute()
                .await
                .map_err(NetOpsError::Netlink)?;
        } else {
            return Err(NetOpsError::Permission(format!(
                "interface {} not found",
                ifname
            )));
        }
        Ok(())
    }

    async fn set_prosmisc_by_name(
        &self,
        handle: &rtnetlink::Handle,
        ifname: &str,
    ) -> Result<(), NetOpsError> {
        let mut links = handle.link().get().match_name(ifname.to_string()).execute();
        if let Some(msg) = links.try_next().await.map_err(NetOpsError::Netlink)? {
            handle
                .link()
                .set(
                    LinkUnspec::new_with_index(msg.header.index)
                        .promiscuous(true)
                        .build(),
                )
                .execute()
                .await
                .map_err(NetOpsError::Netlink)?;
        } else {
            return Err(NetOpsError::Permission(format!(
                "interface {} not found",
                ifname
            )));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl NetOperator for RealNetOps {
    async fn delegate_ip_to_container(
        &self,
        ip: &str,
        container_pid: u32,
        parent_if: &str,
        child_if: &str,
        host_proc_path: &Path,
    ) -> Result<(), NetOpsError> {
        let ns_path = host_proc_path.join(format!("{}/ns/net", container_pid));
        if !ns_path.exists() {
            return Err(NetOpsError::Permission(format!(
                "netns path not found: {}",
                ns_path.display()
            )));
        }
        if !ns_path.exists() {
            return Err(NetOpsError::Permission(format!(
                "netns path not found: {}",
                ns_path.display()
            )));
        }

        let (addr, prefix) = parse_ip_with_prefix(ip)?;

        let (connection, handle, _) = rtnetlink::new_connection().map_err(NetOpsError::Io)?;
        tokio::spawn(connection);

        tracing::debug!(
            ip=%ip,
            container_pid=%container_pid,
            parent_if=%parent_if,
            child_if=%child_if,
            "delegating ip to container"
        );
        // Create macvlan with automatic cleanup on failure
        let eth1_idx = self.create_macvlan(&handle, parent_if, child_if).await?;
        let eth1_guard = LinkGuard::new(handle.clone(), eth1_idx);

        // All operations from here will auto-cleanup eth1 on failure
        self.set_link_up_by_name(&handle, child_if).await?;

        tracing::debug!(
            ip=%ip,
            container_pid=%container_pid,
            parent_if=%parent_if,
            child_if=%child_if,
            "set {} up", child_if
        );

        if let Err(e) = self.set_prosmisc_by_name(&handle, parent_if).await {
            tracing::warn!(
                "failed to set {} promisc mode, continuing: {}",
                parent_if,
                e
            );
        }

        tracing::debug!(
            ip=%ip,
            container_pid=%container_pid,
            parent_if=%parent_if,
            child_if=%child_if,
            "set {} promisc mode", parent_if
        );

        let ns_file = File::open(&ns_path)?;
        let fd = ns_file.as_raw_fd();

        self.move_link_to_ns_by_fd(&handle, child_if, fd).await?;

        tracing::debug!(
            ip=%ip,
            container_pid=%container_pid,
            parent_if=%parent_if,
            child_if=%child_if,
            "moved {} to container namespace", child_if
        );

        // Link moved to container namespace - disarm host cleanup
        eth1_guard.disarm();

        // Enter container namespace with automatic restore on drop
        tracing::debug!(
            ip=%ip,
            container_pid=%container_pid,
            parent_if=%parent_if,
            child_if=%child_if,
            "entering container network namespace"
        );
        let original = File::open("/proc/self/ns/net")?;
        let _netns_guard = NetnsGuard::new(original);

        setns(&ns_file, CloneFlags::CLONE_NEWNET)
            .map_err(|e| NetOpsError::Permission(format!("setns failed: {}", e)))?;

        let (cn_conn, cn_handle, _) = rtnetlink::new_connection().map_err(NetOpsError::Io)?;
        tokio::spawn(cn_conn);

        tracing::debug!(
            ip=%ip,
            container_pid=%container_pid,
            parent_if=%parent_if,
            child_if=%child_if,
            "creating cleanup guard for link in container namespace"
        );
        let container_eth1_guard = LinkGuard::new(cn_handle.clone(), eth1_idx);

        self.set_link_up_by_name(&cn_handle, child_if).await?;
        self.add_addr_by_name(&cn_handle, child_if, addr, prefix)
            .await?;

        tracing::debug!(
            ip=%ip,
            container_pid=%container_pid,
            parent_if=%parent_if,
            child_if=%child_if,
            "assigned ip {} to {}", ip, child_if
        );

        // Success! Disarm container cleanup
        container_eth1_guard.disarm();

        tracing::debug!(
            ip=%ip,
            container_pid=%container_pid,
            parent_if=%parent_if,
            child_if=%child_if,
            "successfully delegated ip to container"
        );

        // Namespace will be automatically restored by NetnsGuard::drop
        Ok(())
    }
}

pub struct MockNetOps {}

impl MockNetOps {
    pub fn new() -> Self {
        MockNetOps {}
    }
}

#[async_trait::async_trait]
impl NetOperator for MockNetOps {
    async fn delegate_ip_to_container(
        &self,
        ip: &str,
        container_pid: u32,
        parent_if: &str,
        child_if: &str,
        host_proc_path: &Path,
    ) -> Result<(), NetOpsError> {
        let ns_path = host_proc_path.join(format!("{}/ns/net", container_pid));
        if !ns_path.exists() {
            return Err(NetOpsError::Permission(format!(
                "netns path not found: {}",
                ns_path.display()
            )));
        }
        parse_ip_with_prefix(ip)?;
        tracing::info!(%container_pid, ip=%ip, parent_if=%parent_if, child_if=%child_if, "mock delegate_ip_to_container");
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(())
    }
}

pub async fn delegate_ip_to_container(
    ip: &str,
    container_pid: u32,
    parent_if: &str,
    child_if: &str,
    host_proc_path: &Path,
) -> Result<(), NetOpsError> {
    let use_real = std::env::var("USE_REAL_NETOPS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    if use_real {
        let r = RealNetOps::new();
        r.delegate_ip_to_container(ip, container_pid, parent_if, child_if, host_proc_path)
            .await
    } else {
        let m = MockNetOps::new();
        m.delegate_ip_to_container(ip, container_pid, parent_if, child_if, host_proc_path)
            .await
    }
}

fn parse_ip_with_prefix(s: &str) -> Result<(std::net::IpAddr, u8), NetOpsError> {
    if let Some(pos) = s.find('/') {
        let (addr_str, pref_str) = s.split_at(pos);
        let pref = pref_str
            .trim_start_matches('/')
            .parse::<u8>()
            .map_err(|e| NetOpsError::Permission(format!("invalid prefix: {}", e)))?;
        let addr = addr_str
            .parse::<std::net::IpAddr>()
            .map_err(|e| NetOpsError::Permission(format!("invalid ip: {}", e)))?;
        Ok((addr, pref))
    } else {
        Err(NetOpsError::Permission(
            "ip must be in form x.x.x.x/prefix".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_ip_ok() {
        let (addr, prefix) = parse_ip_with_prefix("192.0.2.5/24").unwrap();
        assert_eq!(prefix, 24);
        assert_eq!(addr.to_string(), "192.0.2.5");
    }

    #[tokio::test]
    async fn delegate_missing_ns_err() {
        let res = delegate_ip_to_container(
            "192.0.2.10/24",
            9999999,
            "parent0",
            "child0",
            Path::new("/proc"),
        )
        .await;
        assert!(res.is_err(), "expected error for missing netns");
    }

    #[tokio::test]
    async fn delegate_self_ns_ok() {
        let pid = std::process::id();
        let res = delegate_ip_to_container(
            "192.0.2.11/24",
            pid,
            "parent0",
            "child0",
            Path::new("/proc"),
        )
        .await;
        assert!(
            res.is_ok(),
            "expected mock delegate to succeed for current process ns"
        );
    }
}
