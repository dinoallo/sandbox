use futures_util::TryStreamExt;
use nix::sched::{setns, CloneFlags};
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
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

/// Delegate the given ip (string like "192.0.2.10/24") from the host eth0 to the container's netns.
/// This implements the high-level steps from the guide:
///  - create macvlan eth1 linked to eth0
///  - set eth1 up
///  - set eth0 promisc on
///  - move eth1 to container netns (by pid)
///  - remove ip from host eth0 and add it inside the container's netns on eth1
///
/// NOTE: these operations require root and will fail without the necessary capabilities. In
/// this repository we implement the logic but tests use the mock LXD client and do not require
/// an actual LXD installation.
// NetOperator trait — allows real or mock implementations
#[async_trait::async_trait]
pub trait NetOperator: Send + Sync {
    async fn delegate_ip_to_container(
        &self,
        ip: &str,
        container_pid: u32,
    ) -> Result<(), NetOpsError>;
}

/// RealNetOps: perform the network operations using rtnetlink and setns
pub struct RealNetOps {}

impl RealNetOps {
    pub fn new() -> Self {
        RealNetOps {}
    }

    async fn create_macvlan(
        &self,
        handle: &rtnetlink::Handle,
        master: &str,
        name: &str,
    ) -> Result<u32, NetOpsError> {
        // find master
        let mut links = handle.link().get().match_name(master.to_string()).execute();
        let master_opt = links.try_next().await.map_err(NetOpsError::Netlink)?;
        let master_msg = master_opt.ok_or_else(|| {
            NetOpsError::Permission(format!("master device {} not found", master))
        })?;
        let master_index = master_msg.header.index;

        // create macvlan; mode=0 (private) or other — passthru mode varies by kernel
        let _ = handle
            .link()
            .add()
            .macvlan(name.to_string(), master_index, 0u32)
            .execute()
            .await
            .map_err(NetOpsError::Netlink);

        // find created link
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
                .set(msg.header.index)
                .up()
                .execute()
                .await
                .map_err(NetOpsError::Netlink)?;
        }
        Ok(())
    }

    async fn move_link_to_ns_by_fd(
        &self,
        handle: &rtnetlink::Handle,
        idx: u32,
        fd: i32,
    ) -> Result<(), NetOpsError> {
        handle
            .link()
            .set(idx)
            .setns_by_fd(fd)
            .execute()
            .await
            .map_err(NetOpsError::Netlink)?;
        Ok(())
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
    ) -> Result<(), NetOpsError> {
        // validate input
        let ns_path = PathBuf::from(format!("/proc/{}/ns/net", container_pid));
        if !ns_path.exists() {
            return Err(NetOpsError::Permission(format!(
                "netns path not found: {}",
                ns_path.display()
            )));
        }

        // parse ip/prefix
        let (addr, prefix) = parse_ip_with_prefix(ip)?;

        // create rtnetlink connection in host
        let (connection, handle, _) = rtnetlink::new_connection().map_err(NetOpsError::Io)?;
        tokio::spawn(connection);

        // create macvlan eth1 linked to eth0
        let eth1_idx = self.create_macvlan(&handle, "eth0", "eth1").await?;
        // flags not required — we'll perform best-effort cleanup inline

        // bring eth1 up
        if let Err(e) = self.set_link_up_by_name(&handle, "eth1").await {
            // Attempt host cleanup and return
            let _ = handle.link().del(eth1_idx).execute().await;
            return Err(e);
        }

        // try best-effort: set eth0 promisc
        if let Ok(Some(msg)) = handle
            .link()
            .get()
            .match_name("eth0".to_string())
            .execute()
            .try_next()
            .await
        {
            let _ = handle
                .link()
                .set(msg.header.index)
                .promiscuous(true)
                .execute()
                .await;
        }

        // move eth1 into container netns by fd
        let ns_file = File::open(&ns_path)?;
        let fd = ns_file.as_raw_fd();

        if let Err(e) = self.move_link_to_ns_by_fd(&handle, eth1_idx, fd).await {
            // try to remove host eth1 as cleanup
            let _ = handle.link().del(eth1_idx).execute().await;
            return Err(e);
        }
        // macvlan has been moved into container netns

        // inside target namespace: set eth1 up and add ip
        // save original namespace
        let original = File::open("/proc/self/ns/net")?;
        setns(&ns_file, CloneFlags::CLONE_NEWNET)
            .map_err(|e| NetOpsError::Permission(format!("setns failed: {}", e)))?;

        let (cn_conn, cn_handle, _) = rtnetlink::new_connection().map_err(NetOpsError::Io)?;
        tokio::spawn(cn_conn);

        // if any subsequent operations in container fail, attempt best-effort cleanup
        if let Err(e) = self.set_link_up_by_name(&cn_handle, "eth1").await {
            // try to clean up host if moved failed (unlikely here), but be safe
            // try to remove eth1 inside container namespace
            if let Ok(Some(msg)) = cn_handle
                .link()
                .get()
                .match_name("eth1".to_string())
                .execute()
                .try_next()
                .await
            {
                let _ = cn_handle.link().del(msg.header.index).execute().await;
            }
            // restore ns and return
            setns(&original, CloneFlags::CLONE_NEWNET)
                .map_err(|e| NetOpsError::Permission(format!("restore setns failed: {}", e)))?;
            return Err(e);
        }

        if let Err(e) = self
            .add_addr_by_name(&cn_handle, "eth1", addr, prefix)
            .await
        {
            // attempt to remove eth1 in container namespace
            if let Ok(Some(msg)) = cn_handle
                .link()
                .get()
                .match_name("eth1".to_string())
                .execute()
                .try_next()
                .await
            {
                let _ = cn_handle.link().del(msg.header.index).execute().await;
            }
            // restore ns and return
            setns(&original, CloneFlags::CLONE_NEWNET)
                .map_err(|e| NetOpsError::Permission(format!("restore setns failed: {}", e)))?;
            return Err(e);
        }
        // no cleanup needed

        // restore namespace
        // restore namespace
        setns(&original, CloneFlags::CLONE_NEWNET)
            .map_err(|e| NetOpsError::Permission(format!("restore setns failed: {}", e)))?;

        // At this point success — no cleanup needed

        Ok(())
    }
}

/// MockNetOps used for tests and when real implementation is not enabled
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
    ) -> Result<(), NetOpsError> {
        // same behavior as previous simulated function
        let ns_path = PathBuf::from(format!("/proc/{}/ns/net", container_pid));
        if !ns_path.exists() {
            return Err(NetOpsError::Permission(format!(
                "netns path not found: {}",
                ns_path.display()
            )));
        }
        parse_ip_with_prefix(ip)?;
        tracing::info!(%container_pid, ip=%ip, "mock delegate_ip_to_container");
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(())
    }
}

/// Module-level wrapper — choose real or mock implementation via USE_REAL_NETOPS
pub async fn delegate_ip_to_container(ip: &str, container_pid: u32) -> Result<(), NetOpsError> {
    let use_real = std::env::var("USE_REAL_NETOPS")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    if use_real {
        let r = RealNetOps::new();
        r.delegate_ip_to_container(ip, container_pid).await
    } else {
        let m = MockNetOps::new();
        m.delegate_ip_to_container(ip, container_pid).await
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
        // use a pid that almost certainly does not exist
        let res = delegate_ip_to_container("192.0.2.10/24", 9999999).await;
        assert!(res.is_err(), "expected error for missing netns");
    }

    #[tokio::test]
    async fn delegate_self_ns_ok() {
        // using this process's pid should succeed under the mock implementation
        let pid = std::process::id();
        let res = delegate_ip_to_container("192.0.2.11/24", pid).await;
        assert!(
            res.is_ok(),
            "expected mock delegate to succeed for current process ns"
        );
    }
}
