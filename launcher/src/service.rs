use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::launcher::{
    CreateRequest, CreateResponse, DeleteRequest, DeleteResponse, PingRequest, PingResponse,
};

use crate::lxd::LxdClient;
use crate::netops::delegate_ip_to_container;

const DEFAULT_IMAGE: &str = "alpine/3.19";
const DEFAULT_IP: &str = "172.16.0.1/24";
const TIMEOUT: Duration = Duration::from_secs(10);
const PARENT_IF: &str = "veth0";
const CHILD_IF: &str = "eth1";

pub struct LauncherService {
    pub client: Box<dyn LxdClient + Send + Sync>,
    config: LauncherConfig,
    // internal mutex for basic concurrency control in mock
    state: Arc<Mutex<()>>,
}

#[derive(Clone)]
pub struct LauncherConfig {
    pub default_image: Option<String>,
    pub default_ip: Option<String>,
    pub timeout: Option<Duration>,
    pub macvlan_parent_if: Option<String>,
    pub macvlan_child_if: Option<String>,
}

impl LauncherService {
    pub fn new(client: Box<dyn LxdClient + Send + Sync>, config: LauncherConfig) -> Self {
        Self {
            client,
            config,
            state: Default::default(),
        }
    }
}

#[tonic::async_trait]
impl crate::launcher::launcher_server::Launcher for LauncherService {
    async fn create(
        &self,
        req: Request<CreateRequest>,
    ) -> Result<Response<CreateResponse>, Status> {
        let req = req.into_inner();
        let name = if req.name.is_empty() {
            // Generate a random name, for example using a UUID or any other method
            uuid::Uuid::new_v4().to_string()
        } else {
            req.name.clone()
        };
        let image = if req.image.is_empty() {
            self.config
                .default_image
                .clone()
                .unwrap_or_else(|| DEFAULT_IMAGE.to_string())
        } else {
            req.image.clone()
        };
        let ip = if req.ip.is_empty() {
            self.config
                .default_ip
                .clone()
                .unwrap_or_else(|| DEFAULT_IP.to_string())
        } else {
            req.ip.clone()
        };
        // Basic serialized handling so the mock doesn't race
        let _guard = self.state.lock().await;

        self.client
            .create_container(&name, &image)
            .await
            .map_err(|e| Status::internal(format!("create failed: {}", e)))?;

        // Start the container
        self.client
            .start_container(&name)
            .await
            .map_err(|e| Status::internal(format!("start failed: {}", e)))?;

        // Wait for container to be running and get main pid
        let pid = self
            .client
            .wait_for_pid(&name, self.config.timeout.unwrap_or(TIMEOUT))
            .await
            .map_err(|e| Status::internal(format!("wait for pid failed: {}", e)))?;

        // perform network ops
        // TODO: check if ip matches the ip of parent interface to avoid macvlan issues
        let parent_if = self
            .config
            .macvlan_parent_if
            .as_deref()
            .unwrap_or(PARENT_IF);
        let child_if = self.config.macvlan_child_if.as_deref().unwrap_or(CHILD_IF);
        match delegate_ip_to_container(&ip, pid, parent_if, child_if).await {
            Ok(_) => {
                tracing::info!(container=%name, pid=%pid, ip=%ip, "delegated ip to container");
            }
            Err(e) => {
                return Err(Status::internal(format!("network setup failed: {}", e)));
            }
        }

        Ok(Response::new(CreateResponse {
            success: true,
            message: format!("container {} created", name),
        }))
    }

    async fn delete(
        &self,
        req: Request<DeleteRequest>,
    ) -> Result<Response<DeleteResponse>, Status> {
        let req = req.into_inner();
        let name = req.name;

        let _guard = self.state.lock().await;

        // Stop the container first
        self.client
            .stop_container(&name)
            .await
            .map_err(|e| Status::internal(format!("stop failed: {}", e)))?;

        self.client
            .delete_container(&name)
            .await
            .map_err(|e| Status::internal(format!("delete failed: {}", e)))?;

        // Wait for shutdown
        self.client
            .wait_for_shutdown(&name, Duration::from_secs(10))
            .await
            .map_err(|e| Status::internal(format!("wait shutdown failed: {}", e)))?;

        Ok(Response::new(DeleteResponse {
            success: true,
            message: format!("container {} deleted", name),
        }))
    }

    async fn ping(&self, req: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        let _ = req.into_inner();
        // simple health-check; the mock launcher is always responsive
        Ok(Response::new(PingResponse {
            ok: true,
            message: "pong".to_string(),
        }))
    }
}

impl Clone for LauncherService {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone_box(),
            state: self.state.clone(),
            config: self.config.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::launcher::launcher_server::Launcher as LauncherTrait;
    use crate::lxd::MockLxdClient;
    use tonic::Request;

    #[tokio::test]
    async fn create_without_ip_succeeds() {
        let config = LauncherConfig {
            default_image: Some("alpine/3.19".to_string()),
            default_ip: None,
            timeout: None,
            macvlan_parent_if: None,
            macvlan_child_if: None,
        };
        let svc = LauncherService::new(Box::new(MockLxdClient::new()), config);

        let req = Request::new(CreateRequest {
            name: "mytest".to_string(),
            image: "".to_string(),
            ip: "".to_string(),
        });
        // trait needs to be in scope so we can call the async fn on the impl
        let resp = LauncherTrait::create(&svc, req)
            .await
            .expect("create failed");
        let inner = resp.into_inner();
        assert!(inner.success, "expected create success");
    }

    #[tokio::test]
    async fn delete_succeeds() {
        let config = LauncherConfig {
            default_image: Some("alpine/3.19".to_string()),
            default_ip: None,
            timeout: None,
            macvlan_parent_if: None,
            macvlan_child_if: None,
        };
        let svc = LauncherService::new(Box::new(MockLxdClient::new()), config);

        let req = Request::new(DeleteRequest {
            name: "mytest".to_string(),
        });
        let resp = LauncherTrait::delete(&svc, req)
            .await
            .expect("delete failed");
        let inner = resp.into_inner();
        assert!(inner.success, "expected delete success");
    }
}
