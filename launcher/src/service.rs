use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tonic::{Request, Response, Status};

use crate::launcher::{
    CreateRequest, CreateResponse, DeleteRequest, DeleteResponse, PingRequest, PingResponse,
};

use crate::lxd::LxdClient;
use crate::netops::delegate_ip_to_container;

pub struct LauncherService {
    client: Box<dyn LxdClient + Send + Sync>,
    // internal mutex for basic concurrency control in mock
    state: Arc<Mutex<()>>,
}

impl LauncherService {
    pub fn new(client: Box<dyn LxdClient + Send + Sync>) -> Self {
        Self {
            client,
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
        let name = req.name.clone();
        let image = if req.image.is_empty() {
            "alpine/3.19".to_string()
        } else {
            req.image.clone()
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
            .wait_for_pid(&name, Duration::from_secs(10))
            .await
            .map_err(|e| Status::internal(format!("wait for pid failed: {}", e)))?;

        // perform network ops if IP provided
        if !req.ip.is_empty() {
            match delegate_ip_to_container(&req.ip, pid, "veth0", "eth1").await {
                Ok(_) => {
                    tracing::info!(container=%name, pid=%pid, ip=%req.ip, "delegated ip to container");
                }
                Err(e) => {
                    return Err(Status::internal(format!("network setup failed: {}", e)));
                }
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
        let svc = LauncherService::new(Box::new(MockLxdClient::new()));

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
        let svc = LauncherService::new(Box::new(MockLxdClient::new()));

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
