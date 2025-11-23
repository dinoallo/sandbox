use std::net::SocketAddr;

use tonic::transport::Server;
use tracing::info;

mod lxd;
mod netops;
mod service;

use lxd::{MockLxdClient, RealLxdClient};
use service::LauncherService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    tracing_subscriber::fmt::init();

    let addr: SocketAddr = "127.0.0.1:50051".parse()?;
    info!(%addr, "Starting launcher gRPC server");

    // choose between mock and real implementation via env var USE_REAL_LXD=1
    let use_real = std::env::var("USE_REAL_LXD")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    let lxd_client: Box<dyn lxd::LxdClient + Send + Sync> = if use_real {
        Box::new(RealLxdClient::new())
    } else {
        Box::new(MockLxdClient::new())
    };
    let svc = LauncherService::new(lxd_client);

    Server::builder()
        .add_service(launcher::launcher_server::LauncherServer::new(svc))
        .serve(addr)
        .await?;

    Ok(())
}

// Expose tonic-generated proto types
pub(crate) mod launcher {
    tonic::include_proto!("launcher.v1alpha1");
}
