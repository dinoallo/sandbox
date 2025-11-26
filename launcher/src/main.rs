use std::path::PathBuf;

use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server;
use tracing::info;

mod lxd;
mod netops;
mod service;

use lxd::{MockLxdClient, RealLxdClient};
use service::LauncherService;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let socket_path =
        std::env::var("LAUNCHER_SOCKET_PATH").unwrap_or_else(|_| "/tmp/launcher.sock".to_string());
    let path = PathBuf::from(&socket_path);

    // Remove existing socket file if it exists
    if path.exists() {
        std::fs::remove_file(&path)?;
    }

    info!(socket_path = %socket_path, "Starting launcher gRPC server on Unix socket");

    // choose between mock and real implementation via env var USE_REAL_LXD=1
    let use_real = std::env::var("USE_REAL_LXD")
        .map(|v| v == "1" || v.to_lowercase() == "true")
        .unwrap_or(false);
    let lxd_client: Box<dyn lxd::LxdClient + Send + Sync> = if use_real {
        Box::new(RealLxdClient::new())
    } else {
        Box::new(MockLxdClient::new())
    };
    // If we're using a real LXD client, verify we can reach the daemon before serving.
    if use_real {
        // allow configuring timeout and attempts via environment for CI/developer convenience
        let timeout_sec: u64 = std::env::var("LXD_CONNECT_TIMEOUT_SECONDS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(5);
        let attempts: u32 = std::env::var("LXD_CONNECT_ATTEMPTS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(3);

        match lxd_client
            .check_connection(std::time::Duration::from_secs(timeout_sec), attempts)
            .await
        {
            Ok(()) => info!("connected to LXD API successfully"),
            Err(e) => {
                eprintln!(
                    "Failed to contact LXD API after {} attempts: {}",
                    attempts, e
                );
                std::process::exit(1);
            }
        }
    }

    let svc = LauncherService::new(lxd_client);

    let uds = UnixListener::bind(&path)?;
    let uds_stream = UnixListenerStream::new(uds);

    Server::builder()
        .add_service(launcher::launcher_server::LauncherServer::new(svc))
        .serve_with_incoming(uds_stream)
        .await?;

    Ok(())
}

// Expose tonic-generated proto types
pub(crate) mod launcher {
    tonic::include_proto!("launcher.v1alpha1");
}
