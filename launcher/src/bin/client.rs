use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::time::timeout as tokio_timeout;
use tonic::transport::{Endpoint, Uri};
use tower::service_fn;
use tracing_subscriber::EnvFilter;

/// Launcher gRPC client CLI
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Unix socket path for launcher server
    #[arg(
        long,
        env = "LAUNCHER_SOCKET_PATH",
        default_value = "/tmp/launcher.sock"
    )]
    socket_path: String,

    /// RPC timeout in seconds for create/delete operations
    #[arg(
        long,
        env = "LAUNCHER_CLIENT_RPC_TIMEOUT_SECONDS",
        default_value = "300"
    )]
    timeout: u64,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Ping the launcher service
    Ping {
        /// Name to send in ping request
        name: String,
    },
    /// Create a new container
    Create {
        /// Container name
        name: String,
        /// Container image
        #[arg(long)]
        image: Option<String>,
        /// IP address to assign (optional)
        #[arg(long)]
        ip: Option<String>,
    },
    /// Delete an existing container
    Delete {
        /// Container name
        name: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for the CLI. RUST_LOG controls verbosity (e.g. RUST_LOG=info).
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Connect to server via Unix socket
    let socket_path = cli.socket_path.clone();
    let channel = Endpoint::try_from("http://[::]:50051")?
        .timeout(Duration::from_secs(cli.timeout))
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = socket_path.clone();
            async move { tokio::net::UnixStream::connect(path).await }
        }))
        .await?;
    let mut client = launcher::launcher_client::LauncherClient::new(channel);

    match cli.command {
        Commands::Ping { name } => {
            let req = launcher::PingRequest { name };
            let resp = client.ping(req).await?;
            let inner = resp.into_inner();
            println!(
                "ping response: ok={} message=\"{}\"",
                inner.ok, inner.message
            );
        }

        Commands::Create { name, image, ip } => {
            let req = launcher::CreateRequest {
                name,
                image: image.unwrap_or_default(),
                ip: ip.unwrap_or_default(),
            };
            // Create can take a while (image download, container startup). Use a longer
            // timeout and expose it via LAUNCHER_CLIENT_RPC_TIMEOUT_SECONDS.
            match tokio_timeout(Duration::from_secs(cli.timeout), client.create(req)).await {
                Ok(Ok(resp)) => {
                    let inner = resp.into_inner();
                    println!(
                        "create response: success={} message=\"{}\"",
                        inner.success, inner.message
                    );
                }
                Ok(Err(status)) => {
                    eprintln!("create RPC failed: {}", status);
                    std::process::exit(1);
                }
                Err(_) => {
                    eprintln!("create RPC timed out after {} seconds", cli.timeout);
                    std::process::exit(1);
                }
            }
        }
        Commands::Delete { name } => {
            let req = launcher::DeleteRequest { name };
            // Deleting may also block for a bit; reuse the same RPC timeout policy.
            match tokio_timeout(Duration::from_secs(cli.timeout), client.delete(req)).await {
                Ok(Ok(resp)) => {
                    let inner = resp.into_inner();
                    println!(
                        "delete response: success={} message=\"{}\"",
                        inner.success, inner.message
                    );
                }
                Ok(Err(status)) => {
                    eprintln!("delete RPC failed: {}", status);
                    std::process::exit(1);
                }
                Err(_) => {
                    eprintln!("delete RPC timed out after {} seconds", cli.timeout);
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}

// include generated proto module to reference types
pub(crate) mod launcher {
    tonic::include_proto!("launcher.v1alpha1");
}
