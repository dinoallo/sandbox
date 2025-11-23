use std::env;
use std::time::Duration;

use tonic::transport::Channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: client <create|delete> <name> [--image <image>] [--ip <ip>] [--addr <host:port>]");
        std::process::exit(2);
    }

    let cmd = args[1].as_str();
    let name = args[2].clone();
    let mut image = String::new();
    let mut ip = String::new();
    let mut addr = "http://127.0.0.1:50051".to_string();

    let mut idx = 3;
    while idx < args.len() {
        match args[idx].as_str() {
            "--image" => {
                if idx + 1 < args.len() { image = args[idx + 1].clone(); idx += 2; }
                else { eprintln!("--image requires a value"); std::process::exit(2); }
            }
            "--ip" => {
                if idx + 1 < args.len() { ip = args[idx + 1].clone(); idx += 2; }
                else { eprintln!("--ip requires a value"); std::process::exit(2); }
            }
            "--addr" => {
                if idx + 1 < args.len() { addr = args[idx + 1].clone(); idx += 2; }
                else { eprintln!("--addr requires a value"); std::process::exit(2); }
            }
            other => {
                eprintln!("Unknown flag: {}", other);
                std::process::exit(2);
            }
        }
    }

    // Connect to server
    let channel = Channel::from_shared(addr)?.timeout(Duration::from_secs(5)).connect().await?;
    let mut client = launcher::launcher_client::LauncherClient::new(channel);

    match cmd {
        "ping" => {
            let req = launcher::PingRequest { name: name.clone() };
            let resp = client.ping(req).await?;
            let inner = resp.into_inner();
            println!("ping response: ok={} message=\"{}\"", inner.ok, inner.message);
        }
        
        "create" => {
            let req = launcher::CreateRequest { name: name.clone(), image: image.clone(), ip: ip.clone() };
            let resp = client.create(req).await?;
            let inner = resp.into_inner();
            println!("create response: success={} message=\"{}\"", inner.success, inner.message);
        }
        "delete" => {
            let req = launcher::DeleteRequest { name: name.clone() };
            let resp = client.delete(req).await?;
            let inner = resp.into_inner();
            println!("delete response: success={} message=\"{}\"", inner.success, inner.message);
        }
        _ => {
            eprintln!("Unknown command: {}", cmd);
            std::process::exit(2);
        }
    }

    Ok(())
}

// include generated proto module to reference types
pub(crate) mod launcher {
    tonic::include_proto!("launcher.v1alpha1");
}
