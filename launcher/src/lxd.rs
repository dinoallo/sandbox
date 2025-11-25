use std::time::Duration;

use async_trait::async_trait;
use hyper::body::to_bytes;
use hyper::{Body, Client, Request};
use hyperlocal::{UnixClientExt, Uri};
use serde_json::{json, Value};
use std::env;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum LxdError {
    // #[error("container not found")]
    // NotFound,
    #[error("operation failed: {0}")]
    Other(String),
}

/// Minimal trait capturing the operations we need from LXD.
#[async_trait]
pub trait LxdClient: Send + Sync {
    async fn create_container(&self, name: &str, image: &str) -> Result<(), LxdError>;
    async fn wait_for_pid(&self, name: &str, timeout: Duration) -> Result<u32, LxdError>;
    /// Check connectivity to LXD; used to fail fast when configured to use a real client
    /// Implementations should attempt the connection within `timeout` duration and may
    /// retry multiple times before reporting an error.
    async fn check_connection(&self, timeout: Duration, attempts: u32) -> Result<(), LxdError>;
    async fn delete_container(&self, name: &str) -> Result<(), LxdError>;
    async fn wait_for_shutdown(&self, name: &str, timeout: Duration) -> Result<(), LxdError>;

    /// Return a boxed clone (so the service can be cloned cheaply)
    fn clone_box(&self) -> Box<dyn LxdClient + Send + Sync>;
}

#[derive(Default)]
pub struct MockLxdClient {}

impl MockLxdClient {
    pub fn new() -> Self {
        MockLxdClient {}
    }
}

/// RealLxdClient implements LxdClient by invoking the `lxc` command-line tool and
/// parsing its JSON output. This is a pragmatic implementation for developer
/// environments where LXD is already installed and the `lxc` CLI is available.
pub struct RealLxdClient {
    socket_path: String,
    client: Client<hyperlocal::UnixConnector, Body>,
}

impl RealLxdClient {
    pub fn new() -> Self {
        // determine socket path from environment or default locations
        let defaults = [
            "/var/snap/lxd/common/lxd/unix.socket",
            "/var/lib/lxd/unix.socket",
            "/var/snap/lxd/common/lxd/unix.socket",
        ];

        let socket = env::var("LXD_SOCKET_PATH")
            .ok()
            .or_else(|| {
                for p in defaults.iter() {
                    if std::path::Path::new(p).exists() {
                        return Some(p.to_string());
                    }
                }
                None
            })
            .unwrap_or_else(|| defaults[0].to_string());

        let client = Client::unix();
        RealLxdClient {
            socket_path: socket,
            client,
        }
    }

    async fn get_json(&self, path: &str) -> Result<Value, LxdError> {
        let uri: hyper::Uri = Uri::new(&self.socket_path, path).into();
        let resp = self
            .client
            .get(uri)
            .await
            .map_err(|e| LxdError::Other(format!("request failed: {}", e)))?;
        if !resp.status().is_success() {
            return Err(LxdError::Other(format!(
                "status {} for {}",
                resp.status(),
                path
            )));
        }
        let body = to_bytes(resp.into_body())
            .await
            .map_err(|e| LxdError::Other(format!("read body failed: {}", e)))?;
        let v = serde_json::from_slice::<Value>(&body)
            .map_err(|e| LxdError::Other(format!("invalid json: {}", e)))?;
        Ok(v)
    }

    async fn post_json(&self, path: &str, body: Value) -> Result<Value, LxdError> {
        let uri: hyper::Uri = Uri::new(&self.socket_path, path).into();
        let body_str = serde_json::to_string(&body)
            .map_err(|e| LxdError::Other(format!("serialize failed: {}", e)))?;
        let req = Request::post(uri)
            .header("content-type", "application/json")
            .body(Body::from(body_str))
            .map_err(|e| LxdError::Other(format!("build request failed: {}", e)))?;

        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| LxdError::Other(format!("request failed: {}", e)))?;
        if !resp.status().is_success() {
            return Err(LxdError::Other(format!(
                "status {} for {}",
                resp.status(),
                path
            )));
        }
        let body = to_bytes(resp.into_body())
            .await
            .map_err(|e| LxdError::Other(format!("read body failed: {}", e)))?;
        let v = serde_json::from_slice::<Value>(&body)
            .map_err(|e| LxdError::Other(format!("invalid json: {}", e)))?;
        Ok(v)
    }

    // Attempt to discover an operation path from an arbitrary JSON body. Many LXD
    // responses include either top-level `operation` strings or nested references
    // inside metadata; we search recursively for the first string containing
    // "/1.0/operations/" and return it.
    fn find_operation_path_in_value(v: &Value) -> Option<String> {
        fn extract_from_str(s: &str) -> Option<String> {
            if let Some(idx) = s.find("/1.0/operations/") {
                let tail = &s[idx..];
                // stop at delimiters commonly found in responses
                let mut end = tail.len();
                for (i, ch) in tail.char_indices() {
                    if ch == ' '
                        || ch == '"'
                        || ch == '\''
                        || ch == ','
                        || ch == ')'
                        || ch == ']'
                        || ch == '}'
                        || ch == '\n'
                    {
                        end = i;
                        break;
                    }
                }
                return Some(tail[..end].to_string());
            }
            None
        }

        match v {
            Value::String(s) => extract_from_str(s),
            Value::Object(map) => {
                for (_k, v) in map.iter() {
                    if let Some(found) = RealLxdClient::find_operation_path_in_value(v) {
                        return Some(found);
                    }
                }
                None
            }
            Value::Array(arr) => {
                for item in arr.iter() {
                    if let Some(found) = RealLxdClient::find_operation_path_in_value(item) {
                        return Some(found);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Wait for the operation referenced by `op_path` to complete.
    /// `op_path` can be either a full URL or a path beginning with `/1.0/operations/`.
    async fn wait_for_operation(&self, op_path: &str, timeout: Duration) -> Result<(), LxdError> {
        // normalize to a path starting at /1.0/operations/
        let op = if op_path.starts_with("/1.0/operations/") {
            op_path.to_string()
        } else if let Some(idx) = op_path.find("/1.0/operations/") {
            op_path[idx..].to_string()
        } else {
            op_path.to_string()
        };

        let wait_path = format!("{}/wait?timeout={}s", op, timeout.as_secs());

        tracing::debug!(operation=%op, wait=%wait_path, "waiting for operation completion");

        let resp = self.get_json(&wait_path).await?;

        // If the metadata contains a status_code use it to detect failure
        if let Some(code) = resp
            .pointer("/metadata/status_code")
            .and_then(|v| v.as_i64())
        {
            if (200..300).contains(&code) {
                return Ok(());
            } else {
                let msg = resp
                    .pointer("/metadata/err")
                    .and_then(|v| v.as_str())
                    .unwrap_or("operation failed");
                return Err(LxdError::Other(format!(
                    "operation failed status_code={} err={}",
                    code, msg
                )));
            }
        }

        // fallback: if HTTP succeeded, consider operation successful
        Ok(())
    }

    async fn delete_path(&self, path: &str) -> Result<Value, LxdError> {
        let uri: hyper::Uri = Uri::new(&self.socket_path, path).into();
        let req = Request::delete(uri)
            .body(Body::empty())
            .map_err(|e| LxdError::Other(format!("build delete req failed: {}", e)))?;
        let resp = self
            .client
            .request(req)
            .await
            .map_err(|e| LxdError::Other(format!("request failed: {}", e)))?;
        if !resp.status().is_success() {
            return Err(LxdError::Other(format!(
                "status {} for {}",
                resp.status(),
                path
            )));
        }
        let body = to_bytes(resp.into_body())
            .await
            .map_err(|e| LxdError::Other(format!("read body failed: {}", e)))?;
        let v = serde_json::from_slice::<Value>(&body)
            .map_err(|e| LxdError::Other(format!("invalid json: {}", e)))?;
        Ok(v)
    }
}

#[async_trait]
impl LxdClient for MockLxdClient {
    async fn create_container(&self, name: &str, _image: &str) -> Result<(), LxdError> {
        tracing::info!(container=%name, "mock create container");
        // pretend we create the container and it starts
        Ok(())
    }

    async fn wait_for_pid(&self, name: &str, _timeout: Duration) -> Result<u32, LxdError> {
        tracing::info!(container=%name, "mock wait for pid");
        // simulate short asynchronous startup and return a fake pid
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(12345)
    }

    async fn delete_container(&self, name: &str) -> Result<(), LxdError> {
        tracing::info!(container=%name, "mock delete container");
        Ok(())
    }

    async fn wait_for_shutdown(&self, name: &str, _timeout: Duration) -> Result<(), LxdError> {
        tracing::info!(container=%name, "mock wait for shutdown");
        // simulate short asynchronous shutdown
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    fn clone_box(&self) -> Box<dyn LxdClient + Send + Sync> {
        Box::new(MockLxdClient::new())
    }

    async fn check_connection(&self, _timeout: Duration, _attempts: u32) -> Result<(), LxdError> {
        // Mock client always ok
        Ok(())
    }
}

#[async_trait]
impl LxdClient for RealLxdClient {
    async fn create_container(&self, name: &str, image: &str) -> Result<(), LxdError> {
        tracing::info!(container=%name, image=%image, "creating container via lxd api");
        // POST /1.0/instances with source image
        let body = json!({"name": name, "source": {"type": "image", "alias": image}});
        let resp = self.post_json("/1.0/instances", body).await?;

        // If the API returned a status code embedded in metadata and it indicates
        // failure, return early with a descriptive error. Some LXD endpoints include
        // a metadata.status_code even when HTTP was successful.
        if let Some(code) = resp
            .pointer("/metadata/status_code")
            .and_then(|v| v.as_i64())
        {
            if !(200..300).contains(&code) {
                let msg = resp
                    .pointer("/metadata/err")
                    .and_then(|v| v.as_str())
                    .unwrap_or("operation failed");
                return Err(LxdError::Other(format!(
                    "create failed status_code={} err={}",
                    code, msg
                )));
            }
        }

        // If LXD returned an async operation, follow it until completion.
        if let Some(op) = RealLxdClient::find_operation_path_in_value(&resp) {
            tracing::info!(operation=%op, "create returned operation; waiting for completion");
            self.wait_for_operation(&op, Duration::from_secs(60))
                .await?;
        }
        Ok(())
    }

    async fn wait_for_pid(&self, name: &str, timeout: Duration) -> Result<u32, LxdError> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            // run `lxc info <name> --format=json`
            match self.get_json(&format!("/1.0/instances/{}", name)).await {
                Ok(json) => {
                    if let Some(pid) = json.pointer("/metadata/state/pid").and_then(|v| v.as_u64())
                    {
                        if pid > 0 {
                            return Ok(pid as u32);
                        }
                    }
                    if let Some(pid) = json.pointer("/metadata/pid").and_then(|v| v.as_u64()) {
                        if pid > 0 {
                            return Ok(pid as u32);
                        }
                    }
                    if let Some(pid) = json.pointer("/state/pid").and_then(|v| v.as_u64()) {
                        if pid > 0 {
                            return Ok(pid as u32);
                        }
                    }
                    // if status is Running but no pid, continue waiting
                    if let Some(status) = json.pointer("/status").and_then(|v| v.as_str()) {
                        if status == "Running" {
                            // keep waiting
                        }
                    }
                }
                Err(e) => tracing::debug!(name=%name, err=%e, "info failed, will retry"),
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(LxdError::Other("timeout waiting for pid".into()))
    }

    async fn delete_container(&self, name: &str) -> Result<(), LxdError> {
        tracing::info!(container=%name, "deleting container via lxd api");
        // DELETE /1.0/instances/<name>
        let resp = self
            .delete_path(&format!("/1.0/instances/{}", name))
            .await?;

        // If the API returned a status code embedded in metadata and it indicates
        // failure, return early with an error — similar to create_container.
        if let Some(code) = resp
            .pointer("/metadata/status_code")
            .and_then(|v| v.as_i64())
        {
            if !(200..300).contains(&code) {
                let msg = resp
                    .pointer("/metadata/err")
                    .and_then(|v| v.as_str())
                    .unwrap_or("operation failed");
                return Err(LxdError::Other(format!(
                    "delete failed status_code={} err={}",
                    code, msg
                )));
            }
        }

        if let Some(op) = RealLxdClient::find_operation_path_in_value(&resp) {
            tracing::info!(operation=%op, "delete returned operation; waiting for completion");
            self.wait_for_operation(&op, Duration::from_secs(60))
                .await?;
        }
        Ok(())
    }

    async fn wait_for_shutdown(&self, name: &str, timeout: Duration) -> Result<(), LxdError> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            match self.get_json(&format!("/1.0/instances/{}", name)).await {
                Ok(json) => {
                    if let Some(status) = json.pointer("/metadata/status").and_then(|v| v.as_str())
                    {
                        if status != "Running" {
                            return Ok(());
                        }
                    }
                    if let Some(status) = json
                        .pointer("/metadata/state")
                        .and_then(|v| v.get("status"))
                        .and_then(|v| v.as_str())
                    {
                        if status != "Running" {
                            return Ok(());
                        }
                    }
                }
                Err(_) => {
                    // If info fails (container not found) treat as shutdown
                    return Ok(());
                }
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        Err(LxdError::Other("timeout waiting for shutdown".into()))
    }

    fn clone_box(&self) -> Box<dyn LxdClient + Send + Sync> {
        Box::new(RealLxdClient::new())
    }

    async fn check_connection(&self, timeout: Duration, attempts: u32) -> Result<(), LxdError> {
        // perform up to `attempts` tries with the provided timeout per attempt
        for i in 0..attempts {
            tracing::debug!(attempt=%i, attempts=%attempts, "checking LXD connectivity");
            match tokio::time::timeout(timeout, self.get_json("/1.0")).await {
                Ok(Ok(v)) => {
                    tracing::debug!(resp=?v, "LXD /1.0 responded");
                    return Ok(());
                }
                Ok(Err(e)) => {
                    tracing::debug!(err=%e, "LXD GET /1.0 failed");
                }
                Err(_) => {
                    tracing::debug!("LXD /1.0 timed out waiting for response");
                }
            }

            if i + 1 < attempts {
                // short backoff before retrying
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            }
        }

        Err(LxdError::Other(
            "timeout/retries exhausted when contacting LXD".into(),
        ))
    }
}
