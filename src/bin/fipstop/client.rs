use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::timeout;

const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ControlClient {
    /// On Unix, this is a socket path. On Windows, this is a TCP port string.
    address: String,
}

impl ControlClient {
    pub fn new(socket_path: &std::path::Path) -> Self {
        Self {
            address: socket_path.to_string_lossy().into_owned(),
        }
    }

    pub async fn query(&self, command: &str) -> Result<Value, String> {
        let stream = self.connect().await?;

        let (reader, mut writer) = tokio::io::split(stream);

        let request = format!("{{\"command\":\"{command}\"}}\n");
        timeout(IO_TIMEOUT, writer.write_all(request.as_bytes()))
            .await
            .map_err(|_| "write timed out".to_string())?
            .map_err(|e| format!("write: {e}"))?;

        writer
            .shutdown()
            .await
            .map_err(|e| format!("shutdown: {e}"))?;

        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();
        timeout(IO_TIMEOUT, buf_reader.read_line(&mut line))
            .await
            .map_err(|_| "read timed out".to_string())?
            .map_err(|e| format!("read: {e}"))?;

        let response: Value =
            serde_json::from_str(line.trim()).map_err(|e| format!("parse: {e}"))?;

        let status = response
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        if status == "error" {
            let msg = response
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown error");
            return Err(msg.to_string());
        }

        Ok(response.get("data").cloned().unwrap_or(Value::Null))
    }

    #[cfg(unix)]
    async fn connect(&self) -> Result<tokio::net::UnixStream, String> {
        timeout(IO_TIMEOUT, tokio::net::UnixStream::connect(&self.address))
            .await
            .map_err(|_| "connection timed out".to_string())?
            .map_err(|e| format!("connect: {e}"))
    }

    #[cfg(windows)]
    async fn connect(&self) -> Result<tokio::net::TcpStream, String> {
        let port: u16 = match self.address.parse() {
            Ok(p) => p,
            Err(_) => {
                eprintln!(
                    "warning: invalid port '{}', using default 21210",
                    self.address
                );
                21210
            }
        };
        let addr = format!("127.0.0.1:{port}");
        timeout(IO_TIMEOUT, tokio::net::TcpStream::connect(&addr))
            .await
            .map_err(|_| "connection timed out".to_string())?
            .map_err(|e| format!("connect: {e}"))
    }
}
