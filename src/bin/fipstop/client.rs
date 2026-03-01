use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::time::timeout;

const IO_TIMEOUT: Duration = Duration::from_secs(5);

pub struct ControlClient {
    socket_path: PathBuf,
}

impl ControlClient {
    pub fn new(socket_path: &Path) -> Self {
        Self {
            socket_path: socket_path.to_path_buf(),
        }
    }

    pub async fn query(&self, command: &str) -> Result<Value, String> {
        let stream = timeout(IO_TIMEOUT, UnixStream::connect(&self.socket_path))
            .await
            .map_err(|_| "connection timed out".to_string())?
            .map_err(|e| format!("connect: {e}"))?;

        let (reader, mut writer) = stream.into_split();

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
}
