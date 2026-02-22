//! Control socket for runtime observability.
//!
//! Provides a Unix domain socket that accepts query commands and returns
//! structured JSON data about the node's current state. Read-only queries
//! only — no state mutation through this channel.

pub mod protocol;
pub mod queries;

use crate::config::ControlConfig;
use protocol::{Request, Response};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

/// Maximum request size in bytes (4 KB).
const MAX_REQUEST_SIZE: usize = 4096;

/// I/O timeout for client connections.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A message sent from the accept loop to the main event loop.
pub type ControlMessage = (Request, oneshot::Sender<Response>);

/// Control socket listener.
///
/// Manages the Unix domain socket lifecycle: bind, accept, cleanup.
pub struct ControlSocket {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl ControlSocket {
    /// Bind a new control socket.
    ///
    /// Creates parent directories if needed, removes stale socket files,
    /// and binds the Unix listener.
    pub fn bind(config: &ControlConfig) -> Result<Self, std::io::Error> {
        let socket_path = PathBuf::from(&config.socket_path);

        // Create parent directory if it doesn't exist
        if let Some(parent) = socket_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
            debug!(path = %parent.display(), "Created control socket directory");
        }

        // Remove stale socket if it exists
        if socket_path.exists() {
            Self::remove_stale_socket(&socket_path)?;
        }

        let listener = UnixListener::bind(&socket_path)?;
        info!(path = %socket_path.display(), "Control socket listening");

        Ok(Self {
            listener,
            socket_path,
        })
    }

    /// Remove a stale socket file.
    ///
    /// If the file exists but no one is listening, remove it so we can
    /// bind. This handles unclean daemon exits.
    fn remove_stale_socket(path: &Path) -> Result<(), std::io::Error> {
        // Try connecting to see if someone is listening
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => {
                // Someone is listening — don't remove it
                Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("control socket already in use: {}", path.display()),
                ))
            }
            Err(_) => {
                // No one listening — remove the stale socket
                debug!(path = %path.display(), "Removing stale control socket");
                std::fs::remove_file(path)?;
                Ok(())
            }
        }
    }

    /// Run the accept loop, forwarding requests to the main event loop via mpsc.
    ///
    /// Each accepted connection is handled in a spawned task:
    /// 1. Read one line of JSON (the request)
    /// 2. Send (Request, oneshot::Sender) to the main loop
    /// 3. Wait for the response via oneshot
    /// 4. Write the response as one line of JSON
    /// 5. Close the connection
    pub async fn accept_loop(self, control_tx: mpsc::Sender<ControlMessage>) {
        loop {
            let (stream, _addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "Control socket accept failed");
                    continue;
                }
            };

            let tx = control_tx.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, tx).await {
                    debug!(error = %e, "Control connection error");
                }
            });
        }
    }

    /// Handle a single client connection.
    async fn handle_connection(
        stream: tokio::net::UnixStream,
        control_tx: mpsc::Sender<ControlMessage>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (reader, mut writer) = stream.into_split();
        let mut buf_reader = BufReader::new(reader);
        let mut line = String::new();

        // Read one line with timeout and size limit
        let read_result = tokio::time::timeout(IO_TIMEOUT, async {
            let mut total = 0usize;
            loop {
                let n = buf_reader.read_line(&mut line).await?;
                if n == 0 {
                    break; // EOF
                }
                total += n;
                if total > MAX_REQUEST_SIZE {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "request too large",
                    ));
                }
                if line.ends_with('\n') {
                    break;
                }
            }
            Ok(())
        })
        .await;

        let response = match read_result {
            Ok(Ok(())) if line.is_empty() => {
                Response::error("empty request")
            }
            Ok(Ok(())) => {
                // Parse the request
                match serde_json::from_str::<Request>(line.trim()) {
                    Ok(request) => {
                        // Send to main loop and wait for response
                        let (resp_tx, resp_rx) = oneshot::channel();
                        if control_tx.send((request, resp_tx)).await.is_err() {
                            Response::error("node shutting down")
                        } else {
                            match tokio::time::timeout(IO_TIMEOUT, resp_rx).await {
                                Ok(Ok(resp)) => resp,
                                Ok(Err(_)) => Response::error("response channel closed"),
                                Err(_) => Response::error("query timeout"),
                            }
                        }
                    }
                    Err(e) => Response::error(format!("invalid request: {}", e)),
                }
            }
            Ok(Err(e)) => Response::error(format!("read error: {}", e)),
            Err(_) => Response::error("read timeout"),
        };

        // Write response with timeout
        let json = serde_json::to_string(&response)?;
        let write_result = tokio::time::timeout(IO_TIMEOUT, async {
            writer.write_all(json.as_bytes()).await?;
            writer.write_all(b"\n").await?;
            writer.shutdown().await?;
            Ok::<_, std::io::Error>(())
        })
        .await;

        if let Err(_) | Ok(Err(_)) = write_result {
            debug!("Control socket write failed or timed out");
        }

        Ok(())
    }

    /// Get the socket path.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Clean up the socket file.
    fn cleanup(&self) {
        if self.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                warn!(
                    path = %self.socket_path.display(),
                    error = %e,
                    "Failed to remove control socket"
                );
            } else {
                debug!(path = %self.socket_path.display(), "Control socket removed");
            }
        }
    }
}

impl Drop for ControlSocket {
    fn drop(&mut self) {
        self.cleanup();
    }
}
