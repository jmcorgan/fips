//! Control socket for runtime management and observability.
//!
//! Provides a control interface that accepts commands and returns
//! structured JSON responses. Supports both read-only queries (show_*)
//! and mutating commands (connect, disconnect).
//!
//! Platform-specific implementations:
//! - Unix: Uses a Unix domain socket for local IPC
//! - Windows: Uses a TCP socket on localhost (see commit 3)

pub mod commands;
pub mod firewall_state;
pub mod listening;
pub mod probe;
pub mod protocol;
pub mod queries;
pub mod read_handle;
pub mod snapshot;

use crate::config::ControlConfig;
use protocol::{Request, Response};
use read_handle::{ControlReadHandle, snapshot_dispatch};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, info, warn};

/// Maximum request size in bytes (4 KB).
const MAX_REQUEST_SIZE: usize = 4096;

/// I/O timeout for client connections.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// A message sent from the accept loop to the main event loop.
pub type ControlMessage = (Request, oneshot::Sender<Response>);

/// Handle a single client connection over any AsyncRead + AsyncWrite stream.
///
/// Shared between Unix and Windows implementations to avoid duplicating
/// the request/response protocol logic.
async fn handle_connection_generic<S>(
    stream: S,
    control_tx: mpsc::Sender<ControlMessage>,
    read_handle: ControlReadHandle,
) -> Result<(), Box<dyn std::error::Error>>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(stream);
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
        Ok(Ok(())) if line.is_empty() => Response::error("empty request"),
        Ok(Ok(())) => {
            // Parse the request
            match serde_json::from_str::<Request>(line.trim()) {
                Ok(request) => {
                    // First try to serve the request entirely off-loop from the
                    // read handle. It returns None for any command with no snapshot
                    // branch, and those fall through to the rx_loop path below.
                    match snapshot_dispatch(&request, &read_handle) {
                        Some(resp) => resp,
                        None => {
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

// ============================================================================
// Unix implementation
// ============================================================================

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::path::{Path, PathBuf};
    use tokio::net::UnixListener;

    /// Ensure the socket's parent exists and report whether this call created
    /// the leaf directory.
    ///
    /// `create_dir` gives us an atomic ownership decision: an `AlreadyExists`
    /// result means another actor owns the existing directory, while success
    /// means it is safe for this bind to apply FIPS ownership and mode. Missing
    /// ancestors are created recursively, but only the requested leaf is later
    /// treated as the socket's private directory.
    fn ensure_socket_parent(parent: &Path) -> Result<bool, std::io::Error> {
        if parent.as_os_str().is_empty() {
            return Ok(false);
        }

        match std::fs::create_dir(parent) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if parent.is_dir() {
                    Ok(false)
                } else {
                    Err(error)
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let ancestor = parent.parent().ok_or(error)?;
                ensure_socket_parent(ancestor)?;
                ensure_socket_parent(parent)
            }
            Err(error) => Err(error),
        }
    }

    /// Apply access policy to a newly bound control socket.
    ///
    /// The socket is always group-owned. `managed_parent` is either a private
    /// directory this bind created or a canonical FIPS runtime directory. A
    /// shared or operator-owned existing parent is omitted so it retains its
    /// ownership and mode.
    fn set_control_socket_access(
        socket_path: &Path,
        managed_parent: Option<&Path>,
        mut chown_to_fips_group: impl FnMut(&Path),
    ) -> Result<(), std::io::Error> {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o770))?;
        chown_to_fips_group(socket_path);

        if let Some(parent) = managed_parent {
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
            chown_to_fips_group(parent);
        }

        Ok(())
    }

    /// Control socket listener (Unix domain socket).
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

            // Creation is useful for diagnostics, but ownership is keyed to
            // directory identity as well: systemd pre-creates /run/fips on
            // every Linux service start and initially owns it as root:root.
            let managed_parent = match socket_path.parent() {
                Some(parent) => {
                    let created = ensure_socket_parent(parent)?;
                    if created {
                        debug!(path = %parent.display(), "Created private control socket directory");
                    }
                    (created || crate::config::is_managed_socket_parent(parent))
                        .then(|| parent.to_owned())
                }
                None => None,
            };

            // Remove stale socket if it exists
            if socket_path.exists() {
                Self::remove_stale_socket(&socket_path)?;
            }

            let listener = UnixListener::bind(&socket_path)?;

            // Make the socket and its managed private directory group-accessible
            // so fips group members can use fipsctl/fipstop.
            set_control_socket_access(
                &socket_path,
                managed_parent.as_deref(),
                Self::chown_to_fips_group,
            )?;

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

        /// Set group ownership of a path to the 'fips' group (best-effort).
        fn chown_to_fips_group(path: &Path) {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;

            // Look up the 'fips' group
            let group_name = CString::new("fips").unwrap();
            let grp = unsafe { libc::getgrnam(group_name.as_ptr()) };
            if grp.is_null() {
                debug!(
                    "'fips' group not found, skipping chown for {}",
                    path.display()
                );
                return;
            }
            let gid = unsafe { (*grp).gr_gid };

            let c_path = match CString::new(path.as_os_str().as_bytes()) {
                Ok(p) => p,
                Err(_) => return,
            };
            let ret = unsafe { libc::chown(c_path.as_ptr(), u32::MAX, gid) };
            if ret != 0 {
                warn!(
                    path = %path.display(),
                    error = %std::io::Error::last_os_error(),
                    "Failed to chown control socket to 'fips' group"
                );
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
        pub(crate) async fn accept_loop(
            self,
            control_tx: mpsc::Sender<ControlMessage>,
            read_handle: ControlReadHandle,
        ) {
            loop {
                let (stream, _addr) = match self.listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(error = %e, "Control socket accept failed");
                        continue;
                    }
                };

                let tx = control_tx.clone();
                let handle = read_handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection_generic(stream, tx, handle).await {
                        debug!(error = %e, "Control connection error");
                    }
                });
            }
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

    #[cfg(test)]
    mod tests {
        use super::{ensure_socket_parent, set_control_socket_access};
        use std::os::unix::fs::PermissionsExt;

        #[test]
        fn parent_setup_distinguishes_existing_and_created_directories() {
            let temp = tempfile::tempdir().unwrap();
            let existing = temp.path().join("existing");
            std::fs::create_dir(&existing).unwrap();
            assert!(!ensure_socket_parent(&existing).unwrap());

            let nested = temp.path().join("missing").join("fips");
            assert!(ensure_socket_parent(&nested).unwrap());
            assert!(nested.is_dir());
            assert!(!ensure_socket_parent(&nested).unwrap());
        }

        #[test]
        fn access_setup_leaves_an_existing_shared_parent_unchanged() {
            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().join("shared");
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o711)).unwrap();
            let socket = parent.join("control.sock");
            std::fs::File::create(&socket).unwrap();

            let mut chowned = Vec::new();
            set_control_socket_access(&socket, None, |path| chowned.push(path.to_path_buf()))
                .unwrap();

            assert_eq!(chowned, vec![socket.clone()]);
            assert_eq!(
                std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
                0o711
            );
            assert_eq!(
                std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
                0o770
            );
        }

        #[test]
        fn access_setup_secures_a_new_private_parent() {
            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().join("fips");
            std::fs::create_dir(&parent).unwrap();
            let socket = parent.join("control.sock");
            std::fs::File::create(&socket).unwrap();

            let mut chowned = Vec::new();
            set_control_socket_access(&socket, Some(&parent), |path| {
                chowned.push(path.to_path_buf())
            })
            .unwrap();

            assert_eq!(chowned, vec![socket, parent.clone()]);
            assert_eq!(
                std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
                0o750
            );
        }

        #[test]
        fn access_setup_secures_an_existing_managed_parent() {
            let temp = tempfile::tempdir().unwrap();
            let parent = temp.path().join("managed");
            std::fs::create_dir(&parent).unwrap();
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            let socket = parent.join("control.sock");
            std::fs::File::create(&socket).unwrap();

            let mut chowned = Vec::new();
            set_control_socket_access(&socket, Some(&parent), |path| {
                chowned.push(path.to_path_buf())
            })
            .unwrap();

            assert_eq!(chowned, vec![socket, parent.clone()]);
            assert_eq!(
                std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
                0o750
            );
        }
    }
}

// ============================================================================
// Windows implementation (TCP on localhost)
// ============================================================================

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use tokio::net::TcpListener;

    /// Default TCP port for the control socket on Windows.
    const DEFAULT_CONTROL_PORT: u16 = 21210;

    /// Control socket listener (Windows TCP on localhost).
    ///
    /// On Windows, the control socket uses a TCP listener bound to
    /// `127.0.0.1` since Windows does not support Unix domain sockets
    /// reliably. Only localhost connections are accepted.
    ///
    /// Note: Unlike Unix domain sockets, TCP does not provide filesystem-level
    /// ACLs. Any local user can connect to the control port. This is acceptable
    /// for single-user Windows installations but should be documented.
    pub struct ControlSocket {
        listener: TcpListener,
        port: u16,
    }

    impl ControlSocket {
        /// Bind a TCP control socket on localhost.
        ///
        /// Parses the port from `config.socket_path` (which is a port number
        /// string on Windows, e.g. "21210"). Falls back to the default port
        /// with a warning if parsing fails.
        pub fn bind(config: &ControlConfig) -> Result<Self, std::io::Error> {
            let port: u16 = match config.socket_path.parse() {
                Ok(p) => p,
                Err(e) => {
                    warn!(
                        path = %config.socket_path,
                        error = %e,
                        default = DEFAULT_CONTROL_PORT,
                        "Invalid control port, using default"
                    );
                    DEFAULT_CONTROL_PORT
                }
            };

            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            let std_listener = std::net::TcpListener::bind(addr)?;
            std_listener.set_nonblocking(true)?;
            let listener = TcpListener::from_std(std_listener)?;

            info!(port = port, "Control socket listening on localhost");

            Ok(Self { listener, port })
        }

        /// Get the listening port.
        pub fn port(&self) -> u16 {
            self.port
        }

        /// Run the accept loop, forwarding requests to the main event loop via mpsc.
        ///
        /// Each accepted connection is handled in a spawned task using the
        /// shared `handle_connection_generic` protocol handler.
        pub(crate) async fn accept_loop(
            self,
            control_tx: mpsc::Sender<ControlMessage>,
            read_handle: ControlReadHandle,
        ) {
            loop {
                let (stream, addr) = match self.listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!(error = %e, "Control socket accept failed");
                        continue;
                    }
                };

                // Only accept connections from localhost
                if !addr.ip().is_loopback() {
                    warn!(addr = %addr, "Rejected non-localhost control connection");
                    continue;
                }

                let tx = control_tx.clone();
                let handle = read_handle.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection_generic(stream, tx, handle).await {
                        debug!(error = %e, "Control connection error");
                    }
                });
            }
        }
    }
}

// Re-export platform-specific types
#[cfg(unix)]
pub use unix_impl::ControlSocket;
#[cfg(windows)]
pub use windows_impl::ControlSocket;

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::*;

    #[cfg(windows)]
    #[tokio::test]
    async fn test_tcp_control_socket_bind() {
        let config = ControlConfig {
            enabled: true,
            socket_path: "0".to_string(), // port 0 = ephemeral
        };

        // Verify the socket binds successfully on an ephemeral port
        let _socket = ControlSocket::bind(&config).expect("failed to bind control socket");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn test_tcp_control_socket_invalid_port_uses_default() {
        let config = ControlConfig {
            enabled: true,
            socket_path: "not-a-port".to_string(),
        };

        // Should fall back to default port 21210. This may fail if 21210
        // is already in use, which is acceptable for a unit test.
        let result = ControlSocket::bind(&config);
        // We mainly verify it doesn't panic on invalid input
        if let Ok(socket) = result {
            assert_eq!(socket.port(), 21210);
        }
    }
}
