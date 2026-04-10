//! Tor control port client.
//!
//! Minimal async client for the Tor control protocol (control-spec).
//! Implements AUTHENTICATE and GETINFO for monitoring the Tor daemon.

use std::fmt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
use tracing::debug;

// ============================================================================
// Error Type
// ============================================================================

/// Errors from the Tor control port client.
#[derive(Debug)]
pub enum TorControlError {
    /// Failed to connect to the control port.
    ConnectionFailed(String),
    /// Authentication failed.
    AuthFailed(String),
    /// Protocol-level error (unexpected response format).
    ProtocolError(String),
    /// I/O error.
    Io(std::io::Error),
}

impl fmt::Display for TorControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionFailed(msg) => write!(f, "control port connection failed: {}", msg),
            Self::AuthFailed(msg) => write!(f, "control port auth failed: {}", msg),
            Self::ProtocolError(msg) => write!(f, "control protocol error: {}", msg),
            Self::Io(e) => write!(f, "control port I/O error: {}", e),
        }
    }
}

impl std::error::Error for TorControlError {}

impl From<std::io::Error> for TorControlError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

// ============================================================================
// Authentication
// ============================================================================

/// Control port authentication method.
#[derive(Debug, Clone)]
pub enum ControlAuth {
    /// Cookie authentication — reads 32-byte cookie from file, sends as hex.
    Cookie(PathBuf),
    /// Password authentication — sends AUTHENTICATE "password".
    Password(String),
}

impl ControlAuth {
    /// Parse a control_auth config string into a ControlAuth value.
    ///
    /// - `"cookie"` or `"cookie:/path/to/cookie"` → Cookie auth
    /// - `"password:secret"` → Password auth
    pub fn from_config(auth_str: &str, default_cookie_path: &str) -> Result<Self, TorControlError> {
        if auth_str == "cookie" {
            Ok(Self::Cookie(PathBuf::from(default_cookie_path)))
        } else if let Some(path) = auth_str.strip_prefix("cookie:") {
            Ok(Self::Cookie(PathBuf::from(path)))
        } else if let Some(password) = auth_str.strip_prefix("password:") {
            Ok(Self::Password(password.to_string()))
        } else {
            Err(TorControlError::AuthFailed(format!(
                "unknown control_auth format '{}': expected 'cookie', 'cookie:/path', or 'password:secret'",
                auth_str
            )))
        }
    }
}

// ============================================================================
// Monitoring Info
// ============================================================================

/// Snapshot of Tor daemon status collected via control port GETINFO queries.
#[derive(Debug, Clone, Serialize)]
pub struct TorMonitoringInfo {
    /// Bootstrap progress (0-100).
    pub bootstrap: u8,
    /// Whether Tor has at least one working circuit.
    pub circuit_established: bool,
    /// Total bytes read by Tor since startup.
    pub traffic_read: u64,
    /// Total bytes written by Tor since startup.
    pub traffic_written: u64,
    /// Network liveness: "up" or "down".
    pub network_liveness: String,
    /// Tor daemon version string.
    pub version: String,
    /// Whether Tor is in dormant mode (no recent activity).
    pub dormant: bool,
}

// ============================================================================
// Client
// ============================================================================

/// Async Tor control port client.
///
/// Maintains a persistent connection to the Tor daemon's control port.
/// Supports both TCP (`host:port`) and Unix socket (`/path/to/socket`)
/// connections. The connection must stay alive for the lifetime of
/// ephemeral onion services (unless created with detach=true).
pub struct TorControlClient {
    reader: BufReader<Box<dyn AsyncRead + Unpin + Send>>,
    writer: Box<dyn AsyncWrite + Unpin + Send>,
}

impl fmt::Debug for TorControlClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TorControlClient").finish_non_exhaustive()
    }
}

impl TorControlClient {
    /// Connect to a Tor control port.
    ///
    /// The address can be either:
    /// - A TCP address (`host:port` or `IP:port`) for TCP connections
    /// - A filesystem path (starting with `/` or `./`) for Unix socket connections
    ///
    /// Unix sockets are preferred for security: they provide filesystem
    /// permission-based access control and are not reachable from containers
    /// unless explicitly mounted. The Debian default is `/run/tor/control`.
    pub async fn connect(addr: &str) -> Result<Self, TorControlError> {
        if is_unix_socket_path(addr) {
            Self::connect_unix(addr).await
        } else {
            Self::connect_tcp(addr).await
        }
    }

    /// Connect via TCP to a control port at `host:port`.
    async fn connect_tcp(addr: &str) -> Result<Self, TorControlError> {
        let stream = TcpStream::connect(addr).await.map_err(|e| {
            TorControlError::ConnectionFailed(format!(
                "failed to connect to control port {}: {}",
                addr, e
            ))
        })?;

        let (read_half, write_half) = stream.into_split();

        debug!(addr = %addr, transport = "tcp", "Connected to Tor control port");

        Ok(Self {
            reader: BufReader::new(Box::new(read_half)),
            writer: Box::new(write_half),
        })
    }

    /// Connect via Unix socket to a control port at the given path.
    #[cfg(unix)]
    async fn connect_unix(path: &str) -> Result<Self, TorControlError> {
        let stream = UnixStream::connect(path).await.map_err(|e| {
            TorControlError::ConnectionFailed(format!(
                "failed to connect to control socket {}: {}",
                path, e
            ))
        })?;

        let (read_half, write_half) = stream.into_split();

        debug!(path = %path, transport = "unix", "Connected to Tor control port");

        Ok(Self {
            reader: BufReader::new(Box::new(read_half)),
            writer: Box::new(write_half),
        })
    }

    #[cfg(not(unix))]
    async fn connect_unix(path: &str) -> Result<Self, TorControlError> {
        Err(TorControlError::ConnectionFailed(format!(
            "Unix sockets not supported on this platform: {}",
            path
        )))
    }

    /// Authenticate with the Tor daemon.
    pub async fn authenticate(&mut self, auth: &ControlAuth) -> Result<(), TorControlError> {
        let command = match auth {
            ControlAuth::Cookie(path) => {
                let cookie = read_cookie_file(path)?;
                format!("AUTHENTICATE {}\r\n", hex::encode(cookie))
            }
            ControlAuth::Password(password) => {
                // Escape quotes in password
                let escaped = password.replace('\\', "\\\\").replace('"', "\\\"");
                format!("AUTHENTICATE \"{}\"\r\n", escaped)
            }
        };

        self.send_command(&command).await?;
        let response = self.read_response().await?;

        if response.code != 250 {
            return Err(TorControlError::AuthFailed(format!(
                "AUTHENTICATE failed: {} {}",
                response.code, response.message
            )));
        }

        debug!("Authenticated with Tor control port");
        Ok(())
    }

    // ========================================================================
    // Monitoring Queries
    // ========================================================================

    /// Issue a GETINFO query and return the value for the given key.
    ///
    /// Tor responds with `250-key=value` data lines. This extracts the
    /// value for the requested key.
    async fn getinfo(&mut self, key: &str) -> Result<String, TorControlError> {
        let command = format!("GETINFO {}\r\n", key);
        self.send_command(&command).await?;
        let response = self.read_response().await?;

        if response.code != 250 {
            return Err(TorControlError::ProtocolError(format!(
                "GETINFO {} failed: {} {}",
                key, response.code, response.message
            )));
        }

        let prefix = format!("{}=", key);
        for line in &response.data_lines {
            if let Some(value) = line.strip_prefix(&prefix) {
                return Ok(value.to_string());
            }
        }

        Err(TorControlError::ProtocolError(format!(
            "GETINFO response missing key '{}'",
            key
        )))
    }

    /// Query Tor's bootstrap progress (0-100).
    pub async fn get_bootstrap_phase(&mut self) -> Result<u8, TorControlError> {
        let raw = self.getinfo("status/bootstrap-phase").await?;

        // Value looks like: NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"
        if let Some(progress_start) = raw.find("PROGRESS=") {
            let after = &raw[progress_start + 9..];
            let digits: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(progress) = digits.parse::<u8>() {
                return Ok(progress);
            }
        }

        Err(TorControlError::ProtocolError(
            "could not parse bootstrap progress".into(),
        ))
    }

    /// Check whether Tor has established circuits (health check).
    ///
    /// Returns true if Tor has at least one working circuit, false otherwise.
    pub async fn is_circuit_established(&mut self) -> Result<bool, TorControlError> {
        let value = self.getinfo("status/circuit-established").await?;
        Ok(value.trim() == "1")
    }

    /// Query total bytes read by Tor since startup.
    pub async fn traffic_read(&mut self) -> Result<u64, TorControlError> {
        let value = self.getinfo("traffic/read").await?;
        value.trim().parse::<u64>().map_err(|_| {
            TorControlError::ProtocolError(format!("invalid traffic/read value: '{}'", value))
        })
    }

    /// Query total bytes written by Tor since startup.
    pub async fn traffic_written(&mut self) -> Result<u64, TorControlError> {
        let value = self.getinfo("traffic/written").await?;
        value.trim().parse::<u64>().map_err(|_| {
            TorControlError::ProtocolError(format!("invalid traffic/written value: '{}'", value))
        })
    }

    /// Query whether Tor considers the network reachable.
    ///
    /// Returns `"up"` or `"down"`.
    pub async fn network_liveness(&mut self) -> Result<String, TorControlError> {
        self.getinfo("network-liveness").await
    }

    /// Query the Tor daemon version string.
    pub async fn version(&mut self) -> Result<String, TorControlError> {
        self.getinfo("version").await
    }

    /// Query whether Tor is in dormant mode (no recent activity).
    pub async fn is_dormant(&mut self) -> Result<bool, TorControlError> {
        let value = self.getinfo("dormant").await?;
        Ok(value.trim() == "1")
    }

    /// Query Tor's SOCKS listener addresses.
    ///
    /// Returns a list of addresses Tor is listening on for SOCKS connections.
    pub async fn socks_listeners(&mut self) -> Result<Vec<String>, TorControlError> {
        let value = self.getinfo("net/listeners/socks").await?;
        Ok(value
            .split_whitespace()
            .map(|s| s.trim_matches('"').to_string())
            .collect())
    }

    /// Collect all monitoring info in a single batch of queries.
    pub async fn monitoring_snapshot(&mut self) -> Result<TorMonitoringInfo, TorControlError> {
        let bootstrap = self.get_bootstrap_phase().await.unwrap_or(0);
        let circuit_established = self.is_circuit_established().await.unwrap_or(false);
        let traffic_read = self.traffic_read().await.unwrap_or(0);
        let traffic_written = self.traffic_written().await.unwrap_or(0);
        let network_liveness = self
            .network_liveness()
            .await
            .unwrap_or_else(|_| "unknown".into());
        let version = self.version().await.unwrap_or_else(|_| "unknown".into());
        let dormant = self.is_dormant().await.unwrap_or(false);

        Ok(TorMonitoringInfo {
            bootstrap,
            circuit_established,
            traffic_read,
            traffic_written,
            network_liveness,
            version,
            dormant,
        })
    }

    // ========================================================================
    // Protocol Helpers
    // ========================================================================

    /// Send a raw command string to the control port.
    async fn send_command(&mut self, command: &str) -> Result<(), TorControlError> {
        self.writer.write_all(command.as_bytes()).await?;
        self.writer.flush().await?;
        Ok(())
    }

    /// Read a complete response from the control port.
    ///
    /// Tor responses are line-based:
    /// - `250-key=value` — mid-reply data line (more lines follow)
    /// - `250 OK` — final line of a successful reply
    /// - `5xx message` — error
    ///
    /// Returns the status code and collected data lines.
    async fn read_response(&mut self) -> Result<ControlResponse, TorControlError> {
        let mut data_lines = Vec::new();
        let mut line_buf = String::new();

        loop {
            line_buf.clear();
            let n = self.reader.read_line(&mut line_buf).await?;
            if n == 0 {
                return Err(TorControlError::ProtocolError(
                    "control port connection closed".into(),
                ));
            }

            let line = line_buf.trim_end_matches(['\r', '\n']);

            if line.len() < 4 {
                return Err(TorControlError::ProtocolError(format!(
                    "response line too short: '{}'",
                    line
                )));
            }

            let code: u16 = line[..3].parse().map_err(|_| {
                TorControlError::ProtocolError(format!("invalid response code in: '{}'", line))
            })?;

            let separator = line.as_bytes()[3];
            let content = &line[4..];

            match separator {
                b'-' => {
                    // Mid-reply data line
                    data_lines.push(content.to_string());
                }
                b' ' => {
                    // Final line
                    return Ok(ControlResponse {
                        code,
                        message: content.to_string(),
                        data_lines,
                    });
                }
                b'+' => {
                    // Multi-line data (dot-encoded). Read until lone "."
                    data_lines.push(content.to_string());
                    loop {
                        line_buf.clear();
                        let n = self.reader.read_line(&mut line_buf).await?;
                        if n == 0 {
                            return Err(TorControlError::ProtocolError(
                                "connection closed during multi-line response".into(),
                            ));
                        }
                        let dot_line = line_buf.trim_end_matches(['\r', '\n']);
                        if dot_line == "." {
                            break;
                        }
                        // Strip leading dot-escape
                        let unescaped = dot_line.strip_prefix('.').unwrap_or(dot_line);
                        data_lines.push(unescaped.to_string());
                    }
                }
                _ => {
                    return Err(TorControlError::ProtocolError(format!(
                        "unexpected separator '{}' in: '{}'",
                        separator as char, line
                    )));
                }
            }
        }
    }
}

/// Parsed control port response.
struct ControlResponse {
    /// Status code (250 = success, 5xx = error).
    code: u16,
    /// Message from the final line.
    message: String,
    /// Data lines from mid-reply (250-) lines.
    data_lines: Vec<String>,
}

// ============================================================================
// Cookie File
// ============================================================================

/// Read a Tor control cookie file (32 bytes of raw binary).
fn read_cookie_file(path: &Path) -> Result<Vec<u8>, TorControlError> {
    let data = std::fs::read(path).map_err(|e| {
        TorControlError::AuthFailed(format!(
            "failed to read cookie file '{}': {}",
            path.display(),
            e
        ))
    })?;

    if data.len() != 32 {
        return Err(TorControlError::AuthFailed(format!(
            "cookie file '{}' has {} bytes, expected 32",
            path.display(),
            data.len()
        )));
    }

    Ok(data)
}

// ============================================================================
// Unix Socket Detection
// ============================================================================

/// Detect whether a control address string is a Unix socket path.
///
/// Returns true if the string starts with `/` or `./`, indicating a
/// filesystem path rather than a `host:port` TCP address.
fn is_unix_socket_path(addr: &str) -> bool {
    addr.starts_with('/') || addr.starts_with("./")
}

// ============================================================================
// Hex Encoding (minimal, no dependency)
// ============================================================================

mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: Vec<u8>) -> String {
        let mut s = String::with_capacity(data.len() * 2);
        for byte in data {
            s.push(HEX_CHARS[(byte >> 4) as usize] as char);
            s.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        s
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::tor::mock_control::{self, MockTorControlServer};
    use tempfile::TempDir;

    // === ControlAuth parsing ===

    #[test]
    fn test_control_auth_cookie_default() {
        let auth = ControlAuth::from_config("cookie", "/var/run/tor/cookie").unwrap();
        match auth {
            ControlAuth::Cookie(path) => assert_eq!(path, Path::new("/var/run/tor/cookie")),
            _ => panic!("expected Cookie"),
        }
    }

    #[test]
    fn test_control_auth_cookie_custom_path() {
        let auth = ControlAuth::from_config("cookie:/tmp/my_cookie", "/default").unwrap();
        match auth {
            ControlAuth::Cookie(path) => assert_eq!(path, Path::new("/tmp/my_cookie")),
            _ => panic!("expected Cookie"),
        }
    }

    #[test]
    fn test_control_auth_password() {
        let auth = ControlAuth::from_config("password:mypass", "/default").unwrap();
        match auth {
            ControlAuth::Password(p) => assert_eq!(p, "mypass"),
            _ => panic!("expected Password"),
        }
    }

    #[test]
    fn test_control_auth_invalid() {
        let result = ControlAuth::from_config("unknown", "/default");
        assert!(result.is_err());
    }

    // === Hex encoding ===

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex::encode(vec![0xde, 0xad, 0xbe, 0xef]), "deadbeef");
        assert_eq!(hex::encode(vec![0x00, 0xff]), "00ff");
    }

    // === Unix socket path detection ===

    #[test]
    fn test_is_unix_socket_path() {
        assert!(is_unix_socket_path("/run/tor/control"));
        assert!(is_unix_socket_path("/var/run/tor/control"));
        assert!(is_unix_socket_path("./tor-control.sock"));
        assert!(!is_unix_socket_path("127.0.0.1:9051"));
        assert!(!is_unix_socket_path("tor-daemon:9051"));
        assert!(!is_unix_socket_path("localhost:9051"));
    }

    #[tokio::test]
    async fn test_connect_unix_socket_nonexistent() {
        let result = TorControlClient::connect("/tmp/nonexistent-tor-control.sock").await;
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("control socket"));
    }

    #[tokio::test]
    async fn test_connect_unix_socket_roundtrip() {
        // Create a Unix socket listener, accept a connection, respond to AUTHENTICATE
        let dir = TempDir::new().unwrap();
        let sock_path = dir.path().join("control.sock");
        let sock_path_str = sock_path.to_str().unwrap().to_string();

        let listener = tokio::net::UnixListener::bind(&sock_path).unwrap();

        // Spawn a minimal control handler
        let handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = stream.into_split();
            let mut reader = tokio::io::BufReader::new(reader);
            let mut line = String::new();

            // Read AUTHENTICATE
            reader.read_line(&mut line).await.unwrap();
            assert!(line.starts_with("AUTHENTICATE"));

            use tokio::io::AsyncWriteExt;
            writer.write_all(b"250 OK\r\n").await.unwrap();
            writer.flush().await.unwrap();
        });

        let mut client = TorControlClient::connect(&sock_path_str).await.unwrap();
        let auth = ControlAuth::Password("test".to_string());
        client.authenticate(&auth).await.unwrap();

        handle.await.unwrap();
    }

    // === Cookie file ===

    #[test]
    fn test_read_cookie_file_valid() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cookie");
        let cookie_data = vec![0xAA; 32];
        std::fs::write(&path, &cookie_data).unwrap();

        let loaded = read_cookie_file(&path).unwrap();
        assert_eq!(loaded, cookie_data);
    }

    #[test]
    fn test_read_cookie_file_wrong_size() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("cookie");
        std::fs::write(&path, [0u8; 16]).unwrap();

        assert!(read_cookie_file(&path).is_err());
    }

    #[test]
    fn test_read_cookie_file_nonexistent() {
        assert!(read_cookie_file(Path::new("/nonexistent/cookie")).is_err());
    }

    // === Control protocol (requires mock server) ===

    #[tokio::test]
    async fn test_authenticate_password() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();

        let auth = ControlAuth::Password("testpass".to_string());
        client.authenticate(&auth).await.unwrap();
    }

    #[tokio::test]
    async fn test_authenticate_cookie() {
        let mock = MockTorControlServer::start().await;

        // Create a cookie file
        let dir = TempDir::new().unwrap();
        let cookie_path = dir.path().join("cookie");
        std::fs::write(&cookie_path, [0xAA; 32]).unwrap();

        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();
        let auth = ControlAuth::Cookie(cookie_path);
        client.authenticate(&auth).await.unwrap();
    }

    #[tokio::test]
    async fn test_get_bootstrap_phase() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();

        let auth = ControlAuth::Password("testpass".to_string());
        client.authenticate(&auth).await.unwrap();

        let progress = client.get_bootstrap_phase().await.unwrap();
        assert_eq!(progress, 100);
    }

    #[tokio::test]
    async fn test_auth_failure() {
        let mock = MockTorControlServer::start_with_options(mock_control::MockOptions {
            reject_auth: true,
        })
        .await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();

        let auth = ControlAuth::Password("wrongpass".to_string());
        let result = client.authenticate(&auth).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_connect_to_closed_port() {
        // Bind and immediately drop to get a port that's closed
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);

        let result = TorControlClient::connect(&addr.to_string()).await;
        assert!(result.is_err());
    }

    // === Monitoring queries ===

    #[tokio::test]
    async fn test_is_circuit_established() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();
        client
            .authenticate(&ControlAuth::Password("test".into()))
            .await
            .unwrap();

        assert!(client.is_circuit_established().await.unwrap());
    }

    #[tokio::test]
    async fn test_traffic_counters() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();
        client
            .authenticate(&ControlAuth::Password("test".into()))
            .await
            .unwrap();

        assert_eq!(client.traffic_read().await.unwrap(), 1048576);
        assert_eq!(client.traffic_written().await.unwrap(), 524288);
    }

    #[tokio::test]
    async fn test_network_liveness() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();
        client
            .authenticate(&ControlAuth::Password("test".into()))
            .await
            .unwrap();

        assert_eq!(client.network_liveness().await.unwrap(), "up");
    }

    #[tokio::test]
    async fn test_version() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();
        client
            .authenticate(&ControlAuth::Password("test".into()))
            .await
            .unwrap();

        assert_eq!(client.version().await.unwrap(), "0.4.8.10");
    }

    #[tokio::test]
    async fn test_dormant() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();
        client
            .authenticate(&ControlAuth::Password("test".into()))
            .await
            .unwrap();

        assert!(!client.is_dormant().await.unwrap());
    }

    #[tokio::test]
    async fn test_socks_listeners() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();
        client
            .authenticate(&ControlAuth::Password("test".into()))
            .await
            .unwrap();

        let listeners = client.socks_listeners().await.unwrap();
        assert_eq!(listeners, vec!["127.0.0.1:9050"]);
    }

    #[tokio::test]
    async fn test_monitoring_snapshot() {
        let mock = MockTorControlServer::start().await;
        let mut client = TorControlClient::connect(&mock.addr().to_string())
            .await
            .unwrap();
        client
            .authenticate(&ControlAuth::Password("test".into()))
            .await
            .unwrap();

        let info = client.monitoring_snapshot().await.unwrap();
        assert_eq!(info.bootstrap, 100);
        assert!(info.circuit_established);
        assert_eq!(info.traffic_read, 1048576);
        assert_eq!(info.traffic_written, 524288);
        assert_eq!(info.network_liveness, "up");
        assert_eq!(info.version, "0.4.8.10");
        assert!(!info.dormant);
    }
}
