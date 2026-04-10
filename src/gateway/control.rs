//! Gateway control socket for runtime status queries.
//!
//! Provides a Unix domain socket that accepts JSON commands and returns
//! structured responses. Uses the same line-delimited JSON protocol as
//! the daemon control socket: one JSON line in, one JSON line out, then
//! close.

use crate::control::protocol::{Request, Response};
use crate::gateway::pool::{MappingInfo, MappingState, PoolStatus};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::sync::watch;
use tracing::{debug, info, warn};

/// Socket path for the gateway control socket.
pub const GATEWAY_SOCKET_PATH: &str = "/run/fips/gateway.sock";

/// Maximum request size in bytes (4 KB).
const MAX_REQUEST_SIZE: usize = 4096;

/// I/O timeout for client connections.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Snapshot of gateway state published by the main loop.
#[derive(Clone)]
pub struct GatewaySnapshot {
    pub pool: PoolStatus,
    pub mappings: Vec<MappingInfo>,
    pub nat_mappings: usize,
    pub dns_listen: String,
    pub uptime_secs: u64,
    // Config fields
    pub pool_cidr: String,
    pub lan_interface: String,
    pub dns_upstream: String,
    pub dns_ttl: u32,
    pub pool_grace_period: u64,
}

/// Gateway control socket listener.
pub struct GatewayControlSocket {
    listener: UnixListener,
    socket_path: PathBuf,
}

impl GatewayControlSocket {
    /// Bind the gateway control socket.
    ///
    /// Creates parent directories if needed, removes stale socket files,
    /// and sets `root:fips 0770` permissions.
    pub fn bind() -> Result<Self, std::io::Error> {
        let socket_path = PathBuf::from(GATEWAY_SOCKET_PATH);

        // Create parent directory if it doesn't exist
        if let Some(parent) = socket_path.parent()
            && !parent.exists()
        {
            std::fs::create_dir_all(parent)?;
            debug!(path = %parent.display(), "Created gateway control socket directory");
        }

        // Remove stale socket if it exists
        if socket_path.exists() {
            Self::remove_stale_socket(&socket_path)?;
        }

        let listener = UnixListener::bind(&socket_path)?;

        // Set permissions to 0770 and chown to fips group
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o770))?;
        Self::chown_to_fips_group(&socket_path);
        if let Some(parent) = socket_path.parent() {
            Self::chown_to_fips_group(parent);
        }

        info!(path = %socket_path.display(), "Gateway control socket listening");

        Ok(Self {
            listener,
            socket_path,
        })
    }

    /// Remove a stale socket file from a previous unclean exit.
    fn remove_stale_socket(path: &Path) -> Result<(), std::io::Error> {
        match std::os::unix::net::UnixStream::connect(path) {
            Ok(_) => Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("gateway control socket already in use: {}", path.display()),
            )),
            Err(_) => {
                debug!(path = %path.display(), "Removing stale gateway control socket");
                std::fs::remove_file(path)?;
                Ok(())
            }
        }
    }

    /// Set group ownership to the `fips` group (best-effort).
    fn chown_to_fips_group(path: &Path) {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

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
                "Failed to chown gateway control socket to 'fips' group"
            );
        }
    }

    /// Run the accept loop, reading the latest snapshot from the watch channel.
    pub async fn accept_loop(self, snapshot_rx: watch::Receiver<Option<GatewaySnapshot>>) {
        loop {
            let (stream, _addr) = match self.listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "Gateway control socket accept failed");
                    continue;
                }
            };

            let rx = snapshot_rx.clone();
            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(stream, rx).await {
                    debug!(error = %e, "Gateway control connection error");
                }
            });
        }
    }

    /// Handle a single client connection.
    async fn handle_connection(
        stream: tokio::net::UnixStream,
        snapshot_rx: watch::Receiver<Option<GatewaySnapshot>>,
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
                    break;
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
            Ok(Ok(())) => match serde_json::from_str::<Request>(line.trim()) {
                Ok(request) => dispatch_command(&request.command, &snapshot_rx),
                Err(e) => Response::error(format!("invalid request: {e}")),
            },
            Ok(Err(e)) => Response::error(format!("read error: {e}")),
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
            debug!("Gateway control socket write failed or timed out");
        }

        Ok(())
    }

    /// Clean up the socket file.
    fn cleanup(&self) {
        if self.socket_path.exists() {
            if let Err(e) = std::fs::remove_file(&self.socket_path) {
                warn!(
                    path = %self.socket_path.display(),
                    error = %e,
                    "Failed to remove gateway control socket"
                );
            } else {
                debug!(path = %self.socket_path.display(), "Gateway control socket removed");
            }
        }
    }
}

impl Drop for GatewayControlSocket {
    fn drop(&mut self) {
        self.cleanup();
    }
}

/// Dispatch a command against the latest gateway snapshot.
fn dispatch_command(
    command: &str,
    snapshot_rx: &watch::Receiver<Option<GatewaySnapshot>>,
) -> Response {
    let snapshot = match snapshot_rx.borrow().clone() {
        Some(s) => s,
        None => return Response::error("gateway not yet initialized"),
    };

    match command {
        "show_gateway" => build_show_gateway(&snapshot),
        "show_mappings" => build_show_mappings(&snapshot),
        _ => Response::error(format!("unknown command: {command}")),
    }
}

/// Build the `show_gateway` response with pool utilization summary.
fn build_show_gateway(snapshot: &GatewaySnapshot) -> Response {
    Response::ok(serde_json::json!({
        "pool_total": snapshot.pool.total,
        "pool_allocated": snapshot.pool.allocated,
        "pool_active": snapshot.pool.active,
        "pool_draining": snapshot.pool.draining,
        "pool_free": snapshot.pool.free,
        "nat_mappings": snapshot.nat_mappings,
        "dns_listen": snapshot.dns_listen,
        "uptime_secs": snapshot.uptime_secs,
        "pool_cidr": snapshot.pool_cidr,
        "lan_interface": snapshot.lan_interface,
        "dns_upstream": snapshot.dns_upstream,
        "dns_ttl": snapshot.dns_ttl,
        "pool_grace_period": snapshot.pool_grace_period,
    }))
}

/// Build the `show_mappings` response with per-mapping detail.
fn build_show_mappings(snapshot: &GatewaySnapshot) -> Response {
    let mappings: Vec<serde_json::Value> = snapshot
        .mappings
        .iter()
        .map(|m| {
            serde_json::json!({
                "virtual_ip": m.virtual_ip.to_string(),
                "mesh_addr": m.mesh_addr.to_string(),
                "node_addr": m.node_addr.to_string(),
                "dns_name": m.dns_name,
                "state": mapping_state_str(m.state),
                "sessions": m.session_count,
                "age_secs": m.age_secs,
                "last_ref_secs": m.last_ref_secs,
            })
        })
        .collect();

    Response::ok(serde_json::json!({ "mappings": mappings }))
}

/// Convert MappingState to a display string.
fn mapping_state_str(state: MappingState) -> &'static str {
    match state {
        MappingState::Allocated => "Allocated",
        MappingState::Active => "Active",
        MappingState::Draining => "Draining",
    }
}

/// Static gateway configuration for snapshot building.
pub struct SnapshotConfig {
    pub pool_cidr: String,
    pub lan_interface: String,
    pub dns_upstream: String,
    pub dns_listen: String,
    pub dns_ttl: u32,
    pub pool_grace_period: u64,
}

/// Build a `GatewaySnapshot` from current component state.
///
/// Called from the pool tick task to publish updated status.
pub fn build_snapshot(
    pool_status: PoolStatus,
    mappings: Vec<MappingInfo>,
    nat_mappings: usize,
    start_time: Instant,
    config: &SnapshotConfig,
) -> GatewaySnapshot {
    GatewaySnapshot {
        pool: pool_status,
        mappings,
        nat_mappings,
        dns_listen: config.dns_listen.clone(),
        uptime_secs: start_time.elapsed().as_secs(),
        pool_cidr: config.pool_cidr.clone(),
        lan_interface: config.lan_interface.clone(),
        dns_upstream: config.dns_upstream.clone(),
        dns_ttl: config.dns_ttl,
        pool_grace_period: config.pool_grace_period,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NodeAddr;

    fn make_snapshot() -> GatewaySnapshot {
        GatewaySnapshot {
            pool: PoolStatus {
                total: 65535,
                allocated: 1,
                active: 0,
                draining: 0,
                free: 65534,
            },
            mappings: vec![MappingInfo {
                virtual_ip: "fd01::1".parse().unwrap(),
                mesh_addr: "fd97:467a::1".parse().unwrap(),
                node_addr: NodeAddr::from_bytes([0; 16]),
                dns_name: "npub1test.fips".to_string(),
                state: MappingState::Active,
                session_count: 3,
                age_secs: 120,
                last_ref_secs: 5,
            }],
            nat_mappings: 1,
            dns_listen: "[fd02::10]:53".to_string(),
            uptime_secs: 3600,
            pool_cidr: "fd01::/112".to_string(),
            lan_interface: "br-lan".to_string(),
            dns_upstream: "127.0.0.1:5354".to_string(),
            dns_ttl: 60,
            pool_grace_period: 60,
        }
    }

    #[test]
    fn test_show_gateway_response() {
        let snapshot = make_snapshot();
        let resp = build_show_gateway(&snapshot);
        assert_eq!(resp.status, "ok");
        let data = resp.data.unwrap();
        assert_eq!(data["pool_total"], 65535);
        assert_eq!(data["pool_free"], 65534);
        assert_eq!(data["nat_mappings"], 1);
        assert_eq!(data["dns_listen"], "[fd02::10]:53");
        assert_eq!(data["uptime_secs"], 3600);
    }

    #[test]
    fn test_show_mappings_response() {
        let snapshot = make_snapshot();
        let resp = build_show_mappings(&snapshot);
        assert_eq!(resp.status, "ok");
        let data = resp.data.unwrap();
        let mappings = data["mappings"].as_array().unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0]["state"], "Active");
        assert_eq!(mappings[0]["sessions"], 3);
        assert_eq!(mappings[0]["virtual_ip"], "fd01::1");
    }

    #[test]
    fn test_unknown_command() {
        let (tx, rx) = watch::channel(Some(make_snapshot()));
        let resp = dispatch_command("bogus", &rx);
        assert_eq!(resp.status, "error");
        assert!(resp.message.unwrap().contains("unknown command: bogus"));
        drop(tx);
    }

    #[test]
    fn test_not_initialized() {
        let (tx, rx) = watch::channel::<Option<GatewaySnapshot>>(None);
        let resp = dispatch_command("show_gateway", &rx);
        assert_eq!(resp.status, "error");
        assert!(resp.message.unwrap().contains("not yet initialized"));
        drop(tx);
    }

    #[test]
    fn test_mapping_state_str() {
        assert_eq!(mapping_state_str(MappingState::Allocated), "Allocated");
        assert_eq!(mapping_state_str(MappingState::Active), "Active");
        assert_eq!(mapping_state_str(MappingState::Draining), "Draining");
    }

    #[test]
    fn test_empty_mappings() {
        let snapshot = GatewaySnapshot {
            pool: PoolStatus {
                total: 255,
                allocated: 0,
                active: 0,
                draining: 0,
                free: 255,
            },
            mappings: vec![],
            nat_mappings: 0,
            dns_listen: "[::1]:53".to_string(),
            uptime_secs: 0,
            pool_cidr: "fd01::/112".to_string(),
            lan_interface: "br-lan".to_string(),
            dns_upstream: "127.0.0.1:5354".to_string(),
            dns_ttl: 60,
            pool_grace_period: 60,
        };
        let resp = build_show_mappings(&snapshot);
        assert_eq!(resp.status, "ok");
        let data = resp.data.unwrap();
        let mappings = data["mappings"].as_array().unwrap();
        assert!(mappings.is_empty());
    }
}
