//! FIPS Configuration System
//!
//! Loads configuration from YAML files with a cascading priority system:
//! 1. `./fips.yaml` (current directory - highest priority)
//! 2. `~/.config/fips/fips.yaml` (user config directory)
//! 3. `/etc/fips/fips.yaml` (system - lowest priority)
//!
//! Values from higher priority files override those from lower priority files.
//!
//! # YAML Structure
//!
//! The YAML structure mirrors the sysctl-style paths in the architecture docs.
//! For example, `node.identity.nsec` in the docs corresponds to:
//!
//! ```yaml
//! node:
//!   identity:
//!     nsec: "nsec1..."
//! ```

#[cfg(target_os = "linux")]
mod gateway;
mod node;
mod peer;
mod transport;

use crate::upper::config::{DnsConfig, TunConfig};
use crate::{Identity, IdentityError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[cfg(target_os = "linux")]
pub use gateway::{ConntrackConfig, GatewayConfig, GatewayDnsConfig, PortForward, Proto};
pub use node::{
    BloomConfig, BuffersConfig, CacheConfig, ControlConfig, LimitsConfig, LookupConfig, MmpConfig,
    NodeConfig, NostrRendezvousConfig, NostrRendezvousPolicy, RateLimitConfig, RekeyConfig,
    RendezvousConfig, RetryConfig, SessionConfig, SessionMmpConfig, TreeConfig,
};
pub use peer::{ConnectPolicy, PeerAddress, PeerConfig};
pub use transport::{
    BleConfig, DirectoryServiceConfig, EthernetConfig, NymConfig, TcpConfig, TorConfig,
    TransportInstances, TransportsConfig, UdpConfig,
};

/// Default config filename.
const CONFIG_FILENAME: &str = "fips.yaml";

/// Default key filename, placed alongside the config file.
const KEY_FILENAME: &str = "fips.key";

/// Default public key filename, placed alongside the key file.
const PUB_FILENAME: &str = "fips.pub";

/// Returns true if the textual `host:port` form refers to a loopback host.
/// Recognizes IPv4 `127.x.x.x`, IPv6 `::1` (with or without brackets), and
/// the literal string `localhost`. Hostnames are conservatively assumed to
/// be non-loopback. Used by `Config::validate()` to reject misconfigured
/// loopback UDP binds combined with non-loopback peer addresses (see
/// ISSUE-2026-0005).
fn is_loopback_addr_str(addr: &str) -> bool {
    // Bracketed IPv6: `[::1]:port`
    if let Some(rest) = addr.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        let host = &rest[..end];
        return host == "::1";
    }
    // Plain `host:port` — split on the rightmost ':'.
    let host = match addr.rsplit_once(':') {
        Some((h, _)) => h,
        None => addr,
    };
    host == "localhost" || host == "::1" || host == "0:0:0:0:0:0:0:1" || host.starts_with("127.")
}

/// Derive the key file path from a config file path.
pub fn key_file_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(KEY_FILENAME)
}

/// Derive the public key file path from a config file path.
pub fn pub_file_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(PUB_FILENAME)
}

/// Resolve a default Unix-socket path under the canonical order:
/// `/run/fips/<filename>` → `$XDG_RUNTIME_DIR/fips/<filename>` → `/tmp/fips-<filename>`.
///
/// `/run/fips` is the packaged convention (`root:fips 0770` directory
/// created by the daemon at bind time, or by the postinst script).
/// `XDG_RUNTIME_DIR` covers dev runs where `/run/fips` does not exist.
/// `/tmp` is the last-resort fallback.
///
/// Selection is by *existence*, not writability. A fips-group member
/// whose shell session has not picked up the supplementary group (no
/// re-login after `usermod -aG fips`) cannot tempfile-probe a
/// `root:fips 0770` directory but can still connect to a socket inside
/// it once the kernel checks the actual group at `connect(2)` time —
/// and even where the user genuinely cannot connect, surfacing an
/// `EACCES` from the socket call is clearer than silently steering
/// fipstop / fipsctl to a path the daemon never bound. The daemon's
/// own bind code (`ControlSocket::bind`) creates `/run/fips` if it is
/// missing, so the resolver does not need to materialize the directory
/// itself.
///
/// `XDG_RUNTIME_DIR` is validated as an existing directory before being
/// used; a stale post-logout value (after `pam_systemd` reaps the dir)
/// is treated as missing.
#[cfg(unix)]
pub(crate) fn resolve_default_socket(filename: &str) -> String {
    // 1. /run/fips — preferred whenever the directory exists.
    if Path::new("/run/fips").is_dir() {
        return format!("/run/fips/{filename}");
    }

    // 2. $XDG_RUNTIME_DIR/fips/ — only if the variable points at an existing
    //    directory.
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        let xdg_path = Path::new(&xdg);
        if xdg_path.is_dir() {
            return format!("{xdg}/fips/{filename}");
        }
    }

    // 3. Last resort: /tmp with a name-mangled prefix so multiple users
    //    don't collide.
    format!("/tmp/fips-{filename}")
}

/// Default control socket path for fipsctl / fipstop.
///
/// On Unix, delegates to [`resolve_default_socket`] for the canonical
/// `/run/fips` → `XDG_RUNTIME_DIR` → `/tmp` order. On Windows, returns the
/// default TCP port ("21210").
pub fn default_control_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(resolve_default_socket("control.sock"))
    }
    #[cfg(windows)]
    {
        PathBuf::from("21210")
    }
}

/// Default gateway control socket path.
///
/// On Unix, delegates to [`resolve_default_socket`] (same canonical order as
/// the main control socket). The gateway daemon itself uses a hardcoded
/// `/run/fips/gateway.sock` since gateway operation requires root for
/// NAT/conntrack management; this client-side resolver falls through
/// gracefully for non-root dev runs that need a gateway socket path. On
/// Windows, returns a placeholder TCP port ("21211").
pub fn default_gateway_path() -> PathBuf {
    #[cfg(unix)]
    {
        PathBuf::from(resolve_default_socket("gateway.sock"))
    }
    #[cfg(windows)]
    {
        PathBuf::from("21211")
    }
}

/// Read a bare bech32 nsec from a key file.
pub fn read_key_file(path: &Path) -> Result<String, ConfigError> {
    let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
        path: path.to_path_buf(),
        source: e,
    })?;
    let nsec = contents.trim().to_string();
    if nsec.is_empty() {
        return Err(ConfigError::EmptyKeyFile {
            path: path.to_path_buf(),
        });
    }
    Ok(nsec)
}

/// Write a bare bech32 nsec to a key file with restricted permissions.
///
/// On Unix, the file is created with mode 0600 (owner read/write only).
/// On Windows, the file inherits default ACLs from the parent directory.
pub fn write_key_file(path: &Path, nsec: &str) -> Result<(), ConfigError> {
    use std::io::Write;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut file = opts.open(path).map_err(|e| ConfigError::WriteKeyFile {
        path: path.to_path_buf(),
        source: e,
    })?;

    file.write_all(nsec.as_bytes())
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(b"\n")
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(())
}

/// Write a bare bech32 npub to a public key file.
///
/// On Unix, the file is created with mode 0644 (owner read/write, others read).
/// On Windows, the file inherits default ACLs from the parent directory.
pub fn write_pub_file(path: &Path, npub: &str) -> Result<(), ConfigError> {
    use std::io::Write;

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o644);
    }

    let mut file = opts.open(path).map_err(|e| ConfigError::WriteKeyFile {
        path: path.to_path_buf(),
        source: e,
    })?;

    file.write_all(npub.as_bytes())
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    file.write_all(b"\n")
        .map_err(|e| ConfigError::WriteKeyFile {
            path: path.to_path_buf(),
            source: e,
        })?;
    Ok(())
}

/// Resolve identity from config and key file.
///
/// Behavior depends on `node.identity.persistent`:
///
/// - **`persistent: false`** (default): generate a fresh ephemeral keypair
///   every start. Key files are written for operator visibility but overwritten
///   on each restart.
///
/// - **`persistent: true`**: use three-tier resolution:
///   1. Explicit nsec in config — highest priority
///   2. Persistent key file (`fips.key`) — reused across restarts
///   3. Generate new — creates keypair, writes `fips.key` and `fips.pub`
///
/// - **`nsec` set explicitly**: always uses that, regardless of `persistent`.
///
/// Returns the nsec string (bech32 or hex) to be used for identity creation.
pub fn resolve_identity(
    config: &Config,
    loaded_paths: &[PathBuf],
) -> Result<ResolvedIdentity, ConfigError> {
    use crate::encode_nsec;

    // Explicit nsec in config always wins
    if let Some(nsec) = &config.node.identity.nsec {
        return Ok(ResolvedIdentity {
            nsec: nsec.clone(),
            source: IdentitySource::Config,
        });
    }

    // Determine key file directory from loaded config paths
    let config_ref = if let Some(path) = loaded_paths.last() {
        path.clone()
    } else {
        Config::search_paths()
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("./fips.yaml"))
    };
    let key_path = key_file_path(&config_ref);
    let pub_path = pub_file_path(&config_ref);

    if config.node.identity.persistent {
        // Persistent mode: load existing key file or generate-and-persist
        if key_path.exists() {
            let nsec = read_key_file(&key_path)?;
            let identity = Identity::from_secret_str(&nsec)?;
            let _ = write_pub_file(&pub_path, &identity.npub());
            return Ok(ResolvedIdentity {
                nsec,
                source: IdentitySource::KeyFile(key_path),
            });
        }

        // No key file yet — generate and persist
        let identity = Identity::generate();
        let nsec = encode_nsec(&identity.keypair().secret_key());
        let npub = identity.npub();

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match write_key_file(&key_path, &nsec) {
            Ok(()) => {
                let _ = write_pub_file(&pub_path, &npub);
                Ok(ResolvedIdentity {
                    nsec,
                    source: IdentitySource::Generated(key_path),
                })
            }
            Err(_) => Ok(ResolvedIdentity {
                nsec,
                source: IdentitySource::Ephemeral,
            }),
        }
    } else {
        // Ephemeral mode (default): fresh keypair every start, write key files
        // for operator visibility
        let identity = Identity::generate();
        let nsec = encode_nsec(&identity.keypair().secret_key());
        let npub = identity.npub();

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let _ = write_key_file(&key_path, &nsec);
        let _ = write_pub_file(&pub_path, &npub);

        Ok(ResolvedIdentity {
            nsec,
            source: IdentitySource::Ephemeral,
        })
    }
}

/// Result of identity resolution.
pub struct ResolvedIdentity {
    /// The nsec string (bech32 or hex) for creating an Identity.
    pub nsec: String,
    /// Where the identity came from.
    pub source: IdentitySource,
}

/// Where a resolved identity originated.
pub enum IdentitySource {
    /// From explicit nsec in config file.
    Config,
    /// Loaded from a persistent key file.
    KeyFile(PathBuf),
    /// Generated and saved to a new key file.
    Generated(PathBuf),
    /// Generated but could not be persisted.
    Ephemeral,
}

/// Errors that can occur during configuration loading.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read config file {path}: {source}")]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("failed to parse config file {path}: {source}")]
    ParseYaml {
        path: PathBuf,
        source: serde_yaml::Error,
    },

    #[error("key file is empty: {path}")]
    EmptyKeyFile { path: PathBuf },

    #[error("failed to write key file {path}: {source}")]
    WriteKeyFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),

    #[error("invalid configuration: {0}")]
    Validation(String),
}

/// Identity configuration (`node.identity.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdentityConfig {
    /// Secret key in nsec (bech32) or hex format (`node.identity.nsec`).
    /// If not specified, a new keypair will be generated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nsec: Option<String>,

    /// Whether to persist the identity across restarts (`node.identity.persistent`).
    /// When false (default), a fresh ephemeral keypair is generated each start.
    /// When true, the key file is reused across restarts.
    #[serde(default)]
    pub persistent: bool,
}

/// Root configuration structure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// Node configuration (`node.*`).
    #[serde(default)]
    pub node: NodeConfig,

    /// TUN interface configuration (`tun.*`).
    #[serde(default)]
    pub tun: TunConfig,

    /// DNS responder configuration (`dns.*`).
    #[serde(default)]
    pub dns: DnsConfig,

    /// Transport instances (`transports.*`).
    #[serde(default, skip_serializing_if = "TransportsConfig::is_empty")]
    pub transports: TransportsConfig,

    /// Static peers to connect to (`peers`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub peers: Vec<PeerConfig>,

    /// Gateway configuration (`gateway`).
    #[cfg(target_os = "linux")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewayConfig>,
}

impl Config {
    /// Create a new empty configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from the standard search paths.
    ///
    /// Files are loaded in reverse priority order and merged:
    /// 1. `/etc/fips/fips.yaml` (loaded first, lowest priority)
    /// 2. `~/.config/fips/fips.yaml` (user config)
    /// 3. `./fips.yaml` (loaded last, highest priority)
    ///
    /// Returns a tuple of (config, paths_loaded) where paths_loaded contains
    /// the paths that were successfully loaded.
    pub fn load() -> Result<(Self, Vec<PathBuf>), ConfigError> {
        let search_paths = Self::search_paths();
        Self::load_from_paths(&search_paths)
    }

    /// Load configuration from specific paths.
    ///
    /// Paths are processed in order, with later paths overriding earlier ones.
    pub fn load_from_paths(paths: &[PathBuf]) -> Result<(Self, Vec<PathBuf>), ConfigError> {
        let mut config = Config::default();
        let mut loaded_paths = Vec::new();

        for path in paths {
            if path.exists() {
                let file_config = Self::load_file(path)?;
                config.merge(file_config);
                loaded_paths.push(path.clone());
            }
        }

        Ok((config, loaded_paths))
    }

    /// Load configuration from a single file.
    pub fn load_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|e| ConfigError::ReadFile {
            path: path.to_path_buf(),
            source: e,
        })?;

        let mut config: Config =
            serde_yaml::from_str(&contents).map_err(|e| ConfigError::ParseYaml {
                path: path.to_path_buf(),
                source: e,
            })?;
        config.normalize_deprecated_keys();
        Ok(config)
    }

    /// COMPAT (drop at the v2 cutover): fold a deprecated `node.discovery:`
    /// block into the `node.lookup.*` (mesh-lookup scalars) and
    /// `node.rendezvous.*` (nostr/LAN peer rendezvous) tables that replaced it.
    ///
    /// Runs at every deserialize boundary (see `load_file`). A present legacy
    /// field fills the corresponding new-table field, so a config that predates
    /// the split keeps behaving identically. When a legacy block is seen, a
    /// one-time deprecation warning names the old→new key moves. Exposed to the
    /// crate so config tests that deserialize directly can invoke it.
    pub(crate) fn normalize_deprecated_keys(&mut self) {
        let Some(compat) = self.node.discovery.take() else {
            return;
        };
        tracing::warn!(
            target: "fips::config",
            "`node.discovery.*` is deprecated and will be removed: mesh-lookup \
             scalars moved to `node.lookup.*`, and peer-rendezvous keys moved to \
             `node.rendezvous.nostr.*` / `node.rendezvous.lan.*`. Please migrate; \
             a legacy `node.discovery` block still applies for now."
        );
        if let Some(v) = compat.ttl {
            self.node.lookup.ttl = v;
        }
        if let Some(v) = compat.attempt_timeouts_secs {
            self.node.lookup.attempt_timeouts_secs = v;
        }
        if let Some(v) = compat.recent_expiry_secs {
            self.node.lookup.recent_expiry_secs = v;
        }
        if let Some(v) = compat.backoff_base_secs {
            self.node.lookup.backoff_base_secs = v;
        }
        if let Some(v) = compat.backoff_max_secs {
            self.node.lookup.backoff_max_secs = v;
        }
        if let Some(v) = compat.forward_min_interval_secs {
            self.node.lookup.forward_min_interval_secs = v;
        }
        if let Some(v) = compat.nostr {
            self.node.rendezvous.nostr = v;
        }
        if let Some(v) = compat.lan {
            self.node.rendezvous.lan = v;
        }
    }

    /// Get the standard search paths in priority order (lowest to highest).
    pub fn search_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // System config (lowest priority)
        paths.push(PathBuf::from("/etc/fips").join(CONFIG_FILENAME));

        // User config directory
        if let Some(config_dir) = dirs::config_dir() {
            paths.push(config_dir.join("fips").join(CONFIG_FILENAME));
        }

        // Home directory (legacy location)
        if let Some(home_dir) = dirs::home_dir() {
            paths.push(home_dir.join(".fips.yaml"));
        }

        // Current directory (highest priority)
        paths.push(PathBuf::from(".").join(CONFIG_FILENAME));

        paths
    }

    /// Merge another configuration into this one.
    ///
    /// Values from `other` override values in `self` when present.
    pub fn merge(&mut self, other: Config) {
        // Merge node.identity section
        if other.node.identity.nsec.is_some() {
            self.node.identity.nsec = other.node.identity.nsec;
        }
        if other.node.identity.persistent {
            self.node.identity.persistent = true;
        }
        // Merge node.leaf_only
        if other.node.leaf_only {
            self.node.leaf_only = true;
        }
        // Merge tun section
        if other.tun.enabled {
            self.tun.enabled = true;
        }
        if other.tun.name.is_some() {
            self.tun.name = other.tun.name;
        }
        if other.tun.mtu.is_some() {
            self.tun.mtu = other.tun.mtu;
        }
        // Merge dns section — higher-priority config always wins for enabled
        self.dns.enabled = other.dns.enabled;
        if other.dns.bind_addr.is_some() {
            self.dns.bind_addr = other.dns.bind_addr;
        }
        if other.dns.port.is_some() {
            self.dns.port = other.dns.port;
        }
        if other.dns.ttl.is_some() {
            self.dns.ttl = other.dns.ttl;
        }
        // Merge transports section
        self.transports.merge(other.transports);
        // Merge peers (replace if non-empty)
        if !other.peers.is_empty() {
            self.peers = other.peers;
        }
        // Merge gateway section — higher-priority config replaces entirely
        #[cfg(target_os = "linux")]
        if other.gateway.is_some() {
            self.gateway = other.gateway;
        }
    }

    /// Create an Identity from this configuration.
    ///
    /// If an nsec is configured, uses that to create the identity.
    /// Otherwise, generates a new random identity.
    pub fn create_identity(&self) -> Result<Identity, ConfigError> {
        match &self.node.identity.nsec {
            Some(nsec) => Ok(Identity::from_secret_str(nsec)?),
            None => Ok(Identity::generate()),
        }
    }

    /// Check if an identity is configured (vs. will be generated).
    pub fn has_identity(&self) -> bool {
        self.node.identity.nsec.is_some()
    }

    /// Check if leaf-only mode is configured.
    pub fn is_leaf_only(&self) -> bool {
        self.node.leaf_only
    }

    /// Get the configured peers.
    pub fn peers(&self) -> &[PeerConfig] {
        &self.peers
    }

    /// Get peers that should auto-connect on startup.
    pub fn auto_connect_peers(&self) -> impl Iterator<Item = &PeerConfig> {
        self.peers.iter().filter(|p| p.is_auto_connect())
    }

    /// Validate cross-field configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let nostr = &self.node.rendezvous.nostr;

        let any_transport_advertises_on_nostr = self
            .transports
            .udp
            .iter()
            .any(|(_, cfg)| cfg.advertise_on_nostr())
            || self
                .transports
                .tcp
                .iter()
                .any(|(_, cfg)| cfg.advertise_on_nostr())
            || self
                .transports
                .tor
                .iter()
                .any(|(_, cfg)| cfg.advertise_on_nostr());

        if any_transport_advertises_on_nostr && !nostr.enabled {
            return Err(ConfigError::Validation(
                "at least one transport has `advertise_on_nostr = true`, but `node.rendezvous.nostr.enabled` is false".to_string(),
            ));
        }

        if self.peers.iter().any(|peer| peer.via_nostr) && !nostr.enabled {
            return Err(ConfigError::Validation(
                "at least one peer has `via_nostr = true`, but `node.rendezvous.nostr.enabled` is false".to_string(),
            ));
        }

        for (i, peer) in self.peers.iter().enumerate() {
            if peer.addresses.is_empty() && !peer.via_nostr {
                return Err(ConfigError::Validation(format!(
                    "peers[{i}] ({}): must specify at least one address, or set `via_nostr = true` to resolve endpoints from the Nostr advert",
                    peer.npub
                )));
            }
        }

        let has_nat_udp_advert = self
            .transports
            .udp
            .iter()
            .any(|(_, cfg)| cfg.advertise_on_nostr() && !cfg.is_public());

        if nostr.enabled && has_nat_udp_advert {
            if nostr.dm_relays.is_empty() {
                return Err(ConfigError::Validation(
                    "NAT UDP advert publishing requires `node.rendezvous.nostr.dm_relays` to be non-empty".to_string(),
                ));
            }
            if nostr.stun_servers.is_empty() {
                return Err(ConfigError::Validation(
                    "NAT UDP advert publishing requires `node.rendezvous.nostr.stun_servers` to be non-empty".to_string(),
                ));
            }
        }

        // Reject loopback UDP bind combined with non-loopback peer addresses.
        // Linux pins the source IP to a loopback-bound socket, so packets
        // sent from such a socket to external peers are dropped at the
        // routing layer with no clear error in the daemon log. See
        // ISSUE-2026-0005. Outbound-only mode is exempt because it
        // overrides bind_addr to 0.0.0.0:0 (kernel-picked source).
        for (name, cfg) in self.transports.udp.iter() {
            if cfg.outbound_only() {
                continue;
            }
            if is_loopback_addr_str(cfg.bind_addr()) {
                let any_external_peer = self.peers.iter().any(|peer| {
                    peer.addresses
                        .iter()
                        .any(|a| a.transport == "udp" && !is_loopback_addr_str(&a.addr))
                });
                if any_external_peer {
                    let label = name.unwrap_or("(unnamed)");
                    return Err(ConfigError::Validation(format!(
                        "transports.udp[{label}].bind_addr is loopback ({}) but at least one peer has a non-loopback UDP address; \
                         fips cannot reach external peers from a loopback-bound socket. \
                         Use bind_addr: \"0.0.0.0:2121\" (with kernel-firewall hardening if exposure is a concern), or set outbound_only: true.",
                        cfg.bind_addr()
                    )));
                }
            }
        }

        Ok(())
    }

    /// Serialize this configuration to YAML.
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_empty_config() {
        let config = Config::new();
        assert!(config.node.identity.nsec.is_none());
        assert!(!config.has_identity());
    }

    #[test]
    fn test_parse_yaml_with_nsec() {
        let yaml = r#"
node:
  identity:
    nsec: nsec1qyqsqypqxqszqg9qyqsqypqxqszqg9qyqsqypqxqszqg9qyqsqypqxfnm5g9
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_some());
        assert!(config.has_identity());
    }

    /// The fips.yaml shipped in the OpenWrt package must keep parsing as the
    /// config schema evolves. Both the 802.11s mesh backhaul entries
    /// (docs/how-to/set-up-80211s-mesh-backhaul.md) and the open-access SSID
    /// entries (docs/how-to/set-up-open-access-ssid.md) ship commented out —
    /// one per radio, so dual-band routers can run either on both bands — so
    /// a stock install that never creates fips-mesh*/fips-ap* logs no
    /// per-boot bind warning; `fips-mesh-setup`/`fips-ap-setup` uncomment the
    /// matching block when they create the interface. Verify both states
    /// parse: as shipped (both inactive), and after the uncomment the helpers
    /// perform.
    #[test]
    fn shipped_openwrt_config_parses() {
        let yaml = include_str!("../../packaging/openwrt-ipk/files/etc/fips/fips.yaml");

        // As shipped: parses, and the mesh/ap entries are commented out (a
        // running daemon binds no fips-mesh*/fips-ap* transport, no warning).
        let config: Config = serde_yaml::from_str(yaml).expect("shipped OpenWrt fips.yaml");
        for name in ["mesh0", "mesh1", "ap0", "ap1"] {
            assert!(
                !config
                    .transports
                    .ethernet
                    .iter()
                    .any(|(n, _)| n == Some(name)),
                "{name} must ship commented out, not active, in fips.yaml"
            );
        }

        // What `fips-mesh-setup`/`fips-ap-setup` produce: uncomment each
        // block, which must still parse into a transport bound to the right
        // netdev.
        let uncommented =
            uncomment_transport_blocks(&uncomment_transport_blocks(yaml, "mesh"), "ap");
        let config: Config = serde_yaml::from_str(&uncommented)
            .expect("fips.yaml with mesh and ap transports uncommented");
        for (name, interface) in [
            ("mesh0", "fips-mesh0"),
            ("mesh1", "fips-mesh1"),
            ("ap0", "fips-ap0"),
            ("ap1", "fips-ap1"),
        ] {
            assert!(
                config
                    .transports
                    .ethernet
                    .iter()
                    .any(|(n, eth)| n == Some(name) && eth.interface == interface),
                "{name} entry missing after uncommenting shipped fips.yaml"
            );
        }
    }

    /// Mirror the setup helpers' block uncomment: strip the `    # ` prefix
    /// from each `# <prefix><N>:` header and its `    #   ` continuation
    /// lines, leaving every other comment untouched.
    fn uncomment_transport_blocks(yaml: &str, prefix: &str) -> String {
        let header = format!("    # {prefix}");
        let mut out = String::new();
        let mut in_block = false;
        for line in yaml.lines() {
            let is_header = line
                .strip_prefix(&header)
                .and_then(|r| r.strip_suffix(':'))
                .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
            if is_header {
                in_block = true;
                out.push_str(&line.replacen("    # ", "    ", 1));
            } else if in_block && line.starts_with("    #   ") {
                out.push_str(&line.replacen("    # ", "    ", 1));
            } else {
                in_block = false;
                out.push_str(line);
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn test_parse_yaml_with_hex() {
        let yaml = r#"
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_some());

        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_parse_yaml_empty() {
        let yaml = "";
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_none());
    }

    #[test]
    fn test_parse_yaml_partial() {
        let yaml = r#"
node:
  identity: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.node.identity.nsec.is_none());
    }

    #[test]
    fn test_merge_configs() {
        let mut base = Config::new();
        base.node.identity.nsec = Some("base_nsec".to_string());

        let mut override_config = Config::new();
        override_config.node.identity.nsec = Some("override_nsec".to_string());

        base.merge(override_config);
        assert_eq!(base.node.identity.nsec, Some("override_nsec".to_string()));
    }

    #[test]
    fn test_merge_preserves_base_when_override_empty() {
        let mut base = Config::new();
        base.node.identity.nsec = Some("base_nsec".to_string());

        let override_config = Config::new();

        base.merge(override_config);
        assert_eq!(base.node.identity.nsec, Some("base_nsec".to_string()));
    }

    #[test]
    fn test_create_identity_from_nsec() {
        let mut config = Config::new();
        config.node.identity.nsec =
            Some("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string());

        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_create_identity_generates_new() {
        let config = Config::new();
        let identity = config.create_identity().unwrap();
        assert!(!identity.npub().is_empty());
    }

    #[test]
    fn test_load_from_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        let yaml = r#"
node:
  identity:
    nsec: "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
"#;
        fs::write(&config_path, yaml).unwrap();

        let config = Config::load_file(&config_path).unwrap();
        assert!(config.node.identity.nsec.is_some());
    }

    #[test]
    fn test_load_from_paths_merges() {
        let temp_dir = TempDir::new().unwrap();

        // Create two config files
        let low_priority = temp_dir.path().join("low.yaml");
        let high_priority = temp_dir.path().join("high.yaml");

        fs::write(
            &low_priority,
            r#"
node:
  identity:
    nsec: "low_priority_nsec"
"#,
        )
        .unwrap();

        fs::write(
            &high_priority,
            r#"
node:
  identity:
    nsec: "high_priority_nsec"
"#,
        )
        .unwrap();

        let paths = vec![low_priority.clone(), high_priority.clone()];
        let (config, loaded) = Config::load_from_paths(&paths).unwrap();

        assert_eq!(loaded.len(), 2);
        assert_eq!(
            config.node.identity.nsec,
            Some("high_priority_nsec".to_string())
        );
    }

    #[test]
    fn test_load_skips_missing_files() {
        let temp_dir = TempDir::new().unwrap();
        let existing = temp_dir.path().join("exists.yaml");
        let missing = temp_dir.path().join("missing.yaml");

        fs::write(
            &existing,
            r#"
node:
  identity:
    nsec: "existing_nsec"
"#,
        )
        .unwrap();

        let paths = vec![missing, existing.clone()];
        let (config, loaded) = Config::load_from_paths(&paths).unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0], existing);
        assert_eq!(config.node.identity.nsec, Some("existing_nsec".to_string()));
    }

    #[test]
    fn test_search_paths_includes_expected() {
        let paths = Config::search_paths();

        // Should include current directory
        assert!(paths.iter().any(|p| p.ends_with("fips.yaml")));

        // Should include /etc/fips on Unix
        #[cfg(unix)]
        assert!(
            paths
                .iter()
                .any(|p| p.starts_with("/etc/fips") && p.ends_with("fips.yaml"))
        );
    }

    #[test]
    fn test_to_yaml() {
        let mut config = Config::new();
        config.node.identity.nsec = Some("test_nsec".to_string());

        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("node:"));
        assert!(yaml.contains("identity:"));
        assert!(yaml.contains("nsec:"));
        assert!(yaml.contains("test_nsec"));
    }

    #[test]
    fn test_key_file_write_read_roundtrip() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        let identity = crate::Identity::generate();
        let nsec = crate::encode_nsec(&identity.keypair().secret_key());

        write_key_file(&key_path, &nsec).unwrap();

        let loaded_nsec = read_key_file(&key_path).unwrap();
        assert_eq!(loaded_nsec, nsec);

        // Verify the loaded nsec produces the same identity
        let loaded_identity = crate::Identity::from_secret_str(&loaded_nsec).unwrap();
        assert_eq!(loaded_identity.npub(), identity.npub());
    }

    #[cfg(unix)]
    #[test]
    fn test_key_file_permissions() {
        use std::os::unix::fs::MetadataExt;

        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        write_key_file(&key_path, "nsec1test").unwrap();

        let metadata = fs::metadata(&key_path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn test_pub_file_permissions() {
        use std::os::unix::fs::MetadataExt;

        let temp_dir = TempDir::new().unwrap();
        let pub_path = temp_dir.path().join("fips.pub");

        write_pub_file(&pub_path, "npub1test").unwrap();

        let metadata = fs::metadata(&pub_path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o644);
    }

    #[test]
    fn test_key_file_empty_error() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&key_path, "").unwrap();

        let result = read_key_file(&key_path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("empty"));
    }

    #[test]
    fn test_key_file_whitespace_trimmed() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&key_path, "  nsec1test  \n").unwrap();

        let nsec = read_key_file(&key_path).unwrap();
        assert_eq!(nsec, "nsec1test");
    }

    #[test]
    fn test_key_file_path_derivation() {
        let config_path = PathBuf::from("/etc/fips/fips.yaml");
        assert_eq!(
            key_file_path(&config_path),
            PathBuf::from("/etc/fips/fips.key")
        );
        assert_eq!(
            pub_file_path(&config_path),
            PathBuf::from("/etc/fips/fips.pub")
        );
    }

    #[cfg(windows)]
    #[test]
    fn test_key_file_write_read_roundtrip_windows() {
        let temp_dir = TempDir::new().unwrap();
        let key_path = temp_dir.path().join("fips.key");

        let identity = crate::Identity::generate();
        let nsec = crate::encode_nsec(&identity.keypair().secret_key());

        write_key_file(&key_path, &nsec).unwrap();

        // Verify file was created and can be read back
        let loaded_nsec = read_key_file(&key_path).unwrap();
        assert_eq!(loaded_nsec, nsec);

        // Verify the loaded nsec produces the same identity
        let loaded_identity = crate::Identity::from_secret_str(&loaded_nsec).unwrap();
        assert_eq!(loaded_identity.npub(), identity.npub());
    }

    #[test]
    fn test_resolve_identity_from_config() {
        let mut config = Config::new();
        config.node.identity.nsec =
            Some("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string());

        let resolved = resolve_identity(&config, &[]).unwrap();
        assert!(matches!(resolved.source, IdentitySource::Config));
    }

    #[test]
    fn test_resolve_identity_ephemeral_by_default() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

        let config = Config::load_file(&config_path).unwrap();
        assert!(!config.node.identity.persistent);

        let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
        assert!(matches!(resolved.source, IdentitySource::Ephemeral));

        // Key files should still be written for operator visibility
        let key_path = temp_dir.path().join("fips.key");
        let pub_path = temp_dir.path().join("fips.pub");
        assert!(key_path.exists());
        assert!(pub_path.exists());
    }

    #[test]
    fn test_resolve_identity_ephemeral_changes_each_call() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

        let config = Config::load_file(&config_path).unwrap();
        let first = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
        let second = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();

        // Each call generates a different key
        assert_ne!(first.nsec, second.nsec);
    }

    #[test]
    fn test_resolve_identity_persistent_from_key_file() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");
        let key_path = temp_dir.path().join("fips.key");

        fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();

        // Write a key file
        let identity = crate::Identity::generate();
        let nsec = crate::encode_nsec(&identity.keypair().secret_key());
        write_key_file(&key_path, &nsec).unwrap();

        let config = Config::load_file(&config_path).unwrap();
        assert!(config.node.identity.persistent);

        let resolved = resolve_identity(&config, &[config_path]).unwrap();
        assert!(matches!(resolved.source, IdentitySource::KeyFile(_)));
        assert_eq!(resolved.nsec, nsec);
    }

    #[test]
    fn test_resolve_identity_persistent_generates_and_persists() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("fips.yaml");

        fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();

        let config = Config::load_file(&config_path).unwrap();
        let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();

        assert!(matches!(resolved.source, IdentitySource::Generated(_)));

        // Key file and pub file should now exist
        let key_path = temp_dir.path().join("fips.key");
        let pub_path = temp_dir.path().join("fips.pub");
        assert!(key_path.exists());
        assert!(pub_path.exists());

        // Second resolve should load from key file (not generate new)
        let resolved2 = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
        assert!(matches!(resolved2.source, IdentitySource::KeyFile(_)));
        assert_eq!(resolved.nsec, resolved2.nsec);
    }

    #[test]
    fn test_to_yaml_empty_nsec_omitted() {
        let config = Config::new();
        let yaml = config.to_yaml().unwrap();

        // Empty nsec should not be serialized
        assert!(!yaml.contains("nsec:"));
    }

    #[test]
    fn test_parse_transport_single_instance() {
        let yaml = r#"
transports:
  udp:
    bind_addr: "0.0.0.0:2121"
    mtu: 1400
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.transports.udp.len(), 1);
        let instances: Vec<_> = config.transports.udp.iter().collect();
        assert_eq!(instances.len(), 1);
        assert_eq!(instances[0].0, None); // Single instance has no name
        assert_eq!(instances[0].1.bind_addr(), "0.0.0.0:2121");
        assert_eq!(instances[0].1.mtu(), 1400);
    }

    #[test]
    fn test_parse_transport_named_instances() {
        let yaml = r#"
transports:
  udp:
    main:
      bind_addr: "0.0.0.0:2121"
    backup:
      bind_addr: "192.168.1.100:2122"
      mtu: 1280
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.transports.udp.len(), 2);

        let instances: std::collections::HashMap<_, _> = config.transports.udp.iter().collect();

        // Named instances have Some(name)
        assert!(instances.contains_key(&Some("main")));
        assert!(instances.contains_key(&Some("backup")));
        assert_eq!(instances[&Some("main")].bind_addr(), "0.0.0.0:2121");
        assert_eq!(instances[&Some("backup")].bind_addr(), "192.168.1.100:2122");
        assert_eq!(instances[&Some("backup")].mtu(), 1280);
    }

    #[test]
    fn test_parse_transport_empty() {
        let yaml = r#"
transports: {}
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();
        assert!(config.transports.udp.is_empty());
        assert!(config.transports.is_empty());
    }

    #[test]
    fn test_transport_instances_iter() {
        // Single instance - no name
        let single = TransportInstances::Single(UdpConfig {
            bind_addr: Some("0.0.0.0:2121".to_string()),
            mtu: None,
            ..Default::default()
        });
        let items: Vec<_> = single.iter().collect();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].0, None);

        // Named instances - have names
        let mut map = HashMap::new();
        map.insert("a".to_string(), UdpConfig::default());
        map.insert("b".to_string(), UdpConfig::default());
        let named = TransportInstances::Named(map);
        let items: Vec<_> = named.iter().collect();
        assert_eq!(items.len(), 2);
        // All named instances should have Some(name)
        assert!(items.iter().all(|(name, _)| name.is_some()));
    }

    #[test]
    fn test_parse_peer_config() {
        let yaml = r#"
peers:
  - npub: "npub1abc123"
    alias: "gateway"
    addresses:
      - transport: udp
        addr: "192.168.1.1:2121"
        priority: 1
      - transport: tor
        addr: "xyz.onion:2121"
        priority: 2
    connect_policy: auto_connect
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.npub, "npub1abc123");
        assert_eq!(peer.alias, Some("gateway".to_string()));
        assert_eq!(peer.addresses.len(), 2);
        assert!(peer.is_auto_connect());

        // Check addresses are sorted by priority
        let sorted = peer.addresses_by_priority();
        assert_eq!(sorted[0].transport, "udp");
        assert_eq!(sorted[0].priority, 1);
        assert_eq!(sorted[1].transport, "tor");
        assert_eq!(sorted[1].priority, 2);
    }

    #[test]
    fn test_parse_peer_minimal() {
        let yaml = r#"
peers:
  - npub: "npub1xyz"
    addresses:
      - transport: udp
        addr: "10.0.0.1:2121"
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 1);
        let peer = &config.peers[0];
        assert_eq!(peer.npub, "npub1xyz");
        assert!(peer.alias.is_none());
        // Default connect_policy is auto_connect
        assert!(peer.is_auto_connect());
        // Default priority is 100
        assert_eq!(peer.addresses[0].priority, 100);
    }

    #[test]
    fn test_parse_multiple_peers() {
        let yaml = r#"
peers:
  - npub: "npub1peer1"
    addresses:
      - transport: udp
        addr: "10.0.0.1:2121"
  - npub: "npub1peer2"
    addresses:
      - transport: udp
        addr: "10.0.0.2:2121"
    connect_policy: on_demand
"#;
        let config: Config = serde_yaml::from_str(yaml).unwrap();

        assert_eq!(config.peers.len(), 2);
        assert_eq!(config.auto_connect_peers().count(), 1);
    }

    #[test]
    fn test_peer_config_builder() {
        let peer = PeerConfig::new("npub1test", "udp", "192.168.1.1:2121")
            .with_alias("test-peer")
            .with_address(PeerAddress::with_priority("tor", "xyz.onion:2121", 50));

        assert_eq!(peer.npub, "npub1test");
        assert_eq!(peer.alias, Some("test-peer".to_string()));
        assert_eq!(peer.addresses.len(), 2);
        assert!(peer.is_auto_connect());
    }

    #[test]
    fn test_parse_legacy_discovery_nostr_config_compat() {
        // COMPAT (drop at the v2 cutover): a deprecated `node.discovery.nostr`
        // block must fold into `node.rendezvous.nostr` via normalize.
        let yaml = r#"
node:
  discovery:
    nostr:
      enabled: true
      advertise: false
      policy: configured_only
      open_discovery_max_pending: 12
      app: "fips.nat.test.v1"
      signal_ttl_secs: 45
      advert_relays:
        - "wss://relay-a.example"
      dm_relays:
        - "wss://relay-b.example"
      stun_servers:
        - "stun:stun.example.org:3478"
peers:
  - npub: "npub1peer"
    via_nostr: true
    addresses:
      - transport: udp
        addr: "nat"
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.normalize_deprecated_keys();
        assert!(config.node.rendezvous.nostr.enabled);
        assert!(!config.node.rendezvous.nostr.advertise);
        assert_eq!(config.node.rendezvous.nostr.app, "fips.nat.test.v1");
        assert_eq!(config.node.rendezvous.nostr.signal_ttl_secs, 45);
        assert_eq!(
            config.node.rendezvous.nostr.policy,
            NostrRendezvousPolicy::ConfiguredOnly
        );
        assert_eq!(config.node.rendezvous.nostr.open_discovery_max_pending, 12);
        assert_eq!(
            config.node.rendezvous.nostr.advert_relays,
            vec!["wss://relay-a.example".to_string()]
        );
        assert_eq!(
            config.node.rendezvous.nostr.dm_relays,
            vec!["wss://relay-b.example".to_string()]
        );
        assert_eq!(
            config.node.rendezvous.nostr.stun_servers,
            vec!["stun:stun.example.org:3478".to_string()]
        );
        assert_eq!(
            config.peers[0].addresses[0].addr, "nat",
            "udp:nat address should parse without special-casing in YAML"
        );
        assert!(config.peers[0].via_nostr);
    }

    #[test]
    fn test_parse_lookup_and_rendezvous_new_keys() {
        // The post-split keys parse directly, with no deprecated block and no
        // normalize warning.
        let yaml = r#"
node:
  lookup:
    ttl: 7
    attempt_timeouts_secs: [3, 6]
    forward_min_interval_secs: 9
  rendezvous:
    nostr:
      enabled: true
      app: "fips.new.keys.v1"
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.normalize_deprecated_keys();
        assert_eq!(config.node.lookup.ttl, 7);
        assert_eq!(config.node.lookup.attempt_timeouts_secs, vec![3, 6]);
        assert_eq!(config.node.lookup.forward_min_interval_secs, 9);
        // Unset scalar keeps its default.
        assert_eq!(config.node.lookup.recent_expiry_secs, 10);
        assert!(config.node.rendezvous.nostr.enabled);
        assert_eq!(config.node.rendezvous.nostr.app, "fips.new.keys.v1");
        assert!(config.node.discovery.is_none());
    }

    #[test]
    fn test_legacy_discovery_lookup_scalars_compat() {
        // COMPAT (drop at the v2 cutover): legacy `node.discovery` mesh-lookup
        // scalars must fold into `node.lookup`; unset keys keep their defaults.
        let yaml = r#"
node:
  discovery:
    ttl: 5
    backoff_base_secs: 4
    backoff_max_secs: 30
"#;
        let mut config: Config = serde_yaml::from_str(yaml).unwrap();
        config.normalize_deprecated_keys();
        assert_eq!(config.node.lookup.ttl, 5);
        assert_eq!(config.node.lookup.backoff_base_secs, 4);
        assert_eq!(config.node.lookup.backoff_max_secs, 30);
        // Unset legacy scalar leaves the new-table default intact.
        assert_eq!(config.node.lookup.attempt_timeouts_secs, vec![1, 2, 4, 8]);
        // The compat block is consumed by normalize.
        assert!(config.node.discovery.is_none());
    }

    #[test]
    fn test_validate_transport_advert_requires_nostr_enabled() {
        let mut config = Config::default();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            advertise_on_nostr: Some(true),
            ..Default::default()
        });
        config.node.rendezvous.nostr.enabled = false;

        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("advertise_on_nostr"));
    }

    #[test]
    fn test_validate_peer_via_nostr_requires_nostr_enabled() {
        let mut config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                via_nostr: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        config.node.rendezvous.nostr.enabled = false;

        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("via_nostr"));
    }

    #[test]
    fn test_validate_peer_addresses_required_unless_via_nostr() {
        // Empty addresses + via_nostr=false → error.
        let mut config = Config {
            peers: vec![PeerConfig {
                npub: "npub1peer".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("at least one address"));

        // Empty addresses + via_nostr=true + nostr.enabled=true → ok.
        config.peers[0].via_nostr = true;
        config.node.rendezvous.nostr.enabled = true;
        config
            .validate()
            .expect("via_nostr should allow empty addresses");
    }

    #[test]
    fn test_validate_nat_udp_advert_requires_relays_and_stun() {
        let mut config = Config::default();
        config.node.rendezvous.nostr.enabled = true;
        config.node.rendezvous.nostr.dm_relays.clear();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            advertise_on_nostr: Some(true),
            public: Some(false),
            ..Default::default()
        });

        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("dm_relays"));

        config.node.rendezvous.nostr.dm_relays = vec!["wss://relay.example".to_string()];
        config.node.rendezvous.nostr.stun_servers.clear();
        let err = config.validate().expect_err("validation should fail");
        assert!(err.to_string().contains("stun_servers"));
    }

    #[test]
    fn test_is_loopback_addr_str() {
        assert!(is_loopback_addr_str("127.0.0.1:2121"));
        assert!(is_loopback_addr_str("127.0.0.5:9999"));
        assert!(is_loopback_addr_str("[::1]:2121"));
        assert!(is_loopback_addr_str("::1:2121"));
        assert!(is_loopback_addr_str("localhost:80"));
        assert!(!is_loopback_addr_str("0.0.0.0:2121"));
        assert!(!is_loopback_addr_str("192.168.1.1:2121"));
        assert!(!is_loopback_addr_str("[fd00::1]:2121"));
        assert!(!is_loopback_addr_str("core-vm.tail65015.ts.net:2121"));
        assert!(!is_loopback_addr_str("example.com:443"));
    }

    #[test]
    fn test_validate_loopback_bind_with_external_peer_rejected() {
        use crate::config::PeerAddress;
        let mut config = Config::default();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:2121".to_string()),
            ..Default::default()
        });
        config.peers = vec![PeerConfig {
            npub: "npub1peer".to_string(),
            addresses: vec![PeerAddress::new("udp", "core-vm.tail65015.ts.net:2121")],
            ..Default::default()
        }];

        let err = config.validate().expect_err("validation should fail");
        let msg = err.to_string();
        assert!(msg.contains("loopback"), "got: {msg}");
        assert!(msg.contains("non-loopback"), "got: {msg}");
    }

    #[test]
    fn test_validate_loopback_bind_with_loopback_peer_ok() {
        use crate::config::PeerAddress;
        let mut config = Config::default();
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:2121".to_string()),
            ..Default::default()
        });
        config.peers = vec![PeerConfig {
            npub: "npub1peer".to_string(),
            addresses: vec![PeerAddress::new("udp", "127.0.0.2:2121")],
            ..Default::default()
        }];

        config
            .validate()
            .expect("loopback peer with loopback bind should validate");
    }

    #[test]
    fn test_validate_outbound_only_exempt_from_loopback_check() {
        use crate::config::PeerAddress;
        let mut config = Config::default();
        // outbound_only overrides bind_addr → 0.0.0.0:0; the loopback
        // check must skip this transport entirely.
        config.transports.udp = TransportInstances::Single(UdpConfig {
            bind_addr: Some("127.0.0.1:2121".to_string()),
            outbound_only: Some(true),
            ..Default::default()
        });
        config.peers = vec![PeerConfig {
            npub: "npub1peer".to_string(),
            addresses: vec![PeerAddress::new("udp", "core-vm.tail65015.ts.net:2121")],
            ..Default::default()
        }];

        config
            .validate()
            .expect("outbound_only should be exempt from the loopback check");
    }

    #[test]
    fn test_outbound_only_forces_ephemeral_bind() {
        let cfg = UdpConfig {
            bind_addr: Some("127.0.0.1:2121".to_string()),
            outbound_only: Some(true),
            ..Default::default()
        };
        assert_eq!(cfg.bind_addr(), "0.0.0.0:0");
        assert!(cfg.outbound_only());
    }

    #[test]
    fn test_outbound_only_forces_advertise_off() {
        let cfg = UdpConfig {
            advertise_on_nostr: Some(true),
            outbound_only: Some(true),
            ..Default::default()
        };
        assert!(!cfg.advertise_on_nostr());
    }

    #[test]
    fn test_udp_accept_connections_default_true() {
        let cfg = UdpConfig::default();
        assert!(cfg.accept_connections());
    }

    /// Mutex serializing tests that mutate `XDG_RUNTIME_DIR`. `cargo test`
    /// runs tests on multiple threads in the same process, and env mutation
    /// is process-global, so concurrent env-touching tests would race.
    #[cfg(unix)]
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[cfg(unix)]
    #[test]
    fn test_resolve_default_socket_call_sites_agree() {
        // The three resolver call sites must all produce strings that agree
        // on the directory, differing only in the filename suffix.
        let _g = ENV_MUTEX.lock().unwrap();

        let control_client = default_control_path().to_string_lossy().into_owned();
        let gateway_client = default_gateway_path().to_string_lossy().into_owned();
        let control_daemon = ControlConfig::default().socket_path;

        // Daemon-side and client-side control paths must be identical.
        assert_eq!(
            control_daemon, control_client,
            "daemon and client default control-socket paths diverged: \
             daemon={control_daemon}, client={control_client}"
        );

        // Control and gateway must share a parent directory (or /tmp prefix).
        let control_dir = std::path::Path::new(&control_client)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let gateway_dir = std::path::Path::new(&gateway_client)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        assert_eq!(
            control_dir, gateway_dir,
            "control and gateway default-socket paths picked different directories: \
             control={control_client}, gateway={gateway_client}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_default_socket_xdg_when_no_run_fips() {
        // With /run/fips absent and XDG_RUNTIME_DIR pointing at an
        // existing directory, the resolver picks XDG. On test hosts where
        // /run/fips happens to exist (a real fips deployment), the
        // resolver legitimately picks /run/fips and skips XDG entirely;
        // both outcomes are accepted below.
        let _g = ENV_MUTEX.lock().unwrap();

        let temp_dir = TempDir::new().unwrap();
        let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        // SAFETY: serialized via ENV_MUTEX above.
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());
        }

        let path = resolve_default_socket("control.sock");

        // Restore env before asserting so a panic doesn't leak state.
        unsafe {
            match prev_xdg {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }

        // If /run/fips happens to be writable in the test environment (CI
        // running as root, for instance), the resolver legitimately picks
        // /run/fips and skips XDG entirely. Accept either outcome but
        // demand that one of the two canonical prefixes is chosen — never
        // /tmp when XDG was valid.
        assert!(
            path.starts_with("/run/fips/")
                || path.starts_with(&format!("{}/fips/", temp_dir.path().display())),
            "expected /run/fips or XDG path, got: {path}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_resolve_default_socket_tmp_when_xdg_invalid() {
        // With XDG_RUNTIME_DIR pointing at a non-existent directory and
        // /run/fips absent, the resolver falls through to /tmp. On hosts
        // where /run/fips exists, the resolver legitimately picks it
        // first; both outcomes are accepted below.
        let _g = ENV_MUTEX.lock().unwrap();

        let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
        // Use a path that definitely does not exist.
        let bogus = "/nonexistent-xdg-runtime-dir-for-fips-test-zzz";
        // SAFETY: serialized via ENV_MUTEX.
        unsafe {
            std::env::set_var("XDG_RUNTIME_DIR", bogus);
        }

        let path = resolve_default_socket("gateway.sock");

        unsafe {
            match prev_xdg {
                Some(v) => std::env::set_var("XDG_RUNTIME_DIR", v),
                None => std::env::remove_var("XDG_RUNTIME_DIR"),
            }
        }

        // Accept either /run/fips/ (test running as root with that dir
        // writable) or /tmp/fips-... (the dev-machine fallback). Never
        // accept the bogus XDG dir leaking through.
        assert!(
            path.starts_with("/run/fips/") || path == "/tmp/fips-gateway.sock",
            "expected /run/fips or /tmp fallback, got: {path}"
        );
        assert!(
            !path.starts_with(bogus),
            "stale/invalid XDG_RUNTIME_DIR leaked into resolver: {path}"
        );
    }
}
