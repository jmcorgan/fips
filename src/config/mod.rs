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

#[cfg(feature = "gateway")]
mod gateway;
mod node;
mod peer;
mod transport;

use crate::upper::config::{DnsConfig, TunConfig};
use crate::{Identity, IdentityError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[cfg(feature = "gateway")]
pub use gateway::{ConntrackConfig, GatewayConfig, GatewayDnsConfig, PortForward, Proto};
pub use node::{
    BloomConfig, BuffersConfig, CacheConfig, ControlConfig, DiscoveryConfig, LimitsConfig,
    NodeConfig, RateLimitConfig, RekeyConfig, RetryConfig, SessionConfig, SessionMmpConfig,
    TreeConfig,
};
pub use peer::{ConnectPolicy, PeerAddress, PeerConfig};
pub use transport::{
    BleConfig, DirectoryServiceConfig, EthernetConfig, TcpConfig, TorConfig, TransportInstances,
    TransportsConfig, UdpConfig,
};

/// Default config filename.
const CONFIG_FILENAME: &str = "fips.yaml";

/// Default key filename, placed alongside the config file.
const KEY_FILENAME: &str = "fips.key";

/// Default public key filename, placed alongside the key file.
const PUB_FILENAME: &str = "fips.pub";

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

/// Default control socket path for fipsctl / fipstop.
///
/// On Unix, checks the system-wide path first (used when the daemon runs as
/// a systemd service), then falls back to the user's XDG runtime directory.
/// On Windows, returns the default TCP port ("21210").
pub fn default_control_path() -> PathBuf {
    #[cfg(unix)]
    {
        if Path::new("/run/fips").exists() {
            PathBuf::from("/run/fips/control.sock")
        } else if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(format!("{runtime_dir}/fips/control.sock"))
        } else {
            PathBuf::from("/tmp/fips-control.sock")
        }
    }
    #[cfg(windows)]
    {
        PathBuf::from("21210")
    }
}

/// Default gateway control socket path.
///
/// On Unix, follows the same pattern as the main control socket.
/// On Windows, returns a placeholder TCP port ("21211").
pub fn default_gateway_path() -> PathBuf {
    #[cfg(unix)]
    {
        if Path::new("/run/fips").exists() {
            PathBuf::from("/run/fips/gateway.sock")
        } else if let Ok(runtime_dir) = std::env::var("XDG_RUNTIME_DIR") {
            PathBuf::from(format!("{runtime_dir}/fips/gateway.sock"))
        } else {
            PathBuf::from("/tmp/fips-gateway.sock")
        }
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
    #[cfg(feature = "gateway")]
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

        serde_yaml::from_str(&contents).map_err(|e| ConfigError::ParseYaml {
            path: path.to_path_buf(),
            source: e,
        })
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
        #[cfg(feature = "gateway")]
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

    /// Derive the node profile from config.
    ///
    /// leaf_only → Leaf (implies non-routing),
    /// disable_routing → NonRouting,
    /// otherwise → Full.
    pub fn node_profile(&self) -> crate::protocol::NodeProfile {
        if self.node.leaf_only {
            crate::protocol::NodeProfile::Leaf
        } else if self.node.disable_routing {
            crate::protocol::NodeProfile::NonRouting
        } else {
            crate::protocol::NodeProfile::Full
        }
    }

    /// Get the configured peers.
    pub fn peers(&self) -> &[PeerConfig] {
        &self.peers
    }

    /// Get peers that should auto-connect on startup.
    pub fn auto_connect_peers(&self) -> impl Iterator<Item = &PeerConfig> {
        self.peers.iter().filter(|p| p.is_auto_connect())
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
}
