//! Host-to-npub static mapping.
//!
//! Provides a `HostMap` that resolves human-readable hostnames to Nostr
//! public keys (npubs). Populated from two sources:
//!
//! 1. Peer `alias` fields in the YAML configuration
//! 2. An operator-maintained hosts file (`/etc/fips/hosts`)
//!
//! The DNS resolver checks the host map before falling back to direct
//! npub resolution, enabling `gateway.fips` instead of `npub1...xyz.fips`.

use crate::config::PeerConfig;
use crate::{NodeAddr, PeerIdentity};
use std::collections::HashMap;
use std::path::Path;
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Default path for the FIPS hosts file.
pub const DEFAULT_HOSTS_PATH: &str = "/etc/fips/hosts";

/// Bidirectional hostname ↔ npub mapping table.
#[derive(Debug, Clone, Default)]
pub struct HostMap {
    /// hostname (lowercase) → npub string
    by_name: HashMap<String, String>,
    /// NodeAddr → hostname (for reverse display lookups)
    by_addr: HashMap<NodeAddr, String>,
}

/// Errors from host map operations.
#[derive(Debug, thiserror::Error)]
pub enum HostMapError {
    #[error("invalid hostname '{hostname}': {reason}")]
    InvalidHostname { hostname: String, reason: String },

    #[error("invalid npub '{npub}': {source}")]
    InvalidNpub {
        npub: String,
        source: crate::IdentityError,
    },

    #[error("I/O error reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },

    #[error("{path}:{line}: {reason}")]
    Parse {
        path: String,
        line: usize,
        reason: String,
    },
}

impl HostMap {
    /// Create an empty host map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a hostname → npub mapping.
    ///
    /// Validates the hostname and npub before inserting. The hostname is
    /// stored in lowercase for case-insensitive matching.
    pub fn insert(&mut self, hostname: &str, npub: &str) -> Result<(), HostMapError> {
        validate_hostname(hostname)?;

        let peer = PeerIdentity::from_npub(npub).map_err(|e| HostMapError::InvalidNpub {
            npub: npub.to_string(),
            source: e,
        })?;

        let key = hostname.to_ascii_lowercase();
        self.by_name.insert(key.clone(), npub.to_string());
        self.by_addr.insert(*peer.node_addr(), key);
        Ok(())
    }

    /// Look up the npub for a hostname (case-insensitive).
    pub fn lookup_npub(&self, hostname: &str) -> Option<&str> {
        self.by_name
            .get(&hostname.to_ascii_lowercase())
            .map(|s| s.as_str())
    }

    /// Look up the hostname for a NodeAddr (reverse lookup for display).
    pub fn lookup_hostname(&self, node_addr: &NodeAddr) -> Option<&str> {
        self.by_addr.get(node_addr).map(|s| s.as_str())
    }

    /// Number of entries in the map.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Build a host map from configured peer aliases.
    ///
    /// Peers with a valid `alias` field are inserted. Invalid hostnames
    /// or npubs are logged as warnings and skipped.
    pub fn from_peer_configs(peers: &[PeerConfig]) -> Self {
        let mut map = Self::new();
        for peer in peers {
            if let Some(alias) = &peer.alias
                && let Err(e) = map.insert(alias, &peer.npub)
            {
                warn!(alias = %alias, npub = %peer.npub, error = %e, "Skipping invalid peer alias for host map");
            }
        }
        if !map.is_empty() {
            debug!(count = map.len(), "Host map entries from peer config");
        }
        map
    }

    /// Load a host map from a hosts file.
    ///
    /// If the file does not exist, returns an empty map (not an error).
    /// Parse errors on individual lines are logged as warnings and skipped.
    pub fn load_hosts_file(path: &Path) -> Self {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = %path.display(), "No hosts file found, skipping");
                return Self::new();
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to read hosts file");
                return Self::new();
            }
        };

        let mut map = Self::new();
        for (line_num, line) in contents.lines().enumerate() {
            let trimmed = line.trim();

            // Skip empty lines and comments
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() != 2 {
                warn!(
                    path = %path.display(),
                    line = line_num + 1,
                    content = %trimmed,
                    "Expected 'hostname npub', skipping"
                );
                continue;
            }

            let hostname = fields[0];
            let npub = fields[1];

            if let Err(e) = map.insert(hostname, npub) {
                warn!(
                    path = %path.display(),
                    line = line_num + 1,
                    error = %e,
                    "Skipping invalid hosts file entry"
                );
            }
        }

        if !map.is_empty() {
            info!(path = %path.display(), count = map.len(), "Loaded hosts file");
        }
        map
    }

    /// Merge another host map into this one. The other map wins on conflicts.
    pub fn merge(&mut self, other: HostMap) {
        for (name, npub) in other.by_name {
            self.by_name.insert(name, npub);
        }
        for (addr, name) in other.by_addr {
            self.by_addr.insert(addr, name);
        }
    }
}

/// Return the modification time of a file, or `None` if it doesn't exist or
/// the metadata can't be read.
pub fn file_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok().and_then(|m| m.modified().ok())
}

/// Tracks a hosts file and reloads it when the modification time changes.
///
/// Holds the base host map (from peer config aliases) and the current
/// effective map (base + hosts file). On each `check_reload()`, stats the
/// hosts file and rebuilds the effective map if the mtime has changed.
pub struct HostMapReloader {
    /// Base map from peer config aliases (never changes).
    base: HostMap,
    /// Current effective map (base merged with hosts file).
    effective: HostMap,
    /// Path to the hosts file.
    path: std::path::PathBuf,
    /// Last observed modification time (None if file didn't exist).
    last_mtime: Option<SystemTime>,
}

impl HostMapReloader {
    /// Create a new reloader.
    ///
    /// Performs the initial load of the hosts file and merges with the base map.
    pub fn new(base: HostMap, path: std::path::PathBuf) -> Self {
        let last_mtime = file_mtime(&path);
        let hosts_file = HostMap::load_hosts_file(&path);
        let mut effective = base.clone();
        effective.merge(hosts_file);

        Self {
            base,
            effective,
            path,
            last_mtime,
        }
    }

    /// Get a reference to the current effective host map.
    pub fn hosts(&self) -> &HostMap {
        &self.effective
    }

    /// Check if the hosts file has been modified and reload if so.
    ///
    /// Returns `true` if the map was reloaded.
    pub fn check_reload(&mut self) -> bool {
        let current_mtime = file_mtime(&self.path);

        if current_mtime == self.last_mtime {
            return false;
        }

        // File appeared, disappeared, or was modified
        self.last_mtime = current_mtime;
        let hosts_file = HostMap::load_hosts_file(&self.path);
        let mut new_effective = self.base.clone();
        new_effective.merge(hosts_file);

        let count = new_effective.len();
        self.effective = new_effective;

        info!(
            path = %self.path.display(),
            entries = count,
            "Reloaded hosts file"
        );
        true
    }
}

/// Validate a hostname for use as a FIPS DNS alias.
///
/// Rules:
/// - ASCII alphanumeric and hyphens only `[a-zA-Z0-9-]`
/// - Must not start or end with a hyphen
/// - 1–63 characters
/// - Must not start with `npub1` (prevents ambiguity with npub resolution)
pub fn validate_hostname(hostname: &str) -> Result<(), HostMapError> {
    let err = |reason: &str| HostMapError::InvalidHostname {
        hostname: hostname.to_string(),
        reason: reason.to_string(),
    };

    if hostname.is_empty() {
        return Err(err("empty hostname"));
    }

    if hostname.len() > 63 {
        return Err(err("exceeds 63 characters"));
    }

    if hostname.to_ascii_lowercase().starts_with("npub1") {
        return Err(err(
            "must not start with 'npub1' (ambiguous with npub resolution)",
        ));
    }

    if hostname.starts_with('-') {
        return Err(err("must not start with a hyphen"));
    }

    if hostname.ends_with('-') {
        return Err(err("must not end with a hyphen"));
    }

    for ch in hostname.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '-' {
            return Err(err(&format!("invalid character '{ch}'")));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    // --- validate_hostname tests ---

    #[test]
    fn test_valid_hostnames() {
        let valid = [
            "gateway",
            "core-vm",
            "a",
            "node1",
            "my-peer-2",
            "A",
            "GATEWAY",
            "a1b2c3",
            &"x".repeat(63),
        ];
        for h in valid {
            assert!(validate_hostname(h).is_ok(), "should be valid: {h}");
        }
    }

    #[test]
    fn test_invalid_hostnames() {
        let cases = [
            ("", "empty"),
            ("-starts", "starts with hyphen"),
            ("ends-", "ends with hyphen"),
            ("has space", "space"),
            ("has.dot", "dot"),
            ("has_underscore", "underscore"),
            (&"x".repeat(64), "too long"),
            ("npub1foo", "npub1 prefix"),
            ("NPUB1bar", "npub1 prefix case"),
        ];
        for (h, desc) in cases {
            assert!(
                validate_hostname(h).is_err(),
                "should be invalid ({desc}): {h}"
            );
        }
    }

    // --- HostMap insert / lookup tests ---

    #[test]
    fn test_insert_and_lookup() {
        let id = Identity::generate();
        let npub = id.npub();

        let mut map = HostMap::new();
        map.insert("gateway", &npub).unwrap();

        assert_eq!(map.lookup_npub("gateway"), Some(npub.as_str()));
        assert_eq!(map.lookup_npub("GATEWAY"), Some(npub.as_str()));
        assert_eq!(map.lookup_npub("Gateway"), Some(npub.as_str()));
        assert_eq!(map.lookup_hostname(id.node_addr()), Some("gateway"));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_insert_invalid_hostname() {
        let id = Identity::generate();
        let mut map = HostMap::new();
        assert!(map.insert("", &id.npub()).is_err());
        assert!(map.is_empty());
    }

    #[test]
    fn test_insert_invalid_npub() {
        let mut map = HostMap::new();
        assert!(map.insert("gateway", "not-an-npub").is_err());
        assert!(map.is_empty());
    }

    #[test]
    fn test_insert_duplicate_overwrites() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        let mut map = HostMap::new();
        map.insert("gateway", &id1.npub()).unwrap();
        map.insert("gateway", &id2.npub()).unwrap();

        assert_eq!(map.lookup_npub("gateway"), Some(id2.npub().as_str()));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn test_lookup_missing() {
        let map = HostMap::new();
        assert!(map.lookup_npub("nonexistent").is_none());
    }

    // --- from_peer_configs tests ---

    #[test]
    fn test_from_peer_configs_with_alias() {
        let id = Identity::generate();
        let peers = vec![PeerConfig {
            npub: id.npub(),
            alias: Some("core".to_string()),
            ..Default::default()
        }];

        let map = HostMap::from_peer_configs(&peers);
        assert_eq!(map.lookup_npub("core"), Some(id.npub().as_str()));
    }

    #[test]
    fn test_from_peer_configs_without_alias() {
        let id = Identity::generate();
        let peers = vec![PeerConfig {
            npub: id.npub(),
            alias: None,
            ..Default::default()
        }];

        let map = HostMap::from_peer_configs(&peers);
        assert!(map.is_empty());
    }

    #[test]
    fn test_from_peer_configs_invalid_alias_skipped() {
        let id = Identity::generate();
        let peers = vec![PeerConfig {
            npub: id.npub(),
            alias: Some("has space".to_string()),
            ..Default::default()
        }];

        let map = HostMap::from_peer_configs(&peers);
        assert!(map.is_empty());
    }

    // --- load_hosts_file tests ---

    #[test]
    fn test_load_hosts_file_not_found() {
        let map = HostMap::load_hosts_file(Path::new("/nonexistent/path/hosts"));
        assert!(map.is_empty());
    }

    #[test]
    fn test_load_hosts_file_valid() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();
        let content = format!(
            "# A comment\n\
             gateway   {}\n\
             \n\
             # Another comment\n\
             core-vm   {}\n",
            id1.npub(),
            id2.npub()
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, content).unwrap();

        let map = HostMap::load_hosts_file(&path);
        assert_eq!(map.len(), 2);
        assert_eq!(map.lookup_npub("gateway"), Some(id1.npub().as_str()));
        assert_eq!(map.lookup_npub("core-vm"), Some(id2.npub().as_str()));
    }

    #[test]
    fn test_load_hosts_file_skips_bad_lines() {
        let id = Identity::generate();
        let content = format!(
            "gateway   {}\n\
             bad_host   {}\n\
             too many fields here\n\
             good-host   {}\n",
            id.npub(),
            id.npub(),
            id.npub()
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, content).unwrap();

        let map = HostMap::load_hosts_file(&path);
        // "gateway" is valid, "bad_host" has underscore, middle line has 3 fields
        // "good-host" is valid
        assert_eq!(map.len(), 2);
        assert!(map.lookup_npub("gateway").is_some());
        assert!(map.lookup_npub("good-host").is_some());
    }

    #[test]
    fn test_load_hosts_file_whitespace_handling() {
        let id = Identity::generate();
        let content = format!(
            "  # indented comment  \n\
             \t gateway \t {} \t \n\
             \n\
             \t  \n",
            id.npub()
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, content).unwrap();

        let map = HostMap::load_hosts_file(&path);
        assert_eq!(map.len(), 1);
        assert!(map.lookup_npub("gateway").is_some());
    }

    // --- merge tests ---

    #[test]
    fn test_merge_non_overlapping() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        let mut map1 = HostMap::new();
        map1.insert("alpha", &id1.npub()).unwrap();

        let mut map2 = HostMap::new();
        map2.insert("beta", &id2.npub()).unwrap();

        map1.merge(map2);
        assert_eq!(map1.len(), 2);
        assert!(map1.lookup_npub("alpha").is_some());
        assert!(map1.lookup_npub("beta").is_some());
    }

    #[test]
    fn test_merge_overlapping_other_wins() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        let mut map1 = HostMap::new();
        map1.insert("gateway", &id1.npub()).unwrap();

        let mut map2 = HostMap::new();
        map2.insert("gateway", &id2.npub()).unwrap();

        map1.merge(map2);
        assert_eq!(map1.len(), 1);
        assert_eq!(map1.lookup_npub("gateway"), Some(id2.npub().as_str()));
    }

    // --- HostMapReloader tests ---

    #[test]
    fn test_reloader_initial_load() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        // Base map from peer config
        let mut base = HostMap::new();
        base.insert("core", &id1.npub()).unwrap();

        // Hosts file with another entry
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id2.npub())).unwrap();

        let reloader = HostMapReloader::new(base, path);
        assert_eq!(reloader.hosts().len(), 2);
        assert!(reloader.hosts().lookup_npub("core").is_some());
        assert!(reloader.hosts().lookup_npub("gateway").is_some());
    }

    #[test]
    fn test_reloader_no_hosts_file() {
        let id = Identity::generate();
        let mut base = HostMap::new();
        base.insert("core", &id.npub()).unwrap();

        let reloader = HostMapReloader::new(base, std::path::PathBuf::from("/nonexistent/hosts"));
        // Only base entries present
        assert_eq!(reloader.hosts().len(), 1);
        assert!(reloader.hosts().lookup_npub("core").is_some());
    }

    #[test]
    fn test_reloader_detects_file_change() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id1.npub())).unwrap();

        let mut reloader = HostMapReloader::new(HostMap::new(), path.clone());
        assert_eq!(reloader.hosts().len(), 1);
        assert_eq!(
            reloader.hosts().lookup_npub("gateway"),
            Some(id1.npub().as_str())
        );

        // No change yet
        assert!(!reloader.check_reload());

        // Modify the file — bump mtime by writing new content
        // Sleep briefly to ensure mtime changes (filesystem granularity)
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(
            &path,
            format!("gateway   {}\nnew-host   {}\n", id1.npub(), id2.npub()),
        )
        .unwrap();

        assert!(reloader.check_reload());
        assert_eq!(reloader.hosts().len(), 2);
        assert!(reloader.hosts().lookup_npub("new-host").is_some());
    }

    #[test]
    fn test_reloader_detects_file_deletion() {
        let id = Identity::generate();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id.npub())).unwrap();

        let mut reloader = HostMapReloader::new(HostMap::new(), path.clone());
        assert_eq!(reloader.hosts().len(), 1);

        // Delete the file
        std::fs::remove_file(&path).unwrap();

        assert!(reloader.check_reload());
        assert!(reloader.hosts().is_empty());
    }

    #[test]
    fn test_reloader_detects_file_creation() {
        let id = Identity::generate();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");

        // Start with no file
        let mut reloader = HostMapReloader::new(HostMap::new(), path.clone());
        assert!(reloader.hosts().is_empty());

        // Create the file
        std::fs::write(&path, format!("gateway   {}\n", id.npub())).unwrap();

        assert!(reloader.check_reload());
        assert_eq!(reloader.hosts().len(), 1);
        assert!(reloader.hosts().lookup_npub("gateway").is_some());
    }

    #[test]
    fn test_reloader_preserves_base_on_reload() {
        let id_base = Identity::generate();
        let id_file = Identity::generate();

        let mut base = HostMap::new();
        base.insert("core", &id_base.npub()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id_file.npub())).unwrap();

        let mut reloader = HostMapReloader::new(base, path.clone());
        assert_eq!(reloader.hosts().len(), 2);

        // Delete hosts file — base entries should remain
        std::fs::remove_file(&path).unwrap();
        assert!(reloader.check_reload());
        assert_eq!(reloader.hosts().len(), 1);
        assert!(reloader.hosts().lookup_npub("core").is_some());
        assert!(reloader.hosts().lookup_npub("gateway").is_none());
    }
}
