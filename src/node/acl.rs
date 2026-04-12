//! Peer access control lists (ACLs) keyed by npub or alias.
//!
//! Evaluation follows TCP Wrappers ordering:
//! 1. If `peers.allow` matches a peer, allow it.
//! 2. Otherwise, if `peers.deny` matches a peer, deny it.
//! 3. Otherwise, allow it.
//!
//! `ALL` acts as a wildcard entry in either file. Because allow rules are
//! evaluated first, an allowlist match overrides a denylist match for the
//! same peer.

use crate::node::{Node, NodeError};
use crate::transport::{TransportAddr, TransportId};
use crate::upper::hosts::{DEFAULT_HOSTS_PATH, HostMap, HostMapReloader, file_mtime};
use crate::{NodeAddr, PeerIdentity};
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use tracing::{debug, info, warn};

/// Default path for the peer allow list.
pub const DEFAULT_PEERS_ALLOW_PATH: &str = "/etc/fips/peers.allow";

/// Default path for the peer deny list.
pub const DEFAULT_PEERS_DENY_PATH: &str = "/etc/fips/peers.deny";

/// Result of evaluating a peer against the ACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAclDecision {
    /// Explicitly permitted by `peers.allow`.
    AllowList,
    /// Explicitly rejected by `peers.deny`.
    DenyList,
    /// No rule matched after evaluating allow and deny rules.
    DefaultAllow,
}

impl PeerAclDecision {
    /// Whether the peer is allowed.
    pub fn allowed(self) -> bool {
        matches!(self, Self::AllowList | Self::DefaultAllow)
    }
}

impl fmt::Display for PeerAclDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AllowList => write!(f, "allowlist match"),
            Self::DenyList => write!(f, "denylist match"),
            Self::DefaultAllow => write!(f, "default allow"),
        }
    }
}

/// Runtime context for ACL enforcement logging.
#[derive(Debug, Clone, Copy)]
pub enum PeerAclContext {
    OutboundConnect,
    InboundHandshake,
    OutboundHandshake,
}

/// Snapshot of the currently loaded ACL state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PeerAclStatus {
    pub allow_file: String,
    pub deny_file: String,
    pub enforcement_active: bool,
    pub effective_mode: String,
    pub default_decision: String,
    pub allow_all: bool,
    pub deny_all: bool,
    pub allow_raw_entries: Vec<String>,
    pub deny_raw_entries: Vec<String>,
    pub allow_entries: Vec<String>,
    pub deny_entries: Vec<String>,
}

impl fmt::Display for PeerAclContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutboundConnect => write!(f, "outbound_connect"),
            Self::InboundHandshake => write!(f, "inbound_handshake"),
            Self::OutboundHandshake => write!(f, "outbound_handshake"),
        }
    }
}

/// Loaded peer ACL state.
#[derive(Debug, Clone, Default)]
pub struct PeerAcl {
    allow: HashSet<NodeAddr>,
    deny: HashSet<NodeAddr>,
    allow_raw_entries: BTreeSet<String>,
    deny_raw_entries: BTreeSet<String>,
    allow_npubs: BTreeSet<String>,
    deny_npubs: BTreeSet<String>,
    allow_all: bool,
    deny_all: bool,
}

impl PeerAcl {
    /// Create an empty ACL.
    pub fn new() -> Self {
        Self::default()
    }

    /// Load the allow/deny files into a new ACL.
    #[cfg(test)]
    pub fn load_files(allow_path: &Path, deny_path: &Path) -> Self {
        let hosts = HostMap::new();
        Self::load_files_with_hosts(allow_path, deny_path, &hosts)
    }

    /// Load the allow/deny files into a new ACL using alias resolution.
    pub fn load_files_with_hosts(allow_path: &Path, deny_path: &Path, hosts: &HostMap) -> Self {
        let mut acl = Self::new();
        acl.load_file(allow_path, true, hosts);
        acl.load_file(deny_path, false, hosts);

        if !acl.is_empty() {
            debug!(
                allow_entries = acl.allow.len(),
                deny_entries = acl.deny.len(),
                allow_all = acl.allow_all,
                deny_all = acl.deny_all,
                "Loaded peer ACL files"
            );
        }

        acl
    }

    /// Evaluate whether a peer is allowed.
    pub fn check(&self, peer: &PeerIdentity) -> PeerAclDecision {
        let addr = peer.node_addr();

        if self.allow_all || self.allow.contains(addr) {
            PeerAclDecision::AllowList
        } else if self.deny_all || self.deny.contains(addr) {
            PeerAclDecision::DenyList
        } else {
            PeerAclDecision::DefaultAllow
        }
    }

    /// Whether the ACL has no entries or wildcards.
    pub fn is_empty(&self) -> bool {
        self.allow.is_empty() && self.deny.is_empty() && !self.allow_all && !self.deny_all
    }

    /// Return the effective ACL mode after applying precedence rules.
    pub fn effective_mode(&self) -> &'static str {
        if self.allow_all {
            "allow_all"
        } else if !self.allow.is_empty() && self.deny_all {
            "allow_then_deny_all"
        } else if !self.allow.is_empty() && !self.deny.is_empty() {
            "allow_then_deny"
        } else if !self.allow.is_empty() {
            "allowlist"
        } else if self.deny_all {
            "deny_all"
        } else if !self.deny.is_empty() {
            "denylist"
        } else {
            "default_open"
        }
    }

    /// Return the decision applied to peers that are not named in either file.
    pub fn default_decision(&self) -> &'static str {
        if self.allow_all || (self.deny.is_empty() && !self.deny_all && self.allow.is_empty()) {
            "allow"
        } else if self.deny_all {
            "deny"
        } else {
            "allow"
        }
    }

    /// Return the loaded allowlist entries as npubs.
    pub fn allow_entries(&self) -> Vec<String> {
        self.allow_npubs.iter().cloned().collect()
    }

    /// Return the loaded allowlist tokens exactly as written in the ACL file.
    pub fn allow_raw_entries(&self) -> Vec<String> {
        self.allow_raw_entries.iter().cloned().collect()
    }

    /// Return the loaded denylist entries as npubs.
    pub fn deny_entries(&self) -> Vec<String> {
        self.deny_npubs.iter().cloned().collect()
    }

    /// Return the loaded denylist tokens exactly as written in the ACL file.
    pub fn deny_raw_entries(&self) -> Vec<String> {
        self.deny_raw_entries.iter().cloned().collect()
    }

    fn load_file(&mut self, path: &Path, is_allow: bool, hosts: &HostMap) {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                debug!(path = %path.display(), "No ACL file found, skipping");
                return;
            }
            Err(e) => {
                warn!(path = %path.display(), error = %e, "Failed to read ACL file");
                return;
            }
        };

        for (line_num, line) in contents.lines().enumerate() {
            let trimmed = line.split('#').next().unwrap_or("").trim();

            if trimmed.is_empty() {
                continue;
            }

            let fields: Vec<&str> = trimmed.split_whitespace().collect();
            if fields.len() != 1 {
                warn!(
                    path = %path.display(),
                    line = line_num + 1,
                    content = %trimmed,
                    "Expected one ACL entry per line, skipping"
                );
                continue;
            }

            let entry = fields[0];
            if entry.eq_ignore_ascii_case("ALL") {
                if is_allow {
                    self.allow_all = true;
                } else {
                    self.deny_all = true;
                }
                continue;
            }

            let (peer, resolved_npub) = match Self::resolve_entry(entry, hosts) {
                Ok(resolved) => resolved,
                Err(e) => {
                    warn!(
                        path = %path.display(),
                        line = line_num + 1,
                        entry = %entry,
                        error = %e,
                        "Skipping invalid ACL entry"
                    );
                    continue;
                }
            };

            if is_allow {
                self.allow.insert(*peer.node_addr());
                self.allow_raw_entries.insert(entry.to_string());
                self.allow_npubs.insert(resolved_npub);
            } else {
                self.deny.insert(*peer.node_addr());
                self.deny_raw_entries.insert(entry.to_string());
                self.deny_npubs.insert(resolved_npub);
            }
        }
    }

    fn resolve_entry(entry: &str, hosts: &HostMap) -> Result<(PeerIdentity, String), String> {
        if let Ok(peer) = PeerIdentity::from_npub(entry) {
            return Ok((peer, entry.to_string()));
        }

        let mapped = hosts
            .lookup_npub(entry)
            .ok_or_else(|| "unknown alias or invalid npub".to_string())?;
        let peer = PeerIdentity::from_npub(mapped)
            .map_err(|e| format!("alias resolves to invalid npub: {e}"))?;
        Ok((peer, mapped.to_string()))
    }
}

/// Tracks peer ACL files and reloads them on mtime changes.
pub struct PeerAclReloader {
    acl: PeerAcl,
    hosts: HostMapReloader,
    allow_path: PathBuf,
    deny_path: PathBuf,
    last_allow_mtime: Option<SystemTime>,
    last_deny_mtime: Option<SystemTime>,
}

impl PeerAclReloader {
    /// Create a reloader using the standard ACL file locations.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::with_alias_sources(
            PathBuf::from(DEFAULT_PEERS_ALLOW_PATH),
            PathBuf::from(DEFAULT_PEERS_DENY_PATH),
            HostMap::new(),
            PathBuf::from(DEFAULT_HOSTS_PATH),
        )
    }

    /// Create a reloader for explicit ACL file paths.
    #[cfg(test)]
    pub(crate) fn with_paths(allow_path: PathBuf, deny_path: PathBuf) -> Self {
        Self::with_alias_sources(
            allow_path,
            deny_path,
            HostMap::new(),
            PathBuf::from(DEFAULT_HOSTS_PATH),
        )
    }

    /// Create a reloader with explicit ACL paths and alias sources.
    pub(crate) fn with_alias_sources(
        allow_path: PathBuf,
        deny_path: PathBuf,
        base_hosts: HostMap,
        hosts_path: PathBuf,
    ) -> Self {
        let last_allow_mtime = file_mtime(&allow_path);
        let last_deny_mtime = file_mtime(&deny_path);
        let hosts = HostMapReloader::new(base_hosts, hosts_path);
        let acl = PeerAcl::load_files_with_hosts(&allow_path, &deny_path, hosts.hosts());

        Self {
            acl,
            hosts,
            allow_path,
            deny_path,
            last_allow_mtime,
            last_deny_mtime,
        }
    }

    /// Get the current ACL.
    pub fn acl(&self) -> &PeerAcl {
        &self.acl
    }

    /// Return a human-readable snapshot of the loaded ACL state.
    pub fn status(&self) -> PeerAclStatus {
        PeerAclStatus {
            allow_file: self.allow_path.display().to_string(),
            deny_file: self.deny_path.display().to_string(),
            enforcement_active: !self.acl.is_empty(),
            effective_mode: self.acl.effective_mode().to_string(),
            default_decision: self.acl.default_decision().to_string(),
            allow_all: self.acl.allow_all,
            deny_all: self.acl.deny_all,
            allow_raw_entries: self.acl.allow_raw_entries(),
            deny_raw_entries: self.acl.deny_raw_entries(),
            allow_entries: self.acl.allow_entries(),
            deny_entries: self.acl.deny_entries(),
        }
    }

    /// Reload ACL files immediately, regardless of mtime.
    pub fn reload_now(&mut self) {
        self.last_allow_mtime = file_mtime(&self.allow_path);
        self.last_deny_mtime = file_mtime(&self.deny_path);
        let _ = self.hosts.check_reload();
        self.acl =
            PeerAcl::load_files_with_hosts(&self.allow_path, &self.deny_path, self.hosts.hosts());
    }

    /// Check whether ACL or hosts alias sources changed and reload if needed.
    pub fn check_reload(&mut self) -> bool {
        let allow_mtime = file_mtime(&self.allow_path);
        let deny_mtime = file_mtime(&self.deny_path);
        let hosts_changed = self.hosts.check_reload();

        if allow_mtime == self.last_allow_mtime
            && deny_mtime == self.last_deny_mtime
            && !hosts_changed
        {
            return false;
        }

        self.last_allow_mtime = allow_mtime;
        self.last_deny_mtime = deny_mtime;
        self.acl =
            PeerAcl::load_files_with_hosts(&self.allow_path, &self.deny_path, self.hosts.hosts());

        info!(
            allow_file = %self.allow_path.display(),
            deny_file = %self.deny_path.display(),
            allow_entries = self.acl.allow.len(),
            deny_entries = self.acl.deny.len(),
            alias_entries = self.hosts.hosts().len(),
            allow_all = self.acl.allow_all,
            deny_all = self.acl.deny_all,
            "Reloaded peer ACL files"
        );
        true
    }
}

impl Node {
    /// Reload the peer ACL if the ACL or hosts files changed.
    pub(crate) fn reload_peer_acl(&mut self) -> bool {
        self.peer_acl.check_reload()
    }

    /// Return a control-plane snapshot of the current peer ACL.
    pub(crate) fn peer_acl_status(&self) -> PeerAclStatus {
        self.peer_acl.status()
    }

    /// Force an immediate ACL reload via the control socket.
    pub(crate) fn api_reload_acl(&mut self) -> serde_json::Value {
        self.peer_acl.reload_now();
        serde_json::to_value(self.peer_acl.status()).unwrap_or_default()
    }

    /// Reject a peer if the current ACL denies it.
    pub(crate) fn authorize_peer(
        &self,
        peer_identity: &PeerIdentity,
        context: PeerAclContext,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> Result<(), NodeError> {
        let decision = self.peer_acl.acl().check(peer_identity);
        if decision.allowed() {
            return Ok(());
        }

        let peer_node_addr = *peer_identity.node_addr();
        warn!(
            peer = %self.peer_display_name(&peer_node_addr),
            npub = %peer_identity.npub(),
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            context = %context,
            decision = %decision,
            "Rejected peer by ACL"
        );

        Err(NodeError::AccessDenied(format!(
            "peer {} rejected by ACL: {}",
            peer_identity.npub(),
            decision
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn test_npub() -> String {
        Identity::generate().npub()
    }

    fn test_peer(npub: &str) -> PeerIdentity {
        PeerIdentity::from_npub(npub).unwrap()
    }

    fn test_node_addr() -> NodeAddr {
        *test_peer(&test_npub()).node_addr()
    }

    fn write_file(path: &Path, contents: &str) {
        std::fs::write(path, contents).unwrap();
    }

    fn acl_with_shape(has_allow: bool, has_deny: bool, allow_all: bool, deny_all: bool) -> PeerAcl {
        let mut acl = PeerAcl::default();
        if has_allow {
            acl.allow.insert(test_node_addr());
        }
        if has_deny {
            acl.deny.insert(test_node_addr());
        }
        acl.allow_all = allow_all;
        acl.deny_all = deny_all;
        acl
    }

    #[test]
    fn test_acl_decision_allowed_and_display() {
        assert!(PeerAclDecision::AllowList.allowed());
        assert!(!PeerAclDecision::DenyList.allowed());
        assert!(PeerAclDecision::DefaultAllow.allowed());

        assert_eq!(PeerAclDecision::AllowList.to_string(), "allowlist match");
        assert_eq!(PeerAclDecision::DenyList.to_string(), "denylist match");
        assert_eq!(PeerAclDecision::DefaultAllow.to_string(), "default allow");
    }

    #[test]
    fn test_acl_context_display() {
        assert_eq!(
            PeerAclContext::OutboundConnect.to_string(),
            "outbound_connect"
        );
        assert_eq!(
            PeerAclContext::InboundHandshake.to_string(),
            "inbound_handshake"
        );
        assert_eq!(
            PeerAclContext::OutboundHandshake.to_string(),
            "outbound_handshake"
        );
    }

    #[test]
    fn test_acl_missing_files_default_open() {
        let acl = PeerAcl::load_files(
            Path::new("/nonexistent/allow"),
            Path::new("/nonexistent/deny"),
        );
        let peer = PeerIdentity::from_npub(&test_npub()).unwrap();

        assert_eq!(acl.check(&peer), PeerAclDecision::DefaultAllow);
        assert!(acl.is_empty());
    }

    #[test]
    fn test_acl_allow_match_wins() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let npub = test_npub();

        std::fs::write(&allow, format!("{npub}\n")).unwrap();
        std::fs::write(&deny, format!("ALL\n{npub}\n")).unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);
        let peer = PeerIdentity::from_npub(&npub).unwrap();

        assert_eq!(acl.check(&peer), PeerAclDecision::AllowList);
    }

    #[test]
    fn test_acl_allow_all_overrides_deny_all_and_specific_entries() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let npub = test_npub();

        write_file(&allow, "aLl # wildcard\n");
        write_file(&deny, &format!("ALL\n{npub}\n"));

        let acl = PeerAcl::load_files(&allow, &deny);
        let peer = test_peer(&npub);

        assert_eq!(acl.check(&peer), PeerAclDecision::AllowList);
        assert_eq!(acl.effective_mode(), "allow_all");
        assert_eq!(acl.default_decision(), "allow");
        assert!(acl.allow_raw_entries().is_empty());
        assert_eq!(acl.deny_raw_entries(), vec![npub.clone()]);
        assert!(acl.allow_entries().is_empty());
        assert_eq!(acl.deny_entries(), vec![npub]);
    }

    #[test]
    fn test_acl_allowlist_miss_falls_through_to_default_allow() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let allowed = test_npub();
        let denied = test_npub();

        std::fs::write(&allow, format!("{allowed}\n")).unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);

        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&allowed).unwrap()),
            PeerAclDecision::AllowList
        );
        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&denied).unwrap()),
            PeerAclDecision::DefaultAllow
        );
    }

    #[test]
    fn test_acl_deny_only() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let denied = test_npub();
        let other = test_npub();

        std::fs::write(&deny, format!("{denied}\n")).unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);

        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&denied).unwrap()),
            PeerAclDecision::DenyList
        );
        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&other).unwrap()),
            PeerAclDecision::DefaultAllow
        );
    }

    #[test]
    fn test_acl_deny_all() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");

        std::fs::write(&deny, "ALL\n").unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);
        let peer = PeerIdentity::from_npub(&test_npub()).unwrap();

        assert_eq!(acl.check(&peer), PeerAclDecision::DenyList);
    }

    #[test]
    fn test_acl_deny_applies_after_allowlist_miss() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let allowed = test_npub();
        let denied = test_npub();

        std::fs::write(&allow, format!("{allowed}\n")).unwrap();
        std::fs::write(&deny, format!("{denied}\n")).unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);

        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&denied).unwrap()),
            PeerAclDecision::DenyList
        );
    }

    #[test]
    fn test_acl_effective_mode_and_default_decision_matrix() {
        let default_open = acl_with_shape(false, false, false, false);
        assert_eq!(default_open.effective_mode(), "default_open");
        assert_eq!(default_open.default_decision(), "allow");

        let allowlist = acl_with_shape(true, false, false, false);
        assert_eq!(allowlist.effective_mode(), "allowlist");
        assert_eq!(allowlist.default_decision(), "allow");

        let denylist = acl_with_shape(false, true, false, false);
        assert_eq!(denylist.effective_mode(), "denylist");
        assert_eq!(denylist.default_decision(), "allow");

        let allow_then_deny = acl_with_shape(true, true, false, false);
        assert_eq!(allow_then_deny.effective_mode(), "allow_then_deny");
        assert_eq!(allow_then_deny.default_decision(), "allow");

        let deny_all = acl_with_shape(false, false, false, true);
        assert_eq!(deny_all.effective_mode(), "deny_all");
        assert_eq!(deny_all.default_decision(), "deny");

        let allow_then_deny_all = acl_with_shape(true, false, false, true);
        assert_eq!(allow_then_deny_all.effective_mode(), "allow_then_deny_all");
        assert_eq!(allow_then_deny_all.default_decision(), "deny");

        let allow_all = acl_with_shape(false, false, true, false);
        assert_eq!(allow_all.effective_mode(), "allow_all");
        assert_eq!(allow_all.default_decision(), "allow");
    }

    #[test]
    fn test_acl_inline_comments_and_bad_lines() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let npub = test_npub();

        std::fs::write(
            &allow,
            format!("# comment\n{npub} # inline comment\ninvalid entry here\n"),
        )
        .unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);

        assert_eq!(
            acl.check(&PeerIdentity::from_npub(&npub).unwrap()),
            PeerAclDecision::AllowList
        );
    }

    #[test]
    fn test_acl_unknown_alias_and_invalid_entries_do_not_activate_enforcement() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");

        write_file(
            &allow,
            "# comment only\nunknown-alias\nnot-a-valid-npub\ninvalid entry here\n",
        );

        let acl = PeerAcl::load_files(&allow, &deny);

        assert!(acl.is_empty());
        assert!(acl.allow_raw_entries().is_empty());
        assert!(acl.allow_entries().is_empty());
    }

    #[test]
    fn test_acl_read_error_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        std::fs::create_dir(&allow).unwrap();

        let acl = PeerAcl::load_files(&allow, &deny);

        assert!(acl.is_empty());
        assert_eq!(
            acl.check(&test_peer(&test_npub())),
            PeerAclDecision::DefaultAllow
        );
    }

    #[test]
    fn test_acl_alias_lookup_is_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let npub = test_npub();
        let mut hosts = HostMap::new();

        hosts.insert("node-a", &npub).unwrap();
        write_file(&allow, "NODE-A\n");

        let acl = PeerAcl::load_files_with_hosts(&allow, &deny, &hosts);

        assert_eq!(acl.allow_raw_entries(), vec!["NODE-A".to_string()]);
        assert_eq!(acl.allow_entries(), vec![npub.clone()]);
        assert_eq!(acl.check(&test_peer(&npub)), PeerAclDecision::AllowList);
    }

    #[test]
    fn test_acl_alias_and_npub_for_same_peer_deduplicate_effective_entries() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let npub = test_npub();
        let mut hosts = HostMap::new();

        hosts.insert("node-a", &npub).unwrap();
        write_file(&allow, &format!("node-a\n{npub}\nnode-a\n"));

        let acl = PeerAcl::load_files_with_hosts(&allow, &deny, &hosts);

        assert_eq!(
            acl.allow_raw_entries(),
            vec!["node-a".to_string(), npub.clone()]
        );
        assert_eq!(acl.allow_entries(), vec![npub.clone()]);
        assert_eq!(acl.check(&test_peer(&npub)), PeerAclDecision::AllowList);
    }

    #[test]
    fn test_acl_reloader_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let denied = test_npub();

        let mut reloader = PeerAclReloader::with_paths(allow.clone(), deny.clone());
        assert!(!reloader.check_reload());

        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(&deny, format!("{denied}\n")).unwrap();

        assert!(reloader.check_reload());
        assert_eq!(
            reloader
                .acl()
                .check(&PeerIdentity::from_npub(&denied).unwrap()),
            PeerAclDecision::DenyList
        );
    }

    #[test]
    fn test_acl_reloader_detects_allow_file_removal() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let allowed = test_npub();

        write_file(&allow, &format!("{allowed}\n"));
        let mut reloader = PeerAclReloader::with_paths(allow.clone(), deny);
        assert_eq!(
            reloader.acl().check(&test_peer(&allowed)),
            PeerAclDecision::AllowList
        );

        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::remove_file(&allow).unwrap();

        assert!(reloader.check_reload());
        assert!(reloader.acl().is_empty());
        assert_eq!(
            reloader.acl().check(&test_peer(&allowed)),
            PeerAclDecision::DefaultAllow
        );
    }

    #[test]
    fn test_acl_status_reports_effective_state_and_entries() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let allowed = test_npub();
        let denied = test_npub();

        std::fs::write(&allow, format!("{allowed}\n")).unwrap();
        std::fs::write(&deny, format!("{denied}\n")).unwrap();

        let reloader = PeerAclReloader::with_paths(allow.clone(), deny.clone());
        let status = reloader.status();

        assert_eq!(status.allow_file, allow.display().to_string());
        assert_eq!(status.deny_file, deny.display().to_string());
        assert!(status.enforcement_active);
        assert_eq!(status.effective_mode, "allow_then_deny");
        assert_eq!(status.default_decision, "allow");
        assert_eq!(status.allow_raw_entries, vec![allowed.clone()]);
        assert_eq!(status.deny_raw_entries, vec![denied.clone()]);
        assert_eq!(status.allow_entries, vec![allowed]);
        assert_eq!(status.deny_entries, vec![denied]);
    }

    #[test]
    fn test_acl_status_reports_default_open_state() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");

        let reloader = PeerAclReloader::with_paths(allow, deny);
        let status = reloader.status();

        assert!(!status.enforcement_active);
        assert_eq!(status.effective_mode, "default_open");
        assert_eq!(status.default_decision, "allow");
        assert!(!status.allow_all);
        assert!(!status.deny_all);
        assert!(status.allow_raw_entries.is_empty());
        assert!(status.deny_raw_entries.is_empty());
        assert!(status.allow_entries.is_empty());
        assert!(status.deny_entries.is_empty());
    }

    #[test]
    fn test_acl_status_reports_allow_all_state() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        write_file(&allow, "ALL\n");

        let reloader = PeerAclReloader::with_paths(allow, deny);
        let status = reloader.status();

        assert!(status.enforcement_active);
        assert_eq!(status.effective_mode, "allow_all");
        assert_eq!(status.default_decision, "allow");
        assert!(status.allow_all);
        assert!(!status.deny_all);
        assert!(status.allow_raw_entries.is_empty());
        assert!(status.allow_entries.is_empty());
    }

    #[test]
    fn test_acl_status_reports_deny_all_default_decision() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");

        std::fs::write(&deny, "ALL\n").unwrap();

        let reloader = PeerAclReloader::with_paths(allow, deny);
        let status = reloader.status();

        assert_eq!(status.effective_mode, "deny_all");
        assert_eq!(status.default_decision, "deny");
    }

    #[test]
    fn test_acl_alias_resolves_from_host_map() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let npub = test_npub();
        let mut hosts = HostMap::new();

        hosts.insert("node-a", &npub).unwrap();
        std::fs::write(&allow, "node-a\n").unwrap();

        let acl = PeerAcl::load_files_with_hosts(&allow, &deny, &hosts);
        let peer = PeerIdentity::from_npub(&npub).unwrap();

        assert_eq!(acl.allow_raw_entries(), vec!["node-a".to_string()]);
        assert_eq!(acl.allow_entries(), vec![npub]);
        assert_eq!(acl.check(&peer), PeerAclDecision::AllowList);
    }

    #[test]
    fn test_acl_reloader_detects_hosts_change_for_alias_entry() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let hosts = dir.path().join("hosts");
        let npub = test_npub();

        std::fs::write(&allow, "node-a\n").unwrap();

        let mut reloader =
            PeerAclReloader::with_alias_sources(allow.clone(), deny, HostMap::new(), hosts.clone());
        assert!(reloader.acl().is_empty());

        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(&hosts, format!("node-a {npub}\n")).unwrap();

        assert!(reloader.check_reload());
        assert_eq!(
            reloader.acl().allow_raw_entries(),
            vec!["node-a".to_string()]
        );
        assert_eq!(reloader.acl().allow_entries(), vec![npub.clone()]);
        assert_eq!(
            reloader
                .acl()
                .check(&PeerIdentity::from_npub(&npub).unwrap()),
            PeerAclDecision::AllowList
        );
    }

    #[test]
    fn test_acl_reloader_detects_hosts_removal_for_alias_entry() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let hosts = dir.path().join("hosts");
        let npub = test_npub();

        write_file(&allow, "node-a\n");
        write_file(&hosts, &format!("node-a {npub}\n"));

        let mut reloader =
            PeerAclReloader::with_alias_sources(allow, deny, HostMap::new(), hosts.clone());
        assert_eq!(
            reloader.acl().check(&test_peer(&npub)),
            PeerAclDecision::AllowList
        );

        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::remove_file(&hosts).unwrap();

        assert!(reloader.check_reload());
        assert!(reloader.acl().is_empty());
        assert_eq!(
            reloader.acl().check(&test_peer(&npub)),
            PeerAclDecision::DefaultAllow
        );
    }
}
