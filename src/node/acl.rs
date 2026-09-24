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

use crate::node::reloadable::Reloadable;
use crate::node::{Node, NodeError};
use crate::transport::{TransportAddr, TransportId};
use crate::upper::hosts::{DEFAULT_HOSTS_PATH, HostMap, HostMapReloader, file_mtime};
use crate::{NodeAddr, PeerIdentity};
use serde::Serialize;
use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{debug, error, info, warn};

/// Default path for the peer allow list.
///
/// On macOS (`packaging/macos/`) and FreeBSD (`packaging/freebsd/`) the
/// install layout ships config under `/usr/local/etc/fips/` rather than
/// `/etc/fips/`; the default follows the platform's packaging so the daemon
/// reads the file the operator was told to edit. Windows uses
/// `C:\ProgramData\fips\`, beside the config and hosts file the service
/// installer sets up. Linux and other Unix keep the historic `/etc/fips/`
/// location.
#[cfg(not(any(target_os = "macos", target_os = "freebsd", windows)))]
pub const DEFAULT_PEERS_ALLOW_PATH: &str = "/etc/fips/peers.allow";
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub const DEFAULT_PEERS_ALLOW_PATH: &str = "/usr/local/etc/fips/peers.allow";
#[cfg(windows)]
pub const DEFAULT_PEERS_ALLOW_PATH: &str = r"C:\ProgramData\fips\peers.allow";

/// Default path for the peer deny list.
///
/// See [`DEFAULT_PEERS_ALLOW_PATH`] for the per-platform rationale.
#[cfg(not(any(target_os = "macos", target_os = "freebsd", windows)))]
pub const DEFAULT_PEERS_DENY_PATH: &str = "/etc/fips/peers.deny";
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub const DEFAULT_PEERS_DENY_PATH: &str = "/usr/local/etc/fips/peers.deny";
#[cfg(windows)]
pub const DEFAULT_PEERS_DENY_PATH: &str = r"C:\ProgramData\fips\peers.deny";

/// Warn about config files stranded at the pre-move default location.
///
/// The macOS/FreeBSD defaults for `hosts`, `peers.allow` and `peers.deny`
/// moved from `/etc/fips` to `/usr/local/etc/fips`, the directory both
/// installers actually populate. The old location is no longer read, and
/// a `peers.deny` silently left behind there would fail open (a missing
/// deny list is not an error), so surface the situation loudly once at
/// startup.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub fn warn_on_legacy_config_paths() {
    for (current, name) in [
        (crate::upper::hosts::DEFAULT_HOSTS_PATH, "hosts"),
        (DEFAULT_PEERS_ALLOW_PATH, "peers.allow"),
        (DEFAULT_PEERS_DENY_PATH, "peers.deny"),
    ] {
        let legacy = format!("/etc/fips/{name}");
        if std::path::Path::new(&legacy).exists() && !std::path::Path::new(current).exists() {
            warn!(
                legacy = %legacy,
                current = %current,
                "Config file found at legacy path but not at the current default; \
                 it is no longer read — move it to the current path"
            );
        }
    }
}

/// Which of an ACL file's two locations the reloader reads.
///
/// Windows read `peers.allow` and `peers.deny` from `\etc\fips` on the current
/// drive before they moved to `C:\ProgramData\fips`. Ignoring a deny list
/// left at the old location would fail open, so for one release a file found
/// only there is still enforced, with a warning to move it. This fallback, with
/// [`default_legacy_paths`], is meant to be removed in a later release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AclPathChoice {
    /// Read the current default; nothing is at the legacy location.
    Current,
    /// Read the legacy location: the file is there and not at the current
    /// default.
    Legacy,
    /// Read the current default; a file also left at the legacy location is
    /// ignored.
    LegacyIgnored,
}

/// Choose where to read one ACL file from: its current default path, or the
/// location an earlier release read it from.
///
/// `exists` is passed in so the rule can be tested on any platform. The
/// current path wins whenever it exists; the legacy one is read only when it
/// is the sole file present.
fn select_acl_path(current: &Path, legacy: &Path, exists: impl Fn(&Path) -> bool) -> AclPathChoice {
    match (exists(current), exists(legacy)) {
        (true, true) => AclPathChoice::LegacyIgnored,
        (false, true) => AclPathChoice::Legacy,
        (_, false) => AclPathChoice::Current,
    }
}

/// Whether a path exists, counting one that cannot be checked as present.
///
/// A current file that is there but inaccessible then stays selected, and
/// the loader reports it as unreadable, rather than an older legacy file
/// being enforced in its place without a word.
fn path_present(path: &Path) -> bool {
    path.try_exists().unwrap_or(true)
}

/// Locations an earlier release read the ACL files from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LegacyAclPaths {
    pub(crate) allow: PathBuf,
    pub(crate) deny: PathBuf,
}

/// The legacy ACL locations honoured on this platform.
///
/// On Windows that is `/etc/fips`, the exact path the `/etc/fips/peers.*`
/// defaults named before the move to `C:\ProgramData\fips`. It is kept
/// drive-relative on purpose: Windows resolves it against the current
/// drive, as it did then, so a run started from another drive still finds
/// the file an earlier release read there. Other platforms have
/// none; see [`AclPathChoice`] for why the fallback exists and that it is
/// meant to be removed in a later release.
#[cfg(windows)]
fn default_legacy_paths() -> Option<LegacyAclPaths> {
    Some(LegacyAclPaths {
        allow: PathBuf::from("/etc/fips/peers.allow"),
        deny: PathBuf::from("/etc/fips/peers.deny"),
    })
}

/// The legacy ACL locations honoured on this platform: none.
#[cfg(not(windows))]
fn default_legacy_paths() -> Option<LegacyAclPaths> {
    None
}

/// One ACL file's current default and legacy location, with the choice the
/// last selection made between them.
struct AclFallback {
    current: PathBuf,
    legacy: PathBuf,
    /// `None` until the first selection, so the startup choice is logged.
    choice: Option<AclPathChoice>,
}

impl AclFallback {
    /// Pair a current default path with its legacy location.
    fn new(current: PathBuf, legacy: PathBuf) -> Self {
        Self {
            current,
            legacy,
            choice: None,
        }
    }

    /// Select the location to read, logging the choice when it changes.
    fn select(&mut self) -> &Path {
        let choice = select_acl_path(&self.current, &self.legacy, path_present);
        if self.choice != Some(choice) {
            match choice {
                AclPathChoice::Legacy => warn!(
                    legacy = %self.legacy.display(),
                    current = %self.current.display(),
                    "Peer ACL file found only at its legacy path; enforcing it from there \
                     for now — move it to the current path, the legacy path will stop \
                     being read in a later release"
                ),
                AclPathChoice::LegacyIgnored => warn!(
                    legacy = %self.legacy.display(),
                    current = %self.current.display(),
                    "Peer ACL file found at both its legacy and current paths; the legacy \
                     file is ignored — remove it"
                ),
                AclPathChoice::Current if self.choice.is_some() => info!(
                    legacy = %self.legacy.display(),
                    current = %self.current.display(),
                    "Peer ACL file no longer at its legacy path; reading the current path"
                ),
                AclPathChoice::Current => {}
            }
            self.choice = Some(choice);
        }
        match choice {
            AclPathChoice::Legacy => &self.legacy,
            AclPathChoice::Current | AclPathChoice::LegacyIgnored => &self.current,
        }
    }
}

/// Point `path` at the location `fallback` selects, if there is a fallback,
/// and report whether it moved.
fn reselect(fallback: &mut Option<AclFallback>, path: &mut PathBuf) -> bool {
    let Some(fallback) = fallback else {
        return false;
    };
    let selected = fallback.select();
    if selected == path.as_path() {
        return false;
    }
    *path = selected.to_path_buf();
    true
}

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

/// How many consecutive reloads the empty-snapshot guard may hold back.
///
/// A reload whose files all read cleanly but which yields an empty ACL where
/// an enforcing one was in force is more likely a read that raced an in-place
/// rewrite than a policy change, so the previous snapshot is held. The guard
/// releases after this many holds, so an operator who deliberately blanks an
/// ACL file in place still converges, one tick late. Raising it widens the
/// window in which a genuine emptying is ignored; setting it to zero disables
/// the torn-read protection.
const EMPTY_ACL_HOLD_LIMIT: u32 = 1;

/// A peer ACL input file exists but could not be read.
#[derive(Debug, thiserror::Error)]
#[error("failed to read {}: {source}", path.display())]
pub struct AclLoadError {
    /// The file whose read failed.
    pub path: PathBuf,
    /// The underlying I/O failure.
    #[source]
    pub source: std::io::Error,
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
    pub allow_file_entries: Vec<String>,
    pub deny_file_entries: Vec<String>,
    pub allow_entries: Vec<String>,
    pub deny_entries: Vec<String>,
    /// Whether the ACL in force is older than the files on disk because a
    /// reload input could not be read.
    pub stale: bool,
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
    allow_file_entries: BTreeSet<String>,
    deny_file_entries: BTreeSet<String>,
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
        Self::try_load_files_with_hosts(allow_path, deny_path, &hosts).unwrap()
    }

    /// Load the allow/deny files into a new ACL using alias resolution.
    ///
    /// An absent file is a policy and contributes an empty set; a file that
    /// is present and unreadable is a fault and is returned as an error, so
    /// the caller can keep enforcing whatever it loaded last rather than
    /// silently becoming an open node.
    pub fn try_load_files_with_hosts(
        allow_path: &Path,
        deny_path: &Path,
        hosts: &HostMap,
    ) -> Result<Self, AclLoadError> {
        let mut acl = Self::new();
        acl.load_file(allow_path, true, hosts)?;
        acl.load_file(deny_path, false, hosts)?;
        acl.log_loaded();
        Ok(acl)
    }

    /// Log the shape of a freshly loaded ACL, unless it has no entries.
    fn log_loaded(&self) {
        if !self.is_empty() {
            debug!(
                allow_entries = self.allow.len(),
                deny_entries = self.deny.len(),
                allow_all = self.allow_all,
                deny_all = self.deny_all,
                "Loaded peer ACL files"
            );
        }
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
    pub fn allow_file_entries(&self) -> Vec<String> {
        self.allow_file_entries.iter().cloned().collect()
    }

    /// Return the loaded denylist entries as npubs.
    pub fn deny_entries(&self) -> Vec<String> {
        self.deny_npubs.iter().cloned().collect()
    }

    /// Return the loaded denylist tokens exactly as written in the ACL file.
    pub fn deny_file_entries(&self) -> Vec<String> {
        self.deny_file_entries.iter().cloned().collect()
    }

    /// Merge one ACL file into this ACL.
    ///
    /// An absent file is a policy and an unreadable one is a fault, and
    /// `NotFound` alone does not say which: a stat that still finds the file
    /// after the read missed it means the file is being rewritten under us,
    /// which is transient and must not be published as an empty policy.
    fn load_file(
        &mut self,
        path: &Path,
        is_allow: bool,
        hosts: &HostMap,
    ) -> Result<(), AclLoadError> {
        let contents = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && file_mtime(path).is_none() => {
                debug!(path = %path.display(), "No ACL file found, skipping");
                return Ok(());
            }
            Err(e) => {
                return Err(AclLoadError {
                    path: path.to_path_buf(),
                    source: e,
                });
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
                self.allow_file_entries.insert(entry.to_string());
                self.allow_npubs.insert(resolved_npub);
            } else {
                self.deny.insert(*peer.node_addr());
                self.deny_file_entries.insert(entry.to_string());
                self.deny_npubs.insert(resolved_npub);
            }
        }

        Ok(())
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
///
/// Follows the canonical Arc-wrapper template from [`Reloadable`]: the
/// reader-facing [`PeerAcl`] snapshot is published through an
/// [`arc_swap::ArcSwap`] so the authorization hot path reads it without
/// locking, while the reloader's change-detection state (file mtimes, the
/// embedded hosts reloader) is touched only by [`Reloadable::reload`] on the
/// single node tick task.
pub struct PeerAclReloader {
    /// Reader-facing effective ACL snapshot.
    acl: arc_swap::ArcSwap<PeerAcl>,
    hosts: HostMapReloader,
    /// The allow and deny files read on the last load: the current defaults,
    /// or a legacy location a fallback below selected instead.
    allow_path: PathBuf,
    deny_path: PathBuf,
    /// Legacy locations re-checked on every reload, so the choice follows
    /// the files as the operator moves them. `None` off Windows.
    allow_fallback: Option<AclFallback>,
    deny_fallback: Option<AclFallback>,
    last_allow_mtime: Option<SystemTime>,
    last_deny_mtime: Option<SystemTime>,
    /// Set while a reload input is unreadable. Forces the next reload
    /// attempt regardless of mtimes, because the mtime comparison alone
    /// cannot see a change the hosts reloader has already consumed, and
    /// gates the fault log to the transition into the held state.
    retry_pending: bool,
    /// Consecutive reloads held back by the empty-snapshot guard.
    empty_holds: u32,
}

impl PeerAclReloader {
    /// Create a reloader using the standard ACL file locations.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::with_default_paths(HostMap::new(), PathBuf::from(DEFAULT_HOSTS_PATH))
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

    /// Create the node's reloader: the platform's default ACL paths, plus
    /// the legacy locations still honoured there (Windows only).
    pub(crate) fn with_default_paths(base_hosts: HostMap, hosts_path: PathBuf) -> Self {
        Self::with_legacy_sources(
            PathBuf::from(DEFAULT_PEERS_ALLOW_PATH),
            PathBuf::from(DEFAULT_PEERS_DENY_PATH),
            default_legacy_paths(),
            base_hosts,
            hosts_path,
        )
    }

    /// Create a reloader with explicit ACL paths and alias sources.
    #[cfg(test)]
    pub(crate) fn with_alias_sources(
        allow_path: PathBuf,
        deny_path: PathBuf,
        base_hosts: HostMap,
        hosts_path: PathBuf,
    ) -> Self {
        Self::with_legacy_sources(allow_path, deny_path, None, base_hosts, hosts_path)
    }

    /// Create a reloader with explicit ACL paths and alias sources that
    /// reads each ACL file from its `legacy` location while the file is
    /// absent from its current one.
    pub(crate) fn with_legacy_sources(
        mut allow_path: PathBuf,
        mut deny_path: PathBuf,
        legacy: Option<LegacyAclPaths>,
        base_hosts: HostMap,
        hosts_path: PathBuf,
    ) -> Self {
        let (mut allow_fallback, mut deny_fallback) = match legacy {
            Some(legacy) => (
                Some(AclFallback::new(allow_path.clone(), legacy.allow)),
                Some(AclFallback::new(deny_path.clone(), legacy.deny)),
            ),
            None => (None, None),
        };
        reselect(&mut allow_fallback, &mut allow_path);
        reselect(&mut deny_fallback, &mut deny_path);

        let last_allow_mtime = file_mtime(&allow_path);
        let last_deny_mtime = file_mtime(&deny_path);
        let hosts = HostMapReloader::new(base_hosts, hosts_path);

        // There is no last-good snapshot to hold at startup, so an
        // unreadable file still comes up on an empty ACL, as it always has.
        // It is logged as the fault it is and armed for retry, so the first
        // tick after the file becomes readable enforces the real policy.
        let (acl, retry_pending) =
            match PeerAcl::try_load_files_with_hosts(&allow_path, &deny_path, hosts.hosts()) {
                Ok(acl) => (acl, false),
                Err(e) => {
                    error!(
                        path = %e.path.display(),
                        error = %e.source,
                        "Peer ACL file is present but unreadable; starting with no ACL entries"
                    );
                    (PeerAcl::new(), true)
                }
            };

        Self {
            acl: arc_swap::ArcSwap::from(Arc::new(acl)),
            hosts,
            allow_path,
            deny_path,
            allow_fallback,
            deny_fallback,
            last_allow_mtime,
            last_deny_mtime,
            retry_pending,
            empty_holds: 0,
        }
    }

    /// Keep the published snapshot after a reload input failed to read.
    ///
    /// Leaves the recorded mtimes and the ACL in force untouched, arms the
    /// retry so the next tick reloads regardless of mtimes, and logs the
    /// fault once, on the transition into the held state, rather than once
    /// per tick for as long as the fault lasts.
    fn hold_snapshot(&mut self, path: &Path, error: &dyn fmt::Display) {
        if !self.retry_pending {
            error!(
                path = %path.display(),
                error = %error,
                "Peer ACL input is unreadable; holding the last loaded ACL"
            );
        }
        self.retry_pending = true;
    }

    /// Acquire a lock-free guard over the current ACL snapshot.
    pub fn acl(&self) -> arc_swap::Guard<Arc<PeerAcl>> {
        self.load()
    }

    /// Return a human-readable snapshot of the loaded ACL state.
    pub fn status(&self) -> PeerAclStatus {
        let acl = self.acl.load();
        PeerAclStatus {
            allow_file: self.allow_path.display().to_string(),
            deny_file: self.deny_path.display().to_string(),
            enforcement_active: !acl.is_empty(),
            effective_mode: acl.effective_mode().to_string(),
            default_decision: acl.default_decision().to_string(),
            allow_all: acl.allow_all,
            deny_all: acl.deny_all,
            allow_file_entries: acl.allow_file_entries(),
            deny_file_entries: acl.deny_file_entries(),
            allow_entries: acl.allow_entries(),
            deny_entries: acl.deny_entries(),
            stale: self.retry_pending,
        }
    }
}

impl Reloadable for PeerAclReloader {
    type Snapshot = PeerAcl;

    async fn reload(&mut self) -> bool {
        // A switch between a legacy and a current location forces the load:
        // a copied file can carry the same mtime as the one it replaces.
        let allow_moved = reselect(&mut self.allow_fallback, &mut self.allow_path);
        let deny_moved = reselect(&mut self.deny_fallback, &mut self.deny_path);
        let allow_mtime = file_mtime(&self.allow_path);
        let deny_mtime = file_mtime(&self.deny_path);
        let hosts_changed = match self.hosts.try_check_reload() {
            Ok(changed) => changed,
            Err(e) => {
                let path = self.hosts.path().to_path_buf();
                self.hold_snapshot(&path, &e);
                return false;
            }
        };

        if allow_mtime == self.last_allow_mtime
            && deny_mtime == self.last_deny_mtime
            && !hosts_changed
            && !self.retry_pending
            && !allow_moved
            && !deny_moved
        {
            return false;
        }

        let new_acl = match PeerAcl::try_load_files_with_hosts(
            &self.allow_path,
            &self.deny_path,
            self.hosts.hosts(),
        ) {
            Ok(acl) => acl,
            Err(e) => {
                self.hold_snapshot(&e.path.clone(), &e.source);
                return false;
            }
        };

        // Every input read cleanly and the policy still evaporated. With the
        // ACL files themselves freshly written and still on disk that is more
        // likely a read that caught one mid-rewrite than an operator emptying
        // both lists, so hold and look again next tick. Deleting a file, or
        // dropping the aliases an entry resolved through, remains an
        // unambiguous way to say "no policy" and is published immediately.
        let acl_files_changed =
            allow_mtime != self.last_allow_mtime || deny_mtime != self.last_deny_mtime;
        if new_acl.is_empty()
            && !self.acl.load().is_empty()
            && acl_files_changed
            && (allow_mtime.is_some() || deny_mtime.is_some())
            && self.empty_holds < EMPTY_ACL_HOLD_LIMIT
        {
            self.empty_holds += 1;
            self.retry_pending = true;
            warn!(
                allow_file = %self.allow_path.display(),
                deny_file = %self.deny_path.display(),
                "Peer ACL reload emptied an enforcing ACL; holding the last loaded ACL"
            );
            return false;
        }

        if self.retry_pending {
            info!(
                allow_file = %self.allow_path.display(),
                deny_file = %self.deny_path.display(),
                "Peer ACL inputs read cleanly again; publishing the files on disk"
            );
        }
        self.retry_pending = false;
        self.empty_holds = 0;
        self.last_allow_mtime = allow_mtime;
        self.last_deny_mtime = deny_mtime;

        info!(
            allow_file = %self.allow_path.display(),
            deny_file = %self.deny_path.display(),
            allow_entries = new_acl.allow.len(),
            deny_entries = new_acl.deny.len(),
            alias_entries = self.hosts.hosts().len(),
            allow_all = new_acl.allow_all,
            deny_all = new_acl.deny_all,
            "Reloaded peer ACL files"
        );
        self.acl.store(Arc::new(new_acl));
        true
    }

    fn load(&self) -> arc_swap::Guard<Arc<PeerAcl>> {
        self.acl.load()
    }
}

impl Node {
    /// Reload the peer ACL if the ACL or hosts files changed.
    pub(crate) async fn reload_peer_acl(&mut self) -> bool {
        self.peer_acl.reload().await
    }

    /// Return a control-plane snapshot of the current peer ACL.
    pub(crate) fn peer_acl_status(&self) -> PeerAclStatus {
        self.peer_acl.status()
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

    /// Test-only: replace the peer-ACL reloader with one that reads from
    /// the given paths, isolating the node from the host's real
    /// `peers.allow` / `peers.deny` files. Used by snapshot tests
    /// that must be deterministic regardless of whether an operator has
    /// edited the system ACL files on the dev/CI machine.
    #[cfg(test)]
    pub(crate) fn isolate_peer_acl_for_test(&mut self, allow: PathBuf, deny: PathBuf) {
        self.peer_acl = PeerAclReloader::with_paths(allow, deny);
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

    // Guard against the path regression: the macOS and FreeBSD install
    // layouts (`packaging/macos/`, `packaging/freebsd/`) ship config under
    // `/usr/local/etc/fips/`, so the default ACL paths must follow it, or
    // `peers.allow`/`peers.deny` are silently unread there (see the
    // `NotFound` no-op in `load_file`).
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn test_default_acl_paths_follow_packaging_layout() {
        assert_eq!(DEFAULT_PEERS_ALLOW_PATH, "/usr/local/etc/fips/peers.allow");
        assert_eq!(DEFAULT_PEERS_DENY_PATH, "/usr/local/etc/fips/peers.deny");
    }

    // Other Unix/Linux keeps the historic `/etc/fips/` location; this
    // runs on the Linux CI matrix and pins the value so a future refactor
    // can't silently drift it.
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "freebsd"))))]
    #[test]
    fn test_default_acl_paths_keep_etc_fips_layout() {
        assert_eq!(DEFAULT_PEERS_ALLOW_PATH, "/etc/fips/peers.allow");
        assert_eq!(DEFAULT_PEERS_DENY_PATH, "/etc/fips/peers.deny");
    }

    // Windows keeps config, hosts and the ACL files in C:\ProgramData\fips,
    // where the service installer puts them.
    #[cfg(windows)]
    #[test]
    fn test_default_acl_paths_follow_windows_layout() {
        assert_eq!(DEFAULT_PEERS_ALLOW_PATH, r"C:\ProgramData\fips\peers.allow");
        assert_eq!(DEFAULT_PEERS_DENY_PATH, r"C:\ProgramData\fips\peers.deny");
    }

    // The hosts file, both ACL files and the config all belong in one
    // directory on every platform. A default that sits anywhere else is read
    // from a directory the operator was never told about, and a missing deny
    // list fails open.
    #[test]
    fn default_hosts_and_acl_paths_sit_in_the_system_config_dir() {
        let system = Some(Path::new(crate::config::SYSTEM_CONFIG_DIR));
        for path in [
            DEFAULT_HOSTS_PATH,
            DEFAULT_PEERS_ALLOW_PATH,
            DEFAULT_PEERS_DENY_PATH,
        ] {
            assert_eq!(
                Path::new(path).parent(),
                system,
                "{path} is outside the system config directory"
            );
        }
    }

    // Before the move to C:\ProgramData\fips, Windows resolved the
    // `/etc/fips/peers.*` defaults against the root of the current drive, so
    // that is where an existing deny list sits after an upgrade. The legacy
    // path stays drive-relative so a run from another drive finds it too.
    #[cfg(windows)]
    #[test]
    fn windows_honours_acl_files_at_the_old_drive_relative_location() {
        assert_eq!(
            default_legacy_paths(),
            Some(LegacyAclPaths {
                allow: PathBuf::from("/etc/fips/peers.allow"),
                deny: PathBuf::from("/etc/fips/peers.deny"),
            })
        );
    }

    // Only Windows moved its ACL files in a way that is still honoured; the
    // other platforms read exactly the one default path they always did.
    #[cfg(not(windows))]
    #[test]
    fn non_windows_platforms_have_no_legacy_acl_location() {
        assert_eq!(default_legacy_paths(), None);
    }

    /// Existence check over a fixed set of paths, for the selection tests.
    fn exists_among<'a>(present: &'a [&'a Path]) -> impl Fn(&Path) -> bool + 'a {
        move |p| present.contains(&p)
    }

    #[test]
    fn acl_path_selection_reads_the_legacy_file_when_only_it_exists() {
        let current = Path::new(r"C:\ProgramData\fips\peers.deny");
        let legacy = Path::new("/etc/fips/peers.deny");
        assert_eq!(
            select_acl_path(current, legacy, exists_among(&[legacy])),
            AclPathChoice::Legacy
        );
    }

    #[test]
    fn acl_path_selection_prefers_the_current_file_and_flags_the_legacy_one_when_both_exist() {
        let current = Path::new(r"C:\ProgramData\fips\peers.deny");
        let legacy = Path::new("/etc/fips/peers.deny");
        assert_eq!(
            select_acl_path(current, legacy, exists_among(&[current, legacy])),
            AclPathChoice::LegacyIgnored
        );
    }

    #[test]
    fn acl_path_selection_reads_the_current_path_when_nothing_is_at_the_legacy_one() {
        let current = Path::new(r"C:\ProgramData\fips\peers.deny");
        let legacy = Path::new("/etc/fips/peers.deny");
        assert_eq!(
            select_acl_path(current, legacy, exists_among(&[current])),
            AclPathChoice::Current
        );
        // Absent from both: the current path is read, and its absence is the
        // ordinary "no deny list" it has always been.
        assert_eq!(
            select_acl_path(current, legacy, exists_among(&[])),
            AclPathChoice::Current
        );
    }

    /// Current and legacy ACL paths under a temporary root, as
    /// `(allow, deny, legacy)`, with both directories created.
    fn legacy_layout(root: &Path) -> (PathBuf, PathBuf, LegacyAclPaths) {
        let new = root.join("new");
        let old = root.join("old");
        std::fs::create_dir_all(&new).unwrap();
        std::fs::create_dir_all(&old).unwrap();
        let legacy = LegacyAclPaths {
            allow: old.join("peers.allow"),
            deny: old.join("peers.deny"),
        };
        (new.join("peers.allow"), new.join("peers.deny"), legacy)
    }

    fn legacy_reloader(
        root: &Path,
        allow: &Path,
        deny: &Path,
        legacy: &LegacyAclPaths,
    ) -> PeerAclReloader {
        PeerAclReloader::with_legacy_sources(
            allow.to_path_buf(),
            deny.to_path_buf(),
            Some(legacy.clone()),
            HostMap::new(),
            root.join("hosts"),
        )
    }

    #[test]
    fn a_deny_list_left_only_at_the_legacy_location_is_still_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let (allow, deny, legacy) = legacy_layout(dir.path());
        let denied = test_npub();
        let allowed = test_npub();
        // The two files are chosen independently: the allow list is at its
        // current path, the deny list only at the legacy one.
        write_file(&allow, &format!("{allowed}\n"));
        write_file(&legacy.deny, &format!("{denied}\n"));

        let reloader = legacy_reloader(dir.path(), &allow, &deny, &legacy);

        assert_eq!(
            reloader.acl().check(&test_peer(&denied)),
            PeerAclDecision::DenyList
        );
        assert_eq!(
            reloader.acl().check(&test_peer(&allowed)),
            PeerAclDecision::AllowList
        );
        let status = reloader.status();
        assert_eq!(status.deny_file, legacy.deny.display().to_string());
        assert_eq!(status.allow_file, allow.display().to_string());
    }

    #[test]
    fn a_current_acl_file_wins_over_one_left_at_the_legacy_location() {
        let dir = tempfile::tempdir().unwrap();
        let (allow, deny, legacy) = legacy_layout(dir.path());
        let old_denied = test_npub();
        let new_denied = test_npub();
        write_file(&legacy.deny, &format!("{old_denied}\n"));
        write_file(&deny, &format!("{new_denied}\n"));

        let reloader = legacy_reloader(dir.path(), &allow, &deny, &legacy);

        assert_eq!(
            reloader.acl().check(&test_peer(&new_denied)),
            PeerAclDecision::DenyList
        );
        assert_eq!(
            reloader.acl().check(&test_peer(&old_denied)),
            PeerAclDecision::DefaultAllow
        );
        assert_eq!(reloader.status().deny_file, deny.display().to_string());
    }

    #[tokio::test]
    async fn acl_reload_re_evaluates_the_legacy_fallback_as_files_come_and_go() {
        let dir = tempfile::tempdir().unwrap();
        let (allow, deny, legacy) = legacy_layout(dir.path());
        let old_denied = test_npub();
        let new_denied = test_npub();
        write_file(&legacy.deny, &format!("{old_denied}\n"));

        let mut reloader = legacy_reloader(dir.path(), &allow, &deny, &legacy);
        assert_eq!(
            reloader.acl().check(&test_peer(&old_denied)),
            PeerAclDecision::DenyList
        );
        assert!(!reloader.reload().await, "nothing changed on disk");

        // The operator puts a deny list at the current path: it takes over.
        std::thread::sleep(std::time::Duration::from_millis(5));
        write_file(&deny, &format!("{new_denied}\n"));
        assert!(reloader.reload().await);
        assert_eq!(
            reloader.acl().check(&test_peer(&new_denied)),
            PeerAclDecision::DenyList
        );
        assert_eq!(
            reloader.acl().check(&test_peer(&old_denied)),
            PeerAclDecision::DefaultAllow
        );
        assert_eq!(reloader.status().deny_file, deny.display().to_string());

        // The current file goes away again: the legacy one is back in force.
        std::fs::remove_file(&deny).unwrap();
        assert!(reloader.reload().await);
        assert_eq!(
            reloader.acl().check(&test_peer(&old_denied)),
            PeerAclDecision::DenyList
        );
        assert_eq!(
            reloader.status().deny_file,
            legacy.deny.display().to_string()
        );
    }

    // A copy keeps its source's modification time on Windows, so a switch
    // between the two locations can leave the tracked mtime unchanged. The
    // switch itself must force the reload.
    #[tokio::test]
    async fn acl_reload_follows_a_switch_of_location_even_when_the_mtimes_match() {
        let dir = tempfile::tempdir().unwrap();
        let (allow, deny, legacy) = legacy_layout(dir.path());
        let old_denied = test_npub();
        let new_denied = test_npub();
        write_file(&legacy.deny, &format!("{old_denied}\n"));

        let mut reloader = legacy_reloader(dir.path(), &allow, &deny, &legacy);
        assert_eq!(
            reloader.acl().check(&test_peer(&old_denied)),
            PeerAclDecision::DenyList
        );

        write_file(&deny, &format!("{new_denied}\n"));
        let old_mtime = std::fs::metadata(&legacy.deny).unwrap().modified().unwrap();
        std::fs::File::options()
            .write(true)
            .open(&deny)
            .unwrap()
            .set_modified(old_mtime)
            .unwrap();
        assert_eq!(file_mtime(&deny), file_mtime(&legacy.deny));

        assert!(reloader.reload().await);
        assert_eq!(
            reloader.acl().check(&test_peer(&new_denied)),
            PeerAclDecision::DenyList
        );
    }

    // A current file whose existence cannot be checked must not hand the
    // decision to an older legacy file: it stays selected, and the loader
    // reports it as unreadable. Root bypasses the directory's mode bits, so
    // the test skips there rather than passing vacuously.
    #[cfg(unix)]
    #[test]
    fn an_acl_path_that_cannot_be_checked_counts_as_present() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let sealed = dir.path().join("sealed");
        std::fs::create_dir(&sealed).unwrap();
        let file = sealed.join("peers.deny");
        write_file(&file, "");
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let checkable = file.try_exists().is_ok();
        let present = path_present(&file);
        std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o755)).unwrap();
        if checkable {
            eprintln!("skipping: the effective uid can search a mode-000 directory");
            return;
        }
        assert!(present);
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
        assert!(acl.allow_file_entries().is_empty());
        assert_eq!(acl.deny_file_entries(), vec![npub.clone()]);
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
        assert!(acl.allow_file_entries().is_empty());
        assert!(acl.allow_entries().is_empty());
    }

    #[test]
    fn test_acl_read_error_is_reported_rather_than_yielding_an_empty_acl() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        std::fs::create_dir(&allow).unwrap();

        let err = PeerAcl::try_load_files_with_hosts(&allow, &deny, &HostMap::new()).unwrap_err();

        assert_eq!(err.path, allow);
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

        let acl = PeerAcl::try_load_files_with_hosts(&allow, &deny, &hosts).unwrap();

        assert_eq!(acl.allow_file_entries(), vec!["NODE-A".to_string()]);
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

        let acl = PeerAcl::try_load_files_with_hosts(&allow, &deny, &hosts).unwrap();

        assert_eq!(
            acl.allow_file_entries(),
            vec!["node-a".to_string(), npub.clone()]
        );
        assert_eq!(acl.allow_entries(), vec![npub.clone()]);
        assert_eq!(acl.check(&test_peer(&npub)), PeerAclDecision::AllowList);
    }

    #[tokio::test]
    async fn test_acl_reloader_detects_change() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let denied = test_npub();

        let mut reloader = PeerAclReloader::with_paths(allow.clone(), deny.clone());
        assert!(!reloader.reload().await);

        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(&deny, format!("{denied}\n")).unwrap();

        assert!(reloader.reload().await);
        assert_eq!(
            reloader
                .acl()
                .check(&PeerIdentity::from_npub(&denied).unwrap()),
            PeerAclDecision::DenyList
        );
    }

    #[tokio::test]
    async fn test_acl_reloader_detects_allow_file_removal() {
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

        assert!(reloader.reload().await);
        assert!(reloader.acl().is_empty());
        assert_eq!(
            reloader.acl().check(&test_peer(&allowed)),
            PeerAclDecision::DefaultAllow
        );
    }

    /// The three permission-fault tests below make a file unreadable through
    /// the unix mode bits, which Windows has no equivalent for: a read-only
    /// NTFS file is still readable, so the fault they need cannot be produced.
    /// They are gated to unix rather than made to pass vacuously elsewhere.
    ///
    /// **Coverage gap**: on Windows nothing exercises the reloader's
    /// unreadable-input path, so the fail-open defect this fix closes is
    /// unverified there.
    /// Make a file unreadable, returning false if the effective uid can read
    /// it anyway. Root bypasses the mode bits, so the permission-fault tests
    /// cannot run there and skip instead of passing vacuously; that leaves
    /// the EACCES path unexercised in any root CI job.
    #[cfg(unix)]
    fn make_unreadable(path: &Path) -> bool {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o000)).unwrap();
        std::fs::read_to_string(path).is_err()
    }

    #[cfg(unix)]
    fn make_readable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_acl_reload_holds_last_good_snapshot_when_deny_file_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let denied = test_npub();

        write_file(&deny, &format!("{denied}\n"));
        let mut reloader = PeerAclReloader::with_paths(allow, deny.clone());
        assert_eq!(
            reloader.acl().check(&test_peer(&denied)),
            PeerAclDecision::DenyList
        );

        // Rewrite before revoking access so the mtime change makes the
        // reloader actually attempt the read that then fails.
        std::thread::sleep(std::time::Duration::from_millis(5));
        write_file(&deny, &format!("{denied}\n"));
        if !make_unreadable(&deny) {
            return;
        }

        assert!(!reloader.reload().await);
        assert_eq!(
            reloader.acl().check(&test_peer(&denied)),
            PeerAclDecision::DenyList
        );
        assert_eq!(reloader.acl().effective_mode(), "denylist");
        assert!(reloader.status().stale);

        make_readable(&deny);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_acl_reload_retries_after_a_transient_read_error() {
        let dir = tempfile::tempdir().unwrap();
        let allow = dir.path().join("peers.allow");
        let deny = dir.path().join("peers.deny");
        let denied = test_npub();

        write_file(&deny, &format!("{denied}\n"));
        let mut reloader = PeerAclReloader::with_paths(allow, deny.clone());
        std::thread::sleep(std::time::Duration::from_millis(5));
        write_file(&deny, &format!("{denied}\n"));
        if !make_unreadable(&deny) {
            return;
        }
        assert!(!reloader.reload().await);

        // No further mtime change: only the armed retry can pick this up.
        make_readable(&deny);
        assert!(reloader.reload().await);
        assert_eq!(
            reloader.acl().check(&test_peer(&denied)),
            PeerAclDecision::DenyList
        );
        assert!(!reloader.status().stale);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_acl_reload_holds_last_good_when_the_hosts_file_becomes_unreadable() {
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
        write_file(&hosts, &format!("node-a {npub}\n"));
        if !make_unreadable(&hosts) {
            return;
        }

        assert!(!reloader.reload().await);
        assert_eq!(
            reloader.acl().check(&test_peer(&npub)),
            PeerAclDecision::AllowList
        );
        assert_eq!(reloader.acl().default_decision(), "allow");
        assert_eq!(
            reloader.acl().allow_file_entries(),
            vec!["node-a".to_string()]
        );

        make_readable(&hosts);
    }

    #[tokio::test]
    async fn test_acl_reload_does_not_publish_an_empty_acl_over_an_enforcing_one() {
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
        write_file(&allow, "");

        assert!(!reloader.reload().await);
        assert_eq!(
            reloader.acl().check(&test_peer(&allowed)),
            PeerAclDecision::AllowList
        );

        // The hold is bounded: a file the operator really did blank in place
        // is published on the following tick.
        assert!(reloader.reload().await);
        assert!(reloader.acl().is_empty());
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
        assert_eq!(status.allow_file_entries, vec![allowed.clone()]);
        assert_eq!(status.deny_file_entries, vec![denied.clone()]);
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
        assert!(status.allow_file_entries.is_empty());
        assert!(status.deny_file_entries.is_empty());
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
        assert!(status.allow_file_entries.is_empty());
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

        let acl = PeerAcl::try_load_files_with_hosts(&allow, &deny, &hosts).unwrap();
        let peer = PeerIdentity::from_npub(&npub).unwrap();

        assert_eq!(acl.allow_file_entries(), vec!["node-a".to_string()]);
        assert_eq!(acl.allow_entries(), vec![npub]);
        assert_eq!(acl.check(&peer), PeerAclDecision::AllowList);
    }

    #[tokio::test]
    async fn test_acl_reloader_detects_hosts_change_for_alias_entry() {
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

        assert!(reloader.reload().await);
        assert_eq!(
            reloader.acl().allow_file_entries(),
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

    #[tokio::test]
    async fn test_acl_reloader_detects_hosts_removal_for_alias_entry() {
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

        assert!(reloader.reload().await);
        assert!(reloader.acl().is_empty());
        assert_eq!(
            reloader.acl().check(&test_peer(&npub)),
            PeerAclDecision::DefaultAllow
        );
    }
}
