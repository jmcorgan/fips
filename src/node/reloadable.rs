//! Lock-free reloadable configuration / resource snapshots.
//!
//! Several node-owned resources are loaded from disk at startup and may be
//! re-read when the backing file changes (for example the `/etc/fips/hosts`
//! map). Historically each one carried its own ad-hoc reloader with a
//! slightly different shape. The [`Reloadable`] trait normalizes them onto a
//! single contract built around an [`arc_swap::ArcSwap`] snapshot.
//!
//! # Canonical Arc-wrapper template
//!
//! These resources follow a single-writer / many-reader pattern: the node
//! tick task is the only writer, while the hot path reads the current value
//! frequently and must never block.
//!
//! - The reader-facing immutable snapshot lives in an
//!   [`arc_swap::ArcSwap<T>`]. Readers call [`Reloadable::load`], which yields
//!   a lock-free [`arc_swap::Guard<Arc<T>>`] that derefs straight to the
//!   snapshot — no mutex, no clone on the read path.
//! - The owning struct also holds the change-detection state (file mtime,
//!   immutable base data, source path). That state is touched only by
//!   [`Reloadable::reload`], which runs on the single writer task.
//! - `reload` builds a brand-new `T` and then stores `Arc::new(new)` into the
//!   `ArcSwap`, so a reader either sees the entire old snapshot or the entire
//!   new one — never a partial update.
//! - Construction performs the initial synchronous load so the snapshot is
//!   valid before the node starts serving reads.
//!
//! `reload` returns `bool` rather than a value or `Result`: the underlying
//! loaders already absorb I/O errors internally (a missing or unreadable
//! source degrades to an empty/base snapshot plus a warning), so callers have
//! nothing to handle. The return flag reports only whether the snapshot was
//! replaced, which is all the tick loop needs for logging.

use std::sync::Arc;

use crate::upper::hosts::{HostMap, file_mtime};

/// A resource backed by a lock-free [`arc_swap::ArcSwap`] snapshot that can be
/// re-read from its source on demand.
///
/// See the [module documentation](self) for the canonical Arc-wrapper
/// template that implementors follow.
pub trait Reloadable: Send {
    /// The immutable snapshot type readers observe.
    type Snapshot;

    /// Re-read the backing source and replace the snapshot if it changed.
    ///
    /// Returns `true` if a new snapshot was stored, `false` if nothing
    /// changed. I/O errors are absorbed internally (degrading to an
    /// empty/base snapshot with a warning) rather than surfaced.
    ///
    /// Not yet driven from the node tick — the host map snapshot is still
    /// taken once at construction and not polled. Wiring the periodic poll
    /// into the tick is a follow-up.
    #[cfg_attr(not(test), allow(dead_code))]
    async fn reload(&mut self) -> bool;

    /// Acquire a lock-free guard over the current snapshot.
    ///
    /// This is the hot-path read: it performs no locking and no allocation.
    fn load(&self) -> arc_swap::Guard<Arc<Self::Snapshot>>;
}

/// Reloadable hostname → npub map (base peer aliases merged with the operator
/// hosts file).
///
/// Holds the immutable base map (from peer-config aliases) plus the
/// change-detection state for the hosts file. The effective map (base merged
/// with the hosts file) is published through an [`arc_swap::ArcSwap`] so the
/// display path can read it without locking.
pub struct HostMapReloadable {
    /// Reader-facing effective snapshot (base merged with hosts file).
    snapshot: arc_swap::ArcSwap<HostMap>,
    /// Base map from peer-config aliases (never changes). Read only by
    /// `reload`, which is not yet driven from the node tick.
    #[cfg_attr(not(test), allow(dead_code))]
    base: HostMap,
    /// Path to the operator hosts file. Read only by `reload`.
    #[cfg_attr(not(test), allow(dead_code))]
    path: std::path::PathBuf,
    /// Last observed modification time of the hosts file (`None` if absent).
    /// Read only by `reload`.
    #[cfg_attr(not(test), allow(dead_code))]
    last_mtime: Option<std::time::SystemTime>,
}

impl HostMapReloadable {
    /// Create a reloadable host map.
    ///
    /// Performs the initial load of the hosts file and merges it over the
    /// base map so the published snapshot is valid immediately.
    pub fn new(base: HostMap, path: std::path::PathBuf) -> Self {
        let last_mtime = file_mtime(&path);
        let hosts_file = HostMap::load_hosts_file(&path);
        let mut effective = base.clone();
        effective.merge(hosts_file);

        Self {
            snapshot: arc_swap::ArcSwap::from(Arc::new(effective)),
            base,
            path,
            last_mtime,
        }
    }
}

impl Reloadable for HostMapReloadable {
    type Snapshot = HostMap;

    async fn reload(&mut self) -> bool {
        let current_mtime = file_mtime(&self.path);

        if current_mtime == self.last_mtime {
            return false;
        }

        // File appeared, disappeared, or was modified.
        self.last_mtime = current_mtime;
        let hosts_file = HostMap::load_hosts_file(&self.path);
        let mut new_effective = self.base.clone();
        new_effective.merge(hosts_file);

        let count = new_effective.len();
        self.snapshot.store(Arc::new(new_effective));

        tracing::info!(
            path = %self.path.display(),
            entries = count,
            "Reloaded hosts file"
        );
        true
    }

    fn load(&self) -> arc_swap::Guard<Arc<HostMap>> {
        self.snapshot.load()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[tokio::test]
    async fn test_initial_load_base_and_file() {
        let id_base = Identity::generate();
        let id_file = Identity::generate();

        let mut base = HostMap::new();
        base.insert("core", &id_base.npub()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id_file.npub())).unwrap();

        let reloadable = HostMapReloadable::new(base, path);
        let snapshot = reloadable.load();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.lookup_npub("core").is_some());
        assert!(snapshot.lookup_npub("gateway").is_some());
    }

    #[tokio::test]
    async fn test_initial_load_no_file_base_only() {
        let id = Identity::generate();
        let mut base = HostMap::new();
        base.insert("core", &id.npub()).unwrap();

        let reloadable =
            HostMapReloadable::new(base, std::path::PathBuf::from("/nonexistent/hosts"));
        let snapshot = reloadable.load();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.lookup_npub("core").is_some());
    }

    #[tokio::test]
    async fn test_reload_detects_file_change() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id1.npub())).unwrap();

        let mut reloadable = HostMapReloadable::new(HostMap::new(), path.clone());
        assert_eq!(reloadable.load().len(), 1);
        assert_eq!(
            reloadable.load().lookup_npub("gateway"),
            Some(id1.npub().as_str())
        );

        // No change yet.
        assert!(!reloadable.reload().await);

        // Bump mtime by rewriting; sleep for filesystem mtime granularity.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(
            &path,
            format!("gateway   {}\nnew-host   {}\n", id1.npub(), id2.npub()),
        )
        .unwrap();

        assert!(reloadable.reload().await);
        let snapshot = reloadable.load();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.lookup_npub("new-host").is_some());
    }

    #[tokio::test]
    async fn test_reload_no_change_returns_false() {
        let id = Identity::generate();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id.npub())).unwrap();

        let mut reloadable = HostMapReloadable::new(HostMap::new(), path);
        assert!(!reloadable.reload().await);
        assert!(!reloadable.reload().await);
    }

    #[tokio::test]
    async fn test_reload_detects_file_deletion() {
        let id = Identity::generate();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id.npub())).unwrap();

        let mut reloadable = HostMapReloadable::new(HostMap::new(), path.clone());
        assert_eq!(reloadable.load().len(), 1);

        std::fs::remove_file(&path).unwrap();

        assert!(reloadable.reload().await);
        assert!(reloadable.load().is_empty());
    }

    #[tokio::test]
    async fn test_reload_detects_file_creation() {
        let id = Identity::generate();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");

        let mut reloadable = HostMapReloadable::new(HostMap::new(), path.clone());
        assert!(reloadable.load().is_empty());

        std::fs::write(&path, format!("gateway   {}\n", id.npub())).unwrap();

        assert!(reloadable.reload().await);
        let snapshot = reloadable.load();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.lookup_npub("gateway").is_some());
    }

    #[tokio::test]
    async fn test_reload_preserves_base() {
        let id_base = Identity::generate();
        let id_file = Identity::generate();

        let mut base = HostMap::new();
        base.insert("core", &id_base.npub()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id_file.npub())).unwrap();

        let mut reloadable = HostMapReloadable::new(base, path.clone());
        assert_eq!(reloadable.load().len(), 2);

        std::fs::remove_file(&path).unwrap();
        assert!(reloadable.reload().await);
        let snapshot = reloadable.load();
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot.lookup_npub("core").is_some());
        assert!(snapshot.lookup_npub("gateway").is_none());
    }

    /// The initial published snapshot must be byte-for-byte equivalent to the
    /// pre-migration `Arc<HostMap>` built by `base.clone()` + `merge(file)`.
    #[tokio::test]
    async fn test_initial_snapshot_matches_pre_migration_construction() {
        let id_base = Identity::generate();
        let id_file = Identity::generate();

        let mut base = HostMap::new();
        base.insert("core", &id_base.npub()).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts");
        std::fs::write(&path, format!("gateway   {}\n", id_file.npub())).unwrap();

        // Pre-migration construction.
        let mut expected = base.clone();
        expected.merge(HostMap::load_hosts_file(&path));

        // Post-migration construction.
        let reloadable = HostMapReloadable::new(base, path);
        let snapshot = reloadable.load();

        assert_eq!(snapshot.len(), expected.len());
        for key in ["core", "gateway"] {
            assert_eq!(snapshot.lookup_npub(key), expected.lookup_npub(key));
        }
    }
}
