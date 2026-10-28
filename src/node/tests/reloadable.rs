//! Tests of how the node's display-name host map (`HostMapReloadable`)
//! handles a hosts file it cannot read.

use super::*;
use crate::Identity;

/// Set a file's modification time.
fn set_mtime(path: &std::path::Path, at: std::time::SystemTime) {
    std::fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(at)
        .unwrap();
}

/// A hosts file that becomes unreadable (non-UTF-8 bytes) after a good load
/// leaves the display map's last good names in place.
#[tokio::test]
async fn a_hosts_file_that_becomes_unreadable_keeps_the_last_display_names() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    std::fs::write(&path, format!("gateway {}\n", Identity::generate().npub())).unwrap();
    let loaded = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    set_mtime(&path, loaded);
    let mut reloadable = HostMapReloadable::new(HostMap::new(), path.clone());
    assert!(reloadable.load().lookup_npub("gateway").is_some());

    std::fs::write(&path, b"# caf\xe9\n").unwrap();
    set_mtime(&path, loaded + std::time::Duration::from_secs(10));
    reloadable.reload().await;
    assert!(
        reloadable.load().lookup_npub("gateway").is_some(),
        "gateway dropped from the display map once the hosts file could not be read"
    );
}

/// A hosts file unreadable when the map is built is read again by the next
/// reload once it is readable, even with its modification time unchanged.
#[tokio::test]
async fn a_hosts_file_unreadable_at_construction_is_read_once_it_becomes_readable() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    let at = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    std::fs::write(&path, b"\xff\xfe not text\n").unwrap();
    set_mtime(&path, at);
    let mut reloadable = HostMapReloadable::new(HostMap::new(), path.clone());
    assert!(reloadable.load().is_empty());

    std::fs::write(&path, format!("gateway {}\n", Identity::generate().npub())).unwrap();
    set_mtime(&path, at);
    reloadable.reload().await;
    assert!(
        reloadable.load().lookup_npub("gateway").is_some(),
        "the failed first read recorded the mtime, so the readable file was never read"
    );
}

/// A failed reload is tried again by the next one even when the file then
/// becomes readable without its modification time changing.
#[tokio::test]
async fn a_failed_display_map_reload_is_retried_though_the_mtime_did_not_change() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    let first = Identity::generate().npub();
    std::fs::write(&path, format!("gateway {first}\n")).unwrap();
    let loaded = std::time::SystemTime::now() - std::time::Duration::from_secs(60);
    set_mtime(&path, loaded);
    let mut reloadable = HostMapReloadable::new(HostMap::new(), path.clone());

    let failed = loaded + std::time::Duration::from_secs(10);
    std::fs::write(&path, b"\xff\xfe not text\n").unwrap();
    set_mtime(&path, failed);
    reloadable.reload().await;

    let second = Identity::generate().npub();
    std::fs::write(&path, format!("gateway {first}\nlater {second}\n")).unwrap();
    set_mtime(&path, failed);
    reloadable.reload().await;
    assert!(
        reloadable.load().lookup_npub("later").is_some(),
        "the failed reload recorded the mtime, so the readable file was never read again"
    );
}
