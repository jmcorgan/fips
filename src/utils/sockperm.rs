//! Permission-safe creation of Unix domain sockets and the directories
//! holding them.
//!
//! The socket inode and its parent directory are created with a mode the
//! process umask can only tighten, rather than created wide and narrowed
//! afterwards. The caller's own chmod and chown stay where they are and
//! remain the authority on the socket's final mode; this closes the window
//! between creation and that fix-up, and the case of an intermediate
//! directory that nothing fixes up at all.

use std::path::Path;
use tokio::net::UnixListener;

/// Mode for a directory this module creates to hold a control socket.
///
/// Matches what the packaging already applies (systemd's
/// `RuntimeDirectoryMode=0750`, `install -d -m 0750` in the FreeBSD rc
/// script), so no packaged deployment sees a different directory mode than
/// it does today. Widening it would expose the socket path to accounts that
/// cannot reach it now; the umask can still tighten it further.
const SOCKET_DIR_MODE: u32 = 0o750;

/// umask held across the socket bind.
///
/// `bind(2)` creates the socket inode with `0777 & !umask`, so under a
/// permissive umask the socket is world-accessible until the chmod that
/// follows it. Masking the "other" bits makes the inode 0770 at creation,
/// which is the mode the caller applies a moment later anyway. Changing
/// this changes the mode the socket is created with, not the mode it ends
/// up with.
const BIND_UMASK: libc::mode_t = 0o007;

/// Restores the process umask when dropped.
struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    /// Install `mask` as the process umask, remembering the previous one.
    fn tighten(mask: libc::mode_t) -> Self {
        // SAFETY: umask(2) cannot fail and touches only process state.
        Self(unsafe { libc::umask(mask) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: as above; restoring the mask this guard replaced.
        unsafe {
            libc::umask(self.0);
        }
    }
}

/// Create the directory that will hold a socket, and any missing ancestors.
///
/// Directories come out 0750 rather than `0777 & !umask`. Nothing chmods an
/// intermediate directory afterwards, so one created under a permissive
/// umask would stay world-writable for the life of the host, and a
/// world-writable parent lets an unprivileged account plant an entry at the
/// socket path.
pub fn make_parent(parent: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(SOCKET_DIR_MODE)
        .create(parent)
}

/// Bind a Unix listener whose inode is never world-accessible.
///
/// The umask is process-global, so it is held across the bind alone. It
/// only clears bits, so anything else created inside that window comes out
/// more restrictive, never less.
pub fn bind(path: &Path) -> Result<UnixListener, std::io::Error> {
    let _umask = UmaskGuard::tighten(BIND_UMASK);
    UnixListener::bind(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    /// The umask is process-global, so the tests that set it run one at a
    /// time. This does not serialize against the rest of the test binary;
    /// the mask used is 0o022, the ordinary default, so a file another test
    /// creates in the window is unaffected.
    static UMASK_LOCK: Mutex<()> = Mutex::new(());

    /// Take the umask lock, ignoring poisoning: a test that fails while
    /// holding it must not turn its siblings red for an unrelated reason.
    fn umask_lock() -> std::sync::MutexGuard<'static, ()> {
        UMASK_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Read the current umask, which is only observable by replacing it.
    fn current_umask() -> libc::mode_t {
        // SAFETY: umask(2) cannot fail; the value read is put straight back.
        unsafe {
            let old = libc::umask(0o022);
            libc::umask(old);
            old
        }
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
    }

    #[tokio::test]
    async fn socket_is_created_without_other_access_under_a_permissive_umask() {
        let _lock = umask_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");

        let restore = UmaskGuard::tighten(0o022);
        let listener = bind(&path).unwrap();
        drop(restore);

        assert_eq!(mode_of(&path) & 0o007, 0);
        drop(listener);
    }

    #[tokio::test]
    async fn socket_bind_leaves_the_process_umask_as_it_found_it() {
        let _lock = umask_lock();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");

        let restore = UmaskGuard::tighten(0o022);
        let listener = bind(&path).unwrap();
        let after = current_umask();
        drop(restore);

        assert_eq!(after, 0o022);
        drop(listener);
    }

    #[test]
    fn socket_parent_and_its_ancestors_are_created_without_other_access() {
        let _lock = umask_lock();
        let dir = tempfile::tempdir().unwrap();
        let intermediate = dir.path().join("run");
        let parent = intermediate.join("fips");

        let restore = UmaskGuard::tighten(0o022);
        make_parent(&parent).unwrap();
        drop(restore);

        assert_eq!(mode_of(&intermediate) & 0o007, 0);
        assert_eq!(mode_of(&parent) & 0o007, 0);
    }
}
