//! Bind a Unix domain socket under the FIPS access policy.
//!
//! Every FIPS Unix socket needs the same four things before it can listen: a
//! parent directory that exists and whose ownership is known, any stale socket
//! file removed, a listener bound, and group access applied so members of the
//! `fips` group can reach it.
//!
//! The policy lives in one place so a change to it reaches every socket rather
//! than whichever copy an author happened to be looking at. All three sockets
//! use it: the control socket, the gateway control socket and the native
//! datagram API socket. The gateway previously kept its own copy, which had
//! already drifted in that it never set the parent's mode at all.

#[cfg(unix)]
use std::path::{Path, PathBuf};
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tracing::{debug, warn};

/// Bind a Unix listener at `path` under the FIPS access policy.
///
/// `what` names the socket for diagnostics: it is the noun in the "already in
/// use" error a caller sees when another process is listening there, and a
/// structured field on the directory and stale-socket log lines. The caller
/// emits its own "listening" line, so each socket keeps its own wording.
///
/// Creates missing ancestors, removes a stale socket file, binds, then applies
/// mode `0o770` to the socket and `0o750` to the parent when this bind owns the
/// parent. An `AddrInUse` error means a live listener already holds the path.
#[cfg(unix)]
pub fn bind(path: &Path, what: &str) -> Result<UnixListener, std::io::Error> {
    // Creation is useful for diagnostics, but ownership is keyed to directory
    // identity as well: systemd pre-creates /run/fips on every Linux service
    // start and initially owns it as root:root.
    let managed_parent = match path.parent() {
        Some(parent) => {
            let created = ensure_socket_parent(parent)?;
            if created {
                debug!(path = %parent.display(), socket = what, "Created private socket directory");
            }
            (created || crate::config::is_managed_socket_parent(parent)).then(|| parent.to_owned())
        }
        None => None,
    };

    if path.exists() {
        remove_stale_socket(path, what)?;
    }

    let listener = UnixListener::bind(path)?;

    set_socket_access(path, managed_parent.as_deref(), chown_to_fips_group)?;

    Ok(listener)
}

/// Ensure the socket's parent exists and report whether this call created the
/// leaf directory.
///
/// `create_dir` gives us an atomic ownership decision: an `AlreadyExists`
/// result means another actor owns the existing directory, while success means
/// it is safe for this bind to apply FIPS ownership and mode. Missing ancestors
/// are created recursively, but only the requested leaf is later treated as the
/// socket's private directory.
#[cfg(unix)]
fn ensure_socket_parent(parent: &Path) -> Result<bool, std::io::Error> {
    if parent.as_os_str().is_empty() {
        return Ok(false);
    }

    match std::fs::create_dir(parent) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if parent.is_dir() {
                Ok(false)
            } else {
                Err(error)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let ancestor = parent.parent().ok_or(error)?;
            ensure_socket_parent(ancestor)?;
            ensure_socket_parent(parent)
        }
        Err(error) => Err(error),
    }
}

/// Apply access policy to a newly bound socket.
///
/// The socket is always group-owned. `managed_parent` is either a private
/// directory this bind created or a canonical FIPS runtime directory. A shared
/// or operator-owned existing parent is omitted so it retains its ownership and
/// mode.
///
/// `chown_to_fips_group` is a parameter so the policy can be tested without
/// requiring the `fips` group to exist on the machine running the tests.
#[cfg(unix)]
fn set_socket_access(
    socket_path: &Path,
    managed_parent: Option<&Path>,
    mut chown_to_fips_group: impl FnMut(&Path),
) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o770))?;
    chown_to_fips_group(socket_path);

    if let Some(parent) = managed_parent {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o750))?;
        chown_to_fips_group(parent);
    }

    Ok(())
}

/// Remove a stale socket file.
///
/// If the file exists but no one is listening, remove it so we can bind. This
/// handles unclean daemon exits. A live listener yields `AddrInUse` instead, so
/// two daemons cannot silently take the same path.
#[cfg(unix)]
fn remove_stale_socket(path: &Path, what: &str) -> Result<(), std::io::Error> {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            format!("{what} socket already in use: {}", path.display()),
        )),
        Err(_) => {
            debug!(path = %path.display(), socket = what, "Removing stale socket");
            std::fs::remove_file(path)?;
            Ok(())
        }
    }
}

/// Set group ownership of a path to the `fips` group (best-effort).
///
/// A missing group is not an error: a source build on a developer machine has
/// no `fips` group, and the socket is still usable by its owner.
#[cfg(unix)]
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
            "Failed to chown socket to 'fips' group"
        );
    }
}

/// Remove a socket file at teardown, ignoring a path that is already gone.
#[cfg(unix)]
pub fn cleanup(path: &PathBuf, what: &str) {
    if !path.exists() {
        return;
    }
    match std::fs::remove_file(path) {
        Ok(()) => debug!(path = %path.display(), socket = what, "Socket file removed"),
        Err(error) => {
            warn!(path = %path.display(), socket = what, error = %error, "Failed to remove socket file")
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::{ensure_socket_parent, set_socket_access};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn parent_setup_distinguishes_existing_and_created_directories() {
        let temp = tempfile::tempdir().unwrap();
        let existing = temp.path().join("existing");
        std::fs::create_dir(&existing).unwrap();
        assert!(!ensure_socket_parent(&existing).unwrap());

        let nested = temp.path().join("missing").join("fips");
        assert!(ensure_socket_parent(&nested).unwrap());
        assert!(nested.is_dir());
        assert!(!ensure_socket_parent(&nested).unwrap());
    }

    #[test]
    fn access_setup_leaves_an_existing_shared_parent_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("shared");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o711)).unwrap();
        let socket = parent.join("control.sock");
        std::fs::File::create(&socket).unwrap();

        let mut chowned = Vec::new();
        set_socket_access(&socket, None, |path| chowned.push(path.to_path_buf())).unwrap();

        assert_eq!(chowned, vec![socket.clone()]);
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o711
        );
        assert_eq!(
            std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
            0o770
        );
    }

    #[test]
    fn access_setup_secures_a_new_private_parent() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("fips");
        std::fs::create_dir(&parent).unwrap();
        let socket = parent.join("control.sock");
        std::fs::File::create(&socket).unwrap();

        let mut chowned = Vec::new();
        set_socket_access(&socket, Some(&parent), |path| {
            chowned.push(path.to_path_buf())
        })
        .unwrap();

        assert_eq!(chowned, vec![socket, parent.clone()]);
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }

    #[test]
    fn access_setup_secures_an_existing_managed_parent() {
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("managed");
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = parent.join("control.sock");
        std::fs::File::create(&socket).unwrap();

        let mut chowned = Vec::new();
        set_socket_access(&socket, Some(&parent), |path| {
            chowned.push(path.to_path_buf())
        })
        .unwrap();

        assert_eq!(chowned, vec![socket, parent.clone()]);
        assert_eq!(
            std::fs::metadata(&parent).unwrap().permissions().mode() & 0o777,
            0o750
        );
    }
}
