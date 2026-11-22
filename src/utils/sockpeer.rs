//! Check who is listening on a FIPS control socket before talking to it.
//!
//! `fipsctl` and `fipstop` find the daemon's socket by path. A path can be
//! bound by any account that can write its directory: `/tmp` and an XDG
//! runtime directory for development runs, or a group-writable runtime
//! directory. A client that sends its request and prints whatever comes back
//! hands that account a channel to the operator's terminal. So a client asks
//! the kernel for the uid of the process at the other end of the connection,
//! and talks only to root, to its own account, or to the `fips` account that
//! an unprivileged daemon runs as.
//!
//! Group membership is not enough: a member of group `fips` can bind a socket
//! in a `root:fips 0770` directory, or under `sg fips`, while running under
//! its own uid. Peer credentials are read from the connected socket, so there
//! is no gap between checking and connecting for the path to be swapped in.

use std::io;
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
use std::os::fd::AsRawFd;
use std::os::fd::BorrowedFd;
use std::path::Path;

/// The uid and gid of the process at the other end of a connected Unix socket.
///
/// Read with `SO_PEERCRED` on Linux and Android and `getpeereid` on the BSDs
/// and macOS; both report the credentials the peer had when it called
/// `listen` or `connect`.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn peer_ids(fd: BorrowedFd<'_>) -> io::Result<(libc::uid_t, libc::gid_t)> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are live locals, `len` holds the size of
    // `cred`, and the kernel writes at most that many bytes.
    let rc = unsafe {
        libc::getsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((cred.uid, cred.gid))
}

/// The uid and gid of the process at the other end of a connected Unix socket.
///
/// Read with `SO_PEERCRED` on Linux and Android and `getpeereid` on the BSDs
/// and macOS; both report the credentials the peer had when it called
/// `listen` or `connect`.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
pub fn peer_ids(fd: BorrowedFd<'_>) -> io::Result<(libc::uid_t, libc::gid_t)> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `uid` and `gid` are live locals the call writes one id each into.
    let rc = unsafe { libc::getpeereid(fd.as_raw_fd(), &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((uid, gid))
}

/// Peer credentials are not read on this platform, so every server is refused.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
)))]
pub fn peer_ids(_fd: BorrowedFd<'_>) -> io::Result<(libc::uid_t, libc::gid_t)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials are not available on this platform",
    ))
}

/// Whether a server running as `uid` may be talked to by a client whose
/// effective uid is `euid`.
///
/// Root, the client's own account and the `fips` account are trusted. Every
/// other account is refused, whatever its groups.
///
/// `fips_uid` looks the `fips` account up (`None` when the host has none). It
/// is called only for a server that is neither root nor this user: `fipstop`
/// connects on every refresh, and on a host whose accounts come from a
/// directory service each lookup is a network query.
pub fn trusted(
    uid: libc::uid_t,
    euid: libc::uid_t,
    fips_uid: impl FnOnce() -> Option<libc::uid_t>,
) -> bool {
    uid == 0 || uid == euid || fips_uid() == Some(uid)
}

/// Refuse a control socket at `path` whose server runs as `uid`, unless
/// [`trusted`] accepts it for this process.
///
/// The error names the path and the server's uid, for the client to print
/// before it exits without having sent anything.
pub fn check_server(path: &Path, uid: libc::uid_t) -> Result<(), String> {
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    if trusted(uid, euid, super::sockbind::fips_user_id) {
        return Ok(());
    }
    Err(format!(
        "refusing control socket {}: it is served by uid {uid}, which is neither root, \
         this user (uid {euid}) nor the 'fips' account; nothing was sent",
        path.display()
    ))
}

/// Read the peer's uid on a connected `stream` and apply [`check_server`].
pub fn check_stream(path: &Path, stream: &impl std::os::fd::AsFd) -> Result<(), String> {
    let (uid, _gid) = peer_ids(stream.as_fd()).map_err(|e| {
        format!(
            "cannot read the credentials of the server on {}: {e}; nothing was sent",
            path.display()
        )
    })?;
    check_server(path, uid)
}

#[cfg(test)]
#[path = "tests/sockpeer.rs"]
mod tests;
