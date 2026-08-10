//! Connected-socket fd construction: the socket / sockopt / bind /
//! connect syscall sequence only. Why established peers get their own
//! socket at all is in the parent module's docs; the handle that adopts
//! the fd is `super::socket::ConnectedPeerSocket`.
//!
//! The four points where the sequence differs between Linux and macOS —
//! the `socket(2)` type flags, the follow-up fd-flag call, the
//! service-type tuning and the buffer-size strategy — come from the `sys`
//! module selected below, which is the same seam the shared receive code
//! uses.

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};

#[cfg(target_os = "linux")]
use super::super::linux as sys;
#[cfg(target_os = "macos")]
use super::super::macos as sys;

/// Open a `connect()`-ed UDP socket for one peer and return the owning
/// fd. Performs the full socket / sockopt / bind / connect syscall
/// sequence. On any mid-construction failure the fd is closed (via the
/// `OwnedFd` RAII guard) before the error is returned; on success
/// ownership of the fd transfers to the returned `OwnedFd`. Callers
/// adopt it into a `super::socket::ConnectedPeerSocket` via
/// `ConnectedPeerSocket::from_fd`.
///
/// `local_addr` is the wildcard bind address (e.g. `0.0.0.0:51820`
/// or `[::]:51820`) — the same address the listen socket bound to.
/// `peer_addr` is the kernel `SocketAddr` of the established peer's
/// UDP endpoint. `recv_buf` / `send_buf` are the requested buffer
/// sizes, applied best-effort: on Linux with `SO_*BUFFORCE` first,
/// falling back to the normal `SO_*BUF` if the process can't bypass the
/// kernel ceiling; on macOS with `SO_*BUF` alone, which has no force
/// variant.
pub(crate) fn open_connected_fd(
    local_addr: SocketAddr,
    peer_addr: SocketAddr,
    recv_buf: usize,
    send_buf: usize,
) -> io::Result<OwnedFd> {
    // Family must match between local and peer.
    if local_addr.is_ipv4() != peer_addr.is_ipv4() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "ConnectedPeerSocket: local + peer address families differ",
        ));
    }

    let domain = if local_addr.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    let fd = unsafe { libc::socket(domain, sys::SOCKET_TYPE, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Adopt the fd into an OwnedFd immediately: from here its Drop
    // closes the fd on any early `return Err` / `?` below. Ownership
    // transfers to the caller only via the final `Ok(owned)`.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let raw = owned.as_raw_fd();

    sys::prepare_fd(raw)?;

    // SO_REUSEADDR lets us bind to the same local port the listen
    // socket already holds. SO_REUSEPORT lets the UDP demux permit
    // several sockets bound to the same address and route the peer
    // 5-tuple to the connected sibling.
    set_sockopt_int(raw, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    set_sockopt_int(raw, libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;

    sys::tune_connected_socket(raw);

    // Buffer sizes — best effort; see the per-platform implementation.
    sys::set_buf_sizes(raw, recv_buf, send_buf);

    // Bind to the wildcard local address (same port as listen socket).
    let local_sa: socket2::SockAddr = local_addr.into();
    let bind_r = unsafe {
        libc::bind(
            raw,
            local_sa.as_ptr() as *const libc::sockaddr,
            local_sa.len(),
        )
    };
    if bind_r < 0 {
        return Err(syscall_err("bind", local_addr));
    }

    // Connect to the peer — locks in the per-packet kernel route.
    let peer_sa: socket2::SockAddr = peer_addr.into();
    let conn_r = unsafe {
        libc::connect(
            raw,
            peer_sa.as_ptr() as *const libc::sockaddr,
            peer_sa.len(),
        )
    };
    if conn_r < 0 {
        return Err(syscall_err("connect", peer_addr));
    }

    Ok(owned)
}

fn syscall_err(syscall: &str, addr: SocketAddr) -> io::Error {
    let err = io::Error::last_os_error();
    io::Error::new(err.kind(), format!("{syscall} {addr}: {err}"))
}

/// Set an integer-valued socket option on `fd`. Returns the kernel
/// error on failure so the caller can `?`-propagate.
fn set_sockopt_int(
    fd: RawFd,
    level: libc::c_int,
    name: libc::c_int,
    value: libc::c_int,
) -> io::Result<()> {
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    const BUF: usize = 1 << 20;

    #[test]
    fn bind_failure_names_bind_and_local_addr() {
        // A plain socket without SO_REUSEPORT holds the address, so the
        // SO_REUSEPORT bind below is refused with EADDRINUSE.
        let holder = UdpSocket::bind("127.0.0.1:0").expect("holder bind");
        let holder_addr = holder.local_addr().expect("holder addr");

        let err = open_connected_fd(holder_addr, "127.0.0.1:9".parse().unwrap(), BUF, BUF)
            .expect_err("bind must fail against a non-reuseport holder");

        assert_eq!(err.kind(), io::ErrorKind::AddrInUse, "{err}");
        let msg = err.to_string();
        assert!(msg.starts_with("bind "), "{msg}");
        assert!(msg.contains(&holder_addr.to_string()), "{msg}");
        assert!(!msg.contains("connect"), "{msg}");
    }

    #[test]
    fn connect_failure_names_connect_and_peer_addr() {
        // connect(2) to the broadcast address without SO_BROADCAST fails
        // synchronously with EACCES; the bind before it succeeds.
        let err = open_connected_fd(
            "127.0.0.1:0".parse().unwrap(),
            "255.255.255.255:9999".parse().unwrap(),
            BUF,
            BUF,
        )
        .expect_err("connect to broadcast without SO_BROADCAST must fail");

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        let msg = err.to_string();
        assert!(msg.starts_with("connect "), "{msg}");
        assert!(msg.contains("255.255.255.255:9999"), "{msg}");
        assert!(!msg.contains("bind"), "{msg}");
    }
}
