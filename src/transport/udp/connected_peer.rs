// The connected-UDP fast path is infra-ready but not yet wired into the
// encrypt-worker dispatch site (a follow-up PR will refcount-clone the
// socket into each FmpSendJob). Keep the API surface in tree.
#![allow(dead_code)]

//! Connected per-peer UDP socket.
//!
//! One of the levers boringtun uses to hit 2.5–3.2 Gbps on a real
//! NIC: after a peer is established, give them their **own UDP socket
//! `connect()`-ed to their address**. The kernel then:
//!
//! - Routes inbound packets *from that peer* directly to the
//!   connected socket (most-specific-match wins over the wildcard
//!   listen socket), so the demux happens once at socket-receive
//!   time instead of repeatedly at the application layer.
//! - Lets us `sendmsg(2)` with `msg_name = NULL` (or `send(2)`),
//!   skipping the per-packet sockaddr copy + route lookup + neighbor
//!   resolve that the kernel otherwise repeats for every datagram on
//!   an unconnected socket.
//! - Combines cleanly with UDP_GSO: the connected socket sends one
//!   super-skb to one cached destination, and the kernel skips
//!   per-segment route lookups.
//!
//! Multiple connected sockets coexist with the wildcard listen socket
//! via `SO_REUSEPORT` plus `SO_REUSEADDR`. The UDP demux picks the
//! most specific match (5-tuple of connected sockets beats the
//! wildcard), so traffic from new / unknown peers continues to land on
//! the listen socket (handshakes / discovery), while established peers'
//! steady-state traffic goes directly to their dedicated socket.
//!
//! **Scope of this module:** infrastructure only — the FD lifecycle
//! (open / close), buffer sizing (matches the listen socket's
//! `SO_RCVBUF` / `SO_SNDBUF` via `FORCE` variants where possible),
//! and unit tests exercising the open + bind + connect path.

#![cfg(any(target_os = "linux", target_os = "macos"))]

use std::io;
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};

/// A `connect()`-ed UDP socket for one established peer.
///
/// Owns the raw fd and closes it on drop. Configured with:
/// - `SO_REUSEADDR` and `SO_REUSEPORT` so it can share the listen port
///   with the wildcard socket and any other peers' connected sockets.
/// - The receive / send buffer sizes inherited from the configured
///   UDP transport (best-effort via `*BUFFORCE` variants — the kernel
///   silently falls back to the normal `*BUF` ceiling if our process
///   lacks `CAP_NET_ADMIN`).
/// - `O_NONBLOCK` so callers that drive it from an OS-thread shard
///   loop don't accidentally block the entire shard on a single
///   recv / send.
/// - `connect()`-ed to the peer's `SocketAddr`, locking in the
///   per-packet kernel-side route + ARP / neighbor cache so neither
///   needs to be redone on the data path.
#[derive(Debug)]
pub(crate) struct ConnectedPeerSocket {
    fd: RawFd,
    peer_addr: SocketAddr,
    local_addr: SocketAddr,
}

impl ConnectedPeerSocket {
    /// Open a new peer-connected UDP socket.
    ///
    /// `local_addr` is the wildcard bind address (e.g. `0.0.0.0:51820`
    /// or `[::]:51820`) — the same address the listen socket bound
    /// to. `peer_addr` is the kernel `SocketAddr` of the established
    /// peer's UDP endpoint. `recv_buf` / `send_buf` are the requested
    /// buffer sizes; they're applied with `SO_*BUFFORCE` first and
    /// fall back to the normal `SO_*BUF` if the process can't bypass
    /// the kernel ceiling.
    pub fn open(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        recv_buf: usize,
        send_buf: usize,
    ) -> io::Result<Self> {
        let fd = open_connected_fd(local_addr, peer_addr, recv_buf, send_buf)?;
        Ok(Self {
            fd: fd.into_raw_fd(),
            peer_addr,
            local_addr,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn set_nonblocking_cloexec(&self) -> io::Result<()> {
        let flags = unsafe { libc::fcntl(self.fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(self.fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }

        let fd_flags = unsafe { libc::fcntl(self.fd, libc::F_GETFD) };
        if fd_flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fcntl(self.fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Set an integer-valued socket option. Returns the kernel error
    /// on failure but doesn't `?`-propagate caller-side because most
    /// callers want to log + continue rather than fail the whole open.
    fn set_sockopt_int(
        &self,
        level: libc::c_int,
        name: libc::c_int,
        value: libc::c_int,
    ) -> io::Result<()> {
        let r = unsafe {
            libc::setsockopt(
                self.fd,
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

    /// Try `SO_*BUFFORCE` first (bypasses the rmem/wmem ceiling) and
    /// fall back to `SO_*BUF` if that fails. Returns silently — buffer
    /// sizing is best-effort.
    #[cfg(target_os = "linux")]
    fn set_buf_size(&self, force_name: libc::c_int, normal_name: libc::c_int, size: usize) {
        let value: libc::c_int = size as libc::c_int;
        let r = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                force_name,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if r < 0 {
            // Fall back to non-force — kernel may clamp.
            let _ = unsafe {
                libc::setsockopt(
                    self.fd,
                    libc::SOL_SOCKET,
                    normal_name,
                    &value as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn set_buf_size(&self, normal_name: libc::c_int, size: usize) {
        let value: libc::c_int = size as libc::c_int;
        let _ = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                normal_name,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    #[allow(dead_code)] // wired up by future per-peer recv loops
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

/// Open a `connect()`-ed UDP socket for one peer and return the owning
/// fd. Performs the full socket / sockopt / bind / connect syscall
/// sequence (see [`ConnectedPeerSocket`] for the rationale). On any
/// mid-construction failure the fd is closed before the error is
/// returned; on success ownership of the fd transfers to the returned
/// [`OwnedFd`]. `ConnectedPeerSocket::open` is a thin wrapper that
/// adopts this fd into the struct.
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
    // Linux accepts SOCK_NONBLOCK | SOCK_CLOEXEC directly. Darwin
    // does not, so we set the equivalent fd flags with fcntl below.
    #[cfg(target_os = "linux")]
    let typ = libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let typ = libc::SOCK_DGRAM;
    let fd = unsafe { libc::socket(domain, typ, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Take ownership of the fd in a temporary wrapper so its Drop
    // closes the fd on any error path below. Ownership is transferred
    // out (via mem::forget + OwnedFd) only after connect() succeeds.
    let sock = ConnectedPeerSocket {
        fd,
        peer_addr,
        local_addr,
    };
    #[cfg(not(target_os = "linux"))]
    sock.set_nonblocking_cloexec()?;

    // SO_REUSEADDR lets us bind to the same local port the listen
    // socket already holds. SO_REUSEPORT lets the UDP demux permit
    // several sockets bound to the same address and route the peer
    // 5-tuple to the connected sibling.
    sock.set_sockopt_int(libc::SOL_SOCKET, libc::SO_REUSEADDR, 1)?;
    sock.set_sockopt_int(libc::SOL_SOCKET, libc::SO_REUSEPORT, 1)?;

    #[cfg(target_os = "macos")]
    crate::transport::udp::darwin_sockopts::apply_udp_socket_tuning(sock.fd, "connected-udp-peer");

    // Buffer sizes — try the FORCE variants first (succeed if we
    // have CAP_NET_ADMIN), then fall back to the ceiling-clamped
    // normal variants. The ceiling-clamped path always succeeds
    // even if it gives us less than we asked for.
    #[cfg(target_os = "linux")]
    {
        sock.set_buf_size(libc::SO_RCVBUFFORCE, libc::SO_RCVBUF, recv_buf);
        sock.set_buf_size(libc::SO_SNDBUFFORCE, libc::SO_SNDBUF, send_buf);
    }
    #[cfg(not(target_os = "linux"))]
    {
        sock.set_buf_size(libc::SO_RCVBUF, recv_buf);
        sock.set_buf_size(libc::SO_SNDBUF, send_buf);
    }

    // Bind to the wildcard local address (same port as listen socket).
    let local_sa: socket2::SockAddr = local_addr.into();
    let bind_r = unsafe {
        libc::bind(
            sock.fd,
            local_sa.as_ptr() as *const libc::sockaddr,
            local_sa.len(),
        )
    };
    if bind_r < 0 {
        return Err(io::Error::last_os_error());
    }

    // Connect to the peer — locks in the per-packet kernel route.
    let peer_sa: socket2::SockAddr = peer_addr.into();
    let conn_r = unsafe {
        libc::connect(
            sock.fd,
            peer_sa.as_ptr() as *const libc::sockaddr,
            peer_sa.len(),
        )
    };
    if conn_r < 0 {
        return Err(io::Error::last_os_error());
    }

    // Success: transfer ownership of the fd to an OwnedFd. Neutralize
    // the temporary wrapper's Drop so the fd is not closed here — its
    // close-on-error role is done. Every early error above still drops
    // `sock` and closes the fd, unchanged from before.
    let raw = sock.fd;
    std::mem::forget(sock);
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

impl AsRawFd for ConnectedPeerSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for ConnectedPeerSocket {
    fn drop(&mut self) {
        // Best-effort close. Ignore the result — if close fails the
        // kernel has already done what it can; we don't want to panic
        // in Drop.
        unsafe {
            libc::close(self.fd);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    /// Open a connected peer socket against a fresh loopback UDP
    /// listener and exercise the round-trip: connected socket sends
    /// without msg_name → listener receives → listener replies →
    /// connected socket receives without parsing msg_name. Validates
    /// reuse flags + `bind` + `connect` + `O_NONBLOCK`.
    #[test]
    fn open_send_recv_loopback() {
        // Peer (the "remote") side: a regular blocking UDP socket on
        // loopback. We'll have our connected socket send to it.
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer local_addr");
        peer.set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set_read_timeout");

        // Our side: a wildcard listen address (use 127.0.0.1:0 to
        // avoid colliding with any real local service). Connect to the
        // peer. Linux requires that we bind before connect — the
        // ConnectedPeerSocket constructor does both.
        let local_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let sock = ConnectedPeerSocket::open(
            local_addr,
            peer_addr,
            /* recv_buf */ 1 << 20,
            /* send_buf */ 1 << 20,
        )
        .expect("ConnectedPeerSocket::open");

        // Confirm the socket is in fact connected: `send(2)` should
        // succeed without specifying a destination.
        let payload = b"hello-from-connected-socket";
        let r = unsafe {
            libc::send(
                sock.as_raw_fd(),
                payload.as_ptr() as *const libc::c_void,
                payload.len(),
                0,
            )
        };
        assert!(r >= 0, "send failed: {}", std::io::Error::last_os_error());
        assert_eq!(r as usize, payload.len());

        let mut recv_buf = [0u8; 64];
        let (len, from) = peer.recv_from(&mut recv_buf).expect("peer recv");
        assert_eq!(len, payload.len());
        assert_eq!(&recv_buf[..len], payload);

        // Reply back from the peer. Since our socket is connected to
        // peer_addr, the kernel UDP demux should route this packet to
        // our connected socket (most-specific-match) and `recv(2)`
        // without sockaddr should pick it up.
        let reply = b"hello-back";
        peer.send_to(reply, from).expect("peer send_to");

        // Drain on the connected socket. Spin briefly because
        // O_NONBLOCK + a tiny one-shot recv would race with the
        // kernel's veth-less loopback delivery.
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            let mut buf = [0u8; 64];
            let r = unsafe {
                libc::recv(
                    sock.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                )
            };
            if r >= 0 {
                assert_eq!(r as usize, reply.len());
                assert_eq!(&buf[..r as usize], reply);
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock {
                if std::time::Instant::now() >= deadline {
                    panic!("connected socket never received reply");
                }
                std::thread::sleep(std::time::Duration::from_millis(2));
                continue;
            }
            panic!("recv failed: {err}");
        }
    }

    /// Two connected sockets coexisting on the same local port via
    /// `SO_REUSEPORT`, each connected to a different peer.
    #[test]
    fn two_connected_sockets_share_listen_port() {
        let peer_a = UdpSocket::bind("127.0.0.1:0").expect("bind peer_a");
        let peer_b = UdpSocket::bind("127.0.0.1:0").expect("bind peer_b");
        let peer_a_addr = peer_a.local_addr().expect("peer_a local_addr");
        let peer_b_addr = peer_b.local_addr().expect("peer_b local_addr");

        // Anchor a shared local port via a wildcard socket on a
        // non-zero ephemeral port, then open two connected sockets
        // bound to the same port.
        let anchor = UdpSocket::bind("127.0.0.1:0").expect("bind anchor");
        let shared_port = anchor.local_addr().expect("anchor local_addr").port();
        let shared_local: SocketAddr = format!("127.0.0.1:{shared_port}").parse().unwrap();
        // Drop the anchor so the only thing holding the port is the
        // connected sockets' reuse semantics.
        drop(anchor);

        let sock_a = ConnectedPeerSocket::open(shared_local, peer_a_addr, 1 << 20, 1 << 20)
            .expect("open sock_a");
        let sock_b = ConnectedPeerSocket::open(shared_local, peer_b_addr, 1 << 20, 1 << 20)
            .expect("open sock_b");

        assert_eq!(sock_a.peer_addr(), peer_a_addr);
        assert_eq!(sock_b.peer_addr(), peer_b_addr);
    }

    /// The production fast path keeps the wildcard UDP listener bound
    /// while opening a sibling socket connected to a peer. This catches
    /// the Darwin regression where the adopted traversal socket used a
    /// different reuse mode than the connected-peer socket and every
    /// activation failed with EADDRINUSE.
    #[test]
    fn connected_socket_shares_live_listener_port() {
        let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
        let peer_addr = peer.local_addr().expect("peer local_addr");

        let listener = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .expect("create listener");
        listener
            .set_reuse_address(true)
            .expect("listener reuseaddr");
        listener.set_reuse_port(true).expect("listener reuseport");
        listener
            .bind(&"0.0.0.0:0".parse::<SocketAddr>().unwrap().into())
            .expect("bind listener");
        let local = listener
            .local_addr()
            .expect("listener local addr")
            .as_socket()
            .expect("ip socket");

        let sock = ConnectedPeerSocket::open(local, peer_addr, 1 << 20, 1 << 20)
            .expect("open connected sibling");

        assert_eq!(sock.local_addr(), local);
        assert_eq!(sock.peer_addr(), peer_addr);
    }
}
