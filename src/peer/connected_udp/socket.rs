//! Owning handle for a per-peer `connect()`-ed UDP socket.
//!
//! Adopts an fd produced by `crate::transport::udp::open_connected_fd`
//! and closes it on drop. See that function's docs for why established
//! peers get their own connected socket.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, IntoRawFd, OwnedFd, RawFd};

/// A `connect()`-ed UDP socket for one established peer.
///
/// Owns the raw fd and closes it on drop. Configured (by
/// `crate::transport::udp::open_connected_fd`) with:
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
    /// Adopt an already-opened, bound, and `connect()`-ed fd (from
    /// `crate::transport::udp::open_connected_fd`) into an owning
    /// handle. Takes ownership of the fd; it is closed on drop.
    pub(crate) fn from_fd(fd: OwnedFd, peer_addr: SocketAddr, local_addr: SocketAddr) -> Self {
        Self {
            fd: fd.into_raw_fd(),
            peer_addr,
            local_addr,
        }
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    #[allow(dead_code)] // wired up by future per-peer recv loops
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
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

    /// Open a connected peer socket the way production does: build the
    /// fd via the transport opener, then adopt it into the handle.
    fn open(
        local_addr: SocketAddr,
        peer_addr: SocketAddr,
        recv_buf: usize,
        send_buf: usize,
    ) -> std::io::Result<ConnectedPeerSocket> {
        let fd =
            crate::transport::udp::open_connected_fd(local_addr, peer_addr, recv_buf, send_buf)?;
        Ok(ConnectedPeerSocket::from_fd(fd, peer_addr, local_addr))
    }

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
        let sock = open(
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

        let sock_a = open(shared_local, peer_a_addr, 1 << 20, 1 << 20).expect("open sock_a");
        let sock_b = open(shared_local, peer_b_addr, 1 << 20, 1 << 20).expect("open sock_b");

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

        let sock = open(local, peer_addr, 1 << 20, 1 << 20).expect("open connected sibling");

        assert_eq!(sock.local_addr(), local);
        assert_eq!(sock.peer_addr(), peer_addr);
    }
}
