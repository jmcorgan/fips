//! UDP socket implementation shared by every Unix target.
//!
//! Everything here is platform-independent within Unix: socket creation,
//! adoption, buffer sizing, the synchronous send/receive calls, and the
//! `AsyncFd`-based async wrapper. The three points where behaviour genuinely
//! differs per OS — enabling the kernel drop counter, sizing and parsing the
//! ancillary control buffer, and batched receive — are delegated to the `sys`
//! module selected below.

use crate::transport::TransportError;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tracing::warn;

#[cfg(target_os = "linux")]
use super::linux as sys;
#[cfg(target_os = "macos")]
use super::macos as sys;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use super::unix_other as sys;

/// Maximum number of datagrams a single recvmmsg / recvmsg_x / sendmmsg
/// syscall will pull from / push to the kernel. Tuned to amortise syscall +
/// per-task-wakeup overhead across a useful burst without blowing the
/// stack (each slot owns an mmsghdr/msghdr_x + sockaddr_storage + iovec).
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(super) const BATCH_SIZE: usize = 32;

/// Wrapper around a `socket2::Socket` providing sync send/recv with
/// `SO_RXQ_OVFL` ancillary data parsing.
pub struct UdpRawSocket {
    inner: Socket,
    local_addr: SocketAddr,
}

impl UdpRawSocket {
    /// Create, bind, and configure a UDP socket.
    ///
    /// Enables `SO_RXQ_OVFL` for kernel drop counting (non-fatal if
    /// unsupported). Sets non-blocking mode for async integration.
    pub fn open(
        bind_addr: SocketAddr,
        recv_buf_size: usize,
        send_buf_size: usize,
    ) -> Result<Self, TransportError> {
        let domain = if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| TransportError::StartFailed(format!("socket create failed: {}", e)))?;

        sock.set_nonblocking(true)
            .map_err(|e| TransportError::StartFailed(format!("set nonblocking failed: {}", e)))?;

        // SO_REUSEPORT lets per-peer `ConnectedPeerSocket`s bind
        // to the same wildcard port the listen socket holds. Must
        // be set BEFORE bind. Without this, the connected-UDP
        // activation handler fails with EADDRINUSE on Linux and
        // every outbound packet falls back to the wildcard listen
        // socket — losing the kernel 5-tuple cache benefit and
        // most of the multihop forwarding throughput gain.
        let _ = sock.set_reuse_port(true);
        let _ = sock.set_reuse_address(true);

        sock.bind(&bind_addr.into())
            .map_err(|e| TransportError::StartFailed(format!("bind failed: {}", e)))?;

        // Set socket buffer sizes
        sock.set_recv_buffer_size(recv_buf_size)
            .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
        sock.set_send_buffer_size(send_buf_size)
            .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

        let actual_recv = sock
            .recv_buffer_size()
            .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))?;
        let actual_send = sock
            .send_buffer_size()
            .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))?;

        if actual_recv < recv_buf_size {
            warn!(
                requested = recv_buf_size,
                actual = actual_recv,
                "UDP recv buffer clamped by kernel (increase net.core.rmem_max)"
            );
        }
        if actual_send < send_buf_size {
            warn!(
                requested = send_buf_size,
                actual = actual_send,
                "UDP send buffer clamped by kernel (increase net.core.wmem_max)"
            );
        }

        sys::enable_drop_counting(sock.as_raw_fd());

        let local_addr = sock
            .local_addr()
            .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
            .as_socket()
            .ok_or_else(|| {
                TransportError::StartFailed("local address is not an IP socket".into())
            })?;

        Ok(Self {
            inner: sock,
            local_addr,
        })
    }

    /// Adopt an existing bound UDP socket.
    ///
    /// This preserves socket identity/NAT mapping created by bootstrap code.
    pub fn adopt(
        socket: std::net::UdpSocket,
        recv_buf_size: usize,
        send_buf_size: usize,
    ) -> Result<Self, TransportError> {
        let sock = Socket::from(socket);

        sock.set_nonblocking(true)
            .map_err(|e| TransportError::StartFailed(format!("set nonblocking failed: {}", e)))?;

        sock.set_recv_buffer_size(recv_buf_size)
            .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
        sock.set_send_buffer_size(send_buf_size)
            .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

        let actual_recv = sock
            .recv_buffer_size()
            .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))?;
        let actual_send = sock
            .send_buffer_size()
            .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))?;

        if actual_recv < recv_buf_size {
            warn!(
                requested = recv_buf_size,
                actual = actual_recv,
                "UDP recv buffer clamped by kernel (increase net.core.rmem_max)"
            );
        }
        if actual_send < send_buf_size {
            warn!(
                requested = send_buf_size,
                actual = actual_send,
                "UDP send buffer clamped by kernel (increase net.core.wmem_max)"
            );
        }

        sys::enable_drop_counting(sock.as_raw_fd());

        let local_addr = sock
            .local_addr()
            .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
            .as_socket()
            .ok_or_else(|| {
                TransportError::StartFailed("local address is not an IP socket".into())
            })?;

        Ok(Self {
            inner: sock,
            local_addr,
        })
    }

    /// Get the local bound address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the actual receive buffer size granted by the kernel.
    pub fn recv_buffer_size(&self) -> Result<usize, TransportError> {
        self.inner
            .recv_buffer_size()
            .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))
    }

    /// Get the actual send buffer size granted by the kernel.
    pub fn send_buffer_size(&self) -> Result<usize, TransportError> {
        self.inner
            .send_buffer_size()
            .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))
    }

    /// Synchronous send to a destination address.
    ///
    /// Returns the number of bytes sent, or an `io::Error`.
    pub fn send_to(&self, data: &[u8], dest: &SocketAddr) -> std::io::Result<usize> {
        let dest: socket2::SockAddr = (*dest).into();
        self.inner.send_to(data, &dest)
    }

    /// Synchronous receive with `SO_RXQ_OVFL` ancillary data parsing.
    ///
    /// Returns `(bytes_read, source_addr, kernel_drops)`. The `kernel_drops`
    /// value is a cumulative counter since socket creation; it is 0 if
    /// `SO_RXQ_OVFL` is not supported.
    ///
    /// The production receive path on Linux/macOS uses `recv_batch`
    /// (recvmmsg / recvmsg_x); this single-packet variant remains for
    /// other unix targets and for the local `tests` module.
    #[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
    pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr, u32)> {
        let fd = self.inner.as_raw_fd();

        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };

        let mut cmsg_buf = [0u8; sys::CMSG_BUF_SIZE];

        let mut src_addr: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = &mut src_addr as *mut _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1 as _;
        msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = cmsg_buf.len() as _;

        let n = unsafe { libc::recvmsg(fd, &mut msg, 0) };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Parse source address from sockaddr_storage
        let addr = sockaddr_to_socket_addr(&src_addr)?;

        let drops = sys::parse_drops(&msg);

        Ok((n as usize, addr, drops))
    }

    /// Receive up to `BATCH_SIZE` datagrams in a single syscall —
    /// `recvmmsg` on Linux, `recvmsg_x` on macOS. See the per-platform
    /// implementations for the full `(count, drops)` contract.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn recv_batch(
        &self,
        bufs: &mut [&mut [u8]],
        addrs: &mut [Option<SocketAddr>],
        lens: &mut [usize],
    ) -> std::io::Result<(usize, u32)> {
        sys::recv_batch(self.inner.as_raw_fd(), bufs, addrs, lens)
    }

    /// Wrap this socket in a tokio `AsyncFd` for async I/O.
    pub fn into_async(self) -> Result<AsyncUdpSocket, TransportError> {
        let async_fd = AsyncFd::new(self)
            .map_err(|e| TransportError::StartFailed(format!("AsyncFd::new failed: {}", e)))?;
        Ok(AsyncUdpSocket {
            inner: Arc::new(async_fd),
        })
    }
}

impl AsRawFd for UdpRawSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

/// Async wrapper around `UdpRawSocket` using tokio's `AsyncFd`.
///
/// `Arc`-shareable between send and receive tasks. `AsyncFd<T>` is
/// `Sync` when `T: Send`, which `socket2::Socket` satisfies.
#[derive(Clone)]
pub struct AsyncUdpSocket {
    inner: Arc<AsyncFd<UdpRawSocket>>,
}

impl AsRawFd for AsyncUdpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }
}

impl AsyncUdpSocket {
    /// Send a payload to a destination address.
    pub async fn send_to(&self, data: &[u8], dest: &SocketAddr) -> Result<usize, TransportError> {
        loop {
            let mut guard = self
                .inner
                .writable()
                .await
                .map_err(|e| TransportError::SendFailed(format!("writable wait: {}", e)))?;

            match guard.try_io(|inner| inner.get_ref().send_to(data, dest)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(TransportError::SendFailed(format!("{}", e))),
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive a payload, source address, and kernel drop counter.
    ///
    /// Returns `(bytes_read, source_addr, kernel_drops)`. On Linux/macOS
    /// the production receive path uses `recv_batch`; this single-packet
    /// variant remains for other unix targets and for the local `tests`
    /// module.
    #[cfg_attr(any(target_os = "linux", target_os = "macos"), allow(dead_code))]
    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr, u32), TransportError> {
        loop {
            let mut guard = self
                .inner
                .readable()
                .await
                .map_err(|e| TransportError::RecvFailed(format!("readable wait: {}", e)))?;

            match guard.try_io(|inner| inner.get_ref().recv_from(buf)) {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => return Err(TransportError::RecvFailed(format!("{}", e))),
                Err(_would_block) => continue,
            }
        }
    }

    /// Drain up to `BATCH_SIZE` datagrams from the kernel via
    /// `recvmmsg` (Linux) or `recvmsg_x` (macOS). Returns
    /// `(count, kernel_drops)`; same buffer / addr / len contract as
    /// `UdpRawSocket::recv_batch`. `kernel_drops` is always 0 on macOS.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub async fn recv_batch(
        &self,
        bufs: &mut [&mut [u8]],
        addrs: &mut [Option<SocketAddr>],
        lens: &mut [usize],
    ) -> Result<(usize, u32), TransportError> {
        loop {
            let mut guard = self
                .inner
                .readable()
                .await
                .map_err(|e| TransportError::RecvFailed(format!("readable wait: {}", e)))?;

            match guard.try_io(|inner| inner.get_ref().recv_batch(bufs, addrs, lens)) {
                Ok(Ok((0, _))) => {
                    // Spurious wakeup or no datagrams ready — yield
                    // back to the reactor instead of busy-looping.
                    guard.clear_ready();
                    continue;
                }
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(e)) => return Err(TransportError::RecvFailed(format!("{}", e))),
                Err(_would_block) => continue,
            }
        }
    }
}

/// Convert a `libc::sockaddr_storage` to `std::net::SocketAddr`.
pub(super) fn sockaddr_to_socket_addr(
    storage: &libc::sockaddr_storage,
) -> std::io::Result<SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let addr: &libc::sockaddr_in =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Ok(SocketAddr::from((ip, port)))
        }
        libc::AF_INET6 => {
            let addr: &libc::sockaddr_in6 =
                unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            // Carry `sin6_scope_id` through. A link-local source (fe80::/10)
            // identifies a host only together with its interface scope — the
            // same address can be present on several interfaces — so an
            // address parsed without it cannot be replied to. Sources outside
            // the link-local range carry scope 0, for which this is identical
            // to the unscoped form.
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                ip,
                port,
                0,
                addr.sin6_scope_id,
            )))
        }
        family => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unsupported address family: {}", family),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::sockaddr_to_socket_addr;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    /// Build an `AF_INET6` `sockaddr_storage` the way the kernel fills one in
    /// on receive: network-order port, raw address bytes, host-order scope.
    fn sockaddr_v6(ip: Ipv6Addr, port: u16, scope_id: u32) -> libc::sockaddr_storage {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: `sockaddr_storage` is defined to be large enough for, and
        // aligned for, every concrete `sockaddr_*`; we write the `AF_INET6`
        // variant and then tag `ss_family` to match.
        let addr = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
        addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        addr.sin6_port = port.to_be();
        addr.sin6_addr = libc::in6_addr {
            s6_addr: ip.octets(),
        };
        addr.sin6_scope_id = scope_id;
        storage
    }

    fn sockaddr_v4(ip: Ipv4Addr, port: u16) -> libc::sockaddr_storage {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        // SAFETY: as above, for the `AF_INET` variant.
        let addr = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
        addr.sin_family = libc::AF_INET as libc::sa_family_t;
        addr.sin_port = port.to_be();
        addr.sin_addr = libc::in_addr {
            s_addr: u32::from(ip).to_be(),
        };
        storage
    }

    /// The regression this function exists to prevent: a link-local source is
    /// routable only with its interface scope, so dropping `sin6_scope_id`
    /// leaves an address that cannot be replied to. Every address on a Wi-Fi
    /// Aware NDP interface is link-local, so losing it there stalls the Noise
    /// handshake — msg1 arrives, msg2 has nowhere to go.
    #[test]
    fn link_local_source_keeps_its_scope_id() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let storage = sockaddr_v6(ip, 4871, 42);

        match sockaddr_to_socket_addr(&storage).expect("AF_INET6 converts") {
            SocketAddr::V6(addr) => {
                assert_eq!(*addr.ip(), ip);
                assert_eq!(addr.port(), 4871);
                assert_eq!(addr.scope_id(), 42, "scope id must survive conversion");
            }
            other => panic!("expected V6, got {other:?}"),
        }
    }

    /// A scoped address is not equal to its unscoped twin, which is precisely
    /// why the bug was silent: both parse, both look right in a log line, and
    /// only the reply fails.
    #[test]
    fn scoped_and_unscoped_addresses_are_distinct() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let scoped = sockaddr_to_socket_addr(&sockaddr_v6(ip, 4871, 42)).unwrap();
        let unscoped = sockaddr_to_socket_addr(&sockaddr_v6(ip, 4871, 0)).unwrap();
        assert_ne!(scoped, unscoped);
    }

    /// Sources outside the link-local range carry scope 0, and must convert
    /// exactly as they did before.
    #[test]
    fn global_v6_source_is_unchanged() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let addr = sockaddr_to_socket_addr(&sockaddr_v6(ip, 4871, 0)).unwrap();
        assert_eq!(addr, SocketAddr::from((ip, 4871)));
    }

    #[test]
    fn v4_source_is_unchanged() {
        let ip = Ipv4Addr::new(192, 168, 8, 238);
        let addr = sockaddr_to_socket_addr(&sockaddr_v4(ip, 2121)).unwrap();
        assert_eq!(addr, SocketAddr::from((ip, 2121)));
    }

    #[test]
    fn unsupported_family_is_an_error() {
        let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
        storage.ss_family = libc::AF_UNIX as libc::sa_family_t;
        assert!(sockaddr_to_socket_addr(&storage).is_err());
    }
}
