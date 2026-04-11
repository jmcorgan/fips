//! UDP socket wrapper with platform-specific receive implementations.
//!
//! On Linux, provides `SO_RXQ_OVFL` kernel drop counter support via
//! `recvmsg()` ancillary data parsing. The async wrapper uses
//! `tokio::io::unix::AsyncFd` for integration with the tokio runtime.
//!
//! On macOS, uses the same `recvmsg()` path but without `SO_RXQ_OVFL`
//! (kernel drop counting is not available; the drops field returns 0).
//!
//! On Windows, uses `tokio::net::UdpSocket` directly (kernel drop
//! counting is not available; the drops field always returns 0).
//!
//! Follows the pattern established by `transport/ethernet/socket.rs`.

use crate::transport::TransportError;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(unix)]
use tracing::warn;

// ============================================================================
// Unix implementation
// ============================================================================

#[cfg(unix)]
mod platform {
    use super::*;
    use std::os::unix::io::{AsRawFd, RawFd};
    use tokio::io::unix::AsyncFd;

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

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

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

            // Enable SO_RXQ_OVFL for kernel drop counter in recvmsg ancillary data.
            // Non-fatal: older kernels or non-Linux platforms may not support it.
            #[cfg(target_os = "linux")]
            {
                let enable: libc::c_int = 1;
                let ret = unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::SOL_SOCKET,
                        libc::SO_RXQ_OVFL,
                        &enable as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
                if ret < 0 {
                    warn!(
                        "setsockopt(SO_RXQ_OVFL) failed: {}",
                        std::io::Error::last_os_error()
                    );
                }
            }

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
        pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr, u32)> {
            let fd = self.inner.as_raw_fd();

            let mut iov = libc::iovec {
                iov_base: buf.as_mut_ptr() as *mut libc::c_void,
                iov_len: buf.len(),
            };

            // Control message buffer sized for SO_RXQ_OVFL (u32).
            // CMSG_SPACE computes the aligned size including header.
            #[cfg(target_os = "linux")]
            const CMSG_BUF_SIZE: usize = unsafe { libc::CMSG_SPACE(4) } as usize;
            #[cfg(not(target_os = "linux"))]
            const CMSG_BUF_SIZE: usize = 64;
            let mut cmsg_buf = [0u8; CMSG_BUF_SIZE];

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

            // Walk cmsg chain for SO_RXQ_OVFL drop counter
            #[cfg(target_os = "linux")]
            let mut drops: u32 = 0;
            #[cfg(not(target_os = "linux"))]
            let drops: u32 = 0;
            #[cfg(target_os = "linux")]
            unsafe {
                let mut cmsg = libc::CMSG_FIRSTHDR(&msg);
                while !cmsg.is_null() {
                    if (*cmsg).cmsg_level == libc::SOL_SOCKET
                        && (*cmsg).cmsg_type == libc::SO_RXQ_OVFL
                    {
                        let data = libc::CMSG_DATA(cmsg);
                        drops = std::ptr::read_unaligned(data as *const u32);
                    }
                    cmsg = libc::CMSG_NXTHDR(&msg, cmsg);
                }
            }

            Ok((n as usize, addr, drops))
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

    impl AsyncUdpSocket {
        /// Send a payload to a destination address.
        pub async fn send_to(
            &self,
            data: &[u8],
            dest: &SocketAddr,
        ) -> Result<usize, TransportError> {
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
        /// Returns `(bytes_read, source_addr, kernel_drops)`.
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
    }

    /// Convert a `libc::sockaddr_storage` to `std::net::SocketAddr`.
    fn sockaddr_to_socket_addr(storage: &libc::sockaddr_storage) -> std::io::Result<SocketAddr> {
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
                Ok(SocketAddr::from((ip, port)))
            }
            family => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unsupported address family: {}", family),
            )),
        }
    }
}

// ============================================================================
// Windows implementation
// ============================================================================

#[cfg(windows)]
mod platform {
    use super::*;

    /// UDP socket wrapper (Windows).
    ///
    /// Uses `socket2::Socket` for configuration and `tokio::net::UdpSocket`
    /// for async I/O. Kernel drop counting is not available on Windows;
    /// the drops field always returns 0.
    pub struct UdpRawSocket {
        inner: Socket,
        local_addr: SocketAddr,
    }

    impl UdpRawSocket {
        /// Create, bind, and configure a UDP socket.
        ///
        /// Sets non-blocking mode and configures buffer sizes. The socket
        /// is bound immediately so `local_addr()` returns the actual
        /// assigned address (important when binding to port 0).
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

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

            sock.bind(&bind_addr.into())
                .map_err(|e| TransportError::StartFailed(format!("bind failed: {}", e)))?;

            // Set socket buffer sizes
            sock.set_recv_buffer_size(recv_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
            sock.set_send_buffer_size(send_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

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

        /// Get the actual receive buffer size.
        pub fn recv_buffer_size(&self) -> Result<usize, TransportError> {
            self.inner
                .recv_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))
        }

        /// Get the actual send buffer size.
        pub fn send_buffer_size(&self) -> Result<usize, TransportError> {
            self.inner
                .send_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))
        }

        /// Wrap this socket in an async wrapper for tokio I/O.
        pub fn into_async(self) -> Result<AsyncUdpSocket, TransportError> {
            let std_socket: std::net::UdpSocket = self.inner.into();
            let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| TransportError::StartFailed(format!("tokio socket failed: {}", e)))?;

            Ok(AsyncUdpSocket {
                inner: Arc::new(tokio_socket),
            })
        }
    }

    /// Async UDP socket wrapper (Windows).
    ///
    /// Uses `tokio::net::UdpSocket` directly. Kernel drop counting
    /// is not available; the drops field always returns 0.
    #[derive(Clone)]
    pub struct AsyncUdpSocket {
        inner: Arc<tokio::net::UdpSocket>,
    }

    impl AsyncUdpSocket {
        /// Send a payload to a destination address.
        pub async fn send_to(
            &self,
            data: &[u8],
            dest: &SocketAddr,
        ) -> Result<usize, TransportError> {
            self.inner
                .send_to(data, dest)
                .await
                .map_err(|e| TransportError::SendFailed(format!("{}", e)))
        }

        /// Receive a payload, source address, and kernel drop counter.
        ///
        /// Returns `(bytes_read, source_addr, 0)`. The drops field is always 0
        /// on Windows since kernel drop counting is not available.
        pub async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> Result<(usize, SocketAddr, u32), TransportError> {
            let (n, addr) = self
                .inner
                .recv_from(buf)
                .await
                .map_err(|e| TransportError::RecvFailed(format!("{}", e)))?;
            Ok((n, addr, 0))
        }
    }
}

pub use platform::{AsyncUdpSocket, UdpRawSocket};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_socket_bind() {
        // Bind to an ephemeral port
        let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind UDP socket");

        let addr = sock.local_addr();
        assert!(addr.port() > 0, "should be assigned an ephemeral port");
        assert!(addr.ip().is_loopback());
    }

    #[test]
    fn test_udp_socket_buffer_sizes() {
        let sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind UDP socket");

        let recv_buf = sock.recv_buffer_size().expect("get recv buffer");
        let send_buf = sock.send_buffer_size().expect("get send buffer");
        assert!(recv_buf > 0, "recv buffer should be non-zero");
        assert!(send_buf > 0, "send buffer should be non-zero");
    }

    #[tokio::test]
    async fn test_async_udp_socket_send_recv() {
        let sock1 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind socket 1");
        let addr1 = sock1.local_addr();
        let async1 = sock1.into_async().expect("into_async 1");

        let sock2 = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 65536, 65536)
            .expect("failed to bind socket 2");
        let addr2 = sock2.local_addr();
        let async2 = sock2.into_async().expect("into_async 2");

        // Send from socket 1 to socket 2
        let payload = b"hello fips";
        let sent = async1.send_to(payload, &addr2).await.expect("send_to");
        assert_eq!(sent, payload.len());

        // Receive on socket 2
        let mut buf = [0u8; 1024];
        let (n, src, _drops) = async2.recv_from(&mut buf).await.expect("recv_from");
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
        assert_eq!(src, addr1);
    }
}
