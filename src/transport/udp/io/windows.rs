//! UDP socket implementation for Windows.
//!
//! Uses `socket2::Socket` for configuration and `tokio::net::UdpSocket`
//! for async I/O. Neither kernel drop counting nor receive batching is
//! available, so this backend shares no code with the Unix one beyond the
//! type names it exports.

use crate::transport::TransportError;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;

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

        sock.set_nonblocking(true)
            .map_err(|e| TransportError::StartFailed(format!("set nonblocking failed: {}", e)))?;

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

    /// Adopt an existing bound UDP socket.
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
    pub async fn send_to(&self, data: &[u8], dest: &SocketAddr) -> Result<usize, TransportError> {
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
