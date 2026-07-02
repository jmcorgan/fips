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

    /// Maximum number of datagrams a single recvmmsg / recvmsg_x / sendmmsg
    /// syscall will pull from / push to the kernel. Tuned to amortise syscall +
    /// per-task-wakeup overhead across a useful burst without blowing the
    /// stack (each slot owns an mmsghdr/msghdr_x + sockaddr_storage + iovec).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const BATCH_SIZE: usize = 32;

    /// Darwin-private `msghdr_x` for the `recvmsg_x` / `sendmsg_x` syscalls.
    /// Layout matches `bsd/sys/socket_private.h` in xnu — same as `msghdr` plus
    /// a trailing `msg_datalen` (per-message bytes-received output, in lieu of
    /// the `msg_len` field that `mmsghdr` uses on Linux).
    #[cfg(target_os = "macos")]
    #[repr(C)]
    #[allow(non_camel_case_types)]
    struct msghdr_x {
        msg_name: *mut libc::c_void,
        msg_namelen: libc::socklen_t,
        msg_iov: *mut libc::iovec,
        msg_iovlen: libc::c_int,
        msg_control: *mut libc::c_void,
        msg_controllen: libc::socklen_t,
        msg_flags: libc::c_int,
        msg_datalen: usize,
    }

    #[cfg(target_os = "macos")]
    unsafe extern "C" {
        fn recvmsg_x(
            s: libc::c_int,
            msgp: *const msghdr_x,
            cnt: libc::c_uint,
            flags: libc::c_int,
        ) -> isize;
    }

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

        /// Adopt an existing bound UDP socket.
        ///
        /// This preserves socket identity/NAT mapping created by bootstrap code.
        pub fn adopt(
            socket: std::net::UdpSocket,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            let sock = Socket::from(socket);

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

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

        /// Receive up to `BATCH_SIZE` datagrams in a single recvmmsg syscall
        /// (Linux only — macOS falls through to per-packet recvmsg).
        ///
        /// Returns `(count, kernel_drops)`. Caller pre-sizes `bufs` (each
        /// must be at least the configured MTU) and the matching `addrs` /
        /// `lens` slices; on return, slots `[0..count)` are valid.
        ///
        /// `kernel_drops` is the `SO_RXQ_OVFL` cumulative counter sampled
        /// from the cmsg chain of the FIRST datagram in the batch. The
        /// counter is monotonic per-socket since `SO_RXQ_OVFL` was enabled,
        /// so a single sample per batch is sufficient to feed the 1Hz
        /// congestion detector in `sample_transport_congestion()`. Returns
        /// `(0, 0)` on a spurious wakeup with no datagrams ready.
        #[cfg(target_os = "linux")]
        pub fn recv_batch(
            &self,
            bufs: &mut [&mut [u8]],
            addrs: &mut [Option<SocketAddr>],
            lens: &mut [usize],
        ) -> std::io::Result<(usize, u32)> {
            let n = bufs.len().min(addrs.len()).min(lens.len()).min(BATCH_SIZE);
            if n == 0 {
                return Ok((0, 0));
            }
            let fd = self.inner.as_raw_fd();

            // CMSG buffer wired to msgs[0] only. SO_RXQ_OVFL delivers a
            // monotonic u32 drop counter; sampling once per batch gives
            // the 1Hz congestion detector ample fresh values under load
            // (one batch = up to 32 datagrams).
            const CMSG_BUF_SIZE: usize = unsafe { libc::CMSG_SPACE(4) } as usize;
            let mut cmsg_buf = [0u8; CMSG_BUF_SIZE];

            // Stack-allocated parallel arrays; lifetime tied to this call.
            let mut iovs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut storages: [libc::sockaddr_storage; BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..n {
                iovs[i].iov_base = bufs[i].as_mut_ptr() as *mut libc::c_void;
                iovs[i].iov_len = bufs[i].len();
                msgs[i].msg_hdr.msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_hdr.msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                msgs[i].msg_hdr.msg_iov = &mut iovs[i];
                msgs[i].msg_hdr.msg_iovlen = 1;
                msgs[i].msg_len = 0;
            }
            // Only msgs[0] carries a cmsg buffer — sampling the OVFL counter
            // there is enough since it is socket-wide and monotonic.
            msgs[0].msg_hdr.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
            msgs[0].msg_hdr.msg_controllen = cmsg_buf.len() as _;

            let r = unsafe {
                libc::recvmmsg(
                    fd,
                    msgs.as_mut_ptr(),
                    n as libc::c_uint,
                    0,
                    std::ptr::null_mut(),
                )
            };
            if r < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let count = r as usize;
            for i in 0..count {
                lens[i] = msgs[i].msg_len as usize;
                addrs[i] = sockaddr_to_socket_addr(&storages[i]).ok();
            }

            // Walk msgs[0] cmsg chain for SO_RXQ_OVFL. Skip when no
            // datagram landed (cmsg buffer is undefined in that case).
            let mut drops: u32 = 0;
            if count > 0 {
                unsafe {
                    let mut cmsg = libc::CMSG_FIRSTHDR(&msgs[0].msg_hdr);
                    while !cmsg.is_null() {
                        if (*cmsg).cmsg_level == libc::SOL_SOCKET
                            && (*cmsg).cmsg_type == libc::SO_RXQ_OVFL
                        {
                            let data = libc::CMSG_DATA(cmsg);
                            drops = std::ptr::read_unaligned(data as *const u32);
                        }
                        cmsg = libc::CMSG_NXTHDR(&msgs[0].msg_hdr, cmsg);
                    }
                }
            }

            Ok((count, drops))
        }

        /// Receive up to `BATCH_SIZE` datagrams in a single `recvmsg_x` syscall
        /// (macOS). Same `(count, drops)` contract as the Linux `recv_batch`,
        /// except `drops` is always 0 — Darwin has no `SO_RXQ_OVFL` equivalent.
        ///
        /// `recvmsg_x` is a Darwin-private syscall (not in the public SDK) but
        /// is shipped in production xnu and is used by quinn-udp for the same
        /// per-syscall-amortisation reason as our Linux `recvmmsg` path.
        #[cfg(target_os = "macos")]
        pub fn recv_batch(
            &self,
            bufs: &mut [&mut [u8]],
            addrs: &mut [Option<SocketAddr>],
            lens: &mut [usize],
        ) -> std::io::Result<(usize, u32)> {
            let n = bufs.len().min(addrs.len()).min(lens.len()).min(BATCH_SIZE);
            if n == 0 {
                return Ok((0, 0));
            }
            let fd = self.inner.as_raw_fd();

            let mut iovs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut storages: [libc::sockaddr_storage; BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut msgs: [msghdr_x; BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..n {
                iovs[i].iov_base = bufs[i].as_mut_ptr() as *mut libc::c_void;
                iovs[i].iov_len = bufs[i].len();
                msgs[i].msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
                msgs[i].msg_namelen =
                    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
                msgs[i].msg_iov = &mut iovs[i];
                msgs[i].msg_iovlen = 1;
                // No cmsg consumption — leave msg_control null. (msg_controllen
                // is documented as not overwritten by macOS recvmsg_x; zeroed
                // init keeps it sane.)
            }

            let r = unsafe { recvmsg_x(fd, msgs.as_ptr(), n as libc::c_uint, 0) };
            if r < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let count = r as usize;
            for i in 0..count {
                lens[i] = msgs[i].msg_datalen;
                addrs[i] = sockaddr_to_socket_addr(&storages[i]).ok();
            }

            Ok((count, 0))
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
                // Preserve sin6_scope_id: a link-local source (fe80::/10) is
                // only routable together with its interface scope, so dropping
                // it here breaks replies to a link-local peer (e.g. a Wi-Fi
                // Aware NDP interface). Non-link-local sources carry scope 0,
                // for which SocketAddrV6 is identical to the unscoped form.
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

        /// Adopt an existing bound UDP socket.
        pub fn adopt(
            socket: std::net::UdpSocket,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            let sock = Socket::from(socket);

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

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

    /// Microbench: compare per-packet `recv_from` (single recvmsg syscall +
    /// task wakeup per datagram — the macOS pre-recvmsg_x baseline) vs
    /// `recv_batch` (the new recvmsg_x path, up to 32 datagrams per syscall).
    /// Both modes run back-to-back in this binary on loopback so the only
    /// thing that varies is the receive-syscall strategy. Sender is a tight
    /// `socket.send_to()` loop in a separate task; receiver counts datagrams
    /// drained over a fixed wall-clock window per mode.
    ///
    /// Run with:
    ///   cargo test --release -p fips --lib transport::udp::socket::tests::bench_udp_recv_amortization -- --ignored --nocapture
    ///
    /// Sender runs on a dedicated *blocking* OS thread (std::net::UdpSocket
    /// in default blocking mode) so it always saturates the kernel rx queue
    /// regardless of how the tokio receiver schedules. That's the scenario
    /// where recvmmsg / recvmsg_x is meant to win: the receiver wakes up to
    /// find N packets already buffered, and one syscall reaps the burst.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore]
    async fn bench_udp_recv_amortization() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        const RECV_BUF: usize = 4 * 1024 * 1024;
        const SEND_BUF: usize = 1024 * 1024;
        const PAYLOAD_LEN: usize = 100;
        const WINDOW: Duration = Duration::from_secs(3);
        const WARMUP: Duration = Duration::from_millis(500);

        async fn run_mode(
            label: &str,
            batched: bool,
            sender_threads: usize,
        ) -> (u64, u64, Duration) {
            let rx_sock = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), RECV_BUF, SEND_BUF)
                .expect("rx bind");
            let rx_addr = rx_sock.local_addr();
            let rx = rx_sock.into_async().expect("rx into_async");

            // Senders: N dedicated blocking std threads. More threads → deeper
            // kernel rx queue → larger amortization opportunity for recv_batch.
            // ENOBUFS / EAGAIN just yield and retry; we want saturation, not
            // perfect accounting. Sent count is best-effort.
            let stop = Arc::new(AtomicBool::new(false));
            let mut sender_handles = Vec::with_capacity(sender_threads);
            for _ in 0..sender_threads {
                let stop_tx = stop.clone();
                sender_handles.push(std::thread::spawn(move || {
                    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("tx bind");
                    sock.connect(rx_addr).expect("tx connect");
                    let payload = vec![0xABu8; PAYLOAD_LEN];
                    let mut sent: u64 = 0;
                    while !stop_tx.load(Ordering::Relaxed) {
                        match sock.send(&payload) {
                            Ok(_) => sent += 1,
                            Err(_) => std::thread::yield_now(),
                        }
                    }
                    sent
                }));
            }

            // Warm-up: let the sender thread reach steady state and the
            // kernel rx queue start filling.
            tokio::time::sleep(WARMUP).await;

            let start = Instant::now();
            let deadline = start + WINDOW;
            let mut recv_count: u64 = 0;
            let mut last_drops: u32 = 0;

            if batched {
                const BATCH: usize = 32;
                let mut backing: Vec<Vec<u8>> =
                    (0..BATCH).map(|_| vec![0u8; PAYLOAD_LEN + 64]).collect();
                let mut addrs: [Option<SocketAddr>; BATCH] = std::array::from_fn(|_| None);
                let mut lens: [usize; BATCH] = [0; BATCH];
                let mut batch_sum: u64 = 0;
                let mut batch_calls: u64 = 0;

                while Instant::now() < deadline {
                    let mut bufs: [&mut [u8]; BATCH] = {
                        let mut iter = backing.iter_mut();
                        std::array::from_fn(|_| iter.next().unwrap().as_mut_slice())
                    };
                    match rx.recv_batch(&mut bufs, &mut addrs, &mut lens).await {
                        Ok((n, drops)) => {
                            recv_count += n as u64;
                            batch_sum += n as u64;
                            batch_calls += 1;
                            last_drops = drops;
                        }
                        Err(_) => break,
                    }
                }
                let avg_batch = if batch_calls > 0 {
                    batch_sum as f64 / batch_calls as f64
                } else {
                    0.0
                };
                eprintln!(
                    "[{:>10}] avg_batch_per_call={:.2} ({} calls)",
                    label, avg_batch, batch_calls
                );
            } else {
                let mut buf = vec![0u8; PAYLOAD_LEN + 64];
                while Instant::now() < deadline {
                    match rx.recv_from(&mut buf).await {
                        Ok((_n, _src, drops)) => {
                            recv_count += 1;
                            last_drops = drops;
                        }
                        Err(_) => break,
                    }
                }
            }
            let elapsed = start.elapsed();

            stop.store(true, Ordering::Relaxed);
            drop(rx);
            let sent: u64 = sender_handles
                .into_iter()
                .map(|h| h.join().unwrap_or(0))
                .sum();

            let pps = (recv_count as f64) / elapsed.as_secs_f64();
            let mbps =
                (recv_count as f64) * (PAYLOAD_LEN as f64) * 8.0 / 1e6 / elapsed.as_secs_f64();
            eprintln!(
                "[{:>10}] recv={:>10} sent={:>10} elapsed={:?} pps={:>12.0} mbps={:>7.1} kdrops={}",
                label, recv_count, sent, elapsed, pps, mbps, last_drops
            );
            (recv_count, sent, elapsed)
        }

        eprintln!("--- udp recv amortization bench ---");
        eprintln!(
            "payload={}B window={:?} warmup={:?} runtime=multi_thread(2)",
            PAYLOAD_LEN, WINDOW, WARMUP
        );

        // Sweep sender concurrency. Each level shows how the win scales as
        // the rx queue gets deeper (more amortization opportunity).
        for senders in [1usize, 2, 4, 8] {
            eprintln!("\n=== sender_threads = {} ===", senders);
            let (b_recv, _, b_el) = run_mode(" recv_from", false, senders).await;
            let (x_recv, _, x_el) = run_mode("recv_batch", true, senders).await;
            let (x_recv2, _, x_el2) = run_mode("recv_batch", true, senders).await;
            let (b_recv2, _, b_el2) = run_mode(" recv_from", false, senders).await;

            let baseline_pps =
                (b_recv as f64 / b_el.as_secs_f64() + b_recv2 as f64 / b_el2.as_secs_f64()) / 2.0;
            let batched_pps =
                (x_recv as f64 / x_el.as_secs_f64() + x_recv2 as f64 / x_el2.as_secs_f64()) / 2.0;
            let speedup = batched_pps / baseline_pps;
            eprintln!(
                "--- senders={}: baseline={:.0} pps  batched={:.0} pps  speedup={:.2}x ---",
                senders, baseline_pps, batched_pps, speedup
            );
        }
    }
}
