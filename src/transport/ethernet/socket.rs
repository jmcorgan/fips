//! AF_PACKET socket creation, binding, and ioctl helpers.

use crate::transport::TransportError;
use std::os::unix::io::{AsRawFd, RawFd};
use tokio::io::unix::AsyncFd;

/// Broadcast MAC address.
pub const ETHERNET_BROADCAST: [u8; 6] = [0xff; 6];

/// Wrapper around an AF_PACKET SOCK_DGRAM file descriptor.
///
/// Owns the fd and closes it on drop. Provides synchronous send/recv
/// methods used by the async wrappers via `AsyncFd`.
pub struct PacketSocket {
    fd: RawFd,
    if_index: i32,
    ethertype: u16,
}

impl PacketSocket {
    /// Create and bind an AF_PACKET SOCK_DGRAM socket.
    ///
    /// Returns an error with a clear message if CAP_NET_RAW is missing.
    pub fn open(interface: &str, ethertype: u16) -> Result<Self, TransportError> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_DGRAM,
                (ethertype).to_be() as i32,
            )
        };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EPERM) {
                return Err(TransportError::StartFailed(
                    "AF_PACKET requires CAP_NET_RAW capability \
                     (run as root or use: setcap cap_net_raw=ep <binary>)"
                        .into(),
                ));
            }
            return Err(TransportError::StartFailed(format!(
                "socket(AF_PACKET) failed: {}",
                err
            )));
        }

        // Look up interface index
        let if_index = get_if_index(fd, interface)?;

        // Bind to the interface
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = ethertype.to_be();
        sll.sll_ifindex = if_index;

        let ret = unsafe {
            libc::bind(
                fd,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(TransportError::StartFailed(format!(
                "bind(AF_PACKET, {}) failed: {}",
                interface, err
            )));
        }

        // Set non-blocking for async integration
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(TransportError::StartFailed(format!(
                "fcntl(F_GETFL) failed: {}",
                err
            )));
        }
        let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(TransportError::StartFailed(format!(
                "fcntl(F_SETFL, O_NONBLOCK) failed: {}",
                err
            )));
        }

        Ok(Self {
            fd,
            if_index,
            ethertype,
        })
    }

    /// Get the interface index.
    pub fn if_index(&self) -> i32 {
        self.if_index
    }

    /// Get the local MAC address of the bound interface.
    pub fn local_mac(&self) -> Result<[u8; 6], TransportError> {
        get_mac_addr(self.fd, self.if_index)
    }

    /// Get the interface MTU.
    pub fn interface_mtu(&self) -> Result<u16, TransportError> {
        get_if_mtu(self.fd, self.if_index)
    }

    /// Set the socket receive buffer size.
    pub fn set_recv_buffer_size(&self, size: usize) -> Result<(), TransportError> {
        let size = size as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(TransportError::StartFailed(format!(
                "setsockopt(SO_RCVBUF) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Set the socket send buffer size.
    pub fn set_send_buffer_size(&self, size: usize) -> Result<(), TransportError> {
        let size = size as libc::c_int;
        let ret = unsafe {
            libc::setsockopt(
                self.fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            return Err(TransportError::StartFailed(format!(
                "setsockopt(SO_SNDBUF) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    /// Send a payload to a destination MAC address.
    ///
    /// Returns the number of bytes sent, or an io::Error.
    pub fn send_to(&self, data: &[u8], dest_mac: &[u8; 6]) -> std::io::Result<usize> {
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        sll.sll_family = libc::AF_PACKET as u16;
        sll.sll_protocol = self.ethertype.to_be();
        sll.sll_ifindex = self.if_index;
        sll.sll_halen = 6;
        sll.sll_addr[..6].copy_from_slice(dest_mac);

        let ret = unsafe {
            libc::sendto(
                self.fd,
                data.as_ptr() as *const libc::c_void,
                data.len(),
                0,
                &sll as *const libc::sockaddr_ll as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(ret as usize)
        }
    }

    /// Receive a payload and source MAC address.
    ///
    /// Returns (bytes_read, source_mac), or an io::Error.
    pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, [u8; 6])> {
        let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        let mut sll_len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;

        let ret = unsafe {
            libc::recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                &mut sll as *mut libc::sockaddr_ll as *mut libc::sockaddr,
                &mut sll_len,
            )
        };
        if ret < 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&sll.sll_addr[..6]);

        Ok((ret as usize, src_mac))
    }

    /// Wrap this socket in a tokio AsyncFd for async I/O.
    pub fn into_async(self) -> Result<AsyncPacketSocket, TransportError> {
        let async_fd = AsyncFd::new(self)
            .map_err(|e| TransportError::StartFailed(format!("AsyncFd::new failed: {}", e)))?;
        Ok(AsyncPacketSocket { inner: async_fd })
    }
}

impl AsRawFd for PacketSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for PacketSocket {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// Async wrapper around PacketSocket using tokio's AsyncFd.
pub struct AsyncPacketSocket {
    inner: AsyncFd<PacketSocket>,
}

impl AsyncPacketSocket {
    /// Send a payload to a destination MAC address.
    pub async fn send_to(&self, data: &[u8], dest_mac: &[u8; 6]) -> Result<usize, TransportError> {
        loop {
            let mut guard = self
                .inner
                .writable()
                .await
                .map_err(|e| TransportError::SendFailed(format!("writable wait: {}", e)))?;

            match guard.try_io(|inner| inner.get_ref().send_to(data, dest_mac)) {
                Ok(Ok(n)) => return Ok(n),
                Ok(Err(e)) => return Err(TransportError::SendFailed(format!("{}", e))),
                Err(_would_block) => continue,
            }
        }
    }

    /// Receive a payload and source MAC address.
    pub async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, [u8; 6]), TransportError> {
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

    /// Get a reference to the inner PacketSocket.
    pub fn get_ref(&self) -> &PacketSocket {
        self.inner.get_ref()
    }
}

// ============================================================================
// ioctl helpers
// ============================================================================

/// Get the interface index by name.
fn get_if_index(_fd: RawFd, interface: &str) -> Result<i32, TransportError> {
    let c_name = std::ffi::CString::new(interface).map_err(|_| {
        TransportError::StartFailed(format!("invalid interface name: {}", interface))
    })?;

    let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if idx == 0 {
        return Err(TransportError::StartFailed(format!(
            "interface not found: {} ({})",
            interface,
            std::io::Error::last_os_error()
        )));
    }
    Ok(idx as i32)
}

/// Get the MAC address of an interface by its index.
fn get_mac_addr(fd: RawFd, if_index: i32) -> Result<[u8; 6], TransportError> {
    // First get the interface name from the index
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Use if_indextoname to get the name
    let mut name_buf = [0u8; libc::IFNAMSIZ];
    let ret = unsafe {
        libc::if_indextoname(if_index as libc::c_uint, name_buf.as_mut_ptr() as *mut libc::c_char)
    };
    if ret.is_null() {
        return Err(TransportError::StartFailed(format!(
            "if_indextoname({}) failed: {}",
            if_index,
            std::io::Error::last_os_error()
        )));
    }

    // Copy name into ifreq
    let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(name_buf.len());
    let copy_len = name_len.min(libc::IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_buf.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }

    #[cfg(target_env = "musl")]
    let ioctl_req = libc::SIOCGIFHWADDR as libc::c_int;
    #[cfg(not(target_env = "musl"))]
    let ioctl_req = libc::SIOCGIFHWADDR as libc::c_ulong;
    let ret = unsafe { libc::ioctl(fd, ioctl_req, &ifr) };
    if ret < 0 {
        return Err(TransportError::StartFailed(format!(
            "ioctl(SIOCGIFHWADDR) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut mac = [0u8; 6];
    unsafe {
        let sa_data = ifr.ifr_ifru.ifru_hwaddr.sa_data;
        for (i, byte) in mac.iter_mut().enumerate() {
            *byte = sa_data[i] as u8;
        }
    }

    Ok(mac)
}

/// Get the MTU of an interface by its index.
fn get_if_mtu(fd: RawFd, if_index: i32) -> Result<u16, TransportError> {
    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };

    // Get the interface name from index
    let mut name_buf = [0u8; libc::IFNAMSIZ];
    let ret = unsafe {
        libc::if_indextoname(if_index as libc::c_uint, name_buf.as_mut_ptr() as *mut libc::c_char)
    };
    if ret.is_null() {
        return Err(TransportError::StartFailed(format!(
            "if_indextoname({}) failed: {}",
            if_index,
            std::io::Error::last_os_error()
        )));
    }

    let name_len = name_buf.iter().position(|&b| b == 0).unwrap_or(name_buf.len());
    let copy_len = name_len.min(libc::IFNAMSIZ - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_buf.as_ptr(),
            ifr.ifr_name.as_mut_ptr() as *mut u8,
            copy_len,
        );
    }

    #[cfg(target_env = "musl")]
    let ioctl_req = libc::SIOCGIFMTU as libc::c_int;
    #[cfg(not(target_env = "musl"))]
    let ioctl_req = libc::SIOCGIFMTU as libc::c_ulong;
    let ret = unsafe { libc::ioctl(fd, ioctl_req, &ifr) };
    if ret < 0 {
        return Err(TransportError::StartFailed(format!(
            "ioctl(SIOCGIFMTU) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mtu = unsafe { ifr.ifr_ifru.ifru_mtu } as u16;
    Ok(mtu)
}
