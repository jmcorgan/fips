//! BPF-based raw Ethernet socket for macOS.
//!
//! Provides the same `PacketSocket` API as the Linux AF_PACKET implementation,
//! using Berkeley Packet Filter (BPF) devices (`/dev/bpf*`).
//!
//! Key differences from Linux AF_PACKET SOCK_DGRAM:
//! - BPF operates on raw frames including the 14-byte Ethernet header.
//!   `send_to()` prepends it; `recv_from()` strips it.
//! - BPF reads may return multiple frames in one buffer (chained `bpf_hdr`).
//! - MAC address is obtained via `getifaddrs()` with `AF_LINK`.

use crate::transport::TransportError;
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::Mutex;

/// Ethernet header size: dst(6) + src(6) + ethertype(2).
const ETH_HDRLEN: usize = 14;

/// macOS SIOCGIFMTU ioctl constant.
const SIOCGIFMTU: libc::c_ulong = 0xC0206933;

/// BPF internal read state (behind Mutex for interior mutability,
/// since the async recv path needs `&self` access).
struct BpfReadState {
    buf: Vec<u8>,
    offset: usize,
    len: usize,
}

/// RAII guard that closes a raw fd on drop, used during socket setup
/// to prevent fd leaks if an intermediate step fails.
struct FdGuard(RawFd);

impl FdGuard {
    /// Disarm the guard, returning the fd without closing it.
    fn into_raw(self) -> RawFd {
        let fd = self.0;
        std::mem::forget(self);
        fd
    }
}

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0); }
    }
}

/// Wrapper around a BPF file descriptor.
///
/// Owns the fd and closes it on drop. Provides synchronous send/recv
/// methods matching the Linux `PacketSocket` API.
pub struct PacketSocket {
    fd: RawFd,
    if_index: i32,
    ethertype: u16,
    local_mac: [u8; 6],
    bpf_buflen: usize,
    read_state: Mutex<BpfReadState>,
    /// Write end of the shutdown pipe. Writing a byte wakes the reader
    /// thread's `select()` loop so it can exit promptly.
    shutdown_write_fd: RawFd,
    /// Read end of the shutdown pipe (passed to the reader thread).
    shutdown_read_fd: RawFd,
}

impl PacketSocket {
    /// Open a BPF device and bind it to the named interface.
    pub fn open(interface: &str, ethertype: u16) -> Result<Self, TransportError> {
        // Open the first available /dev/bpf device
        let guard = FdGuard(open_bpf_device()?);
        let fd = guard.0;

        // Look up interface index (for API compat; BPF binds by name)
        let if_index = get_if_index(interface)?;

        // Bind to the interface
        bind_to_interface(fd, interface)?;

        // Set immediate mode (deliver packets as they arrive)
        set_bpf_immediate(fd)?;

        // We supply complete Ethernet headers on writes
        set_bpf_hdrcmplt(fd)?;

        // Install a BPF filter to only capture our EtherType
        install_ethertype_filter(fd, ethertype)?;

        // Get the BPF read buffer length
        let bpf_buflen = get_bpf_buflen(fd)?;

        // Get local MAC address
        let local_mac = get_mac_addr(interface)?;

        // Create shutdown pipe — the reader thread select()s on both
        // the BPF fd and this pipe. Writing a byte signals shutdown.
        let mut pipe_fds = [0i32; 2];
        if unsafe { libc::pipe(pipe_fds.as_mut_ptr()) } < 0 {
            unsafe { libc::close(guard.0) };
            std::mem::forget(guard); // don't double-close via FdGuard
            return Err(TransportError::StartFailed(format!(
                "pipe() failed: {}", std::io::Error::last_os_error()
            )));
        }

        // All setup succeeded — disarm the guard so fd isn't closed
        guard.into_raw();

        Ok(Self {
            fd,
            if_index,
            ethertype,
            local_mac,
            bpf_buflen,
            read_state: Mutex::new(BpfReadState {
                buf: vec![0u8; bpf_buflen],
                offset: 0,
                len: 0,
            }),
            shutdown_read_fd: pipe_fds[0],
            shutdown_write_fd: pipe_fds[1],
        })
    }

    /// Get the interface index.
    pub fn if_index(&self) -> i32 {
        self.if_index
    }

    /// Get the local MAC address of the bound interface.
    pub fn local_mac(&self) -> Result<[u8; 6], TransportError> {
        Ok(self.local_mac)
    }

    /// Get the interface MTU.
    pub fn interface_mtu(&self) -> Result<u16, TransportError> {
        get_if_mtu(self.if_index)
    }

    /// Set the socket receive buffer size.
    ///
    /// BPF devices use a fixed kernel buffer; silently ignored.
    pub fn set_recv_buffer_size(&self, _size: usize) -> Result<(), TransportError> {
        Ok(())
    }

    /// Get the BPF read buffer length.
    pub fn bpf_buflen(&self) -> usize {
        self.bpf_buflen
    }

    /// Get the read end of the shutdown pipe (for the reader thread).
    pub fn shutdown_read_fd(&self) -> RawFd {
        self.shutdown_read_fd
    }

    /// Signal the reader thread to stop by writing to the shutdown pipe.
    pub fn request_shutdown(&self) {
        unsafe {
            libc::write(self.shutdown_write_fd, b"x".as_ptr() as *const libc::c_void, 1);
        }
    }

    /// Set the socket send buffer size.
    ///
    /// BPF devices use a fixed kernel buffer; silently ignored.
    pub fn set_send_buffer_size(&self, _size: usize) -> Result<(), TransportError> {
        Ok(())
    }

    /// Send a payload to a destination MAC address.
    ///
    /// Prepends a 14-byte Ethernet header (dst + src + ethertype) using
    /// `writev` for zero-copy scatter-gather. Returns the payload bytes
    /// sent (excluding the Ethernet header).
    pub fn send_to(&self, data: &[u8], dest_mac: &[u8; 6]) -> std::io::Result<usize> {
        // Build the 14-byte Ethernet header on the stack
        let mut hdr = [0u8; ETH_HDRLEN];
        hdr[..6].copy_from_slice(dest_mac);
        hdr[6..12].copy_from_slice(&self.local_mac);
        hdr[12..14].copy_from_slice(&self.ethertype.to_be_bytes());

        let iov = [
            libc::iovec {
                iov_base: hdr.as_ptr() as *mut libc::c_void,
                iov_len: ETH_HDRLEN,
            },
            libc::iovec {
                iov_base: data.as_ptr() as *mut libc::c_void,
                iov_len: data.len(),
            },
        ];

        let ret = unsafe { libc::writev(self.fd, iov.as_ptr(), 2) };
        if ret < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            // Return payload bytes (subtract Ethernet header)
            let sent = (ret as usize).saturating_sub(ETH_HDRLEN);
            Ok(sent)
        }
    }

    /// Receive a payload and source MAC address.
    ///
    /// BPF reads return raw frames with `bpf_hdr` prefixes. This method
    /// parses the next frame from the internal buffer, stripping the
    /// Ethernet header. Returns `(payload_bytes, source_mac)`.
    pub fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, [u8; 6])> {
        let mut state = self.read_state.lock().unwrap();
        let state = &mut *state;
        loop {
            // Try to parse the next frame from the read buffer
            if let Some(result) = parse_next_frame(&state.buf, &mut state.offset, state.len, buf) {
                return result;
            }

            // Buffer exhausted — read more from BPF
            let ret = unsafe {
                libc::read(
                    self.fd,
                    state.buf.as_mut_ptr() as *mut libc::c_void,
                    self.bpf_buflen,
                )
            };
            if ret < 0 {
                return Err(std::io::Error::last_os_error());
            }
            state.len = ret as usize;
            state.offset = 0;
        }
    }
}

/// Parse the next BPF frame from the read buffer.
///
/// Returns `None` if the buffer is exhausted and needs a new `read()`.
pub fn parse_next_frame(
    read_buf: &[u8],
    read_offset: &mut usize,
    read_len: usize,
    out_buf: &mut [u8],
) -> Option<std::io::Result<(usize, [u8; 6])>> {
    const BPF_HDR_SIZE: usize = std::mem::size_of::<BpfHeader>();

    if *read_offset >= read_len {
        return None;
    }

    let remaining = read_len - *read_offset;
    if remaining < BPF_HDR_SIZE {
        *read_offset = read_len;
        return None;
    }

    // Read the bpf_hdr
    let hdr_ptr = read_buf[*read_offset..].as_ptr() as *const BpfHeader;
    let hdr = unsafe { std::ptr::read_unaligned(hdr_ptr) };
    let cap_len = hdr.bh_caplen as usize;
    let data_offset = hdr.bh_hdrlen as usize;

    // Advance past this frame (BPF_WORDALIGN)
    let total_len = bpf_wordalign(data_offset + cap_len);
    let frame_start = *read_offset + data_offset;
    *read_offset += total_len;

    // Validate we have enough captured data for an Ethernet header
    if cap_len < ETH_HDRLEN {
        return None; // Runt frame, skip
    }

    if frame_start + cap_len > read_len {
        return None; // Truncated, skip
    }

    let frame = &read_buf[frame_start..frame_start + cap_len];

    // Extract source MAC from Ethernet header bytes [6..12]
    let mut src_mac = [0u8; 6];
    src_mac.copy_from_slice(&frame[6..12]);

    // Copy payload (after 14-byte Ethernet header) into caller's buffer
    let payload = &frame[ETH_HDRLEN..];
    let copy_len = payload.len().min(out_buf.len());
    out_buf[..copy_len].copy_from_slice(&payload[..copy_len]);

    Some(Ok((copy_len, src_mac)))
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
            libc::close(self.shutdown_read_fd);
            libc::close(self.shutdown_write_fd);
        }
    }
}

// ============================================================================
// BPF helpers
// ============================================================================

/// BPF header (matches `struct bpf_hdr` from `<net/bpf.h>`).
///
/// On macOS, `bpf_hdr` uses `struct BPF_TIMEVAL` which is `struct timeval32`
/// (two `u32` fields) regardless of architecture. Total size: 20 bytes
/// (4+4+4+4+2 = 18, padded to 20 for alignment).
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfHeader {
    bh_tstamp_sec: u32,
    bh_tstamp_usec: u32,
    bh_caplen: u32,
    bh_datalen: u32,
    bh_hdrlen: u16,
    _pad: u16,
}

// Compile-time check that our struct matches the kernel's bpf_hdr (20 bytes).
const _: () = assert!(std::mem::size_of::<BpfHeader>() == 20);

/// BPF word alignment (round up to next 4-byte boundary).
fn bpf_wordalign(x: usize) -> usize {
    (x + 3) & !3
}

/// BPF ioctl constants (from <net/bpf.h>).
const BIOCSETIF: libc::c_ulong = 0x8020426C;
const BIOCIMMEDIATE: libc::c_ulong = 0x80044270;
const BIOCSHDRCMPLT: libc::c_ulong = 0x80044275;
const BIOCSETF: libc::c_ulong = 0x80104267;
const BIOCGBLEN: libc::c_ulong = 0x40044266;

/// BPF instruction.
#[repr(C)]
#[derive(Clone, Copy)]
struct BpfInsn {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

/// BPF program.
#[repr(C)]
struct BpfProgram {
    bf_len: u32,
    bf_insns: *const BpfInsn,
}

/// Open the first available `/dev/bpf*` device.
fn open_bpf_device() -> Result<RawFd, TransportError> {
    for i in 0..256 {
        let path = format!("/dev/bpf{}", i);
        let c_path = std::ffi::CString::new(path.as_str()).unwrap();
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR) };
        if fd >= 0 {
            return Ok(fd);
        }
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EACCES) {
            return Err(TransportError::StartFailed(
                "BPF requires root (run with sudo)".into(),
            ));
        }
        // EBUSY: device in use, try next one
    }
    Err(TransportError::StartFailed(
        "no available /dev/bpf* device".into(),
    ))
}

/// Bind a BPF fd to a network interface.
fn bind_to_interface(fd: RawFd, interface: &str) -> Result<(), TransportError> {
    let mut ifreq: [u8; 32] = [0; 32]; // struct ifreq
    let name_bytes = interface.as_bytes();
    let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
    ifreq[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

    let ret = unsafe { libc::ioctl(fd, BIOCSETIF, ifreq.as_ptr()) };
    if ret < 0 {
        return Err(TransportError::StartFailed(format!(
            "BIOCSETIF({}) failed: {}", interface, std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Enable immediate mode (deliver packets without buffering).
fn set_bpf_immediate(fd: RawFd) -> Result<(), TransportError> {
    let enable: libc::c_uint = 1;
    let ret = unsafe { libc::ioctl(fd, BIOCIMMEDIATE, &enable) };
    if ret < 0 {
        return Err(TransportError::StartFailed(format!(
            "BIOCIMMEDIATE failed: {}", std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Tell BPF we supply complete Ethernet headers on writes.
fn set_bpf_hdrcmplt(fd: RawFd) -> Result<(), TransportError> {
    let enable: libc::c_uint = 1;
    let ret = unsafe { libc::ioctl(fd, BIOCSHDRCMPLT, &enable) };
    if ret < 0 {
        return Err(TransportError::StartFailed(format!(
            "BIOCSHDRCMPLT failed: {}", std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Install a BPF filter to only capture frames with the given EtherType.
fn install_ethertype_filter(fd: RawFd, ethertype: u16) -> Result<(), TransportError> {
    // BPF program: match EtherType at offset 12 in Ethernet header
    //   ldh [12]                    ; load half-word at offset 12 (EtherType)
    //   jeq #ethertype, accept, reject
    //   accept: ret #65535          ; accept entire packet
    //   reject: ret #0              ; drop
    let filter = [
        BpfInsn { code: 0x28, jt: 0, jf: 0, k: 12 },                     // ldh [12]
        BpfInsn { code: 0x15, jt: 0, jf: 1, k: ethertype as u32 },       // jeq #ethertype
        BpfInsn { code: 0x06, jt: 0, jf: 0, k: 0xFFFF },                 // ret #65535
        BpfInsn { code: 0x06, jt: 0, jf: 0, k: 0 },                     // ret #0
    ];

    let prog = BpfProgram {
        bf_len: filter.len() as u32,
        bf_insns: filter.as_ptr(),
    };

    let ret = unsafe { libc::ioctl(fd, BIOCSETF, &prog) };
    if ret < 0 {
        return Err(TransportError::StartFailed(format!(
            "BIOCSETF failed: {}", std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// Get the BPF read buffer length.
fn get_bpf_buflen(fd: RawFd) -> Result<usize, TransportError> {
    let mut buflen: libc::c_uint = 0;
    let ret = unsafe { libc::ioctl(fd, BIOCGBLEN, &mut buflen) };
    if ret < 0 {
        return Err(TransportError::StartFailed(format!(
            "BIOCGBLEN failed: {}", std::io::Error::last_os_error()
        )));
    }
    Ok(buflen as usize)
}

/// Get the interface index by name.
fn get_if_index(interface: &str) -> Result<i32, TransportError> {
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

/// Get the MAC address of an interface using `getifaddrs()` with `AF_LINK`.
fn get_mac_addr(interface: &str) -> Result<[u8; 6], TransportError> {
    let mut addrs: *mut libc::ifaddrs = std::ptr::null_mut();
    let ret = unsafe { libc::getifaddrs(&mut addrs) };
    if ret != 0 {
        return Err(TransportError::StartFailed(format!(
            "getifaddrs() failed: {}", std::io::Error::last_os_error()
        )));
    }

    let result = (|| {
        let mut cur = addrs;
        while !cur.is_null() {
            let ifa = unsafe { &*cur };
            let name = unsafe { std::ffi::CStr::from_ptr(ifa.ifa_name) }
                .to_str()
                .unwrap_or("");

            if name == interface && !ifa.ifa_addr.is_null() {
                let sa = unsafe { &*ifa.ifa_addr };
                if sa.sa_family as i32 == libc::AF_LINK {
                    let sdl = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_dl) };
                    let nlen = sdl.sdl_nlen as usize;
                    // MAC address starts after the interface name in sdl_data
                    let data_ptr = sdl.sdl_data.as_ptr();
                    let mut mac = [0u8; 6];
                    for i in 0..6 {
                        mac[i] = unsafe { *data_ptr.add(nlen + i) } as u8;
                    }
                    return Ok(mac);
                }
            }
            cur = unsafe { (*cur).ifa_next };
        }
        Err(TransportError::StartFailed(format!(
            "MAC address not found for interface: {}", interface
        )))
    })();

    unsafe { libc::freeifaddrs(addrs) };
    result
}

// ============================================================================
// Unit tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // bpf_wordalign
    // -----------------------------------------------------------------------

    #[test]
    fn test_bpf_wordalign_already_aligned() {
        assert_eq!(bpf_wordalign(0), 0);
        assert_eq!(bpf_wordalign(4), 4);
        assert_eq!(bpf_wordalign(8), 8);
        assert_eq!(bpf_wordalign(20), 20);
    }

    #[test]
    fn test_bpf_wordalign_rounds_up() {
        assert_eq!(bpf_wordalign(1), 4);
        assert_eq!(bpf_wordalign(2), 4);
        assert_eq!(bpf_wordalign(3), 4);
        assert_eq!(bpf_wordalign(5), 8);
        assert_eq!(bpf_wordalign(21), 24);
    }

    // -----------------------------------------------------------------------
    // parse_next_frame helpers
    // -----------------------------------------------------------------------

    /// Build a single BPF packet in a buffer.
    ///
    /// Layout:
    ///   [0..20]  BpfHeader  (bh_hdrlen = 20)
    ///   [20..26] dst_mac
    ///   [26..32] src_mac
    ///   [32..34] ethertype (0x0800)
    ///   [34..]   payload
    ///   [..]     zero padding to BPF_WORDALIGN boundary
    fn make_bpf_packet(src_mac: [u8; 6], payload: &[u8]) -> Vec<u8> {
        let cap_len = ETH_HDRLEN + payload.len();
        let hdr = BpfHeader {
            bh_tstamp_sec: 0,
            bh_tstamp_usec: 0,
            bh_caplen: cap_len as u32,
            bh_datalen: cap_len as u32,
            bh_hdrlen: std::mem::size_of::<BpfHeader>() as u16,
            _pad: 0,
        };
        let hdr_size = std::mem::size_of::<BpfHeader>();
        let total = bpf_wordalign(hdr_size + cap_len);
        let mut buf = vec![0u8; total];

        // Write header
        unsafe {
            std::ptr::copy_nonoverlapping(
                &hdr as *const BpfHeader as *const u8,
                buf.as_mut_ptr(),
                hdr_size,
            );
        }

        // Write Ethernet header: dst(6) + src(6) + ethertype(2)
        let frame_start = hdr_size;
        buf[frame_start..frame_start + 6].copy_from_slice(&[0xff; 6]); // dst = broadcast
        buf[frame_start + 6..frame_start + 12].copy_from_slice(&src_mac);
        buf[frame_start + 12] = 0x08;
        buf[frame_start + 13] = 0x00;

        // Write payload
        buf[frame_start + ETH_HDRLEN..frame_start + ETH_HDRLEN + payload.len()]
            .copy_from_slice(payload);

        buf
    }

    // -----------------------------------------------------------------------
    // parse_next_frame
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_next_frame_single() {
        let src_mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        let payload = b"hello world";
        let buf = make_bpf_packet(src_mac, payload);

        let mut out_buf = vec![0u8; 1500];
        let mut offset = 0usize;
        let len = buf.len();

        let result = parse_next_frame(&buf, &mut offset, len, &mut out_buf)
            .expect("should return Some")
            .expect("should be Ok");

        assert_eq!(result.0, payload.len());
        assert_eq!(result.1, src_mac);
        assert_eq!(&out_buf[..result.0], payload);
        // offset should have advanced past this frame
        assert!(offset > 0);
    }

    #[test]
    fn test_parse_next_frame_two_frames() {
        let src1 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let src2 = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let payload1 = b"first";
        let payload2 = b"second";

        let mut buf = make_bpf_packet(src1, payload1);
        buf.extend_from_slice(&make_bpf_packet(src2, payload2));
        let len = buf.len();

        let mut out_buf = vec![0u8; 1500];
        let mut offset = 0usize;

        // First frame
        let (n1, mac1) = parse_next_frame(&buf, &mut offset, len, &mut out_buf)
            .expect("Some")
            .expect("Ok");
        assert_eq!(mac1, src1);
        assert_eq!(&out_buf[..n1], payload1);

        // Second frame
        let (n2, mac2) = parse_next_frame(&buf, &mut offset, len, &mut out_buf)
            .expect("Some")
            .expect("Ok");
        assert_eq!(mac2, src2);
        assert_eq!(&out_buf[..n2], payload2);

        // Buffer exhausted
        assert!(parse_next_frame(&buf, &mut offset, len, &mut out_buf).is_none());
    }

    #[test]
    fn test_parse_next_frame_empty_buffer() {
        let buf = vec![0u8; 0];
        let mut out_buf = vec![0u8; 1500];
        let mut offset = 0usize;
        assert!(parse_next_frame(&buf, &mut offset, 0, &mut out_buf).is_none());
    }

    #[test]
    fn test_parse_next_frame_offset_at_end() {
        let buf = vec![0u8; 64];
        let mut out_buf = vec![0u8; 1500];
        let mut offset = 64usize;
        assert!(parse_next_frame(&buf, &mut offset, 64, &mut out_buf).is_none());
    }

    #[test]
    fn test_parse_next_frame_runt_skipped() {
        // Build a packet with cap_len < ETH_HDRLEN (13 bytes — too short for
        // a valid Ethernet header). parse_next_frame should skip it and return None.
        let hdr_size = std::mem::size_of::<BpfHeader>();
        let cap_len: usize = 13; // < ETH_HDRLEN (14)
        let hdr = BpfHeader {
            bh_tstamp_sec: 0,
            bh_tstamp_usec: 0,
            bh_caplen: cap_len as u32,
            bh_datalen: cap_len as u32,
            bh_hdrlen: hdr_size as u16,
            _pad: 0,
        };
        let total = bpf_wordalign(hdr_size + cap_len);
        let mut buf = vec![0u8; total];
        unsafe {
            std::ptr::copy_nonoverlapping(
                &hdr as *const BpfHeader as *const u8,
                buf.as_mut_ptr(),
                hdr_size,
            );
        }

        let mut out_buf = vec![0u8; 1500];
        let mut offset = 0usize;
        // Runt: returns None (skipped, not an error)
        assert!(parse_next_frame(&buf, &mut offset, buf.len(), &mut out_buf).is_none());
    }

    #[test]
    fn test_parse_next_frame_output_buf_truncation() {
        // out_buf smaller than payload — result should be truncated to out_buf size.
        let src_mac = [0xde, 0xad, 0xbe, 0xef, 0x00, 0x01];
        let payload = b"this payload is longer than the output buffer";
        let bpf_buf = make_bpf_packet(src_mac, payload);
        let len = bpf_buf.len();

        let mut out_buf = vec![0u8; 10]; // deliberately small
        let mut offset = 0usize;
        let (n, mac) = parse_next_frame(&bpf_buf, &mut offset, len, &mut out_buf)
            .expect("Some")
            .expect("Ok");

        assert_eq!(n, 10);
        assert_eq!(mac, src_mac);
        assert_eq!(&out_buf[..n], &payload[..10]);
    }

    // -----------------------------------------------------------------------
    // Shutdown pipe signaling
    //
    // Verifies the self-pipe pattern used to wake the BPF reader thread.
    // -----------------------------------------------------------------------

    /// Returns true if `fd` is readable within the given timeout (0 = poll).
    fn fd_is_readable(fd: RawFd, timeout_ms: i64) -> bool {
        unsafe {
            let mut tv = libc::timeval {
                tv_sec: timeout_ms / 1000,
                tv_usec: ((timeout_ms % 1000) * 1000) as i32,
            };
            let mut read_fds: libc::fd_set = std::mem::zeroed();
            libc::FD_ZERO(&mut read_fds);
            libc::FD_SET(fd, &mut read_fds);
            let ret = libc::select(
                fd + 1,
                &mut read_fds,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut tv,
            );
            ret > 0 && libc::FD_ISSET(fd, &read_fds)
        }
    }

    #[test]
    fn test_shutdown_pipe_initially_not_readable() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);

        let readable = fd_is_readable(read_fd, 0);
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        assert!(!readable, "pipe read end should not be readable before write");
    }

    #[test]
    fn test_shutdown_pipe_readable_after_write() {
        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (read_fd, write_fd) = (fds[0], fds[1]);

        unsafe {
            libc::write(write_fd, b"x".as_ptr() as *const libc::c_void, 1);
        }

        let readable = fd_is_readable(read_fd, 0);
        unsafe {
            libc::close(read_fd);
            libc::close(write_fd);
        }
        assert!(readable, "pipe read end should be readable after write");
    }
}

/// Get the MTU of an interface by index.
fn get_if_mtu(if_index: i32) -> Result<u16, TransportError> {
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(TransportError::StartFailed(format!(
            "socket(AF_INET) for MTU query failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    // Get interface name from index
    let mut name_buf = [0i8; libc::IFNAMSIZ];
    let ret = unsafe {
        libc::if_indextoname(if_index as libc::c_uint, name_buf.as_mut_ptr())
    };
    if ret.is_null() {
        unsafe { libc::close(sock) };
        return Err(TransportError::StartFailed(format!(
            "if_indextoname({}) failed: {}", if_index, std::io::Error::last_os_error()
        )));
    }

    let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
    unsafe {
        std::ptr::copy_nonoverlapping(
            name_buf.as_ptr(),
            ifr.ifr_name.as_mut_ptr(),
            libc::IFNAMSIZ,
        );
    }

    let ret = unsafe { libc::ioctl(sock, SIOCGIFMTU, &mut ifr) };
    unsafe { libc::close(sock) };
    if ret < 0 {
        return Err(TransportError::StartFailed(format!(
            "ioctl(SIOCGIFMTU) failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mtu = unsafe { ifr.ifr_ifru.ifru_mtu } as u16;
    Ok(mtu)
}
