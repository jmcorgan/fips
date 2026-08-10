//! Darwin-specific UDP receive and connected-socket construction.
//!
//! Holds the `recvmsg_x` FFI and the seam points the shared Unix code
//! delegates to. Darwin has no `SO_RXQ_OVFL` equivalent, so the drop
//! counter is always 0 here; the batching win comes from `recvmsg_x`
//! instead.

use super::unix::{BATCH_SIZE, sockaddr_to_socket_addr};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;

/// Darwin-private `msghdr_x` for the `recvmsg_x` / `sendmsg_x` syscalls.
/// Layout matches `bsd/sys/socket_private.h` in xnu — same as `msghdr` plus
/// a trailing `msg_datalen` (per-message bytes-received output, in lieu of
/// the `msg_len` field that `mmsghdr` uses on Linux).
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

unsafe extern "C" {
    fn recvmsg_x(
        s: libc::c_int,
        msgp: *const msghdr_x,
        cnt: libc::c_uint,
        flags: libc::c_int,
    ) -> isize;
}

/// Darwin has no `SO_RXQ_OVFL`, so there is no ancillary data to read;
/// the buffer only has to be large enough to be harmless.
pub(super) const CMSG_BUF_SIZE: usize = 64;

/// No kernel drop counter is available on Darwin.
pub(super) fn enable_drop_counting(_fd: RawFd) {}

/// Always 0 — see [`enable_drop_counting`].
pub(super) fn parse_drops(_msg: &libc::msghdr) -> u32 {
    0
}

/// Drain a connected Darwin UDP socket with one `recvmsg_x(2)` call.
///
/// Connected sockets do not need source-address storage, so this is the
/// compact counterpart to [`recv_batch`] used by per-peer receive threads.
pub(crate) fn recvmsg_x_drain(
    fd: RawFd,
    backing: &mut [Vec<u8>],
    lens: &mut [usize],
) -> io::Result<usize> {
    let n = backing.len().min(lens.len()).min(BATCH_SIZE);
    if n == 0 {
        return Ok(0);
    }

    let mut iovs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut msgs: [msghdr_x; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    for i in 0..n {
        iovs[i].iov_base = backing[i].as_mut_ptr() as *mut libc::c_void;
        iovs[i].iov_len = backing[i].len();
        msgs[i].msg_iov = &mut iovs[i];
        msgs[i].msg_iovlen = 1;
    }

    let received = loop {
        let received = unsafe { recvmsg_x(fd, msgs.as_ptr(), n as libc::c_uint, 0) };
        if received >= 0 {
            break received;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    };

    let count = received as usize;
    if count > n {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recvmsg_x reported more datagrams than requested",
        ));
    }
    for i in 0..count {
        lens[i] = msgs[i].msg_datalen;
    }
    Ok(count)
}

/// Receive up to `BATCH_SIZE` datagrams in a single `recvmsg_x` syscall.
/// Same `(count, drops)` contract as the Linux `recv_batch`, except
/// `drops` is always 0 — Darwin has no `SO_RXQ_OVFL` equivalent.
///
/// `recvmsg_x` is a Darwin-private syscall (not in the public SDK) but
/// is shipped in production xnu and is used by quinn-udp for the same
/// per-syscall-amortisation reason as our Linux `recvmmsg` path.
pub(super) fn recv_batch(
    fd: RawFd,
    bufs: &mut [&mut [u8]],
    addrs: &mut [Option<SocketAddr>],
    lens: &mut [usize],
) -> io::Result<(usize, u32)> {
    let n = bufs.len().min(addrs.len()).min(lens.len()).min(BATCH_SIZE);
    if n == 0 {
        return Ok((0, 0));
    }

    let mut iovs: [libc::iovec; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut storages: [libc::sockaddr_storage; BATCH_SIZE] = unsafe { std::mem::zeroed() };
    let mut msgs: [msghdr_x; BATCH_SIZE] = unsafe { std::mem::zeroed() };

    for i in 0..n {
        iovs[i].iov_base = bufs[i].as_mut_ptr() as *mut libc::c_void;
        iovs[i].iov_len = bufs[i].len();
        msgs[i].msg_name = &mut storages[i] as *mut _ as *mut libc::c_void;
        msgs[i].msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        msgs[i].msg_iov = &mut iovs[i];
        msgs[i].msg_iovlen = 1;
        // No cmsg consumption — leave msg_control null. (msg_controllen
        // is documented as not overwritten by macOS recvmsg_x; zeroed
        // init keeps it sane.)
    }

    let r = unsafe { recvmsg_x(fd, msgs.as_ptr(), n as libc::c_uint, 0) };
    if r < 0 {
        return Err(io::Error::last_os_error());
    }
    let count = r as usize;
    for i in 0..count {
        lens[i] = msgs[i].msg_datalen;
        addrs[i] = sockaddr_to_socket_addr(&storages[i]).ok();
    }

    Ok((count, 0))
}

// ============================================================================
// Connected-socket construction seam (see `super::connected`)
// ============================================================================

/// Darwin does not accept `SOCK_NONBLOCK` / `SOCK_CLOEXEC` in `socket(2)`;
/// [`prepare_fd`] sets the equivalent fd flags instead.
pub(super) const SOCKET_TYPE: libc::c_int = libc::SOCK_DGRAM;

/// Set `O_NONBLOCK` and `FD_CLOEXEC` with `fcntl`, standing in for the
/// socket-type flags Linux passes to `socket(2)`.
pub(super) fn prepare_fd(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Apply the Darwin service-type hint to a connected peer socket.
pub(super) fn tune_connected_socket(fd: RawFd) {
    super::macos_sockopts::apply_udp_socket_tuning(fd, "connected-udp-peer");
}

/// Apply receive and send buffer sizes to a connected peer socket.
/// Darwin has no `SO_*BUFFORCE`, so this is the ceiling-clamped path only.
pub(super) fn set_buf_sizes(fd: RawFd, recv_buf: usize, send_buf: usize) {
    set_buf_size(fd, libc::SO_RCVBUF, recv_buf);
    set_buf_size(fd, libc::SO_SNDBUF, send_buf);
}

/// Returns silently — buffer sizing is best-effort.
fn set_buf_size(fd: RawFd, normal_name: libc::c_int, size: usize) {
    let value: libc::c_int = size as libc::c_int;
    let _ = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            normal_name,
            &value as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
}
