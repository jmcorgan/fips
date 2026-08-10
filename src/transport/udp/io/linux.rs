//! Linux-specific UDP receive and connected-socket construction.
//!
//! Holds the three seam points the shared Unix code delegates to —
//! `SO_RXQ_OVFL` drop counting, the ancillary-data control buffer, and
//! `recvmmsg(2)` batching — plus the Linux half of the per-peer
//! connected-fd syscall sequence.

use super::unix::{BATCH_SIZE, sockaddr_to_socket_addr};
use std::io;
use std::net::SocketAddr;
use std::os::unix::io::RawFd;
use tracing::warn;

/// Control message buffer size for `SO_RXQ_OVFL` (u32). `CMSG_SPACE`
/// computes the aligned size including header.
pub(super) const CMSG_BUF_SIZE: usize = unsafe { libc::CMSG_SPACE(4) } as usize;

/// Enable `SO_RXQ_OVFL` so `recvmsg` ancillary data carries the kernel
/// drop counter. Non-fatal: older kernels may not support it.
pub(super) fn enable_drop_counting(fd: RawFd) {
    let enable: libc::c_int = 1;
    let ret = unsafe {
        libc::setsockopt(
            fd,
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

/// Walk the cmsg chain for the `SO_RXQ_OVFL` drop counter.
pub(super) fn parse_drops(msg: &libc::msghdr) -> u32 {
    let mut drops: u32 = 0;
    unsafe {
        let mut cmsg = libc::CMSG_FIRSTHDR(msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == libc::SOL_SOCKET && (*cmsg).cmsg_type == libc::SO_RXQ_OVFL {
                let data = libc::CMSG_DATA(cmsg);
                drops = std::ptr::read_unaligned(data as *const u32);
            }
            cmsg = libc::CMSG_NXTHDR(msg, cmsg);
        }
    }
    drops
}

/// Receive up to `BATCH_SIZE` datagrams in a single `recvmmsg` syscall.
///
/// Returns `(count, kernel_drops)`. Caller pre-sizes `bufs` (each must be
/// at least the configured MTU) and the matching `addrs` / `lens` slices;
/// on return, slots `[0..count)` are valid.
///
/// `kernel_drops` is the `SO_RXQ_OVFL` cumulative counter sampled from the
/// cmsg chain of the FIRST datagram in the batch. The counter is monotonic
/// per-socket since `SO_RXQ_OVFL` was enabled, so a single sample per batch
/// is sufficient to feed the 1Hz congestion detector in
/// `sample_transport_congestion()`. Returns `(0, 0)` on a spurious wakeup
/// with no datagrams ready.
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

    // CMSG buffer wired to msgs[0] only. SO_RXQ_OVFL delivers a
    // monotonic u32 drop counter; sampling once per batch gives
    // the 1Hz congestion detector ample fresh values under load
    // (one batch = up to 32 datagrams).
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
        return Err(io::Error::last_os_error());
    }
    let count = r as usize;
    for i in 0..count {
        lens[i] = msgs[i].msg_len as usize;
        addrs[i] = sockaddr_to_socket_addr(&storages[i]).ok();
    }

    // Walk msgs[0] cmsg chain for SO_RXQ_OVFL. Skip when no
    // datagram landed (cmsg buffer is undefined in that case).
    let drops = if count > 0 {
        parse_drops(&msgs[0].msg_hdr)
    } else {
        0
    };

    Ok((count, drops))
}

// ============================================================================
// Connected-socket construction seam (see `super::connected`)
// ============================================================================

/// Linux accepts `SOCK_NONBLOCK | SOCK_CLOEXEC` directly in `socket(2)`.
pub(super) const SOCKET_TYPE: libc::c_int =
    libc::SOCK_DGRAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;

/// Nothing further to do: `SOCKET_TYPE` already carried the fd flags.
pub(super) fn prepare_fd(_fd: RawFd) -> io::Result<()> {
    Ok(())
}

/// No Darwin-style service-type tuning applies here.
pub(super) fn tune_connected_socket(_fd: RawFd) {}

/// Apply receive and send buffer sizes to a connected peer socket.
pub(super) fn set_buf_sizes(fd: RawFd, recv_buf: usize, send_buf: usize) {
    set_buf_size(fd, libc::SO_RCVBUFFORCE, libc::SO_RCVBUF, recv_buf);
    set_buf_size(fd, libc::SO_SNDBUFFORCE, libc::SO_SNDBUF, send_buf);
}

/// Try `SO_*BUFFORCE` first (bypasses the rmem/wmem ceiling) and
/// fall back to `SO_*BUF` if that fails. Returns silently — buffer
/// sizing is best-effort.
fn set_buf_size(fd: RawFd, force_name: libc::c_int, normal_name: libc::c_int, size: usize) {
    let value: libc::c_int = size as libc::c_int;
    let r = unsafe {
        libc::setsockopt(
            fd,
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
                fd,
                libc::SOL_SOCKET,
                normal_name,
                &value as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
    }
}
