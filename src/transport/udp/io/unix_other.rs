//! Seam implementation for Unix targets that are neither Linux nor macOS.
//!
//! Two supported targets land here: FreeBSD, and Android — which is
//! `target_os = "android"` rather than `"linux"`, and is the one of the two
//! that CI actually lints.
//!
//! These targets get the portable `recvmsg(2)` path only: no kernel drop
//! counter and no receive batching, so the shared code's `recv_batch` and
//! the connected-socket fast path are both compiled out for them. What
//! remains is the small set of hooks `super::unix` calls unconditionally.

use std::os::unix::io::RawFd;

/// No ancillary data is consumed on these targets; the buffer only has to
/// be large enough to be harmless.
pub(super) const CMSG_BUF_SIZE: usize = 64;

/// No kernel drop counter is available.
pub(super) fn enable_drop_counting(_fd: RawFd) {}

/// Always 0 — see [`enable_drop_counting`].
pub(super) fn parse_drops(_msg: &libc::msghdr) -> u32 {
    0
}
