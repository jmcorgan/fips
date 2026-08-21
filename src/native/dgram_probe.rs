//! What a connected `AF_UNIX` `SOCK_DGRAM` pair does at end of file.
//!
//! This module is tests only. It exists to answer, by measurement on each
//! kernel rather than from the manual pages, the one question a macOS port of
//! this API turns on.
//!
//! [`super::seqpacket`] uses `SOCK_SEQPACKET`, which macOS does not implement
//! for `AF_UNIX`. The candidate replacement there is `SOCK_DGRAM`, which macOS
//! does implement and which also keeps message boundaries. What is not
//! transferable is the rule that tells a close apart from an empty datagram:
//! both produce a zero-byte read, and `seqpacket` resolves them with a latched
//! `POLLHUP` measured on Linux 6.8. Datagram poll semantics differ between
//! kernels, so that rule has to be re-established on Darwin before anything is
//! built on it.
//!
//! **The tests below assert the properties an implementation would need.** A
//! failure here is the measurement coming back negative, not a regression: it
//! says this kernel cannot support the `seqpacket` close rule on `SOCK_DGRAM`
//! and that a macOS port needs a different close signal. The same code runs on
//! every unix so the platforms can be compared without the test itself being a
//! variable.
//!
//! `SOCK_CLOEXEC` is deliberately not passed in the type argument, though
//! `super::seqpacket::pair` does pass it. Linux and FreeBSD accept it there and
//! macOS does not, and that difference belongs to the port rather than to this
//! measurement.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

/// Create a connected `AF_UNIX` `SOCK_DGRAM` pair.
fn dgram_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a two-element array of the type socketpair writes, and
    // the call either fills both entries or reports failure.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair reported success, so both entries are open descriptors
    // this frame now owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// One non-blocking receive, returning the byte count or the errno.
fn recv(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    // SAFETY: the descriptor is open and the pointer and length describe `buf`.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Send one datagram, returning the byte count or the errno.
fn send(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    // SAFETY: the descriptor is open and the pointer and length describe `buf`.
    let n = unsafe { libc::send(fd, buf.as_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(n as usize)
}

/// Whether `POLLHUP` is set, by the same rule `seqpacket::peer_hung_up` uses.
///
/// `POLLIN` is requested rather than nothing. An empty `events` registers no
/// filter on Darwin, so a poll asking for nothing reports nothing there and
/// every assertion built on this helper would pass whatever the kernel did.
/// That is the shape of a guard that executes and cannot fail, so it is worth
/// more than a comment: with `POLLIN` requested, a Darwin that began reporting
/// `POLLHUP` would red the tests below instead of slipping past them.
fn hung_up(fd: RawFd) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` points at one live pollfd and the call cannot block.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    rc > 0 && (poll.revents & libc::POLLHUP) != 0
}

#[test]
fn a_connected_dgram_pair_keeps_message_boundaries() {
    let (a, b) = dgram_pair().expect("AF_UNIX SOCK_DGRAM socketpair");
    assert_eq!(send(a.as_raw_fd(), &[1, 2, 3]).unwrap(), 3);
    assert_eq!(send(a.as_raw_fd(), &[4, 5]).unwrap(), 2);

    // Two sends must read back as two messages of their own lengths. A stream
    // socket would hand back all five bytes in one read, which is the failure
    // this discriminates.
    let mut buf = [0u8; 64];
    assert_eq!(recv(b.as_raw_fd(), &mut buf).unwrap(), 3);
    assert_eq!(&buf[..3], &[1, 2, 3]);
    assert_eq!(recv(b.as_raw_fd(), &mut buf).unwrap(), 2);
    assert_eq!(&buf[..2], &[4, 5]);
}

#[test]
fn an_empty_datagram_reads_as_zero_bytes_and_is_not_a_hangup() {
    let (a, b) = dgram_pair().expect("AF_UNIX SOCK_DGRAM socketpair");
    assert_eq!(send(a.as_raw_fd(), &[]).unwrap(), 0);

    let mut buf = [0u8; 64];
    assert_eq!(
        recv(b.as_raw_fd(), &mut buf).unwrap(),
        0,
        "an empty datagram must be delivered as a zero-byte message"
    );
    assert!(
        !hung_up(b.as_raw_fd()),
        "an empty datagram must not look like a closed peer: if this fails, a \
         client could tear down its own flow by sending nothing"
    );
}

/// Linux 6.8, measured 2026-08-20 with this test and cross-checked with a C
/// probe over both socket types: a connected `AF_UNIX` `SOCK_DGRAM` pair gives
/// **no close signal at all**. The peer closing leaves `revents` empty and
/// leaves `recv` returning `EAGAIN`, which is what an idle socket with a live
/// peer also does. `SOCK_SEQPACKET` on the same kernel sets `POLLHUP` and
/// returns a zero-byte read.
///
/// This is asserted rather than merely written down so that a kernel which
/// starts reporting the close reds this test and reopens the question.
#[cfg(target_os = "linux")]
#[test]
fn linux_gives_a_dgram_pair_no_close_signal_at_all() {
    let (a, b) = dgram_pair().expect("AF_UNIX SOCK_DGRAM socketpair");
    drop(a);

    let mut buf = [0u8; 64];
    let read = recv(b.as_raw_fd(), &mut buf);
    let err = read.as_ref().err().map(|e| e.raw_os_error());
    assert_eq!(
        err,
        Some(Some(libc::EAGAIN)),
        "expected the closed peer to be indistinguishable from an idle socket, got {read:?}"
    );
    assert!(
        !hung_up(b.as_raw_fd()),
        "POLLHUP is now set on a closed SOCK_DGRAM peer: this kernel has gained \
         the close signal Linux 6.8 did not have, and the macOS port's design \
         question should be reopened"
    );
}

/// The open question, and the only thing a Mac is needed for.
///
/// BSD kernels differ from Linux on datagram close reporting, so Darwin may
/// return `ECONNRESET`, or set `POLLHUP`, where Linux reports nothing. Either
/// would give the receive path something to key on.
///
/// **A failure here is the measurement coming back negative, not a
/// regression.** It says Darwin behaves as Linux does, that a `SOCK_DGRAM`
/// descriptor carries no close signal, and that a macOS port must take the
/// close from the client's line-protocol connection instead of from the flow
/// descriptor.
#[cfg(target_os = "macos")]
#[test]
fn darwin_reports_a_closed_dgram_peer_somehow() {
    let (a, b) = dgram_pair().expect("AF_UNIX SOCK_DGRAM socketpair");
    drop(a);

    let mut buf = [0u8; 64];
    let read = recv(b.as_raw_fd(), &mut buf);
    let hup = hung_up(b.as_raw_fd());
    let signalled = hup
        || matches!(&read, Ok(0))
        || read.as_ref().err().is_some_and(|e| {
            e.raw_os_error() != Some(libc::EAGAIN) && e.raw_os_error() != Some(libc::EWOULDBLOCK)
        });
    assert!(
        signalled,
        "Darwin reports nothing when a connected SOCK_DGRAM peer closes: \
         POLLHUP unset and recv gave {read:?}, which is what an idle socket \
         gives. The flow descriptor cannot carry the close on this platform."
    );
}

/// Which signal Darwin gives: `ECONNRESET`, and not `POLLHUP`.
///
/// Measured 2026-08-20 on `macos-latest`, run 32353220389, and identical across
/// all three of nextest's attempts, so it is the kernel's behaviour and not a
/// race. The exact reading was `poll` returning 0 with an empty `revents`, and
/// `recv` returning errno 54, `ECONNRESET`.
///
/// This is the opposite of `SOCK_SEQPACKET` on Linux, which sets `POLLHUP` and
/// returns a zero-byte read, and it is why
/// [`super::seqpacket::recv_once`](super::seqpacket) treats `ECONNRESET` as end
/// of file alongside the `POLLHUP` rule rather than choosing between them by
/// platform: one rule that accepts either signal is correct on both kernels.
///
/// Asserted rather than only written down, so that a Darwin release which moves
/// to `POLLHUP`, or stops reporting the close at all, reds this test instead of
/// silently changing what the receive path depends on.
#[cfg(target_os = "macos")]
#[test]
fn darwin_signals_a_closed_dgram_peer_with_econnreset() {
    let (a, b) = dgram_pair().expect("AF_UNIX SOCK_DGRAM socketpair");
    drop(a);

    let mut poll = libc::pollfd {
        fd: b.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` points at one live pollfd and the call cannot block.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };

    let mut buf = [0u8; 64];
    let read = recv(b.as_raw_fd(), &mut buf);
    let errno = read.as_ref().err().and_then(|e| e.raw_os_error());

    assert_eq!(
        errno,
        Some(libc::ECONNRESET),
        "Darwin no longer reports a closed SOCK_DGRAM peer as ECONNRESET. \
         Measured: poll rc={rc}, revents=0x{:04x}, recv={read:?}. The receive \
         path treats ECONNRESET as end of file and would now hang instead.",
        poll.revents,
    );
    assert!(
        (poll.revents & libc::POLLHUP) == 0,
        "Darwin has gained POLLHUP on a closed SOCK_DGRAM peer, revents=0x{:04x}. \
         Nothing breaks, since the receive path accepts either signal, but the \
         record here is now wrong and the SOCK_SEQPACKET comparison it rests on \
         should be re-read.",
        poll.revents,
    );
}

/// Whether a `SOCK_DGRAM` pair can carry the largest payload the API offers.
///
/// Darwin bounds a unix-domain datagram with the `net.local.dgram.maxdgram`
/// sysctl, whose default is small, and it is a system tunable rather than
/// something this process can rely on. Linux has no equivalent ceiling on an
/// `AF_UNIX` datagram beyond the socket buffer. The API advertises a payload
/// limit of 1362 bytes to its clients, so a kernel that refuses a datagram that
/// size would break the contract the client was told.
///
/// Written to answer on failure as well as on success: the assertion message
/// carries the largest size that did cross, so a negative result names the
/// actual ceiling rather than only saying the hoped-for one was not reached.
#[test]
fn a_dgram_pair_carries_the_largest_payload_the_api_advertises() {
    /// The `max_payload` the API reports to a client, from `super::mod`'s
    /// wire-derived limit. Duplicated rather than imported because the constant
    /// lives inside a module gated to the platforms that have the listener, and
    /// this test runs where that module does not exist.
    const ADVERTISED_PAYLOAD: usize = 1362;

    let (a, b) = dgram_pair().expect("AF_UNIX SOCK_DGRAM socketpair");

    // Walk up rather than testing one size, so a failure reports the ceiling.
    let mut largest = 0usize;
    let mut buf = vec![0u8; ADVERTISED_PAYLOAD * 4];
    for size in [64, 256, 1024, ADVERTISED_PAYLOAD, ADVERTISED_PAYLOAD * 2] {
        let payload = vec![0xA5u8; size];
        if send(a.as_raw_fd(), &payload).is_err() {
            break;
        }
        match recv(b.as_raw_fd(), &mut buf) {
            Ok(n) if n == size => largest = size,
            _ => break,
        }
    }

    assert!(
        largest >= ADVERTISED_PAYLOAD,
        "a SOCK_DGRAM pair carried at most {largest} bytes, below the \
         {ADVERTISED_PAYLOAD} the API advertises to clients. On Darwin this is \
         the net.local.dgram.maxdgram ceiling and the port has to raise it, or \
         lower what it advertises, rather than let a client send what it was \
         told it could."
    );
}

#[test]
fn a_datagram_queued_before_the_close_is_still_readable() {
    let (a, b) = dgram_pair().expect("AF_UNIX SOCK_DGRAM socketpair");
    assert_eq!(send(a.as_raw_fd(), &[7, 7, 7]).unwrap(), 3);
    drop(a);

    // Data sent before the close must survive it. A kernel that discards the
    // queue on close would lose a client's last datagram.
    let mut buf = [0u8; 64];
    assert_eq!(
        recv(b.as_raw_fd(), &mut buf).unwrap(),
        3,
        "a datagram queued before the peer closed must still be delivered"
    );
    assert_eq!(&buf[..3], &[7, 7, 7]);
}

#[test]
fn an_empty_datagram_queued_before_the_close_is_not_read_as_the_close() {
    let (a, b) = dgram_pair().expect("AF_UNIX SOCK_DGRAM socketpair");
    assert_eq!(send(a.as_raw_fd(), &[]).unwrap(), 0);
    drop(a);

    // The ordering case the close rule is weakest against. The peer has closed,
    // so POLLHUP is set, and the queued empty datagram also reads as zero
    // bytes, so `zero && hung_up` cannot tell them apart. Whatever the kernel
    // does here, the implementation has to handle it; this test records which
    // kernel loses the datagram.
    let mut buf = [0u8; 64];
    let read = recv(b.as_raw_fd(), &mut buf);
    let hup = hung_up(b.as_raw_fd());
    assert!(
        matches!(read, Ok(0)),
        "expected the queued empty datagram to read as zero bytes, got {read:?}"
    );
    assert!(
        !hup,
        "POLLHUP is set while an empty datagram is still queued, so a zero-byte \
         read plus POLLHUP cannot mean end of file on this kernel: the queued \
         datagram would be swallowed and reported as a close"
    );
}
