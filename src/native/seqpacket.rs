//! A connected `SOCK_SEQPACKET` pair, one half driven by tokio readiness.
//!
//! `SOCK_SEQPACKET` is what a datagram API wants from a local socket: it keeps
//! message boundaries, it is flow controlled, and it reports end of file when
//! the peer closes. `SOCK_STREAM` loses the boundaries and `SOCK_DGRAM` gives a
//! weaker close signal.
//!
//! Tokio ships no type for it — `UnixStream` is `SOCK_STREAM` and
//! `UnixDatagram` is `SOCK_DGRAM` — so the daemon's half is driven through
//! [`AsyncFd`], which is tokio's supported way to put an arbitrary file
//! descriptor under the reactor.
//!
//! **macOS and FreeBSD use `SOCK_DGRAM` instead**, for two different reasons
//! that come to the same thing. macOS does not implement `SOCK_SEQPACKET` for
//! `AF_UNIX` at all. FreeBSD accepts the constant and gives back a socket that
//! is not an atomic-record socket: `seqpacketproto` carries no `PR_ATOMIC` and
//! shares its send and receive handlers with `SOCK_STREAM`, so consecutive
//! messages coalesce and a zero-length message is queued nowhere and delivered
//! never. **Measured on the FreeBSD 15.1 CI image on 2026-08-22**, by the two
//! probes in [`super::dgram_probe`] named for it: a `SOCK_SEQPACKET` pair there
//! does not keep message boundaries, and it drops a zero-length message instead
//! of delivering it. The reading of the kernel source came first and the
//! measurement agreed with it; before that run the mechanism was inferred from
//! a CI log in which the zero-length-message test hung until the job was killed
//! and five boundary tests failed within 360 ms.
//! Everything else this module needs works on both: `SCM_RIGHTS` is supported,
//! `AsyncFd` is backed by kqueue, and a connected `SOCK_DGRAM` pair keeps
//! message boundaries and delivers an empty datagram, which `SOCK_SEQPACKET`
//! does on Linux and does not here.
//!
//! The two types are **not** interchangeable at end of file, and that is the
//! whole difficulty of the port. Measured 2026-08-20 and recorded in
//! [`super::dgram_probe`]: on Linux 6.8 a closed peer on a connected
//! `SOCK_DGRAM` pair produces no signal whatsoever, leaving `revents` empty and
//! `recv` returning `EAGAIN`, which is exactly what an idle socket with a live
//! peer does. Darwin does report the close. So the socket type is chosen per
//! platform and the close rule below accepts either signal rather than assuming
//! the one this kernel happens to use.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;
use tokio::io::unix::AsyncFd;

/// What one receive attempt produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Received {
    /// A datagram of this many bytes. Zero is a legitimate value: a client may
    /// send an empty datagram, and that is not the same as closing.
    Datagram(usize),
    /// The peer closed its half of the pair.
    Eof,
}

/// The socket type a flow's descriptor uses on this platform.
///
/// `SOCK_SEQPACKET` where `AF_UNIX` genuinely implements it as an atomic-record
/// socket, `SOCK_DGRAM` where it does not. macOS has no `AF_UNIX`
/// `SOCK_SEQPACKET`; FreeBSD has the name without the record semantics. On both
/// the replacement is `SOCK_DGRAM`, which keeps message boundaries and delivers
/// a zero-length message, and those two are the properties the API's contract
/// with its clients rests on. See the module header for what changes with it and
/// what does not, and [`super::dgram_probe`] for the measurements.
///
/// The list is by exclusion rather than by inclusion so that a new unix target
/// gets Linux's arm, which is the one that fails loudly: a kernel without
/// `AF_UNIX` `SOCK_SEQPACKET` refuses the `socketpair` outright rather than
/// returning something that silently loses messages.
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
const SOCK_TYPE: libc::c_int = libc::SOCK_SEQPACKET;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const SOCK_TYPE: libc::c_int = libc::SOCK_DGRAM;

/// Create a connected socket pair of this platform's [`SOCK_TYPE`].
///
/// Both descriptors are close-on-exec so neither leaks into a child process.
/// Linux and FreeBSD take `SOCK_CLOEXEC` in `socketpair`'s type argument and
/// set it atomically; **macOS rejects it there**, so Darwin sets `FD_CLOEXEC`
/// with `fcntl` afterwards instead. The Darwin path has a window between the
/// two calls in which a concurrent `fork` and `exec` would inherit the
/// descriptors. It is accepted rather than closed because the alternative needs
/// a lock this module has no business holding, and the daemon spawns no child
/// on this path.
///
/// Neither descriptor is set non-blocking here: the two halves are independent
/// sockets, so [`Seqpacket::new`] can make the daemon's half non-blocking for
/// the reactor while the half handed to the client stays blocking, which is
/// what a client calling `recv` in a loop expects.
pub fn pair() -> io::Result<(OwnedFd, OwnedFd)> {
    #[cfg(not(target_os = "macos"))]
    let sock_type = SOCK_TYPE | libc::SOCK_CLOEXEC;
    #[cfg(target_os = "macos")]
    let sock_type = SOCK_TYPE;

    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a two-element array of the type socketpair writes, and
    // the return value is checked before either descriptor is read.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, sock_type, 0, fds.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair reported success, so both entries are open
    // descriptors this process now owns. Wrapping them before any further
    // syscall means an error below closes them rather than leaking them.
    let pair = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    #[cfg(target_os = "macos")]
    {
        set_cloexec(pair.0.as_raw_fd())?;
        set_cloexec(pair.1.as_raw_fd())?;
    }

    Ok(pair)
}

/// Mark `fd` close-on-exec, for the platform that will not do it atomically.
///
/// Read-modify-write rather than a bare set, so that any other flag the
/// descriptor carries survives. Used both here, where `socketpair` refuses
/// `SOCK_CLOEXEC`, and by [`super::fdpass`], where `recvmsg` has no
/// `MSG_CMSG_CLOEXEC` to pass.
#[cfg(target_os = "macos")]
pub(super) fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: the descriptor is open for the call.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the descriptor is open and the flag word is the one just read.
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Size the send buffer of `fd`, in bytes.
///
/// Used on the daemon's half of a listener's pair, where the buffer is the only
/// bound on arrivals a client has stopped reading. `SO_SNDBUF` on an `AF_UNIX`
/// socket accounts bytes plus per-message overhead rather than messages, so a
/// caller converting a message count to bytes is approximating and should
/// approximate generously. Linux doubles what it is given and clamps to its own
/// minimum, which is why nothing here reads the value back and asserts on it.
pub fn set_sndbuf(fd: &OwnedFd, bytes: usize) -> io::Result<()> {
    let size = libc::c_int::try_from(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "send buffer size too large"))?;
    // SAFETY: the descriptor is open for the call, and the pointer and length
    // describe one `c_int` that outlives it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            std::ptr::addr_of!(size).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// How long a receive waits on the reactor before retrying the syscall, on a
/// platform whose reactor cannot see a closed `SOCK_DGRAM` peer.
///
/// This is a detection latency, not a poll interval for data: an arriving
/// datagram does wake the reactor normally, so ordinary traffic is unaffected
/// and this bound is only reached on an idle flow. What it bounds is how long a
/// closed flow keeps its port and its registry entry before the daemon notices.
///
/// A quarter second is chosen against the cost, which is one timer per idle
/// flow and listener. Shortening it buys a faster reclaim of something nothing
/// is waiting on; lengthening it holds a dead flow's port longer.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const CLOSE_RETRY: Duration = Duration::from_millis(250);

/// The daemon's half of a flow's or a listener's socket pair, registered with
/// the reactor.
pub struct Seqpacket {
    inner: AsyncFd<OwnedFd>,
}

impl Seqpacket {
    /// Put `fd` under the reactor, making it non-blocking first.
    ///
    /// `AsyncFd` requires a non-blocking descriptor: a blocking one would stall
    /// the whole runtime thread inside a syscall the reactor believed would
    /// return at once.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        set_nonblocking(fd.as_raw_fd(), true)?;
        Ok(Self {
            inner: AsyncFd::new(fd)?,
        })
    }

    /// The raw descriptor, for a caller that must perform its own syscall.
    ///
    /// The one such caller is the listener's task, which needs a send that
    /// reports a full buffer rather than waiting for one; see
    /// [`try_send`](super::fdpass::try_send). Everything else goes through
    /// [`Seqpacket::send`] and [`Seqpacket::recv`].
    pub(super) fn raw(&self) -> RawFd {
        self.inner.get_ref().as_raw_fd()
    }

    /// Receive one datagram, or report that the peer closed.
    ///
    /// A datagram longer than `buf` is truncated and the remainder discarded,
    /// which is `SOCK_SEQPACKET` behaviour. Callers size `buf` at the largest
    /// payload the API accepts, so a truncation means the client exceeded it.
    pub async fn recv(&self, buf: &mut [u8]) -> io::Result<Received> {
        loop {
            // **A read before the wait, because on one platform the reactor
            // cannot see a close.** Darwin's `unp_disconnect` takes a different
            // branch for `SOCK_DGRAM` than for `SOCK_STREAM`: it clears
            // `SS_ISCONNECTED` and latches `so_error`, and calls none of
            // `sorwakeup`, `socantrcvmore` or `soisdisconnected`. So a closed
            // peer wakes no knote. The registration is edge-triggered and was
            // made while the socket was healthy, so waiting first would park
            // for ever on exactly the event this call exists to report. The
            // latched error is visible to a syscall, and only to a syscall.
            //
            // On Linux this attempt costs one `recv` returning `EAGAIN` before
            // the wait, and changes nothing else.
            match recv_once(self.raw(), buf) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                other => return other,
            }

            // **The wait is bounded where the close raises no event**, so a peer
            // that goes away while this task is parked is noticed on the next
            // attempt rather than never. `so_error` is latched until a read
            // consumes it, so the bound sets detection latency and cannot lose
            // the event. Everywhere else the readiness is authoritative and the
            // wait stays unbounded.
            #[cfg(any(target_os = "macos", target_os = "freebsd"))]
            let mut guard = match tokio::time::timeout(CLOSE_RETRY, self.inner.readable()).await {
                Ok(ready) => ready?,
                // The bound expired. The loop retries the syscall, which is the
                // only thing that can see this platform's close.
                Err(_elapsed) => continue,
            };
            #[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
            let mut guard = self.inner.readable().await?;
            let attempt = guard.try_io(|inner| recv_once(inner.get_ref().as_raw_fd(), buf));
            match attempt {
                Ok(result) => return result,
                // The reactor said readable and the syscall disagreed. Clear
                // the readiness and wait again rather than reporting an error.
                Err(_would_block) => continue,
            }
        }
    }

    /// Send one datagram.
    ///
    /// `SOCK_SEQPACKET` delivers it whole or not at all, so a short write is
    /// not a case the caller has to handle.
    pub async fn send(&self, buf: &[u8]) -> io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            let attempt = guard.try_io(|inner| {
                // SAFETY: the descriptor is owned and open, and the pointer and
                // length describe `buf`.
                let n = unsafe {
                    libc::send(
                        inner.get_ref().as_raw_fd(),
                        buf.as_ptr().cast(),
                        buf.len(),
                        libc::MSG_NOSIGNAL,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match attempt {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

/// One receive, distinguishing an empty datagram from end of file.
///
/// Both produce a zero-byte read, so something else has to tell them apart.
/// `MSG_EOR` is the technique the manual pages suggest and it **does not work
/// here**: measured on Linux 6.8, `recvmsg` on an `AF_UNIX` `SOCK_SEQPACKET`
/// socket returns `msg_flags == 0` for a normal message, for an empty message
/// and at end of file alike, so the flag carries no information.
///
/// `POLLHUP` narrows the question and does not answer it, measured the same
/// way. A live peer never sets it, so a zero-byte read without it is an empty
/// datagram and nothing else. A closed peer does set it, **and it latches while
/// messages are still queued**: a socket holding one empty datagram from a peer
/// that has since closed reports what a drained socket reports, in `revents`,
/// in `FIONREAD`, under `MSG_PEEK` and in the `recvmsg` return alike.
///
/// So the hang-up is one of two conditions rather than the whole rule. The other
/// is [`bytes_queued`], which catches the case that costs a real payload: an
/// empty datagram with a further message behind it, read after the peer closed.
/// Without it that read reports end of file, the caller frees the flow, and the
/// message behind it is never taken.
///
/// This matters because reading an empty datagram as a close would let a client
/// tear down its own flow by sending nothing, and the defect would present as a
/// spurious disconnect.
///
/// **One case survives and cannot be fixed here.** A zero-length datagram that
/// is the last message before a close is indistinguishable from the close:
/// reading it drains the queue, and every observation then matches a bare end of
/// file. Separating those needs a payload that is never zero bytes on the wire,
/// which is a protocol change rather than a receive-path one.
///
/// **`ECONNRESET` is treated as end of file too**, for the platform whose
/// datagram sockets report a close that way rather than through `POLLHUP`. Both
/// arms are compiled everywhere rather than split by `cfg`, because a rule that
/// accepts either signal is correct on both kernels and a rule that assumes one
/// would be silently wrong on the other. `EAGAIN` is deliberately not in that
/// company: it means the socket is empty and the peer is alive, so it stays an
/// error and the caller waits for readiness again.
fn recv_once(fd: RawFd, buf: &mut [u8]) -> io::Result<Received> {
    // SAFETY: the descriptor is open and the pointer and length describe `buf`.
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    if n < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ECONNRESET) {
            return Ok(Received::Eof);
        }
        return Err(err);
    }
    if n == 0 && peer_hung_up(fd) && bytes_queued(fd) == 0 {
        return Ok(Received::Eof);
    }
    Ok(Received::Datagram(n as usize))
}

/// Bytes the receive queue still holds.
///
/// Only one direction of this is sound, and the rule that uses it depends on
/// that asymmetry. **A non-zero answer proves a further message is waiting**, so
/// whatever was just read was a datagram and not the close. A zero answer proves
/// nothing: a zero-length datagram contributes no bytes, so a queue holding one
/// is indistinguishable from a drained queue by this measure or any other.
///
/// The one-directional reading is what makes this safe on every platform the
/// module compiles for, whatever socket type it chose and however its kernel
/// signals a close. Bytes queued means the peer's data has not been consumed
/// yet, and that cannot be end of file anywhere.
///
/// A failed `ioctl` reports zero, which leaves the caller with the rule that
/// applied before this check existed rather than with an error on a path that
/// has no way to report one.
///
/// Visible within [`super`] for the same reason [`peer_hung_up`] is: the
/// end-of-file rule belongs to the pair, not to the end that reads it, and the
/// client half at [`super::client::FipsStream::recv`] has to reach the same
/// verdict on the same socket. One implementation is what stops the two halves
/// drifting, which they had already done once.
pub(super) fn bytes_queued(fd: RawFd) -> usize {
    let mut queued: libc::c_int = 0;
    // SAFETY: the descriptor is open and `queued` is a live `c_int`, which is
    // what `FIONREAD` writes through the pointer.
    let rc = unsafe { libc::ioctl(fd, libc::FIONREAD as _, &mut queued) };
    if rc < 0 || queued < 0 {
        return 0;
    }
    queued as usize
}

/// Translate a platform's spelling of "the peer is gone" into this API's.
///
/// Darwin reports a closed `SOCK_DGRAM` peer as `ECONNRESET`, on the read path
/// and the write path alike, where Linux `SOCK_SEQPACKET` reports `EPIPE` on a
/// write and a zero-byte read plus `POLLHUP` on a read. The client's contract
/// names `EPIPE` for that condition and says so in its documentation, so the
/// difference is translated once here rather than at each call site. Every
/// other errno passes through untouched, because only this one condition has
/// two spellings.
pub(super) fn peer_gone_as_epipe(error: io::Error) -> io::Error {
    if error.raw_os_error() == Some(libc::ECONNRESET) {
        return io::Error::from_raw_os_error(libc::EPIPE);
    }
    error
}

/// Whether the peer has closed its half of the pair.
///
/// `POLLIN` is requested even though only `POLLHUP` is read. `POLLHUP` is
/// reported in `revents` whether or not it was asked for, which holds on Linux
/// and was measured there; **an empty `events` is not enough on Darwin**, where
/// a poll that requests nothing registers no filter and returns 0 with an empty
/// `revents` for a peer that has in fact closed. That was measured too, in
/// [`super::dgram_probe`], and asking for `POLLIN` costs nothing on either
/// platform because the result is masked to `POLLHUP` regardless.
///
/// This function is not what detects a close on Darwin: `ECONNRESET` arrives
/// first and both callers act on it before reaching the zero-byte path. It is
/// corrected so that it answers truthfully wherever it is called from, rather
/// than being left as a function whose contract holds on one platform.
/// The poll does not block, and runs only on the zero-byte path.
///
/// Visible within [`super`] because the client half needs the same
/// discrimination on the same socket pair: the rule belongs to the pair, not to
/// the end that reads it.
pub(super) fn peer_hung_up(fd: RawFd) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `poll` points at one live pollfd and the call cannot block.
    let rc = unsafe { libc::poll(&mut poll, 1, 0) };
    rc > 0 && (poll.revents & libc::POLLHUP) != 0
}

/// Size the receive buffer of `fd`, in bytes.
///
/// The counterpart to [`set_sndbuf`], and needed because the two kernels charge
/// a queued `AF_UNIX` message to different ends: Linux to the sender's
/// `SO_SNDBUF`, BSD to the receiver's `so_rcv`. Sizing only one leaves the
/// queue bounded by a system default on the other platform. As with the send
/// buffer, the value is not read back and asserted, because a kernel is free to
/// double it or clamp it to its own minimum.
pub(super) fn set_rcvbuf(fd: &OwnedFd, bytes: usize) -> io::Result<()> {
    let size = libc::c_int::try_from(bytes).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "receive buffer size too large")
    })?;
    // SAFETY: the descriptor is open for the call, and the pointer and length
    // describe one `c_int` that outlives it.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            std::ptr::addr_of!(size).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set or clear a receive or send timeout on a socket.
///
/// `option` is `SO_RCVTIMEO` or `SO_SNDTIMEO`. `None` clears the timeout, which
/// the kernel spells as a zero `timeval`.
///
/// A zero duration is refused with `EINVAL` rather than passed through, because
/// the kernel reads a zero `timeval` as "no timeout" and a caller asking for
/// zero means the opposite. `std::net` makes the same refusal for the same
/// reason, and silently inverting the request would be worse than failing it.
pub(super) fn set_timeout(fd: RawFd, option: libc::c_int, dur: Option<Duration>) -> io::Result<()> {
    let timeout = match dur {
        Some(d) if d == Duration::ZERO => {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // Saturating rather than wrapping: a duration past `time_t` becomes the
        // longest wait the kernel can express, which is the caller's intent.
        //
        // `tv_usec` is cast rather than converted because `suseconds_t` is
        // `i64` on Linux and `i32` on Darwin. `From` does not exist for the
        // Darwin width and `try_from` is a clippy error on the Linux one, so a
        // cast is the only form that compiles on both. It cannot truncate:
        // `subsec_micros` is below 1_000_000 by construction and fits either.
        Some(d) => libc::timeval {
            tv_sec: d.as_secs().min(libc::time_t::MAX as u64) as libc::time_t,
            tv_usec: d.subsec_micros() as libc::suseconds_t,
        },
        None => libc::timeval {
            tv_sec: 0,
            tv_usec: 0,
        },
    };
    // SAFETY: the descriptor is open, and the pointer and length describe a
    // `timeval` this frame owns.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_ref(&timeout).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Read back a receive or send timeout, or `None` when none is set.
pub(super) fn timeout(fd: RawFd, option: libc::c_int) -> io::Result<Option<Duration>> {
    let mut timeout = libc::timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let mut len = size_of::<libc::timeval>() as libc::socklen_t;
    // SAFETY: the descriptor is open, and both pointers describe values this
    // frame owns and keeps alive across the call.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut timeout).cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    if timeout.tv_sec == 0 && timeout.tv_usec == 0 {
        return Ok(None);
    }
    Ok(Some(
        Duration::from_secs(timeout.tv_sec as u64) + Duration::from_micros(timeout.tv_usec as u64),
    ))
}

/// Set or clear a descriptor's non-blocking mode, preserving its other flags.
///
/// Read-modify-write rather than a bare `F_SETFL`, because the flag word also
/// carries the access mode and `O_APPEND`, and writing `O_NONBLOCK` alone would
/// drop them.
pub(super) fn set_nonblocking(fd: RawFd, nonblocking: bool) -> io::Result<()> {
    // SAFETY: the descriptor is open for the duration of both calls.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let wanted = if nonblocking {
        flags | libc::O_NONBLOCK
    } else {
        flags & !libc::O_NONBLOCK
    };
    // SAFETY: as above; `wanted` is the value just read back, one bit changed.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, wanted) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream as StdUnixStream;

    /// Turn the client half into something a blocking test can drive, the way a
    /// client process would after receiving it.
    fn client(fd: OwnedFd) -> StdUnixStream {
        StdUnixStream::from(fd)
    }

    /// One receive, bounded in time.
    ///
    /// Every assertion in this module is about something arriving on the
    /// descriptor, and the failure mode of each is that it never does. An
    /// unbounded await against that defect parks for ever: the suite wedges
    /// with no named failure and no diagnostic, and a hang is not a red. This
    /// matters more since the socket type became platform-dependent, because a
    /// kernel that does not report a close makes the end-of-file test the one
    /// that hangs, and it would hang on a runner rather than here.
    async fn recv_bounded(sock: &Seqpacket, buf: &mut [u8]) -> Received {
        tokio::time::timeout(Duration::from_secs(5), sock.recv(buf))
            .await
            .expect("nothing arrived on the descriptor within 5s: it is still waiting")
            .expect("recv failed")
    }

    #[tokio::test]
    async fn message_boundaries_survive_in_both_directions() {
        let (daemon, theirs) = pair().unwrap();
        let daemon = Seqpacket::new(daemon).unwrap();
        let mut theirs = client(theirs);

        // Three writes must arrive as three datagrams, not one run of bytes.
        // This is the property SOCK_STREAM would lose.
        theirs.write_all(b"one").unwrap();
        theirs.write_all(b"two").unwrap();
        theirs.write_all(b"three").unwrap();

        let mut buf = [0u8; 64];
        assert_eq!(recv_bounded(&daemon, &mut buf).await, Received::Datagram(3));
        assert_eq!(&buf[..3], b"one");
        assert_eq!(recv_bounded(&daemon, &mut buf).await, Received::Datagram(3));
        assert_eq!(&buf[..3], b"two");
        assert_eq!(recv_bounded(&daemon, &mut buf).await, Received::Datagram(5));
        assert_eq!(&buf[..5], b"three");

        daemon.send(b"alpha").await.unwrap();
        daemon.send(b"beta").await.unwrap();
        let mut got = [0u8; 64];
        assert_eq!(theirs.read(&mut got).unwrap(), 5);
        assert_eq!(&got[..5], b"alpha");
        assert_eq!(theirs.read(&mut got).unwrap(), 4);
        assert_eq!(&got[..4], b"beta");
    }

    #[tokio::test]
    async fn closing_the_client_half_reports_end_of_file() {
        let (daemon, theirs) = pair().unwrap();
        let daemon = Seqpacket::new(daemon).unwrap();
        drop(client(theirs));

        let mut buf = [0u8; 64];
        assert_eq!(recv_bounded(&daemon, &mut buf).await, Received::Eof);
    }

    #[tokio::test]
    async fn an_empty_datagram_is_not_end_of_file() {
        // The whole reason recv_once uses recvmsg. If an empty datagram read as
        // a close, a client could tear down its own flow by sending nothing,
        // and the bug would look like a spurious disconnect.
        let (daemon, theirs) = pair().unwrap();
        let daemon = Seqpacket::new(daemon).unwrap();
        let mut theirs = client(theirs);

        // `write_all(b"")` is a no-op in Rust and never reaches the socket, so
        // the zero-length datagram has to be sent with `send` directly. The
        // first version of this test used `write_all` and asserted a behaviour
        // it had not exercised.
        // SAFETY: the descriptor is open and owned by `theirs`.
        let sent = unsafe { libc::send(theirs.as_raw_fd(), std::ptr::null(), 0, 0) };
        assert_eq!(sent, 0, "{}", io::Error::last_os_error());
        theirs.write_all(b"after").unwrap();

        let mut buf = [0u8; 64];
        assert_eq!(recv_bounded(&daemon, &mut buf).await, Received::Datagram(0));
        assert_eq!(recv_bounded(&daemon, &mut buf).await, Received::Datagram(5));
    }

    #[tokio::test]
    async fn an_empty_datagram_before_a_close_does_not_swallow_the_message_behind_it() {
        // The case the test above does not reach. It keeps the client half open,
        // so `POLLHUP` is never set and the end-of-file rule is never consulted.
        // Here the client closes, which latches `POLLHUP` while both messages
        // are still queued. Reading `POLLHUP` alone then reports the empty
        // datagram as the close, `drain` frees the flow, and `after` is
        // discarded without ever being read.
        let (daemon, theirs) = pair().unwrap();
        let daemon = Seqpacket::new(daemon).unwrap();
        let mut theirs = client(theirs);

        // SAFETY: the descriptor is open and owned by `theirs`.
        let sent = unsafe { libc::send(theirs.as_raw_fd(), std::ptr::null(), 0, 0) };
        assert_eq!(sent, 0, "{}", io::Error::last_os_error());
        theirs.write_all(b"after").unwrap();
        drop(theirs);

        let mut buf = [0u8; 64];
        assert_eq!(
            recv_bounded(&daemon, &mut buf).await,
            Received::Datagram(0),
            "the empty datagram was reported as the close"
        );
        assert_eq!(
            recv_bounded(&daemon, &mut buf).await,
            Received::Datagram(5),
            "the message queued behind the empty datagram was lost"
        );
        assert_eq!(&buf[..5], b"after");
        assert_eq!(recv_bounded(&daemon, &mut buf).await, Received::Eof);
    }

    #[test]
    fn both_halves_of_a_pair_are_close_on_exec() {
        // Asserted rather than assumed because the platforms disagree on how it
        // is set: Linux and FreeBSD get it atomically from socketpair's type
        // argument, macOS rejects it there and has to use a second fcntl. A
        // missing flag leaks both descriptors into any child the daemon spawns,
        // which is silent, so nothing else would report it.
        let (daemon, theirs) = pair().unwrap();
        for (label, fd) in [
            ("daemon", daemon.as_raw_fd()),
            ("client", theirs.as_raw_fd()),
        ] {
            // SAFETY: the descriptor is open and owned by this frame.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0, "{label} half: F_GETFD failed");
            assert_eq!(
                flags & libc::FD_CLOEXEC,
                libc::FD_CLOEXEC,
                "{label} half of the pair is not close-on-exec"
            );
        }
    }

    #[tokio::test]
    async fn the_client_half_is_left_blocking() {
        // The daemon's half is made non-blocking for the reactor. If that flag
        // reached the client's half, a client doing an ordinary blocking recv
        // would get EAGAIN instead of waiting, which is a trap worth a test
        // rather than a comment.
        let (daemon, theirs) = pair().unwrap();
        let _daemon = Seqpacket::new(daemon).unwrap();

        // SAFETY: the descriptor is open and owned by `theirs`.
        let flags = unsafe { libc::fcntl(theirs.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::O_NONBLOCK, 0);
    }
}
