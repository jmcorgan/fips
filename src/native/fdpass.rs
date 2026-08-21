//! Write a reply on the client connection, optionally carrying a descriptor.
//!
//! Passing a file descriptor between processes is `sendmsg` with an `SCM_RIGHTS`
//! control message, which neither std nor tokio exposes. The descriptor travels
//! in the ancillary data of the same `sendmsg` that carries the reply line, so a
//! client reads one message and gets both, with no window in which it holds one
//! without the other.
//!
//! Every write goes through `try_io`, including the ones with no descriptor, so
//! the connection's `UnixStream` is only ever borrowed shared. That is what lets
//! the reader keep the stream inside a `BufReader` while replies are written
//! through `get_ref`.
//!
//! The receiving half lives here too, in `recv`. It is blocking and uses no
//! tokio, because a client process is what runs it, but it is the same concern
//! read backwards and it needs the same control message sizing.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use tokio::io::Interest;
use tokio::net::UnixStream;

/// Space for the control message, sized at runtime and checked against this.
///
/// `CMSG_SPACE(4)` is 24 bytes on Linux and 16 on Darwin, whose `cmsghdr` is
/// 12 bytes and whose alignment is 4 rather than 8. The array is `u64` so it
/// carries the alignment `cmsghdr` requires, and at 64 bytes is larger than
/// either, so a platform with a wider header is caught by the assertion rather
/// than by memory corruption. Nothing computes from the number: the send path
/// checks the runtime `CMSG_SPACE` against this buffer's size and the receive
/// path offers the whole buffer.
type CmsgBuf = [u64; 8];

/// `recvmsg` flags that make a received descriptor close-on-exec.
///
/// Linux and FreeBSD do it atomically with `MSG_CMSG_CLOEXEC`, which is the
/// only way to be certain no `fork` in another thread wins the race. macOS has
/// no equivalent flag, so there is nothing to pass and [`recv`] sets
/// `FD_CLOEXEC` on each descriptor afterwards instead.
#[cfg(not(target_os = "macos"))]
const RECV_FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
#[cfg(target_os = "macos")]
const RECV_FLAGS: libc::c_int = 0;

/// Send `line` on `stream`, with `fd` in the ancillary data when given.
///
/// The whole reply goes in one datagram-shaped `sendmsg`. A short write is
/// treated as an error rather than retried: the replies are a few hundred bytes
/// into an empty socket buffer, so a partial one means something is wrong that a
/// retry loop would hide.
pub async fn reply(stream: &UnixStream, line: &[u8], fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
    loop {
        stream.writable().await?;
        match stream.try_io(Interest::WRITABLE, || {
            send_once(stream.as_raw_fd(), line, fd)
        }) {
            Ok(written) if written == line.len() => return Ok(()),
            Ok(written) => {
                return Err(io::Error::other(format!(
                    "native API reply truncated: wrote {written} of {}",
                    line.len()
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
    }
}

/// One `sendmsg` that reports a full send buffer instead of waiting for one.
///
/// The listener's task writes onto socket pairs whose client half it has not
/// handed over yet, so no process can read either one and a task that waited
/// would stop serving that listener for good. [`Seqpacket::send`] is the wrong
/// tool for exactly that reason: it treats a would-block as a reason to await
/// readiness rather than as an answer. This is the raw syscall on a descriptor
/// the reactor has already made non-blocking, so a full buffer comes back as
/// `WouldBlock` and the caller decides.
///
/// [`Seqpacket::send`]: super::seqpacket::Seqpacket::send
pub(super) fn try_send(sock: RawFd, line: &[u8], fd: Option<BorrowedFd<'_>>) -> io::Result<usize> {
    send_once(sock, line, fd)
}

/// One `sendmsg`, with or without an `SCM_RIGHTS` control message.
///
/// Visible within [`super`] so the client's tests can play daemon through the
/// real ancillary framing rather than an imitation of it.
pub(super) fn send_once(sock: i32, line: &[u8], fd: Option<BorrowedFd<'_>>) -> io::Result<usize> {
    let mut iov = libc::iovec {
        iov_base: line.as_ptr() as *mut libc::c_void,
        iov_len: line.len(),
    };
    // SAFETY: msghdr is a plain C struct with no invalid bit patterns; every
    // field this call reads is set below.
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;

    let mut control: CmsgBuf = [0; 8];
    if let Some(fd) = fd {
        // SAFETY: CMSG_SPACE is a pure size computation over its argument.
        let space = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::c_int>() as u32) } as usize;
        if space > mem::size_of::<CmsgBuf>() {
            return Err(io::Error::other(
                "control message buffer too small for a descriptor",
            ));
        }

        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = space as _;

        // SAFETY: msg_control points at `control`, which is aligned for
        // cmsghdr and at least `space` bytes long, so the header the kernel
        // macro returns lies inside it.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&msg);
            if header.is_null() {
                return Err(io::Error::other("control message header unavailable"));
            }
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(mem::size_of::<libc::c_int>() as u32) as _;
            let raw = fd.as_raw_fd();
            std::ptr::copy_nonoverlapping(
                std::ptr::addr_of!(raw).cast::<u8>(),
                libc::CMSG_DATA(header),
                mem::size_of::<libc::c_int>(),
            );
        }
    }

    // SAFETY: `sock` is the connection's open descriptor, and `msg` describes
    // buffers that outlive this call.
    let sent = unsafe { libc::sendmsg(sock, &msg, libc::MSG_NOSIGNAL) };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sent as usize)
}

/// What one `recvmsg` on a client's RPC connection produced.
///
/// The bytes and the descriptor are reported together because they arrive
/// together. Handing them back separately would reopen the window this module
/// exists to close.
///
/// Visible within [`super`] only, like [`send_once`]: the client module is the
/// one caller, and the API this crate publishes is `FipsAddr`, `FipsStream` and
/// `FipsListener` rather than the framing underneath them.
#[derive(Debug)]
pub(super) struct Chunk {
    /// How many bytes landed in the caller's buffer. Zero is end of file.
    pub(super) len: usize,
    /// The descriptor the message carried, where it carried one.
    pub(super) fd: Option<OwnedFd>,
}

/// Receive one message into `buf`, keeping any descriptor that came with it.
///
/// Blocking and `libc`-only, with no tokio: this is the half a client process
/// runs. It lives beside [`reply`] because the two share the control message
/// sizing and the same safety argument.
///
/// **Every read on the RPC connection must come through here.** A plain `read`
/// consumes a descriptor-bearing message's bytes with no ancillary buffer, and
/// the kernel closes the descriptor rather than queueing it, so the reply looks
/// right and the flow is silently gone.
///
/// A received descriptor is kept out of a child the client forks later, by
/// [`RECV_FLAGS`] where the platform has a flag for it and by an `fcntl` on
/// each descriptor where it does not. `EINTR` is retried, because a signal
/// delivered during the wait says nothing about the connection.
pub(super) fn recv(sock: RawFd, buf: &mut [u8]) -> io::Result<Chunk> {
    loop {
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control: CmsgBuf = [0; 8];
        // SAFETY: as in send_once; every field this call reads is set below.
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = mem::size_of::<CmsgBuf>() as _;

        // SAFETY: `sock` is the caller's open socket, and `msg` describes
        // buffers that outlive the call.
        let received = unsafe { libc::recvmsg(sock, &mut msg, RECV_FLAGS) };
        if received < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            // A listener's descriptor is a socket pair half, and Darwin reports
            // its closed peer as ECONNRESET where Linux returns a zero-byte
            // message. They are the same event, so it is reported as the empty
            // chunk every caller here already reads as the far end going away.
            // Doing it here rather than in each caller keeps `accept`'s
            // documented EPIPE true on both platforms.
            if error.raw_os_error() == Some(libc::ECONNRESET) {
                return Ok(Chunk { len: 0, fd: None });
            }
            return Err(error);
        }

        // SAFETY: recvmsg succeeded, so it filled `msg_control` within
        // `msg_controllen`, and `control` is still alive.
        let mut fds = unsafe { take_fds(&msg) };

        // Darwin has no `MSG_CMSG_CLOEXEC`, so the flag is set here instead.
        // Later than the atomic form and with the same window `seqpacket::pair`
        // documents: a concurrent `fork` and `exec` in these few instructions
        // would inherit the descriptor. A failure to set it is reported rather
        // than ignored, because the descriptor is live either way and the
        // caller must not be told the receive was clean.
        #[cfg(target_os = "macos")]
        for fd in &fds {
            super::seqpacket::set_cloexec(fd.as_raw_fd())?;
        }

        // Whatever did arrive is taken before the truncation check, so nothing
        // leaks on that path: dropping an `OwnedFd` closes it. The connection
        // cannot continue either way, because a descriptor the kernel dropped
        // is one no later read can recover.
        if (msg.msg_flags & libc::MSG_CTRUNC) != 0 {
            return Err(io::Error::other(
                "native API control message truncated: a descriptor was lost",
            ));
        }

        // More than one descriptor is not something this protocol sends. The
        // extras are dropped, and so closed, rather than leaked.
        let fd = if fds.is_empty() {
            None
        } else {
            Some(fds.swap_remove(0))
        };

        return Ok(Chunk {
            len: received as usize,
            fd,
        });
    }
}

/// Collect every descriptor an `SCM_RIGHTS` control message carried.
///
/// The whole control buffer is walked rather than only its first header: a
/// reader that took `CMSG_FIRSTHDR` alone would leak any descriptor behind it.
///
/// # Safety
///
/// `msg` must be a `msghdr` that a successful `recvmsg` filled in, whose
/// `msg_control` buffer is still live and unmodified since.
unsafe fn take_fds(msg: &libc::msghdr) -> Vec<OwnedFd> {
    let mut fds = Vec::new();
    // SAFETY: the caller guarantees `msg` came from a successful recvmsg, so
    // every header these macros return lies inside its control buffer, and
    // every descriptor named there is one this process now owns.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(msg);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let payload = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                for index in 0..payload / mem::size_of::<libc::c_int>() {
                    let mut raw: libc::c_int = 0;
                    std::ptr::copy_nonoverlapping(
                        libc::CMSG_DATA(header).add(index * mem::size_of::<libc::c_int>()),
                        std::ptr::addr_of_mut!(raw).cast::<u8>(),
                        mem::size_of::<libc::c_int>(),
                    );
                    fds.push(OwnedFd::from_raw_fd(raw));
                }
            }
            header = libc::CMSG_NXTHDR(msg, header);
        }
    }
    fds
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::seqpacket::{Received, Seqpacket, pair};
    use std::io::Write;
    use std::os::fd::AsFd;
    use std::os::unix::net::UnixStream as StdUnixStream;

    /// Receive one line plus an optional descriptor, the way a client does.
    ///
    /// Goes through [`recv`] rather than repeating its `recvmsg`, so these
    /// tests exercise the receiving half a client actually runs.
    fn recv_with_fd(sock: &StdUnixStream) -> (Vec<u8>, Option<OwnedFd>) {
        let mut buf = [0u8; 4096];
        let chunk = recv(sock.as_raw_fd(), &mut buf).expect("recvmsg should succeed");
        (buf[..chunk.len].to_vec(), chunk.fd)
    }

    #[tokio::test]
    async fn a_reply_without_a_descriptor_arrives_whole() {
        let (ours, theirs) = StdUnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let ours = UnixStream::from_std(ours).unwrap();

        reply(&ours, b"{\"status\":\"ok\"}\n", None).await.unwrap();

        let (line, fd) = recv_with_fd(&theirs);
        assert_eq!(line, b"{\"status\":\"ok\"}\n");
        assert!(fd.is_none());
    }

    #[tokio::test]
    async fn a_descriptor_arrives_with_its_reply_and_still_works() {
        let (ours, theirs) = StdUnixStream::pair().unwrap();
        ours.set_nonblocking(true).unwrap();
        let ours = UnixStream::from_std(ours).unwrap();

        let (daemon_half, client_half) = pair().unwrap();
        let daemon_half = Seqpacket::new(daemon_half).unwrap();

        reply(&ours, b"{\"status\":\"ok\"}\n", Some(client_half.as_fd()))
            .await
            .unwrap();
        // The daemon closes its copy once it is sent; the receiver holds the
        // only remaining reference to the client half.
        drop(client_half);

        let (line, fd) = recv_with_fd(&theirs);
        assert_eq!(line, b"{\"status\":\"ok\"}\n");
        let fd = fd.expect("a descriptor should have arrived");

        // The passed descriptor is a live half of the flow, not merely a
        // number: writing on it must reach the daemon's side.
        let mut received = StdUnixStream::from(fd);
        received.write_all(b"through the passed fd").unwrap();

        let mut buf = [0u8; 64];
        assert_eq!(
            daemon_half.recv(&mut buf).await.unwrap(),
            Received::Datagram(21)
        );
        assert_eq!(&buf[..21], b"through the passed fd");
    }
}
