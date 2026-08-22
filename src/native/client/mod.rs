//! A blocking client for the native datagram API, shaped like `std::net`.
//!
//! An external program links this crate and speaks the API through
//! [`FipsStream`] and [`FipsListener`] without knowing its line protocol. The
//! names, signatures and error type follow `TcpStream` and `TcpListener`,
//! because the descriptor the daemon hands back **is a real socket**: `send`,
//! `recv`, `poll`, `select`, `epoll`, `close` and `SO_RCVTIMEO` on it are the
//! genuine syscalls. Only setup is not, so setup is the part shaped to look
//! like Berkeley's.
//!
//! An address is an x-only secp256k1 public key and a port. The npub is that
//! key written down, and converting between the two is bech32 and nothing else:
//! no lookup, no resolution, no name service. The 16-byte node address on the
//! wire is a truncated hash of the key, it does not invert, and it appears
//! nowhere on this surface. [`ToFipsAddr`] is how one parameter takes every
//! spelling of the same address, exactly as `ToSocketAddrs` does.
//!
//! **A stream that outlives its connection is not representable, because the
//! connection is not an object.** [`FipsStream::connect`] opens an RPC
//! connection to the daemon socket, sends one command, receives the descriptor
//! and closes that connection. What it returns holds the descriptor and plain
//! copies of what the reply said, and no handle on anything else, which is what
//! a Berkeley setup call leaves behind. Both types are therefore `Send` and
//! `'static` with no `Arc` and no borrow.
//!
//! **The connection is read with `recvmsg` and never with a buffered reader.**
//! The daemon attaches a descriptor to the ancillary data of the same `sendmsg`
//! that carries the reply line, so a reader that consumed those bytes without a
//! control buffer would consume the descriptor into nothing. See [`Wire::fill`]
//! for the rule that decides which line a descriptor belongs to.

mod codec;

use super::{fdpass, seqpacket};
use codec::Opened;
use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

pub use secp256k1::XOnlyPublicKey;

/// Where a packaged daemon puts its native API socket.
///
/// The path-taking constructors exist for a program that is told where its
/// daemon is; everything else uses this, the way a Berkeley call needs no
/// argument to find the kernel.
///
/// **Platform-conditional, because the daemon's own default is.** The daemon
/// resolves its path at startup by looking for a directory rather than by
/// compiling a string, and macOS has no `/run` at all, so a client that
/// compiled the Linux path there would look somewhere that cannot exist. The
/// value here is the first branch of that resolver which applies to the
/// platform: `/run/fips` on Linux, `/var/run/fips` on macOS and FreeBSD, whose
/// packaged services create it.
///
/// A daemon that fell through to `$XDG_RUNTIME_DIR` or `/tmp`, which a
/// development run usually does, is not at this path on any platform. That is
/// what `connect_at` and `bind_at` are for, and it is why the resolver is
/// documented rather than hidden.
#[cfg(not(any(target_os = "macos", target_os = "freebsd")))]
pub const SOCKET: &str = "/run/fips/api.sock";
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub const SOCKET: &str = "/var/run/fips/api.sock";

/// Bytes taken from the RPC connection per `recvmsg`.
///
/// A reply is a few hundred bytes, so this holds several and the reader rarely
/// makes two syscalls for one line. The same size serves an arrival message,
/// which is smaller still.
const CHUNK: usize = 8192;

/// Largest partial line the client will hold before giving up on the daemon.
///
/// It bounds a daemon that stops sending newlines, which is the only way the
/// line buffer could grow without end. Well above any reply the daemon writes.
const MAX_LINE: usize = 65536;

/// How long a setup command waits for its answer.
///
/// Matches the control socket's per-connection timeout. **It is the only wait
/// on this surface**: a native `connect` is a local registration that contacts
/// no peer, so nothing else here can time out, and `ETIMEDOUT` has exactly this
/// one producer.
const SETUP: Duration = Duration::from_secs(5);

/// One end of a flow: an x-only public key and a port.
///
/// The Rust mirror of `struct sockaddr_fips`. [`Display`](fmt::Display) writes
/// `npub1…:4242` and [`FromStr`] reads it back; the colon is unambiguous
/// because bech32's character set does not contain one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FipsAddr {
    key: XOnlyPublicKey,
    port: u16,
}

impl FipsAddr {
    /// An address from a key and a port.
    pub fn new(key: XOnlyPublicKey, port: u16) -> Self {
        Self { key, port }
    }

    /// The public key. This is the address; nothing else identifies an end.
    pub fn key(&self) -> XOnlyPublicKey {
        self.key
    }

    /// The port.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl fmt::Display for FipsAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", codec::ntop(&self.key), self.port)
    }
}

impl FromStr for FipsAddr {
    type Err = io::Error;

    /// Read `npub1…:4242`, refusing anything else with `EINVAL`.
    fn from_str(text: &str) -> io::Result<Self> {
        let (npub, port) = text
            .rsplit_once(':')
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;
        let port: u16 = port
            .parse()
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        Ok(Self::new(codec::pton(npub)?, port))
    }
}

/// Every spelling of one address, behind one parameter.
///
/// Mirrors `std::net::ToSocketAddrs`. The implementations are the address in
/// binary ([`XOnlyPublicKey`] or 32 bytes), the address in text (an npub), and
/// the whole thing as one string.
pub trait ToFipsAddr {
    /// The address this value names, or `EINVAL` if it names none.
    fn to_fips_addr(&self) -> io::Result<FipsAddr>;
}

impl ToFipsAddr for FipsAddr {
    fn to_fips_addr(&self) -> io::Result<FipsAddr> {
        Ok(*self)
    }
}

impl ToFipsAddr for (XOnlyPublicKey, u16) {
    fn to_fips_addr(&self) -> io::Result<FipsAddr> {
        Ok(FipsAddr::new(self.0, self.1))
    }
}

impl ToFipsAddr for ([u8; 32], u16) {
    fn to_fips_addr(&self) -> io::Result<FipsAddr> {
        let key = XOnlyPublicKey::from_slice(&self.0)
            .map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?;
        Ok(FipsAddr::new(key, self.1))
    }
}

impl ToFipsAddr for (&str, u16) {
    fn to_fips_addr(&self) -> io::Result<FipsAddr> {
        Ok(FipsAddr::new(codec::pton(self.0)?, self.1))
    }
}

impl ToFipsAddr for (String, u16) {
    fn to_fips_addr(&self) -> io::Result<FipsAddr> {
        (self.0.as_str(), self.1).to_fips_addr()
    }
}

impl ToFipsAddr for str {
    fn to_fips_addr(&self) -> io::Result<FipsAddr> {
        self.parse()
    }
}

impl ToFipsAddr for String {
    fn to_fips_addr(&self) -> io::Result<FipsAddr> {
        self.as_str().to_fips_addr()
    }
}

impl<T: ToFipsAddr + ?Sized> ToFipsAddr for &T {
    fn to_fips_addr(&self) -> io::Result<FipsAddr> {
        (**self).to_fips_addr()
    }
}

/// The RPC connection's reader, and the write side beside it.
///
/// Holds its own line buffer over `recvmsg` because a buffered reader is not
/// usable here: see [`Wire::fill`]. It lives only for the length of one setup
/// call, and dropping it is what closes the connection.
#[derive(Debug)]
struct Wire {
    sock: UnixStream,
    /// Bytes read that do not yet form a complete line.
    partial: Vec<u8>,
    /// Complete lines, oldest first, each with the descriptor it arrived with.
    lines: VecDeque<(Vec<u8>, Option<OwnedFd>)>,
}

impl Wire {
    /// Open a connection to the daemon's socket, with the setup deadline on it.
    ///
    /// The deadline is `SO_RCVTIMEO`, so it bounds the wait for the answer
    /// rather than the whole call, which is what the contract's one `ETIMEDOUT`
    /// producer describes.
    fn open(path: &Path) -> io::Result<Self> {
        let sock = UnixStream::connect(path)?;
        sock.set_read_timeout(Some(SETUP))?;
        Ok(Self::new(sock))
    }

    /// A reader over an already connected socket.
    fn new(sock: UnixStream) -> Self {
        Self {
            sock,
            partial: Vec::new(),
            lines: VecDeque::new(),
        }
    }

    /// Send one command and read its answer, with any descriptor it carried.
    ///
    /// The RPC socket carries **replies only, in command order**, so the next
    /// complete line is the answer and there is nothing to queue.
    fn call(&mut self, request: Vec<u8>) -> io::Result<(serde_json::Value, Option<OwnedFd>)> {
        self.send(&request)?;
        let (line, fd) = self.line()?;
        Ok((codec::reply(&line)?, fd))
    }

    /// Write one command line.
    ///
    /// `libc::send` with `MSG_NOSIGNAL` rather than `write_all`, so a command
    /// written to a daemon that has gone away is an `EPIPE` error whatever the
    /// host program is. A Rust binary ignores `SIGPIPE` by default and would see
    /// the error anyway, but a C program that loads this crate would be killed
    /// instead. [`FipsStream::send`] makes the same choice for the same reason.
    fn send(&mut self, line: &[u8]) -> io::Result<()> {
        let mut rest = line;
        while !rest.is_empty() {
            // SAFETY: the socket is owned and open, and the pointer and length
            // describe `rest`.
            let sent = unsafe {
                libc::send(
                    self.sock.as_raw_fd(),
                    rest.as_ptr().cast(),
                    rest.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if sent == 0 {
                // A blocking stream socket does not do this with bytes left to
                // write. Reported rather than spun on.
                return Err(io::Error::other("the native API socket took no bytes"));
            }
            rest = &rest[sent as usize..];
        }
        Ok(())
    }

    /// Take the next complete line, reading until one is available.
    fn line(&mut self) -> io::Result<(Vec<u8>, Option<OwnedFd>)> {
        loop {
            if let Some(line) = self.lines.pop_front() {
                return Ok(line);
            }
            self.fill()?;
        }
    }

    /// One `recvmsg`, split into lines, with any descriptor placed by the
    /// association rule.
    ///
    /// **A descriptor belongs to the last complete line of the read that
    /// carried it, never to the next line the reader assembles.** Measured on
    /// Linux 6.8.0-117 with a C program rather than reasoned about: a `recvmsg`
    /// that returns ancillary data ends exactly at the end of the `sendmsg` that
    /// carried it, but it may begin with any amount of data written before it.
    /// So a line the daemon wrote earlier and a descriptor-bearing reply arrive
    /// as one read, and a reader that attached the descriptor to the next line
    /// it completed would hand a flow to the wrong one.
    ///
    /// Such a read never ends on a partial line, because the daemon writes
    /// exactly one whole line per `sendmsg` and treats a short write as an error
    /// rather than retrying. That is an invariant of these two programs rather
    /// than of the socket type, which is why a read carrying a descriptor and no
    /// complete line is reported instead of guessed at.
    fn fill(&mut self) -> io::Result<()> {
        let mut buf = [0u8; CHUNK];
        let chunk = fdpass::recv(self.sock.as_raw_fd(), &mut buf).map_err(expired)?;
        if chunk.len == 0 {
            // The daemon accepted the connection and then dropped it, which is
            // the socket not accepting by a slower route.
            return Err(io::Error::from_raw_os_error(libc::ECONNREFUSED));
        }
        self.partial.extend_from_slice(&buf[..chunk.len]);

        let mut produced = 0usize;
        while let Some(end) = self.partial.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = self.partial.drain(..=end).collect();
            line.pop();
            self.lines.push_back((line, None));
            produced += 1;
        }

        if self.partial.len() > MAX_LINE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} bytes with no newline", self.partial.len()),
            ));
        }

        if let Some(fd) = chunk.fd {
            if produced == 0 {
                // Dropping the descriptor closes it. Holding it would mean
                // guessing which later line it belongs to, which is the defect
                // this rule exists to prevent.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "a descriptor arrived on a read that completed no line",
                ));
            }
            self.lines
                .back_mut()
                .expect("a read that produced a line has one to attach to")
                .1 = Some(fd);
        }
        Ok(())
    }
}

/// Turn the setup deadline expiring into the errno the contract names.
///
/// `SO_RCVTIMEO` reports a would-block, which says nothing to a caller about
/// which wait ended. `ETIMEDOUT` is the row this is, and it is the only row
/// that produces it.
fn expired(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            io::Error::from_raw_os_error(libc::ETIMEDOUT)
        }
        _ => error,
    }
}

/// One datagram flow, and the descriptor it is carried on.
///
/// Five scalars and two keys, all fixed when the flow opened: a flow's key pair
/// and port pair cannot change while it is open, and `max_payload` is computed
/// once. There is nothing else to hold, which is what makes the type `Send` and
/// self-contained, so a server serving one thread per flow can move it there.
///
/// The protocol has no close command. Dropping the stream closes its
/// descriptor, and that is what releases the flow and its local port at the
/// daemon.
#[derive(Debug)]
pub struct FipsStream {
    fd: OwnedFd,
    peer: FipsAddr,
    local: FipsAddr,
    max: usize,
}

impl FipsStream {
    /// Open a flow to `addr`, from a port the daemon picks.
    ///
    /// **This contacts no peer.** It is a local registration, and nothing about
    /// it proves the peer exists, is reachable, or is listening. A
    /// Berkeley-shaped surface invites the opposite reading, so it is said here
    /// rather than left to a manual.
    pub fn connect<A: ToFipsAddr>(addr: A) -> io::Result<FipsStream> {
        Self::connect_at(Path::new(SOCKET), 0, addr)
    }

    /// Open a flow from a named local port, which a peer can be told in advance.
    ///
    /// `connect_from(0, addr)` means an ephemeral port, the same as
    /// [`FipsStream::connect`]. There is no other spelling of it.
    pub fn connect_from<A: ToFipsAddr>(local: u16, addr: A) -> io::Result<FipsStream> {
        Self::connect_at(Path::new(SOCKET), local, addr)
    }

    /// The same call, for a program that is told where its daemon's socket is.
    pub fn connect_at<A: ToFipsAddr>(sock: &Path, local: u16, addr: A) -> io::Result<FipsStream> {
        let addr = addr.to_fips_addr()?;
        Self::open(Wire::open(sock)?, local, addr)
    }

    /// Perform the `connect` exchange on an open connection, then close it.
    ///
    /// The connection is a local here on purpose: it is dropped before this
    /// returns, so what the caller holds cannot outlive it.
    fn open(mut wire: Wire, local: u16, addr: FipsAddr) -> io::Result<FipsStream> {
        let (data, fd) = wire.call(codec::connect(&addr.key, addr.port, local))?;
        let fd = fd.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a connect reply carried no descriptor",
            )
        })?;
        Ok(Self::wired(fd, codec::opened(&data)?))
    }

    /// A stream over a descriptor and the facts the daemon reported with it.
    fn wired(fd: OwnedFd, opened: Opened) -> FipsStream {
        FipsStream {
            fd,
            peer: FipsAddr::new(opened.peer, opened.remote),
            local: FipsAddr::new(opened.node, opened.local),
            max: opened.max,
        }
    }

    /// Send one datagram.
    ///
    /// No byte count: `SOCK_SEQPACKET` delivers a message whole or not at all,
    /// so there is no short write and no count worth checking. A count would
    /// give every `?`-using caller something it could ignore incorrectly, and
    /// no test would catch it because the count is always the full length.
    ///
    /// Above [`FipsStream::max_payload`] this is `EMSGSIZE` before the syscall,
    /// so a caller learns which datagram was too large instead of finding a gap
    /// at the far end. The limit itself is allowed.
    pub fn send(&self, buf: &[u8]) -> io::Result<()> {
        if buf.len() > self.max {
            return Err(io::Error::from_raw_os_error(libc::EMSGSIZE));
        }
        loop {
            // SAFETY: the descriptor is owned and open, and the pointer and
            // length describe `buf`.
            let sent = unsafe {
                libc::send(
                    self.fd.as_raw_fd(),
                    buf.as_ptr().cast(),
                    buf.len(),
                    libc::MSG_NOSIGNAL,
                )
            };
            if sent < 0 {
                let error = seqpacket::peer_gone_as_epipe(io::Error::last_os_error());
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            return Ok(());
        }
    }

    /// Receive one datagram, returning how many bytes it held.
    ///
    /// **`Ok(0)` is an empty datagram**, which a peer may legitimately send. It
    /// is not end of file, and this is the one place where mimicking Berkeley
    /// exactly would be wrong: reading a zero-byte datagram as a close would let
    /// a peer tear down a live flow by sending nothing. A closed daemon half is
    /// `EPIPE` on every platform, but the platforms disagree on how the kernel
    /// says so: Linux discriminates a zero-byte read with `POLLHUP`, and Darwin
    /// returns `ECONNRESET` outright. Both are measured for this socket pair in
    /// [`seqpacket`](super::seqpacket), and both are translated to `EPIPE` here
    /// so a caller never sees the difference.
    ///
    /// A datagram longer than `buf` is truncated and the remainder discarded,
    /// which is `SOCK_SEQPACKET` behaviour. Size `buf` at
    /// [`FipsStream::max_payload`] and it cannot happen.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            // SAFETY: the descriptor is owned and open, and the pointer and
            // length describe `buf`.
            let received =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if received < 0 {
                let error = seqpacket::peer_gone_as_epipe(io::Error::last_os_error());
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if received == 0 && seqpacket::peer_hung_up(self.fd.as_raw_fd()) {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
            }
            return Ok(received as usize);
        }
    }

    /// The far end, by public key and port.
    ///
    /// Not an `io::Result`, unlike `TcpStream::peer_addr`, which is a syscall
    /// that can fail. This is a field read of what setup already reported, and a
    /// `Result` that is structurally always `Ok` teaches a caller to `unwrap`.
    pub fn peer_addr(&self) -> FipsAddr {
        self.peer
    }

    /// This end: the node's own public key and the port the flow holds.
    pub fn local_addr(&self) -> FipsAddr {
        self.local
    }

    /// Set or clear the deadline on [`FipsStream::recv`].
    ///
    /// Mirrors `TcpStream::set_read_timeout`. `None` clears it. When the
    /// deadline expires, `recv` returns [`io::ErrorKind::WouldBlock`], which is
    /// the same answer a non-blocking descriptor gives and is what the platform
    /// reports; the two are told apart by which the caller asked for.
    ///
    /// **A zero duration is refused with `EINVAL`.** The kernel reads a zero
    /// timeout as "wait for ever", which is the opposite of what a caller
    /// passing zero means, so it is refused rather than silently inverted.
    ///
    /// This bounds one `recv`, not a conversation. Nothing peer-driven ever
    /// ends a flow, so a program still decides its own termination.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        seqpacket::set_timeout(self.fd.as_raw_fd(), libc::SO_RCVTIMEO, dur)
    }

    /// Set or clear the deadline on [`FipsStream::send`].
    ///
    /// Mirrors `TcpStream::set_write_timeout`. It matters less than the read
    /// deadline and is not useless: `send` blocks when the daemon is not
    /// draining this flow fast enough. Same zero-duration refusal.
    pub fn set_write_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        seqpacket::set_timeout(self.fd.as_raw_fd(), libc::SO_SNDTIMEO, dur)
    }

    /// The deadline on [`FipsStream::recv`], or `None` when there is none.
    pub fn read_timeout(&self) -> io::Result<Option<Duration>> {
        seqpacket::timeout(self.fd.as_raw_fd(), libc::SO_RCVTIMEO)
    }

    /// The deadline on [`FipsStream::send`], or `None` when there is none.
    pub fn write_timeout(&self) -> io::Result<Option<Duration>> {
        seqpacket::timeout(self.fd.as_raw_fd(), libc::SO_SNDTIMEO)
    }

    /// Set or clear non-blocking mode on this flow's descriptor.
    ///
    /// Mirrors `TcpStream::set_nonblocking`. In non-blocking mode
    /// [`FipsStream::recv`] returns [`io::ErrorKind::WouldBlock`] instead of
    /// waiting, and [`FipsStream::send`] does the same when the daemon is not
    /// draining the flow fast enough.
    ///
    /// **This exists so a flow can be driven by a reactor.** `AsyncFd` and its
    /// equivalents require a non-blocking descriptor, and without a safe call a
    /// caller has to reach through [`AsRawFd`] and make the `fcntl` themselves,
    /// or give the flow a thread of its own.
    ///
    /// A flow from [`FipsListener::accept`] is blocking however the listener was
    /// set: they are separate sockets, and the daemon hands over a fresh one.
    /// Set it on the flow if the flow is what you poll.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        seqpacket::set_nonblocking(self.fd.as_raw_fd(), nonblocking)
    }

    /// The largest datagram this flow carries, as the daemon computed it.
    ///
    /// No `std::net` counterpart, because TCP has no such limit to report. It is
    /// here because `EMSGSIZE` is reachable and a caller needs the threshold
    /// before it sends.
    pub fn max_payload(&self) -> usize {
        self.max
    }
}

impl AsRawFd for FipsStream {
    /// The flow's descriptor, for a caller with its own reactor or poll loop.
    ///
    /// The stream keeps ownership: the descriptor is closed when it is dropped,
    /// which is what releases the flow at the daemon.
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for FipsStream {
    /// The flow's descriptor as a borrow, which is the form a reactor wants.
    ///
    /// Preferred over [`AsRawFd`]: the borrow cannot outlive the stream, so a
    /// registered descriptor cannot be closed out from under the reactor and
    /// then reused for something else by the next `open`. A `RawFd` carries no
    /// such guarantee and is kept for callers whose interface demands an `int`.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// A held local port, and the descriptor arriving flows are delivered on.
///
/// **The listener is a descriptor**, which is what makes it pollable: it joins
/// an existing `poll`, `select` or `epoll` loop with no new mechanism, and
/// [`FipsListener::accept`] is one `recvmsg` on it. Dropping the listener closes
/// that descriptor, which unbinds the port; flows already accepted from it are
/// untouched.
#[derive(Debug)]
pub struct FipsListener {
    fd: OwnedFd,
    local: FipsAddr,
}

impl FipsListener {
    /// Hold `port`, or an ephemeral one when `port` is 0.
    pub fn bind(port: u16) -> io::Result<FipsListener> {
        Self::bind_at(Path::new(SOCKET), port)
    }

    /// The same call, for a program that is told where its daemon's socket is.
    pub fn bind_at(sock: &Path, port: u16) -> io::Result<FipsListener> {
        Self::hold(Wire::open(sock)?, port)
    }

    /// Perform the `listen` exchange on an open connection, then close it.
    fn hold(mut wire: Wire, port: u16) -> io::Result<FipsListener> {
        let (data, fd) = wire.call(codec::listen(port))?;
        let fd = fd.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "a listen reply carried no descriptor",
            )
        })?;
        let bound = codec::bound(&data)?;
        Ok(FipsListener {
            fd,
            local: FipsAddr::new(bound.node, bound.local),
        })
    }

    /// Take the next arriving flow, blocking until one arrives.
    ///
    /// One `recvmsg`, one arrival: `SOCK_SEQPACKET` means the message carries
    /// exactly its own descriptor, so the association rule the RPC socket needs
    /// does not arise here.
    ///
    /// **Whatever the peer sent before this returned is already on the returned
    /// stream's descriptor.** The daemon writes those datagrams before the
    /// message that carries the descriptor, so the ordering is the guarantee and
    /// a peer's opening datagram cannot be lost between the two.
    ///
    /// Refusing a flow is dropping the stream, which closes its descriptor.
    /// There is no other way to refuse one, which is why an unreadable arrival
    /// message is reported after the descriptor it carried has been taken: the
    /// flow is then refused rather than leaked.
    pub fn accept(&self) -> io::Result<(FipsStream, FipsAddr)> {
        let mut buf = [0u8; CHUNK];
        let chunk = fdpass::recv(self.fd.as_raw_fd(), &mut buf)?;
        let Some(fd) = chunk.fd else {
            // Nothing to refuse and nothing to report on: either the daemon
            // closed its half, or it wrote an arrival with no flow in it.
            return Err(io::Error::from_raw_os_error(libc::EPIPE));
        };
        let stream = FipsStream::wired(fd, codec::arrival(&buf[..chunk.len])?);
        let peer = stream.peer_addr();
        Ok((stream, peer))
    }

    /// An iterator over arriving flows, as `TcpListener::incoming` is.
    ///
    /// It never ends: a listener has no last flow, and a failed accept is an
    /// item rather than the end of the iteration.
    pub fn incoming(&self) -> Incoming<'_> {
        Incoming { listener: self }
    }

    /// Set or clear non-blocking mode on this listener's descriptor.
    ///
    /// Mirrors `TcpListener::set_nonblocking`. In non-blocking mode
    /// [`FipsListener::accept`] returns [`io::ErrorKind::WouldBlock`] when no
    /// flow has arrived, and so does every [`FipsListener::incoming`] item,
    /// which makes that iterator spin unless the caller waits on the descriptor
    /// between items.
    ///
    /// **This is what a reactor needs.** `AsyncFd` and its equivalents require a
    /// non-blocking descriptor, and without a safe call a caller has to reach
    /// through [`AsRawFd`] and make the `fcntl` themselves, or give the accept
    /// loop a thread of its own.
    ///
    /// It does not reach the flows this listener yields: each arrives blocking.
    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        seqpacket::set_nonblocking(self.fd.as_raw_fd(), nonblocking)
    }

    /// The port this listener holds, with the node's own public key.
    ///
    /// The port is the one actually held, so a caller that asked for 0 reads
    /// what it got, which is `getsockname` after `bind(2)` with port 0.
    pub fn local_addr(&self) -> FipsAddr {
        self.local
    }
}

impl AsRawFd for FipsListener {
    /// The listener's descriptor, for a caller with its own event loop.
    ///
    /// This is the point of the listener being a descriptor: `poll` on it
    /// reports readable exactly when [`FipsListener::accept`] would not block.
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl AsFd for FipsListener {
    /// The listener's descriptor as a borrow, which is the form a reactor wants.
    ///
    /// Preferred over [`AsRawFd`], for the reason given on the same impl for
    /// [`FipsStream`]: the borrow is tied to the listener's lifetime, so the
    /// descriptor cannot be closed while a reactor still holds it.
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Arriving flows, one per [`Iterator::next`].
#[derive(Debug)]
pub struct Incoming<'a> {
    listener: &'a FipsListener,
}

impl Iterator for Incoming<'_> {
    type Item = io::Result<FipsStream>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.listener.accept().map(|(stream, _peer)| stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::thread;

    /// An npub shaped like the ones a caller passes. No test reaches the peer.
    const PEER: &str = "npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m";

    /// A second one, standing in for the node's own identity.
    const NODE: &str = "npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl";

    /// The reply to a `connect`, which carries the flow's descriptor.
    const CONNECT_REPLY: &[u8] = concat!(
        r#"{"status":"ok","data":{"flow_id":3,"local_port":49152,"remote_port":4242,"#,
        r#""peer":"npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m","#,
        r#""node":"npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl","#,
        r#""max_payload":1362}}"#,
        "\n",
    )
    .as_bytes();

    /// The reply to a `listen`, which carries the listener's descriptor.
    const LISTEN_REPLY: &[u8] = concat!(
        r#"{"status":"ok","data":{"local_port":4242,"#,
        r#""node":"npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl","#,
        r#""backlog":16}}"#,
        "\n",
    )
    .as_bytes();

    /// One arrival message, as the listener's task writes it: no newline,
    /// because the `SOCK_SEQPACKET` boundary is the framing.
    const ARRIVAL: &[u8] = concat!(
        r#"{"flow_id":9,"#,
        r#""peer":"npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m","#,
        r#""node":"npub1n9lpnv0592cc2ps6nm0ca3qls642vx7yjsv35rkxqzj2vgds52sqgpverl","#,
        r#""local_port":4242,"remote_port":5001,"max_payload":1362,"held":1}"#,
    )
    .as_bytes();

    /// A refusal, as the daemon writes one for a port that is already held.
    const REFUSAL: &[u8] = concat!(
        r#"{"status":"error","message":"port 4242 is already in use on this node","#,
        r#""data":{"errno":"EADDRINUSE"}}"#,
        "\n",
    )
    .as_bytes();

    /// Read one whole line from a socket, one byte at a time.
    ///
    /// A test daemon reads its command this way so it never consumes past the
    /// newline, which a buffered reader would.
    fn read_line(sock: &UnixStream) -> Vec<u8> {
        let mut line = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let read = (&*sock)
                .read(&mut byte)
                .expect("the client should be there");
            assert_eq!(read, 1, "the client closed mid-command");
            if byte[0] == b'\n' {
                return line;
            }
            line.push(byte[0]);
        }
    }

    /// How long a test waits for something that should already be there.
    ///
    /// Every assertion in this module about a datagram or an arrival has the
    /// same failure mode: the thing never comes. A blocking `recv` against that
    /// defect parks for ever, so the suite wedges with no named failure and no
    /// diagnostic instead of reporting one, and **a hang is not a red**. That is
    /// not hypothetical: it is what a kernel whose `AF_UNIX SOCK_SEQPACKET`
    /// drops a zero-length message did to this suite on a FreeBSD runner, six
    /// runs in a row, until the job's own ceiling killed it.
    ///
    /// The bound is not a workaround for a slow machine. It is what makes the
    /// assertion decidable: the descriptors here are socket pairs this thread
    /// already wrote to, so anything that is coming has arrived, and a wait past
    /// this is a wait that will not end. Loose enough that a loaded runner does
    /// not trip it, short enough that a real block reds within one test.
    const DEADLINE: Duration = Duration::from_secs(5);

    /// One receive on a flow, bounded by [`DEADLINE`].
    ///
    /// The deadline is set for the call and put back afterwards, so a test can
    /// still assert what the flow's own deadline is. A blocked receive panics
    /// naming the flow rather than returning `WouldBlock`, because no caller
    /// here asked for a deadline and a `WouldBlock` they did not ask for would
    /// be read as the defect it is hiding.
    fn recv_bounded(flow: &FipsStream, buf: &mut [u8]) -> io::Result<usize> {
        let previous = flow.read_timeout().expect("the descriptor is open");
        flow.set_read_timeout(Some(DEADLINE))
            .expect("the descriptor is open");
        let outcome = flow.recv(buf);
        flow.set_read_timeout(previous)
            .expect("the descriptor is open");
        if let Err(error) = &outcome {
            assert!(
                error.kind() != io::ErrorKind::WouldBlock,
                "nothing arrived on the flow within {DEADLINE:?} and the recv \
                 was still waiting: the datagram this asserts on was never \
                 delivered, or the peer closed without this platform saying so"
            );
        }
        outcome
    }

    /// A listener over `fd`, with [`DEADLINE`] on its accepts.
    ///
    /// Every test here writes the arrival onto the far half before accepting,
    /// so a blocked accept means the message was not delivered. Bounded for the
    /// same reason [`recv_bounded`] is: without it that is a hang rather than a
    /// failure.
    fn listener(fd: OwnedFd) -> FipsListener {
        seqpacket::set_timeout(fd.as_raw_fd(), libc::SO_RCVTIMEO, Some(DEADLINE))
            .expect("the descriptor is open");
        FipsListener {
            fd,
            local: FipsAddr::new(codec::pton(NODE).unwrap(), 4242),
        }
    }

    /// A stream whose far end is a socket the test drives, standing in for the
    /// daemon's half of a real flow.
    ///
    /// The far half carries [`DEADLINE`] from the start, because the tests read
    /// it directly rather than through [`recv_bounded`]. The flow half does not:
    /// two tests assert that a fresh flow has no deadline, which is the API's
    /// documented default, so the flow's bound is applied per call instead.
    fn stream(max: usize) -> (FipsStream, UnixStream) {
        let (ours, theirs) = seqpacket::pair().expect("a socket pair should be available");
        let stream = FipsStream::wired(
            ours,
            Opened {
                peer: codec::pton(PEER).unwrap(),
                node: codec::pton(NODE).unwrap(),
                local: 4242,
                remote: 5001,
                max,
            },
        );
        let far = UnixStream::from(theirs);
        far.set_read_timeout(Some(DEADLINE))
            .expect("the descriptor is open");
        (stream, far)
    }

    #[test]
    fn a_read_deadline_expires_rather_than_waiting_for_a_datagram_that_never_comes() {
        let (flow, _daemon) = stream(1362);
        flow.set_read_timeout(Some(Duration::from_millis(150)))
            .expect("the descriptor is open");

        // The far end is held open and silent, so without a deadline this
        // parks for ever. Timing it is what shows the deadline did the work
        // rather than something else returning early.
        //
        // The recv runs on its own thread and is collected through a channel
        // with a bound of its own, because the defect this test exists to catch
        // is precisely a deadline that never reached the descriptor: called
        // inline, that parks for ever and wedges the whole `cargo test --lib`
        // run with no diagnostic. A hang is not a red, so the bound is what
        // makes this test able to fail.
        let (report, collected) = std::sync::mpsc::channel();
        thread::spawn(move || {
            let start = std::time::Instant::now();
            let mut buf = [0u8; 64];
            let outcome = flow.recv(&mut buf);
            let _ = report.send((outcome, start.elapsed()));
        });

        let (outcome, waited) = collected
            .recv_timeout(Duration::from_secs(5))
            .expect("the 150ms read deadline never bounded the recv");
        let error = outcome.expect_err("nothing was ever sent");

        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(
            waited >= Duration::from_millis(100),
            "returned after {waited:?}, too soon to have waited out a 150ms deadline"
        );
    }

    #[test]
    fn a_zero_read_deadline_is_refused_because_the_kernel_would_read_it_as_no_deadline() {
        let (flow, _daemon) = stream(1362);
        let error = flow
            .set_read_timeout(Some(Duration::ZERO))
            .expect_err("zero means the opposite to the kernel");
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));

        // And it did not reach the socket: no deadline is set afterwards.
        assert_eq!(flow.read_timeout().unwrap(), None);
    }

    #[test]
    fn a_deadline_reads_back_as_it_was_set_and_none_clears_it() {
        let (flow, _daemon) = stream(1362);
        assert_eq!(flow.read_timeout().unwrap(), None, "none is the default");
        assert_eq!(flow.write_timeout().unwrap(), None);

        flow.set_read_timeout(Some(Duration::from_millis(1500)))
            .unwrap();
        assert_eq!(
            flow.read_timeout().unwrap(),
            Some(Duration::from_millis(1500))
        );

        // The two directions are separate options; setting one must not set
        // the other, which a copied constant would.
        assert_eq!(flow.write_timeout().unwrap(), None, "send is untouched");

        flow.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(flow.write_timeout().unwrap(), Some(Duration::from_secs(2)));
        assert_eq!(
            flow.read_timeout().unwrap(),
            Some(Duration::from_millis(1500)),
            "recv keeps its own"
        );

        flow.set_read_timeout(None).unwrap();
        assert_eq!(flow.read_timeout().unwrap(), None, "cleared");
        assert_eq!(
            flow.write_timeout().unwrap(),
            Some(Duration::from_secs(2)),
            "clearing one leaves the other"
        );
    }

    #[test]
    fn a_nonblocking_flow_reports_would_block_rather_than_waiting_for_a_datagram() {
        let (flow, _daemon) = stream(1362);

        // Blocking is the default, so the flag has somewhere to move from.
        let raw = flow.as_raw_fd();
        let before = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        assert_eq!(before & libc::O_NONBLOCK, 0, "a flow starts out blocking");

        flow.set_nonblocking(true).expect("the descriptor is open");

        // Nothing has been sent, so a blocking recv would park here for ever.
        let mut buf = [0u8; 64];
        let error = flow.recv(&mut buf).expect_err("no datagram is waiting");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn clearing_nonblocking_returns_a_flow_to_blocking_and_leaves_its_other_flags_alone() {
        let (flow, _daemon) = stream(1362);
        let raw = flow.as_raw_fd();

        // A second flag to watch, and it has to be one F_SETFL actually
        // honours. The access mode looks like the obvious choice and is not:
        // F_SETFL ignores it, so the kernel preserves O_RDWR however carelessly
        // the flag word is written, and asserting on it gives a test that
        // cannot fail. O_ASYNC is settable on a socket, so it does discriminate.
        let start = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        assert!(start >= 0);
        assert_eq!(
            unsafe { libc::fcntl(raw, libc::F_SETFL, start | libc::O_ASYNC) },
            0,
            "O_ASYNC should be settable on a seqpacket socket"
        );
        let original = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        assert_ne!(original & libc::O_ASYNC, 0, "the flag under test is set");

        flow.set_nonblocking(true).unwrap();
        assert_ne!(
            unsafe { libc::fcntl(raw, libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );

        flow.set_nonblocking(false).unwrap();
        let after = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        assert_eq!(after & libc::O_NONBLOCK, 0, "blocking mode is restored");
        assert_ne!(
            after & libc::O_ASYNC,
            0,
            "a flag the caller set survived the round trip, which a bare \
             F_SETFL of O_NONBLOCK alone would have cleared"
        );
        assert_eq!(
            after, original,
            "the whole flag word is unchanged but for O_NONBLOCK"
        );
    }

    #[test]
    fn a_nonblocking_listener_reports_would_block_rather_than_waiting_for_a_flow() {
        let (ours, _theirs) = seqpacket::pair().expect("a socket pair should be available");
        let listener = listener(ours);

        listener
            .set_nonblocking(true)
            .expect("the descriptor is open");

        let error = listener.accept().expect_err("no flow has arrived");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn the_borrowed_descriptor_is_the_same_one_the_raw_accessor_reports() {
        let (flow, _daemon) = stream(1362);
        assert_eq!(flow.as_fd().as_raw_fd(), flow.as_raw_fd());

        let (ours, _theirs) = seqpacket::pair().unwrap();
        let listener = listener(ours);
        assert_eq!(listener.as_fd().as_raw_fd(), listener.as_raw_fd());
    }

    #[test]
    fn a_descriptor_lands_on_the_last_complete_line_of_the_read_that_carried_it() {
        let (daemon, client) = UnixStream::pair().unwrap();
        let (passed, held) = seqpacket::pair().unwrap();
        let held = UnixStream::from(held);

        // Both are written before the client reads, so everything below is
        // already queued and no read here waits on anything.
        (&daemon).write_all(REFUSAL).unwrap();
        fdpass::send_once(daemon.as_raw_fd(), CONNECT_REPLY, Some(passed.as_fd())).unwrap();
        drop(passed);

        // **How many reads this takes is the platform's business, and asserting
        // it was wrong.** Linux coalesces the plain write with the sendmsg that
        // follows, so one recvmsg returns both lines and the descriptor. Darwin
        // stops a stream read at the ancillary boundary, so the plain line
        // arrives by itself and the descriptor-bearing line comes on the next
        // read. Measured on macos-latest, where the earlier form of this test
        // failed on exactly that difference.
        //
        // The rule under test is the same on both and is what the assertions
        // below check: a descriptor belongs to the last complete line of the
        // read that carried it. Darwin satisfies it more easily than Linux
        // does, since the read it arrives on holds nothing later.
        let mut wire = Wire::new(client);
        for _ in 0..4 {
            if wire.lines.len() >= 2 {
                break;
            }
            wire.fill().unwrap();
        }
        assert_eq!(
            wire.lines.len(),
            2,
            "both lines should have arrived within four reads of a socket that \
             already held them"
        );

        let (first, first_fd) = wire.line().unwrap();
        assert!(
            first.starts_with(br#"{"status":"error""#),
            "first line was {first:?}"
        );
        assert!(
            first_fd.is_none(),
            "the earlier line must not be given the descriptor"
        );

        let (second, second_fd) = wire.line().unwrap();
        assert!(second.starts_with(br#"{"status":"ok""#));
        let received = second_fd.expect("the reply must carry the descriptor");

        // A live socket rather than merely a number: the far half sees it.
        let mut received = UnixStream::from(received);
        received.write_all(b"alive").unwrap();
        let mut got = [0u8; 5];
        (&held).read_exact(&mut got).unwrap();
        assert_eq!(&got, b"alive");
    }

    #[test]
    fn a_descriptor_on_a_read_that_completed_no_line_is_reported_rather_than_guessed_at() {
        let (daemon, client) = UnixStream::pair().unwrap();
        let (passed, _held) = seqpacket::pair().unwrap();

        // A descriptor with no line to attach it to. Holding it would mean
        // guessing which later line owns it, and the guess loses a flow.
        fdpass::send_once(daemon.as_raw_fd(), b"{\"status\":", Some(passed.as_fd())).unwrap();

        let mut wire = Wire::new(client);
        let error = wire.fill().unwrap_err();
        assert!(
            error.to_string().contains("completed no line"),
            "got {error}"
        );
    }

    #[test]
    fn connect_returns_a_stream_and_closes_the_connection_that_made_it() {
        let (daemon, client) = UnixStream::pair().unwrap();
        let (passed, _held) = seqpacket::pair().unwrap();

        let worker = thread::spawn(move || {
            let command = read_line(&daemon);
            fdpass::send_once(daemon.as_raw_fd(), CONNECT_REPLY, Some(passed.as_fd())).unwrap();
            // The connection must be gone once connect has returned: a stream
            // that outlived its connection is the defect this shape removes,
            // and a reply is the last thing this socket is for.
            // A deadline, or the defect this asserts against fails as a hang
            // rather than as a named test: a client that kept its connection
            // leaves this read blocked for ever and the suite never finishes.
            daemon
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut rest = [0u8; 16];
            let read = (&daemon)
                .read(&mut rest)
                .expect("the RPC connection outlived the setup call that opened it");
            (command, read)
        });

        let addr = (PEER, 4242).to_fips_addr().unwrap();
        let flow = FipsStream::open(Wire::new(client), 0, addr).unwrap();

        assert_eq!(flow.peer_addr().to_string(), format!("{PEER}:4242"));
        assert_eq!(flow.local_addr().to_string(), format!("{NODE}:49152"));
        assert_eq!(flow.max_payload(), 1362);

        let (command, read) = worker.join().unwrap();
        let command: serde_json::Value = serde_json::from_slice(&command).unwrap();
        assert_eq!(command["command"], "connect");
        assert_eq!(command["params"]["peer"], PEER);
        assert_eq!(command["params"]["local_port"], 0);
        assert_eq!(read, 0, "the RPC connection was still open");
    }

    #[test]
    fn bind_keeps_the_listener_descriptor_and_reports_the_port_actually_held() {
        let (daemon, client) = UnixStream::pair().unwrap();
        let (passed, held) = seqpacket::pair().unwrap();
        let held = UnixStream::from(held);

        let worker = thread::spawn(move || {
            let command = read_line(&daemon);
            fdpass::send_once(daemon.as_raw_fd(), LISTEN_REPLY, Some(passed.as_fd())).unwrap();
            drop(passed);
            // As for connect: setup is over, so the connection is over. A
            // listener that held one would take its flows down with it.
            // A deadline, or the defect this asserts against fails as a hang
            // rather than as a named test: a client that kept its connection
            // leaves this read blocked for ever and the suite never finishes.
            daemon
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut rest = [0u8; 16];
            let read = (&daemon)
                .read(&mut rest)
                .expect("the RPC connection outlived the setup call that opened it");
            (command, read)
        });

        // Asking for 0 is asking the daemon to pick, so the reply's port is the
        // only place the answer exists.
        let listener = FipsListener::hold(Wire::new(client), 0).unwrap();
        assert_eq!(listener.local_addr().to_string(), format!("{NODE}:4242"));

        let (command, read) = worker.join().unwrap();
        let command: serde_json::Value = serde_json::from_slice(&command).unwrap();
        assert_eq!(command["command"], "listen");
        assert_eq!(command["params"]["local_port"], 0);
        assert_eq!(read, 0, "the RPC connection was still open");

        // The descriptor is a live socket, not merely a number the reply named.
        let mut buf = [0u8; 5];
        (&held).write_all(b"alive").unwrap();
        // SAFETY: the listener's descriptor is open and owned by it.
        let got = unsafe { libc::recv(listener.as_raw_fd(), buf.as_mut_ptr().cast(), 5, 0) };
        assert_eq!(got, 5, "{}", io::Error::last_os_error());
    }

    #[test]
    fn a_refusal_becomes_the_error_a_bind_would_have_returned() {
        let (daemon, client) = UnixStream::pair().unwrap();

        let worker = thread::spawn(move || {
            read_line(&daemon);
            (&daemon).write_all(REFUSAL).unwrap();
            daemon
        });

        let error = FipsListener::hold(Wire::new(client), 4242).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EADDRINUSE));

        let _daemon = worker.join().unwrap();
    }

    #[test]
    fn a_daemon_that_never_answers_is_the_one_producer_of_etimedout() {
        let (_daemon, client) = UnixStream::pair().unwrap();
        // The real deadline is five seconds and its subject is the same wait;
        // shortening it here keeps the suite quick without changing the path.
        client
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();

        let error = FipsListener::hold(Wire::new(client), 4242).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ETIMEDOUT));
    }

    #[test]
    fn a_daemon_that_goes_away_ends_a_blocking_setup_call_rather_than_looping() {
        // Gone before the command: the write is what fails, and a write to a
        // socket whose far end has closed is `EPIPE`. It is an error here
        // rather than a signal because the command is sent with `MSG_NOSIGNAL`.
        let (daemon, client) = UnixStream::pair().unwrap();
        drop(daemon);
        let error = FipsListener::hold(Wire::new(client), 4242).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));

        // Gone after the command: the read ends at once instead of waiting out
        // the setup deadline, and a connection the daemon accepted and then
        // dropped is the socket not accepting by a slower route.
        let (daemon, client) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            read_line(&daemon);
            drop(daemon);
        });
        let error = FipsListener::hold(Wire::new(client), 4242).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::ECONNREFUSED));
        worker.join().unwrap();
    }

    #[test]
    fn accept_takes_the_flow_the_arrival_carried_and_names_its_peer_by_npub() {
        let (ours, theirs) = seqpacket::pair().unwrap();
        let (passed, held) = seqpacket::pair().unwrap();
        let held = UnixStream::from(held);

        let listener = listener(ours);

        // The daemon writes the peer's opening datagram onto the flow's own
        // half first, and the arrival that carries that flow's descriptor
        // second. The order is the guarantee: whatever arrived before the
        // client could read the arrival is already there when it holds it.
        (&held).write_all(b"opening").unwrap();
        fdpass::send_once(theirs.as_raw_fd(), ARRIVAL, Some(passed.as_fd())).unwrap();
        drop(passed);

        let (flow, peer) = listener.accept().unwrap();
        assert_eq!(peer.to_string(), format!("{PEER}:5001"));
        assert_eq!(flow.peer_addr(), peer);
        // From the arrival's own `node`, not from the listener: an accepted
        // stream answers `getsockname` without consulting what produced it.
        assert_eq!(flow.local_addr().to_string(), format!("{NODE}:4242"));
        assert_eq!(flow.max_payload(), 1362);

        let mut buf = [0u8; 64];
        assert_eq!(recv_bounded(&flow, &mut buf).unwrap(), 7);
        assert_eq!(&buf[..7], b"opening");

        // The descriptor is the flow's own half and nothing else's.
        flow.send(b"back").unwrap();
        let mut got = [0u8; 64];
        assert_eq!((&held).read(&mut got).unwrap(), 4);
    }

    #[test]
    fn a_listener_descriptor_is_pollable_and_reports_a_waiting_arrival() {
        // The point of the listener being a descriptor. Without this, `accept`
        // could only be discovered by blocking in it.
        let (ours, theirs) = seqpacket::pair().unwrap();
        let (passed, _held) = seqpacket::pair().unwrap();
        let listener = listener(ours);

        let mut poll = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` names one live descriptor and the call cannot block.
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 0, "readable early");

        fdpass::send_once(theirs.as_raw_fd(), ARRIVAL, Some(passed.as_fd())).unwrap();

        poll.revents = 0;
        // SAFETY: as above.
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
        assert_ne!(poll.revents & libc::POLLIN, 0);
        listener.accept().unwrap();
    }

    #[test]
    fn an_arrival_with_no_descriptor_is_reported_rather_than_taken_as_a_flow() {
        let (ours, theirs) = seqpacket::pair().unwrap();
        let listener = listener(ours);
        fdpass::send_once(theirs.as_raw_fd(), ARRIVAL, None).unwrap();

        assert_eq!(
            listener.accept().unwrap_err().raw_os_error(),
            Some(libc::EPIPE)
        );
    }

    #[test]
    fn incoming_yields_the_same_flows_accept_would() {
        let (ours, theirs) = seqpacket::pair().unwrap();
        let (passed, _held) = seqpacket::pair().unwrap();
        let listener = listener(ours);
        fdpass::send_once(theirs.as_raw_fd(), ARRIVAL, Some(passed.as_fd())).unwrap();

        let flow = listener.incoming().next().unwrap().unwrap();
        assert_eq!(flow.peer_addr().to_string(), format!("{PEER}:5001"));
    }

    #[test]
    fn datagrams_cross_a_flow_whole_in_both_directions() {
        let (flow, far) = stream(1362);

        flow.send(b"out").unwrap();
        flow.send(b"again").unwrap();
        let mut got = [0u8; 64];
        assert_eq!((&far).read(&mut got).unwrap(), 3);
        assert_eq!(&got[..3], b"out");
        assert_eq!((&far).read(&mut got).unwrap(), 5);
        assert_eq!(&got[..5], b"again");

        (&far).write_all(b"back").unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(recv_bounded(&flow, &mut buf).unwrap(), 4);
        assert_eq!(&buf[..4], b"back");
    }

    #[test]
    fn an_empty_datagram_is_not_reported_as_a_closed_flow() {
        let (flow, far) = stream(1362);

        // Both produce a zero-byte read, and a client that read the first as a
        // close would tear down a live flow because a peer sent nothing.
        //
        // `write_all(b"")` is a no-op in Rust and never reaches the socket, so
        // the zero-length datagram is sent with `send` directly. The first
        // version of this test used `write_all` and blocked for ever waiting
        // for a datagram nothing had sent.
        // SAFETY: the descriptor is open and owned by `far`.
        let sent = unsafe { libc::send(far.as_raw_fd(), std::ptr::null(), 0, 0) };
        assert_eq!(sent, 0, "{}", io::Error::last_os_error());

        let mut buf = [0u8; 64];
        assert_eq!(recv_bounded(&flow, &mut buf).unwrap(), 0);

        drop(far);
        let error = recv_bounded(&flow, &mut buf).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPIPE));
    }

    #[test]
    fn a_datagram_above_the_flows_limit_is_refused_before_it_is_sent() {
        let (flow, far) = stream(8);
        let error = flow.send(&[0u8; 9]).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EMSGSIZE));

        // Nothing reached the socket: the far end has no datagram waiting.
        far.set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let mut buf = [0u8; 64];
        assert!(
            (&far).read(&mut buf).is_err(),
            "a refused datagram was sent"
        );

        // The limit itself is allowed, so the check is not off by one.
        flow.send(&[0u8; 8]).unwrap();
        assert_eq!((&far).read(&mut buf).unwrap(), 8);
    }

    #[test]
    fn a_flow_can_move_to_another_thread() {
        // The point of a stream holding no reference to a connection: a server
        // can hand one to a worker thread.
        let (flow, far) = stream(1362);
        let worker = thread::spawn(move || {
            flow.send(b"from the worker").unwrap();
            flow
        });
        let flow = worker.join().unwrap();
        assert_eq!(flow.local_addr().port(), 4242);

        let mut got = [0u8; 64];
        assert_eq!((&far).read(&mut got).unwrap(), 15);
    }

    #[test]
    fn one_parameter_takes_every_spelling_of_the_same_address() {
        let want = FipsAddr::new(codec::pton(PEER).unwrap(), 4242);
        let key = want.key();

        assert_eq!((PEER, 4242u16).to_fips_addr().unwrap(), want);
        assert_eq!((PEER.to_string(), 4242u16).to_fips_addr().unwrap(), want);
        assert_eq!((key, 4242u16).to_fips_addr().unwrap(), want);
        assert_eq!((key.serialize(), 4242u16).to_fips_addr().unwrap(), want);
        assert_eq!(format!("{PEER}:4242").to_fips_addr().unwrap(), want);
        assert_eq!(want.to_fips_addr().unwrap(), want);

        // Through a generic parameter, which is how the setup calls take one:
        // this is what exercises the blanket reference implementation, and
        // without it a caller could not pass `&addr` at all.
        fn resolve<A: ToFipsAddr>(addr: A) -> FipsAddr {
            addr.to_fips_addr().expect("the address should resolve")
        }
        let text: &str = &format!("{PEER}:4242");
        let by_ref: &FipsAddr = &want;
        assert_eq!(resolve(text), want);
        assert_eq!(resolve(by_ref), want);
    }

    #[test]
    fn an_address_that_does_not_parse_is_einval_with_no_daemon_involved() {
        // Local and pure, like `inet_pton`: nothing here opens a socket.
        for bad in [
            "not-an-npub",
            "npub1abc:4242",
            &format!("{PEER}:70000"),
            PEER,
        ] {
            let error = bad.to_fips_addr().unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINVAL), "{bad}");
        }
        assert_eq!(
            ([0u8; 32], 4242u16)
                .to_fips_addr()
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EINVAL)
        );
    }

    #[test]
    fn an_address_written_out_reads_back_as_itself() {
        let addr = FipsAddr::new(codec::pton(PEER).unwrap(), 4242);
        assert_eq!(addr.to_string(), format!("{PEER}:4242"));
        assert_eq!(addr.to_string().parse::<FipsAddr>().unwrap(), addr);
    }
}
