//! Kernel socket buffer sizing, shared by the transports that own a raw
//! descriptor: the UDP listen and per-peer sockets and the Ethernet packet
//! socket.
//!
//! A plain `SO_RCVBUF` or `SO_SNDBUF` is capped by Linux at
//! `net.core.rmem_max` or `wmem_max`, 212992 bytes by default, which the
//! kernel doubles to 425984 for bookkeeping. At the rates a FIPS link carries
//! that is a few milliseconds of frames, and a socket that fills drops the
//! rest in the kernel, before the node can read them. `SO_RCVBUFFORCE` and
//! `SO_SNDBUFFORCE` bypass the cap for a process with `CAP_NET_ADMIN`, which a
//! node running its TUN device has, so they are tried first and the plain
//! options are the fallback.

use std::io;
use std::os::unix::io::RawFd;

/// Which of a socket's two kernel buffers to size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Buffer {
    /// The receive buffer.
    Recv,
    /// The send buffer.
    Send,
}

impl Buffer {
    /// The plain socket option, which the kernel caps.
    fn plain(self) -> libc::c_int {
        match self {
            Buffer::Recv => libc::SO_RCVBUF,
            Buffer::Send => libc::SO_SNDBUF,
        }
    }

    /// The forcing option, where the platform has one.
    #[cfg(target_os = "linux")]
    fn forced(self) -> Option<libc::c_int> {
        Some(match self {
            Buffer::Recv => libc::SO_RCVBUFFORCE,
            Buffer::Send => libc::SO_SNDBUFFORCE,
        })
    }

    #[cfg(not(target_os = "linux"))]
    fn forced(self) -> Option<libc::c_int> {
        None
    }
}

/// What a sizing request asked for and what the kernel granted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Granted {
    /// The size asked for, in bytes.
    pub requested: usize,
    /// The size the kernel reports afterwards. Linux reports twice the value
    /// it accepted.
    pub actual: usize,
}

impl Granted {
    /// Whether the kernel held the buffer below what was asked for.
    pub fn clamped(&self) -> bool {
        self.actual < self.requested
    }
}

/// Size one of `fd`'s kernel buffers to `size` bytes and read back what the
/// kernel granted.
///
/// The forcing option is tried first and the plain one if that fails, so an
/// unprivileged process still gets the capped size. Errors only when neither
/// option could be set, with the plain option's error, or when the size
/// cannot be read back. A caller that treats sizing as best-effort ignores
/// the error; one that treats it as part of setup fails on it.
pub(crate) fn set_buffer(fd: RawFd, which: Buffer, size: usize) -> io::Result<Granted> {
    let value = libc::c_int::try_from(size).unwrap_or(libc::c_int::MAX);
    let forced = which
        .forced()
        .is_some_and(|name| setsockopt_int(fd, name, value).is_ok());
    if !forced {
        setsockopt_int(fd, which.plain(), value)?;
    }
    let actual = getsockopt_int(fd, which.plain())?;
    Ok(Granted {
        requested: size,
        actual: usize::try_from(actual).unwrap_or(0),
    })
}

/// `setsockopt(fd, SOL_SOCKET, name, value)`.
fn setsockopt_int(fd: RawFd, name: libc::c_int, value: libc::c_int) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `getsockopt(fd, SOL_SOCKET, name)` for an integer option.
fn getsockopt_int(fd: RawFd, name: libc::c_int) -> io::Result<libc::c_int> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            name,
            &mut value as *mut libc::c_int as *mut libc::c_void,
            &mut len,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

#[cfg(test)]
#[path = "tests/sockbuf.rs"]
mod tests;
