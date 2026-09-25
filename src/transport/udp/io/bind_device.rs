//! Binding a UDP socket to one interface (`udp.interface`), the one way
//! for both the listen socket and the per-peer connected sockets.
//!
//! Linux: `SO_BINDTODEVICE`, both directions. macOS: `IP_BOUND_IF` /
//! `IPV6_BOUND_IF`, egress only — inbound still arrives from any
//! interface, which is why the interface-bound transport's paths are
//! detected by unreachable-on-send and the echo timeout, not by presence.
//! Elsewhere naming an interface is an error rather than a silent no-op.

use std::io;
use std::os::unix::io::RawFd;

/// Bind `fd` to the interface named `name`. `v4` selects the IPv4 or IPv6
/// option where the platform has one per family.
#[cfg(target_os = "linux")]
pub(super) fn bind_to_interface(fd: RawFd, name: &str, _v4: bool) -> io::Result<()> {
    // SAFETY: `fd` is an open socket owned by the caller; the option value
    // is `name`'s bytes with the length passed alongside, and the kernel
    // copies them for the duration of the call.
    let r = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr() as *const libc::c_void,
            name.len() as libc::socklen_t,
        )
    };
    if r < 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!("bind to interface {name}: {err}"),
        ));
    }
    Ok(())
}

/// Bind `fd` to the interface named `name`. `v4` selects the IPv4 or IPv6
/// option where the platform has one per family.
#[cfg(target_os = "macos")]
pub(super) fn bind_to_interface(fd: RawFd, name: &str, v4: bool) -> io::Result<()> {
    let c_name = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface name"))?;
    // SAFETY: `c_name` is a valid NUL-terminated string for the call's duration.
    let index = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if index == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {name} not found"),
        ));
    }
    let (level, opt) = if v4 {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    } else {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    };
    let value = index as libc::c_int;
    // SAFETY: `fd` is an open socket owned by the caller; the option value
    // is a `c_int` on the stack whose size is passed alongside.
    let r = unsafe {
        libc::setsockopt(
            fd,
            level,
            opt,
            &value as *const libc::c_int as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if r < 0 {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(
            err.kind(),
            format!("bind to interface {name}: {err}"),
        ));
    }
    Ok(())
}

/// Bind `fd` to the interface named `name`: not supported on this platform.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn bind_to_interface(_fd: RawFd, name: &str, _v4: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!("udp.interface ({name}) is supported on Linux and macOS only"),
    ))
}
