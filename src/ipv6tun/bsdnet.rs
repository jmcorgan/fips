//! Host interface and route configuration on macOS and FreeBSD by direct
//! kernel calls.
//!
//! The TUN setup needs four things from the host: whether the kernel has
//! IPv6 at all (`sysctlbyname`), a `/128` address on the device
//! (`SIOCAIFADDR_IN6`), the device up (`SIOCGIFFLAGS`/`SIOCSIFFLAGS`), and a
//! route for `fd00::/8` through it (an `RTM_ADD` on a `PF_ROUTE` socket).
//! FreeBSD also needs the interface's `ND6_IFF_IFDISABLED` flag cleared
//! (`SIOCGIFINFO_IN6`/`SIOCSIFINFO_IN6`). Every call here returns the
//! kernel's error as an [`io::Error`], so callers decide what is benign by
//! error code rather than by another program's output text.
//!
//! libc does not define every structure these calls take on both targets.
//! The missing ones are defined here with `#[repr(C)]`, and each carries a
//! compile-time size check whose expected value was read from the platform
//! header for 64-bit targets: FreeBSD's `netinet6/in6_var.h`,
//! `netinet6/nd6.h` and `net/route.h`, and XNU's `bsd/netinet6/in6_var.h`.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv6Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use libc::{c_char, c_int, c_ulong};

/// `IOC_IN`: the ioctl copies its argument into the kernel.
const IOC_IN: c_ulong = 0x8000_0000;
/// `IOC_INOUT`: the ioctl copies its argument in and back out.
const IOC_INOUT: c_ulong = 0xc000_0000;
/// `IOCPARM_MASK`: the argument length field of an ioctl number.
const IOCPARM_MASK: c_ulong = 0x1fff;

/// An ioctl request number, as `<sys/ioccom.h>`'s `_IOC` builds it.
const fn ioc(dir: c_ulong, group: u8, num: u8, len: usize) -> c_ulong {
    dir | (((len as c_ulong) & IOCPARM_MASK) << 16) | ((group as c_ulong) << 8) | (num as c_ulong)
}

/// `struct in6_aliasreq`, the argument of `SIOCAIFADDR_IN6`.
///
/// FreeBSD appends `ifra_vhid`; XNU does not.
#[repr(C)]
struct In6Aliasreq {
    ifra_name: [c_char; libc::IFNAMSIZ],
    ifra_addr: libc::sockaddr_in6,
    ifra_dstaddr: libc::sockaddr_in6,
    ifra_prefixmask: libc::sockaddr_in6,
    ifra_flags: c_int,
    ifra_lifetime: libc::in6_addrlifetime,
    #[cfg(target_os = "freebsd")]
    ifra_vhid: c_int,
}

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
const _: () = assert!(size_of::<In6Aliasreq>() == 128);
#[cfg(all(target_os = "freebsd", target_pointer_width = "64"))]
const _: () = assert!(size_of::<In6Aliasreq>() == 136);

/// `SIOCAIFADDR_IN6`: add (or update) an IPv6 address on an interface.
#[cfg(target_os = "macos")]
const SIOCAIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 26, size_of::<In6Aliasreq>());
/// `SIOCAIFADDR_IN6`: add (or update) an IPv6 address on an interface.
#[cfg(target_os = "freebsd")]
const SIOCAIFADDR_IN6: c_ulong = ioc(IOC_IN, b'i', 27, size_of::<In6Aliasreq>());

#[cfg(all(target_os = "macos", target_pointer_width = "64"))]
const _: () = assert!(SIOCAIFADDR_IN6 == 0x8080_691a);
#[cfg(all(target_os = "freebsd", target_pointer_width = "64"))]
const _: () = assert!(SIOCAIFADDR_IN6 == 0x8088_691b);

/// `SIOCGIFFLAGS`: read an interface's flags.
const SIOCGIFFLAGS: c_ulong = ioc(IOC_INOUT, b'i', 17, size_of::<libc::ifreq>());
/// `SIOCSIFFLAGS`: write an interface's flags.
const SIOCSIFFLAGS: c_ulong = ioc(IOC_IN, b'i', 16, size_of::<libc::ifreq>());

const _: () = assert!(SIOCGIFFLAGS == 0xc020_6911);
const _: () = assert!(SIOCSIFFLAGS == 0x8020_6910);
#[cfg(target_os = "macos")]
const _: () = assert!(SIOCGIFFLAGS == libc::SIOCGIFFLAGS && SIOCSIFFLAGS == libc::SIOCSIFFLAGS);

/// `ND6_INFINITE_LIFETIME`: an address lifetime that never expires.
const INFINITE_LIFETIME: u32 = 0xffff_ffff;

/// `struct nd_ifinfo` (FreeBSD `netinet6/nd6.h`).
#[cfg(target_os = "freebsd")]
#[repr(C)]
struct NdIfinfo {
    linkmtu: u32,
    maxmtu: u32,
    basereachable: u32,
    reachable: u32,
    retrans: u32,
    flags: u32,
    recalctm: c_int,
    chlim: u8,
    initialized: u8,
    randomseed0: [u8; 8],
    randomseed1: [u8; 8],
    randomid: [u8; 8],
}

/// `struct in6_ndireq`, the argument of `SIOCGIFINFO_IN6`/`SIOCSIFINFO_IN6`.
#[cfg(target_os = "freebsd")]
#[repr(C)]
struct In6Ndireq {
    ifname: [c_char; libc::IFNAMSIZ],
    ndi: NdIfinfo,
}

#[cfg(target_os = "freebsd")]
const _: () = assert!(size_of::<NdIfinfo>() == 56 && size_of::<In6Ndireq>() == 72);

/// `SIOCGIFINFO_IN6`: read an interface's neighbour-discovery settings.
#[cfg(target_os = "freebsd")]
const SIOCGIFINFO_IN6: c_ulong = ioc(IOC_INOUT, b'i', 108, size_of::<In6Ndireq>());
/// `SIOCSIFINFO_IN6`: write an interface's neighbour-discovery settings.
#[cfg(target_os = "freebsd")]
const SIOCSIFINFO_IN6: c_ulong = ioc(IOC_INOUT, b'i', 109, size_of::<In6Ndireq>());
/// `ND6_IFF_IFDISABLED`: IPv6 is disabled on the interface.
#[cfg(target_os = "freebsd")]
const IFDISABLED: u32 = 0x8;

#[cfg(target_os = "freebsd")]
const _: () = assert!(SIOCGIFINFO_IN6 == 0xc048_696c && SIOCSIFINFO_IN6 == 0xc048_696d);

/// `struct rt_metrics` (FreeBSD `net/route.h`); libc defines it only for
/// Apple targets.
#[cfg(target_os = "freebsd")]
#[repr(C)]
struct RtMetrics {
    rmx_locks: c_ulong,
    rmx_mtu: c_ulong,
    rmx_hopcount: c_ulong,
    rmx_expire: c_ulong,
    rmx_recvpipe: c_ulong,
    rmx_sendpipe: c_ulong,
    rmx_ssthresh: c_ulong,
    rmx_rtt: c_ulong,
    rmx_rttvar: c_ulong,
    rmx_pksent: c_ulong,
    rmx_weight: c_ulong,
    rmx_nhidx: c_ulong,
    rmx_filler: [c_ulong; 2],
}

/// `struct rt_msghdr` (FreeBSD `net/route.h`); libc defines it only for
/// Apple targets.
#[cfg(target_os = "freebsd")]
#[repr(C)]
struct RtMsghdr {
    rtm_msglen: u16,
    rtm_version: u8,
    rtm_type: u8,
    rtm_index: u16,
    rtm_spare1: u16,
    rtm_flags: c_int,
    rtm_addrs: c_int,
    rtm_pid: libc::pid_t,
    rtm_seq: c_int,
    rtm_errno: c_int,
    rtm_fmask: c_int,
    rtm_inits: c_ulong,
    rtm_rmx: RtMetrics,
}

/// The routing message header of the target.
#[cfg(target_os = "macos")]
type RtMsghdr = libc::rt_msghdr;

#[cfg(all(target_os = "freebsd", target_pointer_width = "64"))]
const _: () = assert!(size_of::<RtMsghdr>() == 152);
#[cfg(target_os = "macos")]
const _: () = assert!(size_of::<RtMsghdr>() == 92);

/// `RTM_VERSION`: the routing message format both kernels speak.
const RTM_VERSION: u8 = 5;

/// The alignment each socket address in a routing message is padded to:
/// 4 bytes on XNU (`ROUNDUP32` in `bsd/net/rtsock.c`), `sizeof(long)` on
/// FreeBSD (`SA_SIZE` in `net/route.h`).
#[cfg(target_os = "macos")]
const SA_ALIGN: usize = 4;
/// The alignment each socket address in a routing message is padded to:
/// 4 bytes on XNU (`ROUNDUP32` in `bsd/net/rtsock.c`), `sizeof(long)` on
/// FreeBSD (`SA_SIZE` in `net/route.h`).
#[cfg(target_os = "freebsd")]
const SA_ALIGN: usize = size_of::<libc::c_long>();

/// The space a socket address of `len` bytes takes in a routing message.
pub(crate) fn sa_space(len: usize) -> usize {
    if len == 0 {
        SA_ALIGN
    } else {
        1 + ((len - 1) | (SA_ALIGN - 1))
    }
}

/// Read an integer sysctl by name.
///
/// A name the kernel does not know is `ENOENT`, kept as the error's raw code.
pub(crate) fn sysctl_int(name: &str) -> io::Result<c_int> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "sysctl name holds a NUL"))?;
    let mut value: c_int = 0;
    let mut len = size_of::<c_int>();
    // SAFETY: `cname` is NUL-terminated, and `value`/`len` describe a buffer
    // of exactly `len` bytes that outlives the call.
    let rc = unsafe {
        libc::sysctlbyname(
            cname.as_ptr(),
            (&mut value as *mut c_int).cast(),
            &mut len,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    if len != size_of::<c_int>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("sysctl {name} is {len} bytes, not an int"),
        ));
    }
    Ok(value)
}

/// Copy an interface name into the fixed `IFNAMSIZ` field the ioctls take.
fn ifname(name: &str) -> io::Result<[c_char; libc::IFNAMSIZ]> {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid interface name {name:?}"),
        ));
    }
    let mut out = [0 as c_char; libc::IFNAMSIZ];
    for (dst, src) in out.iter_mut().zip(bytes) {
        *dst = *src as c_char;
    }
    Ok(out)
}

/// A `sockaddr_in6` holding `addr`, with the BSD length byte set.
fn sockaddr6(addr: Ipv6Addr) -> libc::sockaddr_in6 {
    // SAFETY: `sockaddr_in6` is plain data; all-zero is a valid value.
    let mut sa: libc::sockaddr_in6 = unsafe { zeroed() };
    sa.sin6_len = size_of::<libc::sockaddr_in6>() as u8;
    sa.sin6_family = libc::AF_INET6 as libc::sa_family_t;
    sa.sin6_addr.s6_addr = addr.octets();
    sa
}

/// The netmask of an IPv6 prefix `len` bits long.
pub(crate) fn prefix_mask(len: u8) -> Ipv6Addr {
    let len = u32::from(len.min(128));
    let bits = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    Ipv6Addr::from(bits)
}

/// An `AF_INET6` datagram socket, the handle the interface ioctls go to.
fn inet6_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the result is checked before it is owned.
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this function alone holds.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Run one ioctl on `sock`, returning the kernel's error.
///
/// # Safety
///
/// `arg` must point to the structure `request` expects, sized as the
/// request number encodes.
unsafe fn ioctl<T>(sock: &OwnedFd, request: c_ulong, arg: *mut T) -> io::Result<()> {
    // SAFETY: the caller guarantees `arg` matches `request`.
    if unsafe { libc::ioctl(sock.as_raw_fd(), request, arg) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Add `addr/prefix_len` to interface `name`, with infinite lifetimes, as
/// `ifconfig <name> inet6 <addr> prefixlen <prefix_len>` does.
///
/// Adding an address the interface already has updates it in place and is
/// not an error.
pub(crate) fn add_address(name: &str, addr: Ipv6Addr, prefix_len: u8) -> io::Result<()> {
    // SAFETY: `In6Aliasreq` is plain data; all-zero is a valid value.
    let mut req: In6Aliasreq = unsafe { zeroed() };
    req.ifra_name = ifname(name)?;
    req.ifra_addr = sockaddr6(addr);
    req.ifra_prefixmask = sockaddr6(prefix_mask(prefix_len));
    req.ifra_lifetime.ia6t_vltime = INFINITE_LIFETIME;
    req.ifra_lifetime.ia6t_pltime = INFINITE_LIFETIME;
    let sock = inet6_socket()?;
    // SAFETY: `req` is the `in6_aliasreq` this request number encodes.
    unsafe { ioctl(&sock, SIOCAIFADDR_IN6, &mut req) }
}

/// Clear `ND6_IFF_IFDISABLED` on interface `name`, as
/// `ifconfig <name> inet6 -ifdisabled` does.
#[cfg(target_os = "freebsd")]
pub(crate) fn enable_inet6(name: &str) -> io::Result<()> {
    // SAFETY: `In6Ndireq` is plain data; all-zero is a valid value.
    let mut req: In6Ndireq = unsafe { zeroed() };
    req.ifname = ifname(name)?;
    let sock = inet6_socket()?;
    // SAFETY: `req` is the `in6_ndireq` both request numbers encode.
    unsafe { ioctl(&sock, SIOCGIFINFO_IN6, &mut req)? };
    if req.ndi.flags & IFDISABLED == 0 {
        return Ok(());
    }
    req.ndi.flags &= !IFDISABLED;
    // SAFETY: as above.
    unsafe { ioctl(&sock, SIOCSIFINFO_IN6, &mut req) }
}

/// Set or clear `IFF_UP` on interface `name`, keeping every other flag, as
/// `ifconfig <name> up` and `ifconfig <name> down` do.
pub(crate) fn set_up(name: &str, up: bool) -> io::Result<()> {
    // SAFETY: `ifreq` is plain data; all-zero is a valid value.
    let mut req: libc::ifreq = unsafe { zeroed() };
    req.ifr_name = ifname(name)?;
    let sock = inet6_socket()?;
    // SAFETY: `req` is the `ifreq` both request numbers encode.
    unsafe { ioctl(&sock, SIOCGIFFLAGS, &mut req)? };
    let flag = libc::IFF_UP as libc::c_short;
    // SAFETY: SIOCGIFFLAGS filled the flags member of the union. On FreeBSD
    // it is two shorts, low and high; IFF_UP is in the low one and the high
    // one is written back unchanged.
    unsafe {
        #[cfg(target_os = "freebsd")]
        let flags = &mut req.ifr_ifru.ifru_flags[0];
        #[cfg(target_os = "macos")]
        let flags = &mut req.ifr_ifru.ifru_flags;
        if up {
            *flags |= flag;
        } else {
            *flags &= !flag;
        }
    }
    // SAFETY: as above.
    unsafe { ioctl(&sock, SIOCSIFFLAGS, &mut req) }
}

/// The kernel index of interface `name`.
pub(crate) fn interface_index(name: &str) -> io::Result<u32> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name holds a NUL"))?;
    // SAFETY: `cname` is NUL-terminated and outlives the call.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(index)
}

/// The name of the interface with kernel index `index`, or `None` when no
/// interface has it (it may have gone since the index was read).
pub(crate) fn interface_name(index: u32) -> Option<String> {
    let mut buf = [0 as c_char; libc::IFNAMSIZ];
    // SAFETY: `buf` is the IFNAMSIZ bytes if_indextoname may write.
    let name = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if name.is_null() {
        return None;
    }
    // SAFETY: on success `buf` holds a NUL-terminated name.
    let name = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Some(name.to_string_lossy().into_owned())
}

/// An interface as a message names it: `interface utun3 (index 12)`, or
/// the index alone when no interface has that index any more.
fn interface_label(index: u32) -> String {
    match interface_name(index) {
        Some(name) => format!("interface {name} (index {index})"),
        None => format!("interface index {index}"),
    }
}

/// What a route add found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteAdd {
    /// The kernel added the route.
    Added,
    /// A route for exactly this prefix was already present (`EEXIST`).
    Exists,
}

/// Copy the bytes of a plain-data value onto the end of `buf`, padded to
/// the routing message's socket address alignment.
fn push_sockaddr<T>(buf: &mut Vec<u8>, sa: &T, sa_len: usize) {
    // SAFETY: `T` is a plain-data socket address of at least `sa_len` bytes.
    let bytes = unsafe { std::slice::from_raw_parts((sa as *const T).cast::<u8>(), sa_len) };
    buf.extend_from_slice(bytes);
    buf.resize(buf.len() + sa_space(sa_len) - sa_len, 0);
}

/// Build a routing message of type `kind` for `dst/prefix_len`, with the
/// interface of index `ifindex` as its gateway when one is given.
///
/// The message is what `route add -inet6 <dst> -prefixlen <len> -interface
/// <if>` sends: `RTF_UP | RTF_STATIC`, and a link-level gateway naming the
/// interface by index (the kernel finds the interface from `sdl_index`).
/// Socket addresses follow the header in `RTA_*` bit order, each padded to
/// [`SA_ALIGN`].
pub(crate) fn route_message(
    kind: c_int,
    seq: c_int,
    dst: Ipv6Addr,
    prefix_len: u8,
    ifindex: Option<u32>,
) -> io::Result<Vec<u8>> {
    let header = size_of::<RtMsghdr>();
    let mut buf = vec![0u8; header];
    let dst_sa = sockaddr6(dst);
    push_sockaddr(&mut buf, &dst_sa, size_of::<libc::sockaddr_in6>());
    let mut addrs = libc::RTA_DST;
    if let Some(index) = ifindex {
        let index = u16::try_from(index).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "interface index above 65535")
        })?;
        // SAFETY: `sockaddr_dl` is plain data; all-zero is a valid value.
        let mut gw: libc::sockaddr_dl = unsafe { zeroed() };
        gw.sdl_len = size_of::<libc::sockaddr_dl>() as u8;
        gw.sdl_family = libc::AF_LINK as u8;
        gw.sdl_index = index;
        push_sockaddr(&mut buf, &gw, size_of::<libc::sockaddr_dl>());
        addrs |= libc::RTA_GATEWAY;
    }
    let mask_sa = sockaddr6(prefix_mask(prefix_len));
    push_sockaddr(&mut buf, &mask_sa, size_of::<libc::sockaddr_in6>());
    addrs |= libc::RTA_NETMASK;

    let msglen = u16::try_from(buf.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "routing message too long"))?;
    // SAFETY: `RtMsghdr` is plain data; all-zero is a valid value.
    let mut hdr: RtMsghdr = unsafe { zeroed() };
    hdr.rtm_msglen = msglen;
    hdr.rtm_version = RTM_VERSION;
    hdr.rtm_type = kind as u8;
    hdr.rtm_flags = libc::RTF_UP | libc::RTF_STATIC;
    hdr.rtm_addrs = addrs;
    hdr.rtm_seq = seq;
    // SAFETY: `hdr` is `header` bytes of plain data.
    let hdr_bytes =
        unsafe { std::slice::from_raw_parts((&hdr as *const RtMsghdr).cast::<u8>(), header) };
    buf[..header].copy_from_slice(hdr_bytes);
    Ok(buf)
}

/// A `PF_ROUTE` socket for IPv6 routes.
fn route_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket(2); the result is checked before it is owned.
    let fd = unsafe { libc::socket(libc::PF_ROUTE, libc::SOCK_RAW, libc::AF_INET6) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh descriptor this function alone holds.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Write one routing message; the kernel reports a refused change as the
/// write's error.
fn route_write(sock: &OwnedFd, msg: &[u8]) -> io::Result<()> {
    // SAFETY: `msg` is a valid buffer of `msg.len()` bytes.
    let n = unsafe { libc::write(sock.as_raw_fd(), msg.as_ptr().cast(), msg.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    if n as usize != msg.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "short routing socket write",
        ));
    }
    Ok(())
}

/// Add a route for `dst/prefix_len` through interface `ifindex`.
///
/// `EEXIST`, a route for exactly this prefix already present, is returned as
/// [`RouteAdd::Exists`]; every other refusal is the kernel's error.
pub(crate) fn add_route(dst: Ipv6Addr, prefix_len: u8, ifindex: u32) -> io::Result<RouteAdd> {
    let msg = route_message(libc::RTM_ADD, 1, dst, prefix_len, Some(ifindex))?;
    let sock = route_socket()?;
    match route_write(&sock, &msg) {
        Ok(()) => Ok(RouteAdd::Added),
        Err(e) if e.raw_os_error() == Some(libc::EEXIST) => Ok(RouteAdd::Exists),
        Err(e) => Err(e),
    }
}

/// Make sure the route for `dst/prefix_len` goes through interface
/// `ifindex`, adding it if absent.
///
/// A route for that prefix already present is accepted when it goes through
/// this interface, as when the interface is configured a second time. One
/// through another interface is refused with
/// [`io::ErrorKind::AlreadyExists`], since accepting it would leave the
/// traffic going elsewhere while setup reported success.
pub(crate) fn ensure_route(dst: Ipv6Addr, prefix_len: u8, ifindex: u32) -> io::Result<()> {
    if add_route(dst, prefix_len, ifindex)? == RouteAdd::Added {
        return Ok(());
    }
    match route_interface(dst, prefix_len)? {
        Some(index) if index == ifindex => Ok(()),
        Some(index) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "a route for {dst}/{prefix_len} already goes through {}",
                interface_label(index)
            ),
        )),
        // Removed between the add and the lookup: add once more, and treat
        // a second collision as the error it now is.
        None => match add_route(dst, prefix_len, ifindex)? {
            RouteAdd::Added => Ok(()),
            RouteAdd::Exists => Err(io::Error::from_raw_os_error(libc::EEXIST)),
        },
    }
}

/// Delete the route for exactly `dst/prefix_len`. Returns `false` when there
/// was none (`ESRCH`). Only the tests remove routes; a stop does not remove
/// the mesh route.
#[cfg(test)]
pub(crate) fn delete_route(dst: Ipv6Addr, prefix_len: u8) -> io::Result<bool> {
    let msg = route_message(libc::RTM_DELETE, 1, dst, prefix_len, None)?;
    let sock = route_socket()?;
    match route_write(&sock, &msg) {
        Ok(()) => Ok(true),
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Ok(false),
        Err(e) => Err(e),
    }
}

/// The interface index of the route for exactly `dst/prefix_len`, or `None`
/// when there is none (`ESRCH`).
///
/// Sends `RTM_GET` with the netmask, so the kernel looks up that prefix
/// rather than the longest match, and reads the reply carrying this
/// process's id and the request's sequence number. Both kernels put the
/// route's interface in the reply's `rtm_index`.
pub(crate) fn route_interface(dst: Ipv6Addr, prefix_len: u8) -> io::Result<Option<u32>> {
    const SEQ: c_int = 0x4650; // arbitrary; only this socket's replies are read
    let msg = route_message(libc::RTM_GET, SEQ, dst, prefix_len, None)?;
    let sock = route_socket()?;
    let timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    // SAFETY: `timeout` is a `timeval` of the size passed.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    match route_write(&sock, &msg) {
        Ok(()) => {}
        Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Ok(None),
        Err(e) => return Err(e),
    }
    // SAFETY: getpid(2) cannot fail.
    let pid = unsafe { libc::getpid() };
    let mut buf = vec![0u8; 2048];
    // Other processes' routing messages can arrive on this socket too; read
    // a bounded number looking for the reply.
    for _ in 0..64 {
        // SAFETY: `buf` is a valid buffer of `buf.len()` bytes.
        let n = unsafe { libc::read(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if (n as usize) < size_of::<RtMsghdr>() {
            continue;
        }
        // SAFETY: at least a header's worth of bytes was read; the copy has
        // no alignment requirement.
        let hdr: RtMsghdr = unsafe { std::ptr::read_unaligned(buf.as_ptr().cast()) };
        if c_int::from(hdr.rtm_type) != libc::RTM_GET || hdr.rtm_pid != pid || hdr.rtm_seq != SEQ {
            continue;
        }
        if hdr.rtm_errno != 0 {
            if hdr.rtm_errno == libc::ESRCH {
                return Ok(None);
            }
            return Err(io::Error::from_raw_os_error(hdr.rtm_errno));
        }
        return Ok(Some(u32::from(hdr.rtm_index)));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "no RTM_GET reply among 64 routing messages",
    ))
}

#[cfg(test)]
#[path = "tests/bsdnet.rs"]
mod tests;
