//! Host interface and route configuration on Windows through the IP Helper
//! API.
//!
//! The Wintun adapter needs three things from the host: its `/128` address
//! (`CreateUnicastIpAddressEntry`), its IPv6 MTU (`GetIpInterfaceEntry` and
//! `SetIpInterfaceEntry`), and a route for `fd00::/8` through it
//! (`CreateIpForwardEntry2`, and `DeleteIpForwardEntry2` at stop). Each call
//! returns its Win32 error code as an [`io::Error`], so callers decide what
//! is benign by code (`ERROR_OBJECT_ALREADY_EXISTS`, `ERROR_NOT_FOUND`)
//! rather than by matching `netsh`'s output, which is in the system's
//! language. Interfaces are named by their LUID, the identity IP Helper
//! keys every row on.

use std::io;
use std::net::Ipv6Addr;

use windows_sys::Win32::Foundation::{
    ERROR_FILE_NOT_FOUND, ERROR_NOT_FOUND, ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR, WIN32_ERROR,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, CreateIpForwardEntry2, CreateUnicastIpAddressEntry,
    DeleteIpForwardEntry2, GetIpInterfaceEntry, InitializeIpForwardEntry,
    InitializeIpInterfaceEntry, InitializeUnicastIpAddressEntry, MIB_IPFORWARD_ROW2,
    MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW, SetIpInterfaceEntry,
};
use windows_sys::Win32::NetworkManagement::Ndis::NET_LUID_LH;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET6, IpPrefixOriginManual, IpSuffixOriginManual, MIB_IPPROTO_NETMGMT, SOCKADDR_INET,
};

/// The route metric `netsh interface ipv6 add route` uses when none is given.
const ROUTE_METRIC: u32 = 256;

/// What a create call found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Created {
    /// The row was created.
    Added,
    /// An identical row was already present (`ERROR_OBJECT_ALREADY_EXISTS`).
    Exists,
}

/// Turn a Win32 return code into a result, keeping the code.
fn check(code: WIN32_ERROR) -> io::Result<()> {
    if code == NO_ERROR {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

/// Map `ERROR_OBJECT_ALREADY_EXISTS` to [`Created::Exists`].
fn created(code: WIN32_ERROR) -> io::Result<Created> {
    if code == ERROR_OBJECT_ALREADY_EXISTS {
        return Ok(Created::Exists);
    }
    check(code).map(|()| Created::Added)
}

/// A LUID from its 64-bit value.
fn luid(value: u64) -> NET_LUID_LH {
    NET_LUID_LH { Value: value }
}

/// A `SOCKADDR_INET` holding `addr`.
fn sockaddr6(addr: Ipv6Addr) -> SOCKADDR_INET {
    let mut sa = SOCKADDR_INET::default();
    // Writing a union member is safe; it is the reads that are not.
    sa.Ipv6.sin6_family = AF_INET6;
    sa.Ipv6.sin6_addr.u.Byte = addr.octets();
    sa
}

/// The LUID of the interface whose alias (the name shown in network
/// settings) is `alias`.
pub(crate) fn alias_luid(alias: &str) -> io::Result<u64> {
    let wide: Vec<u16> = alias.encode_utf16().chain(std::iter::once(0)).collect();
    let mut out = luid(0);
    // SAFETY: `wide` is NUL-terminated and `out` is a valid LUID to fill.
    check(unsafe { ConvertInterfaceAliasToLuid(wide.as_ptr(), &mut out) })?;
    // SAFETY: every bit pattern of the union is a valid u64.
    Ok(unsafe { out.Value })
}

/// The IPv6 interface row of interface `luid_value`.
///
/// `ERROR_NOT_FOUND` means the interface has no IPv6 stack bound, or does
/// not exist (yet).
fn ipv6_interface(luid_value: u64) -> io::Result<MIB_IPINTERFACE_ROW> {
    let mut row = MIB_IPINTERFACE_ROW::default();
    // SAFETY: `row` is a valid row to initialise and fill.
    unsafe { InitializeIpInterfaceEntry(&mut row) };
    row.Family = AF_INET6;
    row.InterfaceLuid = luid(luid_value);
    // SAFETY: as above.
    check(unsafe { GetIpInterfaceEntry(&mut row) })?;
    Ok(row)
}

/// Whether interface `luid_value` has an IPv6 interface row yet.
///
/// A new Wintun adapter is registered with the IP stack shortly after it is
/// created; `false` is `GetIpInterfaceEntry` answering `ERROR_NOT_FOUND` or
/// `ERROR_FILE_NOT_FOUND`, the codes it gives for an interface it does not
/// (yet) know. They persist when IPv6 is not bound to the adapter at all, so
/// the caller bounds its wait.
pub(crate) fn ipv6_present(luid_value: u64) -> io::Result<bool> {
    match ipv6_interface(luid_value) {
        Ok(_) => Ok(true),
        Err(e) if missing(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Whether `e` is one of the codes IP Helper gives for a missing row or
/// interface.
fn missing(e: &io::Error) -> bool {
    matches!(e.raw_os_error(), Some(c) if c == ERROR_NOT_FOUND as i32 || c == ERROR_FILE_NOT_FOUND as i32)
}

/// Set the IPv6 MTU of interface `luid_value`, as `netsh interface ipv6 set
/// subinterface <if> mtu=<mtu>` does.
pub(crate) fn set_mtu(luid_value: u64, mtu: u32) -> io::Result<()> {
    let mut row = ipv6_interface(luid_value)?;
    row.NlMtu = mtu;
    // SAFETY: `row` is the row GetIpInterfaceEntry filled, changed in NlMtu.
    check(unsafe { SetIpInterfaceEntry(&mut row) })
}

/// The IPv6 MTU of interface `luid_value`.
#[cfg(test)]
pub(crate) fn mtu(luid_value: u64) -> io::Result<u32> {
    Ok(ipv6_interface(luid_value)?.NlMtu)
}

/// The unicast address row for `addr/prefix_len` on interface `luid_value`.
fn address_row(luid_value: u64, addr: Ipv6Addr, prefix_len: u8) -> MIB_UNICASTIPADDRESS_ROW {
    let mut row = MIB_UNICASTIPADDRESS_ROW::default();
    // SAFETY: `row` is a valid row to initialise; this sets infinite
    // lifetimes and the other defaults.
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.Address = sockaddr6(addr);
    row.InterfaceLuid = luid(luid_value);
    row.OnLinkPrefixLength = prefix_len;
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;
    row
}

/// Add `addr/prefix_len` to interface `luid_value`, as `netsh interface ipv6
/// add address` does. The address already being there is
/// [`Created::Exists`].
pub(crate) fn add_address(luid_value: u64, addr: Ipv6Addr, prefix_len: u8) -> io::Result<Created> {
    let row = address_row(luid_value, addr, prefix_len);
    // SAFETY: `row` is a fully initialised row.
    created(unsafe { CreateUnicastIpAddressEntry(&row) })
}

/// Remove `addr` from interface `luid_value`. Returns `false` when it was
/// not there.
#[cfg(test)]
pub(crate) fn delete_address(luid_value: u64, addr: Ipv6Addr) -> io::Result<bool> {
    use windows_sys::Win32::NetworkManagement::IpHelper::DeleteUnicastIpAddressEntry;
    let row = address_row(luid_value, addr, 128);
    // SAFETY: `row` is a fully initialised row.
    match check(unsafe { DeleteUnicastIpAddressEntry(&row) }) {
        Ok(()) => Ok(true),
        Err(e) if missing(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// The on-link route row for `dst/prefix_len` on interface `luid_value`.
fn route_row(luid_value: u64, dst: Ipv6Addr, prefix_len: u8) -> MIB_IPFORWARD_ROW2 {
    let mut row = MIB_IPFORWARD_ROW2::default();
    // SAFETY: `row` is a valid row to initialise; this sets infinite
    // lifetimes and the other defaults.
    unsafe { InitializeIpForwardEntry(&mut row) };
    row.InterfaceLuid = luid(luid_value);
    row.DestinationPrefix.Prefix = sockaddr6(dst);
    row.DestinationPrefix.PrefixLength = prefix_len;
    // The unspecified address as next hop: on-link through the interface.
    row.NextHop = sockaddr6(Ipv6Addr::UNSPECIFIED);
    row.Metric = ROUTE_METRIC;
    row.Protocol = MIB_IPPROTO_NETMGMT;
    row
}

/// Add an on-link route for `dst/prefix_len` through interface `luid_value`,
/// as `netsh interface ipv6 add route <prefix> <if>` does.
///
/// A route row is keyed on its prefix, next hop and interface, so
/// [`Created::Exists`] means this very route through this interface was
/// already present; a route for the prefix through another interface is a
/// separate row and does not collide.
pub(crate) fn add_route(luid_value: u64, dst: Ipv6Addr, prefix_len: u8) -> io::Result<Created> {
    let row = route_row(luid_value, dst, prefix_len);
    // SAFETY: `row` is a fully initialised row.
    created(unsafe { CreateIpForwardEntry2(&row) })
}

/// Delete the route for `dst/prefix_len` through interface `luid_value`.
/// Returns `false` when there was no such route or no such interface (the
/// adapter may already be gone at stop).
pub(crate) fn delete_route(luid_value: u64, dst: Ipv6Addr, prefix_len: u8) -> io::Result<bool> {
    let row = route_row(luid_value, dst, prefix_len);
    // SAFETY: `row` is a fully initialised row.
    match check(unsafe { DeleteIpForwardEntry2(&row) }) {
        Ok(()) => Ok(true),
        Err(e) if missing(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "tests/winnet.rs"]
mod tests;
