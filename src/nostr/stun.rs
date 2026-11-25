//! The host reads a traversal's local candidates need: the interface list,
//! and the local address of each probe and wildcard bind. The STUN exchange
//! and the selection are the machine's (`machine/stun/`).

use std::net::IpAddr;

use super::machine::rendezvous::Interfaces;
#[cfg(test)]
use super::machine::stun::candidates::offerable;
use super::machine::stun::candidates::{self, InterfaceAddr};
#[cfg(test)]
use super::machine::stun::client::pick_family;
#[cfg(test)]
pub(super) use super::machine::stun::{parse_stun_binding_success, parse_stun_url};

/// This host's raw reads for a traversal socket bound on `port`: every
/// interface address with its flags, and the local address of each probe
/// and of each wildcard bind on `port`. The machine selects the candidates
/// to offer from them (`machine/stun/candidates.rs`).
pub(super) fn read_candidates(port: u16) -> Interfaces {
    let mut observed = Vec::new();
    for (bind_addr, connect_addr) in candidates::PROBES {
        observed.push(local_probe(bind_addr, connect_addr));
    }
    for host in candidates::WILDCARDS {
        observed.push(bound_addr((host, port)));
    }
    Interfaces::Candidates {
        entries: interface_addrs(),
        observed,
    }
}

/// Every IPv4 and IPv6 address in the host's interface list, in listing
/// order, with its interface's up and loopback flags.
#[cfg(unix)]
fn interface_addrs() -> Vec<InterfaceAddr> {
    let mut output = Vec::new();
    let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();

    // SAFETY: `getifaddrs` initializes `ifaddrs` on success, and the linked
    // list is valid until `freeifaddrs` is called.
    let rc = unsafe { libc::getifaddrs(&mut ifaddrs) };
    if rc != 0 || ifaddrs.is_null() {
        return output;
    }

    let mut cursor = ifaddrs;
    while !cursor.is_null() {
        // SAFETY: `cursor` points at a valid node from the `getifaddrs` list.
        let entry = unsafe { &*cursor };
        let flags = entry.ifa_flags as i32;

        if !entry.ifa_addr.is_null() {
            // SAFETY: `ifa_addr` is non-null and its concrete type matches
            // `sa_family` for this entry.
            let maybe_ip = unsafe {
                match (*entry.ifa_addr).sa_family as i32 {
                    libc::AF_INET => {
                        let sockaddr = &*(entry.ifa_addr as *const libc::sockaddr_in);
                        Some(IpAddr::V4(std::net::Ipv4Addr::from(
                            sockaddr.sin_addr.s_addr.to_ne_bytes(),
                        )))
                    }
                    libc::AF_INET6 => {
                        let sockaddr = &*(entry.ifa_addr as *const libc::sockaddr_in6);
                        Some(IpAddr::V6(std::net::Ipv6Addr::from(
                            sockaddr.sin6_addr.s6_addr,
                        )))
                    }
                    _ => None,
                }
            };

            if let Some(ip) = maybe_ip {
                output.push(InterfaceAddr {
                    ip,
                    up: (flags & libc::IFF_UP) != 0,
                    loopback: (flags & libc::IFF_LOOPBACK) != 0,
                });
            }
        }

        cursor = entry.ifa_next;
    }

    // SAFETY: `ifaddrs` came from `getifaddrs` and has not yet been freed.
    unsafe { libc::freeifaddrs(ifaddrs) };
    output
}

#[cfg(not(unix))]
fn interface_addrs() -> Vec<InterfaceAddr> {
    Vec::new()
}

/// The local address the host picks for a UDP socket bound to `bind_addr`
/// and connected to `connect_addr`, if both steps succeed.
fn local_probe(bind_addr: &str, connect_addr: &str) -> Option<IpAddr> {
    let socket = std::net::UdpSocket::bind(bind_addr).ok()?;
    socket.connect(connect_addr).ok()?;
    socket.local_addr().ok().map(|local_addr| local_addr.ip())
}

/// The local address of a UDP socket bound to `bind_addr`, if the bind
/// succeeds.
fn bound_addr<A: std::net::ToSocketAddrs>(bind_addr: A) -> Option<IpAddr> {
    std::net::UdpSocket::bind(bind_addr)
        .and_then(|socket| socket.local_addr())
        .ok()
        .map(|local_addr| local_addr.ip())
}

#[cfg(test)]
#[path = "tests/stun.rs"]
mod tests;
