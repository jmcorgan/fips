//! Local-candidate selection: which of this host's own addresses a traversal
//! offers a peer as same-LAN candidates.
//!
//! The shell reads the host (the interface list, and the local address of
//! each probe and wildcard bind) and hands the raw results here; selection
//! filters, orders and deduplicates them.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::IpAddr;

/// The probes whose local address is a candidate: a UDP socket bound to the
/// first address and connected to the second, which sends nothing but makes
/// the host pick the source address it would route from.
pub const PROBES: [(&str, &str); 2] = [
    ("0.0.0.0:0", "8.8.8.8:80"),
    ("[::]:0", "[2001:4860:4860::8888]:80"),
];

/// The wildcard hosts bound on the traversal port, whose local address is a
/// candidate.
pub const WILDCARDS: [&str; 2] = ["0.0.0.0", "::"];

/// One address from the host's interface list, with the two flags selection
/// reads, in the order the host listed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceAddr {
    /// The interface address.
    pub ip: IpAddr,
    /// The interface is up.
    pub up: bool,
    /// The interface is a loopback interface.
    pub loopback: bool,
}

/// Addresses an interface may offer as a same-LAN candidate: private IPv4
/// and unique-local IPv6.
pub fn is_private_overlay_candidate_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private(),
        IpAddr::V6(v6) => v6.is_unique_local(),
    }
}

/// The candidates to offer, as text: the private addresses of every up,
/// non-loopback interface in listing order, then each address in `observed`
/// (the probes', then the wildcard binds', each `None` where the read
/// failed). An unspecified address is dropped and a repeat is kept once.
pub fn local_candidates(interfaces: &[InterfaceAddr], observed: &[Option<IpAddr>]) -> Vec<String> {
    let mut addresses = Vec::new();
    for entry in interfaces {
        if entry.up && !entry.loopback && is_private_overlay_candidate_ip(entry.ip) {
            push_ip(&mut addresses, entry.ip);
        }
    }
    for ip in observed.iter().flatten() {
        push_ip(&mut addresses, *ip);
    }
    addresses
}

/// Append `ip` as text unless it is unspecified or already present.
fn push_ip(addresses: &mut Vec<String>, ip: IpAddr) {
    if ip.is_unspecified() {
        return;
    }
    let ip = ip.to_string();
    if !addresses.contains(&ip) {
        addresses.push(ip);
    }
}

#[cfg(test)]
#[path = "tests/candidates.rs"]
mod tests;
