//! The local overlay advert, assembled from the node's transports.
//!
//! The node snapshots each operational transport's advertisable inputs; this
//! turns the snapshot into the advert body this node publishes, with the
//! public address learned for each advertised public UDP transport bound to
//! a wildcard. Learning that address is the shell's (a STUN exchange), so
//! [`learned_wanted`] names the transports that need one and [`assemble`]
//! takes what was learned. What an operator should hear about, a transport
//! that could not be advertised, comes back as an [`AssemblyNote`] for the
//! shell to log.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::net::SocketAddr;

use super::super::types::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert, OverlayTransportKind,
};

/// Snapshot of a single operational transport's advertisable endpoint
/// inputs, captured on `Node` at advert-build time so the advert can be
/// assembled without borrowing the transport table.
/// Only transports whose type matched a configured listener are included;
/// the `advertise` gate is carried verbatim so the assembly reproduces the
/// original per-transport branch logic exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdvertTransportSnapshot {
    Udp {
        advertise: bool,
        is_public: bool,
        external_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
        transport_key: u32,
    },
    Tcp {
        advertise: bool,
        external_addr: Option<SocketAddr>,
        local_addr: Option<SocketAddr>,
    },
    Tor {
        advertise: bool,
        onion_addr: Option<String>,
        advertised_port: u16,
    },
}

/// A transport the assembly left out of the advert, for the shell to warn
/// about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssemblyNote {
    /// An advertised public UDP transport bound to a wildcard, with no
    /// external address, whose public address was not learned.
    UdpUnlearned {
        transport_id: u32,
        bind_addr: SocketAddr,
    },
    /// An advertised TCP transport bound to a wildcard with no external
    /// address. TCP has no STUN equivalent, so it is never advertised.
    TcpWildcard { bind_addr: SocketAddr },
}

/// What one assembly gave: the advert, or `None` when no transport
/// contributed an endpoint, and the transports it left out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assembly {
    pub advert: Option<OverlayAdvert>,
    pub notes: Vec<AssemblyNote>,
}

/// The transport key and port of each transport whose public address must
/// be learned before the advert can name it: an advertised, public UDP
/// transport bound to a wildcard with no external address. In snapshot
/// order.
pub fn learned_wanted(snapshot: &[AdvertTransportSnapshot]) -> Vec<(u32, u16)> {
    snapshot
        .iter()
        .filter_map(|entry| match entry {
            AdvertTransportSnapshot::Udp {
                advertise: true,
                is_public: true,
                external_addr: None,
                local_addr: Some(addr),
                transport_key,
            } if addr.ip().is_unspecified() => Some((*transport_key, addr.port())),
            _ => None,
        })
        .collect()
}

/// The advert `snapshot` gives, with `learned` holding the public address
/// learned for each transport key [`learned_wanted`] named (`None`, or no
/// entry, when none was). A transport that names `udp:nat` brings the
/// signal relays (`dm_relays`) and the STUN servers into the advert.
///
/// Precedence for a public UDP transport: its external address, then a
/// specific (non-wildcard) bind address, then the learned address, else
/// it is left out with a note. For TCP: its external address, then a
/// specific bind address, else left out with a note. A Tor transport is
/// advertised by its onion address and port once it has one.
pub fn assemble(
    snapshot: &[AdvertTransportSnapshot],
    learned: &BTreeMap<u32, Option<SocketAddr>>,
    dm_relays: &[String],
    stun_servers: &[String],
) -> Assembly {
    let mut endpoints = Vec::new();
    let mut notes = Vec::new();
    let mut has_udp_nat = false;
    let endpoint = |transport, addr: String| OverlayEndpointAdvert { transport, addr };

    for entry in snapshot {
        match entry {
            AdvertTransportSnapshot::Udp {
                advertise,
                is_public,
                external_addr,
                local_addr,
                transport_key,
            } => {
                if !advertise {
                    continue;
                }
                if !is_public {
                    endpoints.push(endpoint(OverlayTransportKind::Udp, "nat".to_string()));
                    has_udp_nat = true;
                    continue;
                }
                if let Some(explicit) = external_addr {
                    endpoints.push(endpoint(OverlayTransportKind::Udp, explicit.to_string()));
                    continue;
                }
                match local_addr {
                    Some(addr) if !addr.ip().is_unspecified() => {
                        endpoints.push(endpoint(OverlayTransportKind::Udp, addr.to_string()));
                    }
                    Some(addr) => match learned.get(transport_key).copied().flatten() {
                        Some(public) => {
                            endpoints.push(endpoint(OverlayTransportKind::Udp, public.to_string()));
                        }
                        None => notes.push(AssemblyNote::UdpUnlearned {
                            transport_id: *transport_key,
                            bind_addr: *addr,
                        }),
                    },
                    None => {}
                }
            }
            AdvertTransportSnapshot::Tcp {
                advertise,
                external_addr,
                local_addr,
            } => {
                if !advertise {
                    continue;
                }
                if let Some(explicit) = external_addr {
                    endpoints.push(endpoint(OverlayTransportKind::Tcp, explicit.to_string()));
                    continue;
                }
                match local_addr {
                    Some(addr) if !addr.ip().is_unspecified() => {
                        endpoints.push(endpoint(OverlayTransportKind::Tcp, addr.to_string()));
                    }
                    Some(addr) => notes.push(AssemblyNote::TcpWildcard { bind_addr: *addr }),
                    None => {}
                }
            }
            AdvertTransportSnapshot::Tor {
                advertise,
                onion_addr,
                advertised_port,
            } => {
                if !advertise {
                    continue;
                }
                if let Some(addr) = onion_addr {
                    endpoints.push(endpoint(
                        OverlayTransportKind::Tor,
                        format!("{}:{}", addr, advertised_port),
                    ));
                }
            }
        }
    }

    let advert = (!endpoints.is_empty()).then(|| OverlayAdvert {
        identifier: ADVERT_IDENTIFIER.to_string(),
        version: ADVERT_VERSION,
        endpoints,
        signal_relays: has_udp_nat.then(|| dm_relays.to_vec()),
        stun_servers: has_udp_nat.then(|| stun_servers.to_vec()),
    });
    Assembly { advert, notes }
}

#[cfg(test)]
#[path = "tests/assemble.rs"]
mod tests;
