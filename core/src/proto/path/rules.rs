//! Path policy (multipath v1 draft, Section 5.5): which transports a link's
//! paths may run over. A link's paths keep to the anonymity class of its
//! original path and, unless the node mixes kinds, to its kind; a
//! transport whose role is never takes no new path, though one held from
//! before stays; a candidate is probed only where the node would dial the
//! peer, and a received probe creates a path only where it would accept
//! the peer's handshake.
//!
//! Every function reads the facts the host gives at the moment it is
//! called and keeps nothing, so a change in the facts governs the next
//! decision. None allocates: an address is parsed in place.

use core::net::{IpAddr, Ipv4Addr, SocketAddr};
use core::str::FromStr;

use super::{Class, Facts, Kind, Role};
use crate::transport::{TransportAddr, TransportId};

/// The rule that refused a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    /// The transport is of another anonymity class than the link's.
    Class,
    /// The path is of another kind than the link's, and kinds are not
    /// mixed.
    Kind,
    /// The transport's role is never to carry a path.
    Role,
    /// The node would refuse the peer's handshake initiation on the
    /// transport.
    Accept,
    /// The node would not initiate a handshake to the peer on the
    /// transport.
    Dial,
}

/// A link's anonymity class and kind: its original path's, fixed when the
/// bundle is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    /// The anonymity class.
    pub class: Class,
    /// The kind.
    pub kind: Kind,
}

/// The scope of the peer's address `addr`: local for a loopback,
/// link-local, private (RFC 1918) or unique-local address, an IPv4-mapped
/// IPv6 address taking its IPv4 address's scope, and Internet for every
/// other address, a host name, a MAC address and anything that does not
/// parse as an IP address, with or without a port, included.
pub(super) fn scope(addr: &TransportAddr) -> Kind {
    let Some(text) = addr.as_str() else {
        return Kind::Internet;
    };
    let ip = SocketAddr::from_str(text)
        .map(|s| s.ip())
        .or_else(|_| IpAddr::from_str(text));
    match ip {
        Ok(IpAddr::V4(v4)) => near(v4),
        Ok(IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
            Some(v4) => near(v4),
            None => {
                if v6.is_loopback() || v6.is_unicast_link_local() || v6.is_unique_local() {
                    Kind::Local
                } else {
                    Kind::Internet
                }
            }
        },
        Err(_) => Kind::Internet,
    }
}

/// The scope of the IPv4 address `ip`.
fn near(ip: Ipv4Addr) -> Kind {
    if ip.is_loopback() || ip.is_link_local() || ip.is_private() {
        Kind::Local
    } else {
        Kind::Internet
    }
}

/// The kind of a path on `transport` to `addr`: the transport's own, if the
/// host gives it one, and otherwise the address's scope.
pub(super) fn kind(facts: &dyn Facts, transport: TransportId, addr: &TransportAddr) -> Kind {
    facts.kind(transport).unwrap_or_else(|| scope(addr))
}

/// The scope of a link whose original path is on `transport` to `addr`.
pub(super) fn link(facts: &dyn Facts, transport: TransportId, addr: &TransportAddr) -> Scope {
    Scope {
        class: facts.class(transport),
        kind: kind(facts, transport, addr),
    }
}

/// Whether a path of the link `link` may run on `transport` to `addr`, as
/// it must to be moved there: the transport is of the link's class, the
/// path of its kind unless kinds are mixed (`mix`), and the transport's
/// role is not never.
pub(super) fn moves(
    facts: &dyn Facts,
    link: Scope,
    mix: bool,
    transport: TransportId,
    addr: &TransportAddr,
) -> Result<(), Rule> {
    if facts.class(transport) != link.class {
        return Err(Rule::Class);
    }
    if !mix && kind(facts, transport, addr) != link.kind {
        return Err(Rule::Kind);
    }
    if facts.role(transport) == Role::Never {
        return Err(Rule::Role);
    }
    Ok(())
}

/// The shape of [`moves`], [`probe`] and [`admit`], for a caller that
/// applies one of them chosen elsewhere.
pub(super) type Check =
    fn(&dyn Facts, Scope, bool, TransportId, &TransportAddr) -> Result<(), Rule>;

/// Whether the node may probe a path on `transport` to `addr` that the
/// link `link` does not hold as it is: [`moves`], and the node would dial
/// the peer on the transport.
pub(super) fn probe(
    facts: &dyn Facts,
    link: Scope,
    mix: bool,
    transport: TransportId,
    addr: &TransportAddr,
) -> Result<(), Rule> {
    moves(facts, link, mix, transport, addr)?;
    if !facts.dials(transport) {
        return Err(Rule::Dial);
    }
    Ok(())
}

/// Whether a probe received on `transport` from `addr` may create a path
/// of the link `link`: [`moves`], and the node would accept the peer's
/// handshake on the transport.
pub(super) fn admit(
    facts: &dyn Facts,
    link: Scope,
    mix: bool,
    transport: TransportId,
    addr: &TransportAddr,
) -> Result<(), Rule> {
    moves(facts, link, mix, transport, addr)?;
    if !facts.accepts(transport) {
        return Err(Rule::Accept);
    }
    Ok(())
}

#[cfg(test)]
#[path = "tests/rules.rs"]
mod tests;
