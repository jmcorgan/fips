//! The overlay advert's content rules: which endpoints an advert may name, the
//! checks a peer's advert must pass, the rule for a `udp:nat` endpoint, the
//! clamp on a peer's `created_at`, and the arithmetic of an advert's validity
//! horizon. Reading the Nostr event (its tags, its expiration, whether it has
//! expired) stays in the shell, which passes the numbers in. The cache of
//! peers' adverts is `cache.rs`, the local advert's assembly from the
//! node's transports is `assemble.rs`, and the local advert and its
//! publishing decision are `publisher.rs`.

use alloc::format;
use alloc::string::ToString;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::error::Error;
use super::punch::plan::{is_doc_ip, is_never_punchable_ip, is_private_ip};
use super::signal::FRESHNESS_SKEW_TOLERANCE_MS;
use super::types::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert, OverlayTransportKind,
};

pub mod assemble;
pub mod cache;
pub mod ingest;
pub mod publisher;

/// Addresses an advert must not name as a directly dialable endpoint: the
/// never-punchable ranges plus the private and documentation ones, which are
/// useless to a peer that found the advert on a relay, and the reserved ones
/// of [`is_reserved_ip`].
pub fn is_unroutable_direct_advert_ip(ip: IpAddr) -> bool {
    is_never_punchable_ip(ip) || is_private_ip(ip) || is_doc_ip(ip) || is_reserved_ip(ip)
}

/// Ranges no host is reachable at on the public internet: `0.0.0.0/8`,
/// `240.0.0.0/4` (which holds the broadcast address) and the IPv6
/// documentation range `2001:db8::/32`.
///
/// The advert's term only: the punch planner (`punch/plan.rs`) does not use
/// it, so traversal targets are unchanged. `198.18.0.0/15`, the benchmarking
/// range, is left out on purpose: the NAT lab uses it as its public
/// internet, and it is never on a receiver's own network.
pub fn is_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.octets()[0] == 0 || v4.octets()[0] >= 240,
        IpAddr::V6(v6) => v6.segments()[0] == 0x2001 && v6.segments()[1] == 0x0db8,
    }
}

/// Whether an advert may name the IP literal `ip` as a direct endpoint. An
/// IPv4-mapped IPv6 address is judged by the IPv4 address it maps, which is
/// the address a dial reaches.
fn routable_literal(ip: IpAddr) -> bool {
    !is_unroutable_direct_advert_ip(ip.to_canonical())
}

/// Whether a label is a number as a URL host parser reads one: all decimal
/// digits, or `0x` followed by hex digits, in either case.
fn numeric_label(label: &str) -> bool {
    let hex = label
        .get(..2)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("0x"));
    if hex {
        label.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
    } else {
        !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit())
    }
}

/// Whether an advert may name `host` with a port, where the endpoint is not
/// a socket address as written. A bracketed host must be an IPv6 address,
/// and a canonical dotted quad is an IPv4 one; either is judged as an IP
/// literal. Anything else must be a host name: one trailing dot allowed,
/// labels of ASCII letters, digits, `-` and `_` of 1 to 63 bytes, 253 bytes
/// in all, not `localhost` or a name under it, and not ending in a numeric
/// label. A host that ends in a number is an IPv4 address in another
/// spelling (`127.1`, `2130706433`, `0x7f000001`, `010.0.0.1`), which the
/// system resolver turns into an address without asking DNS, so it is
/// refused rather than judged.
fn dial_host(host: &str) -> bool {
    let host = host.trim();
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner
            .parse::<Ipv6Addr>()
            .is_ok_and(|ip| routable_literal(IpAddr::V6(ip)));
    }
    if host.contains(['[', ']']) {
        return false;
    }
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return routable_literal(IpAddr::V4(ip));
    }
    let name = host.strip_suffix('.').unwrap_or(host);
    let label_ok = |label: &str| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if name.is_empty() || name.len() > 253 || !name.split('.').all(label_ok) {
        return false;
    }
    let under_localhost =
        name.len() > 10 && name.as_bytes()[name.len() - 10..].eq_ignore_ascii_case(b".localhost");
    if name.eq_ignore_ascii_case("localhost") || under_localhost {
        return false;
    }
    !name.rsplit('.').next().is_some_and(numeric_label)
}

/// Whether `addr` names a version 3 onion service with a port: 56 base32
/// characters, `.onion`, ignoring case, then a port of 1 to 65535. The check
/// is of syntax only: no checksum or version byte is checked.
///
/// The other forms a Tor address may take (an IP address or a DNS name) are
/// not accepted from an advert. A FIPS node publishes only its onion, and
/// those forms would let an advert's author choose a clearnet destination
/// for this node's Tor exit.
fn onion_endpoint(addr: &str) -> bool {
    let Some((host, port)) = addr.rsplit_once(':') else {
        return false;
    };
    if port.trim().parse::<u16>().ok().is_none_or(|p| p == 0) {
        return false;
    }
    let host = host.as_bytes();
    host.len() == 62
        && host[56..].eq_ignore_ascii_case(b".onion")
        && host[..56]
            .iter()
            .all(|b| matches!(b.to_ascii_lowercase(), b'a'..=b'z' | b'2'..=b'7'))
}

/// Whether an advert may name `endpoint`: `udp:nat`, a version 3 onion, or a UDP
/// or TCP address with a nonzero port whose host is not one of the addresses
/// [`is_unroutable_direct_advert_ip`] refuses, judged by the address it
/// actually names, or is a host name `dial_host` accepts. An IPv6 address
/// with a zone index is refused: the zone names one of the receiver's own
/// interfaces, which a remote publisher cannot know.
pub fn endpoint_advert_is_publicly_usable(endpoint: &OverlayEndpointAdvert) -> bool {
    let addr = endpoint.addr.trim();
    if addr.is_empty() {
        return false;
    }

    if endpoint.transport == OverlayTransportKind::Udp && addr.eq_ignore_ascii_case("nat") {
        return true;
    }
    if addr.eq_ignore_ascii_case("nat") {
        return false;
    }

    match endpoint.transport {
        OverlayTransportKind::Udp | OverlayTransportKind::Tcp => {
            let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
                let Some((host, port)) = addr.rsplit_once(':') else {
                    return false;
                };
                if port.trim().parse::<u16>().ok().is_none_or(|p| p == 0) {
                    return false;
                }
                return dial_host(host);
            };
            let zoned = matches!(socket_addr, SocketAddr::V6(v6) if v6.scope_id() != 0);
            socket_addr.port() != 0 && !zoned && routable_literal(socket_addr.ip())
        }
        OverlayTransportKind::Tor => onion_endpoint(addr),
        OverlayTransportKind::Unknown => false,
    }
}

/// What an advert with a `udp:nat` endpoint lacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatGap {
    /// It names no signal relay, so no peer can send it an offer.
    SignalRelays,
    /// It names no STUN server, so a peer cannot learn its own reflexive
    /// address the same way.
    StunServers,
}

/// The rule for a `udp:nat` endpoint, applied to `advert` in place.
///
/// An advert with one must name signal relays and STUN servers, and the
/// first that is missing is returned, relays before servers. An advert
/// without one carries neither, so both are cleared. Each caller words the
/// refusal itself: publishing and validation have always reported it in
/// different words.
pub fn apply_nat_rule(advert: &mut OverlayAdvert) -> Result<(), NatGap> {
    if advert.has_udp_nat_endpoint() {
        if advert
            .signal_relays
            .as_ref()
            .is_none_or(|relays| relays.is_empty())
        {
            return Err(NatGap::SignalRelays);
        }
        if advert
            .stun_servers
            .as_ref()
            .is_none_or(|servers| servers.is_empty())
        {
            return Err(NatGap::StunServers);
        }
    } else {
        advert.signal_relays = None;
        advert.stun_servers = None;
    }
    Ok(())
}

/// Check a peer's advert body: its identifier and version are ours, it names
/// at least one endpoint, and at least one is publicly usable. The unusable
/// endpoints are dropped, and the `udp:nat` rule is applied.
pub fn validate_overlay_advert(mut advert: OverlayAdvert) -> Result<OverlayAdvert, Error> {
    if advert.identifier != ADVERT_IDENTIFIER {
        return Err(Error::InvalidAdvert(format!(
            "unsupported identifier '{}'",
            advert.identifier
        )));
    }
    if advert.version != ADVERT_VERSION {
        return Err(Error::InvalidAdvert(format!(
            "unsupported version '{}'",
            advert.version
        )));
    }
    if advert.endpoints.is_empty() {
        return Err(Error::InvalidAdvert(
            "missing required endpoints".to_string(),
        ));
    }
    advert.endpoints.retain(endpoint_advert_is_publicly_usable);
    if advert.endpoints.is_empty() {
        return Err(Error::InvalidAdvert(
            "missing publicly routable endpoints".to_string(),
        ));
    }

    match apply_nat_rule(&mut advert) {
        Ok(()) => Ok(advert),
        Err(NatGap::SignalRelays) => Err(Error::InvalidAdvert(
            "udp:nat endpoint requires signalRelays".to_string(),
        )),
        Err(NatGap::StunServers) => Err(Error::InvalidAdvert(
            "udp:nat endpoint requires stunServers".to_string(),
        )),
    }
}

/// A peer's advert `created_at`, in seconds, clamped so it can never read
/// more than `FRESHNESS_SKEW_TOLERANCE_MS` ahead of `now_ms`.
///
/// An unbounded future `created_at` buys a cache entry two things it
/// should not have: a proportionally distant validity horizon, and an
/// unbeatable position in every replacement comparison, so a later genuine
/// advert can never displace it. Clamping rather than rejecting is
/// deliberate: a node whose own clock runs slow reads every peer's honest
/// advert as future-dated, and rejecting would take out Nostr-mediated
/// dialing for every peer at once with nothing but a cache miss to show
/// for it. Raising the tolerance widens the window in which a future-dated
/// advert outranks an honest one; lowering it makes an ordinary clock
/// difference look hostile.
pub fn effective_created_at_secs(created_at_secs: u64, now_ms: u64) -> u64 {
    let ceiling_secs = now_ms.saturating_add(FRESHNESS_SKEW_TOLERANCE_MS) / 1000;
    created_at_secs.min(ceiling_secs)
}

/// An advert's validity horizon in wall-clock ms, or `None` if it has passed.
///
/// The horizon is the clamped `created_at` plus `advert_max_age_ms`, cut short
/// by the event's NIP-40 expiration (`expiration_secs`) when that is sooner.
/// The caller has already refused an event that has expired.
pub fn advert_valid_until_ms(
    created_at_secs: u64,
    expiration_secs: Option<u64>,
    advert_max_age_ms: u64,
    now_ms: u64,
) -> Option<u64> {
    let created_ms = effective_created_at_secs(created_at_secs, now_ms).saturating_mul(1000);
    let created_window_until = created_ms.saturating_add(advert_max_age_ms);
    if created_window_until <= now_ms {
        return None;
    }

    let expires_ms = expiration_secs.map(|secs| secs.saturating_mul(1000));
    let valid_until_ms = expires_ms
        .map(|expires| expires.min(created_window_until))
        .unwrap_or(created_window_until);

    (valid_until_ms > now_ms).then_some(valid_until_ms)
}

#[cfg(test)]
mod tests;
