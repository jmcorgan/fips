//! The overlay advert's content rules: which endpoints an advert may name, the
//! checks a peer's advert must pass, the rule for a `udp:nat` endpoint, the
//! clamp on a peer's `created_at`, and the arithmetic of an advert's validity
//! horizon. Reading the Nostr event (its tags, its expiration, whether it has
//! expired) stays in the shell, which passes the numbers in. The cache of
//! peers' adverts is `cache.rs`, and the local advert and its publishing
//! decision are `publisher.rs`.

use alloc::format;
use alloc::string::ToString;
use core::net::{IpAddr, SocketAddr};

use super::error::Error;
use super::punch::plan::{is_doc_ip, is_never_punchable_ip, is_private_ip};
use super::signal::FRESHNESS_SKEW_TOLERANCE_MS;
use super::types::{
    ADVERT_IDENTIFIER, ADVERT_VERSION, OverlayAdvert, OverlayEndpointAdvert, OverlayTransportKind,
};

pub mod cache;
pub mod publisher;

/// Addresses an advert must not name as a directly dialable endpoint: the
/// never-punchable ranges plus the private and documentation ones, which are
/// useless to a peer that found the advert on a relay.
pub fn is_unroutable_direct_advert_ip(ip: IpAddr) -> bool {
    is_never_punchable_ip(ip) || is_private_ip(ip) || is_doc_ip(ip)
}

/// Whether an advert may name `endpoint`: `udp:nat`, a Tor address, or a UDP
/// or TCP address with a nonzero port whose host is not one of the addresses
/// [`is_unroutable_direct_advert_ip`] refuses (a host name other than
/// `localhost` is allowed).
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
                let host = host.trim().trim_start_matches('[').trim_end_matches(']');
                if host.is_empty() || port.trim().parse::<u16>().ok().is_none_or(|p| p == 0) {
                    return false;
                }
                if host.eq_ignore_ascii_case("localhost") {
                    return false;
                }
                return host
                    .parse::<IpAddr>()
                    .ok()
                    .is_none_or(|ip| !is_unroutable_direct_advert_ip(ip));
            };
            socket_addr.port() != 0 && !is_unroutable_direct_advert_ip(socket_addr.ip())
        }
        OverlayTransportKind::Tor => true,
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
