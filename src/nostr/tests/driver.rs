//! Tests of the advert endpoints the driver turns into dial candidates.

use super::*;

/// An endpoint advert.
fn endpoint(transport: OverlayTransportKind, addr: &str) -> OverlayEndpointAdvert {
    OverlayEndpointAdvert {
        transport,
        addr: addr.to_string(),
    }
}

/// A configured address at `priority`.
fn existing(transport: &str, addr: &str, priority: u8) -> PeerAddress {
    PeerAddress::with_priority(transport, addr, priority)
}

/// Each address as (transport, address, priority, time seen).
fn rows(addresses: &[PeerAddress]) -> Vec<(&str, &str, u8, Option<u64>)> {
    addresses
        .iter()
        .map(|a| {
            (
                a.transport.as_str(),
                a.addr.as_str(),
                a.priority,
                a.seen_at_ms,
            )
        })
        .collect()
}

#[test]
fn fallback_candidates_start_one_past_the_highest_existing_priority() {
    let found = RendezvousDriver::fallback_from(
        vec![
            endpoint(OverlayTransportKind::Udp, "203.0.113.7:2121"),
            endpoint(OverlayTransportKind::Tcp, "203.0.113.7:443"),
        ],
        &[
            existing("udp", "192.0.2.1:2121", 5),
            existing("tcp", "192.0.2.1:443", 40),
        ],
        1_000,
    );
    assert_eq!(
        rows(&found),
        [
            ("udp", "203.0.113.7:2121", 41, Some(1_000)),
            ("tcp", "203.0.113.7:443", 42, Some(1_000)),
        ]
    );
}

#[test]
fn fallback_candidates_start_at_101_with_nothing_existing() {
    let found = RendezvousDriver::fallback_from(
        vec![endpoint(OverlayTransportKind::Udp, "203.0.113.7:2121")],
        &[],
        7,
    );
    assert_eq!(rows(&found), [("udp", "203.0.113.7:2121", 101, Some(7))]);
}

#[test]
fn fallback_candidates_skip_what_is_already_listed_or_already_taken() {
    let found = RendezvousDriver::fallback_from(
        vec![
            endpoint(OverlayTransportKind::Udp, "192.0.2.1:2121"),
            endpoint(OverlayTransportKind::Tcp, "203.0.113.7:443"),
            endpoint(OverlayTransportKind::Tcp, "203.0.113.7:443"),
            // The same address on another transport is another candidate.
            endpoint(OverlayTransportKind::Udp, "203.0.113.7:443"),
        ],
        &[existing("udp", "192.0.2.1:2121", 100)],
        0,
    );
    assert_eq!(
        rows(&found),
        [
            ("tcp", "203.0.113.7:443", 101, Some(0)),
            ("udp", "203.0.113.7:443", 102, Some(0)),
        ]
    );
}

#[test]
fn fallback_candidates_leave_out_an_endpoint_of_an_unknown_kind() {
    let found = RendezvousDriver::fallback_from(
        vec![
            endpoint(OverlayTransportKind::Unknown, "198.51.100.9:9"),
            endpoint(OverlayTransportKind::Tor, "abcdefghijklmnop.onion:443"),
        ],
        &[],
        3,
    );
    assert_eq!(
        rows(&found),
        [("tor", "abcdefghijklmnop.onion:443", 101, Some(3))]
    );
}

#[test]
fn fallback_candidates_after_an_existing_priority_of_255_stay_at_255() {
    let found = RendezvousDriver::fallback_from(
        vec![
            endpoint(OverlayTransportKind::Udp, "203.0.113.7:2121"),
            endpoint(OverlayTransportKind::Tcp, "203.0.113.7:443"),
        ],
        &[existing("udp", "192.0.2.1:2121", 255)],
        9,
    );
    assert_eq!(
        rows(&found),
        [
            ("udp", "203.0.113.7:2121", 255, Some(9)),
            ("tcp", "203.0.113.7:443", 255, Some(9)),
        ]
    );
}

#[test]
fn overlay_addresses_start_at_120_in_advert_order_without_duplicates_or_unknown_kinds() {
    let found = RendezvousDriver::overlay_addresses(
        &[
            endpoint(OverlayTransportKind::Udp, "203.0.113.7:2121"),
            endpoint(OverlayTransportKind::Tcp, "203.0.113.8:443"),
            endpoint(OverlayTransportKind::Unknown, "198.51.100.9:9"),
            endpoint(OverlayTransportKind::Udp, "203.0.113.7:2121"),
            endpoint(OverlayTransportKind::Tor, "abcdefghijklmnop.onion:443"),
        ],
        42,
    );
    assert_eq!(
        rows(&found),
        [
            ("udp", "203.0.113.7:2121", 120, Some(42)),
            ("tcp", "203.0.113.8:443", 121, Some(42)),
            ("tor", "abcdefghijklmnop.onion:443", 122, Some(42)),
        ]
    );
}

#[test]
fn overlay_addresses_of_an_advert_with_only_unknown_kinds_are_none() {
    let found = RendezvousDriver::overlay_addresses(
        &[endpoint(OverlayTransportKind::Unknown, "198.51.100.9:9")],
        42,
    );
    assert!(found.is_empty(), "{found:?}");
}
