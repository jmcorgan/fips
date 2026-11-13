//! A peer named by its npub in any letter case is looked up, signalled and
//! remembered by its key: the advert cache, the offer's recipient, the
//! active-initiator set and the failure state all use the canonical npub,
//! whatever spelling the configuration holds. A spelling that is not a
//! NIP-19 npub (a bech32m checksum, non-zero padding bits) is refused.

use nostr::ToBech32;

use super::{
    NostrRendezvous, OverlayEndpointAdvert, OverlayTransportKind, UNCONNECTED_RELAY, now_ms,
    offer_between, peer_keys_ordered,
};
use crate::nostr::types::BootstrapError;

/// The FRC-1703 Appendix C.1 key's canonical npub.
const CANONICAL_NPUB: &str = "npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus6gq266";

/// The same key under a bech32m checksum, under non-zero padding bits
/// (`0001`), and under both (`1111`).
const NON_CANONICAL_NPUBS: [&str; 3] = [
    "npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmus05sxlc",
    "npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmu3875l8g",
    "npub1lycg5qvjtrp3qjf5f7zl382j9x6nrjz9sdhenvyxq8c3808qxmulser6qq",
];

/// `text` with every other letter upper-cased.
fn alternating_case(text: &str) -> String {
    text.chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect()
}

/// The canonical npub and two other spellings of it: all upper case and
/// mixed case.
fn spellings(npub: &str) -> [String; 3] {
    [
        npub.to_string(),
        npub.to_ascii_uppercase(),
        alternating_case(npub),
    ]
}

/// A peer config naming `npub` as written.
fn peer_config(npub: &str) -> crate::config::PeerConfig {
    crate::config::PeerConfig {
        npub: npub.to_string(),
        ..Default::default()
    }
}

/// A UDP endpoint advert at `addr`.
fn udp_endpoint(addr: &str) -> OverlayEndpointAdvert {
    OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: addr.to_string(),
    }
}

/// An initiator runtime that runs no STUN exchange, with the unconnected relay
/// in its pool and, cached under `peer`'s canonical npub, an advert that names
/// a NAT endpoint and that relay for signalling.
async fn initiator_with_cached_nat_peer(
    mut runtime: NostrRendezvous,
    peer: &nostr::Keys,
) -> (std::sync::Arc<NostrRendezvous>, String) {
    runtime.set_stun_servers_for_test(Vec::new());
    runtime
        .add_unconnected_relay_for_test(UNCONNECTED_RELAY)
        .await;
    let peer_npub = peer.public_key().to_bech32().unwrap();
    let mut advert = NostrRendezvous::cached_advert_for_test(
        peer_npub.clone(),
        udp_endpoint("nat"),
        now_ms() / 1_000,
    );
    advert.advert.signal_relays = Some(vec![UNCONNECTED_RELAY.to_string()]);
    runtime
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    (std::sync::Arc::new(runtime), peer_npub)
}

/// The first traversal offer `runtime` publishes, waiting up to 10 s for it.
async fn wait_for_sent_offer(runtime: &NostrRendezvous) -> crate::nostr::TraversalOffer {
    for _ in 0..200 {
        if let Some(offer) = runtime.sent_offers_for_test().into_iter().next() {
            return offer;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("no traversal offer was published within 10 s");
}

/// A TCP listener that accepts and never speaks: a relay URL pointed at it
/// makes a fetch run its full timeout and return no events.
fn blackhole_relay() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });
    format!("ws://127.0.0.1:{port}")
}

#[tokio::test]
async fn a_peer_configured_in_any_case_is_sent_an_offer_addressed_to_its_canonical_npub() {
    let peer = nostr::Keys::generate();
    let canonical = peer.public_key().to_bech32().unwrap();
    for spelling in spellings(&canonical) {
        let (runtime, peer_npub) =
            initiator_with_cached_nat_peer(NostrRendezvous::new_for_test(), &peer).await;
        runtime.request_connect(peer_config(&spelling)).await;
        let offer = wait_for_sent_offer(&runtime).await;
        // The responder routes an offer only when its recipient is its own
        // canonical npub, and refuses any other text as `identity-mismatch`.
        assert_eq!(
            offer.recipient_npub, peer_npub,
            "the offer to a peer configured as {spelling} is addressed to another text"
        );
        assert!(
            runtime.initiator_active_for_test(&peer_npub),
            "the initiator for a peer configured as {spelling} is not registered under its key"
        );
    }
}

#[tokio::test]
async fn a_peer_configured_in_upper_case_still_wins_the_dual_init_election() {
    let base = NostrRendezvous::new_for_test();
    let our_npub = base.npub_for_test().to_string();
    // A peer whose NodeAddr sorts after ours: our initiator wins, so its offer
    // is suppressed while ours is in flight.
    let peer = peer_keys_ordered(&our_npub, true);
    let (runtime, peer_npub) = initiator_with_cached_nat_peer(base, &peer).await;
    runtime
        .request_connect(peer_config(&peer_npub.to_ascii_uppercase()))
        .await;
    let _ = wait_for_sent_offer(&runtime).await;

    let theirs = offer_between("their-session", &peer_npub, &our_npub);
    let handled = runtime
        .clone()
        .handle_incoming_offer_for_test(theirs, peer.public_key(), peer_npub.clone())
        .await;
    assert!(
        handled.is_ok(),
        "the peer's offer was answered instead of suppressed in favour of ours: {handled:?}"
    );
}

#[tokio::test]
async fn a_stale_check_for_a_peer_configured_in_upper_case_evicts_the_canonical_entry() {
    let peer_npub = crate::Identity::generate().npub();
    let mut runtime = NostrRendezvous::new_for_test();
    runtime
        .set_advert_relays_for_test(vec![blackhole_relay()])
        .await;
    let advert = NostrRendezvous::cached_advert_for_test(
        peer_npub.clone(),
        udp_endpoint("203.0.113.7:2121"),
        1_000,
    );
    runtime
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;

    let outcome = runtime
        .refetch_advert_for_stale_check(&peer_npub.to_ascii_uppercase())
        .await;
    let left = runtime.cached_created_at_for_test(&peer_npub).await;
    assert!(
        left.is_none(),
        "refetch reported {outcome:?}, but the canonical entry is still cached (created_at {left:?})"
    );
}

#[tokio::test]
async fn a_peers_advert_endpoints_are_found_from_its_npub_in_any_case() {
    let runtime = NostrRendezvous::new_for_test();
    let peer_npub = crate::Identity::generate().npub();
    let endpoint = udp_endpoint("203.0.113.7:2121");
    let advert = NostrRendezvous::cached_advert_for_test(
        peer_npub.clone(),
        endpoint.clone(),
        now_ms() / 1_000,
    );
    runtime
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;
    for spelling in spellings(&peer_npub) {
        let endpoints = runtime.advert_endpoints_for_peer(&spelling).await;
        assert!(
            matches!(&endpoints, Ok(found) if *found == vec![endpoint.clone()]),
            "the cached advert was not found from {spelling}: {endpoints:?}"
        );
    }
}

#[tokio::test]
async fn a_spelling_that_is_not_a_nip19_npub_finds_no_advert() {
    let runtime = NostrRendezvous::new_for_test();
    let endpoint = udp_endpoint("203.0.113.7:2121");
    let advert = NostrRendezvous::cached_advert_for_test(
        CANONICAL_NPUB.to_string(),
        endpoint.clone(),
        now_ms() / 1_000,
    );
    runtime
        .insert_advert_for_test(CANONICAL_NPUB.to_string(), advert)
        .await;
    let found = runtime.advert_endpoints_for_peer(CANONICAL_NPUB).await;
    assert!(
        matches!(&found, Ok(e) if *e == vec![endpoint.clone()]),
        "control: {found:?}"
    );
    for text in NON_CANONICAL_NPUBS {
        let found = runtime.advert_endpoints_for_peer(text).await;
        assert!(
            matches!(found, Err(BootstrapError::InvalidPeerNpub { .. })),
            "{text} is not a NIP-19 npub, but was looked up: {found:?}"
        );
    }
}

#[test]
fn a_cooldown_recorded_under_an_upper_case_npub_holds_for_the_canonical_npub() {
    let runtime = NostrRendezvous::new_for_test();
    let peer_npub = crate::Identity::generate().npub();
    let now = now_ms();
    runtime.record_protocol_mismatch(&peer_npub.to_ascii_uppercase(), now);
    assert!(
        runtime.cooldown_until(&peer_npub, now + 1).is_some(),
        "a protocol-mismatch cooldown recorded under the upper-case npub does not hold for the \
         canonical npub the discovery sweep checks"
    );
}
