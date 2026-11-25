//! A peer named by its npub in any letter case is looked up and remembered
//! by its key: the advert cache and the failure state use the canonical
//! npub, whatever spelling the configuration holds. A spelling that is not a
//! NIP-19 npub (a bech32m checksum, non-zero padding bits) is refused. A
//! connect's failure hands back the configuration as the node gave it. The
//! offer's recipient and the initiator set are the machine's, tested in
//! `machine/rendezvous/tests/traversal.rs`.

use super::{NostrRendezvous, OverlayEndpointAdvert, OverlayTransportKind, now_ms};
use crate::nostr::types::{BootstrapError, BootstrapEvent};

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

/// A UDP endpoint advert at `addr`.
fn udp_endpoint(addr: &str) -> OverlayEndpointAdvert {
    OverlayEndpointAdvert {
        transport: OverlayTransportKind::Udp,
        addr: addr.to_string(),
    }
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
async fn a_stale_check_for_a_peer_configured_in_upper_case_evicts_the_canonical_entry() {
    let peer_npub = crate::Identity::generate().npub();
    let runtime = NostrRendezvous::new_for_test();
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

#[tokio::test]
async fn a_cooldown_recorded_under_an_upper_case_npub_holds_for_the_canonical_npub() {
    let runtime = NostrRendezvous::new_for_test();
    let peer_npub = crate::Identity::generate().npub();
    let now = now_ms();
    runtime.note_version_mismatch(
        &peer_npub.to_ascii_uppercase(),
        "udp0",
        "192.0.2.1:2121",
        1,
        0,
    );
    runtime.settled_for_test().await;
    assert!(
        runtime.cooldown_until(&peer_npub, now + 1).is_some(),
        "a protocol-mismatch cooldown recorded under the upper-case npub does not hold for the \
         canonical npub the discovery sweep checks"
    );
}

/// A connect refused because the node has no room comes back as a failure
/// event carrying the peer's configuration as the node gave it, in the
/// spelling it was configured with, not the canonical npub the traversal
/// runs under.
#[tokio::test]
async fn a_connect_refused_for_capacity_comes_back_failed_with_the_configuration_as_given() {
    let runtime = std::sync::Arc::new(NostrRendezvous::new_for_test());
    let spelling = alternating_case(&crate::Identity::generate().npub());
    let config = crate::config::PeerConfig::new(spelling.clone(), "udp", "203.0.113.7:2121");
    runtime.set_capacity(false);
    runtime.request_connect(config).await;
    runtime.settled_for_test().await;
    let events = runtime.drain_events().await;
    assert_eq!(events.len(), 1, "one event for the connect: {events:?}");
    let BootstrapEvent::Failed {
        peer_config,
        reason,
    } = &events[0]
    else {
        panic!("the connect did not fail: {events:?}");
    };
    assert_eq!(
        peer_config.npub, spelling,
        "the configuration was not handed back as given"
    );
    let addresses: Vec<_> = peer_config
        .addresses
        .iter()
        .map(|a| (a.transport.as_str(), a.addr.as_str()))
        .collect();
    assert_eq!(addresses, [("udp", "203.0.113.7:2121")]);
    assert_eq!(reason, "bootstrap disabled");
}
