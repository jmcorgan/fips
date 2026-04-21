//! Direct tests for the M1 antipoison FPR cap in handle_filter_announce.
//!
//! These tests construct a minimal Node with a single synthetic peer,
//! then call handle_filter_announce directly with crafted FilterAnnounce
//! payloads. Focused on the ingress check semantics; broader
//! filter-exchange behavior is covered by the multi-node tests in
//! bloom.rs.

use super::*;
use crate::bloom::{BloomFilter, DEFAULT_FILTER_SIZE_BITS, DEFAULT_HASH_COUNT};
use crate::peer::ActivePeer;
use crate::protocol::FilterAnnounce;

/// Inject a synthetic active peer into the node with a known NodeAddr.
/// Returns the peer's NodeAddr.
fn inject_peer(node: &mut Node) -> NodeAddr {
    let peer_identity = make_peer_identity();
    let peer_addr = *peer_identity.node_addr();
    let peer = ActivePeer::new(peer_identity, LinkId::new(1), 0);
    node.peers.insert(peer_addr, peer);
    peer_addr
}

/// Encode a FilterAnnounce to the payload format handle_filter_announce
/// expects (msg_type byte stripped).
fn encode_payload(announce: &FilterAnnounce) -> Vec<u8> {
    let (mut full, _stats) = announce.encode().unwrap();
    full.remove(0); // strip msg_type byte
    full
}

#[tokio::test]
async fn test_m1_rejects_all_ones_filter_announce() {
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);

    // Craft an all-ones FilterAnnounce (the observed-in-the-wild attack).
    let all_ones = BloomFilter::from_bytes(
        vec![0xFFu8; DEFAULT_FILTER_SIZE_BITS / 8],
        DEFAULT_HASH_COUNT,
    )
    .unwrap();
    let announce = FilterAnnounce::full(all_ones, 1, 1);
    let payload = encode_payload(&announce);

    let before_fill_exceeded = node.stats().bloom.fill_exceeded;
    let before_accepted = node.stats().bloom.accepted;

    node.handle_filter_announce(&peer_addr, &payload).await;

    let after = &node.stats().bloom;
    assert_eq!(
        after.fill_exceeded,
        before_fill_exceeded + 1,
        "fill_exceeded counter must increment on all-ones rejection"
    );
    assert_eq!(
        after.accepted, before_accepted,
        "accepted counter must NOT increment on rejection"
    );

    // Peer state unchanged: no filter stored, sequence not advanced.
    let peer = node.get_peer(&peer_addr).expect("peer still present");
    assert!(
        peer.inbound_filter().is_none(),
        "peer must NOT have a stored filter after rejection"
    );
    assert_eq!(
        peer.filter_sequence(),
        0,
        "peer filter_sequence must NOT advance on rejection"
    );
}

#[tokio::test]
async fn test_m1_accepts_sub_cap_filter() {
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);

    // A legitimate filter with 50 entries — fill ~0.03, FPR ~2e-8,
    // far below the 0.05 cap. Represents normal mesh traffic.
    let mut filter = BloomFilter::new();
    for i in 0..50u8 {
        let mut bytes = [0u8; 16];
        bytes[0] = i;
        filter.insert(&NodeAddr::from_bytes(bytes));
    }
    let announce = FilterAnnounce::full(filter, 1, 1);
    let payload = encode_payload(&announce);

    let before_fill_exceeded = node.stats().bloom.fill_exceeded;
    let before_accepted = node.stats().bloom.accepted;

    node.handle_filter_announce(&peer_addr, &payload).await;

    let after = &node.stats().bloom;
    assert_eq!(
        after.fill_exceeded, before_fill_exceeded,
        "fill_exceeded must NOT increment on legitimate sub-cap filter"
    );
    assert_eq!(
        after.accepted,
        before_accepted + 1,
        "accepted must increment on legitimate filter"
    );

    // Peer state updated: filter stored, sequence advanced.
    let peer = node.get_peer(&peer_addr).expect("peer still present");
    assert!(
        peer.inbound_filter().is_some(),
        "peer must have a stored filter after acceptance"
    );
    assert_eq!(
        peer.filter_sequence(),
        1,
        "peer filter_sequence must advance to announce's sequence"
    );
}

#[tokio::test]
async fn test_m1_sequence_not_advanced_allows_recovery() {
    // Confirms the "keep prior filter, don't advance seq" rejection
    // semantics: a compliant announce after a rejected one still
    // succeeds at seq=1, because the rejected announce (also seq=1)
    // did not advance the peer's recorded sequence.
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);

    // First announce: all-ones, rejected.
    let bad = BloomFilter::from_bytes(
        vec![0xFFu8; DEFAULT_FILTER_SIZE_BITS / 8],
        DEFAULT_HASH_COUNT,
    )
    .unwrap();
    let bad_announce = FilterAnnounce::full(bad, 1, 1);
    node.handle_filter_announce(&peer_addr, &encode_payload(&bad_announce))
        .await;
    assert_eq!(
        node.get_peer(&peer_addr).unwrap().filter_sequence(),
        0,
        "rejected announce must not advance sequence"
    );

    // Second announce: legitimate, seq=1 (would be stale if rejection
    // had advanced the recorded sequence). Must be accepted.
    let mut good = BloomFilter::new();
    for i in 0..10u8 {
        let mut bytes = [0u8; 16];
        bytes[0] = i;
        good.insert(&NodeAddr::from_bytes(bytes));
    }
    let good_announce = FilterAnnounce::full(good, 1, 1);
    node.handle_filter_announce(&peer_addr, &encode_payload(&good_announce))
        .await;

    let peer = node.get_peer(&peer_addr).unwrap();
    assert!(
        peer.inbound_filter().is_some(),
        "compliant announce at same seq must be accepted after rejection"
    );
    assert_eq!(peer.filter_sequence(), 1);
    assert_eq!(node.stats().bloom.fill_exceeded, 1);
    assert_eq!(node.stats().bloom.accepted, 1);
}
