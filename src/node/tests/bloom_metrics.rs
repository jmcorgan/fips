//! Registry-counter coverage tests for the bloom-v2 metric counters that
//! the mesh-lab suites do not reliably exercise.
//!
//! The send-path bloom counters (`deltas_sent`, `full_sends`,
//! `total_compressed_bytes`, `total_raw_bytes`) fire on every filter
//! announce and are covered by the steady-state suites. The three
//! condition-dependent counters (`nacks_sent`, `nacks_received`,
//! `size_changes`) only fire on out-of-sequence deltas, inbound NACKs,
//! and adaptive resizes — none of which occur in the stable, lossless
//! mesh-lab scenarios. These tests drive each of those paths directly and
//! assert the registry counter increments.

use super::*;
use crate::bloom::{BloomFilter, V1_SIZE_CLASS};
use crate::peer::ActivePeer;
use crate::protocol::{FilterAnnounce, FilterNack};

/// Inject a synthetic active peer with a known NodeAddr; returns it.
fn inject_peer(node: &mut Node) -> NodeAddr {
    let peer_identity = make_peer_identity();
    let peer_addr = *peer_identity.node_addr();
    let peer = ActivePeer::new(peer_identity, LinkId::new(1), 0);
    node.peers.insert(peer_addr, peer);
    peer_addr
}

/// Encode a FilterAnnounce to the payload format handle_filter_announce
/// expects (msg_type byte stripped).
fn encode_announce(announce: &FilterAnnounce) -> Vec<u8> {
    let (mut full, _stats) = announce.encode().unwrap();
    full.remove(0); // strip msg_type byte
    full
}

/// An out-of-sequence delta to a peer with no stored filter makes the node
/// send a NACK, bumping `nacks_sent`.
#[tokio::test]
async fn test_bloom_nacks_sent_counter() {
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);

    // Fresh peer: filter_sequence == 0. A delta whose base_seq does not
    // match the expected base (0) is out-of-sequence → NACK.
    let announce = FilterAnnounce::delta(BloomFilter::new(), 2, 5, V1_SIZE_CLASS);
    let payload = encode_announce(&announce);

    node.handle_filter_announce(&peer_addr, &payload).await;

    assert_eq!(
        node.metrics().bloom.nacks_sent.get(),
        1,
        "registry nacks_sent must increment on out-of-sequence delta"
    );
}

/// An inbound FilterNack bumps `nacks_received`.
#[tokio::test]
async fn test_bloom_nacks_received_counter() {
    let mut node = make_node();
    let peer_addr = inject_peer(&mut node);

    let mut payload = FilterNack { expected_seq: 7 }.encode();
    payload.remove(0); // strip msg_type byte (decode expects the seq only)

    node.handle_filter_nack(&peer_addr, &payload).await;

    assert_eq!(
        node.metrics().bloom.nacks_received.get(),
        1,
        "registry nacks_received must increment on inbound NACK"
    );
}

/// A fresh Full node starts at V1_SIZE_CLASS with a nearly empty outgoing
/// filter (just its own addr), so the first adaptive-sizing pass steps the
/// size class down, bumping `size_changes`.
#[tokio::test]
async fn test_bloom_size_changes_counter() {
    let mut node = make_node();
    // check_adaptive_sizing needs at least one peer for the representative
    // outgoing-filter computation.
    let _peer = inject_peer(&mut node);

    assert_eq!(
        node.bloom_state.size_class(),
        V1_SIZE_CLASS,
        "fresh node starts at the v1 size class"
    );

    node.check_bloom_state().await;

    assert_eq!(
        node.metrics().bloom.size_changes.get(),
        1,
        "registry size_changes must increment on adaptive resize"
    );
    assert_eq!(
        node.bloom_state.size_class(),
        V1_SIZE_CLASS - 1,
        "near-empty outgoing filter steps the size class down"
    );
}
