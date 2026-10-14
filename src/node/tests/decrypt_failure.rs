//! Tests for the consecutive-decrypt-failure threshold.
//!
//! Covers `Node::handle_decrypt_failure` (in `node/dataplane/encrypted.rs`),
//! which increments `ActivePeer::increment_decrypt_failures` on each AEAD
//! verification failure and logs one warning when the count reaches
//! `DECRYPT_FAILURE_THRESHOLD`. The peer is kept: a frame that does not
//! authenticate names its peer only by a receiver index sent in clear, so
//! anyone who has seen the index can produce the failures. The warning is
//! what the integration harnesses grep for, so its once-per-run shape is
//! part of the contract.

use super::*;

/// Threshold constant in node/dataplane/encrypted.rs (kept in sync with
/// production code; see DECRYPT_FAILURE_THRESHOLD).
const THRESHOLD: u32 = 20;

/// The prefix of the warning logged when the counter reaches the threshold.
const WARNING: &str = "Excessive decryption failures";

/// Warnings captured so far that carry the threshold message.
fn threshold_warnings(logs: &crate::testutil::LogCapture) -> usize {
    logs.warnings()
        .iter()
        .filter(|line| line.contains(WARNING))
        .count()
}

/// Assert the peer and its index entry are still held, and return its
/// consecutive failure count.
fn held_count(node: &Node, node_addr: &NodeAddr, key: &u32, when: &str) -> u32 {
    let count = node
        .get_peer(node_addr)
        .unwrap_or_else(|| panic!("peer present {when}"))
        .consecutive_decrypt_failures();
    assert_eq!(
        node.peers_by_index.get(key),
        Some(node_addr),
        "peers_by_index still maps the index to the peer {when}"
    );
    count
}

/// Drive a fully-promoted peer to twice the decrypt-failure threshold and
/// verify one warning is logged at the threshold and the peer is kept in both
/// `peers` and `peers_by_index`. A later run of failures, after a reset, warns
/// again.
#[test]
fn reaching_the_decrypt_failure_threshold_logs_one_warning_and_keeps_the_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Build a fully-promoted active peer with our_index/transport_id set
    // so peers_by_index is populated by promote_connection.
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.promote_connection(link_id, identity, 2_000).unwrap();

    assert_eq!(node.peer_count(), 1, "peer should be present after promote");
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("promoted peer must have our_index");
    let key = our_index.as_u32();
    assert_eq!(
        held_count(&node, &node_addr, &key, "after promote"),
        0,
        "fresh peer's failure counter must start at zero"
    );

    let (logs, guard) = crate::testutil::capture_logs_scoped();

    for expected in 1..THRESHOLD {
        node.handle_decrypt_failure(&node_addr);
        assert_eq!(
            held_count(&node, &node_addr, &key, "below the threshold"),
            expected,
            "counter should track failures below the threshold"
        );
    }
    assert_eq!(
        threshold_warnings(&logs),
        0,
        "no threshold warning before the threshold-th failure"
    );

    node.handle_decrypt_failure(&node_addr);
    assert_eq!(
        held_count(&node, &node_addr, &key, "at the threshold"),
        THRESHOLD
    );
    assert_eq!(
        threshold_warnings(&logs),
        1,
        "one threshold warning at the threshold-th failure"
    );

    for expected in THRESHOLD + 1..=2 * THRESHOLD {
        node.handle_decrypt_failure(&node_addr);
        assert_eq!(
            held_count(&node, &node_addr, &key, "past the threshold"),
            expected,
            "counter keeps counting past the threshold"
        );
    }
    assert_eq!(
        threshold_warnings(&logs),
        1,
        "failures past the threshold do not warn again"
    );
    assert_eq!(node.peer_count(), 1, "the peer is kept");

    // An authenticated frame resets the counter; a later run warns again.
    node.get_peer_mut(&node_addr)
        .unwrap()
        .reset_decrypt_failures();
    for _ in 0..THRESHOLD {
        node.handle_decrypt_failure(&node_addr);
    }
    assert_eq!(
        held_count(&node, &node_addr, &key, "after a second run"),
        THRESHOLD
    );
    assert_eq!(
        threshold_warnings(&logs),
        2,
        "a second run of failures warns once more"
    );
    drop(guard);
}
