//! Tests for the consecutive-decrypt-failure threshold force-removal path.
//!
//! Covers `Node::handle_decrypt_failure` (in `node/dataplane/encrypted.rs`),
//! which increments `ActivePeer::increment_decrypt_failures` on each AEAD
//! verification failure and force-removes the peer once
//! `DECRYPT_FAILURE_THRESHOLD` consecutive failures are observed. The
//! threshold is a defensive signal against a peer whose session is
//! desynchronized or under attack, so regression coverage of the wiring
//! between counter, threshold, and peer eviction is security-relevant.

use super::*;

/// Drive a fully-promoted peer to the decrypt-failure threshold and verify
/// it is removed from both `peers` and `peers_by_index`.
///
/// Setup uses the `make_completed_connection` harness so the peer has a
/// real `our_index`/`transport_id`, ensuring `remove_active_peer` exercises
/// the full `peers_by_index` cleanup path (not just the bare `peers` table).
#[test]
fn test_decrypt_failure_threshold_removes_peer() {
    // Threshold constant in node/dataplane/encrypted.rs (kept in sync with
    // production code; see DECRYPT_FAILURE_THRESHOLD).
    const THRESHOLD: u32 = 20;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Build a fully-promoted active peer with our_index/transport_id set
    // so peers_by_index is populated by promote_connection.
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1_000);
    let node_addr = *identity.node_addr();

    node.promote_connection(link_id, identity, 2_000).unwrap();

    // Sanity: peer is registered and indexed.
    assert_eq!(node.peer_count(), 1, "peer should be present after promote");
    let our_index = node
        .get_peer(&node_addr)
        .and_then(|p| p.our_index())
        .expect("promoted peer must have our_index");
    assert_eq!(
        node.peers_by_index.get(&(transport_id, our_index.as_u32())),
        Some(&node_addr),
        "peers_by_index must be populated after promote"
    );
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "fresh peer's failure counter must start at zero"
    );

    // Drive failures up to (but not including) the threshold; peer must
    // remain present and the counter must increase monotonically.
    for expected in 1..THRESHOLD {
        node.handle_decrypt_failure(&node_addr);
        let count = node
            .get_peer(&node_addr)
            .expect("peer must still be present below threshold")
            .consecutive_decrypt_failures();
        assert_eq!(
            count, expected,
            "counter should track failures pre-threshold"
        );
    }
    assert_eq!(
        node.peer_count(),
        1,
        "peer must remain registered until threshold is reached"
    );

    // The Nth failure crosses the threshold and triggers force-removal.
    node.handle_decrypt_failure(&node_addr);

    assert!(
        node.get_peer(&node_addr).is_none(),
        "peer must be removed from peers table at threshold"
    );
    assert_eq!(
        node.peer_count(),
        0,
        "peer_count must be zero after eviction"
    );
    assert!(
        !node
            .peers_by_index
            .contains_key(&(transport_id, our_index.as_u32())),
        "peers_by_index entry must be cleaned up at threshold"
    );
}
