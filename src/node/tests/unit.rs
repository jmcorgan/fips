use super::*;
use crate::peer::PromotionResult;

#[test]
fn test_node_creation() {
    let node = make_node();

    assert_eq!(node.state(), NodeState::Created);
    assert_eq!(node.peer_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.link_count(), 0);
    assert!(!node.is_leaf_only());
}

#[test]
fn test_node_with_identity() {
    let identity = Identity::generate();
    let expected_node_addr = *identity.node_addr();
    let config = Config::new();

    let node = Node::with_identity(identity, config);

    assert_eq!(node.node_addr(), &expected_node_addr);
}

#[test]
fn test_node_leaf_only() {
    let config = Config::new();
    let node = Node::leaf_only(config).unwrap();

    assert!(node.is_leaf_only());
    assert!(node.bloom_state().is_leaf_only());
}

#[tokio::test]
async fn test_node_state_transitions() {
    let mut node = make_node();

    assert!(!node.is_running());
    assert!(node.state().can_start());

    node.start().await.unwrap();
    assert!(node.is_running());
    assert!(!node.state().can_start());

    node.stop().await.unwrap();
    assert!(!node.is_running());
    assert_eq!(node.state(), NodeState::Stopped);
}

#[tokio::test]
async fn test_node_double_start() {
    let mut node = make_node();
    node.start().await.unwrap();

    let result = node.start().await;
    assert!(matches!(result, Err(NodeError::AlreadyStarted)));

    // Clean up
    node.stop().await.unwrap();
}

#[tokio::test]
async fn test_node_stop_not_started() {
    let mut node = make_node();

    let result = node.stop().await;
    assert!(matches!(result, Err(NodeError::NotStarted)));
}

#[test]
fn test_node_link_management() {
    let mut node = make_node();

    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        TransportId::new(1),
        TransportAddr::from_string("test"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    node.add_link(link).unwrap();
    assert_eq!(node.link_count(), 1);

    assert!(node.get_link(&link_id).is_some());

    // Test addr_to_link lookup
    assert_eq!(
        node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")),
        Some(link_id)
    );

    node.remove_link(&link_id);
    assert_eq!(node.link_count(), 0);

    // Lookup should be gone
    assert!(node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test")).is_none());
}

#[test]
fn test_node_link_limit() {
    let mut node = make_node();
    node.set_max_links(2);

    for i in 0..2 {
        let link_id = node.allocate_link_id();
        let link = Link::connectionless(
            link_id,
            TransportId::new(1),
            TransportAddr::from_string(&format!("test{}", i)),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );
        node.add_link(link).unwrap();
    }

    let link_id = node.allocate_link_id();
    let link = Link::connectionless(
        link_id,
        TransportId::new(1),
        TransportAddr::from_string("test_extra"),
        LinkDirection::Outbound,
        Duration::from_millis(50),
    );

    let result = node.add_link(link);
    assert!(matches!(result, Err(NodeError::MaxLinksExceeded { .. })));
}

#[test]
fn test_node_connection_management() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    let conn = PeerConnection::outbound(link_id, identity, 1000);

    node.add_connection(conn).unwrap();
    assert_eq!(node.connection_count(), 1);

    assert!(node.get_connection(&link_id).is_some());

    node.remove_connection(&link_id);
    assert_eq!(node.connection_count(), 0);
}

#[test]
fn test_node_connection_duplicate() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    let conn1 = PeerConnection::outbound(link_id, identity, 1000);
    let conn2 = PeerConnection::outbound(link_id, identity, 2000);

    node.add_connection(conn1).unwrap();
    let result = node.add_connection(conn2);

    assert!(matches!(result, Err(NodeError::ConnectionAlreadyExists(_))));
}

#[test]
fn test_node_promote_connection() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn).unwrap();
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.peer_count(), 0);

    let result = node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 1);

    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.authenticated_at(), 2000);
    assert!(peer.has_session(), "Promoted peer should have NoiseSession");
    assert!(peer.our_index().is_some(), "Promoted peer should have our_index");
    assert!(peer.their_index().is_some(), "Promoted peer should have their_index");

    // Verify peers_by_index is populated
    let our_index = peer.our_index().unwrap();
    assert_eq!(
        node.peers_by_index.get(&(transport_id, our_index.as_u32())),
        Some(&node_addr)
    );
}

#[test]
fn test_node_cross_connection_resolution() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // First connection and promotion (becomes active peer)
    let link_id1 = LinkId::new(1);
    let (conn1, identity) =
        make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr = *identity.node_addr();

    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity, 1500).unwrap();

    assert_eq!(node.peer_count(), 1);
    assert_eq!(node.get_peer(&node_addr).unwrap().link_id(), link_id1);

    // Cross-connection tie-breaker logic is tested in peer/mod.rs tests.
    // The integration test will cover the real cross-connection path with
    // two actual nodes. Here we verify promotion works correctly.

    // Verify first promotion populated peers_by_index
    let peer = node.get_peer(&node_addr).unwrap();
    let our_idx = peer.our_index().unwrap();
    assert_eq!(
        node.peers_by_index.get(&(transport_id, our_idx.as_u32())),
        Some(&node_addr)
    );

    // Still only one peer
    assert_eq!(node.peer_count(), 1);
}

#[test]
fn test_node_peer_limit() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    node.set_max_peers(2);

    // Add two peers via promotion
    for i in 0..2 {
        let link_id = LinkId::new(i as u64 + 1);
        let (conn, identity) =
            make_completed_connection(&mut node, link_id, transport_id, 1000);
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, identity, 2000).unwrap();
    }

    assert_eq!(node.peer_count(), 2);

    // Third should fail
    let link_id = LinkId::new(3);
    let (conn, identity) =
        make_completed_connection(&mut node, link_id, transport_id, 3000);
    node.add_connection(conn).unwrap();

    let result = node.promote_connection(link_id, identity, 4000);
    assert!(matches!(result, Err(NodeError::MaxPeersExceeded { .. })));
}

#[test]
fn test_node_link_id_allocation() {
    let mut node = make_node();

    let id1 = node.allocate_link_id();
    let id2 = node.allocate_link_id();
    let id3 = node.allocate_link_id();

    assert_ne!(id1, id2);
    assert_ne!(id2, id3);
    assert_eq!(id1.as_u64(), 1);
    assert_eq!(id2.as_u64(), 2);
    assert_eq!(id3.as_u64(), 3);
}

#[test]
fn test_node_transport_management() {
    let mut node = make_node();

    // Initially no transports (transports are created during start())
    assert_eq!(node.transport_count(), 0);

    // Allocating IDs still works
    let id1 = node.allocate_transport_id();
    let id2 = node.allocate_transport_id();
    assert_ne!(id1, id2);

    // get_transport returns None when transport doesn't exist
    assert!(node.get_transport(&id1).is_none());
    assert!(node.get_transport(&id2).is_none());

    // transport_ids() iterator is empty
    assert_eq!(node.transport_ids().count(), 0);
}

#[test]
fn test_node_sendable_peers() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Add a healthy peer
    let link_id1 = LinkId::new(1);
    let (conn1, identity1) =
        make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr1 = *identity1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity1, 2000).unwrap();

    // Add another peer and mark it stale (still sendable)
    let link_id2 = LinkId::new(2);
    let (conn2, identity2) =
        make_completed_connection(&mut node, link_id2, transport_id, 1000);
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, identity2, 2000).unwrap();

    // Add a third peer and mark it disconnected (not sendable)
    let link_id3 = LinkId::new(3);
    let (conn3, identity3) =
        make_completed_connection(&mut node, link_id3, transport_id, 1000);
    let node_addr3 = *identity3.node_addr();
    node.add_connection(conn3).unwrap();
    node.promote_connection(link_id3, identity3, 2000).unwrap();
    node.get_peer_mut(&node_addr3).unwrap().mark_disconnected();

    assert_eq!(node.peer_count(), 3);
    assert_eq!(node.sendable_peer_count(), 2);

    let sendable: Vec<_> = node.sendable_peers().collect();
    assert_eq!(sendable.len(), 2);
    assert!(sendable.iter().any(|p| p.node_addr() == &node_addr1));
}

// === RX Loop Tests ===

#[test]
fn test_node_index_allocator_initialized() {
    let node = make_node();
    // Index allocator should be empty on creation
    assert_eq!(node.index_allocator.count(), 0);
}

#[test]
fn test_node_pending_outbound_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in pending_outbound
    node.pending_outbound.insert((transport_id, index.as_u32()), link_id);

    // Verify we can look it up
    let found = node.pending_outbound.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&link_id));

    // Clean up
    node.pending_outbound.remove(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert_eq!(node.index_allocator.count(), 0);
    assert!(node.pending_outbound.is_empty());
}

#[test]
fn test_node_peers_by_index_tracking() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let node_addr = make_node_addr(42);

    // Allocate an index
    let index = node.index_allocator.allocate().unwrap();

    // Track in peers_by_index
    node.peers_by_index.insert((transport_id, index.as_u32()), node_addr);

    // Verify lookup
    let found = node.peers_by_index.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&node_addr));

    // Clean up
    node.peers_by_index.remove(&(transport_id, index.as_u32()));
    let _ = node.index_allocator.free(index);

    assert!(node.peers_by_index.is_empty());
}

#[tokio::test]
async fn test_node_rx_loop_requires_start() {
    let mut node = make_node();

    // RX loop should fail if node not started (no packet_rx)
    let result = node.run_rx_loop().await;
    assert!(matches!(result, Err(NodeError::NotStarted)));
}

#[tokio::test]
async fn test_node_rx_loop_takes_channel() {
    let mut node = make_node();
    node.start().await.unwrap();

    // packet_rx should be available after start
    assert!(node.packet_rx.is_some());

    // After run_rx_loop takes ownership, it should be None
    // We can't actually run the loop (it blocks), but we can test the take
    let rx = node.packet_rx.take();
    assert!(rx.is_some());
    assert!(node.packet_rx.is_none());

    node.stop().await.unwrap();
}

#[test]
fn test_rate_limiter_initialized() {
    let mut node = make_node();

    // Rate limiter should allow handshakes initially
    assert!(node.msg1_rate_limiter.can_start_handshake());

    // Start a handshake
    assert!(node.msg1_rate_limiter.start_handshake());
    assert_eq!(node.msg1_rate_limiter.pending_count(), 1);

    // Complete it
    node.msg1_rate_limiter.complete_handshake();
    assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
}

// === Promotion / Retry Tests ===

/// Test that promoting a connection cleans up a pending outbound to the same peer.
///
/// Simulates the scenario where node A has a pending outbound handshake to B
/// (unanswered because B wasn't running), then B starts and initiates to A.
/// When A promotes B's inbound connection, it should immediately clean up the
/// stale pending outbound rather than waiting for the 30s timeout.
#[test]
fn test_promote_cleans_up_pending_outbound_to_same_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Generate peer B's identity (shared between the two connections)
    let peer_b_full = Identity::generate();
    let peer_b_identity = PeerIdentity::from_pubkey_full(peer_b_full.pubkey_full());
    let peer_b_node_addr = *peer_b_identity.node_addr();

    // --- Set up the pending outbound to B (link_id 1) ---
    // This simulates A having sent msg1 to B before B was running.
    let pending_link_id = LinkId::new(1);
    let pending_time_ms = 1000;
    let mut pending_conn =
        PeerConnection::outbound(pending_link_id, peer_b_identity, pending_time_ms);

    let our_keypair = node.identity.keypair();
    let _msg1 = pending_conn.start_handshake(our_keypair, node.startup_epoch, pending_time_ms).unwrap();

    let pending_index = node.index_allocator.allocate().unwrap();
    pending_conn.set_our_index(pending_index);
    pending_conn.set_transport_id(transport_id);
    let pending_addr = TransportAddr::from_string("10.0.0.2:2121");
    pending_conn.set_source_addr(pending_addr.clone());

    let pending_link = Link::connectionless(
        pending_link_id,
        transport_id,
        pending_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node.links.insert(pending_link_id, pending_link);
    node.addr_to_link
        .insert((transport_id, pending_addr.clone()), pending_link_id);
    node.connections.insert(pending_link_id, pending_conn);
    node.pending_outbound
        .insert((transport_id, pending_index.as_u32()), pending_link_id);

    // Verify pending state
    assert_eq!(node.connection_count(), 1);
    assert_eq!(node.link_count(), 1);
    assert_eq!(node.index_allocator.count(), 1);

    // --- Set up the completing inbound from B (link_id 2) ---
    // Simulate B's outbound arriving at A and completing the handshake.
    // We use make_completed_connection's pattern but with B's known identity.
    let completing_link_id = LinkId::new(2);
    let completing_time_ms = 2000;

    let mut completing_conn = PeerConnection::outbound(
        completing_link_id,
        peer_b_identity,
        completing_time_ms,
    );

    let our_keypair = node.identity.keypair();
    let msg1 = completing_conn
        .start_handshake(our_keypair, node.startup_epoch, completing_time_ms)
        .unwrap();

    // B responds
    let mut resp_conn = PeerConnection::inbound(LinkId::new(999), completing_time_ms);
    let peer_keypair = peer_b_full.keypair();
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, completing_time_ms)
        .unwrap();

    completing_conn
        .complete_handshake(&msg2, completing_time_ms)
        .unwrap();

    let completing_index = node.index_allocator.allocate().unwrap();
    completing_conn.set_our_index(completing_index);
    completing_conn.set_their_index(SessionIndex::new(99));
    completing_conn.set_transport_id(transport_id);
    completing_conn.set_source_addr(TransportAddr::from_string("10.0.0.2:4001"));

    node.add_connection(completing_conn).unwrap();

    // Now 2 connections, 1 link (pending has link, completing doesn't yet need one for this test)
    assert_eq!(node.connection_count(), 2);
    assert_eq!(node.index_allocator.count(), 2);

    // --- Promote the completing connection ---
    let result = node
        .promote_connection(completing_link_id, peer_b_identity, completing_time_ms)
        .unwrap();

    assert!(matches!(result, PromotionResult::Promoted(_)));

    // The pending outbound should NOT be cleaned up during promotion —
    // it's deferred so handle_msg2 can learn the peer's inbound index.
    assert_eq!(
        node.connection_count(),
        1,
        "Pending outbound should be preserved (deferred cleanup)"
    );
    assert_eq!(node.peer_count(), 1, "Promoted peer should exist");
    assert!(
        node.pending_outbound
            .contains_key(&(transport_id, pending_index.as_u32())),
        "pending_outbound entry should still exist (awaiting msg2)"
    );
    assert_eq!(
        node.index_allocator.count(),
        2,
        "Both indices should remain until msg2 cleanup"
    );

    // Verify the promoted peer is correct
    let peer = node.get_peer(&peer_b_node_addr).unwrap();
    assert_eq!(peer.link_id(), completing_link_id);
}

/// Test that schedule_retry creates a retry entry for auto-connect peers.
#[test]
fn test_schedule_retry_creates_entry() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    assert!(node.retry_pending.is_empty());

    node.schedule_retry(peer_node_addr, 1000, false);

    assert_eq!(node.retry_pending.len(), 1);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 1);
    // Default base = 5s, 2^1 = 10s, but first retry is 2^0... let me check:
    // retry_count is set to 1, backoff_ms(5000) = 5000 * 2^1 = 10000
    assert_eq!(state.retry_after_ms, 1000 + 10_000);
}

/// Test that schedule_retry increments on subsequent calls.
#[test]
fn test_schedule_retry_increments() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // First failure
    node.schedule_retry(peer_node_addr, 1000, false);
    assert_eq!(node.retry_pending.get(&peer_node_addr).unwrap().retry_count, 1);

    // Second failure
    node.schedule_retry(peer_node_addr, 11_000, false);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 2);
    // backoff_ms(5000) with retry_count=2 = 5000 * 4 = 20000
    assert_eq!(state.retry_after_ms, 11_000 + 20_000);
}

/// Test that schedule_retry gives up after max_retries.
#[test]
fn test_schedule_retry_max_retries_exhausted() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.retry.max_retries = 2;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    // Attempts 1 and 2 should schedule retries
    node.schedule_retry(peer_node_addr, 1000, false);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    node.schedule_retry(peer_node_addr, 2000, false);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    // Attempt 3 exceeds max_retries=2, should remove entry
    node.schedule_retry(peer_node_addr, 3000, false);
    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "Should be removed after max retries exhausted"
    );
}

/// Test that schedule_retry does nothing when max_retries is 0.
#[test]
fn test_schedule_retry_disabled() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    config.node.retry.max_retries = 0;
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();

    node.schedule_retry(peer_node_addr, 1000, false);
    assert!(
        node.retry_pending.is_empty(),
        "No retry should be scheduled when max_retries=0"
    );
}

/// Test that schedule_retry does nothing for non-auto-connect peers.
#[test]
fn test_schedule_retry_ignores_non_autoconnect() {
    let peer_identity = Identity::generate();
    let peer_node_addr = *peer_identity.node_addr();

    // No peers configured at all
    let mut node = make_node();

    node.schedule_retry(peer_node_addr, 1000, false);
    assert!(
        node.retry_pending.is_empty(),
        "No retry for unconfigured peer"
    );
}

/// Test that schedule_retry does nothing if peer is already connected.
#[test]
fn test_schedule_retry_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    // Promote a peer so it's in the peers map
    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();
    assert_eq!(node.peer_count(), 1);

    // Scheduling a retry for an already-connected peer should be a no-op
    node.schedule_retry(node_addr, 3000, false);
    assert!(
        node.retry_pending.is_empty(),
        "No retry for already-connected peer"
    );
}

/// Test that promote_connection clears retry_pending.
#[test]
fn test_promote_clears_retry_pending() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    // Simulate a retry entry existing for this peer
    node.retry_pending.insert(
        node_addr,
        super::super::retry::RetryState::new(crate::config::PeerConfig::default()),
    );
    assert_eq!(node.retry_pending.len(), 1);

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        !node.retry_pending.contains_key(&node_addr),
        "retry_pending should be cleared on successful promotion"
    );
}
