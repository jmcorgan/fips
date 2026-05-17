use super::*;
use crate::discovery::nostr::{BootstrapEvent, NostrDiscovery};
use crate::peer::PromotionResult;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportHandle, packet_channel};
use std::sync::Arc;

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

    let node = Node::with_identity(identity, config).unwrap();

    assert_eq!(node.node_addr(), &expected_node_addr);
}

#[test]
fn test_node_with_identity_validates_config() {
    let identity = Identity::generate();
    let mut config = Config::new();
    config.node.discovery.nostr.enabled = false;
    config.peers = vec![crate::config::PeerConfig {
        npub: "npub1peer".to_string(),
        via_nostr: true,
        ..Default::default()
    }];

    let err = Node::with_identity(identity, config).expect_err("expected config validation error");
    assert!(matches!(err, NodeError::Config(_)));
}

#[test]
fn test_node_leaf_only() {
    let config = Config::new();
    let node = Node::leaf_only(config).unwrap();

    assert!(node.is_leaf_only());
    assert!(node.bloom_state().is_leaf_only());
}

#[tokio::test]
async fn test_nat_bootstrap_failure_falls_back_to_direct_udp_address() {
    let peer_identity = Identity::generate();
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx.clone());
    node.packet_rx = Some(packet_rx);

    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("main".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let peer_config = crate::config::PeerConfig {
        npub: peer_identity.npub(),
        alias: None,
        addresses: vec![
            crate::config::PeerAddress::with_priority("udp", "nat", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    assert_eq!(node.connection_count(), 1);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
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
    assert!(
        node.find_link_by_addr(TransportId::new(1), &TransportAddr::from_string("test"))
            .is_none()
    );
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
    assert!(
        peer.our_index().is_some(),
        "Promoted peer should have our_index"
    );
    assert!(
        peer.their_index().is_some(),
        "Promoted peer should have their_index"
    );

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
    let (conn1, identity) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
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
        let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
        node.add_connection(conn).unwrap();
        node.promote_connection(link_id, identity, 2000).unwrap();
    }

    assert_eq!(node.peer_count(), 2);

    // Third should fail
    let link_id = LinkId::new(3);
    let (conn, identity) = make_completed_connection(&mut node, link_id, transport_id, 3000);
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
    let (conn1, identity1) = make_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr1 = *identity1.node_addr();
    node.add_connection(conn1).unwrap();
    node.promote_connection(link_id1, identity1, 2000).unwrap();

    // Add another peer and mark it stale (still sendable)
    let link_id2 = LinkId::new(2);
    let (conn2, identity2) = make_completed_connection(&mut node, link_id2, transport_id, 1000);
    node.add_connection(conn2).unwrap();
    node.promote_connection(link_id2, identity2, 2000).unwrap();

    // Add a third peer and mark it disconnected (not sendable)
    let link_id3 = LinkId::new(3);
    let (conn3, identity3) = make_completed_connection(&mut node, link_id3, transport_id, 1000);
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
    node.pending_outbound
        .insert((transport_id, index.as_u32()), link_id);

    // Verify we can look it up
    let found = node.pending_outbound.get(&(transport_id, index.as_u32()));
    assert_eq!(found, Some(&link_id));

    // Clean up
    node.pending_outbound
        .remove(&(transport_id, index.as_u32()));
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
    node.peers_by_index
        .insert((transport_id, index.as_u32()), node_addr);

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
    let _msg1 = pending_conn
        .start_handshake(our_keypair, node.startup_epoch, pending_time_ms)
        .unwrap();

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

    let mut completing_conn =
        PeerConnection::outbound(completing_link_id, peer_b_identity, completing_time_ms);

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
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, None, completing_time_ms)
        .unwrap();

    let (msg3, _neg) = completing_conn
        .complete_handshake(&msg2, None, completing_time_ms)
        .unwrap();
    resp_conn
        .complete_handshake_msg3(&msg3, completing_time_ms)
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

    node.schedule_retry(peer_node_addr, 1000);

    assert_eq!(node.retry_pending.len(), 1);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 1);
    assert!(
        state.reconnect,
        "Auto-connect peers always get reconnect=true"
    );
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
    node.schedule_retry(peer_node_addr, 1000);
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        1
    );

    // Second failure
    node.schedule_retry(peer_node_addr, 11_000);
    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert_eq!(state.retry_count, 2);
    // backoff_ms(5000) with retry_count=2 = 5000 * 4 = 20000
    assert_eq!(state.retry_after_ms, 11_000 + 20_000);
}

/// Test that auto-connect peers retry indefinitely (never exhaust).
#[test]
fn test_schedule_retry_auto_connect_never_exhausts() {
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

    // All attempts should keep the entry alive despite max_retries=2
    node.schedule_retry(peer_node_addr, 1000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    node.schedule_retry(peer_node_addr, 2000);
    assert!(node.retry_pending.contains_key(&peer_node_addr));

    // Attempt 3 would have exhausted before, but now retries indefinitely
    node.schedule_retry(peer_node_addr, 3000);
    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "Auto-connect peers should never exhaust retries"
    );
    assert_eq!(
        node.retry_pending.get(&peer_node_addr).unwrap().retry_count,
        3
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

    node.schedule_retry(peer_node_addr, 1000);
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

    node.schedule_retry(peer_node_addr, 1000);
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
    node.schedule_retry(node_addr, 3000);
    assert!(
        node.retry_pending.is_empty(),
        "No retry for already-connected peer"
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");

    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    let link_count = node.link_count();
    let connection_count = node.connection_count();

    node.try_peer_addresses(&peer_config, peer_identity, true)
        .await
        .unwrap();

    assert_eq!(
        node.link_count(),
        link_count,
        "stale retry/traversal fallback must not create a duplicate link"
    );
    assert_eq!(
        node.connection_count(),
        connection_count,
        "stale retry/traversal fallback must not create a duplicate handshake"
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connecting_peer() {
    let mut node = make_node();
    let peer_identity = make_peer_identity();
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");
    let pending = PeerConnection::outbound(LinkId::new(1), peer_identity, 1000);
    node.add_connection(pending).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, true)
        .await
        .unwrap();

    assert_eq!(
        node.connection_count(),
        1,
        "stale retry/traversal fallback must not start a second handshake"
    );
    assert_eq!(
        node.link_count(),
        0,
        "stale retry/traversal fallback must not allocate a link while a handshake is pending"
    );
}

#[tokio::test]
async fn test_nostr_traversal_failure_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    bootstrap.push_event_for_test(BootstrapEvent::Failed {
        peer_config: crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9"),
        reason: "stale traversal failure".to_string(),
    });
    node.nostr_discovery = Some(bootstrap.clone());

    node.poll_nostr_discovery().await;

    assert!(
        bootstrap.failure_state_snapshot().is_empty(),
        "stale failures for connected peers must not affect traversal cooldown"
    );
    assert!(
        node.retry_pending.is_empty(),
        "stale failures for connected peers must not enqueue reconnect attempts"
    );
}

#[tokio::test]
async fn test_nostr_traversal_established_skips_connected_peer() {
    use crate::discovery::EstablishedTraversal;
    use std::net::UdpSocket;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let (conn, peer_identity) = make_completed_connection(&mut node, link_id, transport_id, 1000);
    node.add_connection(conn).unwrap();
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    let link_count = node.link_count();
    let connection_count = node.connection_count();

    let bootstrap = Arc::new(NostrDiscovery::new_for_test());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local UDP socket");
    let remote_addr = "127.0.0.1:9999".parse().expect("parse remote addr");
    bootstrap.push_event_for_test(BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "test-session",
            peer_identity.npub(),
            remote_addr,
            socket,
        ),
    });
    node.nostr_discovery = Some(bootstrap.clone());

    node.poll_nostr_discovery().await;

    assert_eq!(
        node.link_count(),
        link_count,
        "stale established handoff must not allocate a new link"
    );
    assert_eq!(
        node.connection_count(),
        connection_count,
        "stale established handoff must not start a new handshake"
    );
    assert!(
        node.retry_pending.is_empty(),
        "stale established handoff must not enqueue a reconnect"
    );
}

#[tokio::test]
async fn test_process_pending_retries_drops_expired_entries() {
    let mut node = make_node();
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut state = super::super::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.expires_at_ms = Some(1_000);
    state.reconnect = true;
    node.retry_pending.insert(peer_node_addr, state);

    node.process_pending_retries(1_000).await;

    assert!(
        !node.retry_pending.contains_key(&peer_node_addr),
        "expired retry entries should be dropped before retry processing"
    );
}

/// Test that schedule_reconnect preserves accumulated backoff across link-dead cycles.
///
/// Regression test for issue #5: previously `schedule_reconnect` always created a
/// fresh `RetryState` with `retry_count=0`, discarding any backoff accumulated by
/// prior failed handshake attempts. On repeated link-dead evictions the node would
/// restart exponential backoff from the base interval every time instead of
/// continuing to back off.
#[test]
fn test_schedule_reconnect_preserves_backoff() {
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

    // Simulate two stale handshake timeouts incrementing the retry count.
    node.schedule_retry(peer_node_addr, 1_000); // count=1, delay=10s
    node.schedule_retry(peer_node_addr, 11_000); // count=2, delay=20s
    {
        let state = node.retry_pending.get(&peer_node_addr).unwrap();
        assert_eq!(state.retry_count, 2, "Two failures should yield count=2");
    }

    // Now simulate a link-dead removal triggering schedule_reconnect.
    // The existing retry entry (count=2) should be preserved and bumped to 3,
    // NOT reset to 0 as it was before the fix.
    node.schedule_reconnect(peer_node_addr, 31_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 3,
        "schedule_reconnect should increment existing count (was 2), not reset to 0 (regression: issue #5)"
    );

    // With count=3, backoff should be 5s * 2^3 = 40s.
    let base_ms = node.config.node.retry.base_interval_secs * 1000;
    let max_ms = node.config.node.retry.max_backoff_secs * 1000;
    let expected_delay = state.backoff_ms(base_ms, max_ms);
    assert_eq!(
        state.retry_after_ms,
        31_000 + expected_delay,
        "retry_after_ms should reflect count=3 backoff"
    );
}

/// Test that schedule_reconnect on a fresh peer (no prior retry entry) starts at count=0.
#[test]
fn test_schedule_reconnect_fresh_state() {
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

    // No prior retry entry — first reconnect should use base delay.
    node.schedule_reconnect(peer_node_addr, 1_000);

    let state = node.retry_pending.get(&peer_node_addr).unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect should start at count=0"
    );
    // Base delay: 5s * 2^0 = 5s
    let base_ms = node.config.node.retry.base_interval_secs * 1000;
    let max_ms = node.config.node.retry.max_backoff_secs * 1000;
    let expected_delay = state.backoff_ms(base_ms, max_ms);
    assert_eq!(state.retry_after_ms, 1_000 + expected_delay);
}

/// Test that a graceful Disconnect from an auto-connect peer schedules reconnect.
///
/// Regression test for issue #60: `handle_disconnect` previously called
/// `remove_active_peer` without `schedule_reconnect`, orphaning auto-connect
/// entries on a clean upstream shutdown. Other peer-removal paths (link-dead,
/// decrypt failure, peer restart) all schedule reconnect.
#[test]
fn test_disconnect_schedules_reconnect() {
    use crate::protocol::{Disconnect, DisconnectReason};

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

    let payload = Disconnect::new(DisconnectReason::Shutdown).encode();
    node.handle_disconnect(&peer_node_addr, &payload);

    let state = node
        .retry_pending
        .get(&peer_node_addr)
        .expect("handle_disconnect should schedule reconnect for auto-connect peer");
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect after disconnect should start at count=0"
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

/// Initial peer-init failure at startup must enqueue a retry. Otherwise a peer
/// whose addresses cannot be dialed at boot (no operational transport for the
/// configured transport types, all addresses unreachable, NAT rebind, etc.)
/// stays dead forever — pings arrive but cannot be answered until the daemon
/// is manually restarted.
#[tokio::test]
async fn test_initiate_peer_connections_schedules_retry_on_no_transport() {
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut config = Config::new();
    // udp address but no UDP transport registered on the node — every dial
    // attempt resolves to NodeError::NoTransportForType.
    config.peers.push(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "10.0.0.2:2121",
    ));

    let mut node = Node::new(config).unwrap();
    assert!(node.retry_pending.is_empty());

    node.initiate_peer_connections().await;

    assert!(
        node.retry_pending.contains_key(&peer_node_addr),
        "startup peer-init failure must enqueue a retry so the peer can recover \
         without a daemon restart"
    );
}

// ============================================================================
// transport_mtu() — ISSUE-2026-0011 regression coverage
// ============================================================================

/// Helper: spawn a UdpTransport with the given mtu, started and operational.
async fn make_udp_transport_with_mtu(id: u32, mtu: u16) -> TransportHandle {
    let (packet_tx, _packet_rx) = packet_channel(64);
    let transport_id = TransportId::new(id);
    let mut udp = UdpTransport::new(
        transport_id,
        Some(format!("udp{}", id)),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(mtu),
            ..Default::default()
        },
        packet_tx,
    );
    udp.start_async().await.unwrap();
    TransportHandle::Udp(udp)
}

#[tokio::test]
async fn test_transport_mtu_returns_min_across_operational() {
    // Multiple operational transports with varied MTUs. The picker must
    // return the smallest, deterministically, regardless of HashMap
    // iteration order. This is the core ISSUE-2026-0011 regression test.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp1 = make_udp_transport_with_mtu(1, 1497).await;
    let udp2 = make_udp_transport_with_mtu(2, 1280).await;
    let udp3 = make_udp_transport_with_mtu(3, 1400).await;

    node.transports.insert(TransportId::new(1), udp1);
    node.transports.insert(TransportId::new(2), udp2);
    node.transports.insert(TransportId::new(3), udp3);

    // Expect the smallest (UDP-1280), not whichever HashMap iterates first.
    assert_eq!(node.transport_mtu(), 1280);

    // effective_ipv6_mtu = 1280 - 77 = 1203, max_mss = 1203 - 60 = 1143
    // (verifies the downstream clamp value).
    assert_eq!(node.effective_ipv6_mtu(), 1203);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_transport_mtu_fallback_when_no_operational_transports() {
    // No transports configured at all → falls back to 1280 (IPv6 minimum).
    let node = make_node();
    assert_eq!(node.transport_mtu(), 1280);
}

#[tokio::test]
async fn test_transport_mtu_min_with_single_operational() {
    // Single transport: trivially returns its MTU. Pins the picker doesn't
    // accidentally drop down to a smaller fallback when one transport is
    // operational.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    assert_eq!(node.transport_mtu(), 1452);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

// path_mtu_lookup seeding for direct-link (configured) peers — closes the
// B3 coverage gap where configured/auto-connect peers never go through the
// discovery Lookup flow and so their FipsAddress was missing from
// path_mtu_lookup, causing the SYN-time TCP MSS clamp to fall back to the
// global ceiling.

#[tokio::test]
async fn test_seed_path_mtu_inserts_when_empty() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xAA);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.2:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1452),
        "Empty lookup should be seeded with the link MTU"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_keeps_tighter_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xBB);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.3:2121");

    // Pre-populate with a tighter value, e.g. learned from discovery's
    // reverse-path bottleneck.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, 1280);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1280),
        "Existing tighter value (1280) must not be loosened by direct-link seed (1452)"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_tightens_looser_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1280).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xCC);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.4:2121");

    // Pre-populate with a looser stale value.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, 1452);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .copied();
    assert_eq!(
        stored,
        Some(1280),
        "Direct-link seed (1280) must overwrite looser existing value (1452)"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_noop_for_unknown_transport() {
    let node = make_node();
    let peer_addr = make_node_addr(0xDD);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.5:2121");

    // No transport registered — call must be a no-op, not panic.
    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(99), &transport_addr);

    let map = node.path_mtu_lookup.read().unwrap();
    assert!(
        map.get(&fips_addr).is_none(),
        "Seed must be a no-op when transport_id is not registered"
    );
}
