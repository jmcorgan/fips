use super::*;
use crate::nostr::{BootstrapEvent, NostrRendezvous};
use crate::proto::fmp::PromotionResult;
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
    config.node.rendezvous.nostr.enabled = false;
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
    node.supervisor.packet_tx = Some(packet_tx.clone());
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
async fn test_try_peer_addresses_races_all_concrete_udp_candidates() {
    let peer_identity = Identity::generate();
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx.clone());
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
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:9", 1),
            crate::config::PeerAddress::with_priority("udp", "127.0.0.1:10", 2),
        ],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    let peer_identity = PeerIdentity::from_npub(&peer_config.npub).unwrap();

    node.try_peer_addresses(&peer_config, peer_identity, false)
        .await
        .unwrap();

    let mut addrs = node
        .connections()
        .filter_map(|(_, machine)| machine.conn_source_addr().and_then(|addr| addr.as_str()))
        .collect::<Vec<_>>();
    addrs.sort();
    assert_eq!(addrs, vec!["127.0.0.1:10", "127.0.0.1:9"]);

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_node_state_transitions() {
    // A transport-less node now resolves to `Failed` on start, so exercise
    // state transitions with a genuinely healthy node.
    let mut node = make_healthy_node();

    assert!(!node.is_running());
    assert!(node.state().can_start());

    node.start().await.unwrap();
    assert!(node.is_running());
    assert_eq!(node.state(), NodeState::Running);
    assert!(!node.state().can_start());

    node.stop().await.unwrap();
    assert!(!node.is_running());
    assert_eq!(node.state(), NodeState::Stopped);
}

#[tokio::test]
async fn test_transportless_start_fails_and_publishes_failed() {
    // The intended behavioral change: a node with zero
    // transports up cannot serve, so `start()` returns `NoOperationalTransports`
    // and leaves the published state at `Failed` (not operational, not
    // restartable in-process).
    let mut node = make_node();
    assert!(node.state().can_start());

    let result = node.start().await;
    assert!(matches!(result, Err(NodeError::NoOperationalTransports)));
    assert_eq!(node.state(), NodeState::Failed);
    assert!(!node.is_running());
    assert!(!node.state().is_operational());
    assert!(!node.state().can_start());
}

#[tokio::test]
async fn test_drain_publishes_draining_state() {
    let mut node = make_healthy_node();
    node.start().await.unwrap();
    assert_eq!(node.state(), NodeState::Running);
    assert!(node.state().is_operational());

    // Enter the bounded drain in place: publishes the operator-visible
    // `Draining` state (not operational) without tearing down.
    node.enter_drain().await;
    assert_eq!(node.state(), NodeState::Draining);
    assert!(!node.state().is_operational());
    // `Draining` is neither startable nor externally stoppable; the daemon
    // drain finishes via the supervisor's `DrainDeadlineElapsed`, not `stop()`.
    assert!(!node.state().can_start());
    assert!(!node.state().can_stop());

    // Finishing shutdown from `Draining` tears down to `Stopped`.
    node.finish_shutdown().await;
    assert_eq!(node.state(), NodeState::Stopped);
}

#[tokio::test]
async fn test_immediate_stop_never_publishes_draining() {
    let mut node = make_healthy_node();
    node.start().await.unwrap();
    assert_eq!(node.state(), NodeState::Running);

    // The immediate stop() path (used by tests and the stop-now path)
    // transitions Running → Stopping → Stopped and never enters `Draining`.
    node.stop().await.unwrap();
    assert_eq!(node.state(), NodeState::Stopped);
    assert_ne!(node.state(), NodeState::Draining);
}

#[tokio::test]
async fn test_node_start_does_not_wait_for_nostr_relay_startup() {
    let mut config = Config::new();
    config.node.control.enabled = false;
    config.node.rendezvous.nostr.enabled = true;
    config.node.rendezvous.nostr.advertise = true;
    config.node.rendezvous.nostr.policy = crate::config::NostrRendezvousPolicy::Open;
    config.node.rendezvous.nostr.advert_relays = vec!["wss://127.0.0.1:9".to_string()];
    config.node.rendezvous.nostr.dm_relays = vec!["wss://127.0.0.1:9".to_string()];
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        advertise_on_nostr: Some(true),
        public: Some(false),
        accept_connections: Some(true),
        ..Default::default()
    });

    let mut node = Node::new(config).unwrap();
    tokio::time::timeout(std::time::Duration::from_millis(500), node.start())
        .await
        .expect("node start should not wait for relay I/O")
        .unwrap();

    assert!(node.is_running());
    assert!(node.nostr_rendezvous_handle().is_some());

    node.stop().await.unwrap();
}

#[tokio::test]
async fn test_node_double_start() {
    let mut node = make_healthy_node();
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
fn remove_link_clears_a_reverse_lookup_entry_keyed_on_a_second_address_form() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = node.allocate_link_id();
    node.add_link(Link::connectionless(
        link_id,
        transport_id,
        TransportAddr::from_string("10.128.2.4:2121"),
        LinkDirection::Inbound,
        Duration::from_millis(50),
    ))
    .unwrap();

    // The cross-connection arms key the surviving link on the *packet's*
    // source address, which need not be the form the link itself carries.
    node.addr_to_link.insert(
        (transport_id, TransportAddr::from_string("node-b:2121")),
        link_id,
    );

    // An entry another link has claimed is not this link's to remove.
    let other_link_id = node.allocate_link_id();
    node.addr_to_link.insert(
        (transport_id, TransportAddr::from_string("10.128.2.5:2121")),
        other_link_id,
    );

    node.remove_link(&link_id);

    assert!(
        node.find_link_by_addr(transport_id, &TransportAddr::from_string("10.128.2.4:2121"))
            .is_none()
    );
    assert!(
        node.find_link_by_addr(transport_id, &TransportAddr::from_string("node-b:2121"))
            .is_none(),
        "the second address form outlived the link it named"
    );
    assert_eq!(
        node.find_link_by_addr(transport_id, &TransportAddr::from_string("10.128.2.5:2121")),
        Some(other_link_id)
    );
}

#[test]
fn test_node_link_limit() {
    let mut node = make_node_with_max_links(2);

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
    node.seed_handshake_machine(HandshakeSeed::outbound(link_id, identity, 1000))
        .unwrap();

    assert_eq!(node.connection_count(), 1);

    assert!(node.has_pending_leg(&link_id));

    node.remove_peer_machine(link_id);
    assert_eq!(node.connection_count(), 0);
}

#[test]
fn test_node_connection_duplicate() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    node.seed_handshake_machine(HandshakeSeed::outbound(link_id, identity, 1000))
        .unwrap();

    let result = node.seed_handshake_machine(HandshakeSeed::outbound(link_id, identity, 2000));

    assert!(matches!(result, Err(NodeError::ConnectionAlreadyExists(_))));
}

#[cfg(debug_assertions)]
#[test]
fn test_peer_maps_coherent_after_seeding_a_handshake() {
    let mut node = make_node();

    let identity = make_peer_identity();
    let link_id = LinkId::new(1);
    node.seed_handshake_machine(HandshakeSeed::outbound(link_id, identity, 1000))
        .unwrap();

    assert!(
        node.peer_machines.contains_key(&link_id),
        "seeding a handshake creates its control machine"
    );
    node.debug_assert_peer_maps_coherent();
}

#[cfg(debug_assertions)]
#[test]
fn test_peer_maps_coherent_through_establish() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);

    node.debug_assert_peer_maps_coherent();

    let result = node.promote_connection(link_id, identity, 2000).unwrap();
    assert!(matches!(result, PromotionResult::Promoted(_)));

    // The leg's connection entry is consumed by the promote; the active peer
    // on the same link is now the machine's carrier.
    node.debug_assert_peer_maps_coherent();
}

#[cfg(debug_assertions)]
#[test]
fn test_peer_maps_coherence_detects_orphaned_machine() {
    let mut node = make_node();

    // A machine with no connection, no active peer, and no pending connect
    // has no live carrier; the check must panic on it.
    let link_id = LinkId::new(7);
    let machine = crate::peer::machine::PeerMachine::new_inbound(link_id, 1000);
    node.peer_machines.insert(link_id, machine);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        node.debug_assert_peer_maps_coherent();
    }));
    assert!(
        result.is_err(),
        "coherence check accepts a machine with no live carrier"
    );
}

/// Promotion detaches the pending connection before it validates anything, and
/// then validates the required fields in a fixed order. Both properties are
/// depended on: the caller of a rejected promotion disposes of a machine it
/// expects to be leg-less, and the reported error names the first field that is
/// missing, not an arbitrary one.
#[test]
fn test_promote_connection_error_order_and_leg_detach() {
    fn expect_promotion_failure(
        shape: impl FnOnce(HandshakeSeed) -> HandshakeSeed,
        expected_reason: &str,
    ) {
        let mut node = make_node();
        let link_id = LinkId::new(1);
        let identity = seed_completed_connection_with(&mut node, link_id, 1000, shape);

        let err = node
            .promote_connection(link_id, identity, 2000)
            .expect_err("promotion must reject an incomplete connection");
        match err {
            NodeError::PromotionFailed { reason, .. } => assert_eq!(
                reason, expected_reason,
                "promotion named the wrong missing field"
            ),
            other => panic!("expected PromotionFailed, got {other:?}"),
        }
        assert!(
            node.peer_machines
                .get(&link_id)
                .expect("the control machine survives a failed promotion")
                .leg()
                .is_none(),
            "a failed promotion must leave the machine leg-less"
        );
        assert_eq!(node.peer_count(), 0);
    }

    // Each case leaves every later field missing as well, so a promotion that
    // gathered all of them before validating would name the wrong one.
    expect_promotion_failure(|seed| seed, "missing our_index");
    expect_promotion_failure(
        |seed| seed.with_our_index(SessionIndex::new(7)),
        "missing their_index",
    );
    expect_promotion_failure(
        |seed| {
            seed.with_our_index(SessionIndex::new(7))
                .with_their_index(SessionIndex::new(42))
        },
        "missing transport_id",
    );
    expect_promotion_failure(
        |seed| {
            seed.with_our_index(SessionIndex::new(7))
                .with_their_index(SessionIndex::new(42))
                .with_transport_id(TransportId::new(1))
        },
        "missing source_addr",
    );

    // An unknown link and a machine carrying no connection are both
    // ConnectionNotFound, ahead of every field check.
    let mut node = make_node();
    let identity = make_peer_identity();
    assert!(matches!(
        node.promote_connection(LinkId::new(9), identity, 2000),
        Err(NodeError::ConnectionNotFound(_))
    ));

    let link_id = LinkId::new(2);
    node.peer_machines
        .insert(link_id, PeerMachine::new_inbound(link_id, 1000));
    assert!(matches!(
        node.promote_connection(link_id, identity, 2000),
        Err(NodeError::ConnectionNotFound(_))
    ));

    // A connection that never ran the handshake fails on the session check,
    // after the detach and ahead of every field check — the seed below
    // supplies none of the four fields above.
    let link_id = LinkId::new(3);
    node.seed_handshake_machine(HandshakeSeed::outbound(link_id, identity, 1000))
        .unwrap();
    assert!(matches!(
        node.promote_connection(link_id, identity, 2000),
        Err(NodeError::HandshakeIncomplete(_))
    ));
    assert!(
        node.peer_machines
            .get(&link_id)
            .expect("the control machine survives a failed promotion")
            .leg()
            .is_none(),
        "an incomplete handshake must still leave the machine leg-less"
    );
}

#[test]
fn test_node_promote_connection() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let link_id = LinkId::new(1);
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

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
    let identity = seed_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr = *identity.node_addr();

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
    let mut node = make_node_with_max_peers(2);
    let transport_id = TransportId::new(1);

    // Add two peers via promotion
    for i in 0..2 {
        let link_id = LinkId::new(i as u64 + 1);
        let identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);
        node.promote_connection(link_id, identity, 2000).unwrap();
    }

    assert_eq!(node.peer_count(), 2);

    // Third should fail
    let link_id = LinkId::new(3);
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 3000);

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
    let identity1 = seed_completed_connection(&mut node, link_id1, transport_id, 1000);
    let node_addr1 = *identity1.node_addr();
    node.promote_connection(link_id1, identity1, 2000).unwrap();

    // Add another peer and mark it stale (still sendable)
    let link_id2 = LinkId::new(2);
    let identity2 = seed_completed_connection(&mut node, link_id2, transport_id, 1000);
    node.promote_connection(link_id2, identity2, 2000).unwrap();

    // Add a third peer and mark it disconnected (not sendable)
    let link_id3 = LinkId::new(3);
    let identity3 = seed_completed_connection(&mut node, link_id3, transport_id, 1000);
    let node_addr3 = *identity3.node_addr();
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
    let mut node = make_healthy_node();
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
    use crate::node::rate_limit::Msg1Class;

    let mut node = make_node();

    // Rate limiter should allow handshakes initially
    assert!(
        node.msg1_rate_limiter
            .can_start_handshake(Msg1Class::Stranger)
    );

    // Start a handshake
    let slot = node
        .msg1_rate_limiter
        .start_handshake(Msg1Class::Stranger)
        .expect("fresh limiter admits");
    assert_eq!(node.msg1_rate_limiter.pending_count(), 1);

    // Complete it
    drop(slot);
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
    let pending_index = node.index_allocator.allocate().unwrap();
    let pending_addr = TransportAddr::from_string("10.0.0.2:2121");
    node.seed_handshake_machine(
        HandshakeSeed::outbound(pending_link_id, peer_b_identity, pending_time_ms)
            .with_our_index(pending_index)
            .with_transport_id(transport_id)
            .with_source_addr(pending_addr.clone()),
    )
    .unwrap();

    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let _msg1 = node
        .peer_machines
        .get_mut(&pending_link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, pending_time_ms)
        .unwrap();

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

    let completing_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(completing_link_id, peer_b_identity, completing_time_ms)
            .with_our_index(completing_index)
            .with_their_index(SessionIndex::new(99))
            .with_transport_id(transport_id)
            .with_source_addr(TransportAddr::from_string("10.0.0.2:4001")),
    )
    .unwrap();

    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let msg1 = node
        .peer_machines
        .get_mut(&completing_link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, completing_time_ms)
        .unwrap();

    // B responds
    let mut resp_conn = inbound_leg(LinkId::new(999), completing_time_ms);
    let peer_keypair = peer_b_full.keypair();
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    let msg2 = resp_conn
        .receive_handshake_init(peer_keypair, resp_epoch, &msg1, completing_time_ms)
        .unwrap();

    node.peer_machines
        .get_mut(&completing_link_id)
        .unwrap()
        .complete_handshake(&msg2, completing_time_ms)
        .unwrap();

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

    assert!(node.peering.reconciler.retry_pending.is_empty());

    node.note_handshake_timeout(peer_node_addr, 1000);

    assert_eq!(node.peering.reconciler.retry_pending.len(), 1);
    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .unwrap();
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
    node.note_handshake_timeout(peer_node_addr, 1000);
    assert_eq!(
        node.peering
            .reconciler
            .retry_pending
            .get(&peer_node_addr)
            .unwrap()
            .retry_count,
        1
    );

    // Second failure
    node.note_handshake_timeout(peer_node_addr, 11_000);
    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .unwrap();
    assert_eq!(state.retry_count, 2);
    // backoff_ms(5000) with retry_count=2 = 5000 * 4 = 20000
    assert_eq!(state.retry_after_ms, 11_000 + 20_000);
}

/// Retry processing is paced so a large due set cannot start every
/// handshake candidate in one maintenance tick.
#[tokio::test]
async fn test_process_pending_retries_is_budgeted_per_tick() {
    let mut node = make_node();
    let mut addrs = Vec::new();

    for _ in 0..20 {
        let identity = Identity::generate();
        let npub = identity.npub();
        let peer_identity = PeerIdentity::from_npub(&npub).unwrap();
        let node_addr = *peer_identity.node_addr();
        node.peering.reconciler.retry_pending.insert(
            node_addr,
            crate::node::peering::retry::RetryState {
                peer_config: crate::config::PeerConfig::new(npub, "udp", "10.0.0.2:2121"),
                retry_count: 0,
                retry_after_ms: 0,
                reconnect: true,
                expires_at_ms: None,
            },
        );
        addrs.push(node_addr);
    }

    // The retry-dial tick runs only under a `Reconciling` gate (it fires from the
    // rx loop, which spins only after start() reaches Running). Put the node in
    // Running so the retry-dial budget — the property under test — is exercised.
    node.supervisor.state = crate::node::NodeState::Running;
    node.process_pending_retries(1).await;

    let processed = addrs
        .iter()
        .filter(|addr| {
            node.peering
                .reconciler
                .retry_pending
                .get(addr)
                .is_some_and(|state| state.retry_count > 0)
        })
        .count();
    let deferred = addrs.len().saturating_sub(processed);

    assert_eq!(processed, 16);
    assert_eq!(deferred, 4);
    assert_eq!(node.peering.reconciler.retry_pending.len(), 20);
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
    node.note_handshake_timeout(peer_node_addr, 1000);
    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr)
    );

    node.note_handshake_timeout(peer_node_addr, 2000);
    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr)
    );

    // Attempt 3 would have exhausted before, but now retries indefinitely
    node.note_handshake_timeout(peer_node_addr, 3000);
    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr),
        "Auto-connect peers should never exhaust retries"
    );
    assert_eq!(
        node.peering
            .reconciler
            .retry_pending
            .get(&peer_node_addr)
            .unwrap()
            .retry_count,
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

    node.note_handshake_timeout(peer_node_addr, 1000);
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
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

    node.note_handshake_timeout(peer_node_addr, 1000);
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
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
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();
    node.promote_connection(link_id, identity, 2000).unwrap();
    assert_eq!(node.peer_count(), 1);

    // Scheduling a retry for an already-connected peer should be a no-op
    node.note_handshake_timeout(node_addr, 3000);
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
        "No retry for already-connected peer"
    );
}

#[tokio::test]
async fn test_try_peer_addresses_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let peer_identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    let peer_config = crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9");

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
    node.seed_handshake_machine(HandshakeSeed::outbound(LinkId::new(1), peer_identity, 1000))
        .unwrap();

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

#[test]
fn active_peer_same_path_discovery_skips_fresh_peer() {
    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), Node::now_ms());
    active_peer.set_current_addr(transport_id, current_addr.clone());
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    // Live link: discovery must not dial this peer at all.
    assert!(node.active_peer_link_is_live(&peer_node_addr));
    let _ = candidate;
}

#[test]
fn active_peer_same_path_discovery_refreshes_stale_peer() {
    let mut node = make_node();
    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let transport_id = TransportId::new(1);
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let stale_at = Node::now_ms().saturating_sub(
        node.config()
            .node
            .heartbeat_interval_secs
            .saturating_add(1)
            .saturating_mul(1000),
    );
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), stale_at);
    active_peer.set_current_addr(transport_id, current_addr.clone());
    node.peers.insert(peer_node_addr, active_peer);
    let candidate = crate::config::PeerAddress::new("udp", "127.0.0.1:9");

    // Gone quiet past the heartbeat interval: every path is dialable again,
    // which is what keeps failover working now that a live link is never
    // displaced.
    assert!(!node.active_peer_link_is_live(&peer_node_addr));
    let _ = candidate;
}

/// An instance-qualified candidate is the peer's *current* path only when it
/// names the instance the peer is actually on. Without this, every qualified
/// address looked like a different path from the `"udp"` a transport reports as
/// its type, so a platform lane that re-pushes its peers — Wi-Fi Aware does, on
/// every data-path callback — would re-dial a peer it is already connected to,
/// for as long as it stayed connected.
#[tokio::test]
async fn an_instance_qualified_candidate_matches_only_its_own_instance() {
    let mut listeners = std::collections::HashMap::new();
    for name in ["main", "backup"] {
        listeners.insert(
            name.to_string(),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
        );
    }
    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Named(listeners);
    config.dns.enabled = false;

    let mut node = make_node_with(config);
    node.start().await.unwrap();

    let main_id = *node
        .transports
        .iter()
        .find(|(_, handle)| handle.name() == Some("main"))
        .expect("the `main` listener came up")
        .0;

    let peer_full = Identity::generate();
    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let mut active_peer = ActivePeer::new(peer_identity, LinkId::new(7), Node::now_ms());
    active_peer.set_current_addr(main_id, TransportAddr::from_string("127.0.0.1:9"));
    node.peers.insert(peer_node_addr, active_peer);

    // Path matching, which still gates the *configured-peer* refresh even
    // though beacon discovery now gates on liveness alone.
    let matches = |transport: &str| {
        let candidate = crate::config::PeerAddress::new(transport, "127.0.0.1:9");
        node.active_peer_matches_candidate(&peer_node_addr, &candidate)
    };

    assert!(
        matches("udp"),
        "an unqualified candidate still matches, as it always did",
    );
    assert!(
        matches("udp/main"),
        "the instance the peer is on is the same path, not an alternative",
    );
    assert!(
        !matches("udp/backup"),
        "a different instance is a genuinely different path",
    );

    node.stop().await.unwrap();
}

#[tokio::test]
async fn node_context_mirrors_config_and_immutable_facades() {
    let mut node = make_node();

    // The immutable facades read the shared NodeContext.
    let expected_addr = *node.identity().node_addr();
    assert_eq!(node.node_addr(), &expected_addr);
    assert!(!node.is_leaf_only());
    let _ = node.uptime();
    assert_eq!(node.config().peers().len(), 0);

    // update_peers must rebuild the context so config() — which now reads the
    // context — reflects the new peer list. Guards the copy-on-write sync.
    let peer = Identity::generate();
    let new_peer = crate::config::PeerConfig {
        npub: peer.npub(),
        alias: None,
        addresses: vec![],
        connect_policy: crate::config::ConnectPolicy::OnDemand,
        auto_reconnect: false,
        via_nostr: false,
    };
    node.update_peers(vec![new_peer]).await.unwrap();

    assert_eq!(
        node.config().peers().len(),
        1,
        "config() must reflect update_peers through the rebuilt context"
    );
    assert_eq!(node.config().peers()[0].npub, peer.npub());
}

#[tokio::test]
async fn update_peers_races_new_alternative_without_dropping_active_peer() {
    // The node's *current* (pre-update) peer set must contain `old_peer`, so it
    // is baked into the Config at construction (immutable context = sole store).
    let peer_full = Identity::generate();
    let old_peer = crate::config::PeerConfig {
        npub: peer_full.npub(),
        alias: None,
        addresses: vec![crate::config::PeerAddress::new("udp", "127.0.0.1:9")],
        connect_policy: crate::config::ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    let mut config = Config::new();
    config.peers = vec![old_peer.clone()];
    let mut node = make_node_with(config);
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx.clone());
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

    let peer_identity = PeerIdentity::from_pubkey_full(peer_full.pubkey_full());
    let peer_node_addr = *peer_identity.node_addr();
    let current_addr = TransportAddr::from_string("127.0.0.1:9");
    let new_addr = TransportAddr::from_string("127.0.0.1:10");
    let old_link_id = LinkId::new(7);
    let mut active_peer = ActivePeer::new(peer_identity, old_link_id, Node::now_ms());
    active_peer.set_current_addr(transport_id, current_addr.clone());
    node.peers.insert(peer_node_addr, active_peer);
    node.links.insert(
        old_link_id,
        Link::connectionless(
            old_link_id,
            transport_id,
            current_addr.clone(),
            LinkDirection::Outbound,
            Duration::from_millis(100),
        ),
    );

    let new_peer = crate::config::PeerConfig {
        addresses: vec![
            crate::config::PeerAddress::new("udp", "127.0.0.1:9"),
            crate::config::PeerAddress::new("udp", "127.0.0.1:10"),
        ],
        ..old_peer.clone()
    };

    let outcome = node.update_peers(vec![new_peer]).await.unwrap();

    assert_eq!(outcome.updated, 1);
    assert_eq!(node.peer_count(), 1, "existing link must stay live");
    assert_eq!(node.connection_count(), 1);
    assert_eq!(
        node.connections()
            .next()
            .and_then(|(_, machine)| machine.conn_source_addr()),
        Some(&new_addr)
    );
    let active = node.get_peer(&peer_node_addr).unwrap();
    assert_eq!(active.link_id(), old_link_id);
    assert_eq!(active.current_addr(), Some(&current_addr));

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_nostr_traversal_failure_skips_connected_peer() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let peer_identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();

    let bootstrap = Arc::new(NostrRendezvous::new_for_test());
    bootstrap.push_event_for_test(BootstrapEvent::Failed {
        peer_config: crate::config::PeerConfig::new(peer_identity.npub(), "udp", "127.0.0.1:9"),
        reason: "stale traversal failure".to_string(),
    });
    node.supervisor
        .nostr_rendezvous
        .set_engine(bootstrap.clone());

    node.poll_nostr_rendezvous().await;

    assert!(
        bootstrap.failure_state_snapshot().is_empty(),
        "stale failures for connected peers must not affect traversal cooldown"
    );
    assert!(
        node.peering.reconciler.retry_pending.is_empty(),
        "stale failures for connected peers must not enqueue reconnect attempts"
    );
}

#[tokio::test]
async fn test_nostr_traversal_established_skips_connected_peer() {
    use crate::nostr::EstablishedTraversal;
    use std::net::UdpSocket;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);
    let peer_identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    node.promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    let link_count = node.link_count();
    let connection_count = node.connection_count();

    let bootstrap = Arc::new(NostrRendezvous::new_for_test());
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
    node.supervisor
        .nostr_rendezvous
        .set_engine(bootstrap.clone());

    node.poll_nostr_rendezvous().await;

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
        node.peering.reconciler.retry_pending.is_empty(),
        "stale established handoff must not enqueue a reconnect"
    );
}

#[tokio::test]
async fn test_process_pending_retries_drops_expired_entries() {
    let mut node = make_node();
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();

    let mut state = super::super::peering::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.expires_at_ms = Some(1_000);
    state.reconnect = true;
    node.peering
        .reconciler
        .retry_pending
        .insert(peer_node_addr, state);

    // Retry-dial runs only under a `Reconciling` gate; put the node in Running so
    // the expired-entry drop (the property under test) is reached.
    node.supervisor.state = crate::node::NodeState::Running;
    node.process_pending_retries(1_000).await;

    assert!(
        !node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr),
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
    node.note_handshake_timeout(peer_node_addr, 1_000); // count=1, delay=10s
    node.note_handshake_timeout(peer_node_addr, 11_000); // count=2, delay=20s
    {
        let state = node
            .peering
            .reconciler
            .retry_pending
            .get(&peer_node_addr)
            .unwrap();
        assert_eq!(state.retry_count, 2, "Two failures should yield count=2");
    }

    // Now simulate a link-dead removal triggering schedule_reconnect.
    // The existing retry entry (count=2) should be preserved and bumped to 3,
    // NOT reset to 0 as it was before the fix.
    node.note_link_dead(peer_node_addr, 31_000);

    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 3,
        "schedule_reconnect should increment existing count (was 2), not reset to 0 (regression: issue #5)"
    );

    // With count=3, backoff should be 5s * 2^3 = 40s.
    let base_ms = node.config().node.retry.base_interval_secs * 1000;
    let max_ms = node.config().node.retry.max_backoff_secs * 1000;
    let expected_delay = crate::proto::fmp::backoff_ms(state.retry_count, base_ms, max_ms);
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
    node.note_link_dead(peer_node_addr, 1_000);

    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .unwrap();
    assert!(state.reconnect, "Entry should be marked as reconnect");
    assert_eq!(
        state.retry_count, 0,
        "Fresh reconnect should start at count=0"
    );
    // Base delay: 5s * 2^0 = 5s
    let base_ms = node.config().node.retry.base_interval_secs * 1000;
    let max_ms = node.config().node.retry.max_backoff_secs * 1000;
    let expected_delay = crate::proto::fmp::backoff_ms(state.retry_count, base_ms, max_ms);
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
    use crate::proto::fmp::{Disconnect, DisconnectReason};

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
        .peering
        .reconciler
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
    let identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);
    let node_addr = *identity.node_addr();

    // Simulate a retry entry existing for this peer
    node.peering.reconciler.retry_pending.insert(
        node_addr,
        super::super::peering::retry::RetryState::new(crate::config::PeerConfig::default()),
    );
    assert_eq!(node.peering.reconciler.retry_pending.len(), 1);

    node.promote_connection(link_id, identity, 2000).unwrap();

    assert!(
        !node
            .peering
            .reconciler
            .retry_pending
            .contains_key(&node_addr),
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
    assert!(node.peering.reconciler.retry_pending.is_empty());

    node.initiate_peer_connections().await;

    assert!(
        node.peering
            .reconciler
            .retry_pending
            .contains_key(&peer_node_addr),
        "startup peer-init failure must enqueue a retry so the peer can recover \
         without a daemon restart"
    );
}

// ============================================================================
// transport_mtu() — minimum-across-transports regression coverage
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
    // iteration order. This is the core regression test for that.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
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
async fn the_tun_mss_ceiling_follows_a_transport_arriving_and_leaving() {
    // The TUN reader and writer used to be handed a `u16` computed once at
    // spawn. Every other consumer of `transport_mtu()` reads it live, so once
    // a transport could bind minutes after start the daemon reported one
    // effective MTU in `show_status` and clamped to another.
    //
    // Both directions. A narrow transport arriving has to tighten the ceiling
    // or traffic egressing over it is clamped too loose; the same transport
    // leaving has to release it, or unplugging a low-MTU adapter leaves the
    // node over-clamped until it restarts.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let wide = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), wide);
    node.refresh_tun_mss_ceiling();
    let wide_ceiling = node.tun_mss_ceiling();
    assert_eq!(
        wide_ceiling,
        crate::upper::icmp::mss_ceiling(1452),
        "the seeded ceiling must match the only bound transport"
    );

    // A narrower transport arrives after the TUN threads would already be
    // running. The shared ceiling has to tighten.
    let narrow = make_udp_transport_with_mtu(2, 1280).await;
    node.transports.insert(TransportId::new(2), narrow);
    node.refresh_tun_mss_ceiling();
    let narrow_ceiling = node.tun_mss_ceiling();
    assert_eq!(narrow_ceiling, crate::upper::icmp::mss_ceiling(1280));
    assert!(
        narrow_ceiling < wide_ceiling,
        "a narrower transport must tighten the clamp, not be ignored"
    );
    assert_eq!(
        narrow_ceiling,
        crate::upper::icmp::mss_ceiling(node.transport_mtu()),
        "the clamp and the reported MTU must not disagree"
    );

    // ...and leaving has to release it again.
    if let Some(mut gone) = node.transports.remove(&TransportId::new(2)) {
        gone.stop().await.ok();
    }
    node.refresh_tun_mss_ceiling();
    assert_eq!(
        node.tun_mss_ceiling(),
        wide_ceiling,
        "the ceiling must rise again when the narrow transport goes away"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn a_presence_edge_refreshes_the_tun_mss_ceiling_without_being_asked() {
    // The one above pins the arithmetic; this pins the wiring. A presence
    // edge arriving has to refresh the ceiling on its own — if the refresh is
    // dropped from the edge handlers the value silently stops tracking, which
    // is the defect in its original form.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let (presence_tx, presence_rx) = tokio::sync::mpsc::channel(4);
    node.transport_presence_tx = Some(presence_tx.clone());
    node.transport_presence_rx = Some(presence_rx);

    // Nothing bound: the conservative seed.
    node.refresh_tun_mss_ceiling();
    let seeded = node.tun_mss_ceiling();
    assert_eq!(seeded, crate::upper::icmp::mss_ceiling(1280));

    // A wide transport appears, and an edge announces it. No explicit
    // refresh call here — draining the edge is the whole trigger.
    let wide = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), wide);
    presence_tx
        .send(crate::transport::TransportPresence {
            transport_id: TransportId::new(1),
            present: true,
            health_relevant: true,
        })
        .await
        .expect("presence edge queued");
    node.drain_transport_presence();

    assert_eq!(
        node.tun_mss_ceiling(),
        crate::upper::icmp::mss_ceiling(1452),
        "draining a presence edge must refresh the ceiling on its own"
    );
    assert_ne!(
        node.tun_mss_ceiling(),
        seeded,
        "the ceiling stayed at its seed, so the edge did not refresh it"
    );

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
    node.supervisor.packet_tx = Some(packet_tx);
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
    node.supervisor.packet_tx = Some(packet_tx);
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
        .map(|e| e.mtu);
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
async fn test_seeded_narrow_link_mtu_reaches_the_clamp_as_a_tight_ceiling() {
    // The seed and the SYN-time MSS clamp are two halves of one mechanism: the
    // seed writes the node's own outgoing link MTU, the clamp reads it. A
    // narrow link is the case that matters, because BLE negotiates its MTU per
    // connection and lands below the remote-value floor routinely, and a
    // direct link has no forwarder to answer an over-large segment with
    // MtuExceeded. Driving the real seed rather than inserting into the map
    // pins that the clamp honours what the seed actually stores.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 240).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xEE);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.6:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    assert_eq!(
        node.path_mtu_lookup
            .read()
            .unwrap()
            .get(&fips_addr)
            .map(|e| e.mtu),
        Some(240),
        "the seed stores a narrow link MTU unchanged"
    );
    // 240 - 77 encap - 40 IPv6 - 20 TCP = 103. A clamp that discarded the
    // seeded value would advertise the 1143 conservative ceiling instead, and
    // every full-size segment would be refused by the transport with no
    // feedback to the TCP stack.
    assert_eq!(
        crate::upper::tun::per_flow_max_mss(&node.path_mtu_lookup, fips_addr.as_bytes(), 1360),
        103,
        "the clamp must honour the seeded link MTU, not fall back to 1143"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_seed_path_mtu_keeps_tighter_existing_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
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
        .insert(fips_addr, crate::upper::tun::PathMtuEntry::held(1280));

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .map(|e| e.mtu);
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
    node.supervisor.packet_tx = Some(packet_tx);
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
        .insert(fips_addr, crate::upper::tun::PathMtuEntry::held(1452));

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);

    let stored = node
        .path_mtu_lookup
        .read()
        .unwrap()
        .get(&fips_addr)
        .map(|e| e.mtu);
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

/// The upgrade case, and the reason the seeding transport is tracked.
///
/// A peer first reachable only over a narrow link, then moving to a wider
/// one, must not stay clamped to the narrow link's MTU. Every writer of
/// `path_mtu_lookup` keeps the tighter value, so without recording which link
/// a value described, the low MTU outlives the link it came from and pins the
/// peer for the process lifetime.
#[tokio::test]
async fn test_seed_path_mtu_reseeds_when_peer_moves_to_wider_transport() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let narrow = make_udp_transport_with_mtu(1, 1280).await;
    let wide = make_udp_transport_with_mtu(2, 1452).await;
    node.transports.insert(TransportId::new(1), narrow);
    node.transports.insert(TransportId::new(2), wide);

    let peer_addr = make_node_addr(0xE1);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let narrow_addr = TransportAddr::from_string("10.0.0.6:2121");
    let wide_addr = TransportAddr::from_string("10.0.0.7:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &narrow_addr);
    assert_eq!(
        node.path_mtu_lookup
            .read()
            .unwrap()
            .get(&fips_addr)
            .map(|e| e.mtu),
        Some(1280),
        "first seed takes the narrow link's MTU"
    );

    // The peer moves to the wider transport.
    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(2), &wide_addr);
    assert_eq!(
        node.path_mtu_lookup
            .read()
            .unwrap()
            .get(&fips_addr)
            .map(|e| e.mtu),
        Some(1452),
        "a seed from a different transport must replace a value describing \
         the link the peer has left"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// A value learned *about the narrow link* is discarded on the move too — it
/// measured a path the peer no longer uses.
#[tokio::test]
async fn test_seed_path_mtu_discards_learned_value_from_abandoned_link() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let narrow = make_udp_transport_with_mtu(1, 1280).await;
    let wide = make_udp_transport_with_mtu(2, 1452).await;
    node.transports.insert(TransportId::new(1), narrow);
    node.transports.insert(TransportId::new(2), wide);

    let peer_addr = make_node_addr(0xE2);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let narrow_addr = TransportAddr::from_string("10.0.0.8:2121");
    let wide_addr = TransportAddr::from_string("10.0.0.9:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &narrow_addr);
    // Reactive MtuExceeded tightens further, still on the narrow link.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, crate::upper::tun::PathMtuEntry::held(900));

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(2), &wide_addr);
    assert_eq!(
        node.path_mtu_lookup
            .read()
            .unwrap()
            .get(&fips_addr)
            .map(|e| e.mtu),
        Some(1452),
        "a tighter value measured on the abandoned link must not clamp the new one"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// The guard against over-loosening. Promotion re-seeds on every handshake,
/// so discarding a tighter learned value on a *same-link* re-seed would reset
/// genuine PMTU discovery repeatedly and the estimate would never converge.
#[tokio::test]
async fn test_seed_path_mtu_keeps_tighter_value_when_reseeding_same_transport() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xE3);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.10:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);
    // Reactive learning tightens the same link.
    node.path_mtu_lookup
        .write()
        .unwrap()
        .insert(fips_addr, crate::upper::tun::PathMtuEntry::held(1200));

    // Re-promotion on the same transport.
    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);
    assert_eq!(
        node.path_mtu_lookup
            .read()
            .unwrap()
            .get(&fips_addr)
            .map(|e| e.mtu),
        Some(1200),
        "re-seeding the same link must not undo reactive learning"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// The seeding record is bounded by the same lifecycle that writes it.
///
/// Promotion seeds; release drops. Without the release the map keeps a row
/// per peer this node has ever linked with, for the life of the process, and
/// the two stores drift apart: `path_mtu_lookup` forgets the value while the
/// record still names the transport that supplied it.
#[tokio::test]
async fn test_releasing_a_path_drops_the_seeding_transport_record_with_the_value() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let peer_addr = make_node_addr(0xE4);
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.11:2121");

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);
    assert_eq!(
        node.path_mtu_seeded_by
            .read()
            .unwrap()
            .get(&fips_addr)
            .copied(),
        Some(TransportId::new(1)),
        "the seed records the transport it came from"
    );

    // No entry in `node.peers`, so nothing reseeds behind the release — the
    // departed-peer case.
    node.path_mtu_lookup_release(&peer_addr);

    assert!(
        node.path_mtu_lookup
            .read()
            .unwrap()
            .get(&fips_addr)
            .is_none(),
        "release drops the stored value"
    );
    assert!(
        node.path_mtu_seeded_by
            .read()
            .unwrap()
            .get(&fips_addr)
            .is_none(),
        "release must drop the seeding record with it, or the map grows for \
         the life of the process"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

/// The live-link case: release is immediately followed by a reseed, so both
/// stores come back rather than leaving a linked peer on the fallback ceiling.
#[tokio::test]
async fn test_releasing_a_path_for_a_still_linked_peer_reseeds_both_stores() {
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let udp = make_udp_transport_with_mtu(1, 1452).await;
    node.transports.insert(TransportId::new(1), udp);

    let identity = make_peer_identity();
    let peer_addr = *identity.node_addr();
    let fips_addr = crate::FipsAddress::from_node_addr(&peer_addr);
    let transport_addr = TransportAddr::from_string("10.0.0.12:2121");

    let mut peer = crate::peer::ActivePeer::new(identity, LinkId::new(1), 0);
    peer.set_current_addr(TransportId::new(1), transport_addr.clone());
    node.peers.insert(peer_addr, peer);

    node.seed_path_mtu_for_link_peer(&peer_addr, TransportId::new(1), &transport_addr);
    node.path_mtu_lookup_release(&peer_addr);

    assert_eq!(
        node.path_mtu_lookup
            .read()
            .unwrap()
            .get(&fips_addr)
            .map(|e| e.mtu),
        Some(1452),
        "a peer whose link is still up is reseeded from that link"
    );
    assert_eq!(
        node.path_mtu_seeded_by
            .read()
            .unwrap()
            .get(&fips_addr)
            .copied(),
        Some(TransportId::new(1)),
        "and the seeding record comes back with it, so a later move is still \
         detectable"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

// === Outbound admission gate tests ===

/// Inject `count` synthetic active peers into `node.peers` so peer_count()
/// reflects a desired saturation level for admission-gate tests.
fn inject_dummy_peers(node: &mut Node, count: usize) {
    use crate::peer::ActivePeer;
    for i in 0..count {
        let identity = make_peer_identity();
        let addr = *identity.node_addr();
        let peer = ActivePeer::new(identity, LinkId::new((i + 1) as u64), 0);
        node.peers.insert(addr, peer);
    }
}

#[test]
fn outbound_admission_check_direct() {
    // max_peers cap honored: above-cap returns false, below-cap returns true.
    let mut node = make_node_with_max_peers(3);

    assert!(node.outbound_admission_check(), "0/3 should be admissible");
    inject_dummy_peers(&mut node, 2);
    assert!(node.outbound_admission_check(), "2/3 should be admissible");
    inject_dummy_peers(&mut node, 1);
    assert!(
        !node.outbound_admission_check(),
        "3/3 (at cap) should suppress"
    );
    inject_dummy_peers(&mut node, 1);
    assert!(
        !node.outbound_admission_check(),
        "4/3 (above cap) should suppress"
    );

    // No-cap sentinel: max_peers == 0 admits unconditionally.
    let mut uncapped = make_node_with_max_peers(0);
    assert!(uncapped.outbound_admission_check());
    inject_dummy_peers(&mut uncapped, 50);
    assert!(
        uncapped.outbound_admission_check(),
        "max_peers=0 (no cap) must always admit"
    );
}

#[tokio::test]
async fn process_pending_retries_gated_at_capacity() {
    let mut node = make_node_with_max_peers(2);
    inject_dummy_peers(&mut node, 2);

    // Queue a retry that would otherwise be due.
    let peer_identity = Identity::generate();
    let peer_npub = peer_identity.npub();
    let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();
    let mut state = super::super::peering::retry::RetryState::new(crate::config::PeerConfig::new(
        peer_npub,
        "udp",
        "127.0.0.1:9",
    ));
    state.retry_after_ms = 0;
    state.reconnect = true;
    node.peering
        .reconciler
        .retry_pending
        .insert(peer_node_addr, state);

    let before_peers = node.peer_count();
    let before_connections = node.connection_count();

    // Running gate so the admission short-circuit (not the startup gate) is what
    // suppresses the dial — the fingerprint this test asserts on.
    node.supervisor.state = crate::node::NodeState::Running;
    node.process_pending_retries(1_000).await;

    // At capacity: gate short-circuits before due-list collection. The
    // retry entry must still be present (untouched) and no connection
    // attempt may have been started. Without the gate, the due-list
    // collector would pick the entry up, fire `initiate_peer_connection`
    // (which fails without a registered transport), and the failure
    // handler would call `schedule_retry`, bumping `retry_count` to 1.
    let state = node
        .peering
        .reconciler
        .retry_pending
        .get(&peer_node_addr)
        .expect("retry entry must be preserved when suppressed at capacity");
    assert_eq!(
        state.retry_count, 0,
        "gate must short-circuit before initiate_peer_connection; \
         a bumped retry_count is the fingerprint of the ungated path"
    );
    assert_eq!(
        state.retry_after_ms, 0,
        "gate must short-circuit before initiate_peer_connection; \
         retry_after_ms still zero means no attempt fired"
    );
    assert_eq!(
        node.peer_count(),
        before_peers,
        "no peer adoption while suppressed"
    );
    assert_eq!(
        node.connection_count(),
        before_connections,
        "no connection initiated while suppressed"
    );
}

/// A TCP listener that accepts connections and then never speaks. A relay
/// URL pointed at it makes the nostr client's websocket handshake hang, so
/// `refetch_advert_for_stale_check` burns its full 2s fetch timeout without
/// any network egress.
fn spawn_blackhole_relay() -> String {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind blackhole listener");
    let port = listener.local_addr().expect("blackhole local addr").port();
    std::thread::spawn(move || {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept() {
            held.push(stream);
        }
    });
    format!("ws://127.0.0.1:{port}")
}

/// The author filter on advert selection must not swallow a genuine eviction.
///
/// Dropping foreign-authored events narrows what the selection can return, and
/// the eviction arm is guarded on the relays having answered with nothing at
/// all. If that guard is written too broadly it also suppresses the real case
/// this function exists for: the peer withdrew its advert and the cached entry
/// has to go. Discriminator: a seeded cache entry plus relays that return
/// nothing must still come back `Evicted` with the entry gone.
#[tokio::test]
async fn refetch_still_evicts_a_cached_advert_when_the_relays_return_nothing() {
    let peer_npub = Identity::generate().npub();
    let mut bootstrap = crate::nostr::NostrRendezvous::new_for_test();
    bootstrap
        .set_advert_relays_for_test(vec![spawn_blackhole_relay()])
        .await;

    let endpoint = crate::nostr::OverlayEndpointAdvert {
        transport: crate::nostr::OverlayTransportKind::Udp,
        addr: "203.0.113.7:2121".to_string(),
    };
    let advert =
        crate::nostr::NostrRendezvous::cached_advert_for_test(peer_npub.clone(), endpoint, 1_000);
    bootstrap
        .insert_advert_for_test(peer_npub.clone(), advert)
        .await;

    let outcome = bootstrap.refetch_advert_for_stale_check(&peer_npub).await;

    assert_eq!(
        outcome,
        crate::nostr::NostrRefetchOutcome::Evicted,
        "an empty relay answer is still evidence the advert is gone"
    );
    assert!(
        bootstrap
            .cached_created_at_for_test(&peer_npub)
            .await
            .is_none(),
        "the stale entry should have been removed from the cache"
    );
}

/// The per-tick retry loop must not await the pre-dial advert refetch.
///
/// `process_pending_retries` runs inline on the node's 1s rx-loop tick. Each
/// due peer's refetch carries a 2s relay-fetch timeout, so awaiting it stalls
/// the whole tick by 2s per peer — up to `MAX_RETRY_CONNECTIONS_PER_TICK`
/// times in one tick body. The refresh is fire-and-forget: it exists to make
/// the *next* retry dial a fresh endpoint, and retries are backoff-paced.
///
/// Discriminator: wall-clock duration of one `process_pending_retries` call
/// with several due peers whose refetches all hang. Awaited, the call takes
/// `2s * peers`; spawned, it returns without waiting on any of them.
#[tokio::test]
async fn process_pending_retries_does_not_await_advert_refetch() {
    use std::time::Instant;

    const DUE_PEERS: usize = 4;
    // Awaited: >= 8s (4 x 2s). Spawned: milliseconds. A 3s bound sits far
    // from both, so neither machine load nor the 2s timeout's own slack can
    // flip the verdict.
    const MAX_TICK_MS: u128 = 3_000;

    let mut node = make_node_with_max_peers(64);

    let mut bootstrap = crate::nostr::NostrRendezvous::new_for_test();
    bootstrap
        .set_advert_relays_for_test(vec![spawn_blackhole_relay()])
        .await;
    node.supervisor
        .nostr_rendezvous
        .set_engine(Arc::new(bootstrap));
    // Running gate, so the admission short-circuit is not what suppresses the
    // dial — same fingerprint the capacity-gate test relies on.
    node.supervisor.state = crate::node::NodeState::Running;

    let mut queued = Vec::new();
    for _ in 0..DUE_PEERS {
        let peer_npub = Identity::generate().npub();
        let peer_node_addr = *PeerIdentity::from_npub(&peer_npub).unwrap().node_addr();
        let mut state = super::super::peering::retry::RetryState::new(
            crate::config::PeerConfig::new(peer_npub, "udp", "127.0.0.1:9"),
        );
        state.retry_after_ms = 0;
        state.reconnect = true;
        node.peering
            .reconciler
            .retry_pending
            .insert(peer_node_addr, state);
        queued.push(peer_node_addr);
    }

    let started = Instant::now();
    node.process_pending_retries(1_000).await;
    let elapsed = started.elapsed();

    assert!(
        elapsed.as_millis() < MAX_TICK_MS,
        "retry tick must not block on the advert refetch: took {}ms for {} due peers \
         (a per-peer 2s relay-fetch timeout awaited inline is the fingerprint)",
        elapsed.as_millis(),
        DUE_PEERS
    );

    // The rest of the loop body is unchanged: every due peer was still
    // attempted, failed for want of a transport, and was rescheduled.
    for addr in &queued {
        let state = node
            .peering
            .reconciler
            .retry_pending
            .get(addr)
            .expect("due peer must remain queued after a failed attempt");
        assert_eq!(
            state.retry_count, 1,
            "each due peer must still have been attempted and rescheduled"
        );
    }
}

#[tokio::test]
async fn poll_nostr_rendezvous_established_gated_at_capacity() {
    use crate::nostr::EstablishedTraversal;
    use std::net::UdpSocket;

    let mut node = make_node_with_max_peers(2);
    inject_dummy_peers(&mut node, 2);

    let bootstrap = Arc::new(NostrRendezvous::new_for_test());
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind local UDP socket");
    let remote_addr = "127.0.0.1:9999".parse().expect("parse remote addr");
    let peer_identity = Identity::generate();
    bootstrap.push_event_for_test(BootstrapEvent::Established {
        traversal: EstablishedTraversal::new(
            "cap-test-session",
            peer_identity.npub(),
            remote_addr,
            socket,
        ),
    });
    node.supervisor
        .nostr_rendezvous
        .set_engine(bootstrap.clone());

    let before_peers = node.peer_count();
    let before_links = node.link_count();
    let before_connections = node.connection_count();

    node.poll_nostr_rendezvous().await;

    assert_eq!(
        node.peer_count(),
        before_peers,
        "Established event must not add a peer while at capacity"
    );
    assert_eq!(
        node.link_count(),
        before_links,
        "Established event must not allocate a link while at capacity"
    );
    assert_eq!(
        node.connection_count(),
        before_connections,
        "Established event must not start a handshake while at capacity"
    );
}

#[test]
fn nostr_rendezvous_outbound_admission_atomic_roundtrip() {
    // Verifies the runtime-side plumbing for the two NAT-traversal gate
    // points: the setter mutates the atomic and the (super-visible)
    // reader observes the value the Node-side wiring would publish.
    let bootstrap = NostrRendezvous::new_for_test();
    assert!(
        bootstrap.outbound_admission_allowed(),
        "default must allow (start unsaturated)"
    );
    bootstrap.set_outbound_admission(false);
    assert!(
        !bootstrap.outbound_admission_allowed(),
        "after suppression store: traversal initiator/responder must see false"
    );
    bootstrap.set_outbound_admission(true);
    assert!(
        bootstrap.outbound_admission_allowed(),
        "after recovery store: traversal initiator/responder must see true"
    );
}

/// Sender-side helper: build a wire-format Msg1 from a fresh peer
/// identity targeting `node_b`, *and* send it on the wire over `socket_a`
/// to `addr_b`. Returns the sender's NodeAddr so the test can assert on
/// identity-keyed maps.
///
/// Uses the same outbound-machine->Noise IK pattern as the
/// integration handshake tests, but inlined and unit-scoped.
async fn craft_and_send_msg1(
    node_b: &Node,
    sender_identity: &Identity,
    socket_a: &tokio::net::UdpSocket,
    addr_b: std::net::SocketAddr,
    timestamp_ms: u64,
) -> NodeAddr {
    use crate::proto::fmp::wire::build_msg1;
    use crate::utils::index::SessionIndex;

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let sender_pubkey_id = PeerIdentity::from_pubkey_full(sender_identity.pubkey_full());
    let sender_node_addr = *sender_pubkey_id.node_addr();

    let link_id = LinkId::new(0xDEAD_BEEF);
    let mut conn = outbound_leg(link_id, peer_b_identity, timestamp_ms);

    let sender_keypair = sender_identity.keypair();
    let mut startup_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut startup_epoch);
    let noise_msg1 = conn
        .start_handshake(sender_keypair, startup_epoch, timestamp_ms)
        .expect("start_handshake should produce noise msg1");

    let sender_index = SessionIndex::new(0x5151);
    let wire_msg1 = build_msg1(sender_index, &noise_msg1);

    socket_a
        .send_to(&wire_msg1, addr_b)
        .await
        .expect("sender_socket.send_to");
    sender_node_addr
}

/// Helper: deliver a packet from `node`'s registered UDP transport to
/// `node.handle_msg1`. Returns Ok(()) on success or Err if the packet
/// was not received within `timeout`.
async fn pump_one_msg1_into_node(
    node: &mut Node,
    packet_rx: &mut crate::transport::PacketRx,
    timeout_ms: u64,
) -> Result<(), &'static str> {
    use tokio::time::{Duration, timeout};
    let packet = timeout(Duration::from_millis(timeout_ms), packet_rx.recv())
        .await
        .map_err(|_| "timed out waiting for msg1 on packet_rx")?
        .ok_or("packet channel closed")?;
    node.handle_msg1(packet).await;
    Ok(())
}

/// Verifies the early max_peers cap check in `handle_msg1` silent-drops
/// a Msg1 from a brand-new identity at saturation: no peer is admitted,
/// no Msg2 response goes back on the wire, and the msg1 rate-limiter
/// pending_count returns to baseline.
///
/// Wire-observable Msg2 absence is the load-bearing discriminator. With
/// the early cap gate removed (stash-verify), the late gate inside
/// `promote_connection` still rejects the new identity — but only
/// *after* `handle_msg1` has already built the Msg2 frame and
/// `transport.send(...wire_msg2)` has put it on the wire. The
/// post-call wire-side poll catches that Msg2 (FAIL pre-fix; the
/// silent timeout is the PASS post-fix).
#[tokio::test]
async fn handle_msg1_silent_drops_at_cap_for_new_peer() {
    use crate::config::UdpConfig;
    use tokio::time::{Duration, timeout};

    let mut node = make_node_with_max_peers(2);
    inject_dummy_peers(&mut node, 2);
    assert_eq!(node.peer_count(), 2, "precondition: at cap");

    // === UDP transport setup for node_b (the unit under test) ===
    let transport_id_b = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);
    transport_b.start_async().await.unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    node.transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    // === Sender-side socket ===
    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");

    let before_peers = node.peer_count();
    let before_pending = node.msg1_rate_limiter.pending_count();

    // Fresh sender identity — never seen by `node`.
    let sender = Identity::generate();
    let sender_node_addr = craft_and_send_msg1(&node, &sender, &socket_a, addr_b, 1000).await;

    // Sanity: new identity is not currently a peer.
    assert!(
        !node.peers.contains_key(&sender_node_addr),
        "precondition: new sender not yet a peer"
    );

    // Pump the wire-arrived Msg1 into the node's handler.
    pump_one_msg1_into_node(&mut node, &mut packet_rx_b, 1000)
        .await
        .expect("msg1 must reach packet_rx_b");

    // Post-call state checks.
    assert_eq!(
        node.peer_count(),
        before_peers,
        "early cap gate must not adopt a new peer at saturation"
    );
    assert!(
        !node.peers.contains_key(&sender_node_addr),
        "new sender must not appear in peers map"
    );
    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        before_pending,
        "rate limiter must rebalance: the pending slot start_handshake() \
         took is released by its guard before the silent-drop return"
    );

    // Wire-observable discriminator: with the early gate in place, no
    // Msg2 should come back. With the gate removed, Msg2 IS sent
    // before promote_connection rejects.
    let mut buf = [0u8; 2048];
    let recv = timeout(Duration::from_millis(300), socket_a.recv_from(&mut buf)).await;
    let received_bytes = recv.ok().and_then(|inner| inner.ok()).map(|(n, _)| n);
    assert!(
        received_bytes.is_none(),
        "Msg2 must NOT be sent in response when at max_peers cap; \
         observed {received_bytes:?} wire bytes — the fingerprint of \
         the late-gate path replying with Msg2 before rejecting"
    );
}

/// Verifies the bypass: at saturation, an inbound Msg1 from an
/// *existing* peer's identity is not silent-dropped by the early cap
/// check (the gate would otherwise wedge legitimate
/// reconnect/restart/rekey traffic against an at-cap node).
///
/// The cap-gate's `is_known_active = self.peers.contains_key(&peer_node_addr)`
/// branch admits this case; the downstream handling (restart-detect or
/// duplicate-msg1 resend) then runs per existing semantics. The
/// observable assertion here is the existing peer's continued
/// presence — the rate-limiter rebalance is the same in
/// bypass-admit and silent-drop, so this test isn't a discriminator
/// against the no-gate (stash) build; it's a regression check that the
/// gate doesn't accidentally evict known peers.
#[tokio::test]
async fn handle_msg1_admits_existing_peer_at_cap() {
    use crate::config::UdpConfig;

    let mut node = make_node_with_max_peers(2);

    inject_dummy_peers(&mut node, 1);

    let existing_sender = Identity::generate();
    let existing_pid = PeerIdentity::from_pubkey_full(existing_sender.pubkey_full());
    let existing_node_addr = *existing_pid.node_addr();
    let existing_link_id = LinkId::new(7777);
    {
        use crate::peer::ActivePeer;
        let peer = ActivePeer::new(existing_pid, existing_link_id, 0);
        node.peers.insert(existing_node_addr, peer);
    }
    assert_eq!(node.peer_count(), 2, "precondition: at cap");

    let transport_id_b = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);
    transport_b.start_async().await.unwrap();
    let addr_b = transport_b.local_addr().unwrap();
    node.transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");

    let before_pending = node.msg1_rate_limiter.pending_count();

    let sender_node_addr =
        craft_and_send_msg1(&node, &existing_sender, &socket_a, addr_b, 2000).await;
    assert_eq!(
        sender_node_addr, existing_node_addr,
        "sanity: crafted msg1 carries the existing peer's NodeAddr"
    );

    pump_one_msg1_into_node(&mut node, &mut packet_rx_b, 1000)
        .await
        .expect("msg1 must reach packet_rx_b");

    // Bypass must not evict the existing peer or grow peer count.
    assert_eq!(node.peer_count(), 2, "peer count unchanged");
    assert!(
        node.peers.contains_key(&existing_node_addr),
        "existing peer must still be present after bypass-admitted msg1"
    );
    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        before_pending,
        "rate limiter must rebalance after the (bypass-admitted) handler returns"
    );
}

/// Every reject arm of `handle_msg1` releases *its own* pending slot and
/// nothing else.
///
/// The failure this guards is invisible by construction: a slot released
/// by a path that never took one frees a slot belonging to a **different**
/// in-flight handshake, lifting effective concurrency above `max_pending`
/// with no counter moving, no log firing, and no underflow (the release
/// saturates at zero). The only way to observe it is to hold a *foreign*
/// slot across the calls and watch whether it survives — which is what
/// `seed` is. A borrow-based guard could not be held here at all, since
/// `handle_msg1` needs `&mut node` throughout.
///
/// Each arm additionally asserts the reject counter it is supposed to
/// bump, so a setup that silently failed to reach the arm (wrong addr,
/// packet rejected earlier) shows up as a red rather than as a
/// vacuously-stable pending count.
#[tokio::test]
async fn msg1_reject_arms_do_not_release_another_handshakes_slot() {
    use crate::config::UdpConfig;
    use crate::node::rate_limit::Msg1Class;
    use crate::noise::HANDSHAKE_MSG1_SIZE;
    use crate::proto::fmp::wire::build_msg1;
    use crate::utils::index::SessionIndex;

    // max_peers 2 so the early-cap arm is reachable on the *same* node the
    // foreign slot is seeded on. That would otherwise derive a 2-token
    // established bucket, which refuses the third arm before it runs, so
    // both buckets are overridden to sizes this test never approaches:
    // the subject here is slot accounting, not admission.
    let mut config = Config::new();
    config.node.limits.max_peers = 2;
    config.node.rate_limit.handshake_burst = 100;
    config.node.rate_limit.established_handshake_burst = Some(100);
    let mut node = make_node_with(config);

    let transport_id = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx, mut packet_rx) = packet_channel(64);
    let mut transport = UdpTransport::new(transport_id, None, udp_config, packet_tx);
    transport.start_async().await.unwrap();
    let node_udp_addr = transport.local_addr().unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));

    let socket_a = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");
    let wire_addr = TransportAddr::from_string(&socket_a.local_addr().unwrap().to_string());

    // A foreign in-flight handshake's slot, held for the whole test.
    let seed = node
        .msg1_rate_limiter
        .start_handshake(Msg1Class::Stranger)
        .expect("fresh limiter admits the seed");
    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        1,
        "baseline: exactly one foreign slot outstanding"
    );

    // Both source tuples are established links, so the msg1s below are in
    // the exempted class. The link ids are deliberately absent from
    // `node.links` for now, so the duplicate-msg1 branch is skipped.
    let hand_addr = TransportAddr::from_string("198.51.100.7:2121");
    let hand_link_id = node.allocate_link_id();
    let wire_link_id = node.allocate_link_id();
    node.addr_to_link
        .insert((transport_id, hand_addr.clone()), hand_link_id);
    node.addr_to_link
        .insert((transport_id, wire_addr.clone()), wire_link_id);

    let hand_packet = |data: Vec<u8>| ReceivedPacket {
        transport_id,
        remote_addr: hand_addr.clone(),
        data,
        timestamp_ms: 1000,
    };
    let garbage_msg1 = build_msg1(SessionIndex::new(0x4242), &[0u8; HANDSHAKE_MSG1_SIZE]);

    // Arm 1: invalid header (truncated body).
    let before = node.stats().handshake.bad_state;
    node.handle_msg1(hand_packet(vec![0u8; 8])).await;
    assert_eq!(
        node.stats().handshake.bad_state,
        before + 1,
        "arm 1 must reach the invalid-header reject"
    );
    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        1,
        "invalid-header arm must not release the foreign slot"
    );

    // Arm 2: well-formed header, unusable Noise payload.
    let before = node.stats().handshake.bad_state;
    node.handle_msg1(hand_packet(garbage_msg1.clone())).await;
    assert_eq!(
        node.stats().handshake.bad_state,
        before + 1,
        "arm 2 must reach the receive_handshake_init reject"
    );
    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        1,
        "handshake-init-failure arm must not release the foreign slot"
    );

    // Arm 3: duplicate msg1 on a pending inbound link with no stored msg2.
    node.links.insert(
        hand_link_id,
        Link::connectionless(
            hand_link_id,
            transport_id,
            hand_addr.clone(),
            LinkDirection::Inbound,
            Duration::from_millis(100),
        ),
    );
    let before = node.stats().handshake.unknown_connection;
    node.handle_msg1(hand_packet(garbage_msg1)).await;
    assert_eq!(
        node.stats().handshake.unknown_connection,
        before + 1,
        "arm 3 must reach the duplicate-msg1-no-stored-msg2 reject"
    );
    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        1,
        "duplicate-msg1 arm must not release the foreign slot"
    );

    // Arm 4: the early max_peers cap gate, on a genuine crafted msg1 that
    // gets all the way through the Noise step.
    inject_dummy_peers(&mut node, 2);
    assert_eq!(node.peer_count(), 2, "precondition: at cap");
    let sender = Identity::generate();
    let sender_node_addr =
        craft_and_send_msg1(&node, &sender, &socket_a, node_udp_addr, 2000).await;
    let before = node.stats().handshake.bad_state;
    pump_one_msg1_into_node(&mut node, &mut packet_rx, 1000)
        .await
        .expect("crafted msg1 must reach packet_rx");
    assert_eq!(
        node.stats().handshake.bad_state,
        before + 1,
        "arm 4 must reach the max_peers cap reject"
    );
    assert!(
        !node.peers.contains_key(&sender_node_addr),
        "arm 4 must not admit the new identity"
    );
    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        1,
        "max_peers-cap arm must not release the foreign slot"
    );

    // The foreign slot was still ours to release all along.
    drop(seed);
    assert_eq!(node.msg1_rate_limiter.pending_count(), 0);
}

/// The msg1 handler keeps its pending slot for as long as it is running.
///
/// The complement of `msg1_reject_arms_do_not_release_another_handshakes_slot`:
/// that one covers releasing a slot the handler never took, this one covers
/// releasing its own slot too early. Rebinding `handle_msg1`'s `let _slot` to
/// a bare `_` drops the guard at acquire time, so the limiter's concurrency
/// limb stops bounding anything — and every counter this test could read
/// afterwards is identical either way, because the slot comes back at the end
/// of the handler in both worlds. The difference exists only while the handler
/// is on the stack, which is why the observation lives there: the
/// `#[cfg(test)]` assertion in `handle_msg1` immediately below the acquire
/// fires under the premature release and under nothing else.
///
/// Two packets, so the handler is entered twice on different paths past the
/// acquire, and each arm asserts the reject counter it must bump. Without
/// that, a msg1 refused before the acquire (an empty bucket, say) would leave
/// this test passing while sampling nothing.
#[tokio::test]
async fn msg1_handler_holds_its_pending_slot_while_the_handler_runs() {
    use crate::noise::HANDSHAKE_MSG1_SIZE;
    use crate::proto::fmp::wire::build_msg1;
    use crate::utils::index::SessionIndex;

    // No transport is registered: both arms reject before any send, and the
    // absent transport admits past the `accept_connections` gate.
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let source = TransportAddr::from_string("198.51.100.9:4141");
    let packet = |data: Vec<u8>| ReceivedPacket {
        transport_id,
        remote_addr: source.clone(),
        data,
        timestamp_ms: 1000,
    };

    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        0,
        "baseline: no handshake in flight"
    );

    // Arm 1: rejected at the header parse, the shortest path past the acquire.
    let before = node.stats().handshake.bad_state;
    node.handle_msg1(packet(vec![0u8; 8])).await;
    assert_eq!(
        node.stats().handshake.bad_state,
        before + 1,
        "arm 1 must reach the invalid-header reject, not a rate-limit refusal"
    );

    // Arm 2: well-formed header, unusable Noise payload — rejected further in,
    // after the duplicate short-circuit and the DH attempt.
    let before = node.stats().handshake.bad_state;
    node.handle_msg1(packet(build_msg1(
        SessionIndex::new(0x4242),
        &[0u8; HANDSHAKE_MSG1_SIZE],
    )))
    .await;
    assert_eq!(
        node.stats().handshake.bad_state,
        before + 1,
        "arm 2 must reach the receive_handshake_init reject"
    );

    assert_eq!(
        node.msg1_rate_limiter.pending_count(),
        0,
        "each handler released its own slot exactly once on the way out"
    );
}

/// The established-link bucket is wired from config at construction:
/// derived from `max_peers` by default, overridden when the operator sets
/// the key. This is the only test covering the config → limiter path.
#[test]
fn node_established_bucket_is_derived_then_overridable() {
    let mut config = Config::new();
    config.node.limits.max_peers = 300;
    let node = make_node_with(config);
    assert_eq!(
        node.msg1_rate_limiter.established_bucket().capacity(),
        300,
        "derived burst tracks max_peers"
    );

    let mut config = Config::new();
    config.node.limits.max_peers = 300;
    config.node.rate_limit.established_handshake_burst = Some(7);
    let node = make_node_with(config);
    assert_eq!(
        node.msg1_rate_limiter.established_bucket().capacity(),
        7,
        "an explicit key wins over the derivation"
    );
}

/// Build a node whose *stranger* msg1 bucket holds exactly one token and
/// never refills, with a UDP transport bound and started. Returns the node,
/// its transport id, its wire address and its packet receiver.
///
/// The established-link bucket is left at its derived size (128 burst at
/// default `max_peers`), which is the whole point: the two classes are
/// metered separately.
async fn node_with_single_stranger_token() -> (
    Node,
    TransportId,
    std::net::SocketAddr,
    crate::transport::PacketRx,
) {
    use crate::config::UdpConfig;

    let mut config = Config::new();
    config.node.rate_limit.handshake_burst = 1;
    config.node.rate_limit.handshake_rate = 0.0;
    let mut node = make_node_with(config);

    let transport_id = TransportId::new(1);
    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };
    let (packet_tx, packet_rx) = packet_channel(64);
    let mut transport = UdpTransport::new(transport_id, None, udp_config, packet_tx);
    transport.start_async().await.unwrap();
    let wire_addr = transport.local_addr().unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));

    (node, transport_id, wire_addr, packet_rx)
}

/// Poll a sender socket for a msg2 reply. `None` means nothing arrived
/// within 300 ms, the same wire-observable discriminator the max_peers cap
/// tests use.
async fn poll_for_msg2(socket: &tokio::net::UdpSocket) -> Option<usize> {
    use tokio::time::{Duration, timeout};
    let mut buf = [0u8; 2048];
    timeout(Duration::from_millis(300), socket.recv_from(&mut buf))
        .await
        .ok()
        .and_then(|inner| inner.ok())
        .map(|(n, _)| n)
}

/// An established link's rekey/restart msg1 is admitted even when the
/// stranger bucket is empty, because it draws on its own bucket.
///
/// This is the symptom the whole change exists to fix: before it, one
/// drained global bucket refused an established peer's maintenance traffic
/// on exactly the same terms as a stranger's first packet.
#[tokio::test]
async fn established_link_msg1_admitted_when_stranger_bucket_drained() {
    use crate::node::rate_limit::Msg1Class;

    let (mut node, transport_id, wire_addr, mut packet_rx) =
        node_with_single_stranger_token().await;

    // Spend the one stranger token, so any msg1 classed as a stranger is
    // refused from here on.
    drop(
        node.msg1_rate_limiter
            .start_handshake(Msg1Class::Stranger)
            .expect("the single stranger token is available at t=0"),
    );

    for attempt in 0..3 {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind sender socket");
        let sender_addr = TransportAddr::from_string(&socket.local_addr().unwrap().to_string());

        // Mark the source as an established link. The link id is
        // deliberately absent from `node.links`, so the duplicate-msg1
        // branch is skipped and the msg1 is processed as a fresh
        // connection that answers with msg2.
        let link_id = node.allocate_link_id();
        node.addr_to_link
            .insert((transport_id, sender_addr), link_id);

        let sender = Identity::generate();
        craft_and_send_msg1(&node, &sender, &socket, wire_addr, 1000 + attempt).await;
        pump_one_msg1_into_node(&mut node, &mut packet_rx, 1000)
            .await
            .expect("msg1 must reach packet_rx");

        assert!(
            poll_for_msg2(&socket).await.is_some(),
            "attempt {attempt}: established-link msg1 must be answered with \
             msg2 while the stranger bucket is empty"
        );
    }
}

/// The twin of the test above: a stranger is still refused once the
/// stranger bucket is drained. The second bucket must not become a way in
/// for sources that match no established link.
///
/// The first sender is a **positive control** on the same node, transport
/// and code path: it proves the setup really delivers a msg1 and really
/// produces a msg2 on the wire, so the second sender's silence is
/// attributable to the drained bucket rather than to a msg1 that never
/// arrived.
#[tokio::test]
async fn stranger_msg1_still_refused_when_bucket_drained() {
    let (mut node, _transport_id, wire_addr, mut packet_rx) =
        node_with_single_stranger_token().await;

    // Positive control: one token is available, so this stranger is
    // admitted and answered.
    let socket_ok = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind sender socket");
    craft_and_send_msg1(&node, &Identity::generate(), &socket_ok, wire_addr, 1000).await;
    pump_one_msg1_into_node(&mut node, &mut packet_rx, 1000)
        .await
        .expect("control msg1 must reach packet_rx");
    assert!(
        poll_for_msg2(&socket_ok).await.is_some(),
        "positive control: a stranger with a token available must be \
         answered with msg2 — without this the silence below proves nothing"
    );
    assert_eq!(node.peer_count(), 1, "control msg1 was fully processed");

    // The bucket is now empty and never refills. A second stranger, at a
    // different source addr and with no established link, gets nothing.
    let socket_refused = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind second sender socket");
    craft_and_send_msg1(
        &node,
        &Identity::generate(),
        &socket_refused,
        wire_addr,
        2000,
    )
    .await;
    pump_one_msg1_into_node(&mut node, &mut packet_rx, 1000)
        .await
        .expect("refused msg1 must still reach packet_rx");
    let bytes = poll_for_msg2(&socket_refused).await;
    assert!(
        bytes.is_none(),
        "stranger msg1 must stay refused once the stranger bucket is \
         drained; observed {bytes:?} wire bytes"
    );
    assert_eq!(
        node.peer_count(),
        1,
        "the refused stranger must not have been admitted"
    );
}

/// App-owned TUN seam: `enable_app_owned_tun` wires the embedder's packet
/// channels (an Android `VpnService` owns the fd) and marks the TUN active so
/// `start()` skips system-TUN creation.
#[test]
fn app_owned_tun_seam_wires_channels() {
    let mut config = crate::Config::new();
    config.tun.enabled = true;
    let mut node = make_node_with(config);

    let (outbound_tx, tun_rx) = node.enable_app_owned_tun();

    // TUN is active and the inbound (mesh→app) sender is installed, so `start()`
    // will skip `TunDevice::create` (it gates on `tun_tx.is_none()`).
    assert_eq!(node.tun_state(), crate::upper::tun::TunState::Active);
    assert!(node.tun_tx().is_some(), "inbound sender installed");

    // mesh → app: a packet the node delivers to its `tun_tx` reaches the app's rx.
    let pkt = vec![0x60u8, 0, 0, 0, 0, 0];
    node.tun_tx().unwrap().send(pkt.clone()).unwrap();
    assert_eq!(
        tun_rx
            .recv_timeout(std::time::Duration::from_millis(200))
            .unwrap(),
        pkt,
        "the app pulls the same bytes the node wrote",
    );

    // app → mesh: the returned sender is live (its matching rx is held by the node
    // and drained by `run_rx_loop` → `handle_tun_outbound`).
    assert!(outbound_tx.try_send(vec![0x60]).is_ok());
}

/// With an app-owned TUN configured, `start()` must NOT create a system TUN
/// device: it leaves `tun_name` unset (a real device records its interface name)
/// and keeps the TUN `Active` with the app-owned channels.
#[tokio::test]
async fn start_skips_system_tun_when_app_owned() {
    // Mirror `make_healthy_node` (one loopback UDP transport so bring-up
    // reaches `Full`), plus tun.enabled so the Tun child WOULD spawn if the
    // app-owned gate failed.
    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = false;
    config.tun.enabled = true;
    let mut node = make_node_with(config);

    let (_outbound_tx, _tun_rx) = node.enable_app_owned_tun();
    node.start().await.unwrap();

    // No system device was created (that path records the interface name); the
    // app-owned TUN stayed active.
    assert!(
        node.tun_name().is_none(),
        "app-owned TUN must not create a named system device",
    );
    assert_eq!(node.tun_state(), crate::upper::tun::TunState::Active);

    node.stop().await.unwrap();
}

/// Config for the app-owned-UDP-fd tests: one loopback UDP transport on an
/// ephemeral port and no DNS, mirroring `make_healthy_node`.
#[cfg(unix)]
fn udp_loopback_config() -> crate::Config {
    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = false;
    config
}

/// App-owned UDP fd seam: the embedder gets the descriptor of the socket the
/// transport actually bound, and gets it only once the bind has happened —
/// there is no fd to hand out before `start()`.
#[cfg(unix)]
#[tokio::test]
async fn app_owned_udp_fd_seam_delivers_the_bound_socket() {
    let mut node = make_node_with(udp_loopback_config());
    let rx = node.enable_app_owned_udp_fd();

    assert!(
        rx.try_recv().is_err(),
        "nothing is delivered at arm time — the socket is not bound until start()",
    );

    node.start().await.unwrap();

    let socket = rx
        .try_recv()
        .expect("the seam fires once the UDP socket is bound");
    let live_fd = node
        .transports
        .values()
        .next()
        .expect("the loopback UDP transport came up")
        .raw_fd();
    assert_eq!(
        Some(socket.fd),
        live_fd,
        "the delivered fd must be the live transport's socket, not some other descriptor",
    );
    assert_eq!(
        socket.instance, None,
        "a `Single` UDP config has no instance name to report",
    );

    assert!(
        rx.try_recv().is_err(),
        "one UDP transport bound means exactly one delivery",
    );

    node.stop().await.unwrap();
}

/// One message per UDP transport that binds: an embedder pinning sockets to a
/// network needs every listener's fd, not just the first, so the seam does not
/// latch after the first send.
#[cfg(unix)]
#[tokio::test]
async fn app_owned_udp_fd_seam_delivers_every_udp_listener_that_binds() {
    let mut listeners = std::collections::HashMap::new();
    for name in ["main", "backup"] {
        listeners.insert(
            name.to_string(),
            crate::config::UdpConfig {
                bind_addr: Some("127.0.0.1:0".to_string()),
                ..Default::default()
            },
        );
    }
    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Named(listeners);
    config.dns.enabled = false;

    let mut node = make_node_with(config);
    let rx = node.enable_app_owned_udp_fd();
    node.start().await.unwrap();

    let mut delivered: Vec<_> = rx
        .try_iter()
        .map(|socket| (socket.instance, socket.fd))
        .collect();
    delivered.sort_unstable();
    let mut live: Vec<_> = node
        .transports
        .values()
        .filter_map(|handle| {
            handle
                .raw_fd()
                .map(|fd| (handle.name().map(str::to_string), fd))
        })
        .collect();
    live.sort_unstable();
    assert_eq!(
        delivered, live,
        "every UDP listener that bound must be handed out, not just the first",
    );
    assert_eq!(delivered.len(), 2, "both named listeners bound");

    // The label is what makes two descriptors usable: an embedder pins each
    // socket to a different network, and arrival order — the transports come
    // out of a `HashMap` — cannot tell it which is which.
    let names: Vec<_> = delivered
        .iter()
        .map(|(instance, _)| instance.as_deref())
        .collect();
    assert!(
        names.contains(&Some("main")) && names.contains(&Some("backup")),
        "each fd names the configured instance it belongs to, got {names:?}",
    );
    assert_ne!(
        delivered[0].1, delivered[1].1,
        "two instances are two distinct sockets",
    );

    node.stop().await.unwrap();
}

/// No UDP transport means no fd: the channel stays silent rather than
/// delivering a sentinel, so a receive that times out is how an embedder tells
/// "there is no socket" from "here is the socket".
#[cfg(unix)]
#[tokio::test]
async fn app_owned_udp_fd_seam_stays_silent_without_a_udp_transport() {
    let mut config = crate::Config::new();
    config.dns.enabled = false;
    let mut node = make_node_with(config);
    let rx = node.enable_app_owned_udp_fd();

    // A node with no transports configured fails bring-up with
    // `NoOperationalTransports`; asserted so this test cannot silently stop
    // exercising the no-UDP path if that outcome ever changes.
    let started = node.start().await;
    assert!(
        started.is_err(),
        "a transportless node has no operational transports",
    );

    assert!(
        rx.try_recv().is_err(),
        "no UDP transport means no fd is ever delivered",
    );
}

/// A UDP transport that never bound has no fd to hand out. The bind address is
/// deliberately unparseable, so the failure is in parsing and cannot depend on
/// what else happens to hold a port while the suite runs.
#[cfg(unix)]
#[tokio::test]
async fn app_owned_udp_fd_seam_stays_silent_when_the_udp_transport_fails_to_start() {
    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("not-a-socket-addr".to_string()),
        ..Default::default()
    });
    config.dns.enabled = false;
    let mut node = make_node_with(config);
    let rx = node.enable_app_owned_udp_fd();

    // Transport-start failure is warn-and-continue; the node's overall start
    // outcome is not what this test pins.
    let _ = node.start().await;

    assert!(
        rx.try_recv().is_err(),
        "a UDP transport that never bound has no fd to hand out",
    );
}

/// The seam is per-`Node` state with a fresh channel per arming, so an embedder
/// that tears the mesh down and rebuilds the node — a radio off→on cycle — gets
/// the new socket on the new node's channel, with nothing shared between them.
#[cfg(unix)]
#[tokio::test]
async fn app_owned_udp_fd_seam_rearms_on_a_rebuilt_node() {
    let mut node_a = make_node_with(udp_loopback_config());
    let rx_a = node_a.enable_app_owned_udp_fd();
    node_a.start().await.unwrap();
    rx_a.try_recv()
        .expect("node A's socket reached node A's rx");
    node_a.stop().await.unwrap();
    drop(node_a);

    let mut node_b = make_node_with(udp_loopback_config());
    let rx_b = node_b.enable_app_owned_udp_fd();
    node_b.start().await.unwrap();
    rx_b.try_recv()
        .expect("node B's socket reached node B's rx");

    // Nothing from B reaches A's channel. (A is dropped, so this is
    // `Disconnected` rather than `Empty`; the specific variant is not part of
    // the contract, only that no fd arrives.)
    assert!(
        rx_a.try_recv().is_err(),
        "the channels are per-node — no shared or global arming state",
    );

    node_b.stop().await.unwrap();
}

/// Arming twice on the same node replaces the first arming: the last receiver
/// wins and the earlier one is disconnected. Asserted by firing through the
/// installed sender directly, so the test needs no real bind.
#[cfg(unix)]
#[test]
fn app_owned_udp_fd_seam_second_arm_replaces_the_first() {
    let mut node = make_node_with(udp_loopback_config());
    let rx1 = node.enable_app_owned_udp_fd();
    let rx2 = node.enable_app_owned_udp_fd();

    let sent = crate::node::AppOwnedUdpSocket {
        instance: Some("aware".to_string()),
        fd: 7,
    };
    node.supervisor
        .udp_fd_tx
        .as_ref()
        .expect("the second arming installed a sender")
        .send(sent.clone())
        .expect("the surviving receiver is live");

    assert_eq!(
        rx2.try_recv().ok(),
        Some(sent),
        "the last receiver armed is the one the node feeds",
    );
    assert!(
        rx1.try_recv().is_err(),
        "the replaced receiver gets nothing",
    );
}

/// The app-owned BLE radio seam. The slot is live from the moment it is armed
/// — before `start()`, which is when the transport that reads it gets built —
/// and installing a radio through it is a slot operation, not a node one.
#[cfg(all(ble_available, any(target_os = "android", test)))]
#[test]
fn app_owned_ble_radio_seam_hands_out_a_live_slot_before_start() {
    use crate::transport::ble::io_android::{AndroidBleBridge, BleRadioSlot};

    let mut node = make_node();
    let slot: std::sync::Arc<BleRadioSlot> = node.enable_app_owned_ble_radio();

    assert!(
        !slot.is_installed(),
        "arming supplies the slot, not a radio to put in it",
    );

    slot.install(AndroidBleBridge::new(std::sync::Arc::new(
        test_radio::TestRadio,
    )));
    assert!(slot.is_installed(), "the embedder installs whenever it can");

    slot.clear();
    assert!(!slot.is_installed(), "and can take it away again");
}

/// Arming twice returns the same slot, so a second call cannot orphan a radio
/// installed through the first. This is where the seam deliberately differs
/// from `enable_app_owned_udp_fd`, whose last arming wins: a channel can be
/// replaced because nothing was delivered on it yet, while a slot may already
/// be holding the embedder's live radio.
#[cfg(all(ble_available, any(target_os = "android", test)))]
#[test]
fn app_owned_ble_radio_seam_second_arm_returns_the_same_slot() {
    use crate::transport::ble::io_android::AndroidBleBridge;

    let mut node = make_node();
    let first = node.enable_app_owned_ble_radio();
    first.install(AndroidBleBridge::new(std::sync::Arc::new(
        test_radio::TestRadio,
    )));

    let second = node.enable_app_owned_ble_radio();

    assert!(
        std::sync::Arc::ptr_eq(&first, &second),
        "re-arming must not hand back a different slot",
    );
    assert!(
        second.is_installed(),
        "the radio installed through the first handle is still there",
    );
}

/// The slot is per-node state, which is the whole reason it is not a process
/// global: two nodes in one process each drive their own radio.
#[cfg(all(ble_available, any(target_os = "android", test)))]
#[test]
fn app_owned_ble_radio_slots_are_per_node() {
    use crate::transport::ble::io_android::AndroidBleBridge;

    let mut node_a = make_node();
    let mut node_b = make_node();
    let slot_a = node_a.enable_app_owned_ble_radio();
    let slot_b = node_b.enable_app_owned_ble_radio();

    slot_a.install(AndroidBleBridge::new(std::sync::Arc::new(
        test_radio::TestRadio,
    )));

    assert!(slot_a.is_installed());
    assert!(
        !slot_b.is_installed(),
        "node B's radio is node B's — no shared or global slot",
    );
}

/// A node that never armed the seam has no slot to hand the transport, which
/// is how a build with the embedder-supplied backend distinguishes "no radio
/// yet" from "this embedder does not supply one at all".
#[cfg(all(ble_available, any(target_os = "android", test)))]
#[test]
fn app_owned_ble_radio_seam_is_absent_until_armed() {
    let node = make_node();
    assert!(node.ble_radio.is_none());
}

#[cfg(all(ble_available, any(target_os = "android", test)))]
mod test_radio {
    use crate::transport::ble::addr::BleAddr;
    use crate::transport::ble::io_android::AndroidRadio;

    /// A radio that does nothing. These tests are about the seam handing one
    /// over, not about what it then does — that is covered where the backend
    /// lives.
    pub(super) struct TestRadio;

    impl AndroidRadio for TestRadio {
        fn listen(&self) -> u16 {
            0
        }
        fn connect(&self, _connect_id: i64, _addr: &BleAddr, _psm: u16) {}
        fn start_advertising(&self, _psm: u16) {}
        fn stop_advertising(&self) {}
        fn start_scanning(&self) {}
        fn stop_scanning(&self) {}
        fn close_channel(&self, _ch_id: i64) {}
    }
}

/// The embedder-facing DNS contract, end to end.
///
/// An embedder that owns the TUN fd (Android `VpnService`) has no system DNS
/// socket to point at us, so it proxies `.fips` query payloads it lifts out of
/// its own tunnel to the built-in responder. That requires three things to
/// hold, and this pins all three:
///
/// 1. `dns_local_addr()` publishes where to send — read back off the bound
///    socket, so a `port = 0` config reports the assigned port, not 0.
/// 2. The responder answers a proxied query with the right AAAA.
/// 3. The resolved identity reaches `dns_identity_rx` — the channel
///    `run_rx_loop` drains into `register_identity`. This is the leg that
///    populates the identity cache, without which the first packet to a
///    freshly-resolved `<npub>.fips` is rejected with ICMPv6 "No route".
#[tokio::test]
async fn dns_responder_serves_a_proxying_embedder() {
    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = true;
    config.dns.bind_addr = Some("::1".to_string());
    // Port 0: proves the address is read back off the socket rather than
    // echoed from config — an embedder dialling 0 would reach nothing.
    config.dns.port = Some(0);
    // The TUN is app-owned, as it is on the platform this seam serves.
    let mut node = make_node_with(config);
    let (_outbound_tx, _tun_rx) = node.enable_app_owned_tun();

    assert!(
        node.dns_local_addr().is_none(),
        "no responder before start()",
    );

    node.start().await.unwrap();

    let dns_addr = node
        .dns_local_addr()
        .expect("responder is up, so its address is published");
    assert_ne!(dns_addr.port(), 0, "must report the kernel-assigned port");

    // Proxy a query the way the embedder would: payload only, no IP/UDP header
    // (it strips those off the packet it read from its own TUN fd).
    let peer = Identity::generate();
    let query = {
        use simple_dns::{CLASS, Name, Packet, QCLASS, QTYPE, Question, TYPE};
        let mut packet = Packet::new_query(0x1234);
        packet.questions.push(Question::new(
            Name::new_unchecked(&format!("{}.fips", peer.npub())).into_owned(),
            QTYPE::TYPE(TYPE::AAAA),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        packet.build_bytes_vec().unwrap()
    };
    let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    client.send_to(&query, dns_addr).await.unwrap();

    let mut buf = [0u8; 512];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.recv_from(&mut buf),
    )
    .await
    .expect("responder answered within the timeout")
    .unwrap();

    let answer = simple_dns::Packet::parse(&buf[..len]).expect("well-formed DNS response");
    let rdata = &answer.answers.first().expect("one AAAA answer").rdata;
    let simple_dns::rdata::RData::AAAA(aaaa) = rdata else {
        panic!("expected an AAAA record, got {rdata:?}");
    };
    assert_eq!(
        std::net::Ipv6Addr::from(aaaa.address),
        peer.address().to_ipv6(),
        "AAAA must be the peer's FipsAddress",
    );

    // The identity leg. `run_rx_loop` owns the node for its whole life, so the
    // embedder cannot register identities itself — the responder publishes them
    // on this channel instead. Drain and register exactly as the rx-loop arm in
    // `dataplane/rx_loop.rs` does, then assert the cache is populated.
    let identity = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        node.supervisor
            .dns_identity_rx
            .as_mut()
            .expect("responder installed the identity receiver")
            .recv(),
    )
    .await
    .expect("identity published within the timeout")
    .expect("channel is open");

    assert_eq!(identity.node_addr, *peer.node_addr());
    node.register_identity(identity.node_addr, identity.pubkey);
    assert!(
        node.has_cached_identity(peer.node_addr()),
        "resolving a name must warm the identity cache, or the first packet \
         to that address is rejected with ICMPv6 \"No route\"",
    );

    node.stop().await.unwrap();
    assert!(
        node.dns_local_addr().is_none(),
        "the published address must be retracted with the listener",
    );
}

/// `retract_child_publications(Dns)` clears the published address.
///
/// Scoped to the helper deliberately, and named for that rather than for the
/// scenario: no responder dies here, and deleting the `run_rx_loop` call site
/// leaves this green. Driving a real exit through the loop needs the node moved
/// into a task, which puts `dns_local_addr()` out of reach — and the producer
/// side cannot deliver `Child::Dns` today regardless, since `run_dns_responder`
/// never returns.
///
/// What it does pin is the behavior the eventual wiring depends on: the FSM's
/// `ChildExited` handling only republishes node health, so without this
/// retraction `dns_local_addr()` would keep naming a socket nobody is listening
/// on, and a proxying embedder would see `.fips` queries silently time out
/// rather than any error it could act on.
#[tokio::test]
async fn retract_child_publications_clears_the_dns_address() {
    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = true;
    config.dns.bind_addr = Some("::1".to_string());
    config.dns.port = Some(0);
    let mut node = make_node_with(config);

    node.start().await.unwrap();
    assert!(node.dns_local_addr().is_some(), "responder came up");

    // What `run_rx_loop` does when the DNS task self-reports its exit.
    node.retract_child_publications(crate::node::lifecycle::supervisor::Child::Dns);

    assert!(
        node.dns_local_addr().is_none(),
        "a dead responder must not keep publishing an address to dial",
    );

    node.stop().await.unwrap();
}

/// `dns.enabled` with a bind that fails must report `None`, not an address.
///
/// This is the third state an embedder has to tell apart, and the one that
/// would otherwise be indistinguishable from a healthy responder by reading
/// config alone: DNS is switched on, so `config.dns.bind_addr()` names a
/// plausible target, but nothing is listening there. A bind failure is only
/// warned about and leaves the node running, so config is not evidence —
/// `dns_local_addr()` is.
///
/// The failure is forced with `EADDRINUSE` against a socket this test holds
/// open, rather than by naming an address the host has no interface for.
/// `bind_dns_socket` sets neither `SO_REUSEADDR` nor `SO_REUSEPORT`, so the
/// collision is deterministic on Linux and macOS. A non-local address is not:
/// `net.ipv4.ip_nonlocal_bind = 1` is ordinary on hosts running keepalived or
/// HAProxy and makes the bind succeed, which reds the test on a developer
/// machine while CI — at the default `0` — stays green.
#[tokio::test]
async fn dns_local_addr_stays_none_when_the_bind_fails() {
    // Hold the port for the whole test so the responder's bind collides.
    let squatter = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
    let taken = squatter.local_addr().unwrap();

    let mut config = crate::Config::new();
    config.transports.udp = crate::config::TransportInstances::Single(crate::config::UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        ..Default::default()
    });
    config.dns.enabled = true;
    config.dns.bind_addr = Some("::1".to_string());
    config.dns.port = Some(taken.port());
    let mut node = make_node_with(config);

    node.start().await.unwrap();

    assert!(
        node.dns_local_addr().is_none(),
        "an unbound responder must not publish an address",
    );

    node.stop().await.unwrap();
    drop(squatter);
}

/// A connection whose handshake failed is retained with BOTH Noise handles
/// empty, and the stale-connection sweep depends on that: presence of the
/// pending connection — not presence of a handle — is what marks a machine as
/// handshake-phase. If presence were ever derived from the handles, every
/// failed connection would become invisible to the sweep and leak forever,
/// holding a peering-budget slot and a wrong `connection_count` permanently.
#[test]
fn test_failed_connection_is_retained_and_reaped() {
    use crate::proto::fmp::LifecycleView;

    let mut node = make_node();
    let link_id = LinkId::new(1);
    let peer_identity = make_peer_identity();

    node.seed_handshake_machine(HandshakeSeed::outbound(link_id, peer_identity, 1000))
        .unwrap();
    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    node.peer_machines
        .get_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, 1000)
        .unwrap();

    // The send of that stored initiation fails.
    let machine = node.peer_machines.get_mut(&link_id).unwrap();
    machine.mark_failed();
    machine.mark_send_failed();

    // Both handles are now empty — the initiation handle was dropped and no
    // session was ever reached — yet the connection is deliberately retained.
    let leg = node.peer_machines.get(&link_id).unwrap().leg().unwrap();
    assert!(
        leg.noise_handshake.is_none() && leg.noise_session.is_none(),
        "a failed connection holds neither handle"
    );

    // (a) it still counts while it waits for the sweep
    assert_eq!(
        node.connection_count(),
        1,
        "a failed connection stays counted until it is reaped"
    );

    // (b) the sweep yields it
    let stale = node.stale_connections(2000, 30_000);
    assert_eq!(
        stale.len(),
        1,
        "the sweep must see a failed connection despite its empty handles"
    );
    assert_eq!(stale[0].link, link_id);

    // (c) reaping it clears the carrier
    node.remove_peer_machine(link_id);
    assert_eq!(node.connection_count(), 0);
}

/// Handshake-phase membership is decided by whether a crypto carrier is
/// ATTACHED, never by whether either Noise handle inside it is populated.
///
/// The distinction is the whole reason the carrier is a struct rather than a
/// pair of bare handle fields. A carrier legitimately sits attached and empty:
/// `mark_failed` drops the initiation handle and deliberately keeps the
/// carrier so the sweep can reclaim it, `take_session` empties the other, and
/// every handshake begins with both handles unset. If presence were derived
/// from the handles, every failed handshake would vanish from the sweep,
/// the count, and the peering budget at once — a permanent leak that no
/// existing test would notice.
///
/// This drives the empty-carrier shape past every presence predicate on
/// `Node` and asserts each one reports "present", then detaches and asserts
/// each reports "absent".
#[test]
fn handshake_presence_tracks_the_carrier_not_the_noise_handles() {
    use crate::proto::fmp::LifecycleView;

    let mut node = make_node();
    let link_id = LinkId::new(31);
    let transport_id = TransportId::new(9);
    let peer_identity = make_peer_identity();
    let peer_addr = TransportAddr::from_string("10.0.0.9:9999");

    node.seed_handshake_machine(
        HandshakeSeed::outbound(link_id, peer_identity, 1000)
            .with_transport_id(transport_id)
            .with_source_addr(peer_addr.clone()),
    )
    .unwrap();

    // A freshly seeded carrier holds neither handle — the construction window.
    let leg = node.peer_machines.get(&link_id).unwrap().leg().unwrap();
    assert!(
        leg.noise_handshake.is_none() && leg.noise_session.is_none(),
        "the seeded carrier must start with both handles empty"
    );

    // Every presence predicate must see it, handles or not.
    let assert_present = |node: &Node, when: &str| {
        assert_eq!(node.connection_count(), 1, "connection_count: {when}");
        assert_eq!(node.connections().count(), 1, "connections(): {when}");
        assert!(node.has_pending_leg(&link_id), "has_pending_leg: {when}");
        assert_eq!(
            node.stale_connections(1_000_000, 30_000).len(),
            1,
            "stale_connections: {when}"
        );
        assert!(
            node.is_connecting_to_peer_on_path(peer_identity.node_addr(), transport_id, &peer_addr),
            "is_connecting_to_peer_on_path: {when}"
        );
        // The last two predicates sit inline in functions with no callable
        // seam, so these MIRROR them rather than exercising them: the shape is
        // pinned here, but a mutation at the production site would not fail
        // this test. Both sites read `machine.leg().is_some()` verbatim.
        assert!(
            node.peer_machines.values().any(|machine| {
                machine.leg().is_some() && machine.conn_transport_id() == Some(transport_id)
            }),
            "transport-in-use: {when}"
        );
        // The complement of the rekey-msg2 discriminator: a machine carrying
        // a pending handshake marks a fresh establish, so `handle_msg2` must
        // NOT take its rekey-completion branch.
        assert!(
            node.peer_machines
                .get(&link_id)
                .is_some_and(|machine| machine.leg().is_some()),
            "rekey-msg2 discriminator: {when}"
        );
        // Fires the live-carrier coherence assertion; a machine that had gone
        // invisible would panic here rather than fail an assert_eq above.
        node.debug_assert_peer_maps_coherent();
    };

    assert_present(&node, "freshly seeded, both handles empty");

    // Drive to the failed shape: the initiation handle is dropped and the
    // carrier is deliberately retained for the sweep.
    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let machine = node.peer_machines.get_mut(&link_id).unwrap();
    machine
        .start_handshake(our_keypair, startup_epoch, 1000)
        .unwrap();
    assert!(
        machine.leg().unwrap().noise_handshake.is_some(),
        "start_handshake arms the initiation handle"
    );
    machine.mark_failed();
    machine.mark_send_failed();

    let leg = node.peer_machines.get(&link_id).unwrap().leg().unwrap();
    assert!(
        leg.noise_handshake.is_none() && leg.noise_session.is_none(),
        "a failed handshake holds neither handle"
    );
    assert_present(&node, "failed, both handles empty");

    // Detaching the carrier — and only that — ends handshake-phase membership.
    node.peer_machines.get_mut(&link_id).unwrap().take_leg();
    assert_eq!(node.connection_count(), 0, "connection_count after detach");
    assert_eq!(node.connections().count(), 0, "connections() after detach");
    assert!(
        !node.has_pending_leg(&link_id),
        "has_pending_leg after detach"
    );
    assert_eq!(
        node.stale_connections(1_000_000, 30_000).len(),
        0,
        "stale_connections after detach"
    );
    assert!(
        !node.is_connecting_to_peer_on_path(peer_identity.node_addr(), transport_id, &peer_addr),
        "is_connecting_to_peer_on_path after detach"
    );
}

/// The identity a responder discovers in msg1 must land on the surviving
/// carrier, not only on the pending leg. Everything that names an inbound
/// peer mid-handshake reads the carrier: the stale-connection sweep's
/// `retry_addr` decides whether a reaped leg is retried or torn down, and a
/// blank identity there silently changes that choreography.
#[test]
fn inbound_msg1_records_the_learned_identity_on_the_carrier() {
    use crate::proto::fmp::LifecycleView;

    let mut node = make_node();
    let link_id = LinkId::new(77);

    // A genuine IK msg1 addressed to this node, from a known sender.
    let sender = Identity::generate();
    let sender_identity = PeerIdentity::from_pubkey_full(sender.pubkey_full());
    let node_identity = PeerIdentity::from_pubkey_full(node.identity().pubkey_full());
    let initiator_link = LinkId::new(78);
    let mut initiator =
        crate::peer::machine::PeerMachine::new_outbound(initiator_link, node_identity, 1000);
    initiator.set_leg(crate::peer::machine::HandshakeCrypto::new());
    let noise_msg1 = initiator
        .start_handshake(sender.keypair(), [9u8; 8], 1000)
        .unwrap();

    // Drive the responder half over an inbound leg that stays pending.
    node.seed_handshake_machine(HandshakeSeed::inbound(link_id, 1000))
        .unwrap();
    let our_keypair = node.identity().keypair();
    let startup_epoch = node.startup_epoch();
    let machine = node.peer_machines.get_mut(&link_id).unwrap();
    machine
        .receive_handshake_init(our_keypair, startup_epoch, &noise_msg1, 1000)
        .unwrap();

    assert_eq!(
        machine.conn_expected_identity(),
        Some(&sender_identity),
        "msg1 identity learn must be recorded on the surviving carrier"
    );

    // The send of the responder's msg2 fails: the leg is retained, empty, for
    // the sweep to reclaim.
    machine.mark_failed();
    machine.mark_send_failed();

    let stale = node.stale_connections(2000, 30_000);
    assert_eq!(
        stale.len(),
        1,
        "the failed inbound leg must reach the sweep"
    );
    assert_eq!(
        stale[0].retry_addr,
        Some(*sender_identity.node_addr()),
        "a failed inbound leg still names the peer it learned from msg1"
    );
}

/// A msg1 that fails Noise processing must leave no trace in the registry.
/// The control machine is built above the crypto so it can drive the
/// handshake, but it stays a local until a promote tail inserts it — a
/// rejected msg1 drops it.
#[tokio::test]
async fn test_rejected_msg1_leaves_no_registry_trace() {
    let mut node = make_node();

    // Well-formed framing, garbage Noise payload: processing fails.
    let wire_msg1 = crate::proto::fmp::wire::build_msg1(
        SessionIndex::new(7),
        &[0u8; crate::noise::HANDSHAKE_MSG1_SIZE],
    );
    let packet = ReceivedPacket::with_timestamp(
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:5000"),
        wire_msg1,
        1000,
    );

    node.handle_msg1(packet).await;

    assert!(
        node.peer_machines.is_empty(),
        "a rejected msg1 must leave no control machine behind"
    );
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 0);
    assert_eq!(node.link_count(), 0);
    assert!(
        node.peers_by_index.is_empty(),
        "a rejected msg1 must allocate no session index"
    );
    assert_eq!(
        node.stats().handshake.bad_state,
        1,
        "the rejection is attributed to the handshake state-machine counter"
    );
}

/// The outbound path registers its control machine at dial, before msg1 is
/// prepared, so a preparation failure has to unwind that registration rather
/// than drop a local.
#[tokio::test]
async fn test_failed_msg1_preparation_unwinds_the_dial_machine() {
    let mut node = make_node();
    let link_id = LinkId::new(1);
    let transport_id = TransportId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5000");
    let peer_identity = make_peer_identity();

    // Stand in for the dial: the machine exists before msg1 is prepared.
    node.peer_machines.insert(
        link_id,
        PeerMachine::new_outbound(link_id, peer_identity, 1000),
    );
    // Force the index allocation inside msg1 preparation to fail.
    node.index_allocator = crate::utils::index::IndexAllocator::with_max_attempts(0);

    let result = node.prepare_outbound_msg1(link_id, transport_id, &remote_addr, peer_identity);

    assert!(matches!(result, Err(NodeError::IndexAllocationFailed(_))));
    assert!(
        !node.peer_machines.contains_key(&link_id),
        "a failed msg1 preparation must unwind the dial-time machine"
    );
    assert_eq!(node.connection_count(), 0);
}

/// The link, direction, and peer address that promotion and the operator view
/// read now come from the control machine rather than the pending connection.
/// A machine's direction is seeded at construction and must match the side that
/// actually opened the link, and its address must be populated by the time
/// promotion needs it.
///
/// This covers the two shapes that seed a carrier independently: the dial and
/// an accepted inbound message 1. The cross-connection winner derives both
/// values from a carrier one of those two already seeded, so it has nothing
/// separate to pin.
#[tokio::test]
async fn test_machine_carries_link_direction_and_address_on_dial_and_inbound() {
    // Outbound: the dial builds the machine, msg1 preparation fills it in.
    let mut node = make_node();
    let link_id = LinkId::new(1);
    let transport_id = TransportId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5000");
    let peer_identity = make_peer_identity();
    node.peer_machines.insert(
        link_id,
        PeerMachine::new_outbound(link_id, peer_identity, 1000),
    );
    node.prepare_outbound_msg1(link_id, transport_id, &remote_addr, peer_identity)
        .unwrap();

    let machine = node.peer_machines.get(&link_id).unwrap();
    assert_eq!(machine.link_id(), link_id);
    assert!(machine.conn_is_outbound(), "a dial is outbound");
    assert!(!machine.conn_is_inbound());
    assert_eq!(machine.conn_direction(), LinkDirection::Outbound);
    assert_eq!(
        machine.conn_source_addr(),
        Some(&remote_addr),
        "the dialled address must reach the surviving carrier"
    );

    // Inbound: msg1 builds the machine from the packet.
    let mut responder = make_node();
    let initiator = make_node();
    let responder_identity = PeerIdentity::from_pubkey_full(responder.identity().pubkey_full());
    let mut initiator_leg = outbound_leg(LinkId::new(9), responder_identity, 1000);
    let noise_msg1 = initiator_leg
        .start_handshake(
            initiator.identity().keypair(),
            initiator.startup_epoch(),
            1000,
        )
        .unwrap();
    let inbound_addr = TransportAddr::from_string("127.0.0.1:6000");
    let packet = ReceivedPacket::with_timestamp(
        TransportId::new(1),
        inbound_addr.clone(),
        crate::proto::fmp::wire::build_msg1(SessionIndex::new(7), &noise_msg1),
        1000,
    );
    responder.handle_msg1(packet).await;

    // The responder completes at msg1 and promotes, so the machine survives as
    // the active peer's control machine — the carrier outlives the connection.
    let (link, machine) = responder
        .peer_machines
        .iter()
        .next()
        .expect("msg1 leaves a control machine behind");
    assert!(machine.conn_is_inbound(), "an accepted msg1 is inbound");
    assert!(!machine.conn_is_outbound());
    assert_eq!(machine.conn_direction(), LinkDirection::Inbound);
    assert_eq!(
        machine.conn_source_addr(),
        Some(&inbound_addr),
        "the sender's address must reach the surviving carrier"
    );
    assert_eq!(machine.link_id(), *link);
}

#[test]
fn test_peer_display_name_uses_cached_short_npub() {
    // Path 3 of `peer_display_name` (no host entry, no alias) reads the
    // per-peer cached short npub; it must still equal the value derived
    // from the peer's identity.
    let mut node = make_node();
    let peer_identity_full = Identity::generate();
    let peer_addr = *peer_identity_full.node_addr();
    let peer_identity = PeerIdentity::from_pubkey(peer_identity_full.pubkey());
    node.peers
        .insert(peer_addr, ActivePeer::new(peer_identity, LinkId::new(1), 0));

    assert_eq!(
        node.peer_display_name(&peer_addr),
        peer_identity.short_npub()
    );
}

#[test]
fn test_peer_display_name_tracks_alias_change() {
    // The display name is NOT cached on the peer: `peer_aliases` is a
    // runtime-mutable map (`update_peers` inserts and removes entries), so
    // a cached name would go stale. Caching only the immutable short npub
    // must leave that tracking intact.
    let mut node = make_node();
    let peer_identity_full = Identity::generate();
    let peer_addr = *peer_identity_full.node_addr();
    let peer_identity = PeerIdentity::from_pubkey(peer_identity_full.pubkey());
    node.peers
        .insert(peer_addr, ActivePeer::new(peer_identity, LinkId::new(1), 0));

    assert_eq!(
        node.peer_display_name(&peer_addr),
        peer_identity.short_npub()
    );

    node.peer_aliases.insert(peer_addr, "gateway".to_string());
    assert_eq!(node.peer_display_name(&peer_addr), "gateway");

    node.peer_aliases.remove(&peer_addr);
    assert_eq!(
        node.peer_display_name(&peer_addr),
        peer_identity.short_npub()
    );
}

/// The DNS mesh-interface filter is keyed on the device the node actually
/// created, not on the configured name. macOS and FreeBSD hand out utunN and
/// tunN of the kernel's choosing, so a filter keyed on the configured name
/// resolved to nothing there and was permanently off.
#[cfg(unix)]
#[test]
fn mesh_filter_resolves_the_live_tun_device_rather_than_the_configured_name() {
    let loopback = if cfg!(target_os = "macos") {
        "lo0"
    } else {
        "lo"
    };
    let c_name = std::ffi::CString::new(loopback).unwrap();
    let expected = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
    if expected == 0 {
        return;
    }

    let mut config = Config::new();
    config.tun.name = Some("fips-absent-dev".to_string());
    let mut node = Node::new(config).unwrap();

    assert_eq!(node.mesh_ifindex(), None);

    node.tun_name = Some(loopback.to_string());
    assert_eq!(node.mesh_ifindex(), Some(expected));
}
