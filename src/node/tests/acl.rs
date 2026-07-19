use super::*;
use crate::ReceivedPacket;
use crate::node::acl::PeerAclReloader;
use crate::node::reloadable::HostMapReloadable;
use crate::proto::fmp::wire::build_msg2;
use crate::upper::hosts::HostMap;
use crate::utils::index::SessionIndex;
use std::path::PathBuf;
use std::time::Duration;

fn make_acl_node() -> (tempfile::TempDir, Node) {
    let dir = tempfile::tempdir().unwrap();
    let mut node = Node::new(Config::new()).unwrap();
    node.peer_acl = PeerAclReloader::with_paths(
        dir.path().join("peers.allow"),
        dir.path().join("peers.deny"),
    );
    (dir, node)
}

fn allow_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("peers.allow")
}

fn deny_path(dir: &tempfile::TempDir) -> PathBuf {
    dir.path().join("peers.deny")
}

#[tokio::test]
async fn test_outbound_connect_denied_by_denylist() {
    let (dir, mut node) = make_acl_node();
    let denied = Identity::generate();
    std::fs::write(deny_path(&dir), format!("{}\n", denied.npub())).unwrap();
    node.reload_peer_acl().await;

    let result = node
        .initiate_connection(
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:9000"),
            Some(PeerIdentity::from_pubkey_full(denied.pubkey_full())),
        )
        .await;

    assert!(matches!(result, Err(NodeError::AccessDenied(_))));
    assert_eq!(node.link_count(), 0);
    assert_eq!(node.connection_count(), 0);
    assert_eq!(node.peer_count(), 0);
}

// The master-line `test_inbound_msg1_denied_by_acl` has no counterpart here.
// Under XX, msg1 is an ephemeral-only exchange that carries no identity, so
// there is no peer to authorize at that step and no ACL decision to assert.
// The equivalent gate on this line runs once msg3 has revealed the initiator's
// static key; `test_inbound_msg3_denied_by_acl` covers it there.

#[tokio::test]
async fn test_outbound_msg2_denied_after_acl_reload() {
    let (dir, mut node_a) = make_acl_node();
    let node_b = make_node();
    let transport_id = TransportId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5001");
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());

    let link_id_a = node_a.allocate_link_id();
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    node_a
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id_a, peer_b_identity, 1000)
                .with_our_index(our_index_a)
                .with_transport_id(transport_id)
                .with_source_addr(remote_addr.clone()),
        )
        .unwrap();
    let keypair_a = node_a.identity().keypair();
    let epoch_a = node_a.startup_epoch();
    let noise_msg1 = node_a
        .peer_machines
        .get_mut(&link_id_a)
        .unwrap()
        .start_handshake(keypair_a, epoch_a, 1000)
        .unwrap();

    let link_a = Link::connectionless(
        link_id_a,
        transport_id,
        remote_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a
        .addr_to_link
        .insert((transport_id, remote_addr.clone()), link_id_a);
    node_a
        .pending_outbound
        .insert((transport_id, our_index_a.as_u32()), link_id_a);

    let mut conn_b = inbound_leg(LinkId::new(2), 1000);
    let responder_epoch = [0x11; 8];
    let noise_msg2 = conn_b
        .receive_handshake_init(
            node_b.identity().keypair(),
            responder_epoch,
            &noise_msg1,
            None,
            1000,
        )
        .unwrap();
    let our_index_b = SessionIndex::new(9);
    let wire_msg2 = build_msg2(our_index_b, our_index_a, &noise_msg2);

    std::fs::write(deny_path(&dir), format!("{}\n", node_b.npub())).unwrap();
    assert!(node_a.reload_peer_acl().await);

    let packet = ReceivedPacket::with_timestamp(transport_id, remote_addr, wire_msg2, 1100);
    node_a.handle_msg2(packet).await;

    assert_eq!(node_a.peer_count(), 0);
    assert_eq!(node_a.connection_count(), 0);
    assert_eq!(node_a.link_count(), 0);
    assert!(node_a.pending_outbound.is_empty());
}

/// Inbound rejection at msg3 must also cut down the initiator.
///
/// Under Noise XX the responder only sees the initiator's identity after
/// processing msg3, so by the time the inbound ACL fires, the initiator
/// has already completed its side of the handshake and promoted the peer
/// locally. Without an explicit rejection signal the initiator would sit
/// as a "zombie peer" until link-dead timeout — several seconds too slow
/// for the `acl-allowlist` integration test's 5s convergence check.
///
/// Exercises the full round trip: responder sends an encrypted
/// `Disconnect(Other)` on the newly-established Noise session, and the
/// initiator's existing `handle_disconnect` path tears the peer down.
#[tokio::test]
async fn test_inbound_msg3_denied_triggers_disconnect() {
    use crate::config::UdpConfig;
    use crate::node::acl::PeerAclReloader;
    use crate::proto::fmp::wire::build_msg1;
    use crate::transport::udp::UdpTransport;
    use crate::transport::{TransportHandle, packet_channel};
    use tokio::time::{Duration, timeout};

    // === Setup: node A (initiator) and node B (responder) over UDP ===

    let mut node_a = make_node();

    let dir_b = tempfile::tempdir().unwrap();
    let mut node_b = make_node();
    node_b.peer_acl = PeerAclReloader::with_paths(
        dir_b.path().join("peers.allow"),
        dir_b.path().join("peers.deny"),
    );
    std::fs::write(
        dir_b.path().join("peers.deny"),
        format!("{}\n", node_a.npub()),
    )
    .unwrap();
    assert!(node_b.reload_peer_acl().await);

    let transport_id_a = TransportId::new(1);
    let transport_id_b = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx_a, mut packet_rx_a) = packet_channel(64);
    let (packet_tx_b, mut packet_rx_b) = packet_channel(64);

    let mut transport_a = UdpTransport::new(transport_id_a, None, udp_config.clone(), packet_tx_a);
    let mut transport_b = UdpTransport::new(transport_id_b, None, udp_config, packet_tx_b);
    transport_a.start_async().await.unwrap();
    transport_b.start_async().await.unwrap();

    let addr_b = TransportAddr::from_string(&transport_b.local_addr().unwrap().to_string());

    node_a
        .transports
        .insert(transport_id_a, TransportHandle::Udp(transport_a));
    node_b
        .transports
        .insert(transport_id_b, TransportHandle::Udp(transport_b));

    // === A initiates the handshake ===

    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let link_id_a = node_a.allocate_link_id();
    let our_index_a = node_a.index_allocator.allocate().unwrap();
    // Mirror the production dial path: the seam seeds the outbound leg's
    // control machine, which owns the handshake crypto.
    node_a
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id_a, peer_b_identity, 1000)
                .with_our_index(our_index_a)
                .with_transport_id(transport_id_a)
                .with_source_addr(addr_b.clone()),
        )
        .unwrap();
    let our_keypair_a = node_a.identity().keypair();
    let startup_epoch_a = node_a.startup_epoch();
    let noise_msg1 = node_a
        .peer_machines
        .get_mut(&link_id_a)
        .unwrap()
        .start_handshake(our_keypair_a, startup_epoch_a, 1000)
        .unwrap();

    let wire_msg1 = build_msg1(our_index_a, &noise_msg1);
    let link_a = Link::connectionless(
        link_id_a,
        transport_id_a,
        addr_b.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    node_a.links.insert(link_id_a, link_a);
    node_a
        .addr_to_link
        .insert((transport_id_a, addr_b.clone()), link_id_a);
    node_a
        .pending_outbound
        .insert((transport_id_a, our_index_a.as_u32()), link_id_a);

    let transport = node_a.transports.get(&transport_id_a).unwrap();
    transport
        .send(&addr_b, &wire_msg1)
        .await
        .expect("Failed to send msg1");

    // === B: msg1 → msg2 (no ACL check yet, identity unknown) ===

    let packet_b_msg1 = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg1")
        .expect("Channel closed");
    node_b.handle_msg1(packet_b_msg1).await;
    assert_eq!(node_b.peer_count(), 0, "B should not promote at msg1 (XX)");
    assert_eq!(node_b.connection_count(), 1, "B should hold pending conn");

    // === A: msg2 → promotes, sends msg3 ===

    let packet_a_msg2 = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for msg2")
        .expect("Channel closed");
    node_a.handle_msg2(packet_a_msg2).await;
    assert_eq!(node_a.peer_count(), 1, "A promoted after msg2 (XX zombie)");

    // === B: msg3 → ACL reject, sends encrypted Disconnect, tears down ===

    let packet_b_msg3 = timeout(Duration::from_secs(1), packet_rx_b.recv())
        .await
        .expect("Timeout waiting for msg3")
        .expect("Channel closed");
    node_b.handle_msg3(packet_b_msg3).await;

    assert_eq!(node_b.peer_count(), 0, "B must not promote a denied peer");
    assert_eq!(node_b.connection_count(), 0, "B pending conn cleaned up");
    assert_eq!(node_b.link_count(), 0, "B link cleaned up");

    // === A: encrypted frame arrives → handle_encrypted_frame →
    //        handle_disconnect → remove_active_peer ===

    let disconnect_packet = timeout(Duration::from_secs(1), packet_rx_a.recv())
        .await
        .expect("Timeout waiting for Disconnect from B")
        .expect("Channel closed");
    node_a.handle_encrypted_frame(disconnect_packet).await;

    assert_eq!(
        node_a.peer_count(),
        0,
        "A must drop the zombie peer after receiving Disconnect"
    );

    // Clean up transports
    for (_, t) in node_a.transports.iter_mut() {
        t.stop().await.ok();
    }
    for (_, t) in node_b.transports.iter_mut() {
        t.stop().await.ok();
    }
}

#[tokio::test]
async fn test_host_map_hot_reloads_from_tick() {
    let dir = tempfile::tempdir().unwrap();
    let hosts_path = dir.path().join("hosts");

    let mut node = Node::new(Config::new()).unwrap();
    node.host_map = HostMapReloadable::new(HostMap::new(), hosts_path.clone());

    let peer = Identity::generate();
    let peer_addr = *PeerIdentity::from_pubkey_full(peer.pubkey_full()).node_addr();

    // No hosts file yet: the display name is not the alias.
    assert_ne!(node.peer_display_name(&peer_addr), "gateway");
    assert!(!node.reload_host_map().await);

    // Write a hosts entry and let the tick-driven reload pick it up.
    std::thread::sleep(Duration::from_millis(50));
    std::fs::write(&hosts_path, format!("gateway   {}\n", peer.npub())).unwrap();

    assert!(node.reload_host_map().await);
    assert_eq!(node.peer_display_name(&peer_addr), "gateway");

    // No further change: reload reports nothing replaced.
    assert!(!node.reload_host_map().await);
}

#[tokio::test]
async fn test_outbound_connect_not_denied_by_allowlist_miss() {
    let (dir, mut node) = make_acl_node();
    let denied = Identity::generate();
    let allowed = Identity::generate();
    std::fs::write(allow_path(&dir), format!("{}\n", allowed.npub())).unwrap();
    node.reload_peer_acl().await;

    let result = node
        .initiate_connection(
            TransportId::new(1),
            TransportAddr::from_string("127.0.0.1:9000"),
            Some(PeerIdentity::from_pubkey_full(denied.pubkey_full())),
        )
        .await;

    assert!(!matches!(result, Err(NodeError::AccessDenied(_))));
}

/// A peer the ACL turns away must leave nothing behind in the registry.
///
/// Under Noise XX the inbound admission gate cannot sit at msg1 — no static
/// key has crossed the wire yet — so it sits at the msg3 `authorize_peer`
/// call, by which point the responder has built a control machine, allocated
/// a session index, opened a link, and completed the Noise session. All of
/// that has to come back down on the denial. A machine left in
/// `peer_machines` is unreachable by every teardown path and holds a
/// peering-budget slot forever, so that is what this pins, along with the
/// link and the connection count.
///
/// What it deliberately does NOT pin is session-index hygiene. This arm does
/// not return the index to the allocator today, unlike the sibling bad-state
/// arm just above it; that gap is tracked and is left exactly as it is here,
/// since this change adds tests only. Asserting on `peers_by_index` would
/// look like coverage of it and would be worthless: nothing maps an index
/// until promotion, which is downstream of this gate, so such an assertion
/// holds no matter what the denial cleans up.
#[tokio::test]
async fn test_acl_rejected_msg3_leaves_no_registry_trace() {
    use crate::proto::fmp::wire::{Msg2Header, build_msg1, build_msg3};

    let (dir_b, mut node_b) = make_acl_node();
    let node_a = make_node();
    std::fs::write(deny_path(&dir_b), format!("{}\n", node_a.npub())).unwrap();
    assert!(node_b.reload_peer_acl().await);

    let transport_id = TransportId::new(1);
    let remote_addr = TransportAddr::from_string("127.0.0.1:5000");

    // Neither node has a transport installed, so the wire bytes are carried
    // across by hand. A dials B and B answers msg2.
    let peer_b_identity = PeerIdentity::from_pubkey_full(node_b.identity().pubkey_full());
    let our_index_a = SessionIndex::new(7);
    let mut conn_a = outbound_leg(LinkId::new(1), peer_b_identity, 1000);
    let noise_msg1 = conn_a
        .start_handshake(node_a.identity().keypair(), node_a.startup_epoch(), 1000)
        .unwrap();

    node_b
        .handle_msg1(ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr.clone(),
            build_msg1(our_index_a, &noise_msg1),
            1000,
        ))
        .await;

    // B has parked a machine awaiting msg3. No admission decision has run:
    // it still does not know who dialed it.
    let link_id_b = *node_b
        .peer_machines
        .keys()
        .next()
        .expect("msg1 parks a machine on the responder");
    let machine_b = node_b.peer_machines.get(&link_id_b).unwrap();
    let our_index_b = machine_b
        .our_index()
        .expect("msg1 allocates the responder's session index");
    let wire_msg2 = machine_b
        .conn_handshake_msg2()
        .expect("msg1 stores the framed msg2 on the carrier")
        .to_vec();
    assert_eq!(node_b.link_count(), 1);

    // A completes on msg2 and answers msg3, which is where its static key —
    // and therefore the denial — first reaches B.
    let msg2_header = Msg2Header::parse(&wire_msg2).unwrap();
    let (noise_msg3, _) = conn_a
        .complete_handshake(msg2_header.noise_msg2(&wire_msg2), None, 1100)
        .unwrap();

    node_b
        .handle_msg3(ReceivedPacket::with_timestamp(
            transport_id,
            remote_addr,
            build_msg3(our_index_a, our_index_b, &noise_msg3),
            1200,
        ))
        .await;

    assert!(
        node_b.peer_machines.is_empty(),
        "a denied peer must leave no control machine behind"
    );
    assert_eq!(node_b.connection_count(), 0);
    assert_eq!(node_b.peer_count(), 0);
    assert_eq!(node_b.link_count(), 0);
    assert_eq!(
        node_b.stats().handshake.bad_state,
        1,
        "the denial is attributed to the handshake state-machine counter"
    );
}
