//! Index-only demux: the first step of the multi-path switchover design
//! (`docs/design/fips-multi-path-switchover.md`, §3).
//!
//! A session index is unique across transports, so a frame carrying a known
//! `receiver_idx` decrypts no matter which transport delivered it. That opens
//! cross-transport delivery, and two rules keep it closed to a relay:
//!
//! 1. an authentic frame from another transport is delivered but does not
//!    move the peer (`ActivePeer::set_current_addr` freezes the transport);
//! 2. a decrypt failure on a transport the peer is not on is not counted
//!    toward the force-removal threshold.

use super::connected_udp::{
    PROMOTED_ADDR, far_side_frame, promoted_peer_with_the_far_side_session,
};
use super::*;
use crate::proto::fmp::wire::{build_encrypted, build_established_header};

/// Where a frame "from the wifi" claims to come from.
const OTHER_ADDR: &str = "10.0.0.7:2121";

/// Threshold constant in node/dataplane/encrypted.rs.
const THRESHOLD: u32 = 20;

/// A well-formed established header over random bytes that no session will
/// authenticate.
fn garbage_frame(receiver_idx: SessionIndex, counter: u64) -> Vec<u8> {
    let junk = [0xA5u8; 48];
    let header = build_established_header(receiver_idx, counter, 0, junk.len() as u16);
    build_encrypted(&header, &junk)
}

#[tokio::test]
async fn an_authentic_frame_on_another_transport_is_delivered_but_does_not_move_the_peer() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);

    // One prior failure, so a successful decrypt is observable as the reset.
    node.handle_decrypt_failure(&node_addr);
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        1
    );

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        wifi,
        TransportAddr::from_string(OTHER_ADDR),
        frame,
    ))
    .await;

    let peer = node
        .get_peer(&node_addr)
        .expect("an authentic frame never removes a peer");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "the frame must have been found by index and authenticated"
    );
    assert_eq!(
        peer.transport_id(),
        Some(cable),
        "an authentic frame on another transport must not move the peer's send side"
    );
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(PROMOTED_ADDR)),
        "nor its address"
    );
}

#[tokio::test]
async fn an_authentic_frame_on_the_bound_transport_still_roams_the_address() {
    let cable = TransportId::new(1);
    let (mut node, node_addr, our_index, mut far_side) =
        promoted_peer_with_the_far_side_session(cable);

    let frame = far_side_frame(&mut far_side, our_index);
    node.handle_encrypted_frame(ReceivedPacket::new(
        cable,
        TransportAddr::from_string(OTHER_ADDR),
        frame,
    ))
    .await;

    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string(OTHER_ADDR)),
        "roaming inside the bound transport is unchanged"
    );
}

#[tokio::test]
async fn garbage_from_a_transport_the_peer_is_not_on_is_not_counted() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    for counter in 0..(THRESHOLD * 2) as u64 {
        node.handle_encrypted_frame(ReceivedPacket::new(
            wifi,
            TransportAddr::from_string(OTHER_ADDR),
            garbage_frame(our_index, counter),
        ))
        .await;
    }

    let peer = node
        .get_peer(&node_addr)
        .expect("garbage from a transport the peer is not on must not tear it down");
    assert_eq!(
        peer.consecutive_decrypt_failures(),
        0,
        "off-path failures are dropped, not counted"
    );
}

#[tokio::test]
async fn garbage_on_the_bound_transport_still_counts() {
    let cable = TransportId::new(1);
    let (mut node, node_addr, our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    for counter in 0..THRESHOLD as u64 {
        node.handle_encrypted_frame(ReceivedPacket::new(
            cable,
            TransportAddr::from_string(PROMOTED_ADDR),
            garbage_frame(our_index, counter),
        ))
        .await;
    }

    assert!(
        node.get_peer(&node_addr).is_none(),
        "the threshold still applies on the transport the peer is on"
    );
    assert!(
        !node.peers_by_index.contains_key(&our_index.as_u32()),
        "and the index entry goes with it"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn a_worker_failure_report_is_charged_only_on_the_bound_transport() {
    use crate::node::decrypt_worker::DecryptFailureReport;

    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (mut node, node_addr, _our_index, _far_side) =
        promoted_peer_with_the_far_side_session(cable);

    node.process_decrypt_failure_report(DecryptFailureReport {
        source_node_addr: node_addr,
        transport_id: wifi,
        fmp_counter: 7,
        fmp_replay_highest: 0,
    })
    .await;
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        0,
        "a worker report from a transport the peer is not on is not counted"
    );

    node.process_decrypt_failure_report(DecryptFailureReport {
        source_node_addr: node_addr,
        transport_id: cable,
        fmp_counter: 8,
        fmp_replay_highest: 0,
    })
    .await;
    assert_eq!(
        node.get_peer(&node_addr)
            .unwrap()
            .consecutive_decrypt_failures(),
        1,
        "one from the bound transport is"
    );
}

#[test]
fn set_current_addr_roams_inside_the_bound_transport_only() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let mut peer = crate::peer::ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);

    // Unbound: the first sighting binds.
    assert!(peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:1")));
    assert_eq!(peer.transport_id(), Some(cable));

    // Same transport, new address: a roam.
    assert!(peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:2")));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );

    // Same transport, same address: nothing changed.
    assert!(!peer.set_current_addr(cable, TransportAddr::from_string("10.0.0.1:2")));

    // Another transport: refused, nothing moved.
    assert!(!peer.set_current_addr(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.transport_id(), Some(cable));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.1:2"))
    );

    // The deliberate rebind crosses.
    assert!(peer.rebind_transport(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.transport_id(), Some(wifi));
    assert_eq!(
        peer.current_addr(),
        Some(&TransportAddr::from_string("10.0.0.7:1"))
    );
}

#[test]
fn a_promoted_peer_holds_one_path_and_rebind_repoints_it() {
    let cable = TransportId::new(1);
    let wifi = TransportId::new(2);
    let (node, node_addr, _our_index, _far_side) = promoted_peer_with_the_far_side_session(cable);
    let peer = node.get_peer(&node_addr).unwrap();
    assert_eq!(peer.paths().len(), 1, "promotion binds exactly one path");
    assert_eq!(peer.active_path().map(|p| p.transport_id()), Some(cable));
    assert_eq!(
        peer.active_path().map(|p| p.addr()),
        Some(&TransportAddr::from_string(PROMOTED_ADDR))
    );

    // Until the probe exchange adds paths, a rebind re-points the single
    // path rather than growing the set.
    let mut peer = crate::peer::ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    assert!(peer.paths().is_empty());
    assert!(peer.rebind_transport(cable, TransportAddr::from_string("10.0.0.1:1")));
    assert!(peer.rebind_transport(wifi, TransportAddr::from_string("10.0.0.7:1")));
    assert_eq!(peer.paths().len(), 1);
    assert_eq!(peer.transport_id(), Some(wifi));
}

// ============================================================================
// UDP `interface:` binding
// ============================================================================

// ============================================================================
// Path probe / path ack (design §4)
// ============================================================================

use super::spanning_tree::{
    LOOPBACK_REGISTRY, TestNode, initiate_handshake, make_test_node, next_loopback_addr,
    process_available_packets,
};
use crate::peer::PathState;
use crate::proto::link::PathMessage;
use crate::transport::TransportHandle;
use crate::transport::loopback::LoopbackTransport;

/// The second transport both nodes share, standing in for the wifi next
/// to the cable that `TestNode` comes with.
fn wifi() -> TransportId {
    TransportId::new(2)
}

/// Give `node` a second loopback transport, `wifi()`, on a fresh address that
/// delivers into the node's existing packet channel. Returns that address.
fn add_wifi(node: &mut TestNode) -> TransportAddr {
    let addr = next_loopback_addr();
    let tx = LOOPBACK_REGISTRY
        .lock()
        .unwrap()
        .get(&node.addr)
        .cloned()
        .expect("the node's cable address is registered");
    LOOPBACK_REGISTRY.lock().unwrap().insert(addr.clone(), tx);
    let transport = LoopbackTransport::new(wifi(), addr.clone(), LOOPBACK_REGISTRY.clone());
    node.node
        .transports
        .insert(wifi(), TransportHandle::Loopback(transport));
    addr
}

/// Two nodes peered over the cable, each also reachable over `wifi()`.
/// Returns `(nodes, wifi_addr_of_0, wifi_addr_of_1)`.
async fn dual_homed_pair() -> (Vec<TestNode>, TransportAddr, TransportAddr) {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let wifi_0 = add_wifi(&mut nodes[0]);
    let wifi_1 = add_wifi(&mut nodes[1]);
    initiate_handshake(&mut nodes, 0, 1).await;
    for _ in 0..10 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert_eq!(nodes[0].node.peer_count(), 1, "peered over the cable");
    assert_eq!(nodes[1].node.peer_count(), 1, "peered over the cable");
    (nodes, wifi_0, wifi_1)
}

/// Hand `nodes[i]` the address `addr` for `peer` on `transport` and run one
/// heartbeat tick: the production route by which a path gets probed
/// (`add_path_candidate` is what a beacon, a config entry or a completed
/// dial leaves behind; the tick is the one issuer of probes). Nothing is
/// delivered here — the caller drives `process_available_packets`.
async fn probe_candidate(
    nodes: &mut [TestNode],
    i: usize,
    peer: NodeAddr,
    transport: TransportId,
    addr: TransportAddr,
) {
    nodes[i].node.add_path_candidate(peer, transport, addr);
    nodes[i].node.run_path_heartbeats().await;
}

#[test]
fn path_message_round_trips_on_the_wire() {
    let probe = PathMessage {
        probe_id: 0xDEAD_BEEF,
        remote_active: true,
        path_id: 7,
    };
    let wire = probe.encode_probe();
    assert_eq!(wire[0], 0x52);
    assert_eq!(PathMessage::decode(&wire[1..]).unwrap(), probe);

    let ack = PathMessage {
        probe_id: 7,
        remote_active: false,
        path_id: 0xFFFF_0000,
    };
    let wire = ack.encode_ack();
    assert_eq!(wire[0], 0x53);
    assert_eq!(PathMessage::decode(&wire[1..]).unwrap(), ack);

    assert!(PathMessage::decode(&wire[1..8]).is_err(), "short payload");
    let mut padded = wire.to_vec();
    padded.extend_from_slice(&[0u8; 1200]);
    assert_eq!(
        PathMessage::decode(&padded[1..]).unwrap(),
        ack,
        "padding is ignored"
    );
}

#[tokio::test]
async fn a_probe_adds_a_path_at_both_ends_and_the_ack_makes_it_live() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    let cable = nodes[0].transport_id;

    // Node 1 probes node 0 over the wifi.
    probe_candidate(&mut nodes, 1, addr_0, wifi(), wifi_0.clone()).await;
    {
        let peer = nodes[1].node.get_peer(&addr_0).unwrap();
        let path = peer
            .path_on(wifi())
            .expect("the prober adds the path first");
        assert_eq!(path.state(), PathState::Probing);
        assert!(path.tx_live_at_ms().is_none());
    }

    // The probe reaches node 0 (the tick heartbeats the active path too,
    // now that the peer has two).
    assert!(process_available_packets(&mut nodes).await >= 1);
    {
        let peer = nodes[0].node.get_peer(&addr_1).unwrap();
        let path = peer.path_on(wifi()).expect("the receiver adds the path");
        assert_eq!(
            path.state(),
            PathState::Probing,
            "hearing is not proof of the reverse"
        );
        assert!(path.rx_live_at_ms().is_some());
        assert!(!path.remote_active(), "node 1 still sends on the cable");
        assert_eq!(peer.transport_id(), Some(cable), "nothing switched");
        assert_eq!(peer.paths().len(), 2);
    }

    // The ack reaches node 1.
    assert!(process_available_packets(&mut nodes).await >= 1);
    {
        let peer = nodes[1].node.get_peer(&addr_0).unwrap();
        let path = peer.path_on(wifi()).unwrap();
        assert_eq!(path.state(), PathState::Live);
        assert!(path.tx_live_at_ms().is_some());
        assert!(path.last_rtt_ms().is_some());
        assert!(!path.remote_active(), "node 0 still sends on the cable");
        assert_eq!(peer.transport_id(), Some(cable), "nothing switched");
    }

    // One session, one index: no handshake was started anywhere.
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[1].node.peer_count(), 1);
    assert!(
        !nodes[1]
            .node
            .is_connecting_to_peer_on_path(&addr_0, wifi(), &wifi_0)
    );
}

#[tokio::test]
async fn a_beacon_from_a_live_peer_on_a_new_transport_probes_instead_of_dialling() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let pubkey_0 = nodes[0].node.identity().pubkey();

    // Node 1 hears node 0 beacon on the wifi.
    match nodes[1].node.transports.get(&wifi()).unwrap() {
        TransportHandle::Loopback(t) => t.inject_discovered(wifi_0.clone(), pubkey_0),
        _ => unreachable!(),
    }
    nodes[1].node.poll_transport_discovery().await;

    assert!(
        !nodes[1]
            .node
            .is_connecting_to_peer_on_path(&addr_0, wifi(), &wifi_0),
        "a live peer is probed, not dialled"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .map(|p| p.state()),
        Some(PathState::Probing)
    );

    // Discovery sends nothing; the heartbeat tick probes the new path.
    assert_eq!(nodes[0].packet_rx.len(), 0);
    nodes[1].node.run_path_heartbeats().await;

    // Probes out (cable heartbeat and wifi probe), acks back.
    for _ in 0..4 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .map(|p| p.state()),
        Some(PathState::Live)
    );
}

#[tokio::test]
async fn a_second_handshake_creates_no_path_state_and_the_address_is_probed_instead() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    let cable = nodes[0].transport_id;
    let session_before = (
        nodes[0].node.get_peer(&addr_1).unwrap().our_index(),
        nodes[1].node.get_peer(&addr_0).unwrap().our_index(),
    );

    // Node 1 dials node 0 over the wifi, as a static config listing both
    // addresses does at startup, while the cable session is live. The
    // responder answers it as it would any msg1 from a peer it holds a
    // session with — a duplicate here, the session being seconds old —
    // and neither end derives a path from the handshake.
    let identity_0 = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    nodes[1]
        .node
        .initiate_connection(wifi(), wifi_0.clone(), identity_0)
        .await
        .expect("dial starts");
    for _ in 0..8 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }

    // Neither end re-peered: one peer each, the session untouched.
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[1].node.peer_count(), 1);
    assert_eq!(
        (
            nodes[0].node.get_peer(&addr_1).unwrap().our_index(),
            nodes[1].node.get_peer(&addr_0).unwrap().our_index(),
        ),
        session_before,
        "the handshake did not replace the session"
    );
    // The dialler holds the address as an unproven candidate, traffic on
    // the cable; the responder learned nothing from the handshake.
    let p1 = nodes[1].node.get_peer(&addr_0).unwrap();
    assert_eq!(p1.transport_id(), Some(cable), "traffic stays on the cable");
    let wifi_path = p1
        .path_on(wifi())
        .expect("the dialled address is a candidate");
    assert_eq!(wifi_path.state(), PathState::Probing);
    assert!(!wifi_path.acked_once(), "a handshake proves no path");
    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .path_on(wifi())
            .is_none(),
        "the responder derives no path from a handshake"
    );

    // The connection the dial opened is left for the probe to ride: on a
    // connection-oriented transport it is the path's socket, and closing
    // it would have the first probe dial again (or, at the responder, find
    // an ephemeral port that cannot be dialled). Loopback records the
    // close it would have been asked for.
    for node in &nodes {
        let closed = match node.node.transports.get(&wifi()).expect("wifi transport") {
            TransportHandle::Loopback(t) => t.closed(),
            _ => unreachable!("tests run over loopback"),
        };
        assert!(
            closed.is_empty(),
            "the dial's connection is kept for the candidate: {closed:?}"
        );
    }

    // The heartbeat tick proves it, at both ends, under the shared session.
    nodes[1].node.run_path_heartbeats().await;
    for _ in 0..8 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    let p1 = nodes[1].node.get_peer(&addr_0).unwrap();
    assert_eq!(p1.path_on(wifi()).unwrap().state(), PathState::Live);
    assert_eq!(p1.transport_id(), Some(cable), "traffic still on the cable");
    let p0 = nodes[0].node.get_peer(&addr_1).unwrap();
    assert!(
        p0.path_on(wifi()).is_some(),
        "the probe taught the responder the path"
    );
    assert_eq!(p0.transport_id(), Some(cable));

    // An operator disconnect closes every path's connection, the standby's
    // included: on a connection-oriented transport each holds a pool entry.
    let npub_0 = nodes[0].node.identity().npub();
    nodes[1]
        .node
        .api_disconnect(&npub_0)
        .await
        .expect("disconnect");
    let closed_wifi = match nodes[1].node.transports.get(&wifi()).unwrap() {
        TransportHandle::Loopback(t) => t.closed(),
        _ => unreachable!(),
    };
    assert_eq!(
        closed_wifi,
        vec![wifi_0.clone()],
        "the standby's connection is closed too"
    );
    let closed_cable = match nodes[1].node.transports.get(&cable).unwrap() {
        TransportHandle::Loopback(t) => t.closed(),
        _ => unreachable!(),
    };
    assert_eq!(closed_cable.len(), 1, "and the active path's");
}

#[tokio::test]
async fn a_beaconed_path_is_probed_by_the_next_heartbeat_tick_and_once_only() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();

    // The beacon adds the path; nothing is sent until the tick.
    nodes[1]
        .node
        .add_path_candidate(addr_0, wifi(), wifi_0.clone());
    assert_eq!(
        nodes[0].packet_rx.len(),
        0,
        "discovery sends nothing itself"
    );

    // Two ticks back to back: one probe on the wifi, the second held
    // while the first is in flight.
    nodes[1].node.run_path_heartbeats().await;
    nodes[1].node.run_path_heartbeats().await;
    let mut on_wifi = 0;
    while let Ok(packet) = nodes[0].packet_rx.try_recv() {
        if packet.transport_id == wifi() {
            on_wifi += 1;
        }
    }
    assert_eq!(on_wifi, 1, "one probe in flight per path");

    // The path is still unproven.
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .map(|p| p.state()),
        Some(PathState::Probing)
    );
}

#[tokio::test]
async fn an_ack_for_no_outstanding_probe_changes_nothing() {
    let (mut nodes, _wifi_0, wifi_1) = dual_homed_pair().await;
    let addr_1 = *nodes[1].node.node_addr();

    let stale = PathMessage {
        probe_id: 99,
        remote_active: false,
        path_id: 1,
    };
    nodes[0]
        .node
        .handle_path_ack(&addr_1, &stale.encode_ack()[1..], (wifi(), &wifi_1));
    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .path_on(wifi())
            .is_none(),
        "an ack never creates a path; only a probe does"
    );
}

// ============================================================================
// Presence loss withdraws a path (design §5–6)
// ============================================================================

/// A dual-homed pair with the wifi path `Live` at both ends: each side has
/// probed the other and heard the ack.
async fn pair_with_wifi_live() -> (Vec<TestNode>, TransportAddr, TransportAddr) {
    let (mut nodes, wifi_0, wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    probe_candidate(&mut nodes, 1, addr_0, wifi(), wifi_0.clone()).await;
    probe_candidate(&mut nodes, 0, addr_1, wifi(), wifi_1.clone()).await;
    for _ in 0..4 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    for (node, peer) in [(&nodes[0], addr_1), (&nodes[1], addr_0)] {
        let path = node.node.get_peer(&peer).unwrap().path_on(wifi()).unwrap();
        assert_eq!(path.state(), PathState::Live, "precondition");
        assert!(path.tx_live_at_ms().is_some(), "precondition");
    }
    (nodes, wifi_0, wifi_1)
}

#[tokio::test]
async fn losing_the_active_transport_moves_traffic_to_the_live_standby() {
    let (mut nodes, wifi_0, _wifi_1) = pair_with_wifi_live().await;
    let addr_0 = *nodes[0].node.node_addr();
    let cable = nodes[1].transport_id;

    let reaped = nodes[1].node.withdraw_transport(cable).await;
    assert_eq!(reaped, 0, "a peer with a live standby is not reaped");

    let peer = nodes[1].node.get_peer(&addr_0).expect("peer survives");
    assert_eq!(peer.transport_id(), Some(wifi()), "traffic moved");
    assert_eq!(peer.current_addr(), Some(&wifi_0));
    assert_eq!(peer.path_on(cable).unwrap().state(), PathState::Dead);
    assert_eq!(peer.paths().len(), 2, "the dead path keeps its history");

    // The link record follows the traffic.
    let link = nodes[1].node.get_link(&peer.link_id()).expect("link kept");
    assert_eq!(link.transport_id(), wifi());
    assert_eq!(link.remote_addr(), &wifi_0);
    assert!(
        nodes[1]
            .node
            .addr_to_link
            .contains_key(&(wifi(), wifi_0.clone()))
    );

    // The path MTU seed now describes the wifi.
    let seeded_by = nodes[1]
        .node
        .path_mtu_seeded_by
        .read()
        .unwrap()
        .get(&crate::FipsAddress::from_node_addr(&addr_0))
        .copied();
    assert_eq!(seeded_by, Some(wifi()));

    // The same session carries on: a frame sent now goes out on the wifi
    // and decrypts at the far end. (The withdrawal also told the far end,
    // with a PathClose on the wifi, that the cable is gone: it moves its
    // own traffic to the wifi on hearing it, and re-peers nowhere.)
    let before = nodes[0].packet_rx.len();
    nodes[1]
        .node
        .send_encrypted_link_message(&addr_0, &[0x51])
        .await
        .expect("send over the standby");
    assert_eq!(nodes[0].packet_rx.len(), before + 1);
    while let Ok(packet) = nodes[0].packet_rx.try_recv() {
        assert_eq!(packet.transport_id, wifi());
        nodes[0].node.handle_encrypted_frame(packet).await;
    }
    let far = nodes[0]
        .node
        .get_peer(nodes[1].node.node_addr())
        .expect("no re-peering");
    assert_eq!(far.consecutive_decrypt_failures(), 0);
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(
        far.transport_id(),
        Some(wifi()),
        "told the cable is gone, the far end moved too"
    );
}

#[tokio::test]
async fn losing_the_active_transport_with_only_a_probing_standby_reaps() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let cable = nodes[1].transport_id;

    // Probe sent, ack never processed: the wifi path is unproven.
    probe_candidate(&mut nodes, 1, addr_0, wifi(), wifi_0.clone()).await;
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .unwrap()
            .state(),
        PathState::Probing
    );

    let reaped = nodes[1].node.withdraw_transport(cable).await;
    assert_eq!(reaped, 1, "an unproven path is not a path to switch to");
    assert!(nodes[1].node.get_peer(&addr_0).is_none());
}

#[tokio::test]
async fn losing_a_standby_leaves_traffic_where_it_is() {
    let (mut nodes, _wifi_0, _wifi_1) = pair_with_wifi_live().await;
    let addr_0 = *nodes[0].node.node_addr();
    let cable = nodes[1].transport_id;

    let reaped = nodes[1].node.withdraw_transport(wifi()).await;
    assert_eq!(reaped, 0);
    let peer = nodes[1].node.get_peer(&addr_0).unwrap();
    assert_eq!(peer.transport_id(), Some(cable));
    let dead = peer.path_on(wifi()).unwrap();
    assert_eq!(dead.state(), PathState::Dead);
    assert!(dead.last_rtt_ms().is_some(), "history kept");
    assert!(!dead.is_eligible());
}

#[tokio::test]
async fn a_dead_path_is_reprobed_when_its_transport_returns_and_forgotten_after_the_grace() {
    let (mut nodes, wifi_0, _wifi_1) = pair_with_wifi_live().await;
    let addr_0 = *nodes[0].node.node_addr();

    let samples_before = nodes[1]
        .node
        .get_peer(&addr_0)
        .unwrap()
        .path_on(wifi())
        .unwrap()
        .rtt_samples();
    assert!(samples_before > 0);
    nodes[1].node.withdraw_transport(wifi()).await;
    // (The withdrawal also sent node 0 a PathClose on the cable.)
    for _ in 0..4 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    let dead = nodes[1]
        .node
        .get_peer(&addr_0)
        .unwrap()
        .path_on(wifi())
        .unwrap();
    assert_eq!(dead.state(), PathState::Dead);
    assert_eq!(dead.addr(), &wifi_0);
    // Dead: the heartbeat tick leaves it alone.
    nodes[1].node.run_path_heartbeats().await;
    assert!(
        nodes[0].packet_rx.try_recv().is_err(),
        "a Dead path is not probed"
    );

    // Presence returns: the path is Probing again, the next heartbeat tick
    // probes it, and the ack brings it back Live with its history.
    nodes[1].node.reset_probe_backoff_on_transport(wifi());
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .unwrap()
            .state(),
        PathState::Probing
    );
    nodes[1].node.run_path_heartbeats().await;
    for _ in 0..4 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    let revived = nodes[1]
        .node
        .get_peer(&addr_0)
        .unwrap()
        .path_on(wifi())
        .unwrap();
    assert_eq!(revived.state(), PathState::Live);
    assert!(
        revived.rtt_samples() > samples_before,
        "re-proved on top of its history, not from nothing"
    );

    // Dead again, and this time the grace expires.
    nodes[1].node.withdraw_transport(wifi()).await;
    let now = crate::time::mono_ms();
    let peer = nodes[1].node.get_peer_mut(&addr_0).unwrap();
    peer.prune_dead_paths(now, 60_000);
    assert!(
        peer.path_on(wifi()).is_some(),
        "inside the grace, history kept"
    );
    peer.prune_dead_paths(now + 60_001, 60_000);
    assert!(
        peer.path_on(wifi()).is_none(),
        "past the grace, a fresh path"
    );
    assert_eq!(peer.paths().len(), 1);
    assert_eq!(peer.transport_id(), Some(nodes[1].transport_id));
}

#[tokio::test]
async fn a_rekey_msg1_on_a_standby_path_is_recognised_as_the_established_peer() {
    let (nodes, wifi_0, _wifi_1) = pair_with_wifi_live().await;
    assert!(
        nodes[1].node.is_established_link_msg1(wifi(), &wifi_0),
        "the peer sends its rekey on the path *it* uses, which may be our standby"
    );
    assert!(
        !nodes[1]
            .node
            .is_established_link_msg1(wifi(), &TransportAddr::from_string("loopback:none"))
    );
}

#[tokio::test]
async fn garbage_on_a_standby_path_counts_against_the_peer() {
    let (mut nodes, _wifi_0, wifi_1) = pair_with_wifi_live().await;
    let addr_1 = *nodes[1].node.node_addr();
    let our_index = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .our_index()
        .unwrap();
    for counter in 0..3u64 {
        nodes[0]
            .node
            .handle_encrypted_frame(ReceivedPacket::new(
                wifi(),
                wifi_1.clone(),
                garbage_frame(our_index, counter),
            ))
            .await;
    }
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .consecutive_decrypt_failures(),
        3,
        "a path in the set is a transport the peer is on"
    );
}

#[tokio::test]
async fn garbage_on_a_path_the_peer_never_acknowledged_is_not_counted() {
    // A candidate is an address we were told about — a beacon, a config
    // entry, a handshake source, possibly a replayed one. Until the peer
    // answers a probe there, garbage on its transport says nothing about
    // the peer, and cannot tear the peering down.
    let (mut nodes, _wifi_0, wifi_1) = dual_homed_pair().await;
    let addr_1 = *nodes[1].node.node_addr();
    nodes[0]
        .node
        .add_path_candidate(addr_1, wifi(), wifi_1.clone());
    assert!(
        !nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .path_on(wifi())
            .unwrap()
            .acked_once()
    );
    let our_index = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .our_index()
        .unwrap();
    for counter in 0..(THRESHOLD * 2) as u64 {
        nodes[0]
            .node
            .handle_encrypted_frame(ReceivedPacket::new(
                wifi(),
                wifi_1.clone(),
                garbage_frame(our_index, counter),
            ))
            .await;
    }
    let peer = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("an unproven path is not a transport the peer is on");
    assert_eq!(peer.consecutive_decrypt_failures(), 0);
}

// ============================================================================
// Selection (design §8)
// ============================================================================

use crate::config::TransportRole;
use crate::peer::{ActivePeer, HeartbeatTiming, PathPolicy, SwitchReason};

const CABLE: u32 = 1;
const WIFI: u32 = 2;

fn tid(n: u32) -> TransportId {
    TransportId::new(n)
}

/// Feed the path on `t` one acknowledged probe with round trip `rtt_ms`,
/// as the heartbeat exchange would. Returns the clock after the ack.
fn sample(peer: &mut ActivePeer, t: u32, now_ms: u64, rtt_ms: u64) -> u64 {
    let (id, _, _) = peer
        .take_probe(tid(t), now_ms, 1, 1)
        .expect("a probe is due: the last one was acked");
    peer.note_path_ack(tid(t), id, false, 1, now_ms + rtt_ms, u64::MAX)
        .expect("the ack matches");
    now_ms + rtt_ms
}

/// A peer active on the cable with three samples at `cable_rtt`, and a
/// wifi standby with three samples at `wifi_rtt`.
fn dual_path_peer(cable_rtt: u64, wifi_rtt: u64) -> ActivePeer {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.7:1"));
    let mut now = 1_000;
    for _ in 0..3 {
        now = sample(&mut peer, CABLE, now, cable_rtt);
        now = sample(&mut peer, WIFI, now, wifi_rtt);
    }
    assert_eq!(peer.transport_id(), Some(tid(CABLE)));
    peer
}

fn policy() -> PathPolicy {
    PathPolicy {
        margin: 1.5,
        dwell_ms: 5_000,
        min_samples: 3,
        rtt_window_ms: u64::MAX,
    }
}

#[test]
fn a_cable_under_a_slightly_better_wifi_is_not_left() {
    // 1.00 vs 1.10 in the design's table: ratio under K, stay.
    let mut peer = dual_path_peer(10, 1);
    assert!(peer.select_path(100_000, &policy()).is_none());
    assert!(peer.select_path(200_000, &policy()).is_none());
    assert_eq!(peer.transport_id(), Some(tid(CABLE)));
}

#[test]
fn a_degraded_active_path_is_left_after_the_dwell() {
    // cable 200 ms → score 3.0; wifi 5 ms → 1.05. Ratio 2.9 > K.
    let mut peer = dual_path_peer(200, 5);
    assert!(
        peer.select_path(100_000, &policy()).is_none(),
        "dwell starts"
    );
    assert!(
        peer.select_path(104_999, &policy()).is_none(),
        "dwell running"
    );
    let switch = peer
        .select_path(105_000, &policy())
        .expect("margin held for the dwell");
    assert_eq!(switch.reason, SwitchReason::Discretionary);
    assert_eq!(switch.to.0, tid(WIFI));
    assert_eq!(peer.transport_id(), Some(tid(WIFI)));
}

#[test]
fn the_dwell_restarts_when_the_margin_stops_holding() {
    let mut peer = dual_path_peer(200, 5);
    assert!(peer.select_path(100_000, &policy()).is_none());
    // The cable recovers for a moment: enough fast samples to pull the
    // window min down.
    let mut now = 101_000;
    for _ in 0..3 {
        now = sample(&mut peer, CABLE, now, 1);
    }
    assert!(peer.select_path(now, &policy()).is_none());
    // Min RTT is min over the window, so the recovery sticks: the path
    // never trips the margin again in this test.
    assert!(peer.select_path(now + 10_000, &policy()).is_none());
    assert_eq!(peer.transport_id(), Some(tid(CABLE)));
}

#[test]
fn a_standby_with_too_few_samples_is_not_selectable() {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.7:1"));
    let mut now = 1_000;
    for _ in 0..3 {
        now = sample(&mut peer, CABLE, now, 200);
    }
    now = sample(&mut peer, WIFI, now, 5);
    now = sample(&mut peer, WIFI, now, 5);
    assert!(peer.select_path(now, &policy()).is_none());
    assert!(peer.select_path(now + 60_000, &policy()).is_none());
}

#[test]
fn a_backup_path_is_not_selected_while_a_normal_one_is_selectable() {
    let mut peer = dual_path_peer(200, 5);
    peer.set_path_role(tid(WIFI), TransportRole::Backup);
    assert!(peer.select_path(100_000, &policy()).is_none());
    assert!(peer.select_path(200_000, &policy()).is_none());
    assert_eq!(peer.transport_id(), Some(tid(CABLE)));
}

#[test]
fn a_backup_active_path_yields_to_a_normal_one_at_once() {
    // Traffic landed on the backup (say, the cable was gone); the cable is
    // back and selectable, and it is slower. Role wins: leave the backup.
    let mut peer = dual_path_peer(20, 1);
    peer.set_path_role(tid(WIFI), TransportRole::Backup);
    peer.pin_path(tid(WIFI));
    let pinned = peer.select_path(100_000, &policy()).expect("pin honoured");
    assert_eq!(pinned.reason, SwitchReason::Pinned);
    peer.unpin_paths();
    let back = peer
        .select_path(100_001, &policy())
        .expect("a backup yields without margin or dwell");
    assert_eq!(back.reason, SwitchReason::Discretionary);
    assert_eq!(peer.transport_id(), Some(tid(CABLE)));
}

#[test]
fn a_pinned_path_wins_and_holds() {
    let mut peer = dual_path_peer(1, 200);
    assert!(peer.pin_path(tid(WIFI)));
    let switch = peer.select_path(100_000, &policy()).expect("pinned");
    assert_eq!(switch.reason, SwitchReason::Pinned);
    assert_eq!(peer.transport_id(), Some(tid(WIFI)));
    // The cable is far better now, and it does not matter.
    assert!(peer.select_path(200_000, &policy()).is_none());
    assert!(!peer.pin_path(tid(9)), "no path there");
}

#[test]
fn a_tie_keeps_the_current_path() {
    let mut peer = dual_path_peer(5, 5);
    assert!(peer.select_path(100_000, &policy()).is_none());
    assert!(peer.select_path(200_000, &policy()).is_none());
    assert_eq!(peer.transport_id(), Some(tid(CABLE)));
}

#[test]
fn withdrawal_prefers_a_selectable_standby_over_a_barely_live_one() {
    let mut peer = dual_path_peer(1, 5);
    let ble = 3;
    peer.add_path(tid(ble), TransportAddr::from_string("ble:1"));
    let now = sample(&mut peer, ble, 500_000, 1); // Live, one sample only
    let outcome = peer.withdraw_path(tid(CABLE), now, &policy());
    match outcome {
        crate::peer::PathWithdrawal::Switched { to, .. } => {
            assert_eq!(to.0, tid(WIFI), "three samples beat one, whatever the RTT");
        }
        other => panic!("expected a switch, got {other:?}"),
    }
}

#[test]
fn transport_role_and_path_config_parse() {
    let cfg: crate::config::UdpConfig = serde_yaml::from_str("role: backup\n").unwrap();
    assert_eq!(cfg.role(), TransportRole::Backup);
    let cfg: crate::config::UdpConfig = serde_yaml::from_str("bind_addr: 0.0.0.0:1\n").unwrap();
    assert_eq!(cfg.role(), TransportRole::Normal);
    let node: crate::config::PathConfig =
        serde_yaml::from_str("switch_margin: 2.0\nmin_samples: 5\n").unwrap();
    assert_eq!(node.switch_margin, 2.0);
    assert_eq!(node.min_samples, 5);
    assert_eq!(node.switch_dwell_secs, 2);
    assert_eq!(node.active_heartbeat_ms, 200);
}

// ============================================================================
// Detection (design §7)
// ============================================================================

const FAST: u64 = 250;
const SLOW: u64 = 10_000;
const TIMEOUT: u64 = 750;
const TIMING: HeartbeatTiming = HeartbeatTiming {
    fast_ms: FAST,
    slow_ms: SLOW,
    timeout_ms: TIMEOUT,
    discovery_cap_ms: SLOW,
};

#[test]
fn heartbeats_are_fast_on_the_active_path_and_slow_on_a_standby() {
    let mut peer = dual_path_peer(1, 5);
    let t0 = 1_000_000;
    let plan = peer.plan_heartbeats(t0, &TIMING);
    let on: Vec<_> = plan.sends.iter().map(|s| s.transport_id).collect();
    assert!(
        on.contains(&tid(CABLE)) && on.contains(&tid(WIFI)),
        "both due at once: {on:?}"
    );
    assert!(plan.suspects.is_empty());
    let cable = plan
        .sends
        .iter()
        .find(|s| s.transport_id == tid(CABLE))
        .unwrap();
    assert!(cable.remote_active, "the active path says so");

    // Nothing more while both are in flight.
    assert!(peer.plan_heartbeats(t0 + 100, &TIMING).sends.is_empty());

    // Acks land. Then only the active path is due again inside a second.
    for t in [CABLE, WIFI] {
        let id = plan
            .sends
            .iter()
            .find(|s| s.transport_id == tid(t))
            .unwrap()
            .probe_id;
        peer.note_path_ack(tid(t), id, false, 1, t0 + 200, u64::MAX)
            .unwrap();
    }
    let plan = peer.plan_heartbeats(t0 + FAST + 1, &TIMING);
    let on: Vec<_> = plan.sends.iter().map(|s| s.transport_id).collect();
    assert_eq!(on, vec![tid(CABLE)]);
    let plan = peer.plan_heartbeats(t0 + SLOW + 1, &TIMING);
    assert!(plan.sends.iter().any(|s| s.transport_id == tid(WIFI)));
}

#[test]
fn a_timed_out_echo_on_an_acknowledged_path_makes_it_suspect_and_selection_leaves_it() {
    let mut peer = dual_path_peer(1, 5);
    let t0 = 1_000_000;
    let plan = peer.plan_heartbeats(t0, &TIMING);
    assert!(plan.sends.iter().any(|s| s.transport_id == tid(CABLE)));
    // The wifi ack lands; the cable's never does.
    let wifi_id = plan
        .sends
        .iter()
        .find(|s| s.transport_id == tid(WIFI))
        .unwrap()
        .probe_id;
    peer.note_path_ack(tid(WIFI), wifi_id, false, 1, t0 + 5, u64::MAX);

    let before = peer.path_on(tid(CABLE)).unwrap().etx();
    let plan = peer.plan_heartbeats(t0 + TIMEOUT, &TIMING);
    assert_eq!(plan.suspects, vec![tid(CABLE)]);
    let cable = peer.path_on(tid(CABLE)).unwrap();
    assert_eq!(cable.state(), PathState::Suspect);
    assert!(cable.etx() > before, "a lost echo is a lost sample");
    assert!(
        plan.sends.iter().any(|s| s.transport_id == tid(CABLE)),
        "and it is probed again at once"
    );

    let switch = peer
        .select_path(t0 + TIMEOUT, &policy())
        .expect("mandatory: the active path is not tx_live");
    assert_eq!(switch.reason, SwitchReason::Mandatory);
    assert_eq!(peer.transport_id(), Some(tid(WIFI)));

    // The cable answers after all: Live again, and now the standby.
    let cable_id = plan
        .sends
        .iter()
        .find(|s| s.transport_id == tid(CABLE))
        .unwrap()
        .probe_id;
    peer.note_path_ack(tid(CABLE), cable_id, false, 1, t0 + TIMEOUT + 1, u64::MAX)
        .unwrap();
    assert_eq!(peer.path_on(tid(CABLE)).unwrap().state(), PathState::Live);
    assert_eq!(
        peer.transport_id(),
        Some(tid(WIFI)),
        "no ping-pong: K decides fail-back"
    );
}

#[test]
fn a_peer_with_one_live_path_is_not_heartbeated() {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    // Promotion-style: one Live path from the handshake. Nothing to decide,
    // nothing sent — the link heartbeat keeps liveness.
    let t0 = 1_000_000;
    for k in 0..20 {
        assert!(
            peer.plan_heartbeats(t0 + k * FAST, &TIMING)
                .sends
                .is_empty(),
            "a single-path peer gets no path probes"
        );
    }
    // A candidate makes it two: probes start, on the candidate and on the
    // active path alike.
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.7:1"));
    let plan = peer.plan_heartbeats(t0 + 21 * FAST, &TIMING);
    assert_eq!(plan.sends.len(), 2);
    assert!(
        plan.sends
            .iter()
            .any(|s| s.transport_id == tid(WIFI) && s.full_size),
        "the candidate's first probe is the full-size discovery probe"
    );
    assert!(
        plan.sends
            .iter()
            .any(|s| s.transport_id == tid(CABLE) && !s.full_size),
        "the handshake proved the active path: its first probe is small"
    );
}

#[test]
fn an_active_path_the_peer_never_acknowledged_backs_off_instead_of_going_suspect() {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    // A candidate on the wifi makes the peer two-path, so the cable — Live
    // from the handshake, never acked: an old node — is probed too.
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.7:1"));
    let t0 = 1_000_000;
    let plan = peer.plan_heartbeats(t0, &TIMING);
    assert!(plan.sends.iter().any(|s| s.transport_id == tid(CABLE)));
    let plan = peer.plan_heartbeats(t0 + TIMEOUT, &TIMING);
    assert!(plan.suspects.is_empty(), "an old node is not a dead path");
    let cable = peer.path_on(tid(CABLE)).unwrap();
    assert_eq!(cable.state(), PathState::Live);
    assert!(
        plan.sends.iter().any(|s| s.transport_id == tid(CABLE)),
        "tried again, with the backoff doubled"
    );
    assert!(
        !peer
            .plan_heartbeats(t0 + TIMEOUT + 2 * FAST - 1, &TIMING)
            .sends
            .iter()
            .any(|s| s.transport_id == tid(CABLE)),
        "the unanswered probe pushed the next one out"
    );
    // However long it goes unanswered, the active path is never given up:
    // the handshake proved it, and an old node answers no probe.
    let mut t = t0 + TIMEOUT + 2 * FAST;
    for _ in 0..200 {
        peer.plan_heartbeats(t, &TIMING);
        t += TIMEOUT;
    }
    assert_eq!(peer.path_on(tid(CABLE)).unwrap().state(), PathState::Live);
    assert_eq!(peer.transport_id(), Some(tid(CABLE)));
}

#[test]
fn a_standby_the_peer_never_acknowledges_is_given_up_after_the_discovery_budget() {
    let mut peer = dual_path_peer(1, 5);
    // A third address the peer never answers on: a NIC it no longer sends
    // from, a replayed source, an old node's transport.
    peer.add_path(tid(3), TransportAddr::from_string("10.0.0.9:1"));
    let mut t = 1_000_000;
    let mut probes = 0;
    for _ in 0..400 {
        let plan = peer.plan_heartbeats(t, &TIMING);
        assert!(
            plan.suspects.is_empty(),
            "never acknowledged: never Suspect"
        );
        probes += plan
            .sends
            .iter()
            .filter(|s| s.transport_id == tid(3))
            .count();
        for s in plan.sends {
            if s.transport_id != tid(3) {
                peer.note_path_ack(s.transport_id, s.probe_id, false, 1, t + 1, u64::MAX);
            }
        }
        if peer.path_on(tid(3)).unwrap().state() == PathState::Dead {
            break;
        }
        t += TIMEOUT;
    }
    assert_eq!(
        peer.path_on(tid(3)).unwrap().state(),
        PathState::Dead,
        "given up after the budget"
    );
    assert_eq!(probes, crate::peer::MAX_DISCOVERY_PROBES as usize);
    // Dead: not probed again, and forgotten after the grace.
    assert!(
        !peer
            .plan_heartbeats(t + TIMEOUT, &TIMING)
            .sends
            .iter()
            .any(|s| s.transport_id == tid(3))
    );
    peer.prune_dead_paths(t + 10 * 60_000, 5 * 60_000);
    assert!(peer.path_on(tid(3)).is_none());
    // The proven paths are untouched.
    assert_eq!(peer.path_on(tid(CABLE)).unwrap().state(), PathState::Live);
    assert_eq!(peer.path_on(tid(WIFI)).unwrap().state(), PathState::Live);
}

#[test]
fn withdrawing_our_only_path_leaves_it_suspect_and_still_probed() {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    let t0 = 1_000_000;
    // An advisory close from the peer names our only path.
    assert_eq!(
        peer.withdraw_path(tid(CABLE), t0, &policy()),
        crate::peer::PathWithdrawal::NoAlternative
    );
    let cable = peer.path_on(tid(CABLE)).unwrap();
    assert_eq!(
        cable.state(),
        PathState::Suspect,
        "not Dead: a Dead path is never probed"
    );
    assert_eq!(
        peer.transport_id(),
        Some(tid(CABLE)),
        "traffic stays: nowhere else to go"
    );
    // The heartbeat tick keeps probing it, and an ack brings it back.
    let plan = peer.plan_heartbeats(t0 + 1, &TIMING);
    let id = plan
        .sends
        .iter()
        .find(|s| s.transport_id == tid(CABLE))
        .expect("still probed")
        .probe_id;
    peer.note_path_ack(tid(CABLE), id, true, 1, t0 + 3, u64::MAX)
        .unwrap();
    assert_eq!(peer.path_on(tid(CABLE)).unwrap().state(), PathState::Live);
}

#[test]
fn presence_return_resets_the_discovery_backoff() {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    // Two-path, so the never-acked cable is probed at all.
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.7:1"));
    let t0 = 1_000_000;
    let on_cable = |plan: &crate::peer::HeartbeatPlan| {
        plan.sends
            .iter()
            .filter(|s| s.transport_id == tid(CABLE))
            .count()
    };
    // Never answered: each timeout doubles the wait.
    assert_eq!(on_cable(&peer.plan_heartbeats(t0, &TIMING)), 1);
    assert_eq!(on_cable(&peer.plan_heartbeats(t0 + TIMEOUT, &TIMING)), 1);
    assert_eq!(
        on_cable(&peer.plan_heartbeats(t0 + 2 * TIMEOUT, &TIMING)),
        1
    );
    let t = t0 + 3 * TIMEOUT;
    assert_eq!(
        on_cable(&peer.plan_heartbeats(t, &TIMING)),
        0,
        "the third timeout pushed the next probe past now"
    );
    // The transport's presence cycles: probed at once.
    peer.reset_probe_backoff_on(tid(CABLE));
    assert_eq!(on_cable(&peer.plan_heartbeats(t, &TIMING)), 1);
}

#[test]
fn the_discovery_backoff_is_capped_and_never_goes_suspect() {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.7:1"));
    // A standby is probed at `slow_ms`; the backoff doubles from there
    // and the cap is what bounds it.
    let timing = HeartbeatTiming {
        slow_ms: 1_000,
        discovery_cap_ms: 2_000,
        ..TIMING
    };
    // Drive the wifi standby through its unanswered probes.
    let mut t = 1_000_000;
    let mut sent_at = Vec::new();
    for _ in 0..40 {
        let plan = peer.plan_heartbeats(t, &timing);
        assert!(
            plan.suspects.is_empty(),
            "never acknowledged: not a dead path"
        );
        assert!(
            plan.sends
                .iter()
                .filter(|s| s.transport_id == tid(WIFI))
                .all(|s| s.full_size),
            "every probe on an unproven path is full-size"
        );
        if plan.sends.iter().any(|s| s.transport_id == tid(WIFI)) {
            sent_at.push(t);
        }
        if peer.path_on(tid(WIFI)).unwrap().state() == PathState::Dead {
            break;
        }
        t += TIMEOUT;
    }
    let gaps: Vec<u64> = sent_at.windows(2).map(|w| w[1] - w[0]).collect();
    assert!(gaps.len() >= 4, "kept probing: {sent_at:?}");
    assert!(
        gaps.iter().all(|g| *g <= 2_000 + TIMEOUT),
        "the backoff is capped at discovery_cap_ms: {gaps:?}"
    );
    assert_eq!(
        sent_at.len(),
        crate::peer::MAX_DISCOVERY_PROBES as usize,
        "and the budget bounds it: the path is given up, not probed forever"
    );
    assert_eq!(peer.path_on(tid(WIFI)).unwrap().state(), PathState::Dead);
}

#[test]
fn a_late_ack_after_the_echo_timeout_still_measures_the_path() {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.7:1"));
    let t0 = 1_000_000;
    let plan = peer.plan_heartbeats(t0, &TIMING);
    let id = plan
        .sends
        .iter()
        .find(|s| s.transport_id == tid(WIFI))
        .expect("the new path is probed")
        .probe_id;

    // A circuit slower than the timeout floor: the echo times out first.
    let plan = peer.plan_heartbeats(t0 + TIMEOUT, &TIMING);
    assert!(plan.suspects.is_empty());
    assert_eq!(peer.path_on(tid(WIFI)).unwrap().state(), PathState::Probing);

    // Then the ack arrives. It is still the answer to our probe.
    let rtt = peer
        .note_path_ack(tid(WIFI), id, false, 1, t0 + TIMEOUT + 250, u64::MAX)
        .expect("a late ack is still an ack");
    assert_eq!(rtt, TIMEOUT + 250);
    let wifi = peer.path_on(tid(WIFI)).unwrap();
    assert_eq!(wifi.state(), PathState::Live);
    assert!(wifi.acked_once());
    assert_eq!(wifi.last_rtt_ms(), Some(TIMEOUT + 250));

    // A second late ack for the same probe is a duplicate.
    assert!(
        peer.note_path_ack(tid(WIFI), id, false, 1, t0 + TIMEOUT + 300, u64::MAX)
            .is_none()
    );

    // With a round trip on record the timeout stretches: the next probe
    // is not timed out at the floor.
    let plan = peer.plan_heartbeats(t0 + 2 * TIMEOUT, &TIMING);
    let id = plan
        .sends
        .iter()
        .find(|s| s.transport_id == tid(WIFI))
        .map(|s| s.probe_id);
    let t1 = t0 + 2 * TIMEOUT;
    let plan = peer.plan_heartbeats(t1 + TIMEOUT, &TIMING);
    assert!(plan.suspects.is_empty(), "3 × last RTT > the floor");
    if let Some(id) = id {
        assert!(
            peer.note_path_ack(tid(WIFI), id, false, 1, t1 + TIMEOUT + 1, u64::MAX)
                .is_some(),
            "still outstanding, not timed out"
        );
    }
}

#[test]
fn a_remote_active_flip_away_from_a_path_triggers_a_probe_not_a_suspect() {
    let mut peer = dual_path_peer(1, 5);
    let t0 = 1_000_000;
    // The peer said it sends on the wifi, then said it does not.
    peer.note_path_probe(
        tid(WIFI),
        TransportAddr::from_string("10.0.0.7:1"),
        true,
        1,
        t0,
    );
    let plan = peer.plan_heartbeats(t0, &TIMING);
    for s in plan.sends {
        peer.note_path_ack(
            s.transport_id,
            s.probe_id,
            s.transport_id == tid(WIFI),
            1,
            t0 + 1,
            u64::MAX,
        );
    }
    // Wifi is now on the fast cadence (the peer sends there); it was just
    // acked, so nothing is due for a while.
    assert!(peer.plan_heartbeats(t0 + 10, &TIMING).sends.is_empty());
    peer.note_path_probe(
        tid(WIFI),
        TransportAddr::from_string("10.0.0.7:1"),
        false,
        1,
        t0 + 20,
    );
    let plan = peer.plan_heartbeats(t0 + 21, &TIMING);
    assert!(
        plan.sends.iter().any(|s| s.transport_id == tid(WIFI)),
        "probe now"
    );
    assert!(plan.suspects.is_empty());
    assert_eq!(peer.path_on(tid(WIFI)).unwrap().state(), PathState::Live);
}

#[test]
fn silence_on_the_active_path_while_a_standby_hears_the_peer_triggers_a_probe() {
    let mut peer = dual_path_peer(1, 5);
    let t0 = 1_000_000;
    let plan = peer.plan_heartbeats(t0, &TIMING);
    for s in plan.sends {
        peer.note_path_ack(s.transport_id, s.probe_id, false, 1, t0 + 1, u64::MAX);
    }
    // Two of the peer's (slow) intervals of silence on the cable, while
    // the wifi keeps hearing it.
    let later = t0 + 2 * SLOW + 1;
    peer.note_path_rx(tid(WIFI), later);
    let plan = peer.plan_heartbeats(later, &TIMING);
    assert!(plan.sends.iter().any(|s| s.transport_id == tid(CABLE)));
    assert_eq!(
        peer.path_on(tid(CABLE)).unwrap().state(),
        PathState::Live,
        "a hint, not a verdict"
    );
}

#[test]
fn a_hard_signal_marks_a_live_path_suspect_only() {
    let mut peer = dual_path_peer(1, 5);
    assert!(peer.mark_path_suspect(tid(WIFI)));
    assert!(!peer.mark_path_suspect(tid(WIFI)), "already suspect");
    assert!(!peer.mark_path_suspect(tid(9)), "no such path");
    assert!(!peer.path_on(tid(WIFI)).unwrap().is_eligible());
}

#[test]
fn unreachable_send_errors_are_classified() {
    use crate::transport::TransportError;
    let e = TransportError::Io(std::io::Error::from(std::io::ErrorKind::NetworkUnreachable));
    assert!(e.is_unreachable());
    let e = TransportError::Io(std::io::Error::from(std::io::ErrorKind::HostUnreachable));
    assert!(e.is_unreachable());
    let e = TransportError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused));
    assert!(!e.is_unreachable());
    assert!(!TransportError::Timeout.is_unreachable());
}

#[tokio::test]
async fn the_fast_tick_heartbeats_the_active_path_and_the_ack_measures_it() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let cable = nodes[1].transport_id;
    assert!(
        !nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(cable)
            .unwrap()
            .acked_once(),
        "the handshake proved the cable; no probe has yet"
    );

    // A second path makes the peer worth heartbeating; the tick then
    // probes the active cable as well as the wifi candidate.
    nodes[1]
        .node
        .add_path_candidate(addr_0, wifi(), wifi_0.clone());
    nodes[1].node.run_path_heartbeats().await;
    let queued = nodes[0].packet_rx.len();
    assert!(queued >= 1, "a heartbeat probe went out on the cable");
    for _ in 0..4 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    let cable_path = nodes[1]
        .node
        .get_peer(&addr_0)
        .unwrap()
        .path_on(cable)
        .unwrap();
    assert!(cable_path.acked_once());
    assert!(cable_path.min_rtt_ms().is_some());
    assert_eq!(cable_path.state(), PathState::Live);
    // Node 0 learned that node 1 sends on the cable.
    let far = nodes[0].node.get_peer(nodes[1].node.node_addr()).unwrap();
    assert!(far.path_on(cable).unwrap().remote_active());
}

// ============================================================================
// Tree dampening, fipsctl path, UDP interface (design §10, step 7)
// ============================================================================

#[test]
fn a_switch_holds_the_reported_link_cost_for_the_dwell_and_the_reports_that_span_it() {
    let mut peer = dual_path_peer(200, 5);
    let now = crate::time::mono_ms();
    let before = peer.link_cost(now);
    assert!(!peer.link_cost_held(now));
    let p = PathPolicy {
        dwell_ms: 60_000,
        ..policy()
    };
    peer.pin_path(tid(WIFI));
    peer.select_path(now, &p).expect("pinned switch");
    assert!(peer.link_cost_held(now));
    assert_eq!(peer.link_cost(now), before, "held at the pre-switch cost");
    // The dwell alone does not release it: the receiver report that spans
    // the switch counts the frames in flight on the old path as lost and
    // spikes the per-report ETX for one interval, and the one after that
    // replaces it. Two reports, then the dwell, whichever is later.
    assert!(
        peer.link_cost_held(now + 60_001),
        "still held: no report has arrived since the switch"
    );
    peer.note_receiver_report();
    assert!(peer.link_cost_held(now + 60_001), "the spanning report");
    peer.note_receiver_report();
    assert!(!peer.link_cost_held(now + 60_001), "replaced: released");
    assert!(
        peer.link_cost_held(now + 1),
        "reports in, dwell not: still held"
    );

    let p0 = PathPolicy {
        dwell_ms: 0,
        ..policy()
    };
    let mut peer = dual_path_peer(200, 5);
    peer.pin_path(tid(WIFI));
    peer.select_path(now, &p0).expect("pinned switch");
    assert!(!peer.link_cost_held(now), "a zero dwell holds nothing");
}

#[tokio::test]
async fn fipsctl_path_show_pin_and_unpin_go_through_the_control_api() {
    let (nodes, _wifi_0, _wifi_1) = pair_with_wifi_live().await;
    let mut nodes = nodes;
    let npub_0 = nodes[0].node.identity().npub();

    let shown = nodes[1].node.api_path_show(&npub_0).expect("known peer");
    let paths = shown["paths"].as_array().unwrap();
    assert_eq!(paths.len(), 2);
    assert_eq!(
        paths.iter().filter(|p| p["active"] == true).count(),
        1,
        "exactly one active path"
    );
    assert!(paths.iter().all(|p| p["state"] == "live"));
    assert!(paths.iter().all(|p| p["pinned"] == false));

    let err = nodes[1].node.api_path_show("npub1notapeer").unwrap_err();
    assert!(err.contains("invalid npub"), "{err}");

    // Pin by numeric id (the loopback transports carry no name).
    let pinned = nodes[1]
        .node
        .api_path_pin(&npub_0, &wifi().as_u32().to_string())
        .expect("pin");
    assert_eq!(pinned["pinned"], wifi().as_u32());
    nodes[1].node.run_path_selection();
    let addr_0 = *nodes[0].node.node_addr();
    assert_eq!(
        nodes[1].node.get_peer(&addr_0).unwrap().transport_id(),
        Some(wifi()),
        "the pin took on the next selection run"
    );
    let shown = nodes[1].node.api_path_show(&npub_0).unwrap();
    assert!(
        shown["paths"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["pinned"] == true && p["active"] == true)
    );

    assert!(
        nodes[1]
            .node
            .api_path_pin(&npub_0, "no-such-transport")
            .is_err()
    );
    nodes[1].node.api_path_unpin(&npub_0).expect("unpin");
    let shown = nodes[1].node.api_path_show(&npub_0).unwrap();
    assert!(
        shown["paths"]
            .as_array()
            .unwrap()
            .iter()
            .all(|p| p["pinned"] == false)
    );
}

/// `show_peers` carries every path under its peer, from both the on-loop
/// query and the tick-published snapshot fipstop reads, so the Peers tab
/// can draw the transports a peer is reachable over without a per-peer
/// `path show` round trip.
#[tokio::test]
async fn show_peers_lists_every_path_on_and_off_loop() {
    let (mut nodes, _wifi_0, _wifi_1) = pair_with_wifi_live().await;
    let addr_0 = *nodes[0].node.node_addr();

    let check = |peers: &serde_json::Value| {
        let peer = peers["peers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["node_addr"] == hex::encode(addr_0.as_bytes()))
            .expect("peer 0 listed");
        let paths = peer["paths"].as_array().expect("paths array");
        assert_eq!(paths.len(), 2, "both transports listed");
        assert_eq!(
            paths.iter().filter(|p| p["active"] == true).count(),
            1,
            "exactly one active path"
        );
        assert!(paths.iter().all(|p| p["state"] == "live"));
        assert!(paths.iter().all(|p| p["transport_type"] == "loopback"));
        assert!(paths.iter().all(|p| p["addr"].is_string()));
        let ids: std::collections::HashSet<u64> = paths
            .iter()
            .map(|p| p["transport_id"].as_u64().unwrap())
            .collect();
        assert!(
            ids.contains(&u64::from(wifi().as_u32())),
            "wifi path listed"
        );
    };

    check(&crate::control::queries::show_peers(&nodes[1].node));

    nodes[1].node.record_stats_history();
    let handle = nodes[1].node.control_read_handle();
    let off_loop = crate::control::queries::show_peers_from_handle(&handle);
    check(&off_loop);
    assert_eq!(
        serde_json::to_string(&crate::control::queries::show_peers(&nodes[1].node)).unwrap(),
        serde_json::to_string(&off_loop).unwrap(),
        "off-loop show_peers matches on-loop, paths included"
    );
}

#[test]
fn udp_interface_config_parses() {
    let cfg: crate::config::UdpConfig = serde_yaml::from_str("interface: en0\n").unwrap();
    assert_eq!(cfg.interface.as_deref(), Some("en0"));
    let cfg: crate::config::UdpConfig = serde_yaml::from_str("bind_addr: 0.0.0.0:1\n").unwrap();
    assert!(cfg.interface.is_none());
}

#[test]
fn binding_udp_to_a_missing_interface_fails_to_start() {
    use crate::transport::udp::io::UdpRawSocket;
    let err = UdpRawSocket::open_on_interface(
        "127.0.0.1:0".parse().unwrap(),
        65_536,
        65_536,
        Some("fips-absent-x0"),
    )
    .err()
    .expect("an absent interface cannot be bound");
    assert!(err.to_string().contains("fips-absent-x0"), "{err}");
}

// ============================================================================
// Path close, full-size probes, revival
// ============================================================================

#[test]
fn path_close_round_trips_on_the_wire() {
    use crate::proto::link::{PathClose, PathCloseReason};
    let close = PathClose {
        path_id: 0x1234_5678,
        reason: PathCloseReason::CarrierLost,
    };
    let wire = close.encode();
    assert_eq!(wire[0], 0x54);
    assert_eq!(PathClose::decode(&wire[1..]).unwrap(), close);
    assert_eq!(
        PathClose::decode(&[1, 0, 0, 0, 200]).unwrap().reason,
        PathCloseReason::Unspecified,
        "an unknown reason byte is not an error"
    );
}

#[test]
fn a_probe_reaching_a_dead_path_revives_it() {
    let mut peer = dual_path_peer(1, 5);
    peer.withdraw_path(tid(WIFI), 1_000_000, &policy());
    assert_eq!(peer.path_on(tid(WIFI)).unwrap().state(), PathState::Dead);
    peer.note_path_probe(
        tid(WIFI),
        TransportAddr::from_string("10.0.0.7:1"),
        false,
        9,
        1_000_500,
    );
    let wifi = peer.path_on(tid(WIFI)).unwrap();
    assert_eq!(
        wifi.state(),
        PathState::Probing,
        "heard again, unproven our way"
    );
    assert_eq!(wifi.remote_id(), Some(9));
    assert!(wifi.last_rtt_ms().is_some(), "history kept");
}

#[tokio::test]
async fn the_first_probe_on_a_path_is_full_size_and_so_is_its_ack() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    probe_candidate(&mut nodes, 1, addr_0, wifi(), wifi_0.clone()).await;
    // The tick also heartbeated the active cable, small; the wifi probe
    // is the discovery one.
    let mut probe = None;
    while let Ok(packet) = nodes[0].packet_rx.try_recv() {
        if packet.transport_id == wifi() {
            probe = Some(packet);
        }
    }
    let probe = probe.expect("probe queued");
    let mtu = usize::from(
        nodes[1]
            .node
            .transports
            .get(&wifi())
            .unwrap()
            .link_mtu(&wifi_0),
    );
    assert_eq!(probe.data.len(), mtu, "the first probe fills the link MTU");
    nodes[0].node.handle_encrypted_frame(probe).await;
    let ack = nodes[1].packet_rx.try_recv().expect("ack queued");
    assert_eq!(ack.data.len(), mtu, "and the ack echoes its size");
    nodes[1].node.handle_encrypted_frame(ack).await;
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .unwrap()
            .path_on(wifi())
            .unwrap()
            .state(),
        PathState::Live
    );
}

#[test]
fn a_proven_path_is_probed_full_size_once_a_minute() {
    let mut peer = dual_path_peer(1, 5);
    let t0 = 1_000_000;
    let plan = peer.plan_heartbeats(t0, &TIMING);
    // dual_path_peer acked via take_probe, which sets no full-size stamp,
    // so the standby's first heartbeat is full-size — the active path's is
    // not, the handshake having proved it; after that, small until a
    // minute has passed, then full-size on both.
    assert!(
        plan.sends
            .iter()
            .all(|s| s.full_size == (s.transport_id == tid(WIFI)))
    );
    for s in plan.sends {
        peer.note_path_ack(s.transport_id, s.probe_id, false, 1, t0 + 1, u64::MAX);
    }
    let plan = peer.plan_heartbeats(t0 + FAST + 1, &TIMING);
    assert!(plan.sends.iter().all(|s| !s.full_size));
    for s in plan.sends {
        peer.note_path_ack(
            s.transport_id,
            s.probe_id,
            false,
            1,
            t0 + FAST + 2,
            u64::MAX,
        );
    }
    let plan = peer.plan_heartbeats(t0 + 61_000, &TIMING);
    assert_eq!(plan.sends.len(), 2);
    assert!(plan.sends.iter().all(|s| s.full_size));
}

#[tokio::test]
async fn losing_a_transport_tells_the_peer_which_closes_its_side() {
    let (mut nodes, _wifi_0, _wifi_1) = pair_with_wifi_live().await;
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .path_on(wifi())
            .unwrap()
            .remote_id()
            .is_some(),
        "the probe exchange taught each side the other's path id"
    );

    // Node 1 loses its wifi: it tells node 0 over the cable.
    nodes[1].node.withdraw_transport(wifi()).await;
    assert_eq!(nodes[0].packet_rx.len(), 1, "one PathClose on the cable");
    let packet = nodes[0].packet_rx.try_recv().unwrap();
    assert_eq!(packet.transport_id, nodes[0].transport_id);
    nodes[0].node.handle_encrypted_frame(packet).await;
    let wifi_path = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .path_on(wifi())
        .unwrap();
    assert_eq!(
        wifi_path.state(),
        PathState::Dead,
        "closed at once, no echo timeout"
    );
    assert!(wifi_path.last_rtt_ms().is_some(), "history kept");
    assert_eq!(
        nodes[0].node.get_peer(&addr_1).unwrap().transport_id(),
        Some(nodes[0].transport_id)
    );
    let _ = addr_0;
}

#[tokio::test]
async fn carrier_loss_on_the_active_path_moves_traffic_and_tells_the_peer() {
    let (mut nodes, _wifi_0, _wifi_1) = pair_with_wifi_live().await;
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    let cable = nodes[1].transport_id;
    let set_carrier = |node: &TestNode, carrier: bool| match node.node.transports.get(&cable) {
        Some(TransportHandle::Loopback(t)) => t.set_carrier(Some(carrier)),
        _ => unreachable!("the cable is a loopback transport"),
    };

    // One tick with carrier up, so the drop below is an edge.
    set_carrier(&nodes[1], true);
    nodes[1].node.run_path_heartbeats().await;
    for _ in 0..8 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert_eq!(
        nodes[1].node.get_peer(&addr_0).unwrap().transport_id(),
        Some(cable),
        "precondition: traffic on the cable"
    );

    // The cable loses carrier. Inside one tick: Suspect, selection moves
    // traffic to the wifi, and the peer is told on the wifi.
    set_carrier(&nodes[1], false);
    nodes[1].node.run_path_heartbeats().await;
    {
        let peer = nodes[1].node.get_peer(&addr_0).unwrap();
        assert_eq!(peer.path_on(cable).unwrap().state(), PathState::Suspect);
        assert_eq!(peer.transport_id(), Some(wifi()), "moved to the standby");
    }

    // Node 0 takes the tick's frames: the heartbeats it acks, and the
    // PathClose that withdraws its cable path and moves its traffic too.
    for _ in 0..8 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    let peer = nodes[0].node.get_peer(&addr_1).unwrap();
    assert_eq!(
        peer.path_on(cable).unwrap().state(),
        PathState::Dead,
        "closed by the peer's PathClose, not by an echo timeout"
    );
    assert_eq!(peer.transport_id(), Some(wifi()), "and traffic followed");
}

#[tokio::test]
async fn a_peer_closing_our_active_path_moves_our_traffic() {
    let (mut nodes, _wifi_0, _wifi_1) = pair_with_wifi_live().await;
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    let cable = nodes[0].transport_id;

    // One heartbeat exchange on the cable so each side knows the other's
    // id for it (promotion proves the path but names nothing).
    nodes[0].node.run_path_heartbeats().await;
    nodes[1].node.run_path_heartbeats().await;
    for _ in 0..4 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }

    // Node 0 sends on the cable. Node 1 loses the cable and says so on the wifi.
    nodes[1].node.withdraw_transport(cable).await;
    assert_eq!(
        nodes[1].node.get_peer(&addr_0).unwrap().transport_id(),
        Some(wifi())
    );
    let packet = nodes[0]
        .packet_rx
        .try_recv()
        .expect("PathClose on the wifi");
    assert_eq!(packet.transport_id, wifi());
    nodes[0].node.handle_encrypted_frame(packet).await;
    let peer = nodes[0].node.get_peer(&addr_1).unwrap();
    assert_eq!(
        peer.transport_id(),
        Some(wifi()),
        "moved without waiting for a timeout"
    );
    assert_eq!(peer.path_on(cable).unwrap().state(), PathState::Dead);
}

#[test]
fn an_outage_does_not_keep_charging_the_path_s_etx() {
    let mut peer = dual_path_peer(1, 5);
    let t0 = 1_000_000;
    let plan = peer.plan_heartbeats(t0, &TIMING);
    let wifi_id = plan
        .sends
        .iter()
        .find(|s| s.transport_id == tid(WIFI))
        .unwrap()
        .probe_id;
    peer.note_path_ack(tid(WIFI), wifi_id, false, 1, t0 + 5, u64::MAX);
    // The cable goes silent: first timeout is one loss and the Suspect mark.
    let plan = peer.plan_heartbeats(t0 + TIMEOUT, &TIMING);
    assert_eq!(plan.suspects, vec![tid(CABLE)]);
    let after_one = peer.path_on(tid(CABLE)).unwrap().etx();
    // Sixteen more seconds of timeouts while Suspect: no further charge.
    let mut now = t0 + TIMEOUT;
    for _ in 0..16 {
        now += 1_000;
        peer.plan_heartbeats(now, &TIMING);
    }
    assert_eq!(
        peer.path_on(tid(CABLE)).unwrap().etx(),
        after_one,
        "an outage is one event, not a lossy medium"
    );
}

// ---------------------------------------------------------------------------
// A handshake proves a path
// ---------------------------------------------------------------------------

#[test]
fn a_known_transport_at_a_new_address_is_re_pointed_there() {
    let mut peer = ActivePeer::new(make_peer_identity(), LinkId::new(1), 0);
    peer.rebind_transport(tid(CABLE), TransportAddr::from_string("10.0.0.1:1"));
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.7:1"));

    // `add_path` is "add or return": the address it carries is ignored for
    // a path that exists. A move is a separate, explicit step.
    peer.add_path(tid(WIFI), TransportAddr::from_string("10.0.0.8:1"));
    assert_eq!(
        peer.path_on(tid(WIFI)).unwrap().addr(),
        &TransportAddr::from_string("10.0.0.7:1")
    );
    assert!(peer.refresh_path_addr(tid(WIFI), TransportAddr::from_string("10.0.0.8:1")));
    assert_eq!(
        peer.path_on(tid(WIFI)).unwrap().addr(),
        &TransportAddr::from_string("10.0.0.8:1")
    );
    assert!(
        !peer.refresh_path_addr(tid(WIFI), TransportAddr::from_string("10.0.0.8:1")),
        "the same address is not a move"
    );
    assert!(
        !peer.refresh_path_addr(tid(3), TransportAddr::from_string("10.0.0.9:1")),
        "a transport with no path is not re-pointed: that is add_path's job"
    );
    assert!(peer.path_on(tid(3)).is_none());
}

#[tokio::test]
async fn a_dial_to_a_stale_peer_over_another_transport_is_probed_and_taken_when_it_answers() {
    let (mut nodes, wifi_0, _wifi_1) = dual_homed_pair().await;
    let addr_0 = *nodes[0].node.node_addr();
    let cable = nodes[0].transport_id;

    // Node 1 has not heard node 0 in a long time: the cable is not live.
    nodes[1].node.get_peer_mut(&addr_0).unwrap().touch(0);
    assert!(!nodes[1].node.active_peer_link_is_live(&addr_0));

    // An address on another transport arrives. Discovery never dials a
    // peer with a session; a caller that does gets the same outcome: the
    // handshake settles as a cross-connection, the address is a candidate.
    let identity_0 = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    nodes[1]
        .node
        .initiate_connection(wifi(), wifi_0.clone(), identity_0)
        .await
        .expect("dial starts");
    for _ in 0..8 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[1].node.peer_count(), 1);
    let p = nodes[1].node.get_peer(&addr_0).unwrap();
    assert_eq!(
        p.transport_id(),
        Some(cable),
        "nothing moved on the handshake"
    );
    assert_eq!(p.path_on(wifi()).unwrap().state(), PathState::Probing);

    // The heartbeat tick proves the wifi. The cable's own echoes then time
    // out (the peer is silent there, which is why we are here): a hard
    // signal, and the mandatory switch takes the path that answered.
    nodes[1].node.run_path_heartbeats().await;
    for _ in 0..8 {
        if process_available_packets(&mut nodes).await == 0 {
            break;
        }
    }
    assert!(
        nodes[1]
            .node
            .get_peer_mut(&addr_0)
            .unwrap()
            .mark_path_suspect(cable)
    );
    nodes[1].node.run_path_selection();
    let p = nodes[1].node.get_peer(&addr_0).unwrap();
    assert_eq!(p.path_on(wifi()).unwrap().state(), PathState::Live);
    assert_eq!(
        p.transport_id(),
        Some(wifi()),
        "traffic moved to the path that answered"
    );
    assert_eq!(p.current_addr(), Some(&wifi_0));
    // The link record followed the traffic.
    let link = nodes[1].node.links.get(&p.link_id()).expect("peer's link");
    assert_eq!(link.transport_id(), wifi());
    assert_eq!(link.remote_addr(), &wifi_0);
    assert!(
        p.path_on(cable).is_some(),
        "the cable stays for the heartbeat tick to probe"
    );
    // And the session is still shared.
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[1].node.peer_count(), 1);
}
