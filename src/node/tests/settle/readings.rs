//! What a move or a restart does with multipath on to state outside the
//! peer's record, on real nodes: two closes of a released path that reach the
//! wrong connection, each a known defect, with the control that with multipath
//! off a restart's teardown queues none; a no-carrier reading across a move and
//! a removal; and what a restart found at a rekey keeps of the bundle.
//!
//! The file's helpers, a second dial of a node's own and a restart's msg1,
//! also serve the replay tests of `decrypt_replay.rs`.

use super::super::paths::{
    beat, disabled, enabled, loopback, phase, same_transport_with, state_at, t2, transports_with,
    two_transports,
};
use super::super::rekey_parity::{cutover, deliver, linked_pair, rekey_config, trigger_age};
use super::super::spanning_tree::{TestNode, cleanup_nodes, initiate_handshake, restarted_node};
use super::super::*;
use super::{TcpConfig, TcpTransport, TransportHandle, TransportId, with_path};
use crate::peer::PathState;
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2};
use crate::transport::ConnectionState;
use fips_core::proto::path::{Input, PathRef};

/// `nodes[0]` dials the peer it holds at `nodes[1]`, and `nodes[1]`, which
/// has heard nothing for long enough, answers; `nodes[0]` moves its link onto
/// the dial's session. Packets of other phases queued at either end are
/// dropped. The caller checks that the move happened.
pub(in crate::node::tests) async fn own_dial(nodes: &mut [TestNode]) {
    crate::time::advance(Duration::from_secs(20));
    initiate_handshake(nodes, 0, 1).await;
    let a = *nodes[0].node.node_addr();
    let held = nodes[1]
        .node
        .get_peer_mut(&a)
        .expect("precondition: the answering node holds the dialler");
    held.test_backdate_heard(Duration::from_secs(60));
    held.test_backdate_session_established(Duration::from_secs(600));
    while let Ok(packet) = nodes[1].packet_rx.try_recv() {
        if phase(&packet) == Some(PHASE_MSG1) {
            nodes[1].node.handle_msg1(packet).await;
        }
    }
    while let Ok(packet) = nodes[0].packet_rx.try_recv() {
        if phase(&packet) == Some(PHASE_MSG2) {
            nodes[0].node.handle_msg2(packet).await;
        }
    }
}

/// `nodes[0]` last heard its peer `nodes[1]` long ago; `nodes[1]` restarts,
/// built from `config`, and dials from the pair `nodes[0]` holds it at, and
/// `nodes[0]` reads the msg1, tears down the old link and promotes a new one
/// at that pair.
pub(in crate::node::tests) async fn restart_dial(nodes: &mut [TestNode], config: Config) {
    let b = *nodes[1].node.node_addr();
    let pair = nodes[1].addr.clone();
    let held = nodes[0]
        .node
        .get_peer_mut(&b)
        .expect("precondition: node 0 holds its peer");
    held.touch(Node::now_ms().saturating_sub(60_000));
    held.test_backdate_heard(Duration::from_secs(60));
    let old_link = held.link_id();
    let restarted = restarted_node(&nodes[1], config);
    let mut old = std::mem::replace(&mut nodes[1], restarted);
    cleanup_nodes(std::slice::from_mut(&mut old)).await;
    initiate_handshake(nodes, 1, 0).await;
    let msg1 = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok())
        .find(|packet| phase(packet) == Some(PHASE_MSG1))
        .expect("precondition: the restarted node's msg1 is queued");
    assert_eq!(
        msg1.remote_addr, pair,
        "precondition: the msg1 came from the pair the old link holds"
    );
    nodes[0].node.handle_msg1(msg1).await;
    let peer = nodes[0]
        .node
        .get_peer(&b)
        .expect("precondition: the restart promoted the peer");
    assert_ne!(peer.link_id(), old_link, "precondition: a new link");
    assert_eq!(
        peer.current_addr(),
        Some(&pair),
        "precondition: the new link runs at the old link's pair"
    );
}

/// Outbound connections in the TCP pool of `tn`'s transport `id`. Reading
/// them finishes no connect, as asking for a connection's state does.
fn outbound(tn: &TestNode, id: TransportId) -> u64 {
    match tn.node.transports.get(&id) {
        Some(TransportHandle::Tcp(t)) => t.stats().snapshot().pool_outbound,
        _ => panic!("precondition: transport {id} is a TCP transport"),
    }
}

/// Ask for the state of the connection to `addr` until it has left
/// `Connecting`, which also moves a finished connect into the pool. The
/// limit counts polls, so a loaded host only makes the wait longer, and it
/// fails as a precondition: a connect that has not finished must not read as
/// a connection that was closed.
async fn connect_settled(tn: &TestNode, id: TransportId, addr: &TransportAddr) -> ConnectionState {
    let transport = tn
        .node
        .transports
        .get(&id)
        .expect("precondition: the transport is held");
    for _ in 0..3000 {
        let state = transport.connection_state(addr);
        if state != ConnectionState::Connecting {
            return state;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("precondition: the connect to {addr} finished within 3000 polls");
}

/// A capable link holds a path being opened on TCP when a second dial of the
/// node's own moves the peer. The renewed bundle does not hold the path, and
/// its close finds nothing in the pool, since the connect is still out. Once
/// the connect finishes and the tick settles it, nothing should be left open
/// that no path names. The connection stays, holding its slot in the pool.
#[tokio::test]
#[ignore = "known defect: a connect still out when a move releases its path stays open, with no path naming it"]
async fn a_connect_in_flight_across_a_move_leaves_no_connection_with_no_path() {
    let mut config = enabled();
    config.node.path.mix_kinds = true;
    let (mut nodes, b, _b2) = same_transport_with(config).await;
    let t3 = TransportId::new(3);
    let (tx, _rx) = packet_channel(64);
    let mut tcp = TcpTransport::new(
        t3,
        None,
        TcpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1400),
            ..Default::default()
        },
        tx,
    );
    tcp.start_async()
        .await
        .expect("precondition: the TCP transport starts");
    nodes[0]
        .node
        .transports
        .insert(t3, TransportHandle::Tcp(tcp));
    let sink = std::net::TcpListener::bind("127.0.0.1:0")
        .expect("precondition: the connect's target listens");
    let target = TransportAddr::from_string(
        &sink
            .local_addr()
            .expect("precondition: the target is bound")
            .to_string(),
    );
    nodes[0].node.offer_path(&b, t3, target.clone()).await;
    assert_eq!(
        state_at(&nodes[0], &b, t3, &target),
        Some(PathState::Probing),
        "precondition: the path is held and being opened"
    );
    assert_eq!(
        outbound(&nodes[0], t3),
        0,
        "precondition: the connect is not in the pool yet"
    );

    let before = nodes[0]
        .node
        .get_peer(&b)
        .expect("precondition: the peer is held")
        .our_index();
    own_dial(&mut nodes).await;
    let peer = nodes[0]
        .node
        .get_peer(&b)
        .expect("precondition: the move keeps the peer");
    assert_ne!(
        peer.our_index(),
        before,
        "precondition: the peer moved onto the dial's session"
    );
    assert_eq!(
        state_at(&nodes[0], &b, t3, &target),
        None,
        "precondition: the renewed bundle does not hold the pair"
    );
    assert_eq!(
        outbound(&nodes[0], t3),
        0,
        "precondition: the connect was still out when its path was released"
    );

    let state = connect_settled(&nodes[0], t3, &target).await;
    assert!(
        matches!(state, ConnectionState::Connected | ConnectionState::None),
        "precondition: the connect did not fail: {state:?}"
    );
    nodes[0].node.path_tick().await;
    let open = outbound(&nodes[0], t3);
    drop(sink);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(open, 0, "defect: a connection is left open with no path");
}

/// A capable link with the peer active on q leaves p unkept. A restart's msg1
/// arrives from p's pair, and the teardown queues p's close before the new
/// link exists there. The drain should spare the pair the new link was just
/// promoted at; it does not ask again, and calls for its close.
#[tokio::test]
#[ignore = "known defect: a close queued at a restart's teardown is drained at the pair the new link runs on"]
async fn a_close_queued_at_a_restart_teardown_spares_the_new_link_at_that_pair() {
    let t1 = TransportId::new(1);
    let (mut nodes, _b, a2, _b2) = two_transports(1280).await;
    let p = nodes[1].addr.clone();
    let on_q = PathRef {
        transport: t2(),
        addr: a2,
    };
    beat(&mut nodes, Some(&on_q)).await;
    restart_dial(&mut nodes, enabled()).await;
    assert!(
        !loopback(&nodes[0], t1).closed().contains(&p),
        "precondition: the close waits for the drain"
    );
    nodes[0].node.drain_closes().await;
    let closed = loopback(&nodes[0], t1).closed();
    cleanup_nodes(&mut nodes).await;
    assert!(
        !closed.contains(&p),
        "defect: the close queued at the teardown closed the connection the new link runs on: {closed:?}"
    );
}

/// With multipath off no link is capable, so every path keeps its connection:
/// the same restart's teardown queues no close, and the drain closes nothing.
#[tokio::test]
async fn with_multipath_off_a_restart_teardown_queues_no_close() {
    let t1 = TransportId::new(1);
    let mut nodes = linked_pair(disabled(), disabled()).await;
    restart_dial(&mut nodes, disabled()).await;
    nodes[0].node.drain_closes().await;
    let closed = loopback(&nodes[0], t1).closed();
    cleanup_nodes(&mut nodes).await;
    assert!(
        closed.is_empty(),
        "defect: a teardown with multipath off closed {closed:?}"
    );
}

/// A reading of no carrier is kept by link and transport, so a move, which
/// keeps the link id, keeps it; the peer's removal ends it at the next read.
/// The link here holds two paths, since a link of one keeps no reading.
#[tokio::test]
async fn a_no_carrier_reading_stays_across_a_move_and_goes_with_the_peer() {
    let t1 = TransportId::new(1);
    let (mut nodes, b, _a2, _b2) = two_transports(1280).await;
    loopback(&nodes[0], t1).set_carrier(Some(false));
    loopback(&nodes[0], t2()).set_carrier(Some(false));
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    let before = nodes[0].node.paths.readings();
    assert!(before > 0, "precondition: a reading of no carrier is kept");
    let held = nodes[0]
        .node
        .get_peer(&b)
        .expect("precondition: the peer is held");
    let (link, index) = (held.link_id(), held.our_index());

    own_dial(&mut nodes).await;
    let moved = nodes[0]
        .node
        .get_peer(&b)
        .expect("precondition: the move keeps the peer");
    assert_ne!(
        moved.our_index(),
        index,
        "precondition: the peer moved onto the dial's session"
    );
    assert_eq!(moved.link_id(), link, "precondition: the link id stays");
    let after = nodes[0].node.paths.readings();
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    let ticked = nodes[0].node.paths.readings();

    nodes[0].node.remove_active_peer(&b);
    crate::time::advance(Duration::from_millis(50));
    nodes[0].node.path_tick().await;
    let gone = nodes[0].node.paths.readings();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(after, before, "defect: a move keeps the reading");
    assert_eq!(
        ticked, before,
        "defect: a tick after the move keeps the reading"
    );
    assert_eq!(gone, 0, "defect: the reading goes with the peer");
}

/// `nodes[1]` restarts, built from `config`; `nodes[0]`'s rekey msg1 reaches
/// it, its msg2 shows the restart, and `nodes[0]` cuts over.
async fn restart_at_a_rekey(nodes: &mut [TestNode], config: Config) {
    let b = *nodes[1].node.node_addr();
    let restarted = restarted_node(&nodes[1], config);
    drop(std::mem::replace(&mut nodes[1], restarted));
    nodes[0]
        .node
        .get_peer_mut(&b)
        .expect("precondition: node 0 holds its peer")
        .test_backdate_session_established(trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    assert!(
        nodes[0]
            .node
            .get_peer(&b)
            .expect("precondition: node 0 holds its peer")
            .rekey_in_progress(),
        "precondition: node 0 started a rekey to the restarted node"
    );
    deliver(&mut nodes[1]).await;
    let msg2 = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok())
        .find(|packet| phase(packet) == Some(PHASE_MSG2))
        .expect("precondition: the restarted node's msg2 is queued");
    nodes[0].node.handle_msg2(msg2).await;
    let epoch = nodes[1].node.startup_epoch();
    let peer = nodes[0]
        .node
        .get_peer(&b)
        .expect("precondition: the msg2 keeps the peer");
    assert_eq!(
        peer.remote_epoch(),
        Some(epoch),
        "precondition: the msg2 showed the restart"
    );
    cutover(&mut nodes[0], &b).await;
}

/// A capable link of two paths, pinned, whose peer has restarted when a rekey
/// finds it: the link and every path of its bundle stay under the identifiers
/// they had, active on the same one, and only the pin ends. Asserted as the
/// code does it today, as `cells.rs` does, so a change to it shows up here.
#[tokio::test]
async fn chartest_a_restart_at_a_rekey_keeps_the_bundle_and_ends_the_pin() {
    let (mut nodes, b, _a2, _b2) = transports_with(with_path(rekey_config(60), true), 1280).await;
    let p = PathRef {
        transport: nodes[0].transport_id,
        addr: nodes[1].addr.clone(),
    };
    nodes[0]
        .node
        .step_path(
            &b,
            Input::Pin {
                transport: p.transport,
                addr: Some(p.addr),
            },
        )
        .await;
    let held = |tn: &TestNode| {
        let peer = tn
            .node
            .get_peer(&b)
            .expect("precondition: node 0 holds its peer");
        let paths: Vec<_> = peer
            .paths()
            .iter()
            .map(|path| (path.path_id(), path.transport_id(), path.addr().clone()))
            .collect();
        let active = peer.active_path().map(|path| path.path_id());
        (peer.link_id(), paths, active)
    };
    let before = held(&nodes[0]);
    assert_eq!(before.1.len(), 2, "precondition: the link holds two paths");
    {
        let bundle = nodes[0]
            .node
            .get_peer(&b)
            .and_then(|peer| peer.bundle())
            .expect("precondition: the link has a bundle");
        assert!(bundle.capable(), "precondition: the link is capable");
        assert!(bundle.pin().is_some(), "precondition: the link is pinned");
    }

    restart_at_a_rekey(&mut nodes, with_path(rekey_config(60), true)).await;
    let after = held(&nodes[0]);
    let pinned = nodes[0]
        .node
        .get_peer(&b)
        .and_then(|peer| peer.bundle())
        .expect("precondition: the link keeps its bundle")
        .pin()
        .is_some();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(after, before, "defect: the restart kept the bundle");
    assert!(!pinned, "defect: the restart ended the pin");
}
