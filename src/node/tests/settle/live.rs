//! The live audit on real nodes: every node entry that can change a
//! per-peer map audits the maps on its way out in a debug build
//! (`node::settle::audit`), on every node a test did not write past the map
//! writers.
//!
//! The audit is absent from a release build, so every test here that needs
//! it to run carries `#[cfg(debug_assertions)]`.

// Those tests' helpers and imports are unused in a release test build.
#![cfg_attr(not(debug_assertions), allow(dead_code, unused_imports))]

use super::super::crossed_dial::hand;
use super::super::spanning_tree::{TestNode, cleanup_nodes, initiate_handshake};
use super::super::*;
use super::{loopback_node, pump, resolve_connect, tcp_dial, tcp_pair};

/// How many times the live audit has checked `tn`'s node.
fn audits(tn: &TestNode) -> u64 {
    tn.node.links.audits()
}

/// The link `nodes[at]` holds `nodes[peer]` on.
fn held(nodes: &[TestNode], at: usize, peer: usize) -> LinkId {
    nodes[at]
        .node
        .get_peer(nodes[peer].node.node_addr())
        .expect("precondition: the node holds the peer")
        .link_id()
}

/// One loopback dial through `initiate_handshake`, the helper most node
/// tests dial with, and one TCP dial through `initiate_connection`, each
/// delivered until idle: both nodes of each were audited, and nothing
/// breached.
#[cfg(debug_assertions)]
async fn healthy_dial(on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    assert!(
        nodes[0].node.get_peer(nodes[1].node.node_addr()).is_some(),
        "precondition: the loopback dial promoted the peer"
    );
    let counts = [audits(&nodes[0]), audits(&nodes[1])];
    cleanup_nodes(&mut nodes).await;
    assert!(
        counts.iter().all(|n| *n > 0),
        "defect: a loopback dial left a node the live audit never checked: {counts:?}"
    );

    let mut nodes = tcp_pair(on, true).await;
    tcp_dial(&mut nodes, 0, 1).await;
    resolve_connect(&mut nodes[0]).await;
    pump(&mut nodes).await;
    assert!(
        nodes[0].node.get_peer(nodes[1].node.node_addr()).is_some(),
        "precondition: the TCP dial promoted the peer"
    );
    let counts = [audits(&nodes[0]), audits(&nodes[1])];
    cleanup_nodes(&mut nodes).await;
    assert!(
        counts.iter().all(|n| *n > 0),
        "defect: a TCP dial left a node the live audit never checked: {counts:?}"
    );
}

/// [`healthy_dial`] with multipath off.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_healthy_dial_passes_the_live_audit_at_every_entry() {
    healthy_dial(false).await;
}

/// [`healthy_dial`] with multipath on.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_healthy_dial_passes_the_live_audit_at_every_entry_with_multipath_on() {
    healthy_dial(true).await;
}

/// A link no peer, machine or dial names, written into the link table past
/// its writers, is a breach the audit would fail; the node is marked, so the
/// entries it then runs do not audit it.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_node_a_test_wrote_directly_is_not_audited() {
    let mut tn = loopback_node(false).await;
    let stale = tn.node.allocate_link_id();
    let link = Link::connectionless(
        stale,
        tn.transport_id,
        TransportAddr::from_string("127.0.0.1:9"),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    tn.node.links.raw().insert(stale, link);
    tn.node.poll_pending_connects().await;
    tn.node.check_timeouts().await;
    let count = audits(&tn);
    cleanup_nodes(std::slice::from_mut(&mut tn)).await;
    assert_eq!(
        count, 0,
        "defect: the live audit checked a node a test wrote directly"
    );
}

/// The same link with a pending dial naming it, written through the
/// writers: the node is not marked, and the same entries audit it.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_node_a_test_wrote_through_the_writers_is_audited() {
    let mut tn = loopback_node(false).await;
    let dial = tn.node.allocate_link_id();
    let link = Link::connectionless(
        dial,
        tn.transport_id,
        TransportAddr::from_string("127.0.0.1:9"),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    tn.node.links.open(link);
    tn.node.pending_outbound.note((tn.transport_id, 5), dial);
    tn.node.poll_pending_connects().await;
    tn.node.check_timeouts().await;
    let count = audits(&tn);
    cleanup_nodes(std::slice::from_mut(&mut tn)).await;
    assert_eq!(
        count, 2,
        "defect: the live audit did not check a node written through its writers at each entry"
    );
}

/// An index entry a test hook puts in past the table without marking it,
/// the shape of a writer that bypasses the table, off the link's pair and
/// every path its peer holds: the next frame the node reads fails the live
/// audit's `entry-pair` clause.
#[cfg(debug_assertions)]
#[tokio::test]
#[should_panic(expected = "audit_live: handle_encrypted_frame: entry-pair")]
async fn an_index_entry_written_past_the_table_fails_the_live_audit_at_the_next_frame() {
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let link = held(&nodes, 0, 1);
    let tid = nodes[0].transport_id;
    nodes[0]
        .node
        .links
        .plant_entry((tid, TransportAddr::from_string("127.0.0.1:9")), link);
    let to = *nodes[0].node.node_addr();
    nodes[1]
        .node
        .send_encrypted_link_message(
            &to,
            &[crate::proto::link::LinkMessageType::Heartbeat.to_byte()],
        )
        .await
        .expect("precondition: node 1 sends a heartbeat");
    let frame = nodes[0]
        .packet_rx
        .try_recv()
        .expect("precondition: the heartbeat is queued at node 0");
    hand(&mut nodes[0].node, frame).await;
}

/// A node whose decrypt-worker pool lost one of its two workers at start:
/// a session the pool refuses stays with the link machine, so the node holds
/// a current session no worker holds. The live audit does not call that a
/// breach, since the pool refuses on purpose.
#[cfg(all(unix, debug_assertions))]
#[tokio::test]
async fn a_session_a_degraded_pool_refused_passes_the_live_audit() {
    use crate::node::decrypt_worker::DecryptWorkerPool;
    use crate::node::worker_set::TestWorker;
    for _ in 0..64 {
        let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
        nodes[0].node.supervisor.decrypt_workers = Some(DecryptWorkerPool::for_test(vec![
            TestWorker::Run,
            TestWorker::FailSpawn,
        ]));
        initiate_handshake(&mut nodes, 0, 1).await;
        pump(&mut nodes).await;
        let current = nodes[0]
            .node
            .get_peer(nodes[1].node.node_addr())
            .and_then(|p| p.our_index())
            .map(|i| i.as_u32());
        let refused =
            current.is_some_and(|i| !nodes[0].node.decrypt_registered_sessions.contains(&i));
        let count = audits(&nodes[0]);
        cleanup_nodes(&mut nodes).await;
        if refused {
            assert!(
                count > 0,
                "defect: the live audit never checked the node whose pool refused a session"
            );
            return;
        }
    }
    panic!("precondition: in 64 dials the pool never refused a session");
}

/// Two nodes started on UDP, each with its own decrypt-worker pool and its
/// receive loop running, carry a packet between their app-owned TUNs: both
/// are audited at the entries their loops run, with sessions on workers.
#[cfg(all(unix, debug_assertions))]
#[tokio::test]
async fn two_started_nodes_on_a_real_pool_pass_the_live_audit() {
    use super::super::app_tun::{app_tun_config, ipv6_packet, udp_addr};

    let mut node_b = Node::new(app_tun_config()).unwrap();
    let (_b_outbound, b_inbound) = node_b.enable_app_owned_tun();
    node_b.start().await.unwrap();
    let mut config_a = app_tun_config();
    config_a.peers.push(crate::config::PeerConfig::new(
        node_b.npub(),
        "udp",
        udp_addr(&node_b).to_string(),
    ));
    let mut node_a = Node::new(config_a).unwrap();
    let (a_outbound, _a_inbound) = node_a.enable_app_owned_tun();
    node_a.start().await.unwrap();
    let addr_a = node_a.identity().address().to_ipv6();
    let addr_b = node_b.identity().address().to_ipv6();

    let embedder = async {
        let packet = ipv6_packet(addr_a, addr_b, 120);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        loop {
            assert!(
                tokio::time::Instant::now() < deadline,
                "precondition: the packet reached the peer's app within 15 s"
            );
            a_outbound.send(packet.clone()).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            if std::iter::from_fn(|| b_inbound.try_recv().ok()).any(|p| p == packet) {
                break;
            }
        }
    };
    tokio::select! {
        result = node_a.run_rx_loop() => panic!("node A's rx loop exited: {result:?}"),
        result = node_b.run_rx_loop() => panic!("node B's rx loop exited: {result:?}"),
        () = embedder => {}
    }

    let counts = [node_a.links.audits(), node_b.links.audits()];
    let pooled = [
        node_a.supervisor.decrypt_workers.is_some(),
        node_b.supervisor.decrypt_workers.is_some(),
    ];
    let onworker = [
        node_a.decrypt_registered_sessions.len(),
        node_b.decrypt_registered_sessions.len(),
    ];
    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
    assert_eq!(
        pooled,
        [true, true],
        "precondition: each started node runs a decrypt-worker pool"
    );
    assert!(
        onworker.iter().any(|n| *n > 0),
        "precondition: a worker holds a session: {onworker:?}"
    );
    assert!(
        counts.iter().all(|n| *n > 0),
        "defect: a started node was never audited: {counts:?}"
    );
}

/// The core's record of the link `nodes[at]` holds `nodes[peer]` on: each
/// path as `(transport, address, state)`, in the record's order.
fn record(
    nodes: &[TestNode],
    at: usize,
    peer: usize,
) -> Vec<(
    TransportId,
    TransportAddr,
    crate::proto::settle::links::Proven,
)> {
    let links = &nodes[at].node.links;
    let no = links
        .no(&held(nodes, at, peer))
        .expect("precondition: the held link has a core record");
    links
        .core()
        .get(no)
        .expect("precondition: the record is there")
        .paths
        .iter()
        .map(|(p, s)| (p.transport, p.addr.clone(), *s))
        .collect()
}

/// A dial through the writers, with multipath set as `on`: the core's record
/// of each end's link holds the link's original path Live, which is all its
/// bundle holds, so `links-mirror` passes; the same record with that path's
/// state changed past the feed fails it, naming the peer.
async fn dialed_record(on: bool) {
    use crate::proto::settle::links::Proven;
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let tid = nodes[0].transport_id;
    let to = (tid, nodes[1].addr.clone());
    let peer = *nodes[1].node.node_addr();
    let link = held(&nodes, 0, 1);
    let at_dial = record(&nodes, 0, 1);
    let at_answer = record(&nodes, 1, 0);
    let clean = crate::node::settle::audit::links_mirror(&nodes[0].node).bad;
    nodes[0].node.links.plant_path(&link, &to, Proven::Probing);
    let off = crate::node::settle::audit::links_mirror(&nodes[0].node).bad;
    nodes[0].node.links.plant_path(&link, &to, Proven::Live);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        at_dial,
        vec![(tid, to.1.clone(), Proven::Live)],
        "defect: the dialer's record does not hold the original path Live"
    );
    assert_eq!(
        at_answer.len(),
        1,
        "defect: the answerer's record: {at_answer:?}"
    );
    assert_eq!(at_answer[0].2, Proven::Live, "defect: {at_answer:?}");
    assert!(
        clean.is_empty(),
        "defect: links-mirror failed a fed record: {clean:?}"
    );
    assert!(
        off.len() == 1 && off[0].starts_with(&peer.to_string()),
        "defect: links-mirror passed a record off its bundle: {off:?}"
    );
}

/// [`dialed_record`] with multipath off.
#[tokio::test]
async fn a_dialed_links_record_holds_its_original_path_live_and_one_off_its_bundle_fails() {
    dialed_record(false).await;
}

/// [`dialed_record`] with multipath on.
#[tokio::test]
async fn a_dialed_links_record_holds_its_original_path_live_and_one_off_its_bundle_fails_with_multipath_on()
 {
    dialed_record(true).await;
}

/// A heartbeat from a new address of the peer's on the same transport roams
/// the one path of the link, with multipath set as `on`; the bundle reports
/// no roam, and the frame tells the core's record, which then holds the path
/// at the new address, Live, and `links-mirror` passes.
async fn roam_mirrored(on: bool) {
    use crate::proto::settle::links::Proven;
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let tid = nodes[0].transport_id;
    let moved = super::super::spanning_tree::add_loopback_alias(&nodes[1].addr, tid);
    let to = *nodes[0].node.node_addr();
    let peer = *nodes[1].node.node_addr();
    nodes[1]
        .node
        .send_encrypted_link_message(
            &to,
            &[crate::proto::link::LinkMessageType::Heartbeat.to_byte()],
        )
        .await
        .expect("precondition: node 1 sends a heartbeat");
    super::super::paths::deliver_from(&mut nodes[0], &moved).await;
    let active = nodes[0]
        .node
        .get_peer(&peer)
        .and_then(|p| p.active_path())
        .map(|p| (p.transport_id(), p.addr().clone()));
    let rec = record(&nodes, 0, 1);
    let bad = crate::node::settle::audit::links_mirror(&nodes[0].node).bad;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        active,
        Some((tid, moved.clone())),
        "precondition: the frame roamed the link's path"
    );
    assert_eq!(
        rec,
        vec![(tid, moved, Proven::Live)],
        "defect: the record did not follow the roam"
    );
    assert!(bad.is_empty(), "defect: links-mirror after a roam: {bad:?}");
}

/// [`roam_mirrored`] with multipath off.
#[tokio::test]
async fn a_roam_keeps_the_records_mirror() {
    roam_mirrored(false).await;
}

/// [`roam_mirrored`] with multipath on.
#[tokio::test]
async fn a_roam_keeps_the_records_mirror_with_multipath_on() {
    roam_mirrored(true).await;
}

/// A link of two Live paths, p (t1) active and q (t2): p's carrier goes, so
/// p turns Suspect, still acknowledged, and the link switches to q. The core
/// records p acknowledged, as its bundle holds it, and `links-mirror` lets
/// no acknowledged path off but the active one: the same record with p Live
/// fails. Then q's transport goes, and the link switches back to p: the core
/// records p Live, as a switch does, where the bundle holds it acknowledged,
/// and `links-mirror` lets that one difference off, naming the peer.
#[tokio::test]
async fn a_switch_to_an_acked_path_is_recorded_live_and_is_let_off_with_multipath_on() {
    use super::super::paths::{active_of, carrier, state_at, t2, two_transports};
    use crate::proto::settle::links::Proven;
    let (mut nodes, b, _, b2) = two_transports(1280).await;
    let (t1, b1) = (nodes[0].transport_id, nodes[1].addr.clone());
    let link = held(&nodes, 0, 1);
    carrier(&mut nodes, t1, false).await;
    let p_lost = state_at(&nodes[0], &b, t1, &b1);
    let on_q = active_of(&nodes[0], &b);
    let standby = record(&nodes, 0, 1);
    nodes[0]
        .node
        .links
        .plant_path(&link, &(t1, b1.clone()), Proven::Live);
    let standby_live = crate::node::settle::audit::links_mirror(&nodes[0].node);
    nodes[0]
        .node
        .links
        .plant_path(&link, &(t1, b1.clone()), Proven::Acked);
    nodes[0].node.path_removed(t2()).await;
    let on_p = active_of(&nodes[0], &b);
    let p_back = state_at(&nodes[0], &b, t1, &b1);
    let switched = record(&nodes, 0, 1);
    let found = crate::node::settle::audit::links_mirror(&nodes[0].node);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        p_lost,
        Some(crate::peer::PathState::Suspect),
        "precondition: p turned Suspect"
    );
    assert_eq!(
        on_q,
        (t2(), b2.clone()),
        "precondition: the link moved to q"
    );
    assert!(
        standby.contains(&(t1, b1.clone(), Proven::Acked)),
        "precondition: the core records the standby p acknowledged: {standby:?}"
    );
    assert_eq!(
        standby_live.bad.len(),
        1,
        "defect: links-mirror let off an acknowledged path that is not active: {:?}",
        standby_live.bad
    );
    assert_eq!(
        on_p,
        (t1, b1.clone()),
        "precondition: the link switched to p"
    );
    assert_eq!(
        p_back,
        Some(crate::peer::PathState::Suspect),
        "precondition: p is still Suspect"
    );
    assert_eq!(
        switched,
        vec![(t1, b1, Proven::Live)],
        "defect: a switch to an acknowledged path is not recorded Live"
    );
    assert!(found.bad.is_empty(), "defect: {:?}", found.bad);
    assert_eq!(
        found.letoff,
        vec![b],
        "defect: links-mirror did not let the switched path off"
    );
}
