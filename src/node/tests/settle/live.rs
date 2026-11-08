//! The live audit on real nodes: every node entry that can change a
//! per-peer map audits the maps on its way out in a debug build
//! (`node::settle::audit`), on every node a test did not write past the map
//! writers, and the waivers it honours are recorded at the event that makes
//! their state, on that link only.
//!
//! The audit is absent from a release build, so every test here that needs
//! it to run carries `#[cfg(debug_assertions)]`.

// Those tests' helpers and imports are unused in a release test build.
#![cfg_attr(not(debug_assertions), allow(dead_code, unused_imports))]

use super::super::crossed_dial::{Dial, cross_dials_from, hand};
use super::super::spanning_tree::{TestNode, cleanup_nodes, initiate_handshake};
use super::super::*;
use super::{loopback_node, pump, resolve_connect, tcp_dial, tcp_pair, with_path};
use crate::node::settle::Waiver;
use crate::peer::machine::DialOrigin;

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

/// A crossed dial won from a second address of the larger node's: the
/// smaller node's move releases the only index entry of the inbound link it
/// keeps the peer on, and it records the crossing's waiver on that link and
/// on no other, neither a second link it holds nor any link of the larger
/// node. The second link is written in by hand, so the live audit is off for
/// the smaller node here; the waivers are recorded all the same.
#[tokio::test]
async fn the_waiver_is_recorded_at_the_crossing_and_scoped_to_that_link() {
    let crossed = cross_dials_from(Dial::OtherAddress, with_path(Config::new(), false)).await;
    let (s, l) = (crossed.s, crossed.l);
    let mut nodes = crossed.nodes;
    let spare = nodes[s].node.allocate_link_id();
    let link = Link::connectionless(
        spare,
        nodes[s].transport_id,
        TransportAddr::from_string("127.0.0.1:9"),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    nodes[s].node.links.raw().insert(spare, link);
    hand(&mut nodes[s].node, crossed.msg2).await;
    assert!(
        nodes[s].node.links.contains_key(&spare),
        "precondition: the smaller node still holds its second link"
    );
    let link = held(&nodes, s, l);
    let carried = nodes[s].node.links.carries(&link, Waiver::CrossedInbound);
    let others: Vec<(usize, LinkId)> = nodes
        .iter()
        .enumerate()
        .flat_map(|(i, tn)| {
            tn.node
                .links
                .keys()
                .filter(|k| {
                    !(i == s && **k == link) && tn.node.links.carries(k, Waiver::CrossedInbound)
                })
                .map(move |k| (i, *k))
                .collect::<Vec<_>>()
        })
        .collect();
    cleanup_nodes(&mut nodes).await;
    assert!(
        carried,
        "defect: the smaller node recorded no crossing waiver on the link it holds the peer on"
    );
    assert!(
        others.is_empty(),
        "defect: other links carry a waiver: {others:?}"
    );
}

/// A crossed dial won on the tie-break, answered from the address the
/// smaller node already holds the larger on: the move keeps the link at its
/// pair with its index entry, so the swap records no waiver.
#[tokio::test]
async fn a_crossing_that_keeps_the_links_entry_records_no_waiver() {
    let crossed = cross_dials_from(Dial::AnsweredFromFirst, with_path(Config::new(), false)).await;
    let (s, l) = (crossed.s, crossed.l);
    let mut nodes = crossed.nodes;
    hand(&mut nodes[s].node, crossed.msg2).await;
    let link = held(&nodes, s, l);
    let entry = nodes[s]
        .node
        .links
        .index()
        .values()
        .any(|named| *named == link);
    let waived = nodes[s].node.links.carries(&link, Waiver::CrossedInbound)
        || nodes[s].node.links.carries(&link, Waiver::MovedOwnDial);
    cleanup_nodes(&mut nodes).await;
    assert!(
        entry,
        "precondition: the move kept an index entry for the held link"
    );
    assert!(
        !waived,
        "defect: a swap that kept the link's index entry recorded a waiver"
    );
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

/// An anonymous dial on a connection-oriented transport leaves its link named
/// by nothing but its pending connect: `link-named` reads that, so the link
/// passes while the connect is pending, is flagged if the pending connect goes
/// and the link stays, and is named by the leg's machine once the connect
/// resolves.
#[cfg(debug_assertions)]
#[tokio::test]
async fn an_anonymous_connects_link_is_named_by_its_pending_connect_until_its_leg_names_it() {
    use crate::node::settle::audit::link_named;
    let mut nodes = tcp_pair(false, true).await;
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection_from(tid, addr, None, DialOrigin::NeighbourClaim)
        .await
        .expect("precondition: the dial starts");
    let link = nodes[0].node.peering.pending_connects[0].link_id;
    let machine = nodes[0].node.peer_machines.contains_key(&link);
    let pending = link_named(&nodes[0].node);
    let connects = std::mem::take(&mut nodes[0].node.peering.pending_connects);
    let dropped = link_named(&nodes[0].node);
    nodes[0].node.peering.pending_connects = connects;
    resolve_connect(&mut nodes[0]).await;
    let leg = nodes[0].node.peer_machines.contains_key(&link);
    let resolved = link_named(&nodes[0].node);
    let count = audits(&nodes[0]);
    cleanup_nodes(&mut nodes).await;
    assert!(!machine, "precondition: no machine names the pending link");
    assert!(
        pending.is_empty(),
        "defect: link-named flagged a link its pending connect names: {pending:?}"
    );
    assert_eq!(
        dropped,
        vec![link],
        "defect: link-named passed a link with no pending connect left to name it"
    );
    assert!(leg, "precondition: the resolved connect has a leg");
    assert!(
        resolved.is_empty(),
        "defect: link-named flagged a link its leg's machine names: {resolved:?}"
    );
    assert!(count > 0, "defect: the live audit never checked the dialer");
}
