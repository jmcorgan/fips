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
    tn.node.plant_dial_at((tn.transport_id, 5), dial, None);
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

/// A link of one path that is not active (multipath on): a frame from a
/// new address of the peer's roams that path, and the core's record of the
/// link moves the path there and keeps none at the address it left, which
/// the frame's accounting tells the core for a standby path as it does for
/// the active one.
#[tokio::test]
async fn a_standby_paths_roam_moves_its_links_record_with_multipath_on() {
    use crate::proto::settle::links::Proven;
    let mut nodes = vec![loopback_node(true).await, loopback_node(true).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let tid = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    let b = *nodes[1].node.node_addr();
    nodes[0]
        .node
        .peers
        .get_mut(&b)
        .expect("precondition: node 0 holds node 1")
        .idle_active();
    nodes[0].node.resync();
    let standby = nodes[0]
        .node
        .get_peer(&b)
        .and_then(|p| p.bundle())
        .map(|bundle| (bundle.paths().len(), bundle.paths().active_index()));
    let before = record(&nodes, 0, 1);
    let moved = super::super::spanning_tree::add_loopback_alias(&b1, tid);
    let to = *nodes[0].node.node_addr();
    nodes[1]
        .node
        .send_encrypted_link_message(
            &to,
            &[crate::proto::link::LinkMessageType::Heartbeat.to_byte()],
        )
        .await
        .expect("precondition: node 1 sends a heartbeat");
    super::super::paths::deliver_from(&mut nodes[0], &moved).await;
    let after = record(&nodes, 0, 1);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        standby,
        Some((1, None)),
        "precondition: the link holds one path, not active"
    );
    assert_eq!(
        before,
        vec![(tid, b1, Proven::Live)],
        "precondition: the record holds the path"
    );
    assert_eq!(
        after,
        vec![(tid, moved, Proven::Live)],
        "defect: the record did not follow the standby path's roam"
    );
}

/// A link of two Live paths, p (t1) active and q (t2): p's carrier goes, so
/// p turns Suspect, still acknowledged, and the link switches to q. The core
/// records p acknowledged, as its bundle holds it, and `links-mirror` fails
/// the same record with p Live. Then q's transport goes, and the link
/// switches back to p: the core records p acknowledged, the state its bundle
/// holds it in, and `links-mirror` finds nothing.
#[tokio::test]
async fn a_switch_to_an_acked_path_is_recorded_acked_and_the_mirror_holds_with_multipath_on() {
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
        "defect: links-mirror passed a record holding Live a path its bundle holds acknowledged: {:?}",
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
        vec![(t1, b1, Proven::Acked)],
        "defect: a switch to an acknowledged path is recorded Live, not as its bundle holds it"
    );
    assert!(found.bad.is_empty(), "defect: {:?}", found.bad);
}

/// A dial in flight, its msg1 sent and unanswered: the node's machine and
/// the shadow core's leg agree on when the leg is reaped and when its next
/// resend is due, and moving either on the node's side alone is a
/// `legs-agree` difference.
#[tokio::test]
async fn a_dials_deadline_and_next_resend_are_held_to_the_shadow_cores_leg() {
    use crate::node::settle::audit::legs_agree;
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    let id = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection(tid, addr, id)
        .await
        .expect("precondition: the dial starts");
    let node = &mut nodes[0].node;
    let link = node
        .peer_machines
        .iter()
        .find(|(_, m)| m.leg().is_some())
        .map(|(id, _)| *id)
        .expect("precondition: the dial's machine carries a handshake");
    let held = node.shadow.no(link).is_some_and(|no| {
        node.shadow
            .table()
            .is_some_and(|t| t.legs().iter().any(|l| l.link() == no))
    });
    let healthy = legs_agree(node);
    let no = node
        .links
        .no(&link)
        .expect("precondition: the dial's link is numbered");
    let (deadline, resend) = node
        .legs
        .get(no)
        .and_then(|leg| Some((leg.deadline(), leg.next_resend()?)))
        .expect("precondition: the dial's leg has a next resend");
    let later = |at: crate::peer::PeerInstant, ms: u64| {
        fips_core::time::Instant::checked_add(at, std::time::Duration::from_millis(ms))
            .expect("precondition: a later instant")
    };
    node.legs.replant(no, deadline, Some(later(resend, 2_000)));
    let late_resend = legs_agree(node);
    node.legs.replant(no, deadline, Some(resend));
    let restored = legs_agree(node);
    node.legs.replant(no, later(deadline, 5_000), Some(resend));
    let late_reap = legs_agree(node);
    cleanup_nodes(&mut nodes).await;
    assert!(held, "precondition: the shadow core holds the dial's leg");
    assert!(
        healthy.is_empty() && restored.is_empty(),
        "precondition: the node and the shadow agree on the dial: {healthy:?} {restored:?}"
    );
    assert_eq!(
        late_resend.len(),
        1,
        "defect: legs-agree passed a resend the node schedules two seconds after the core: {late_resend:?}"
    );
    assert_eq!(
        late_reap.len(),
        1,
        "defect: legs-agree passed a leg the node reaps five seconds after the core: {late_reap:?}"
    );
}

/// A dial in flight whose next resend the node's machine and the shadow
/// core's leg hold a few milliseconds apart, as each side stamps its own at
/// its site, compared at an instant between the two: the resend is due on
/// the node's side and not yet on the core's, and `legs-agree` finds the
/// two alike, as it does not when the times are further apart than the
/// skew.
#[tokio::test]
async fn a_resend_due_on_one_side_only_between_two_close_times_agrees_in_legs_agree() {
    use crate::node::settle::audit::legs_agree;
    crate::time::freeze();
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    let id = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection(tid, addr, id)
        .await
        .expect("precondition: the dial starts");
    let node = &mut nodes[0].node;
    let link = node
        .peer_machines
        .iter()
        .find(|(_, m)| m.leg().is_some())
        .map(|(id, _)| *id)
        .expect("precondition: the dial's machine carries a handshake");
    let next = node
        .shadow
        .no(link)
        .and_then(|no| node.shadow.table().and_then(|t| t.legs().get(no)))
        .and_then(|leg| leg.next_resend())
        .map(crate::time::mono_ms_at)
        .expect("precondition: the shadow core's leg has a next resend");
    let now = Node::interval_ms();
    assert!(next > now + 1, "precondition: the next resend is ahead");
    crate::time::advance(std::time::Duration::from_millis(next - 1 - now));
    let no = node
        .links
        .no(&link)
        .expect("precondition: the dial's link is numbered");
    let deadline = node
        .legs
        .get(no)
        .map(|leg| leg.deadline())
        .expect("precondition: the node holds the dial's leg");
    node.legs
        .replant(no, deadline, Some(crate::time::mono_at(next - 3)));
    let close = legs_agree(node);
    node.legs
        .replant(no, deadline, Some(crate::time::mono_at(next - 600)));
    let far = legs_agree(node);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        far.len(),
        1,
        "precondition: a resend due on the node's side 600 ms before the core's is a difference: {far:?}"
    );
    assert!(
        close.is_empty(),
        "defect: legs-agree found a resend due on one side only, its two times 3 ms apart: {close:?}"
    );
}

/// A dial a test seeds past the node's writers, stamped at the interval
/// clock's second 1 and with no retransmit timer: the shadow core's leg for
/// it is reaped and resends as the node's machine does, so `legs-agree`
/// finds nothing, rather than a leg opened a full timeout and resend
/// interval from the shadow's resync.
#[tokio::test]
async fn a_seeded_dials_instants_are_the_shadow_cores_legs() {
    use crate::node::settle::audit::legs_agree;
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    crate::time::advance(std::time::Duration::from_secs(5));
    initiate_handshake(&mut nodes, 0, 1).await;
    let node = &mut nodes[0].node;
    let link = node
        .peer_machines
        .iter()
        .find(|(_, m)| m.leg().is_some())
        .map(|(id, _)| *id)
        .expect("precondition: the seeded dial's machine carries a handshake");
    let stamped = node.peer_machines.get(&link).map(|m| m.conn_active_at());
    let held = node.shadow_link(link).is_some_and(|no| {
        node.shadow
            .table()
            .is_some_and(|t| t.legs().iter().any(|l| l.link() == no))
    });
    let found = legs_agree(node);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        stamped,
        Some(1000),
        "precondition: the dial is stamped at 1 s"
    );
    assert!(
        held,
        "precondition: the shadow core holds the seeded dial's leg"
    );
    assert!(
        found.is_empty(),
        "defect: the shadow core's leg for a seeded dial keeps instants of its own: {found:?}"
    );
}

/// A dial a test seeds past the decision sites after the shadow core has
/// run: the live audit at the end of the node's next entry finds the
/// shadow core holding a record of the dial's link, as its next input
/// would, so `links-agree` finds nothing rather than a link the core has
/// no record of.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_dial_seeded_between_inputs_is_in_the_shadow_cores_records_when_the_audit_compares() {
    use crate::node::settle::audit::links_agree;
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    nodes[0].node.shadow_tick();
    initiate_handshake(&mut nodes, 0, 1).await;
    let link = nodes[0]
        .node
        .peer_machines
        .iter()
        .find(|(_, m)| m.leg().is_some())
        .map(|(id, _)| *id)
        .expect("precondition: the seeded dial's machine carries a handshake");
    let unseen = nodes[0].node.shadow.no(link).is_none();
    nodes[0].node.audit_live("test");
    let found = links_agree(&nodes[0].node);
    cleanup_nodes(&mut nodes).await;
    assert!(
        unseen,
        "precondition: the shadow has run, and nothing has reached it since the dial was seeded"
    );
    assert!(
        found.is_empty(),
        "defect: the audit compared the shadow before it took the seeded dial: {found:?}"
    );
}

/// A dial the node's timer reaps one millisecond past the node's deadline
/// while the settlement core's leg beside it, taken a tenth of a second
/// after the node stamped the dial (as when building its msg1 sits between
/// the two), is not yet due: the core reaps the leg itself, its deadline
/// within the skew of the node's instant, and is not handed the node's
/// give-up in place of its own reap.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_dial_the_node_reaps_at_its_deadline_is_reaped_by_the_shadow_core_itself_within_the_skew()
{
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    let to = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let (tid, addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    nodes[0]
        .node
        .initiate_connection(tid, addr, to)
        .await
        .expect("node 0 dials node 1");
    let link = nodes[0]
        .node
        .peer_machines
        .iter()
        .find(|(_, m)| m.leg().is_some())
        .map(|(id, _)| *id)
        .expect("precondition: the dial's machine carries a handshake");
    let last = nodes[0].node.peer_machines[&link].conn_active_at();
    let timeout = nodes[0]
        .node
        .config()
        .node
        .rate_limit
        .handshake_timeout_secs
        * 1000;
    nodes[0]
        .node
        .shadow_delay(link, std::time::Duration::from_millis(100));
    let leg = nodes[0].node.shadow.no(link).is_some();
    nodes[0].node.drive_peer_timers(last + timeout + 1).await;
    let reaped = !nodes[0].node.peer_machines.contains_key(&link);
    let held = nodes[0].node.shadow.no(link).is_some();
    let fed = nodes[0].node.shadow.seen("ConnectFailed");
    cleanup_nodes(&mut nodes).await;
    assert!(
        leg && reaped,
        "precondition: the shadow held the dial's leg and the node reaped the dial"
    );
    assert!(
        !held,
        "defect: the shadow core kept the leg of a dial the node reaped within the skew of its own deadline"
    );
    assert_eq!(
        fed, 0,
        "defect: the shadow core was handed the node's give-up instead of reaping the leg itself"
    );
}

/// A test re-points a held peer's one path past the path machine. The
/// settlement core beside the node takes the new path at its next resync,
/// and the node's own link records take it only at the node's resync, so
/// until then `links-agree` passes the peer's link over, as `links-mirror`
/// does; once the node has resynced, both records hold the new path and the
/// link is compared again.
#[cfg(debug_assertions)]
#[tokio::test]
async fn links_agree_passes_over_a_peer_a_test_changed_past_the_feed_until_the_nodes_resync() {
    use crate::node::settle::audit::links_agree;
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let b = *nodes[1].node.node_addr();
    let link = held(&nodes, 0, 1);
    nodes[0]
        .node
        .peers
        .get_mut(&b)
        .expect("precondition: node 0 holds node 1")
        .repin(
            TransportId::new(1),
            TransportAddr::from_string("loopback:999"),
        );
    nodes[0].node.shadow_resync(None);
    let flagged = links_agree(&nodes[0].node);
    nodes[0].node.resync();
    let after = links_agree(&nodes[0].node);
    let moved = nodes[0]
        .node
        .links
        .no(&link)
        .and_then(|n| nodes[0].node.links.core().get(n))
        .is_some_and(|r| {
            r.paths
                .iter()
                .any(|(p, _)| p.addr == TransportAddr::from_string("loopback:999"))
        });
    cleanup_nodes(&mut nodes).await;
    assert!(
        moved && after.is_empty(),
        "precondition: after the node's resync both records hold the new path"
    );
    assert!(
        flagged.is_empty(),
        "defect: links-agree compared a link whose peer the node's records had not taken yet: {flagged:?}"
    );
}

/// The roam of a link's one path while it is not the active path: the node
/// moves the path and resets nothing for the peer, and the settlement core
/// beside it, told of the roam as a standby path's, resets nothing either,
/// so the shadow's comparison finds no difference at the frame.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_standby_paths_roam_resets_the_peer_in_neither_the_node_nor_the_shadow_core_with_multipath_on()
 {
    let mut nodes = vec![loopback_node(true).await, loopback_node(true).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let tid = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    let b = *nodes[1].node.node_addr();
    nodes[0]
        .node
        .peers
        .get_mut(&b)
        .expect("precondition: node 0 holds node 1")
        .idle_active();
    nodes[0].node.resync();
    let agreed = !nodes[0].node.shadow.diverged();
    let moved = super::super::spanning_tree::add_loopback_alias(&b1, tid);
    let to = *nodes[0].node.node_addr();
    nodes[1]
        .node
        .send_encrypted_link_message(
            &to,
            &[crate::proto::link::LinkMessageType::Heartbeat.to_byte()],
        )
        .await
        .expect("precondition: node 1 sends a heartbeat");
    super::super::paths::deliver_from(&mut nodes[0], &moved).await;
    let roamed = record(&nodes, 0, 1).iter().any(|(_, at, _)| *at == moved);
    let diverged = nodes[0].node.shadow.diverged();
    cleanup_nodes(&mut nodes).await;
    assert!(
        agreed && roamed,
        "precondition: the shadow agreed before the frame, and the standby path roamed"
    );
    assert!(
        !diverged,
        "defect: the shadow core decided otherwise than the node at a standby path's roam"
    );
}

/// A peer promoted past the decision sites onto a link the node records,
/// its bundle bound at the link's pair: the node's record of the link took
/// the bundle's path from the bundle's feed, and the settlement core beside
/// the node, which takes the peer by its facts at its resync, takes the
/// path with it, so `links-agree` finds the two records alike.
#[cfg(debug_assertions)]
#[test]
fn a_peer_the_shadow_takes_by_its_facts_brings_its_bundles_paths_to_the_cores_record() {
    use crate::node::settle::audit::links_agree;
    let (mut node, addr, _, _) =
        super::super::connected_udp::promoted_peer_with_the_far_side_session(TransportId::new(1));
    node.shadow_resync(None);
    let held = node.shadow.table().and_then(|t| t.held(&addr)).is_some();
    let bad = links_agree(&node);
    assert!(
        held && !node.planted(),
        "precondition: the shadow holds the peer of an unplanted node"
    );
    assert!(
        bad.is_empty(),
        "defect: the core's record of a peer taken by its facts lacks its bundle's paths: {bad:?}"
    );
}

/// A pending inbound link a test planted with its stored msg2 and no peer,
/// the state a node leaves when the answer's send failed: a msg1 from its
/// address with other bytes draws the stored msg2 in the node, and so in
/// the settlement core beside it, which takes the planted handshake for an
/// answer not yet sent, so the two decide alike.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_planted_answer_whose_msg2_was_not_sent_is_drawn_by_any_msg1_from_its_address() {
    use super::super::establish_chartests::{craft_msg1_wire, register_udp_with_peer_socket};
    use super::super::link_setup_diag::{EPOCH, packet, pending_inbound, stop_transport};
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (_sock, addr) = register_udp_with_peer_socket(&mut node, tid).await;
    pending_inbound(&mut node, tid, &addr);
    let data = craft_msg1_wire(
        &node,
        &Identity::generate(),
        EPOCH,
        SessionIndex::new(5),
        2000,
    );
    node.handle_msg1(packet(tid, &addr, data, 2000)).await;
    let (planted, diverged) = (node.planted(), node.shadow.diverged());
    stop_transport(&mut node, tid).await;
    assert!(planted, "precondition: the pending link was planted");
    assert!(
        !diverged,
        "defect: the shadow core did not draw a planted answer's stored msg2 for a new msg1"
    );
}

/// The same planted answer, its resend failing: the node decided the
/// stored answer and its send failed, and the settlement core beside it,
/// told both, decided the same answer.
#[cfg(debug_assertions)]
#[tokio::test]
async fn a_stored_answer_whose_resend_fails_is_decided_alike_in_the_node_and_the_shadow_core() {
    use super::super::establish_chartests::{craft_msg1_wire, register_udp_with_peer_socket};
    use super::super::link_setup_diag::{EPOCH, packet, pending_inbound, stop_transport};
    let mut node = make_node();
    let tid = TransportId::new(1);
    let (_sock, addr) = register_udp_with_peer_socket(&mut node, tid).await;
    stop_transport(&mut node, tid).await;
    pending_inbound(&mut node, tid, &addr);
    let data = craft_msg1_wire(
        &node,
        &Identity::generate(),
        EPOCH,
        SessionIndex::new(5),
        2000,
    );
    node.handle_msg1(packet(tid, &addr, data, 2000)).await;
    let link = node.links.index().get(&(tid, addr.clone())).copied();
    let pending = link.is_some_and(|l| node.has_pending_leg(&l));
    assert!(
        pending,
        "precondition: the failed resend left the link pending"
    );
    assert!(
        !node.shadow.diverged(),
        "defect: the node's stored answer and its failed send were not decided alike in the shadow core"
    );
}
