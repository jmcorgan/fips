//! Crossed dials and a dialer's second dial: which session and which link
//! each end is left on.
//!
//! - Crossed TCP dials between two real TCP nodes on 127.0.0.1: one working
//!   session on one connection, by the audit (a known difference on this
//!   line, which settles them at each end's msg3 and closes neither node's
//!   second connection); the smaller node's link record, which is the link
//!   it dialed; and a control that redials after a single dial.
//! - A larger node's dial on the aged link after the smaller node's rekey,
//!   read inside the heard floor: one session.
//! - Two dials to one address with no peer held, the first reaped: the
//!   connection the second runs on stays open, on loopback by its record of
//!   closes and on the BLE mock by its pool.
//! - A move at the dial's msg2 holds the link it dialed: at the address
//!   dialed, with the msg2's pair a path of it; and the control machine
//!   moves with the peer.
//! - The close rule where a second path of another link holds the pair, with
//!   multipath on: the link a crossing retires, and a path released while its
//!   link lives, each leave the connection open.
//! - The close rule on a roamed link: a larger node's dial at the pair its
//!   peer's one path roamed to, torn down when the peer's own dial wins,
//!   leaves the connection the peer runs on open.
//! - What a move closes of the link it left: on TCP, crossed dials the
//!   smaller node settles at its msg2 leave it holding its dial's connection
//!   alone; on loopback, a dial still in flight at the left link's pair keeps
//!   that connection open. The larger node, which settles the same crossing
//!   at the peer's msg3, is left held on the link it dialed, whose connection
//!   the smaller node closed: a known defect on this line, pinned once per
//!   order and setting.
//!
//! The master line's crossings won on another pair, its late second dials,
//! its second own dials, its dials on a quiet peer's aged link, its redials
//! after a crossing, its pin ended by a second dial answered after a
//! crossing and its TCP crossing with one msg1 inside the other's connect
//! window set up states this line's handshake does not reach, and are not
//! run here.
//!
//! Each test is run once per address order, so each order has its own
//! verdict, and once per setting of `node.path.enabled`: a test's plain name
//! runs multipath off, and its `_with_multipath_on` sibling runs it on, as two
//! tests and not one loop, since a pin that fails in a loop's first pass would
//! never reach the second. Setup checks are marked `precondition:`; the
//! assertion of the behaviour is marked `defect:`.

use super::super::control::quieten;
use super::super::crossed_dial::{hand, phase};
use super::super::rekey_parity::{
    age_link, cutover, deliver, heartbeat, rekey_config, rekey_to_pending, trigger_age,
};
use super::super::spanning_tree::{
    TestNode, cleanup_nodes, dial_at, drain_all_packets, initiate_handshake,
    make_test_node_with_config, process_available_packets,
};
use super::super::*;
use super::audit::assert_coherent;
use super::readings::own_dial;
use super::{
    alias, crossed_tcp, heartbeat_reaches, loopback_node, pool, pump, received, resolve_connect,
    settled,
};
use super::{tcp_dial, tcp_pair, with_path};
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2, PHASE_MSG3};
use crate::proto::link::LinkMessageType;
use crate::transport::{TransportHandle, TransportId};

// ---------------------------------------------------------------------------
// Copied private helpers
// ---------------------------------------------------------------------------

/// Where one end's link to the other sits, and which session it is on. A
/// copy of `control::LinkView`, which is private.
#[derive(Debug, Clone, PartialEq)]
struct LinkView {
    link_id: LinkId,
    transport_id: Option<TransportId>,
    current_addr: Option<TransportAddr>,
    our_index: Option<SessionIndex>,
}

/// Read `tn`'s view of its link to `peer`. A copy of `control::link_view`,
/// which is private.
fn link_view(tn: &TestNode, peer: &NodeAddr) -> LinkView {
    let p = tn
        .node
        .get_peer(peer)
        .expect("precondition: the node still holds the peer");
    LinkView {
        link_id: p.link_id(),
        transport_id: p.transport_id(),
        current_addr: p.current_addr().cloned(),
        our_index: p.our_index(),
    }
}

// ---------------------------------------------------------------------------
// Crossed TCP dials
// ---------------------------------------------------------------------------

/// Crossed TCP dials must leave one open connection at each end and a
/// session on which a heartbeat authenticates both ways.
async fn working_session(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, zero_smaller).await;
    let mut bad = Vec::new();
    if let Err(e) = heartbeat_reaches(&mut nodes, s, l).await {
        bad.push(format!("smaller to larger heartbeat: {e}"));
    }
    if let Err(e) = heartbeat_reaches(&mut nodes, l, s).await {
        bad.push(format!("larger to smaller heartbeat: {e}"));
    }
    let (si, so) = pool(&nodes[s]);
    let (li, lo) = pool(&nodes[l]);
    if si + so == 0 || li + lo == 0 {
        bad.push(format!(
            "a node holds no connection: smaller {:?} larger {:?}",
            (si, so),
            (li, lo)
        ));
    }
    assert!(
        bad.is_empty(),
        "defect: crossed TCP dials lost the peering: {bad:#?}"
    );
    assert_coherent(&mut nodes, "the end of crossed TCP dials").await;
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
#[ignore = "known difference on next: crossed TCP dials settled at the peer's msg3 at both ends leave each node both its connections open with one in use, which the audit flags as ConnectionsInUse"]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_smaller_first() {
    working_session(false, true).await;
}

#[tokio::test]
#[ignore = "known difference on next: crossed TCP dials settled at the peer's msg3 at both ends leave each node both its connections open with one in use, which the audit flags as ConnectionsInUse"]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_smaller_first_with_multipath_on()
 {
    working_session(true, true).await;
}

#[tokio::test]
#[ignore = "known difference on next: crossed TCP dials settled at the peer's msg3 at both ends leave each node both its connections open with one in use, which the audit flags as ConnectionsInUse"]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_larger_first() {
    working_session(false, false).await;
}

#[tokio::test]
#[ignore = "known difference on next: crossed TCP dials settled at the peer's msg3 at both ends leave each node both its connections open with one in use, which the audit flags as ConnectionsInUse"]
async fn crossed_tcp_dials_leave_a_working_session_on_one_connection_larger_first_with_multipath_on()
 {
    working_session(true, false).await;
}

/// After crossed TCP dials the smaller node's link record for the peer is
/// the link it dialed (direction `Outbound`) at the pair it holds the peer
/// at, and `addr_to_link` names that link there.
async fn smaller_on_its_dialed_link(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = crossed_tcp(on, zero_smaller).await;
    let l_addr = *nodes[l].node.node_addr();
    let mut bad = Vec::new();
    {
        let p = nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: the smaller node holds the larger");
        let tid = p
            .transport_id()
            .expect("precondition: the peer has a transport");
        let at = p
            .current_addr()
            .cloned()
            .expect("precondition: the peer has a current address");
        let link = nodes[s]
            .node
            .links
            .get(&p.link_id())
            .map(|k| (k.direction(), k.transport_id(), k.remote_addr().clone()));
        let want = Some((LinkDirection::Outbound, tid, at.clone()));
        if link != want {
            bad.push(format!(
                "the smaller node's link record is {link:?}, expected {want:?}"
            ));
        }
        let mapped = nodes[s].node.links.index().get(&(tid, at)).copied();
        if mapped != Some(p.link_id()) {
            bad.push(format!(
                "addr_to_link at the peer's pair is {mapped:?}, the peer's link {:?}",
                p.link_id()
            ));
        }
    }
    cleanup_nodes(&mut nodes).await;
    assert!(bad.is_empty(), "defect: {bad:#?}");
}

#[tokio::test]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first() {
    smaller_on_its_dialed_link(false, true).await;
}

#[tokio::test]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_smaller_first_with_multipath_on()
 {
    smaller_on_its_dialed_link(true, true).await;
}

#[tokio::test]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_larger_first() {
    smaller_on_its_dialed_link(false, false).await;
}

#[tokio::test]
async fn crossed_tcp_dials_leave_the_smaller_node_on_the_link_it_dialed_larger_first_with_multipath_on()
 {
    smaller_on_its_dialed_link(true, false).await;
}

/// Close the smaller node's connection to the larger and report whether a
/// send from the smaller node redials it and reaches the larger within
/// about 3 s.
async fn redial_after_drop(nodes: &mut [TestNode], s: usize, l: usize) -> Result<(), String> {
    let l_addr = *nodes[l].node.node_addr();
    let (tid, at) = {
        let p = nodes[s]
            .node
            .get_peer(&l_addr)
            .expect("precondition: the smaller node holds the larger");
        (
            p.transport_id()
                .expect("precondition: the peer has a transport"),
            p.current_addr()
                .cloned()
                .expect("precondition: the peer has a current address"),
        )
    };
    nodes[s]
        .node
        .transports
        .get(&tid)
        .expect("precondition: the peer's transport is held")
        .close_connection(&at)
        .await;
    // Let the larger node's receive task see the close.
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if pool(&nodes[l]) == (0, 0) {
            break;
        }
    }
    assert_eq!(
        pool(&nodes[s]),
        (0, 0),
        "precondition: the smaller node holds no connection after the close"
    );
    let before = received(nodes, l, s).map(|r| r.0).unwrap_or(0);
    for _ in 0..150 {
        let _ = nodes[s]
            .node
            .send_encrypted_link_message(&l_addr, &[LinkMessageType::Heartbeat.to_byte()])
            .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(nodes).await;
        if received(nodes, l, s).is_some_and(|r| r.0 > before) {
            return Ok(());
        }
    }
    Err(format!(
        "no frame from the smaller node reached the larger; pools smaller {:?} larger {:?}",
        pool(&nodes[s]),
        pool(&nodes[l])
    ))
}

/// The control for the redial pins: after a single TCP dial, a send from
/// the dialer redials a dropped connection.
async fn single_then_redial(on: bool, dialer_smaller: bool) {
    let mut nodes = tcp_pair(on, dialer_smaller).await;
    let (d, r) = (0, 1);
    tcp_dial(&mut nodes, d, r).await;
    resolve_connect(&mut nodes[d]).await;
    pump(&mut nodes).await;
    heartbeat_reaches(&mut nodes, d, r)
        .await
        .expect("precondition: frames authenticate dialer to responder");
    let redial = redial_after_drop(&mut nodes, d, r).await;
    cleanup_nodes(&mut nodes).await;
    assert!(redial.is_ok(), "defect: {redial:?}");
}

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_smaller_dialer() {
    single_then_redial(false, true).await;
}

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_smaller_dialer_with_multipath_on()
 {
    single_then_redial(true, true).await;
}

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_larger_dialer() {
    single_then_redial(false, false).await;
}

#[tokio::test]
async fn after_one_tcp_dial_a_send_from_the_dialer_redials_a_dropped_connection_larger_dialer_with_multipath_on()
 {
    single_then_redial(true, false).await;
}

// ---------------------------------------------------------------------------
// Crossed loopback dials won on another pair
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A dialer's second msg1, more than 1 s after its first
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A larger node's dial on a quiet peer's aged link
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// A crossed msg1 read past the heard floor
// ---------------------------------------------------------------------------

/// Longer than the 15 s heard floor, below which a heard peering is not
/// replaced.
const SILENCE: Duration = Duration::from_secs(16);

// ---------------------------------------------------------------------------
// A larger node's dial on an aged link after the smaller node's own rekey
// ---------------------------------------------------------------------------

/// The smaller node set the link up and, once the link is aged, rekeys it;
/// both ends cut over, so the smaller node's session is younger than the
/// rekey machine's session floor. What the larger node sends after the
/// cutover is lost, and the smaller node last heard it `quiet` ago. Then
/// the larger node dials the smaller node's second address. Whether the
/// two ends are left on one working session.
async fn aged_rekey(on: bool, quiet: Duration) -> Result<(), String> {
    let config = with_path(rekey_config(60), on);
    let mut nodes = vec![
        make_test_node_with_config(config.clone(), 1280).await,
        make_test_node_with_config(config, 1280).await,
    ];
    let zero_smaller = nodes[0].node.node_addr() < nodes[1].node.node_addr();
    let (d, p) = if zero_smaller { (1, 0) } else { (0, 1) };
    let d_addr = *nodes[d].node.node_addr();
    let p_addr = *nodes[p].node.node_addr();
    initiate_handshake(&mut nodes, p, d).await;
    drain_all_packets(&mut nodes, false).await;
    assert!(
        nodes[d].node.get_peer(&p_addr).is_some() && nodes[p].node.get_peer(&d_addr).is_some(),
        "precondition: the two nodes are peered"
    );
    age_link(&mut nodes, d, p, trigger_age());

    // The smaller node's own rekey, completed at both ends.
    rekey_to_pending(&mut nodes, p, d).await;
    cutover(&mut nodes[p], &d_addr).await;
    heartbeat(&mut nodes[p], &d_addr).await;
    deliver(&mut nodes[d]).await;
    {
        let at_p = nodes[p]
            .node
            .get_peer(&d_addr)
            .expect("precondition: the smaller node holds the larger");
        let at_d = nodes[d]
            .node
            .get_peer(&p_addr)
            .expect("precondition: the larger node holds the smaller");
        assert!(
            at_d.pending_new_session().is_none()
                && at_d.our_index() == at_p.their_index()
                && at_p.our_index() == at_d.their_index(),
            "precondition: both ends cut over to the rekeyed session"
        );
    }
    let rekeyed = link_view(&nodes[p], &d_addr).our_index;
    let _lost = std::iter::from_fn(|| nodes[p].packet_rx.try_recv().ok()).count();
    nodes[p]
        .node
        .get_peer_mut(&d_addr)
        .expect("precondition: the smaller node holds the larger")
        .test_backdate_heard(quiet);

    // The larger node dials the smaller node's second address.
    quieten(&mut nodes[d], &p_addr);
    let tid = nodes[p].transport_id;
    let alternate = alias(&nodes[p].addr, tid);
    let p_npub = nodes[p].node.npub();
    let data = nodes[d]
        .node
        .api_connect(&p_npub, &alternate.to_string(), "loopback")
        .await
        .expect("precondition: api_connect on an alternate path succeeds");
    assert_eq!(data["refreshed"], true, "precondition: the dial starts");
    deliver(&mut nodes[p]).await;
    if quiet >= SILENCE {
        assert_ne!(
            link_view(&nodes[p], &d_addr).our_index,
            rekeyed,
            "precondition: the smaller node took the dial as a replacement of its young session"
        );
    }
    deliver(&mut nodes[d]).await;
    drain_all_packets(&mut nodes, false).await;
    let out = settled(&mut nodes, d, p).await;
    cleanup_nodes(&mut nodes).await;
    out
}

/// The same dial with the larger node heard just now leaves one working
/// session: the assertion the pin makes can pass.
#[tokio::test]
async fn a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_inside_the_heard_floor_leaves_one_session()
 {
    let out = aged_rekey(false, Duration::ZERO).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

/// The same dial with the larger node heard just now leaves one working
/// session: the assertion the pin makes can pass.
#[tokio::test]
async fn a_larger_dialers_dial_on_the_aged_link_after_the_smaller_nodes_rekey_inside_the_heard_floor_leaves_one_session_with_multipath_on()
 {
    let out = aged_rekey(true, Duration::ZERO).await;
    assert!(out.is_ok(), "defect: {out:?}");
}

// ---------------------------------------------------------------------------
// A dial reaped while another dial at its pair is in flight
// ---------------------------------------------------------------------------

/// Two dials from node 0 to node 1's one address, neither answered, so no
/// peer is held: the first dial's link is returned, with the second's link
/// still at the same pair.
async fn two_dials(nodes: &mut [TestNode]) -> LinkId {
    initiate_handshake(nodes, 0, 1).await;
    let first: Vec<LinkId> = nodes[0].node.links.keys().copied().collect();
    assert_eq!(first.len(), 1, "precondition: the first dial has one link");
    initiate_handshake(nodes, 0, 1).await;
    assert_eq!(
        nodes[0].node.links.len(),
        2,
        "precondition: two dials in flight at one pair"
    );
    assert!(
        nodes[0].node.peers.is_empty(),
        "precondition: no peer is held, so no peer's path keeps the connection"
    );
    first[0]
}

/// Reap the dial whose link is `first` at node 0, as its handshake timeout
/// does.
async fn reap(nodes: &mut [TestNode], first: LinkId) {
    nodes[0].node.cleanup_stale_connection(first, 0).await;
    assert!(
        !nodes[0].node.links.contains_key(&first),
        "precondition: the first dial is reaped"
    );
}

/// On loopback, which records each close: reaping one of two dials at one
/// pair does not close the connection the other dial is running on.
async fn reaped_dial(on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let t1 = nodes[0].transport_id;
    let b1 = nodes[1].addr.clone();
    let first = two_dials(&mut nodes).await;
    reap(&mut nodes, first).await;
    let closed = match nodes[0].node.transports.get(&t1) {
        Some(TransportHandle::Loopback(t)) => t.closed(),
        _ => panic!("precondition: node 0's transport is loopback"),
    };
    cleanup_nodes(&mut nodes).await;
    assert!(
        !closed.contains(&b1),
        "defect: reaping a dial closed the connection another dial in flight uses: {closed:?}"
    );
}

/// [`reaped_dial`] with multipath off.
#[tokio::test]
async fn a_reaped_dial_leaves_a_connection_another_dial_in_flight_uses() {
    reaped_dial(false).await;
}

/// [`reaped_dial`] with multipath on.
#[tokio::test]
async fn a_reaped_dial_leaves_a_connection_another_dial_in_flight_uses_with_multipath_on() {
    reaped_dial(true).await;
}

/// On the BLE mock, whose pool holds one channel per address and closes it
/// when asked: reaping one of two dials on a channel leaves the channel
/// pooled for the other. Read with the pool's lock awaited, so a lock held
/// by the transport's own tasks cannot pass for a closed channel.
#[cfg(ble_available)]
async fn ble_reaped(on: bool) {
    use super::super::ble::{base_config, larger_second, link_genuinely, make_test_node_ble_from};
    let config = with_path(Config::new(), on);
    let mut nodes = vec![
        make_test_node_ble_from(1, base_config(), config.clone()).await,
        make_test_node_ble_from(2, base_config(), config).await,
    ];
    larger_second(&mut nodes);
    let _bank = link_genuinely(&nodes).await;
    let tid = nodes[0].transport_id;
    let b = nodes[1].addr.clone();
    let pooled = async |nodes: &[TestNode]| match nodes[0].node.transports.get(&tid) {
        Some(TransportHandle::Ble(t)) => t.is_verified(&b).await.is_some(),
        _ => panic!("precondition: node 0's transport is BLE"),
    };
    assert!(pooled(&nodes).await, "precondition: the BLE channel is up");
    let first = two_dials(&mut nodes).await;
    reap(&mut nodes, first).await;
    let kept = pooled(&nodes).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        kept,
        "defect: reaping a dial closed the BLE channel another dial in flight uses"
    );
}

/// [`ble_reaped`] with multipath off.
#[cfg(ble_available)]
#[tokio::test]
async fn a_reaped_ble_dial_leaves_the_channel_another_dial_in_flight_uses() {
    ble_reaped(false).await;
}

/// [`ble_reaped`] with multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn a_reaped_ble_dial_leaves_the_channel_another_dial_in_flight_uses_with_multipath_on() {
    ble_reaped(true).await;
}

// ---------------------------------------------------------------------------
// The move holds the dialed link
// ---------------------------------------------------------------------------

/// Two loopback nodes peered by node 0's dial, delivered until idle. Node
/// 0 is the smaller, so its later dial is the one that moves at its msg2:
/// on this line the larger node's dial is kept, and a larger node moves
/// only at the peer's msg3, where it keeps the link it was held on.
async fn dialed_pair(on: bool) -> Vec<TestNode> {
    let mut nodes = loop {
        let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
        if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
            break nodes;
        }
        cleanup_nodes(&mut nodes).await;
    };
    initiate_handshake(&mut nodes, 0, 1).await;
    pump(&mut nodes).await;
    let b = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "precondition: node 0 holds node 1"
    );
    nodes
}

/// Node 0's later dial to node 1 at `dialed`, which node 1 answers as on
/// an aged link, its msg2 reaching node 0 from `answered`.
async fn answered_from(nodes: &mut [TestNode], dialed: TransportAddr, answered: &TransportAddr) {
    dial_at(nodes, 0, 1, dialed).await;
    let a = *nodes[0].node.node_addr();
    let held = nodes[1]
        .node
        .get_peer_mut(&a)
        .expect("precondition: node 1 holds node 0");
    held.test_backdate_heard(Duration::from_secs(60));
    held.test_backdate_session_established(Duration::from_secs(600));
    let msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: the dial's msg1 is queued at node 1");
    nodes[1].node.handle_msg1(msg1).await;
    let mut msg2 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("precondition: node 1's msg2 is queued at node 0");
    msg2.remote_addr = answered.clone();
    nodes[0].node.handle_msg2(msg2).await;
}

/// A dial answered from another address than the one dialed: the dialer
/// holds the dial's link, `Outbound` and set up at the address it dialed,
/// which a redial needs (FRC-1201, Section 5.7, rule 4.1), and the peer at
/// the msg2's pair, a path of the link's bundle (Section 5.6). The index
/// names the link at both, and the pair of the link it left at neither.
async fn adopted_address(on: bool) {
    let mut nodes = dialed_pair(on).await;
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    let home = nodes[1].addr.clone();
    let dialed = alias(&home, t1);
    let answered = alias(&home, t1);
    let left = nodes[0]
        .node
        .get_peer(&b)
        .map(|p| p.link_id())
        .expect("precondition: node 0 holds node 1");
    answered_from(&mut nodes, dialed.clone(), &answered).await;
    let node = &nodes[0].node;
    let peer = node
        .get_peer(&b)
        .expect("precondition: the move keeps the peer");
    let held = peer.link_id();
    let record = node
        .links
        .get(&held)
        .map(|k| (k.direction(), k.transport_id(), k.remote_addr().clone()));
    let at = (peer.transport_id(), peer.current_addr().cloned());
    let named = |addr: &TransportAddr| node.links.index().get(&(t1, addr.clone())).copied();
    let index = (named(&dialed), named(&answered), named(&home));
    cleanup_nodes(&mut nodes).await;
    assert_ne!(
        held, left,
        "defect: node 0 holds node 1 on the link it left, not the dial's"
    );
    assert_eq!(
        record,
        Some((LinkDirection::Outbound, t1, dialed)),
        "defect: the moved link's record is not the dial's, at the address dialed"
    );
    assert_eq!(
        at,
        (Some(t1), Some(answered)),
        "defect: the peer is not held at the msg2's pair"
    );
    assert_eq!(
        index,
        (Some(held), Some(held), None),
        "defect: the index does not name the dial's link at the address dialed and at the msg2's pair alone"
    );
}

#[tokio::test]
async fn a_moved_links_address_is_the_one_dialed_and_the_msg2s_pair_is_its_path() {
    adopted_address(false).await;
}

/// [`a_moved_links_address_is_the_one_dialed_and_the_msg2s_pair_is_its_path`] with multipath on.
#[tokio::test]
async fn a_moved_links_address_is_the_one_dialed_and_the_msg2s_pair_is_its_path_with_multipath_on()
{
    adopted_address(true).await;
}

/// The peer's control machine and its timers move with the peer onto the
/// dial's link, so the machine controls the link the peer is on, and a
/// link-dead, which finds the machine by the peer's link, reaches it and
/// removes the peer with its machine.
async fn machine_moves(on: bool) {
    use crate::peer::machine::TimerKind;
    use crate::proto::settle::output::Why;

    let mut nodes = dialed_pair(on).await;
    let b = *nodes[1].node.node_addr();
    let left = nodes[0]
        .node
        .get_peer(&b)
        .map(|p| p.link_id())
        .expect("precondition: node 0 holds node 1");
    nodes[0]
        .node
        .peer_machines
        .arm(left, TimerKind::Liveness, u64::MAX / 2);
    own_dial(&mut nodes).await;
    let node = &nodes[0].node;
    let held = node
        .get_peer(&b)
        .map(|p| p.link_id())
        .expect("precondition: the move keeps the peer");
    let machine = node.peer_machines.get(&held).map(|m| m.link_id());
    let timer = node
        .peer_machines
        .timers()
        .get(&held)
        .is_some_and(|t| t.contains_key(&TimerKind::Liveness));
    let behind =
        node.peer_machines.contains_key(&left) || node.peer_machines.timers().contains_key(&left);
    nodes[0]
        .node
        .route_link_dead(b, Node::now_ms(), Why::Dead)
        .await;
    let node = &nodes[0].node;
    let after = (
        node.get_peer(&b).is_some(),
        node.peer_machines.contains_key(&held),
    );
    cleanup_nodes(&mut nodes).await;
    assert_ne!(
        held, left,
        "precondition: node 0 moved onto the dial's link"
    );
    assert_eq!(
        machine,
        Some(held),
        "defect: no machine controls the link the peer is on"
    );
    assert!(timer, "defect: the machine's timers did not move with it");
    assert!(
        !behind,
        "defect: a machine or its timers stay under the link left"
    );
    assert_eq!(
        after,
        (false, false),
        "defect: a link-dead did not reach the moved peer's machine"
    );
}

#[tokio::test]
async fn a_moved_peers_control_machine_moves_with_it() {
    machine_moves(false).await;
}

/// [`a_moved_peers_control_machine_moves_with_it`] with multipath on.
#[tokio::test]
async fn a_moved_peers_control_machine_moves_with_it_with_multipath_on() {
    machine_moves(true).await;
}

// ---------------------------------------------------------------------------
// A TCP crossing with one msg1 inside the other's connect window
// ---------------------------------------------------------------------------

// The master line's test of this case is not run here. It rests on the
// smaller node installing the larger as responder at the larger's msg1 and
// the restart gates then refusing the smaller node's msg1, so that neither
// end moves. On this line a responder installs only at the msg3, and a msg1
// from a held peer is answered and settled as a crossing at the dial's msg2
// or the peer's msg3, so the state it checks is not reached.

// ---------------------------------------------------------------------------
// The close rule on a link of two paths
// ---------------------------------------------------------------------------

/// The closes `tn` asked of its loopback transport `id`, in order.
fn closes(tn: &TestNode, id: TransportId) -> Vec<TransportAddr> {
    match tn.node.transports.get(&id) {
        Some(TransportHandle::Loopback(t)) => t.closed(),
        _ => panic!("precondition: transport {id} is a loopback transport"),
    }
}

/// Link `nodes[0]` to a third loopback node, pushed onto `nodes`, by its
/// own dial, and give that node's link at `nodes[0]` a second path at
/// (`tid`, `at`), proven by the third node's frames: a link of two paths,
/// the second at a pair another node answers at. The offer finds the third
/// node not yet known capable, so node 0 asks it first, and probes `at` on
/// its answer. Loopback delivers what is sent to `at` to the node that owns
/// it, `nodes[1]`, so the test hands the probe from there to the third node
/// and its answer to node 0 as though it came from `at`, as a host behind
/// one shared address would see them.
async fn second_path(nodes: &mut Vec<TestNode>, tid: TransportId, at: &TransportAddr) {
    use super::super::paths::deliver_from;

    nodes.push(loopback_node(true).await);
    let c = nodes.len() - 1;
    initiate_handshake(nodes, 0, c).await;
    pump(nodes).await;
    let c_addr = *nodes[c].node.node_addr();
    nodes[0].node.offer_path(&c_addr, tid, at.clone()).await;
    deliver(&mut nodes[c]).await;
    deliver(&mut nodes[0]).await;
    let mut probes = 0;
    while let Ok(probe) = nodes[1].packet_rx.try_recv() {
        probes += 1;
        nodes[c].node.handle_encrypted_frame(probe).await;
    }
    deliver_from(&mut nodes[0], at).await;
    let peer = nodes[0]
        .node
        .get_peer(&c_addr)
        .expect("precondition: node 0 holds the third node");
    assert!(probes > 0, "precondition: node 0 probed {at}");
    assert!(
        !peer.past_feed(),
        "precondition: no test mutator touched the third node's bundle"
    );
    assert!(
        matches!(peer.path_match(tid, at), crate::peer::Match::Proven { .. }),
        "precondition: the third node's link holds a proven second path at {at}"
    );
}

/// A crossing that moves node 0 off the link it held node 1 on retires that
/// link, and the close rule decides the connection at the link's setup pair.
/// Node 0's dial is answered from a third address of node 1's, so the moved
/// link holds no path at the pair it left; a second path of a third node's
/// link holds it, so the connection stays open.
#[tokio::test]
async fn a_crossing_retires_a_link_at_a_pair_another_links_second_path_holds_with_multipath_on() {
    let mut nodes = dialed_pair(true).await;
    let b = *nodes[1].node.node_addr();
    let t1 = nodes[0].transport_id;
    let home = nodes[1].addr.clone();
    second_path(&mut nodes, t1, &home).await;
    let left = nodes[0]
        .node
        .get_peer(&b)
        .map(|p| p.link_id())
        .expect("precondition: node 0 holds node 1");
    let dialed = alias(&home, t1);
    let answered = alias(&home, t1);
    answered_from(&mut nodes, dialed, &answered).await;
    let node = &nodes[0].node;
    let held = node
        .get_peer(&b)
        .map(|p| p.link_id())
        .expect("precondition: the move keeps the peer");
    let retired = !node.links.contains_key(&left);
    let at_home = node.get_peer(&b).map(|p| p.path_match(t1, &home));
    let closed = closes(&nodes[0], t1);
    cleanup_nodes(&mut nodes).await;
    assert_ne!(
        held, left,
        "precondition: node 0 moved onto the dial's link"
    );
    assert!(retired, "precondition: the link node 0 left is retired");
    assert_eq!(
        at_home,
        Some(crate::peer::Match::None),
        "precondition: the moved link holds no path at the pair it left"
    );
    assert!(
        !closed.contains(&home),
        "defect: retiring the link closed the connection another link's second path holds: {closed:?}"
    );
}

/// A capable link of two paths, p on t1 and q on t2, with the peer active on
/// q: p is killed, left unanswered and discarded past its grace, so the
/// bundle releases it
/// while the link lives, and the close rule decides p's connection. A second
/// path of a third node's link holds p's pair, so the connection stays open,
/// where with nothing else on it it closes
/// (`paths::a_capable_links_original_connection_closes_when_its_path_is_discarded`).
#[tokio::test]
async fn a_released_path_at_a_pair_another_links_path_holds_stays_open_with_multipath_on() {
    use super::super::paths::{beat, loopback_mut, state_at, t2, two_transports};
    use fips_core::proto::path::{Input, PathRef};

    let (mut nodes, b, a2, _b2) = two_transports(1280).await;
    let t1 = TransportId::new(1);
    let p = nodes[1].addr.clone();
    second_path(&mut nodes, t1, &p).await;
    loopback_mut(&mut nodes[0], t1).typed(crate::transport::TransportType::TCP);
    let on_q = PathRef {
        transport: t2(),
        addr: a2,
    };
    beat(&mut nodes, Some(&on_q)).await;
    nodes[0]
        .node
        .get_peer_mut(&b)
        .expect("precondition: node 0 holds node 1")
        .kill_path(t1, &p);
    nodes[0].node.step_path(&b, Input::Poll).await;
    // Nothing node 0 sends towards node 1 now is answered, so p stays dead
    // through its grace, as a path whose pair has gone does.
    while nodes[1].packet_rx.try_recv().is_ok() {}
    crate::time::advance(Duration::from_secs(601));
    nodes[0].node.step_path(&b, Input::Poll).await;
    let released = state_at(&nodes[0], &b, t1, &p).is_none();
    let kept = nodes[0].node.get_peer(&b).is_some();
    let closed = closes(&nodes[0], t1);
    cleanup_nodes(&mut nodes).await;
    assert!(released, "precondition: p is discarded");
    assert!(kept, "precondition: the link lives on q");
    assert!(
        !closed.contains(&p),
        "defect: releasing p closed the connection another link's path holds: {closed:?}"
    );
}

// ---------------------------------------------------------------------------
// The close rule on a roamed link
// ---------------------------------------------------------------------------

/// Two loopback nodes, with the indices of the dialer and the responder,
/// the dialer's address the larger when `dialer_larger`.
async fn ordered_pair(on: bool, dialer_larger: bool) -> (Vec<TestNode>, usize, usize) {
    let nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let zero_larger = nodes[0].node.node_addr() > nodes[1].node.node_addr();
    if zero_larger == dialer_larger {
        (nodes, 0, 1)
    } else {
        (nodes, 1, 0)
    }
}

/// Two loopback nodes, the smaller dialing the larger, so the larger holds
/// the smaller on an inbound link; the larger's transport is then typed TCP,
/// to stand in for one whose connections a close takes. A frame of the
/// smaller node's reaches the larger from a second address of the
/// smaller's: the link's one path roams there, a roam at multipath off and
/// a path `Moved` on. The larger then dials the smaller at that address, and
/// the smaller answers as on an aged link. The larger, whose peer's own dial
/// wins the tie-break, keeps its session and tears its dial down, and the
/// close rule finds the roamed path at the dial's pair, so the connection
/// the peer now runs on stays open.
async fn roamed_through(on: bool) {
    let (mut nodes, s, l) = ordered_pair(on, false).await;
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    initiate_handshake(&mut nodes, s, l).await;
    pump(&mut nodes).await;
    let link = nodes[l]
        .node
        .get_peer(&s_addr)
        .map(|p| p.link_id())
        .expect("precondition: the larger node holds the smaller");
    assert_eq!(
        nodes[l].node.links.get(&link).map(|k| k.direction()),
        Some(LinkDirection::Inbound),
        "precondition: the larger node holds the smaller on the link the smaller dialed"
    );
    let session = nodes[l].node.get_peer(&s_addr).and_then(|p| p.our_index());
    let tid = nodes[l].transport_id;
    match nodes[l].node.transports.get_mut(&tid) {
        Some(TransportHandle::Loopback(t)) => t.typed(crate::transport::TransportType::TCP),
        _ => panic!("precondition: the larger node's transport is loopback"),
    }

    let roamed = alias(&nodes[s].addr, tid);
    heartbeat(&mut nodes[s], &l_addr).await;
    super::super::paths::deliver_from(&mut nodes[l], &roamed).await;
    let active = nodes[l]
        .node
        .get_peer(&s_addr)
        .and_then(|p| p.active_path())
        .map(|p| (p.transport_id(), p.addr().clone()));
    assert_eq!(
        active,
        Some((tid, roamed.clone())),
        "precondition: the frame roamed the link's one path"
    );

    dial_at(&mut nodes, l, s, roamed.clone()).await;
    let held = nodes[s]
        .node
        .get_peer_mut(&l_addr)
        .expect("precondition: the smaller node holds the larger");
    held.test_backdate_heard(Duration::from_secs(60));
    held.test_backdate_session_established(Duration::from_secs(600));
    assert_eq!(
        deliver(&mut nodes[s]).await,
        1,
        "precondition: the larger node's msg1 reaches the smaller"
    );
    assert_eq!(
        deliver(&mut nodes[l]).await,
        1,
        "precondition: the smaller node's msg2 reaches the larger"
    );
    let kept = nodes[l].node.get_peer(&s_addr).and_then(|p| p.our_index());
    let dials = nodes[l].node.pending_outbound.len();
    let closed = closes(&nodes[l], tid);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        (kept, dials),
        (session, 0),
        "precondition: the larger node kept its session and its dial is answered"
    );
    assert!(
        !closed.contains(&roamed),
        "defect: tearing the dial down closed the connection the roamed peer's path runs on: {closed:?}"
    );
}

#[tokio::test]
async fn a_tcp_peer_that_roamed_keeps_its_connection_through_a_crossing() {
    roamed_through(false).await;
}

/// [`a_tcp_peer_that_roamed_keeps_its_connection_through_a_crossing`] with multipath on.
#[tokio::test]
async fn a_tcp_peer_that_roamed_keeps_its_connection_through_a_crossing_with_multipath_on() {
    roamed_through(true).await;
}

// ---------------------------------------------------------------------------
// What a move closes of the link it left
// ---------------------------------------------------------------------------

/// Packets reaching `tn` over TCP, taken as they arrive until `enough` holds
/// of those taken. The limit counts polls 10 ms apart, so a loaded host only
/// makes the wait longer, and it fails as a precondition.
async fn arrived(
    tn: &mut TestNode,
    enough: impl Fn(&[ReceivedPacket]) -> bool,
) -> Vec<ReceivedPacket> {
    let mut got = Vec::new();
    for _ in 0..1000 {
        while let Ok(packet) = tn.packet_rx.try_recv() {
            got.push(packet);
        }
        if enough(&got) {
            return got;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let phases: Vec<Option<u8>> = got.iter().map(phase).collect();
    panic!("precondition: the packets reached the node within 1000 polls: {phases:?}");
}

/// Whether `packets` hold one of handshake phase `want`.
fn holds(packets: &[ReceivedPacket], want: u8) -> bool {
    packets.iter().any(|p| phase(p) == Some(want))
}

/// The first packet of handshake phase `want` in `packets`, taken out.
fn take_phase(packets: &mut Vec<ReceivedPacket>, want: u8) -> ReceivedPacket {
    let at = packets
        .iter()
        .position(|p| phase(p) == Some(want))
        .expect("precondition: a packet of the phase arrived");
    packets.remove(at)
}

/// Crossed TCP dials on this line's three-message handshake, settled so
/// that the smaller node reads the msg2 answering its own dial while it
/// holds the larger on the inbound link: each node reads the other's msg1
/// and answers it, the larger reads the msg2 answering its dial and
/// promotes the smaller as initiator, and the smaller reads that msg3,
/// promoting the larger on the inbound link, and then the msg2 answering
/// its own dial, which moves it onto that dial's link and retires the
/// inbound one. No dial is on the inbound link's connection, so the move
/// closes it. The larger node then reads the smaller's msg3, which settles
/// the crossing at its end at the peer's msg3. Returns the nodes, the
/// smaller node's index and the larger's, with each step asserted.
async fn moved_at_msg2_over_tcp(on: bool, zero_smaller: bool) -> (Vec<TestNode>, usize, usize) {
    let mut nodes = tcp_pair(on, zero_smaller).await;
    let (s, l) = if zero_smaller { (0, 1) } else { (1, 0) };
    let s_addr = *nodes[s].node.node_addr();
    let l_addr = *nodes[l].node.node_addr();
    tcp_dial(&mut nodes, 0, 1).await;
    tcp_dial(&mut nodes, 1, 0).await;
    resolve_connect(&mut nodes[0]).await;
    resolve_connect(&mut nodes[1]).await;
    let s_dial: Vec<u32> = nodes[s].node.pending_outbound.keys().map(|k| k.1).collect();
    assert_eq!(
        s_dial.len(),
        1,
        "precondition: the smaller node's dial is pending"
    );
    assert_eq!(
        nodes[l].node.pending_outbound.len(),
        1,
        "precondition: the larger node's dial is pending"
    );

    let mut at_l = arrived(&mut nodes[l], |got| holds(got, PHASE_MSG1)).await;
    let msg1 = take_phase(&mut at_l, PHASE_MSG1);
    hand(&mut nodes[l].node, msg1).await;
    let mut at_s = arrived(&mut nodes[s], |got| {
        holds(got, PHASE_MSG1) && holds(got, PHASE_MSG2)
    })
    .await;
    let msg1 = take_phase(&mut at_s, PHASE_MSG1);
    let own_msg2 = take_phase(&mut at_s, PHASE_MSG2);
    hand(&mut nodes[s].node, msg1).await;

    let mut more = arrived(&mut nodes[l], |got| holds(got, PHASE_MSG2)).await;
    at_l.append(&mut more);
    let msg2 = take_phase(&mut at_l, PHASE_MSG2);
    hand(&mut nodes[l].node, msg2).await;
    assert!(
        nodes[l].node.get_peer(&s_addr).is_some(),
        "precondition: the larger node holds the smaller at its own dial's msg2"
    );

    let mut more = arrived(&mut nodes[s], |got| holds(got, PHASE_MSG3)).await;
    at_s.append(&mut more);
    let msg3 = take_phase(&mut at_s, PHASE_MSG3);
    hand(&mut nodes[s].node, msg3).await;
    let inbound = nodes[s]
        .node
        .get_peer(&l_addr)
        .and_then(|p| nodes[s].node.links.get(&p.link_id()))
        .map(|k| k.direction());
    assert_eq!(
        inbound,
        Some(LinkDirection::Inbound),
        "precondition: the smaller node holds the larger on the inbound link at its msg3"
    );
    hand(&mut nodes[s].node, own_msg2).await;
    assert_eq!(
        nodes[s].node.get_peer(&l_addr).and_then(|p| p.our_index()),
        Some(SessionIndex::new(s_dial[0])),
        "precondition: the smaller node moved onto its own dial's session"
    );
    for packet in at_s {
        hand(&mut nodes[s].node, packet).await;
    }

    let mut more = arrived(&mut nodes[l], |got| holds(got, PHASE_MSG3)).await;
    at_l.append(&mut more);
    let msg3 = take_phase(&mut at_l, PHASE_MSG3);
    hand(&mut nodes[l].node, msg3).await;
    for packet in at_l {
        hand(&mut nodes[l].node, packet).await;
    }
    (nodes, s, l)
}

/// [`moved_at_msg2_over_tcp`]'s move leaves the smaller node holding its
/// dial's connection alone: the inbound link's connection, which no dial
/// is on, is closed.
async fn left_closed(on: bool, zero_smaller: bool) {
    let (mut nodes, s, _l) = moved_at_msg2_over_tcp(on, zero_smaller).await;
    for _ in 0..100 {
        if pool(&nodes[s]) == (0, 1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let s_pool = pool(&nodes[s]);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        s_pool,
        (0, 1),
        "defect: the smaller node holds a connection besides its dial's, or lost that one"
    );
}

#[tokio::test]
async fn a_move_closes_the_left_links_connection_with_no_dial_on_it_smaller_first() {
    left_closed(false, true).await;
}

/// [`a_move_closes_the_left_links_connection_with_no_dial_on_it_smaller_first`] with multipath on.
#[tokio::test]
async fn a_move_closes_the_left_links_connection_with_no_dial_on_it_smaller_first_with_multipath_on()
 {
    left_closed(true, true).await;
}

#[tokio::test]
async fn a_move_closes_the_left_links_connection_with_no_dial_on_it_larger_first() {
    left_closed(false, false).await;
}

/// [`a_move_closes_the_left_links_connection_with_no_dial_on_it_larger_first`] with multipath on.
#[tokio::test]
async fn a_move_closes_the_left_links_connection_with_no_dial_on_it_larger_first_with_multipath_on()
{
    left_closed(true, false).await;
}

/// After [`moved_at_msg2_over_tcp`], the larger node, which settled the
/// crossing at the peer's msg3, holds the smaller on a link with an open
/// connection. On this line it does not: it moved onto the smaller node's
/// dial's session but stays held on the link it dialed, and the connection
/// of that link is the one the smaller node's move closed.
async fn larger_record_open(on: bool, zero_smaller: bool) {
    let (mut nodes, s, l) = moved_at_msg2_over_tcp(on, zero_smaller).await;
    let s_addr = *nodes[s].node.node_addr();
    for _ in 0..100 {
        if pool(&nodes[s]) == (0, 1) && pool(&nodes[l]).1 == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let record = nodes[l]
        .node
        .get_peer(&s_addr)
        .and_then(|p| nodes[l].node.links.get(&p.link_id()))
        .map(|k| k.direction());
    let l_pool = pool(&nodes[l]);
    cleanup_nodes(&mut nodes).await;
    let open = match record {
        Some(LinkDirection::Inbound) => l_pool.0 >= 1,
        Some(LinkDirection::Outbound) => l_pool.1 >= 1,
        None => panic!("precondition: the larger node holds the smaller"),
    };
    assert!(
        open,
        "defect: the larger node holds the smaller on its {record:?} link, whose connection the smaller node's move closed: pool {l_pool:?}"
    );
}

#[tokio::test]
#[ignore = "known defect on next: a crossing the larger node settles at the peer's msg3 leaves it held on the link it dialed, whose connection the smaller node's move at its msg2 closes"]
async fn a_crossing_settled_at_the_larger_nodes_msg3_leaves_it_on_a_link_with_an_open_connection_smaller_first()
 {
    larger_record_open(false, true).await;
}

#[tokio::test]
#[ignore = "known defect on next: a crossing the larger node settles at the peer's msg3 leaves it held on the link it dialed, whose connection the smaller node's move at its msg2 closes"]
async fn a_crossing_settled_at_the_larger_nodes_msg3_leaves_it_on_a_link_with_an_open_connection_smaller_first_with_multipath_on()
 {
    larger_record_open(true, true).await;
}

#[tokio::test]
#[ignore = "known defect on next: a crossing the larger node settles at the peer's msg3 leaves it held on the link it dialed, whose connection the smaller node's move at its msg2 closes"]
async fn a_crossing_settled_at_the_larger_nodes_msg3_leaves_it_on_a_link_with_an_open_connection_larger_first()
 {
    larger_record_open(false, false).await;
}

#[tokio::test]
#[ignore = "known defect on next: a crossing the larger node settles at the peer's msg3 leaves it held on the link it dialed, whose connection the smaller node's move at its msg2 closes"]
async fn a_crossing_settled_at_the_larger_nodes_msg3_leaves_it_on_a_link_with_an_open_connection_larger_first_with_multipath_on()
 {
    larger_record_open(true, false).await;
}

/// Node 0, holding node 1 on the link it dialed, dials node 1 again at a
/// second address and once more at the held link's own pair, and neither
/// msg1 is read yet. Node 1 answers the first as on an aged link, its msg2
/// reaching node 0 from a third address, and node 0 moves onto that dial and
/// retires the link it left. The second dial is still in flight on the left
/// link's pair, so the close rule leaves that connection open.
async fn flying_dial(on: bool) {
    let mut nodes = dialed_pair(on).await;
    let b = *nodes[1].node.node_addr();
    let a = *nodes[0].node.node_addr();
    let t1 = nodes[0].transport_id;
    let home = nodes[1].addr.clone();
    let dialed = alias(&home, t1);
    let answered = alias(&home, t1);
    let left = nodes[0]
        .node
        .get_peer(&b)
        .map(|p| p.link_id())
        .expect("precondition: node 0 holds node 1");
    dial_at(&mut nodes, 0, 1, dialed).await;
    let msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: the first dial's msg1 is queued at node 1");
    let before: Vec<LinkId> = nodes[0].node.links.keys().copied().collect();
    initiate_handshake(&mut nodes, 0, 1).await;
    let second = nodes[0]
        .node
        .links
        .keys()
        .copied()
        .find(|id| !before.contains(id))
        .expect("precondition: the second dial has a link");
    while nodes[1].packet_rx.try_recv().is_ok() {}
    let held = nodes[1]
        .node
        .get_peer_mut(&a)
        .expect("precondition: node 1 holds node 0");
    held.test_backdate_heard(Duration::from_secs(60));
    held.test_backdate_session_established(Duration::from_secs(600));
    nodes[1].node.handle_msg1(msg1).await;
    let mut msg2 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("precondition: node 1's msg2 is queued at node 0");
    msg2.remote_addr = answered;
    nodes[0].node.handle_msg2(msg2).await;
    let node = &nodes[0].node;
    let moved = node.get_peer(&b).map(|p| p.link_id());
    let retired = !node.links.contains_key(&left);
    let flying = node.links.get(&second).map(|k| k.remote_addr().clone());
    let closed = closes(&nodes[0], t1);
    cleanup_nodes(&mut nodes).await;
    assert!(
        moved.is_some_and(|id| id != left) && retired,
        "precondition: node 0 moved off the link it held and retired it"
    );
    assert_eq!(
        flying,
        Some(home.clone()),
        "precondition: the second dial is in flight at the left link's pair"
    );
    assert!(
        !closed.contains(&home),
        "defect: the move closed the connection a dial in flight uses: {closed:?}"
    );
}

#[tokio::test]
async fn a_move_leaves_a_connection_a_dial_in_flight_uses() {
    flying_dial(false).await;
}

/// [`a_move_leaves_a_connection_a_dial_in_flight_uses`] with multipath on.
#[tokio::test]
async fn a_move_leaves_a_connection_a_dial_in_flight_uses_with_multipath_on() {
    flying_dial(true).await;
}
