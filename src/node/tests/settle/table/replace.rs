//! Cells at replacement: the held peer torn down and a new one installed, by
//! a msg3 at a new epoch or by this node's own dial answered by a restarted
//! peer, each test a plain one and its `_with_multipath_on` sibling. A
//! same-epoch handshake never replaces a held peer on this line, so that
//! cause has no test.
//!
//! The peer's state is dirtied through [`dirty`] before the site, so a row
//! the replacement keeps is held to a value it could have changed, and each
//! test reads the node at the site alone, before any frame of the new
//! peering: for a restart the responder's msg1 and the initiator's msg2 run
//! before the first reading, and the msg3 is the site. The restart siblings
//! run on a capable link of two paths (`two_transports`), where the replaced
//! peer's unkept path is queued to close; the plain tests run where no link
//! is capable and every link keeps.

use super::super::super::paths::{loopback, t2, two_transports};
use super::super::super::spanning_tree::{
    TestNode, cleanup_nodes, initiate_handshake, restarted_node,
};
use super::super::super::*;
use super::super::with_path;
use super::promote::queued_in;
use super::{Outcome, Seen, assert_cells, dirty, peered};
use crate::node::settle::table::{Row, Transition};
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2, PHASE_MSG3};
use crate::proto::settle::output::Why;
use fips_core::proto::path::PathRef;

/// Two nodes with multipath set as `on`, node 0 having dialled node 1 and
/// each holding the other, with the pairs node 0 holds node 1 at; with
/// multipath on node 0 holds two Live paths to node 1 on a capable link.
async fn pair(on: bool) -> (Vec<TestNode>, Vec<PathRef>) {
    if on {
        let (nodes, _, _, b2) = two_transports(1280).await;
        let pairs = vec![
            PathRef {
                transport: nodes[0].transport_id,
                addr: nodes[1].addr.clone(),
            },
            PathRef {
                transport: t2(),
                addr: b2,
            },
        ];
        (nodes, pairs)
    } else {
        let nodes = peered(false).await;
        let pairs = vec![PathRef {
            transport: nodes[0].transport_id,
            addr: nodes[1].addr.clone(),
        }];
        (nodes, pairs)
    }
}

/// Give the dial [`dirty`] notes a link record of its own, as a real dial
/// holds. [`dirty`] notes it at the peer's own link, which a replacement
/// closes, after which the dial names no link and the node's live audit
/// refuses it (`dial-link`).
pub(super) fn dial_of_its_own(node: &mut Node, peer: &NodeAddr) {
    let spare = super::spare(node, peer);
    let key = (spare.transport, 0x0dd_d1a1);
    assert!(
        node.pending_outbound.contains_key(&key),
        "precondition: dirty noted its dial"
    );
    node.pending_outbound.forget(&key);
    let id = node.allocate_link_id();
    node.links.open(
        node.core.parts_mut().0,
        crate::transport::Link::new(
            id,
            spare.transport,
            TransportAddr::from_string("spare:3"),
            crate::transport::LinkDirection::Outbound,
            Duration::from_millis(50),
        ),
    );
    node.pending_outbound.note(key, id);
}

/// Leave the rows [`dirty`] toggles from the peering's current state unlike
/// a new record's, so that a new record shows as a change: a new record marks
/// its filter to be sent, and once the peering has carried frames [`dirty`]'s
/// toggle can land on either. The pair
/// [`dirty`] admits a path at is added to `pairs`, since the replaced bundle
/// leaves it.
pub(super) fn unlike_new(node: &mut Node, peer: &NodeAddr, pairs: &mut Vec<PathRef>) {
    let spare = super::spare(node, peer);
    let p = node
        .get_peer_mut(peer)
        .expect("precondition: the node holds the peer");
    if p.needs_filter_update() {
        p.clear_filter_update_needed();
    }
    assert!(
        !p.needs_filter_update(),
        "precondition: the record is unlike a new one"
    );
    if !pairs.contains(&spare) {
        pairs.push(spare);
    }
}

/// Age `peer` at `node` past the restart gate: last heard a minute ago.
fn quiet(node: &mut Node, peer: &NodeAddr) {
    let p = node
        .get_peer_mut(peer)
        .expect("precondition: the node holds the peer");
    p.touch(Node::now_ms().saturating_sub(60_000));
    p.test_backdate_heard(Duration::from_secs(60));
}

/// With multipath on, whether node 0 queued the close of its path to node 1
/// at `t2()`, and whether, drained, the close reached that connection: the
/// unkept path of the capable link, which the cell queues at the site and the
/// next drain closes. `None` with multipath off, where nothing is unkept.
async fn unkept_closed(
    nodes: &mut [TestNode],
    on: bool,
    pairs: &[PathRef],
) -> Option<(bool, bool)> {
    if !on {
        return None;
    }
    let b = *nodes[1].node.node_addr();
    let q = pairs
        .iter()
        .find(|to| to.transport == t2())
        .expect("precondition: node 0 held a path at the second transport")
        .clone();
    let queued = nodes[0]
        .node
        .paths
        .closes(&b)
        .iter()
        .any(|(to, removed)| *to == q && *removed);
    nodes[0].node.drain_closes().await;
    let closed = loopback(&nodes[0], t2()).closed().contains(&q.addr);
    Some((queued, closed))
}

/// Put a restarted node 1 in `nodes[1]`, with multipath set as `on`.
async fn restart_one(nodes: &mut [TestNode], on: bool) {
    let restarted = restarted_node(&nodes[1], with_path(Config::new(), on));
    let mut old = std::mem::replace(&mut nodes[1], restarted);
    cleanup_nodes(std::slice::from_mut(&mut old)).await;
}

/// The (row, outcome) pairs a replacement test states, with the rows every
/// replacement states alike already in.
///
/// A replacement keeps the identity; the link, its index entry, its paths,
/// its machines and its setup record are new; the old path MTU entry is
/// released and the new link seeds one; the filter's send state and the tree
/// state are cleaned and marked; the identity is registered and the lookup
/// backoff reset. The connects [`dirty`] queued are forgotten. The listings
/// are forgotten only with multipath on.
fn common(on: bool) -> Vec<(Row, Outcome)> {
    vec![
        (Row::Link, Outcome::Changed),
        (Row::Index, Outcome::Changed),
        (Row::Paths, Outcome::Changed),
        (Row::RekeyMachine, Outcome::Changed),
        (Row::Identity, Outcome::Kept),
        (Row::ControlMachine, Outcome::Changed),
        (Row::PathMtu, Outcome::Changed),
        (Row::FilterSend, Outcome::Changed),
        (Row::Tree, Outcome::Changed),
        (Row::IdentityCache, Outcome::Changed),
        (Row::LookupBackoff, Outcome::Changed),
        (Row::PathConnects, Outcome::Changed),
        // Read over the links the reading covers, which the closed old link
        // leaves; that its reading is kept to the next read is asked of the
        // node by link (`reading_kept`).
        (Row::PathCarrier, Outcome::Changed),
        (Row::PathListings, changed_if(on)),
    ]
}

/// A restarted node 1 dials node 0, which last heard node 1 a minute ago,
/// with multipath set as `on`: node 0 answers the msg1, node 1 promotes node 0
/// on the msg2, and node 0 replaces its peering with node 1 on the msg3 at a
/// new epoch. On a capable link node 0's second path, the one the peer was
/// not active on, is queued to close.
async fn restart(on: bool) {
    let (mut nodes, mut pairs) = pair(on).await;
    let b = *nodes[1].node.node_addr();
    dirty(&mut nodes[0].node, &b).await;
    dial_of_its_own(&mut nodes[0].node, &b);
    unlike_new(&mut nodes[0].node, &b, &mut pairs);
    // No stamp, so that a stamp shows, and a stale one pruned does not pass
    // for it.
    nodes[0].node.gates_mut().unstamp(&b);
    quiet(&mut nodes[0].node, &b);
    let old = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    restart_one(&mut nodes, on).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    let msg1 = queued_in(&mut nodes[0], PHASE_MSG1)
        .expect("precondition: the restarted node's msg1 is queued at node 0");
    nodes[0].node.handle_msg1(msg1).await;
    let msg2 = queued_in(&mut nodes[1], PHASE_MSG2)
        .expect("precondition: node 0's msg2 is queued at the restarted node");
    nodes[1].node.handle_msg2(msg2).await;
    let msg3 = queued_in(&mut nodes[0], PHASE_MSG3)
        .expect("precondition: the restarted node's msg3 is queued at node 0");
    let before = Seen::of(&nodes[0].node, &b, &pairs).await;
    nodes[0].node.handle_msg3(msg3).await;
    let after = Seen::of(&nodes[0].node, &b, &pairs).await;
    let new = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    let carried = reading_kept(&nodes[0].node, old);
    let unkept = unkept_closed(&mut nodes, on, &pairs).await;
    cleanup_nodes(&mut nodes).await;
    let link = match (old, new) {
        (Some(o), Some(n)) if o != n => n,
        _ => panic!("precondition: node 0 replaced node 1's peering on the restart msg3"),
    };
    let t = Transition::Replace {
        link,
        initiator: false,
        why: Why::Restart,
    };
    let mut others = common(on);
    others.extend([
        // A capability is new with the bundle; with multipath on the old one
        // held what it learned and [`dirty`]'s candidate.
        (Row::Capability, changed_if(on)),
        // Only the capable link queues its unkept path; the connection
        // closes at the next drain, after the site.
        (Row::Connection, Outcome::Kept),
        (Row::PathCloses, changed_if(on)),
        (Row::BleMark, Outcome::Changed),
        (Row::Bootstrap, Outcome::Kept),
        // The dampener is stamped at the restart it accepts, and the old
        // peering, which frames reached, is not noted silent.
        (Row::Dampener, Outcome::Changed),
        (Row::Silent, Outcome::Kept),
        (Row::Reconnect, Outcome::Changed),
    ]);
    assert_cells(&before, &after, &t, &others);
    assert_reading_kept(carried);
    assert_unkept_closed(unkept);
}

/// Whether `node` still keeps the carrier reading [`dirty`] planted for the
/// replaced link `old`. The cell drops it at the next read, not at the site;
/// the readings of the old link are out of what [`Seen`] covers once the
/// link is closed, so this asks for it by the link.
fn reading_kept(node: &Node, old: Option<LinkId>) -> bool {
    old.is_some_and(|o| !node.paths.carried(o).is_empty())
}

/// Fail at `defect:` unless the replaced link's carrier reading outlived the
/// site.
fn assert_reading_kept(kept: bool) {
    assert!(
        kept,
        "defect: the replaced link's carrier reading is dropped at the site, not at the next read"
    );
}

/// Fail at `defect:` unless the capable link's unkept path was queued at the
/// site and its connection closed at the drain.
fn assert_unkept_closed(unkept: Option<(bool, bool)>) {
    if let Some(seen) = unkept {
        assert_eq!(
            seen,
            (true, true),
            "defect: the replaced peer's unkept path is not queued to close, or the drain does not close it (queued, closed)"
        );
    }
}

/// Kept or changed as `c` says.
fn changed_if(c: bool) -> Outcome {
    if c { Outcome::Changed } else { Outcome::Kept }
}

/// A restart's msg3 replaces the peering as the table says, with multipath
/// off, where no link is capable and every link keeps its connection.
#[tokio::test]
async fn a_restart_msg3_replaces_the_peer_as_the_table_says() {
    restart(false).await;
}

/// [`a_restart_msg3_replaces_the_peer_as_the_table_says`] with multipath on,
/// on a capable link of two paths, whose unkept path is queued to close.
#[tokio::test]
async fn a_restart_msg3_replaces_the_peer_as_the_table_says_with_multipath_on() {
    restart(true).await;
}

/// Node 0 holds node 1 and dials it, and node 1 has restarted: node 0
/// replaces the peering on the msg2, whose epoch is new. With multipath off
/// node 0 holds node 1 on one path; with multipath on it holds node 1 on a
/// capable link of two paths.
async fn own_restart(on: bool) {
    let (mut nodes, mut pairs) = pair(on).await;
    let b = *nodes[1].node.node_addr();
    dirty(&mut nodes[0].node, &b).await;
    dial_of_its_own(&mut nodes[0].node, &b);
    unlike_new(&mut nodes[0].node, &b, &mut pairs);
    let old = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    restart_one(&mut nodes, on).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    let msg1 = queued_in(&mut nodes[1], PHASE_MSG1)
        .expect("precondition: node 0's msg1 is queued at the restarted node");
    nodes[1].node.handle_msg1(msg1).await;
    let msg2 = queued_in(&mut nodes[0], PHASE_MSG2)
        .expect("precondition: the restarted node's msg2 is queued at node 0");
    let before = Seen::of(&nodes[0].node, &b, &pairs).await;
    nodes[0].node.handle_msg2(msg2).await;
    let after = Seen::of(&nodes[0].node, &b, &pairs).await;
    let new = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    let carried = reading_kept(&nodes[0].node, old);
    let unkept = unkept_closed(&mut nodes, on, &pairs).await;
    cleanup_nodes(&mut nodes).await;
    let link = match (old, new) {
        (Some(o), Some(n)) if o != n => n,
        _ => panic!("precondition: node 0 replaced the peering on the restart its msg2 showed"),
    };
    let t = Transition::Replace {
        link,
        initiator: true,
        why: Why::OwnRestart,
    };
    let mut others = common(on);
    others.extend([
        (Row::Capability, changed_if(on)),
        (Row::Connection, Outcome::Kept),
        (Row::PathCloses, changed_if(on)),
        (Row::BleMark, Outcome::Changed),
        (Row::Bootstrap, Outcome::Kept),
        // The answered dial is removed.
        (Row::Dials, Outcome::Changed),
        // The old peering, which frames reached, is not noted silent.
        (Row::Silent, Outcome::Kept),
        (Row::Reconnect, Outcome::Changed),
    ]);
    assert_cells(&before, &after, &t, &others);
    assert_reading_kept(carried);
    assert_unkept_closed(unkept);
}

/// This node's own dial answered by a restarted peer replaces the peering
/// as the table says, with multipath off.
#[tokio::test]
async fn a_restart_seen_in_our_msg2_replaces_the_peer_as_the_table_says() {
    own_restart(false).await;
}

/// [`a_restart_seen_in_our_msg2_replaces_the_peer_as_the_table_says`] with
/// multipath on, on a capable link of two paths, whose unkept path is queued
/// to close.
#[tokio::test]
async fn a_restart_seen_in_our_msg2_replaces_the_peer_as_the_table_says_with_multipath_on() {
    own_restart(true).await;
}

/// A handshake run by hand as `initiator`'s dial of `responder` at
/// `responder`'s BLE link `link`, whose msg2 reaches `initiator`: the msg1 at
/// the initiator's own epoch is handed to the responder, and the msg3 that
/// completes it, carrying a negotiation payload that declares no rekey, is
/// returned unhanded.
#[cfg(ble_available)]
async fn ble_hand_dial(
    nodes: &mut [TestNode],
    initiator: usize,
    responder: usize,
    link: &TransportAddr,
) -> ReceivedPacket {
    use super::promote::next_packet;
    use crate::proto::fmp::NodeProfile;
    use crate::proto::fmp::wire::{
        CommonPrefix, Msg2Header, NegotiationPayload, build_msg1, build_msg3,
    };
    let tid = nodes[responder].transport_id;
    let mut hs =
        crate::noise::HandshakeState::new_initiator(nodes[initiator].node.identity().keypair());
    hs.set_local_epoch(nodes[initiator].node.startup_epoch());
    let ours = SessionIndex::new(0x0B1E_0001);
    let msg1 = build_msg1(
        ours,
        &hs.write_message_1().expect("precondition: the msg1 builds"),
    );
    nodes[responder]
        .node
        .handle_msg1(ReceivedPacket::with_timestamp(
            tid,
            link.clone(),
            msg1,
            Node::now_ms(),
        ))
        .await;
    let msg2 = loop {
        let p = next_packet(&mut nodes[initiator]).await;
        let is_msg2 = CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_MSG2);
        if is_msg2 && Msg2Header::parse(&p.data).is_some_and(|h| h.receiver_idx == ours) {
            break p.data;
        }
    };
    let header = Msg2Header::parse(&msg2).expect("precondition: a framed msg2");
    let (mut fork, _) = hs
        .fork_msg2(&msg2[header.noise_msg2_offset..])
        .expect("precondition: the msg2 reads");
    let mut msg3 = fork
        .write_message_3()
        .expect("precondition: the msg3 builds");
    let payload = NegotiationPayload::fmp(1, 1, NodeProfile::Full).encode();
    msg3.extend(
        fork.encrypt_payload(&payload)
            .expect("precondition: the payload seals"),
    );
    ReceivedPacket::with_timestamp(
        tid,
        link.clone(),
        build_msg3(ours, header.sender_idx, &msg3),
        Node::now_ms(),
    )
}

/// On the BLE pair with multipath set as `on`, node 1 holds node 0 at an
/// epoch other than node 0's own and last heard it a minute ago, its state
/// dirtied and its link marked. Node 0's handshake at its own epoch reads as
/// a restart at its msg3: node 1 replaces the peering, which clears the
/// link's mark, and node 0's first frame on the new peering marks it again.
#[cfg(ble_available)]
async fn ble_restart(on: bool) {
    use super::ble_pair;
    use super::promote::mark_at;
    let (mut nodes, _bank) = ble_pair(on).await;
    let a = *nodes[0].node.node_addr();
    let link = nodes[1].addr.clone();
    let tid = nodes[1].transport_id;
    dirty(&mut nodes[1].node, &a).await;
    dial_of_its_own(&mut nodes[1].node, &a);
    // `dirty` clears the mark at the peer's pair; a frame would mark it again.
    nodes[1]
        .node
        .transports
        .get(&tid)
        .expect("precondition: node 1's BLE transport")
        .mark_verified(&link, &a)
        .await;
    nodes[1]
        .node
        .get_peer_mut(&a)
        .expect("precondition: node 1 holds node 0")
        .set_remote_epoch(Some([0xAA; 8]));
    quiet(&mut nodes[1].node, &a);
    let old = nodes[1].node.get_peer(&a).map(|p| p.link_id());
    let mut pairs = vec![PathRef {
        transport: tid,
        addr: link.clone(),
    }];
    unlike_new(&mut nodes[1].node, &a, &mut pairs);
    // No stamp, so that a stamp shows.
    nodes[1].node.gates_mut().unstamp(&a);
    let marked = mark_at(&nodes[1], &link).await;
    let msg3 = ble_hand_dial(&mut nodes, 0, 1, &link).await;
    let before = Seen::of(&nodes[1].node, &a, &pairs).await;
    nodes[1].node.handle_msg3(msg3).await;
    let after = Seen::of(&nodes[1].node, &a, &pairs).await;
    let cleared = mark_at(&nodes[1], &link).await;
    let new = nodes[1].node.get_peer(&a).map(|p| p.link_id());
    let carried = reading_kept(&nodes[1].node, old);
    // Node 0's first authenticated frame on the new peering, as the decrypt
    // worker hands it on: a 4-byte inner timestamp, then a heartbeat.
    nodes[1]
        .node
        .process_authentic_fmp_plaintext(
            &a,
            crate::node::dataplane::LinkSlot::Current,
            tid,
            &link,
            Node::now_ms(),
            64,
            1_000_000,
            false,
            &[0, 0, 0, 0, 0x51],
        )
        .await;
    let remarked = mark_at(&nodes[1], &link).await;
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        marked,
        Some(true),
        "precondition: node 1's link is marked before the restart"
    );
    let link_id = match (old, new) {
        (Some(o), Some(n)) if o != n => n,
        _ => panic!("precondition: node 1 replaced node 0's peering on the restart msg3"),
    };
    let t = Transition::Replace {
        link: link_id,
        initiator: false,
        why: Why::Restart,
    };
    let mut others = common(on);
    others.extend([
        // With multipath on the old bundle held [`dirty`]'s candidate.
        (Row::Capability, changed_if(on)),
        // One path: nothing is unkept, so nothing is queued to close.
        (Row::Connection, Outcome::Kept),
        (Row::PathCloses, Outcome::Kept),
        (Row::BleMark, Outcome::Changed),
        (Row::Bootstrap, Outcome::Kept),
        // The dampener is stamped at the restart it accepts, and the old
        // peering, which frames reached, is not noted silent.
        (Row::Dampener, Outcome::Changed),
        (Row::Silent, Outcome::Kept),
        (Row::Reconnect, Outcome::Changed),
    ]);
    assert_cells(&before, &after, &t, &others);
    assert_reading_kept(carried);
    assert_eq!(
        (cleared, remarked),
        (Some(false), Some(true)),
        "defect: the restart does not clear the old mark, or the new peering's first frame does not mark it"
    );
}

/// On a BLE link, with multipath off, a restart's msg3 clears the old
/// peering's mark, the new peering's first frame marks it, and every other
/// row is as the table says.
#[cfg(ble_available)]
#[tokio::test]
async fn a_restart_on_a_ble_link_clears_the_old_mark_and_marks_the_new_peering() {
    ble_restart(false).await;
}

/// [`a_restart_on_a_ble_link_clears_the_old_mark_and_marks_the_new_peering`]
/// with multipath on.
#[cfg(ble_available)]
#[tokio::test]
async fn a_restart_on_a_ble_link_clears_the_old_mark_and_marks_the_new_peering_with_multipath_on() {
    ble_restart(true).await;
}
