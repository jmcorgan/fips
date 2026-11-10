//! Cells at replacement: the held peer torn down and a new one installed, by
//! a msg1 at a new epoch, a same-epoch msg1 on a silent peering, or this
//! node's own dial answered by a restarted peer, each test a plain one and
//! its `_with_multipath_on` sibling.
//!
//! The peer's state is dirtied through [`dirty`] before the site, so a row
//! the replacement keeps is held to a value it could have changed, and each
//! test reads the node at the site alone, before any frame of the new
//! peering. The restart siblings run on a capable link of two paths
//! (`two_transports`), where the replaced peer's unkept path is queued to
//! close; the plain tests run where no link is capable and every link keeps.
//! The replacement sibling cannot be capable: a same-epoch msg1 replaces only
//! a peering no frame has reached, and a capability is learned from frames.

use super::super::super::paths::{loopback, t2, two_transports};
use super::super::super::spanning_tree::{
    TestNode, cleanup_nodes, initiate_handshake, restarted_node,
};
use super::super::super::*;
use super::super::{loopback_node, with_path};
use super::promote::queued_in;
use super::{Outcome, Seen, assert_cells, dirty, peered};
use crate::node::handlers::handshake::UNHEARD_PEERING_MIN_AGE_MS;
use crate::node::settle::table::{Row, Transition};
use crate::proto::fmp::wire::{PHASE_MSG1, PHASE_MSG2};
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
    node.links.open(crate::transport::Link::new(
        id,
        spare.transport,
        TransportAddr::from_string("spare:3"),
        crate::transport::LinkDirection::Outbound,
        Duration::from_millis(50),
    ));
    node.pending_outbound.note(key, id);
}

/// Leave the rows [`dirty`] toggles from the peering's current state unlike
/// a new record's, so that a new record shows as a change: a new record marks
/// its filter to be sent and starts its spin bit clear, and once the peering
/// has carried frames [`dirty`]'s toggle can land on either. The pair
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
    if let Some(m) = p.mmp_mut()
        && !m.spin_bit.tx_bit()
    {
        // An initiator flips on its own bit reflected; a responder copies a
        // bit whose counter is higher than any it has seen.
        let seen = !m.spin_bit.is_initiator();
        m.spin_bit
            .rx_observe(seen, (1 << 40) + 1, crate::time::mono_ms());
    }
    assert!(
        !p.needs_filter_update() && p.mmp().is_some_and(|m| m.spin_bit.tx_bit()),
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
/// with multipath set as `on`: node 0 replaces its peering with node 1 on the
/// msg1 at a new epoch. On a capable link node 0's second path, the one the
/// peer was not active on, is queued to close.
async fn restart(on: bool) {
    let (mut nodes, mut pairs) = pair(on).await;
    let b = *nodes[1].node.node_addr();
    dirty(&mut nodes[0].node, &b).await;
    dial_of_its_own(&mut nodes[0].node, &b);
    unlike_new(&mut nodes[0].node, &b, &mut pairs);
    // No stamp, so that a stamp shows, and a stale one pruned does not pass
    // for it.
    nodes[0].node.restart_dampener.remove(&b);
    quiet(&mut nodes[0].node, &b);
    let old = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    restart_one(&mut nodes, on).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    let msg1 = queued_in(&mut nodes[0], PHASE_MSG1)
        .expect("precondition: the restarted node's msg1 is queued at node 0");
    let before = Seen::of(&nodes[0].node, &b, &pairs).await;
    nodes[0].node.handle_msg1(msg1).await;
    let after = Seen::of(&nodes[0].node, &b, &pairs).await;
    let new = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    let carried = reading_kept(&nodes[0].node, old);
    let unkept = unkept_closed(&mut nodes, on, &pairs).await;
    cleanup_nodes(&mut nodes).await;
    let link = match (old, new) {
        (Some(o), Some(n)) if o != n => n,
        _ => panic!("precondition: node 0 replaced node 1's peering on the restart msg1"),
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
        // The old peer dialled, so its machine stored no setup record but
        // the one [`dirty`] noted; the new one, a responder's, stores the
        // msg1's. The reading is the record's length.
        (Row::SetupRecord, Outcome::Kept),
        // Only the capable link queues its unkept path; the connection
        // closes at the next drain, after the site.
        (Row::Connection, Outcome::Kept),
        (Row::PathCloses, changed_if(on)),
        (Row::BleMark, Outcome::Changed),
        (Row::Bootstrap, Outcome::Kept),
        // The old peering was heard: its session closes, the dampener is
        // stamped, and no silent note is made.
        (Row::Session, Outcome::Changed),
        (Row::Dampener, Outcome::Changed),
        (Row::Silent, Outcome::Kept),
        // The new peering is not yet heard, so the msg1's ephemeral is noted.
        (Row::Replayed, Outcome::Changed),
        (Row::Reconnect, Outcome::Changed),
        (Row::Records, Outcome::Changed),
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

/// A restart's msg1 replaces the peering as the table says, with multipath
/// off, where no link is capable and every link keeps its connection.
#[tokio::test]
async fn a_restart_msg1_replaces_the_peer_as_the_table_says() {
    restart(false).await;
}

/// [`a_restart_msg1_replaces_the_peer_as_the_table_says`] with multipath on,
/// on a capable link of two paths, whose unkept path is queued to close.
#[tokio::test]
async fn a_restart_msg1_replaces_the_peer_as_the_table_says_with_multipath_on() {
    restart(true).await;
}

/// Node 1 dials node 0 twice with multipath set as `on`, and node 0 promotes
/// node 1 on the first msg1 and hears nothing more. Past the age an unheard
/// peering may be replaced at, the second msg1, at the same epoch, replaces
/// it.
async fn replacement(on: bool) {
    let mut nodes = vec![loopback_node(on).await, loopback_node(on).await];
    let b = *nodes[1].node.node_addr();
    initiate_handshake(&mut nodes, 1, 0).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    let first = queued_in(&mut nodes[0], PHASE_MSG1)
        .expect("precondition: the first msg1 is queued at node 0");
    let second = queued_in(&mut nodes[0], PHASE_MSG1)
        .expect("precondition: the second msg1 is queued at node 0");
    nodes[0].node.handle_msg1(first).await;
    let old = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    assert!(
        nodes[0].node.get_peer(&b).is_some_and(|p| !p.is_heard()),
        "precondition: node 0 holds node 1, unheard"
    );
    dirty(&mut nodes[0].node, &b).await;
    dial_of_its_own(&mut nodes[0].node, &b);
    let mut pairs = vec![PathRef {
        transport: nodes[0].transport_id,
        addr: nodes[1].addr.clone(),
    }];
    unlike_new(&mut nodes[0].node, &b, &mut pairs);
    // No stamp, so that a stamp would show: an accepted msg1 also prunes
    // every stamp past the interval, as [`dirty`]'s is.
    nodes[0].node.restart_dampener.remove(&b);
    crate::time::advance(Duration::from_millis(UNHEARD_PEERING_MIN_AGE_MS + 500));
    let mut second = second;
    second.timestamp_ms = Node::now_ms();
    let before = Seen::of(&nodes[0].node, &b, &pairs).await;
    nodes[0].node.handle_msg1(second).await;
    let after = Seen::of(&nodes[0].node, &b, &pairs).await;
    let new = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    let carried = reading_kept(&nodes[0].node, old);
    cleanup_nodes(&mut nodes).await;
    let link = match (old, new) {
        (Some(o), Some(n)) if o != n => n,
        _ => panic!("precondition: the second msg1 replaced the unheard peering"),
    };
    let t = Transition::Replace {
        link,
        initiator: false,
        why: Why::Replacement,
    };
    let mut others = common(on);
    others.extend([
        // No frame reached the peering, so no link is capable at either
        // setting; with multipath on the old bundle held [`dirty`]'s
        // candidate.
        (Row::Capability, changed_if(on)),
        // The old machine held the msg1's record and [`dirty`]'s; the new
        // one holds its own msg1's.
        (Row::SetupRecord, Outcome::Changed),
        (Row::Connection, Outcome::Kept),
        (Row::PathCloses, Outcome::Kept),
        (Row::BleMark, Outcome::Changed),
        (Row::Bootstrap, Outcome::Kept),
        // The old peering was never heard: its session stays, the dampener
        // is not stamped, and the silent note is made.
        (Row::Session, Outcome::Kept),
        (Row::Dampener, Outcome::Kept),
        (Row::Silent, Outcome::Changed),
        (Row::Replayed, Outcome::Changed),
        (Row::Reconnect, Outcome::Changed),
        // The old machine's record is filed at the peer's epoch, which the
        // new msg1 carries too, so the promotion takes it straight back.
        (Row::Records, Outcome::Kept),
    ]);
    assert_cells(&before, &after, &t, &others);
    assert_reading_kept(carried);
}

/// A same-epoch msg1 replaces a silent peering as the table says, with
/// multipath off.
#[tokio::test]
async fn a_same_epoch_msg1_replaces_a_silent_peer_as_the_table_says() {
    replacement(false).await;
}

/// [`a_same_epoch_msg1_replaces_a_silent_peer_as_the_table_says`] with
/// multipath on.
#[tokio::test]
async fn a_same_epoch_msg1_replaces_a_silent_peer_as_the_table_says_with_multipath_on() {
    replacement(true).await;
}

/// Node 0 holds node 1 and dials it, and node 1 has restarted: node 0
/// replaces the peering on the msg2, whose epoch is new. With multipath off
/// node 0 holds node 1 by node 1's own msg1, unheard; with multipath on it
/// holds node 1 on a capable link of two paths, heard.
async fn own_restart(on: bool) {
    let (mut nodes, mut pairs) = if on {
        pair(true).await
    } else {
        let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
        initiate_handshake(&mut nodes, 1, 0).await;
        let msg1 = queued_in(&mut nodes[0], PHASE_MSG1)
            .expect("precondition: node 1's msg1 is queued at node 0");
        nodes[0].node.handle_msg1(msg1).await;
        let pairs = vec![PathRef {
            transport: nodes[0].transport_id,
            addr: nodes[1].addr.clone(),
        }];
        (nodes, pairs)
    };
    let b = *nodes[1].node.node_addr();
    let heard = nodes[0].node.get_peer(&b).map(|p| p.is_heard());
    assert_eq!(
        heard,
        Some(on),
        "precondition: node 0 holds node 1, heard only on the capable link"
    );
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
        // An initiator's new machine stores no setup record; the old one held
        // [`dirty`]'s.
        (Row::SetupRecord, Outcome::Changed),
        (Row::Connection, Outcome::Kept),
        (Row::PathCloses, changed_if(on)),
        (Row::BleMark, Outcome::Changed),
        (Row::Bootstrap, Outcome::Kept),
        // The answered dial is removed.
        (Row::Dials, Outcome::Changed),
        // A heard peering's session closes; an unheard one's stays, and
        // the unheard one, which no frame reached, is noted silent.
        (Row::Session, changed_if(on)),
        (Row::Silent, changed_if(!on)),
        (Row::Reconnect, Outcome::Changed),
        (Row::Records, Outcome::Changed),
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

/// Two nodes peered with multipath set as `on`, node 0 having last heard
/// node 1 a minute ago. Node 1 restarts and dials node 0, which by then
/// denies node 1 in its ACL. A replacement removes the held peer before the
/// ACL check, so the msg1 costs node 0 its peering with node 1: the removal
/// stands and nothing is promoted in its place.
async fn refused(on: bool) {
    let mut nodes = super::peered(on).await;
    let b = *nodes[1].node.node_addr();
    nodes[0].node.restart_dampener.remove(&b);
    quiet(&mut nodes[0].node, &b);
    let old = nodes[0]
        .node
        .get_peer(&b)
        .map(|p| p.link_id())
        .expect("precondition: node 0 holds node 1");
    restart_one(&mut nodes, on).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    let msg1 = queued_in(&mut nodes[0], PHASE_MSG1)
        .expect("precondition: the restarted node's msg1 is queued at node 0");
    let dir = tempfile::tempdir().unwrap();
    let deny = dir.path().join("peers.deny");
    std::fs::write(&deny, format!("{}\n", nodes[1].node.npub())).unwrap();
    // The reloader reads the files it is given when it is made, and a held
    // peer stays until a handshake asks the ACL about it.
    nodes[0]
        .node
        .isolate_peer_acl_for_test(dir.path().join("peers.allow"), deny);
    assert!(
        nodes[0].node.get_peer(&b).is_some(),
        "precondition: node 0 still holds node 1 once it denies it"
    );
    nodes[0].node.handle_msg1(msg1).await;
    let held = nodes[0].node.get_peer(&b).map(|p| p.link_id());
    let old_open = nodes[0].node.get_link(&old).is_some();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        held, None,
        "defect: node 0 still holds node 1 after a restart's msg1 the ACL refused"
    );
    assert!(
        !old_open,
        "defect: the refused replacement left the old peering's link open"
    );
}

/// A replacement the ACL refuses after its removal keeps the removal, with
/// multipath off.
#[tokio::test]
async fn a_replacement_refused_by_the_acl_after_its_removal_keeps_the_removal() {
    refused(false).await;
}

/// [`a_replacement_refused_by_the_acl_after_its_removal_keeps_the_removal`]
/// with multipath on.
#[tokio::test]
async fn a_replacement_refused_by_the_acl_after_its_removal_keeps_the_removal_with_multipath_on() {
    refused(true).await;
}

/// A real msg1 from `initiator` to `responder` at the initiator's own epoch,
/// built on a detached machine.
#[cfg(ble_available)]
fn genuine_msg1(initiator: &Node, responder: &Node) -> Vec<u8> {
    let responder_identity = PeerIdentity::from_pubkey_full(responder.identity().pubkey_full());
    let mut machine = outbound_leg(LinkId::new(9_999), responder_identity, 1_000);
    let noise_msg1 = machine
        .start_handshake(
            initiator.identity().keypair(),
            initiator.startup_epoch(),
            LegStamp::at(1_000),
        )
        .expect("precondition: the initiator side of a real msg1 builds");
    crate::proto::fmp::wire::build_msg1(SessionIndex::new(7), &noise_msg1)
}

/// On the BLE pair with multipath set as `on`, node 1 holds node 0 at an
/// epoch other than node 0's own and last heard it a minute ago, its state
/// dirtied and its link marked. Node 0's msg1 at its own epoch reads as a
/// restart: node 1 replaces the peering, which clears the link's mark, and
/// node 0's first frame on the new peering marks it again.
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
    nodes[1].node.restart_dampener.remove(&a);
    let marked = mark_at(&nodes[1], &link).await;
    let before = Seen::of(&nodes[1].node, &a, &pairs).await;
    let msg1 = genuine_msg1(&nodes[0].node, &nodes[1].node);
    nodes[1]
        .node
        .handle_msg1(ReceivedPacket::with_timestamp(
            tid,
            link.clone(),
            msg1,
            2_000,
        ))
        .await;
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
        _ => panic!("precondition: node 1 replaced node 0's peering on the restart msg1"),
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
        // Node 1 answered node 0's dial, so the old machine held that
        // msg1's record and [`dirty`]'s; the new one holds this msg1's.
        (Row::SetupRecord, Outcome::Changed),
        // One path: nothing is unkept, so nothing is queued to close.
        (Row::Connection, Outcome::Kept),
        (Row::PathCloses, Outcome::Kept),
        (Row::BleMark, Outcome::Changed),
        (Row::Bootstrap, Outcome::Kept),
        (Row::Session, Outcome::Changed),
        (Row::Dampener, Outcome::Changed),
        (Row::Silent, Outcome::Kept),
        (Row::Replayed, Outcome::Changed),
        (Row::Reconnect, Outcome::Changed),
        (Row::Records, Outcome::Changed),
    ]);
    assert_cells(&before, &after, &t, &others);
    assert_reading_kept(carried);
    assert_eq!(
        (cleared, remarked),
        (Some(false), Some(true)),
        "defect: the restart does not clear the old mark, or the new peering's first frame does not mark it"
    );
}

/// On a BLE link, with multipath off, a restart's msg1 clears the old
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
