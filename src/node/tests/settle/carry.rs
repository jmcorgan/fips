//! Per-peer state across a change of the peer's link or session: what a new
//! or replaced peer is sent at once, and what a cleared session releases.
//!
//! - A peer promoted for an identity announced to just now, by a fresh dial,
//!   is sent a TreeAnnounce at once: no stamp of the peer it replaces is
//!   carried over to rate-limit it.
//! - A peer replaced by a restart, at the msg3 of the restart's own dial or at
//!   the msg2 of a dial to it, likewise.
//!
//! The master line's case of a redial answered as a rekey rests on its msg1
//! promotion, which this line's handshake does not have, and is not run here.

use super::super::rekey_parity::{deliver, linked_pair};
use super::super::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, restarted_node,
};
use super::super::*;
use super::{loopback_node, restart_dial, with_path};

/// Milliseconds on the clock the TreeAnnounce rate-limit stamp is kept in.
fn stamp_ms() -> u64 {
    crate::time::mono_ms()
}

/// Two loopback nodes, node 0 having dialed node 1, delivered until idle.
async fn peered() -> Vec<TestNode> {
    let mut nodes = vec![loopback_node(false).await, loopback_node(false).await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let a1 = *nodes[1].node.node_addr();
    let a0 = *nodes[0].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&a1).is_some() && nodes[1].node.get_peer(&a0).is_some(),
        "precondition: the two nodes are peered"
    );
    nodes
}

/// Record at `nodes[at]` a TreeAnnounce sent to `peer` just now, and return
/// a reading of the stamp's clock strictly later than the stamp.
async fn announced_just_now(nodes: &mut [TestNode], at: usize, peer: &NodeAddr) -> u64 {
    let stamp = stamp_ms();
    let p = nodes[at]
        .node
        .get_peer_mut(peer)
        .expect("precondition: the node holds the peer");
    p.record_tree_announce_sent(stamp);
    assert!(
        !p.can_send_tree_announce(stamp),
        "precondition: the peer is inside its TreeAnnounce interval"
    );
    while stamp_ms() <= stamp {
        tokio::task::yield_now().await;
    }
    stamp_ms()
}

/// Whether `nodes[at]`'s peer `peer` was sent a TreeAnnounce at or after
/// `since` and holds none pending, with the values seen.
fn sent_at_once(nodes: &[TestNode], at: usize, peer: &NodeAddr, since: u64) -> Result<(), String> {
    let p = nodes[at]
        .node
        .get_peer(peer)
        .expect("precondition: the node holds the new peer");
    let (stamp, pending) = (
        p.last_tree_announce_sent_ms(),
        p.has_pending_tree_announce(),
    );
    if stamp.is_some_and(|s| s >= since) && !pending {
        Ok(())
    } else {
        Err(format!(
            "last TreeAnnounce stamp {stamp:?} against {since} after the old peer's, pending {pending}"
        ))
    }
}

/// A fresh dial, after the previous peer of that identity was removed at
/// both ends, promotes on its msg2 and sends the new peer a TreeAnnounce at
/// once, although the previous peer was sent one just now.
#[tokio::test]
async fn a_peer_promoted_for_an_identity_announced_to_just_now_is_sent_a_tree_announce_at_once() {
    let mut nodes = peered().await;
    let a0 = *nodes[0].node.node_addr();
    let a1 = *nodes[1].node.node_addr();
    let since = announced_just_now(&mut nodes, 0, &a1).await;
    nodes[0].node.remove_active_peer(&a1);
    nodes[1].node.remove_active_peer(&a0);
    assert!(
        nodes[0].node.get_peer(&a1).is_none() && nodes[1].node.get_peer(&a0).is_none(),
        "precondition: both ends removed the previous peering"
    );
    initiate_handshake(&mut nodes, 0, 1).await;
    assert_eq!(
        deliver(&mut nodes[1]).await,
        1,
        "precondition: only node 0's msg1 is queued at node 1"
    );
    let msg2 = nodes[0]
        .packet_rx
        .try_recv()
        .expect("precondition: node 1's msg2 is queued at node 0");
    nodes[0].node.handle_msg2(msg2).await;
    let result = sent_at_once(&nodes, 0, &a1, since);
    cleanup_nodes(&mut nodes).await;
    assert!(result.is_ok(), "defect: {result:?}");
}

/// Multipath off and a minute between a peer's TreeAnnounces, so a stamp the
/// old peer left holds the new peer's first one back however slowly a test
/// runs.
fn minute_interval() -> Config {
    let mut config = with_path(Config::new(), false);
    config.node.tree.announce_min_interval_ms = 60_000;
    config
}

/// Whether `nodes[at]`'s peer `peer` holds a TreeAnnounce stamp at or after
/// `since`, with the stamp seen. It reads the stamp alone: at a minute's
/// interval a later trigger may leave a second announce pending, which says
/// nothing of the first.
fn stamped_since(nodes: &[TestNode], at: usize, peer: &NodeAddr, since: u64) -> Result<(), String> {
    let stamp = nodes[at]
        .node
        .get_peer(peer)
        .expect("precondition: the node holds the new peer")
        .last_tree_announce_sent_ms();
    if stamp.is_some_and(|s| s >= since) {
        Ok(())
    } else {
        Err(format!(
            "last TreeAnnounce stamp {stamp:?} against {since} after the old peer's"
        ))
    }
}

/// The restart's own dial replaces the peer at its msg3, and the new peer is
/// sent a TreeAnnounce at once, although the old one was sent one just now.
#[tokio::test]
async fn a_peer_replaced_by_a_restart_at_msg3_after_an_announce_just_now_is_sent_a_tree_announce_at_once()
 {
    let mut nodes = linked_pair(minute_interval(), minute_interval()).await;
    let a1 = *nodes[1].node.node_addr();
    let since = announced_just_now(&mut nodes, 0, &a1).await;
    let peer = nodes[0]
        .node
        .get_peer_mut(&a1)
        .expect("precondition: node 0 holds node 1");
    let before = peer.link_id();
    peer.touch(Node::now_ms().saturating_sub(60_000));
    peer.test_backdate_heard(std::time::Duration::from_secs(60));
    restart_dial(&mut nodes, minute_interval()).await;
    let after = nodes[0].node.get_peer(&a1).map(|p| p.link_id());
    let result = stamped_since(&nodes, 0, &a1, since);
    cleanup_nodes(&mut nodes).await;
    assert_ne!(
        after,
        Some(before),
        "precondition: the restart replaced the peer"
    );
    assert!(result.is_ok(), "defect: {result:?}");
}

/// Our own dial shows the peer restarted at its msg2, which replaces the peer,
/// and the new peer is sent a TreeAnnounce at once, although the old one was
/// sent one just now.
#[tokio::test]
async fn a_peer_replaced_by_a_restart_at_msg2_after_an_announce_just_now_is_sent_a_tree_announce_at_once()
 {
    let mut nodes = linked_pair(minute_interval(), minute_interval()).await;
    let a1 = *nodes[1].node.node_addr();
    let before = nodes[0].node.get_peer(&a1).map(|p| p.link_id());
    let since = announced_just_now(&mut nodes, 0, &a1).await;
    let restarted = restarted_node(&nodes[1], minute_interval());
    let mut old = std::mem::replace(&mut nodes[1], restarted);
    cleanup_nodes(std::slice::from_mut(&mut old)).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    deliver(&mut nodes[1]).await;
    deliver(&mut nodes[0]).await;
    let after = nodes[0].node.get_peer(&a1).map(|p| p.link_id());
    let result = stamped_since(&nodes, 0, &a1, since);
    cleanup_nodes(&mut nodes).await;
    assert_ne!(after, before, "precondition: the restart replaced the peer");
    assert!(result.is_ok(), "defect: {result:?}");
}
