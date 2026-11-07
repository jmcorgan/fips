//! Per-peer state across a change of the peer's link or session: what a new
//! or replaced peer is sent at once, and what a cleared session releases.
//!
//! - A peer promoted for an identity announced to just now, by a fresh dial,
//!   is sent a TreeAnnounce at once: no stamp of the peer it replaces is
//!   carried over to rate-limit it.
//!
//! The master line's cases of a restart's msg1 and a redial answered as a
//! rekey rest on its msg1 promotion, which this line's handshake does not
//! have, and are not run here.

use super::super::rekey_parity::deliver;
use super::super::spanning_tree::{TestNode, cleanup_nodes, drain_all_packets, initiate_handshake};
use super::super::*;
use super::loopback_node;

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
