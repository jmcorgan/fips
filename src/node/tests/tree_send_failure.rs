//! TreeAnnounce delivery when the link send fails.
//!
//! A TreeAnnounce whose link send fails must stay pending, as a rate-limited
//! one does, so the next tick sends it again. The failure is produced by
//! taking the sender's transport out of its transport map, which makes
//! `send_encrypted_link_message` return `TransportNotFound` on the inline
//! send path that unit-test nodes use (they spawn no encrypt workers).

use super::spanning_tree::*;
use super::*;
use crate::node::tree::sign_declaration;

/// Indices of the attached child (the sender) and the root of a converged
/// two-node tree.
fn child_and_root(nodes: &[TestNode]) -> (usize, usize) {
    if nodes[0].node.tree_state().is_root() {
        (1, 0)
    } else {
        (0, 1)
    }
}

/// Give node `s` a new declaration sequence with the same parent, signed, as
/// a position change would. Returns the new sequence.
fn bump(nodes: &mut [TestNode], s: usize, parent: NodeAddr) -> u64 {
    let identity = nodes[s].node.identity().clone();
    let ts = nodes[s].node.tree_state_mut();
    let seq = ts.my_declaration().sequence() + 1;
    let timestamp = ts.my_declaration().timestamp() + 1;
    ts.set_parent(parent, seq, timestamp, crate::time::mono_ms());
    ts.recompute_coords();
    sign_declaration(ts.my_declaration_mut(), &identity).unwrap();
    seq
}

/// The declaration sequence node `r` stores for node `s`.
fn held_seq(nodes: &[TestNode], r: usize, s: usize) -> Option<u64> {
    let sender = *nodes[s].node.node_addr();
    nodes[r]
        .node
        .tree_state()
        .peer_declaration(&sender)
        .map(|decl| decl.sequence())
}

/// Clear the rate limit on `s`'s link to `peer`, so a send is attempted now.
fn open_rate_limit(nodes: &mut [TestNode], s: usize, peer: &NodeAddr) {
    nodes[s]
        .node
        .peers
        .get_mut(peer)
        .expect("setup: peer exists")
        .set_last_tree_announce_sent_ms(None);
}

/// Take `s`'s transport to `peer` out of its transport map so link sends to
/// that peer fail. Returns the id and handle for `restore_transport`.
fn break_transport(
    nodes: &mut [TestNode],
    s: usize,
    peer: &NodeAddr,
) -> (TransportId, TransportHandle) {
    let tid = nodes[s]
        .node
        .get_peer(peer)
        .expect("setup: peer exists")
        .transport_id()
        .expect("setup: peer has a transport");
    let handle = nodes[s]
        .node
        .transports
        .remove(&tid)
        .expect("setup: transport is registered");
    (tid, handle)
}

fn restore_transport(nodes: &mut [TestNode], s: usize, taken: (TransportId, TransportHandle)) {
    nodes[s].node.transports.insert(taken.0, taken.1);
}

fn pending_for(nodes: &[TestNode], s: usize, peer: &NodeAddr) -> bool {
    nodes[s]
        .node
        .get_peer(peer)
        .expect("setup: peer exists")
        .has_pending_tree_announce()
}

/// A TreeAnnounce whose link send fails stays pending and goes out on the
/// next tick once the link can send, so the peer ends up holding the new
/// declaration.
#[tokio::test]
async fn test_tree_announce_whose_link_send_fails_stays_pending_and_is_resent_on_the_next_tick() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let (s, r) = child_and_root(&nodes);
    let parent = *nodes[r].node.node_addr();

    let seq = bump(&mut nodes, s, parent);
    open_rate_limit(&mut nodes, s, &parent);
    let taken = break_transport(&mut nodes, s, &parent);

    let failed_before = nodes[s].node.metrics().tree.send_failed.get();
    let result = nodes[s].node.send_tree_announce_to_peer(&parent).await;
    assert!(result.is_err(), "setup: the link send must fail");
    assert_eq!(
        nodes[s].node.metrics().tree.send_failed.get(),
        failed_before + 1,
        "the failed send must be counted once"
    );
    assert!(
        pending_for(&nodes, s, &parent),
        "a TreeAnnounce whose link send failed must stay pending"
    );

    restore_transport(&mut nodes, s, taken);
    let sent_before = nodes[s].node.metrics().tree.sent.get();
    nodes[s].node.check_tree_state().await;
    assert_eq!(
        nodes[s].node.metrics().tree.sent.get(),
        sent_before + 1,
        "the next tick must resend the announce"
    );
    assert!(
        !pending_for(&nodes, s, &parent),
        "a successful resend must clear the pending mark"
    );

    let _ = drain_all_packets(&mut nodes, false).await;
    assert_eq!(
        held_seq(&nodes, r, s),
        Some(seq),
        "the peer must hold the declaration whose first send failed"
    );
    cleanup_nodes(&mut nodes).await;
}

/// On a link whose sends keep failing, each tick makes exactly one attempt
/// and the announce stays pending: a failure does not resend within the tick
/// that saw it.
#[tokio::test]
async fn test_tree_announce_on_a_persistently_failing_link_is_tried_once_per_tick() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let (s, r) = child_and_root(&nodes);
    let parent = *nodes[r].node.node_addr();

    bump(&mut nodes, s, parent);
    open_rate_limit(&mut nodes, s, &parent);
    let taken = break_transport(&mut nodes, s, &parent);

    let failed_before = nodes[s].node.metrics().tree.send_failed.get();
    let _ = nodes[s].node.send_tree_announce_to_peer(&parent).await;
    for tick in 1..=3u64 {
        nodes[s].node.check_tree_state().await;
        assert_eq!(
            nodes[s].node.metrics().tree.send_failed.get(),
            failed_before + 1 + tick,
            "tick {tick} must make exactly one send attempt"
        );
        assert!(
            pending_for(&nodes, s, &parent),
            "the announce must stay pending while the link cannot send"
        );
    }

    restore_transport(&mut nodes, s, taken);
    cleanup_nodes(&mut nodes).await;
}
