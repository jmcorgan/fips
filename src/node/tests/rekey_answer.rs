//! Answering an established peer's link rekey.
//!
//! Whether a node answers its peer's rekey, and whether it then retires the
//! session that rekey replaced, must not depend on its own configuration:
//! the peer decides to rekey, and a node that refuses, or that answers and
//! never drains, splits a two-sided outcome on a one-sided setting. These
//! tests drive one rekey over loopback with the answering node on a default
//! config and assert on its slots and index registrations.

use super::rekey_parity::{
    age_link, cutover, deliver, heartbeat, linked_pair, rekey_config, rekey_to_pending, trigger_age,
};
use super::spanning_tree::cleanup_nodes;
use super::*;
use fips_core::proto::rekey::Role;

/// Longer than the fixed drain a cutover or adoption starts, so a backdated
/// drain reads as passed.
const PAST_DRAIN: Duration = Duration::from_secs(12);

/// A answers B's rekey as the responder, adopts the new session on B's first
/// frame on it, and its next rekey tick retires the replaced session and its
/// index.
#[tokio::test]
async fn peer_rekey_is_answered_and_drains_complete() {
    // A, the answering node, keeps the default rekey settings; B, at index 0,
    // is the one whose trigger fires.
    let mut nodes = linked_pair(rekey_config(60), crate::config::Config::new()).await;
    let b_addr = *nodes[0].node.node_addr();
    let a_addr = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    let old_index = nodes[1].node.get_peer(&b_addr).unwrap().our_index();

    let answered = rekey_to_pending(&mut nodes, 0, 1).await;
    cutover(&mut nodes[0], &a_addr).await;
    heartbeat(&mut nodes[0], &a_addr).await;
    deliver(&mut nodes[1]).await;
    {
        let p = nodes[1].node.get_peer(&b_addr).unwrap();
        assert_eq!(
            p.our_index(),
            Some(answered),
            "B's first frame on the new session must promote the session A answered"
        );
        assert_eq!(p.pending_role(), None::<Role>);
        assert!(
            p.is_draining() && p.previous_our_index() == old_index,
            "A must be draining the session the rekey replaced"
        );
    }

    nodes[1]
        .node
        .get_peer_mut(&b_addr)
        .unwrap()
        .test_backdate_drain_started(PAST_DRAIN);
    nodes[1].node.poll_link_rekeys().await;

    let p = nodes[1].node.get_peer(&b_addr).unwrap();
    assert!(
        !p.is_draining() && p.previous_session().is_none(),
        "A's rekey tick must complete the drain once its window has passed"
    );
    let old = old_index.expect("precondition: A had an index before the rekey");
    assert!(
        !nodes[1].node.peers_by_index.contains_key(&old.as_u32()),
        "completing the drain must release the replaced session's index"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A msg1 refused in a dual initiation is recorded by its ephemeral, so a
/// copy of it with a rewritten sender index, replayed once the link is old
/// enough to rekey again, is refused as answered before and arms no
/// pending. Both ends start a rekey together: the smaller keeps its own and
/// refuses the larger's msg1, the larger yields and answers, and the
/// smaller cuts over.
#[tokio::test]
async fn a_msg1_refused_in_a_crossing_and_replayed_with_a_rewritten_sender_index_arms_no_pending() {
    /// Offset of the msg1 header's `sender_idx`, after the 4-byte common
    /// prefix.
    const SENDER_IDX_OFFSET: usize = 4;

    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    age_link(&mut nodes, 0, 1, trigger_age());
    let addrs = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    let (s, l) = if addrs[0] < addrs[1] { (0, 1) } else { (1, 0) };

    nodes[s].node.poll_link_rekeys().await;
    nodes[l].node.poll_link_rekeys().await;
    for x in [s, l] {
        assert!(
            nodes[x]
                .node
                .get_peer(&addrs[1 - x])
                .unwrap()
                .rekey_in_progress(),
            "setup: node {x} started a rekey"
        );
    }

    // The smaller node refuses the larger node's msg1 and keeps its own
    // attempt; a copy of the refused msg1 is kept.
    let refused = nodes[s]
        .packet_rx
        .try_recv()
        .expect("the larger node's msg1 is queued at the smaller");
    let captured = refused.data.clone();
    nodes[s].node.handle_msg1(refused).await;
    assert!(
        nodes[s]
            .node
            .get_peer(&addrs[l])
            .unwrap()
            .pending_new_session()
            .is_none(),
        "setup: the smaller node refuses the crossing msg1"
    );

    // The larger node yields and answers; the smaller completes and cuts
    // over.
    assert_eq!(
        deliver(&mut nodes[l]).await,
        1,
        "setup: the smaller node's msg1"
    );
    assert_eq!(
        deliver(&mut nodes[s]).await,
        1,
        "setup: the larger node's msg2"
    );
    cutover(&mut nodes[s], &addrs[l]).await;

    // Old enough to rekey again, the smaller node gets the refused msg1
    // with its sender index rewritten.
    nodes[s]
        .node
        .get_peer_mut(&addrs[l])
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));
    let mut copy = captured;
    let rewritten = u32::from_le_bytes(
        copy[SENDER_IDX_OFFSET..SENDER_IDX_OFFSET + 4]
            .try_into()
            .unwrap(),
    )
    .wrapping_add(1);
    copy[SENDER_IDX_OFFSET..SENDER_IDX_OFFSET + 4].copy_from_slice(&rewritten.to_le_bytes());
    let replay = ReceivedPacket::new(nodes[s].transport_id, nodes[l].addr.clone(), copy);
    nodes[s].node.handle_msg1(replay).await;
    assert!(
        nodes[s]
            .node
            .get_peer(&addrs[l])
            .unwrap()
            .pending_new_session()
            .is_none(),
        "a header-rewritten copy of a msg1 refused in a crossing must not arm a pending"
    );

    cleanup_nodes(&mut nodes).await;
}
