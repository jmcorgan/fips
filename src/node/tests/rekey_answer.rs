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
use crate::proto::fmp::RekeyRole;

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
        assert_eq!(p.pending_role(), None::<RekeyRole>);
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
    nodes[1].node.check_rekey().await;

    let p = nodes[1].node.get_peer(&b_addr).unwrap();
    assert!(
        !p.is_draining() && p.previous_session().is_none(),
        "A's rekey tick must complete the drain once its window has passed"
    );
    let tid = p.transport_id().unwrap();
    let old = old_index.expect("precondition: A had an index before the rekey");
    assert!(
        !nodes[1]
            .node
            .peers_by_index
            .contains_key(&(tid, old.as_u32())),
        "completing the drain must release the replaced session's index"
    );
    cleanup_nodes(&mut nodes).await;
}
