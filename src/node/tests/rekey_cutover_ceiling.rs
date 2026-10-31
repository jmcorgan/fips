//! The ceiling on the initiator's cutover: an initiator must cut over no
//! later than `REKEY_CHECK_INTERVAL`, at most 1 s, after its rekey msg2
//! completes (FRC-1201, Sections 3.5 and 7.4).
//!
//! The node cuts over only when it polls its link rekey machines, and the
//! receive loop polls them once per [`TICK`] (`dataplane/rx_loop.rs`, the
//! tick arm). The loop cannot be driven from a unit test, so the first test
//! below states the rule as the tick the node runs with, and the second
//! shows that the cutover waits for the poll.

use super::rekey_parity::{
    age_link, cutover, deliver, linked_pair, rekey_config, rekey_to_pending, trigger_age,
};
use super::spanning_tree::cleanup_nodes;
use super::*;
use fips_core::proto::rekey::Role;

/// The initiator's cutover waits for a tick, so a tick longer than 1 s would
/// put it past the 1 s ceiling: the tick is 1 s, and a node's receive loop
/// runs at it.
#[test]
fn the_receive_loop_ticks_once_a_second_so_an_initiator_cuts_over_within_1_s() {
    assert_eq!(
        TICK,
        Duration::from_secs(1),
        "a tick other than 1 s lets a rekey initiator cut over later than 1 s after the msg2"
    );
    let node = Node::new(Config::new()).expect("a node is built from the default configuration");
    assert_eq!(
        node.tick_period(),
        TICK,
        "a node's receive loop must tick at TICK unless a test sets another period"
    );
}

/// After its rekey msg2 completes, the initiator keeps the new session
/// pending and sends nothing under it until its next poll of the link rekey
/// machines, which cuts over: the cutover is as late as the poll.
#[tokio::test]
async fn the_initiator_cuts_over_only_at_its_next_rekey_poll_after_the_msg2() {
    let mut nodes = linked_pair(rekey_config(60), rekey_config(3_600)).await;
    let responder = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    rekey_to_pending(&mut nodes, 0, 1).await;

    crate::time::advance(Duration::from_secs(5));
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&responder)
            .and_then(|p| p.pending_role()),
        Some(Role::Initiator),
        "5 s after its msg2 and with no poll, the initiator still holds the session pending"
    );
    assert_eq!(
        deliver(&mut nodes[1]).await,
        0,
        "nothing went to the responder after the msg2 without a poll"
    );
    cutover(&mut nodes[0], &responder).await;
    cleanup_nodes(&mut nodes).await;
}
