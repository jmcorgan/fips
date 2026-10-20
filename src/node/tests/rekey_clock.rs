//! Rekey timing against a stepped system clock.
//!
//! A host's wall clock can jump either way (an NTP correction, a manual set,
//! a resume from suspend), and a rekey schedule read from it would fire or
//! stall on the jump rather than on elapsed time. These tests step the wall
//! clock and advance the monotonic one independently, with the test hooks of
//! `crate::time`, and assert that only monotonic time moves a rekey.

use super::rekey_parity::{age_link, linked_pair, rekey_config, trigger_age};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;

/// The resend count of node 0's rekey toward `peer`.
fn resends(tn: &TestNode, peer: &NodeAddr) -> u32 {
    tn.node.get_peer(peer).unwrap().rekey_msg1_resend_count()
}

/// A rekey msg1 is resent when the monotonic resend interval has passed, and
/// a step of the wall clock either way neither sends one early nor holds one
/// back.
#[tokio::test]
async fn host_wall_clock_step_changes_no_rekey_decision() {
    let mut nodes = linked_pair(rekey_config(60), crate::config::Config::new()).await;
    let peer = *nodes[1].node.node_addr();
    let interval = nodes[0]
        .node
        .config()
        .node
        .rate_limit
        .handshake_resend_interval_ms;
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0].node.check_rekey().await;
    assert!(
        nodes[0].node.get_peer(&peer).unwrap().rekey_in_progress(),
        "precondition: node 0 started a rekey and its msg1 went out"
    );
    assert_eq!(resends(&nodes[0], &peer), 0);

    // An hour forward on the wall clock, no monotonic time: nothing is due.
    crate::time::step_wall(3_600_000);
    nodes[0].node.resend_pending_rekeys().await;
    assert_eq!(
        resends(&nodes[0], &peer),
        0,
        "a forward wall-clock step must not send a msg1 resend early"
    );

    // Two hours back on the wall clock, and the resend interval of monotonic
    // time: the first resend is due.
    crate::time::step_wall(-7_200_000);
    crate::time::advance(Duration::from_millis(interval));
    nodes[0].node.resend_pending_rekeys().await;
    assert_eq!(
        resends(&nodes[0], &peer),
        1,
        "a backward wall-clock step must not hold back a msg1 resend that is due"
    );
    cleanup_nodes(&mut nodes).await;
}
