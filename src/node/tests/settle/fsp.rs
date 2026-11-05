//! An end-to-end session whose responder restarts before any of its frames
//! reach the initiator.
//!
//! X opens a session to Y; Y's ack arrives, X's msg3 is lost, and nothing of
//! Y's reaches X, so X holds its first msg3. Y then restarts (no session, a
//! new startup epoch) and opens a session to X. With the restarted responder
//! at the smaller address the pair carries data both ways one exchange after
//! Y's setup. At the larger address X refuses Y's setups while it holds the
//! msg3, so the pair recovers only when X's msg3 resends end and the repair
//! rekey X then starts completes. That is accepted behaviour, and the test
//! asserts it as a ceiling: a sooner recovery passes too. The thread's clock
//! is frozen, so the seconds counted are the session clock's.

use super::super::spanning_tree::{
    TestNode, cleanup_nodes, populate_all_coord_caches, process_available_packets,
    run_tree_test_with_configs, verify_tree_convergence,
};
use super::super::*;
use super::pump;

/// A routable two-node pair, converged, with coordinates cached.
async fn routable_pair() -> Vec<TestNode> {
    let configs = (0..2).map(|_| Config::new()).collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    pump(&mut nodes).await;
    nodes
}

/// Discard and count what is queued at `node`.
async fn lose(node: &mut TestNode) -> usize {
    tokio::time::sleep(Duration::from_millis(10)).await;
    std::iter::from_fn(|| node.packet_rx.try_recv().ok()).count()
}

/// Whether both ends hold an established session with each other and a
/// data frame is received each way.
async fn carries_both_ways(nodes: &mut [TestNode], x: usize, y: usize) -> bool {
    let x_addr = *nodes[x].node.node_addr();
    let y_addr = *nodes[y].node.node_addr();
    let est = |n: &TestNode, peer: &NodeAddr| {
        n.node.get_session(peer).is_some_and(|e| e.is_established())
    };
    if !est(&nodes[x], &y_addr) || !est(&nodes[y], &x_addr) {
        return false;
    }
    let rx = |n: &TestNode, peer: &NodeAddr| {
        n.node
            .get_session(peer)
            .map_or(0, |e| e.traffic_counters().1)
    };
    let (bx, by) = (rx(&nodes[x], &y_addr), rx(&nodes[y], &x_addr));
    let _ = nodes[y]
        .node
        .send_session_data(&x_addr, 0, 0, b"restarted to initiator")
        .await;
    let _ = nodes[x]
        .node
        .send_session_data(&y_addr, 0, 0, b"initiator to restarted")
        .await;
    pump(nodes).await;
    rx(&nodes[x], &y_addr) > bx && rx(&nodes[y], &x_addr) > by
}

/// The second, counted from X's install of its first epoch, at which X sends
/// its retained first msg3 for the last time at the defaults: five resends
/// doubling from 1 s, at 1, 3, 7, 15 and 31 s. At that poll X drops the
/// msg3 and, having heard nothing under the epoch, starts the repair rekey
/// that the restarted Y answers as a fresh responder.
const MSG3_RESENDS_END: u64 = 31;

/// The latest second at which the pair may first carry data both ways after
/// a restart at the larger address. The repair's handshake runs inside the
/// step that starts it, since delivery here is in-process and lossless; one
/// more step lets its handshake or first data frame land on the next poll.
const CEILING: u64 = MSG3_RESENDS_END + 1;

/// Drive the restart. Returns whether the pair carried data both ways one
/// exchange after Y's setup, and the second (the thread's clock frozen from
/// before X's initiation, then stepped 1 s at a time, both nodes polled, up
/// to 70 s) at which it first did. Counted on the frozen clock, the seconds
/// are the session clock's and not shortened by the time a step takes to
/// run.
async fn restarted_responder(responder_larger: bool) -> (bool, Option<u64>) {
    let mut nodes = routable_pair().await;
    crate::time::freeze();
    let (small, large) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let (x, y) = if responder_larger {
        (small, large)
    } else {
        (large, small)
    };
    let x_addr = *nodes[x].node.node_addr();
    let y_addr = *nodes[y].node.node_addr();
    let x_pk = nodes[x].node.identity().pubkey_full();
    let y_pk = nodes[y].node.identity().pubkey_full();

    nodes[x]
        .node
        .initiate_session(y_addr, y_pk)
        .await
        .expect("precondition: the initiation starts");
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        process_available_packets(&mut nodes[y..=y]).await,
        1,
        "precondition: Y received X's setup"
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(
        process_available_packets(&mut nodes[x..=x]).await,
        1,
        "precondition: X received Y's ack"
    );
    assert!(
        nodes[x]
            .node
            .get_session(&y_addr)
            .is_some_and(|e| e.is_established() && e.is_initiator()),
        "precondition: X is established as initiator"
    );
    assert_eq!(
        lose(&mut nodes[y]).await,
        1,
        "precondition: X's msg3 was sent and is lost"
    );
    assert_eq!(
        lose(&mut nodes[x]).await,
        0,
        "precondition: nothing of Y's reached X"
    );

    // Y restarts: no session, a new startup epoch.
    nodes[y].node.remove_session(&x_addr);
    nodes[y]
        .node
        .replace_context(|ctx| ctx.startup_epoch = [0x5A; 8]);
    assert!(
        nodes[y].node.get_session(&x_addr).is_none(),
        "precondition: Y holds no session"
    );

    nodes[y]
        .node
        .initiate_session(x_addr, x_pk)
        .await
        .expect("precondition: the restarted node's initiation starts");
    pump(&mut nodes).await;
    let at_once = carries_both_ways(&mut nodes, x, y).await;

    let mut recovered = at_once.then_some(0);
    for secs in 1..=70u64 {
        if recovered.is_some() {
            break;
        }
        crate::time::advance(Duration::from_secs(1));
        let now = Node::session_now();
        nodes[x].node.poll_session_rekeys(now).await;
        nodes[y].node.poll_session_rekeys(now).await;
        pump(&mut nodes).await;
        if carries_both_ways(&mut nodes, x, y).await {
            recovered = Some(secs);
        }
    }
    cleanup_nodes(&mut nodes).await;
    (at_once, recovered)
}

#[tokio::test]
async fn a_restarted_larger_responder_carries_data_both_ways_within_the_msg3_resends_and_one_handshake()
 {
    let config = Config::new();
    assert_eq!(
        config.node.rate_limit.handshake_max_resends, 5,
        "precondition: the default msg3 resend count"
    );
    assert_eq!(
        config.node.rate_limit.handshake_timeout_secs, 30,
        "precondition: the default handshake timeout, which ends the restarted node's own attempt before the msg3 resends end"
    );
    assert_eq!(
        fips_core::proto::rekey::msg1_span(5),
        Duration::from_secs(MSG3_RESENDS_END),
        "precondition: five resends doubling from 1 s end at the second the bound counts from"
    );
    let (at_once, recovered) = restarted_responder(true).await;
    assert!(
        recovered.is_some_and(|s| s <= CEILING),
        "defect: the restarted larger responder does not carry data both ways within {CEILING} s, the initiator's msg3 resends and one handshake (at once {at_once}, recovered at {recovered:?} s)"
    );
}

#[tokio::test]
async fn a_restarted_smaller_responder_carries_data_within_one_exchange() {
    let (at_once, recovered) = restarted_responder(false).await;
    assert!(
        at_once,
        "defect: the restarted smaller responder's setup does not establish a session within one exchange (recovered at {recovered:?} s)"
    );
}
