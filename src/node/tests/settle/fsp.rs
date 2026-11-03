//! An end-to-end session whose responder restarts before any of its frames
//! reach the initiator.
//!
//! X opens a session to Y; Y's ack arrives, X's msg3 is lost, and nothing of
//! Y's reaches X, so X holds its first msg3. Y then restarts (no session, a
//! new startup epoch) and opens a session to X. The pair must carry data
//! both ways one exchange after Y's setup. With the restarted responder at
//! the larger address it does not (a known defect); at the smaller address
//! it does, which shows the assertion can pass.

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

/// Drive the restart. Returns whether the pair carried data both ways one
/// exchange after Y's setup, and the second (the thread's clock stepped 1 s
/// at a time, both nodes polled, up to 45 s) at which it first did.
async fn restarted_responder(responder_larger: bool) -> (bool, Option<u64>) {
    let mut nodes = routable_pair().await;
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
    for secs in 1..=45u64 {
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
#[ignore = "known defect: a restarted responder at the larger address does not carry data until the initiator's msg3 resends run out"]
async fn a_restarted_larger_responder_carries_data_within_one_exchange() {
    let (at_once, recovered) = restarted_responder(true).await;
    assert!(
        at_once,
        "defect: the restarted larger responder's setup does not establish a session within one exchange (recovered at {recovered:?} s)"
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
