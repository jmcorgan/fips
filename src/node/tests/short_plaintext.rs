//! An authenticated FMP plaintext too short for the 5-byte inner header (a
//! 4-byte timestamp and the message type) is dropped on every path, as the
//! inline decrypt path already does. The pending-session path and the
//! decrypt worker's bounce both hand their plaintext to
//! `process_authentic_fmp_plaintext`, which must not count such a frame.

use super::*;
use crate::node::dataplane::LinkSlot;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, make_test_node,
};

/// Node 1's link packet count and MMP receive count for node 0.
fn counts(nodes: &[TestNode]) -> (u64, u64) {
    let n0 = *nodes[0].node.node_addr();
    let peer = nodes[1]
        .node
        .get_peer(&n0)
        .expect("precondition: node 1 peers with node 0");
    let mmp = peer
        .mmp()
        .map(|m| m.receiver.cumulative_packets_recv())
        .expect("precondition: the peer runs MMP");
    (peer.link_stats().packets_recv, mmp)
}

/// Hand node 1 `plaintext` as an authenticated frame from node 0 on the
/// current session, as the pending-session path does after it promotes.
async fn deliver(nodes: &mut [TestNode], plaintext: &[u8], counter: u64) {
    let n0 = *nodes[0].node.node_addr();
    let tid = nodes[1].transport_id;
    let link = nodes[0].addr.clone();
    nodes[1]
        .node
        .process_authentic_fmp_plaintext(
            &n0,
            LinkSlot::Current,
            tid,
            &link,
            Node::now_ms(),
            64,
            counter,
            false,
            false,
            plaintext,
        )
        .await;
}

#[tokio::test]
async fn a_four_byte_authenticated_plaintext_is_not_counted_as_a_received_frame() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;

    let before = counts(&nodes);
    deliver(&mut nodes, &[0, 0, 0, 0], 1_000_000).await;
    assert_eq!(
        counts(&nodes),
        before,
        "defect: a plaintext with no message type was counted (link packets, MMP packets)"
    );

    // Control: a Heartbeat, the same timestamp and one message type byte,
    // is counted by both.
    deliver(&mut nodes, &[0, 0, 0, 0, 0x51], 1_000_001).await;
    let after = counts(&nodes);
    assert_eq!(
        (after.0 - before.0, after.1 - before.1),
        (1, 1),
        "precondition: a full inner header is counted once by each"
    );
    cleanup_nodes(&mut nodes).await;
}
