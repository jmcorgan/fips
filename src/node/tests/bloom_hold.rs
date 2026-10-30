//! FilterAnnounce hold for newly promoted peers.
//!
//! A node does not send a peer a FilterAnnounce before it has heard from the
//! peer. The test drives one side of a handshake at a time over the loopback
//! transport, so the frames each node has heard are exactly the ones the test
//! chose to deliver.

use super::spanning_tree::*;

#[tokio::test]
async fn a_responder_holds_the_filter_announce_until_the_new_peer_sends_a_frame() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let a = *nodes[0].node.node_addr();
    nodes[1].node.bloom_state.set_update_debounce_ms(0);

    initiate_handshake(&mut nodes, 0, 1).await;
    process_available_packets(&mut nodes[1..]).await;
    assert!(
        nodes[1].node.get_peer(&a).is_some(),
        "setup: B must promote A on the msg1"
    );
    assert!(
        nodes[1].node.bloom_state.needs_update(&a),
        "setup: A's promotion must leave an update pending"
    );

    // A has sent B only its msg1: B has heard no frame from A since the
    // promotion.
    let sent = nodes[1].node.metrics().bloom.sent.get();
    for _ in 0..3 {
        nodes[1].node.check_bloom_state().await;
    }
    assert_eq!(
        nodes[1].node.metrics().bloom.sent.get(),
        sent,
        "B must send no FilterAnnounce to A before it has heard from A"
    );
    assert_eq!(
        nodes[1].node.bloom_state.last_update_sent(&a),
        None,
        "no send may be recorded for the unheard peer"
    );
    assert!(
        nodes[1].node.bloom_state.needs_update(&a),
        "the held update must stay pending"
    );

    // Healthy path: once A completes the handshake and B authenticates A's
    // frames, B sends the filter.
    process_available_packets(&mut nodes[..1]).await;
    process_available_packets(&mut nodes[1..]).await;
    nodes[1].node.check_bloom_state().await;
    assert!(
        nodes[1].node.metrics().bloom.sent.get() > sent,
        "B must send the FilterAnnounce once it has heard from A"
    );

    cleanup_nodes(&mut nodes).await;
}
