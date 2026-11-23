//! Copies of one captured msg1 that differ only in their unauthenticated
//! header, replayed against the silent-session back-off.
//!
//! Nothing in an XX msg1 is authenticated, and the header's `sender_idx`
//! sits outside the Noise message, so a party holding one capture can
//! rewrite it before each replay. On XX a session is
//! promoted only on a msg3 bound to this node's fresh msg2, so no copy is
//! promoted, none counts as a silent session, and the genuine peer's next
//! handshake is accepted.

use super::silent_backoff::{
    discard, from_node0, next_phase, node0_initiator, pair, silent_session,
};
use super::spanning_tree::cleanup_nodes;

/// Offset of the msg1 header's `sender_idx`, after the 4-byte common prefix.
const SENDER_IDX_OFFSET: usize = 4;

#[tokio::test]
async fn copies_of_one_msg1_with_a_changed_sender_idx_promote_nothing_and_leave_the_genuine_peer_accepted()
 {
    let mut nodes = pair().await;
    let a = *nodes[0].node.node_addr();
    let epoch = nodes[0].node.startup_epoch();
    let (_, captured) = node0_initiator(&nodes, epoch, 1);
    for i in 0..3u8 {
        let mut copy = captured.clone();
        copy[SENDER_IDX_OFFSET] = copy[SENDER_IDX_OFFSET].wrapping_add(0x40 + i);
        discard(&mut nodes[0]);
        let packet = from_node0(&nodes, copy);
        nodes[1].node.handle_msg1(packet).await;
        assert!(
            next_phase(&mut nodes[0], 2).await.is_some(),
            "copy {i}: node 1 answers the replay"
        );
        assert!(
            nodes[1].node.get_peer(&a).is_none(),
            "copy {i} was promoted"
        );
        nodes[1].node.check_link_heartbeats().await;
    }
    assert_eq!(
        nodes[1].node.gates().silent(&a),
        None,
        "a copy counted as a silent session"
    );
    assert!(
        silent_session(&mut nodes, epoch, 10).await,
        "the genuine peer's handshake was not promoted"
    );
    cleanup_nodes(&mut nodes).await;
}
