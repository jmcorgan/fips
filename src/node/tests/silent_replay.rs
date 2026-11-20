//! Copies of one captured msg1 that differ only in their unauthenticated
//! header, replayed against the silent-session back-off.
//!
//! The header's `sender_idx` is not covered by the msg1's AEAD, so a party
//! holding one capture can rewrite it before each replay. Each copy still
//! carries the capture's ephemeral, and must count once however its header
//! is changed.

use super::silent_backoff::{EPOCH, Rig};

/// Offset of the msg1 header's `sender_idx`, after the 4-byte common prefix.
const SENDER_IDX_OFFSET: usize = 4;

#[tokio::test]
async fn copies_of_one_msg1_with_a_changed_sender_idx_count_once_and_leave_the_genuine_peer_accepted()
 {
    let mut rig = Rig::new().await;
    let captured = rig.msg1(EPOCH);
    for i in 0..3u8 {
        let mut copy = captured.clone();
        copy[SENDER_IDX_OFFSET] = copy[SENDER_IDX_OFFSET].wrapping_add(0x40 + i);
        rig.deliver(copy).await;
        assert!(rig.link().is_some(), "copy {i} was promoted");
        rig.reap().await;
    }
    rig.drain().await;
    let refused = rig.silent_rejects();
    let silent = rig.node.gates().silent(&rig.peer());

    let data = rig.msg1(EPOCH);
    rig.deliver(data).await;

    assert_eq!(
        rig.silent_rejects(),
        refused,
        "the genuine peer's msg1 was refused by the back-off (silent count {silent:?})"
    );
    assert_eq!(silent, Some(1), "the three copies counted as one session");
    assert!(rig.link().is_some(), "the genuine peer's msg1 was promoted");
}
