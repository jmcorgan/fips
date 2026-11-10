//! A crossing resolved on the peer held: moved onto this node's dial, or
//! kept on the peer's inbound session with the dial closed.
//!
//! No site runs a crossing through the executor yet, so each effect here
//! stops a debug build if reached.

use super::Run;
use crate::node::Node;

/// What a crossing's effects read beyond the transition.
#[derive(Debug, Default)]
pub(in crate::node) struct Facts {}

/// Run the rekey machine's outputs from the move.
pub(super) async fn link_outputs(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: link_outputs is not routed here yet");
}

/// Run the path machine's outputs from its renewal.
pub(super) async fn renewed(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: renewed is not routed here yet");
}

/// Read the pair the peer is on after the move into `r.moved`.
pub(super) async fn moved_read(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: moved_read is not routed here yet");
}

/// Seed the path MTU from the pair the peer moved to, if it moved.
pub(super) async fn seed_mtu(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: seed_mtu is not routed here yet");
}

/// End the operator's pin if the move answered this node's own or a later
/// dial and the peer is on that dial's session.
pub(super) async fn unpin_own(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: unpin_own is not routed here yet");
}

/// Log the replays suppressed during the move and the move itself.
pub(super) async fn move_note(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: move_note is not routed here yet");
}

/// Waive the live audit's entry check for a moved link left with no
/// entry.
pub(super) async fn waiver(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: waiver is not routed here yet");
}

/// Tell the peer's control machine how the crossing resolved.
pub(super) async fn machine_crossed(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: machine_crossed is not routed here yet");
}

/// Close the dial's connection unless the peer runs on it.
pub(super) async fn dial_close(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: dial_close is not routed here yet");
}

/// Remove the dial's link.
pub(super) async fn dial_removed(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: dial_removed is not routed here yet");
}

/// Log the crossing kept on the peer's inbound session.
pub(super) async fn keep_note(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: keep_note is not routed here yet");
}

/// Free the session index of the dial a kept crossing closes.
pub(super) async fn lease_freed(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "crossing: lease_freed is not routed here yet");
}
