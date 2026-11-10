//! A promotion, and the promotion a replacement ends with: what the node
//! runs once a new peer is installed for an identity it did not hold.
//!
//! No site runs a promotion through the executor yet, so each effect here
//! stops a debug build if reached.

use super::Run;
use crate::node::Node;

/// What a promotion's effects read beyond the transition.
#[derive(Debug, Default)]
pub(in crate::node) struct Facts {}

/// Feed the promotion's outcome to the leg's control machine and run what
/// it returns.
pub(super) async fn machine_resolved(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "promotion: machine_resolved is not routed here yet");
}

/// Mark the link a dial of this node's promoted, at the transport.
pub(super) async fn relink_initiator(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "promotion: relink_initiator is not routed here yet");
}

/// Log the promotion of a dial of this node's.
pub(super) async fn promoted_note(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "promotion: promoted_note is not routed here yet");
}

/// Store the setup's msg2, msg1 and ephemeral on the peer.
pub(super) async fn setup_note(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "promotion: setup_note is not routed here yet");
}

/// Remember an unheard peering's setup ephemeral.
pub(super) async fn unheard_note(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "promotion: unheard_note is not routed here yet");
}
