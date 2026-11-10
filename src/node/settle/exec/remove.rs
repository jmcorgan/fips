//! A removal: what the node runs once a peer is taken out of its maps, by
//! the table's cells for the cause.
//!
//! No site runs a removal through the executor yet, so each effect here
//! stops a debug build if reached.

use super::Run;
use crate::node::Node;

/// What a removal's effects read beyond the transition.
#[derive(Debug, Default)]
pub(in crate::node) struct Facts {}

/// Clear the transport's mark at the pair the peer was on, by the table's
/// cell.
pub(super) async fn unmark_held(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "removal: unmark_held is not routed here yet");
}

/// Close the transport's connection at the pair the peer was on, by the
/// table's cell.
pub(super) async fn close_held(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "removal: close_held is not routed here yet");
}

/// Note the link dead for a reconnect, or drop a pending one, by the
/// table's cell.
pub(super) async fn reconnect(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "removal: reconnect is not routed here yet");
}
