//! A change to the peer's paths: a one-path roam, a path that followed its
//! peer to another address, a switch of the active path, and a path
//! released while the link lives.
//!
//! A roam's effects are shared ones and await. The other three are reached
//! from code that cannot await, a removal's release of every path among it,
//! so their effects are plain functions, and [`run_now`] walks such a plan
//! without awaiting. No site runs a path change through the executor yet, so
//! each effect here stops a debug build if reached.

use super::Run;
use super::plan::{Effect, plan};
use crate::node::Node;

/// What a path change's effects read beyond the transition.
#[derive(Debug, Default)]
pub(in crate::node) struct Facts {}

/// Run `r`'s plan where the caller cannot await: every effect in it must be
/// one of this file's.
pub(in crate::node) fn run_now(node: &mut Node, r: &mut Run) {
    for effect in plan(&r.t) {
        match effect {
            Effect::LinkFollow => link_follow(node, r),
            Effect::FollowNote => follow_note(node, r),
            Effect::ClearOldUdp => clear_old(node, r),
            Effect::LinkClaim => link_claim(node, r),
            Effect::SeedMtu => seed_mtu(node, r),
            Effect::TightenSessions => tighten(node, r),
            Effect::SwitchNote => switch_note(node, r),
            Effect::LinkUnclaim => link_unclaim(node, r),
            Effect::CloseQueued => close_queued(node, r),
            Effect::CloseSession
            | Effect::SettleData
            | Effect::TreeCleanup
            | Effect::BloomForgetSent
            | Effect::BloomMarkAll
            | Effect::TreeAnnounce
            | Effect::Unpin
            | Effect::DialForget
            | Effect::BloomMark
            | Effect::BackoffReset
            | Effect::PathsRenewed
            | Effect::ClearUdpIfMoved
            | Effect::RelinkIfMoved
            | Effect::MachineResolved
            | Effect::RelinkInitiator
            | Effect::PromotedNote
            | Effect::SetupNote
            | Effect::UnheardNote
            | Effect::RunLinkOutputs
            | Effect::RunRenewed
            | Effect::MovedRead
            | Effect::SeedMtuIfMoved
            | Effect::UnpinIfOwn
            | Effect::MoveNote
            | Effect::WaiverIfNoEntry
            | Effect::MachineCrossed
            | Effect::DialClose
            | Effect::DialLinkRemoved
            | Effect::KeepNote
            | Effect::LeaseFreed
            | Effect::UnmarkHeld
            | Effect::CloseHeld
            | Effect::Reconnect => {
                debug_assert!(
                    false,
                    "{effect:?} awaits, so its plan runs through Node::run"
                );
            }
        }
    }
}

/// Move the link's lookup entry from the path's old pair to its new.
pub(super) fn link_follow(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: link_follow is not routed here yet");
}

/// Log the path's move.
pub(super) fn follow_note(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: follow_note is not routed here yet");
}

/// Drop the connected UDP socket of the path that was active.
pub(super) fn clear_old(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: clear_old is not routed here yet");
}

/// Claim the newly active pair for the link in the lookup.
pub(super) fn link_claim(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: link_claim is not routed here yet");
}

/// Seed the peer's path MTU from the newly active pair.
pub(super) fn seed_mtu(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: seed_mtu is not routed here yet");
}

/// Tighten every session whose next hop is the peer to the new pair's
/// MTU.
pub(super) fn tighten(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: tighten is not routed here yet");
}

/// Log the switch.
pub(super) fn switch_note(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: switch_note is not routed here yet");
}

/// Unclaim the released pair from the link's lookup while the link
/// lives.
pub(super) fn link_unclaim(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: link_unclaim is not routed here yet");
}

/// Queue the released pair's connection to close unless it is kept or
/// another peer's link uses it.
pub(super) fn close_queued(node: &mut Node, r: &mut Run) {
    let _ = (node, r);
    debug_assert!(false, "path change: close_queued is not routed here yet");
}
