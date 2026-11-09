//! What the node runs for a transition outside the peer's record, as a list
//! of effects in their order.
//!
//! [`plan`] gives each [`Transition`] its effects, and [`Node::run_plan`]
//! runs them one after another on a held peer. A transition whose list is
//! empty still runs its own statements at its site: only the transitions with
//! a list are run from here.

#![deny(clippy::wildcard_enum_match_arm)]

use super::table::Transition;
use crate::NodeAddr;
use crate::node::Node;
use tracing::debug;

/// One step the node takes for a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum Effect {
    /// Close the end-to-end session with the peer and the path MTU entry it
    /// tightened.
    CloseSession,
    /// Apply the transition to the peer's record.
    SettleData,
    /// Remove the peer from the spanning tree's state, and if this node's
    /// own tree state changed, mark a tree announce pending to every other
    /// peer.
    TreeCleanup,
    /// Forget the filter last sent to the peer.
    BloomForgetSent,
    /// Mark a filter update due to every peer.
    BloomMarkAll,
    /// Send the peer a tree announce.
    TreeAnnounce,
    /// End the operator's pin on the peer's link.
    Unpin,
}

/// The effects `t` runs, in their order.
pub(in crate::node) fn plan(t: &Transition) -> &'static [Effect] {
    match t {
        // The process the peer ran before has gone, so what was held about
        // it is dropped and this node's own state announced again, on the
        // session the cutover just installed.
        Transition::Restarted => &[
            Effect::CloseSession,
            Effect::SettleData,
            Effect::TreeCleanup,
            Effect::BloomForgetSent,
            Effect::BloomMarkAll,
            Effect::TreeAnnounce,
            Effect::Unpin,
        ],
        Transition::Promote { .. }
        | Transition::Replace { .. }
        | Transition::Move { .. }
        | Transition::Keep { .. }
        | Transition::Cutover { .. }
        | Transition::Roam
        | Transition::Follow
        | Transition::Switch
        | Transition::Release { .. }
        | Transition::Remove { .. } => &[],
    }
}

impl Node {
    /// Run [`plan`]'s effects for `t` on the peer at `peer`, in their order.
    pub(in crate::node) async fn run_plan(&mut self, peer: &NodeAddr, t: &Transition) {
        for effect in plan(t) {
            match effect {
                Effect::CloseSession => {
                    if self.close_session(peer) {
                        debug!(
                            peer = %self.peer_display_name(peer),
                            transition = ?t,
                            "Closed stale FSP session"
                        );
                    }
                }
                Effect::SettleData => {
                    if let Some(held) = self.peers.get_mut(peer) {
                        held.settle(t);
                    }
                }
                Effect::TreeCleanup => {
                    if !node_fault!(RestartSkipsTreeReset)
                        && self.handle_peer_removal_tree_cleanup(peer)
                    {
                        for (addr, other) in self.peers.iter_mut() {
                            if addr != peer {
                                other.mark_tree_announce_pending();
                            }
                        }
                    }
                }
                // The forgotten filter may have been part of what this node
                // announces to every peer, and a restarted peer holds none of
                // its filters.
                Effect::BloomForgetSent => self.bloom_state.forget_sent(peer),
                Effect::BloomMarkAll => {
                    let peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
                    self.bloom_state.mark_all_updates_needed(peers);
                }
                Effect::TreeAnnounce => {
                    if let Err(e) = self.send_tree_announce_to_peer(peer).await {
                        debug!(
                            peer = %self.peer_display_name(peer),
                            transition = ?t,
                            error = %e,
                            "Failed to send TreeAnnounce"
                        );
                    }
                }
                Effect::Unpin => {
                    self.step_path(peer, fips_core::proto::path::Input::Unpin)
                        .await;
                }
            }
        }
    }
}
