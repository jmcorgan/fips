//! The executor: what the node runs for a change to a held peer, as a list
//! of effects in their order.
//!
//! [`plan`] states each transition's effects. A site builds a [`Run`], which
//! holds the transition and what its effects read, and [`Node::run`] carries
//! out each effect of the plan in order. The effects two kinds of change
//! share have their bodies here; each other effect's body is in the file of
//! the change it belongs to, `install.rs`, `cross.rs`, `remove.rs` or
//! `paths.rs`, beside that change's own [`Facts`]. A transition whose list is
//! empty still runs its own statements at its site.

#![deny(clippy::wildcard_enum_match_arm)]

mod cross;
mod install;
mod links;
mod paths;
pub(in crate::node) mod plan;
mod remove;

pub(in crate::node) use links::{PathSteps, pathed};
pub(in crate::node) use remove::Removed;

use crate::NodeAddr;
use crate::node::settle::table::Transition;
use crate::node::{AddrKey, Node};
use crate::transport::TransportId;
use plan::{Effect, plan};
use tracing::debug;

/// What a transition's effects read beyond the transition itself, for the
/// change it belongs to.
pub(in crate::node) enum Facts {
    /// A transition whose effects read nothing more.
    None,
    /// A promotion's or a replacement's.
    Install(install::Facts),
    /// A crossing's, moved or kept.
    Cross(cross::Facts),
    /// A change to the peer's paths.
    Paths(paths::Facts),
    /// A removal's.
    Remove(remove::Facts),
}

/// One transition of the peer at `peer`, and what its effects read.
pub(in crate::node) struct Run {
    /// The peer the transition changes.
    pub(in crate::node) peer: NodeAddr,
    /// The transition, whose plan is run.
    pub(in crate::node) t: Transition,
    /// The pair the peer was on before the transition, for a move or a roam.
    pub(in crate::node) prior: Option<AddrKey>,
    /// The pair the peer is on after it, for a move or a roam: a roam's site
    /// sets it, and a move reads it at its place in the plan.
    pub(in crate::node) moved: Option<AddrKey>,
    /// The dial the transition answered or ended, by its msg2 lookup key.
    pub(in crate::node) dial: Option<(TransportId, u32)>,
    /// What the change's own effects read.
    pub(in crate::node) facts: Facts,
}

impl Run {
    /// A run of `t` on the peer at `peer` whose effects read nothing more.
    pub(in crate::node) fn new(peer: NodeAddr, t: Transition) -> Self {
        Self {
            peer,
            t,
            prior: None,
            moved: None,
            dial: None,
            facts: Facts::None,
        }
    }
}

/// The line a failed tree announce logs at `t`, as its sites wrote it, or
/// `None` for a transition that sends no announce.
pub(in crate::node) fn announce_line(t: &Transition) -> Option<&'static str> {
    match t {
        Transition::Promote { .. } | Transition::Replace { .. } => {
            Some("Failed to send initial TreeAnnounce")
        }
        Transition::Move { .. } | Transition::Keep { .. } => {
            Some("Failed to send TreeAnnounce after cross-connection resolution")
        }
        Transition::Restarted => Some("Failed to send TreeAnnounce"),
        Transition::Cutover { .. }
        | Transition::Roam
        | Transition::Follow
        | Transition::Switch
        | Transition::Release { .. }
        | Transition::Remove { .. } => None,
    }
}

impl Node {
    /// Run `r`'s plan: each of its transition's effects, in their order.
    pub(in crate::node) async fn run(&mut self, r: &mut Run) {
        // Boxed once here, so that no effect boxes anything: an effect can
        // reach the peer action executor, which can run another transition.
        Box::pin(async move {
            for effect in plan(&r.t) {
                self.effect(*effect, r).await;
            }
        })
        .await;
    }

    /// Carry out `effect` for `r`.
    async fn effect(&mut self, effect: Effect, r: &mut Run) {
        match effect {
            Effect::CloseSession => {
                if self.close_session(&r.peer) {
                    debug!(
                        peer = %self.peer_display_name(&r.peer),
                        transition = ?r.t,
                        "Closed stale FSP session"
                    );
                }
            }
            Effect::SettleData => {
                if let Some(held) = self.peers.get_mut(&r.peer) {
                    held.settle(&r.t);
                }
            }
            Effect::TreeCleanup => {
                if !node_fault!(RestartSkipsTreeReset)
                    && self.handle_peer_removal_tree_cleanup(&r.peer)
                {
                    for (addr, other) in self.peers.iter_mut() {
                        if *addr != r.peer {
                            other.mark_tree_announce_pending();
                        }
                    }
                }
            }
            // The forgotten filter may have been part of what this node
            // announces to every peer, and a restarted peer holds none of
            // its filters.
            Effect::BloomForgetSent => self.bloom_state.forget_sent(&r.peer),
            Effect::BloomMarkAll => {
                let peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
                self.bloom_state.mark_all_updates_needed(peers);
            }
            Effect::TreeAnnounce => self.announce(r).await,
            Effect::Unpin => {
                self.step_path(&r.peer, fips_core::proto::path::Input::Unpin)
                    .await;
            }

            Effect::DialForget => {
                if let Some(key) = &r.dial {
                    self.pending_outbound.forget(key);
                }
            }
            Effect::BloomMark => self.bloom_state.mark_update_needed(r.peer),
            Effect::BackoffReset => self.reset_lookup_backoff(),
            Effect::PathsRenewed => self.paths_renewed(&r.peer).await,
            Effect::ClearUdpIfMoved => clear_udp(self, r),
            Effect::RelinkIfMoved => {
                if r.moved != r.prior {
                    self.relink(&r.peer, r.prior.clone(), r.moved.clone()).await;
                }
            }

            Effect::MachineResolved => install::machine_resolved(self, r).await,
            Effect::RelinkInitiator => install::relink_initiator(self, r).await,
            Effect::PromotedNote => install::promoted_note(self, r).await,
            Effect::SetupNote => install::setup_note(self, r).await,
            Effect::UnheardNote => install::unheard_note(self, r).await,

            Effect::RunLinkOutputs => cross::link_outputs(self, r).await,
            Effect::RunRenewed => cross::renewed(self, r).await,
            Effect::MovedRead => cross::moved_read(self, r).await,
            Effect::SeedMtuIfMoved => cross::seed_mtu(self, r).await,
            Effect::UnpinIfOwn => cross::unpin_own(self, r).await,
            Effect::MoveNote => cross::move_note(self, r).await,
            Effect::MachineCrossed => cross::machine_crossed(self, r).await,
            Effect::DialClose => cross::dial_close(self, r).await,
            Effect::DialLinkRemoved => cross::dial_removed(self, r).await,
            Effect::KeepNote => cross::keep_note(self, r).await,
            Effect::LeaseFreed => cross::lease_freed(self, r).await,
            Effect::ReplayForget => cross::replay_forget(self, r).await,

            Effect::LinkFollow => paths::link_follow(self, r),
            Effect::FollowNote => paths::follow_note(self, r),
            Effect::ClearOldUdp => paths::clear_old(self, r),
            Effect::LinkClaim => paths::link_claim(self, r),
            Effect::SeedMtu => paths::seed_mtu(self, r),
            Effect::TightenSessions => paths::tighten(self, r),
            Effect::SwitchNote => paths::switch_note(self, r),
            Effect::LinkUnclaim => paths::link_unclaim(self, r),
            Effect::CloseQueued => paths::close_queued(self, r),

            Effect::UnmarkHeld => remove::unmark_held(self, r).await,
            Effect::CloseHeld => remove::close_held(self, r).await,
            Effect::Reconnect => remove::reconnect(self, r).await,
        }
    }

    /// Send the peer a tree announce, and log a failure with the line `r`'s
    /// transition's sites wrote; a restart's line also names the transition.
    async fn announce(&mut self, r: &Run) {
        let Err(e) = self.send_tree_announce_to_peer(&r.peer).await else {
            return;
        };
        let line = announce_line(&r.t).unwrap_or("Failed to send TreeAnnounce");
        if matches!(r.t, Transition::Restarted) {
            debug!(
                peer = %self.peer_display_name(&r.peer),
                transition = ?r.t,
                error = %e,
                "{line}"
            );
        } else {
            debug!(
                peer = %self.peer_display_name(&r.peer),
                error = %e,
                "{line}"
            );
        }
    }
}

/// Drop the peer's connected UDP socket if the pair it is on moved: a socket
/// pinned to the old 5-tuple would keep sending where the peer no longer is.
fn clear_udp(node: &mut Node, r: &Run) {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    if r.moved != r.prior {
        node.clear_connected_udp_for_peer(&r.peer);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let _ = (node, r);
}
