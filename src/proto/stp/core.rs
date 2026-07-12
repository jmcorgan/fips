//! Pure spanning-tree classification over an in-core [`TreeState`].
//!
//! The post-`update_peer` parent-switch / self-root / loop-drop / ancestry-update
//! ladder that the async `node::tree` handler inlines is extracted here as a pure
//! decision: [`Stp::classify_announce`] reads a consistent `TreeState` plus the
//! shell-passed facts (`peer_costs`, `skip`, and the pre-computed `switch_suppressed`
//! verdict of the flap-dampening / hold-down veto) and returns a [`TreeDecision`]
//! the shell drives. No I/O, no tracing, no keys, no mutation — and no clock: the
//! classify core is clock-free. The shell reads the monotonic clock at the edge,
//! computes the veto verdict via `TreeState::is_switch_suppressed`, and passes the
//! resulting bool in; `evaluate_parent` distinguishes mandatory from discretionary
//! switches and the ladder applies the veto only to the discretionary arm.
//!
//! [`TreeState`] lives beside this module in `proto/stp/state.rs`.

use alloc::collections::{BTreeMap, BTreeSet};

use super::TreeState;
use crate::NodeAddr;

/// Empty namespace anchor for the STP classify ladder (like `Mmp`/`Fmp`).
///
/// The tree state lives on the (soon in-core) [`TreeState`], not here; `Stp`
/// exists only to namespace the pure classification functions.
pub(crate) struct Stp;

/// A structured spanning-tree transition the shell matches and drives.
///
/// The core emits only the structural decision; every effect (sign, coord-cache
/// invalidation, discovery-backoff reset, metrics, fan-out send, bloom mark) runs
/// shell-side while driving the returned variant. The `classify_announce` and
/// `classify_periodic` ladders produce these variants; the removal (`ParentLost`)
/// variant arrives with its own stage.
pub(crate) enum TreeDecision {
    /// `evaluate_parent` picked a (different) parent: switch to it. Shell:
    /// `set_parent(new_parent, new_seq, ts)` -> flap_dampened; `recompute_coords`;
    /// sign; `invalidate_via_node`; reset_backoff;
    /// metrics(parent_switches[, flap_dampened]); send_all;
    /// bloom.mark_all_updates_needed.
    Switch { new_parent: NodeAddr, new_seq: u64 },

    /// `evaluate_parent` None && !is_root && should_be_root: self-promote to root.
    /// Shell: `become_root`; sign; `invalidate_other_roots`; reset_backoff;
    /// metrics(parent_switches); send_all;
    /// bloom.mark_all_updates_needed.
    SelfRoot,

    /// parent == from && parent's ancestry now contains us: drop parent. Shell:
    /// metrics(loop_detected); `handle_parent_lost` -> if changed { sign;
    /// `invalidate_via_node` + `invalidate_other_roots`; reset_backoff; send_all }.
    LoopDrop,

    /// parent == from, no loop: keep parent, recompute, re-announce iff coords
    /// changed. Shell: capture `old_addrs` before mutation; `set_parent(parent,
    /// new_seq, ts)`; recompute; sign; `invalidate_via_node`; reset_backoff; THEN
    /// if `old_addrs != new_addrs` { metrics(ancestry_changed); send_all;
    /// bloom.mark_changed_peers }.
    AncestryUpdate { parent: NodeAddr, new_seq: u64 },

    /// Periodic no-change: re-broadcast our current declaration for eventual
    /// consistency, no state change. Produced only by `classify_periodic` when
    /// neither a parent switch nor a self-root promotion is warranted. Shell:
    /// send_all (no sign, no invalidate, no metrics, no bloom).
    PeriodicRebroadcast,

    /// Removal path: the removed peer was our parent and `handle_parent_lost`
    /// changed our tree state (reparented onto an alternative or self-rooted).
    /// Produced only by the removal drive in
    /// `node::tree::handle_peer_removal_tree_cleanup`, never by `classify_announce`
    /// or `classify_periodic`. Unlike the other variants this is not a pure
    /// classification: `handle_parent_lost` is a `&mut` mutator whose returned
    /// `changed` bool IS the decision, so the shell mutates first and reads the
    /// outcome. Shell: sign; `invalidate_via_node` + `invalidate_other_roots`;
    /// (the `parent_losses` metric is stamped before the mutation, and the caller
    /// announces).
    ParentLost,

    /// No tree transition warranted.
    NoChange,
}

/// Outcome of `TreeState::evaluate_parent`: whether a parent switch is warranted
/// and, if so, whether it is mandatory (bypasses the flap/hold-down veto) or
/// discretionary (the shell applies the veto before switching).
pub(crate) enum ParentEval {
    /// Path-breaking / root-correcting switch — always taken, veto bypassed.
    Mandatory(NodeAddr),
    /// Improvement switch — taken only if the shell's veto is not active.
    Discretionary(NodeAddr),
    /// No switch warranted.
    None,
}

impl ParentEval {
    /// The switch target if one is warranted IGNORING the veto (i.e. treating a
    /// discretionary candidate as taken). Convenience for tests/paths that do not
    /// engage the veto. Returns `None` only for `ParentEval::None`.
    #[cfg(test)]
    pub(crate) fn switch_target(&self) -> Option<NodeAddr> {
        match self {
            ParentEval::Mandatory(a) | ParentEval::Discretionary(a) => Some(*a),
            ParentEval::None => Option::None,
        }
    }
}

impl Stp {
    /// Classify an inbound, already-validated TreeAnnounce into a [`TreeDecision`].
    ///
    /// Pure: reads the post-`update_peer` `tree` plus the shell-passed `peer_costs`
    /// (per-peer link cost), `skip` (non-full/leaf peers excluded from parent
    /// candidacy — empty on master, `non_full_peers()` on next), and the
    /// pre-computed `switch_suppressed` veto verdict (the shell reads the clock and
    /// calls `TreeState::is_switch_suppressed`; a discretionary switch is skipped
    /// while it is true, a mandatory switch ignores it). Mirrors the inline ladder
    /// in `node::tree::handle_tree_announce`: parent-switch, else self-root, else
    /// (same-parent) loop-drop or ancestry-update, else no change.
    pub(crate) fn classify_announce(
        tree: &TreeState,
        from: NodeAddr,
        peer_costs: &BTreeMap<NodeAddr, f64>,
        skip: &BTreeSet<NodeAddr>,
        switch_suppressed: bool,
    ) -> TreeDecision {
        let switch = match tree.evaluate_parent(peer_costs, skip) {
            ParentEval::Mandatory(p) => Some(p),
            ParentEval::Discretionary(p) if !switch_suppressed => Some(p),
            ParentEval::Discretionary(_) | ParentEval::None => None,
        };
        if let Some(new_parent) = switch {
            let new_seq = tree.my_declaration().sequence() + 1;
            TreeDecision::Switch {
                new_parent,
                new_seq,
            }
        } else if !tree.is_root() && tree.should_be_root() {
            TreeDecision::SelfRoot
        } else if !tree.is_root() && *tree.my_declaration().parent_id() == from {
            // Same parent: loop if parent's ancestry now contains us, else the
            // parent's ancestry changed and we recompute + (maybe) re-announce.
            if let Some(parent_coords) = tree.peer_coords(&from)
                && parent_coords.contains(tree.my_node_addr())
            {
                TreeDecision::LoopDrop
            } else {
                let new_seq = tree.my_declaration().sequence() + 1;
                TreeDecision::AncestryUpdate {
                    parent: from,
                    new_seq,
                }
            }
        } else {
            TreeDecision::NoChange
        }
    }

    /// Classify a periodic parent re-evaluation into a [`TreeDecision`].
    ///
    /// Pure: reads the current `tree` plus the shell-passed `peer_costs`, `skip`
    /// (empty on master, `non_full_peers()` on next), and the pre-computed
    /// `switch_suppressed` veto verdict (see `classify_announce`; a discretionary
    /// switch is skipped while true, a mandatory switch ignores it). Mirrors the
    /// periodic ladder in `node::tree::check_periodic_parent_reeval`: parent-switch,
    /// else self-root, else re-broadcast for eventual consistency. Unlike
    /// `classify_announce`, the periodic path has no same-parent loop-drop /
    /// ancestry-update arms — a periodic tick has no announcing peer, so those cases
    /// never arise; the no-change tail is a re-broadcast rather than a true no-op.
    pub(crate) fn classify_periodic(
        tree: &TreeState,
        peer_costs: &BTreeMap<NodeAddr, f64>,
        skip: &BTreeSet<NodeAddr>,
        switch_suppressed: bool,
    ) -> TreeDecision {
        let switch = match tree.evaluate_parent(peer_costs, skip) {
            ParentEval::Mandatory(p) => Some(p),
            ParentEval::Discretionary(p) if !switch_suppressed => Some(p),
            ParentEval::Discretionary(_) | ParentEval::None => None,
        };
        if let Some(new_parent) = switch {
            let new_seq = tree.my_declaration().sequence() + 1;
            TreeDecision::Switch {
                new_parent,
                new_seq,
            }
        } else if !tree.is_root() && tree.should_be_root() {
            TreeDecision::SelfRoot
        } else {
            TreeDecision::PeriodicRebroadcast
        }
    }

    /// Whether to echo our current position back to an announcing peer.
    ///
    /// Root election is smallest-NodeAddr-wins, so a peer advertising a strictly
    /// worse (higher) root than ours has a stale/pre-attachment view and can attach
    /// through us; only the better-rooted side echoes.
    pub(crate) fn should_echo(announce_root: &NodeAddr, our_root: &NodeAddr) -> bool {
        announce_root > our_root
    }
}
