//! What the node runs for a transition outside the peer's record, as a list
//! of effects in their order.
//!
//! [`plan`] gives each [`Transition`] its effects, the statements its sites
//! ran, in the order they ran them. `Node::run`, in `mod.rs`, runs them one
//! after another. A step that consults the table for its value says so; the
//! others ran unconditionally at every site of their transition, or under the
//! condition their name states.

#![deny(clippy::wildcard_enum_match_arm)]

use crate::node::settle::table::{Transition, listed};

listed! {
    /// One step the node takes for a transition.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    Effect {
        /// Close the end-to-end session with the peer and the path MTU entry
        /// it tightened.
        CloseSession,
        /// Apply the transition to the peer's record.
        SettleData,
        /// Remove the peer from the spanning tree's state, and if this node's
        /// own tree state changed, mark a tree announce pending to every
        /// other peer.
        TreeCleanup,
        /// Forget the filter last sent to the peer.
        BloomForgetSent,
        /// Mark a filter update due to every peer.
        BloomMarkAll,
        /// Send the peer a tree announce, logging a failure with the line its
        /// transition's sites wrote.
        TreeAnnounce,
        /// End the operator's pin on the peer's link.
        Unpin,

        /// Forget this node's dial that the transition answered or ended.
        DialForget,
        /// Mark a filter update due to the peer.
        BloomMark,
        /// Reset the discovery backoff.
        BackoffReset,
        /// Tell the path feeds the peer's path machine started again, and
        /// offer it the peer's configured addresses.
        PathsRenewed,
        /// Drop the peer's connected UDP socket, if the pair it is on moved.
        ClearUdpIfMoved,
        /// Move the transport's mark of the peer from the pair it left to the
        /// one it is on, if the pair moved.
        RelinkIfMoved,

        /// Feed the outcome of the promotion back to the leg's control
        /// machine and run what it returns.
        MachineResolved,
        /// Mark the link a dial of this node's promoted, at the transport.
        RelinkInitiator,
        /// Log the promotion of a dial of this node's.
        PromotedNote,
        /// Store the setup's msg2, msg1 and ephemeral on the peer.
        SetupNote,
        /// Remember an unheard peering's setup ephemeral.
        UnheardNote,

        /// Run the rekey machine's outputs from the move.
        RunLinkOutputs,
        /// Run the path machine's outputs from its renewal.
        RunRenewed,
        /// Read the pair the peer is on after the move.
        MovedRead,
        /// Seed the path MTU from the pair the peer moved to, if it moved.
        SeedMtuIfMoved,
        /// End the operator's pin if the move answered this node's own or a
        /// later dial and the peer is now on that dial's session.
        UnpinIfOwn,
        /// Log the replays suppressed during the move and the move itself.
        MoveNote,
        /// Waive the live audit's entry check for a moved link left with no
        /// entry, naming the move; test and debug builds only.
        WaiverIfNoEntry,
        /// Tell the peer's control machine how the crossing resolved.
        MachineCrossed,
        /// Close the dial's connection unless the peer runs on it.
        DialClose,
        /// Remove the dial's link.
        DialLinkRemoved,
        /// Log the crossing kept on the peer's inbound session.
        KeepNote,
        /// Free the session index of the dial a kept crossing closes.
        LeaseFreed,

        /// Move the link's lookup entry from the path's old pair to its new.
        LinkFollow,
        /// Log the path's move.
        FollowNote,
        /// Drop the connected UDP socket of the path that was active.
        ClearOldUdp,
        /// Claim the newly active pair for the link in the lookup.
        LinkClaim,
        /// Seed the peer's path MTU from the newly active pair.
        SeedMtu,
        /// Tighten every session whose next hop is the peer to the new
        /// pair's MTU.
        TightenSessions,
        /// Log the switch.
        SwitchNote,
        /// Unclaim the released pair from the link's lookup while the link
        /// lives.
        LinkUnclaim,
        /// Queue the released pair's connection to close unless it is kept or
        /// another peer's link uses it.
        CloseQueued,

        /// Clear the transport's mark at the pair the peer was on, by the
        /// table's cell.
        UnmarkHeld,
        /// Close the transport's connection at the pair the peer was on, by
        /// the table's cell.
        CloseHeld,
        /// Note the link dead for a reconnect, or drop a pending reconnect,
        /// by the table's cell.
        Reconnect,
    }
}

/// A removal's effects after the peer is taken out of the node's maps.
const REMOVE: &[Effect] = &[Effect::UnmarkHeld, Effect::CloseHeld, Effect::Reconnect];

/// The promotion of a dial of this node's, answered by its msg2.
const PROMOTE_OUT: &[Effect] = &[
    Effect::MachineResolved,
    Effect::RelinkInitiator,
    Effect::PathsRenewed,
    Effect::DialForget,
    Effect::PromotedNote,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
];

/// The promotion of a msg1 this node answered.
const PROMOTE_IN: &[Effect] = &[
    Effect::MachineResolved,
    Effect::PathsRenewed,
    Effect::SetupNote,
    Effect::UnheardNote,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
];

/// A replacement found at this node's own dial: the removal, then the
/// promotion of the dial.
const REPLACE_OUT: &[Effect] = &[
    Effect::UnmarkHeld,
    Effect::CloseHeld,
    Effect::Reconnect,
    Effect::MachineResolved,
    Effect::RelinkInitiator,
    Effect::PathsRenewed,
    Effect::DialForget,
    Effect::PromotedNote,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
];

/// A replacement by a msg1 this node answered: the removal, then the
/// promotion of the msg1.
const REPLACE_IN: &[Effect] = &[
    Effect::UnmarkHeld,
    Effect::CloseHeld,
    Effect::Reconnect,
    Effect::MachineResolved,
    Effect::PathsRenewed,
    Effect::SetupNote,
    Effect::UnheardNote,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
];

/// The effects `t` runs, in their order.
pub(in crate::node) fn plan(t: &Transition) -> &'static [Effect] {
    match t {
        Transition::Promote { initiator, .. } => {
            if *initiator {
                PROMOTE_OUT
            } else {
                PROMOTE_IN
            }
        }
        Transition::Replace { initiator, .. } => {
            if *initiator {
                REPLACE_OUT
            } else {
                REPLACE_IN
            }
        }
        // The rekey machine moved onto the dial's session and the path
        // machine renewed, then what follows a move to another pair, then the
        // dial's leg ends.
        Transition::Move { .. } => &[
            Effect::RunLinkOutputs,
            Effect::RunRenewed,
            Effect::PathsRenewed,
            Effect::MovedRead,
            Effect::ClearUdpIfMoved,
            Effect::SeedMtuIfMoved,
            Effect::RelinkIfMoved,
            Effect::UnpinIfOwn,
            Effect::MoveNote,
            Effect::WaiverIfNoEntry,
            Effect::MachineCrossed,
            Effect::DialForget,
            Effect::DialClose,
            Effect::DialLinkRemoved,
            Effect::TreeAnnounce,
            Effect::BloomMark,
            Effect::BackoffReset,
        ],
        Transition::Keep { .. } => &[
            Effect::KeepNote,
            Effect::LeaseFreed,
            Effect::MachineCrossed,
            Effect::DialForget,
            Effect::DialClose,
            Effect::DialLinkRemoved,
            Effect::TreeAnnounce,
            Effect::BloomMark,
            Effect::BackoffReset,
        ],
        // A cutover runs its statements at the rekey handler, which looks
        // the filter's mark up in the table.
        Transition::Cutover { .. } => &[],
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
        Transition::Roam => &[Effect::ClearUdpIfMoved, Effect::RelinkIfMoved],
        Transition::Follow => &[Effect::LinkFollow, Effect::FollowNote],
        Transition::Switch => &[
            Effect::ClearOldUdp,
            Effect::LinkClaim,
            Effect::SeedMtu,
            Effect::TightenSessions,
            Effect::SwitchNote,
        ],
        Transition::Release { .. } => &[Effect::LinkUnclaim, Effect::CloseQueued],
        Transition::Remove { .. } => REMOVE,
    }
}
