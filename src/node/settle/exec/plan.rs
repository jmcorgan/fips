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

        /// Tell the transport which of two connections at the promoted
        /// link's address to keep, now that the handshake named the peer.
        SettleLink,
        /// Feed the outcome of the promotion back to the leg's control
        /// machine and run what it returns.
        MachineResolved,
        /// Mark the link a dial of this node's promoted, at the transport.
        RelinkInitiator,
        /// Log the promotion of a dial of this node's.
        PromotedNote,
        /// Store on the peer the msg2 that answered the setup's msg1.
        SetupNote,

        /// Run the rekey machine's outputs from the move.
        RunLinkOutputs,
        /// Run the path machine's outputs from its renewal.
        RunRenewed,
        /// Offer the pair the link left to the heard feed, if the move left
        /// one.
        HeardLeft,
        /// Hold the peer's link record, its control machine and its carrier
        /// readings on the dial's link, if the move left another.
        HoldDial,
        /// Read the pair the peer is on after the move.
        MovedRead,
        /// Seed the path MTU from the pair the peer moved to, if it moved.
        SeedMtuIfMoved,
        /// Log the move, and at a dial's msg2 the replays suppressed during
        /// it.
        MoveNote,
        /// Tell the peer's control machine how the crossing resolved.
        MachineCrossed,
        /// Close the losing link's connection unless a live link uses it:
        /// the link a move left, or the dial's.
        LoserClose,
        /// Remove the losing link: the link a move left, or the link of the
        /// handshake the crossing ended, this node's dial or the inbound leg
        /// the peer's msg3 completed.
        LoserRemoved,
        /// Drop the control machine of the inbound leg the peer's msg3
        /// completed.
        LegMachineRemoved,
        /// Log the crossing kept on the session the peer holds.
        KeepNote,
        /// Free the session index of the handshake a kept crossing ends.
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
    Effect::SettleLink,
    Effect::PromotedNote,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
    Effect::DialForget,
    Effect::RelinkInitiator,
    Effect::MachineResolved,
    Effect::PathsRenewed,
];

/// The promotion of an inbound leg the peer's msg3 completed.
const PROMOTE_IN: &[Effect] = &[
    Effect::SettleLink,
    Effect::SetupNote,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
    Effect::MachineResolved,
    Effect::PathsRenewed,
];

/// A replacement found at this node's own dial: the removal, then the
/// promotion of the dial.
const REPLACE_OUT: &[Effect] = &[
    Effect::UnmarkHeld,
    Effect::CloseHeld,
    Effect::Reconnect,
    Effect::SettleLink,
    Effect::PromotedNote,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
    Effect::DialForget,
    Effect::RelinkInitiator,
    Effect::MachineResolved,
    Effect::PathsRenewed,
];

/// A replacement by a msg3 this node received: the removal, then the
/// promotion of the leg the msg3 completed.
const REPLACE_IN: &[Effect] = &[
    Effect::UnmarkHeld,
    Effect::CloseHeld,
    Effect::Reconnect,
    Effect::SettleLink,
    Effect::SetupNote,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
    Effect::MachineResolved,
    Effect::PathsRenewed,
];

/// A crossing won by this node's dial at its msg2: the rekey machine moved
/// onto the dial's session and the path machine renewed, the peer held on
/// the dial's link, then what follows a move to another pair, the note, the
/// control machine, and the link the move left ends.
const MOVE_DIAL: &[Effect] = &[
    Effect::RunLinkOutputs,
    Effect::RunRenewed,
    Effect::HoldDial,
    Effect::PathsRenewed,
    Effect::HeardLeft,
    Effect::MovedRead,
    Effect::ClearUdpIfMoved,
    Effect::SeedMtuIfMoved,
    Effect::RelinkIfMoved,
    Effect::MoveNote,
    Effect::MachineCrossed,
    Effect::DialForget,
    Effect::LoserClose,
    Effect::LoserRemoved,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
];

/// A crossing settled at the peer's msg3 by moving onto the inbound leg it
/// completed: the rekey machine moved onto the leg's session, the path
/// machine renewed, what follows a move to another pair, the note, and the
/// leg ends. The peer stays held on the link it dialed.
const MOVE_LEG: &[Effect] = &[
    Effect::RunLinkOutputs,
    Effect::RunRenewed,
    Effect::PathsRenewed,
    Effect::MovedRead,
    Effect::ClearUdpIfMoved,
    Effect::SeedMtuIfMoved,
    Effect::RelinkIfMoved,
    Effect::MoveNote,
    Effect::LoserRemoved,
    Effect::LegMachineRemoved,
];

/// A crossing lost at this node's dial's msg2: the peer kept on the session
/// it holds and the dial's leg ends.
const KEEP_DIAL: &[Effect] = &[
    Effect::KeepNote,
    Effect::LeaseFreed,
    Effect::MachineCrossed,
    Effect::DialForget,
    Effect::LoserClose,
    Effect::LoserRemoved,
    Effect::TreeAnnounce,
    Effect::BloomMark,
    Effect::BackoffReset,
];

/// A crossing settled at the peer's msg3 by keeping the session the peer
/// holds: the leg's index freed, the note, and the leg ends.
const KEEP_LEG: &[Effect] = &[
    Effect::LeaseFreed,
    Effect::KeepNote,
    Effect::LoserRemoved,
    Effect::LegMachineRemoved,
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
        Transition::Move { inbound, .. } => {
            if *inbound {
                MOVE_LEG
            } else {
                MOVE_DIAL
            }
        }
        Transition::Keep { inbound, .. } => {
            if *inbound {
                KEEP_LEG
            } else {
                KEEP_DIAL
            }
        }
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
