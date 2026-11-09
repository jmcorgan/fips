//! What each change to a held peer does to each piece of its state, as data.
//!
//! A [`Transition`] is one thing the code does to a peer. A [`Row`] is one
//! piece of what the node holds per peer, split where the pieces behave
//! differently. [`cell`] gives the value of one row at one transition, and
//! [`owner`] says who holds the row. The rule is written once here, as nested
//! total matches with no wildcard, so a new row, transition or cause does not
//! compile until it has taken a side at each.
//!
//! The rule states today's behaviour, including where that behaviour is known
//! to be wrong. A transition that has not been routed through the table still
//! runs its own statements. `src/node/settle/tests/table.rs` holds the same
//! rule as data, one line per cell.

#![deny(clippy::wildcard_enum_match_arm)]

use crate::proto::rekey::Role;
use crate::proto::settle::output::Why;
use crate::transport::LinkId;

/// An enum whose `ALL`, in test builds, lists its variants, so that a variant
/// cannot be left off the list.
macro_rules! listed {
    ($(#[$outer:meta])* $name:ident { $($(#[$inner:meta])* $variant:ident,)* }) => {
        $(#[$outer])*
        pub(crate) enum $name {
            $($(#[$inner])* $variant,)*
        }

        impl $name {
            /// Every variant, in declaration order.
            #[cfg(test)]
            pub(crate) const ALL: &'static [$name] = &[$($name::$variant),*];
        }
    };
}

/// One thing the code does to a held peer.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Transition {
    /// A peer installed for an identity not held, by a msg2 this node
    /// initiated or by a msg1 it answered.
    Promote {
        // Named so a site cannot leave out the link it installs; no cell reads
        // it, since a cell states what happens and not to which link.
        #[allow(dead_code)]
        link: LinkId,
        initiator: bool,
    },
    /// The held peer torn down and a new one installed, by a msg3 at a new
    /// epoch (`Restart`), or this node's own dial answered by a restarted
    /// peer (`OwnRestart`, the only one this node initiated). A same-epoch
    /// handshake never replaces a held peer on this line, so `Replacement`
    /// has no site.
    Replace {
        // As in `Promote`.
        #[allow(dead_code)]
        link: LinkId,
        initiator: bool,
        why: Why,
    },
    /// The held peer moved onto the session of another handshake with it: a
    /// crossing won by this node's own dial at its msg2, or, with `inbound`,
    /// a crossing settled at the peer's msg3 by moving onto the inbound leg
    /// it completed. `own` would say this node's own or a later dial was
    /// answered; on this line only the tie-break moves a peer, so no site
    /// sets it. `built` says the peer's rekey machine was rebuilt on the new
    /// session; without it the move was refused or failed and renewed
    /// nothing.
    Move {
        // Named so that a site cannot leave out the link whose session the
        // peer moves onto; no cell reads it yet.
        #[allow(dead_code)]
        dial: LinkId,
        own: bool,
        built: bool,
        inbound: bool,
    },
    /// A crossing lost: the node keeps the session it holds and closes the
    /// other handshake's link, its own dial at the msg2, or, with `inbound`,
    /// the inbound leg the peer's msg3 completed.
    Keep {
        // As in `Move`.
        #[allow(dead_code)]
        dial: LinkId,
        inbound: bool,
    },
    /// A rekey's new session installed, this node having played `role`.
    Cutover { role: Role },
    /// A restart found at a rekey: the link stays, its cutover ran first.
    Restarted,
    /// An authenticated frame moved a link's one path to another address.
    Roam,
    /// A path message moved a path of a link of more than one path.
    Follow,
    /// The active path changed, for any cause.
    Switch,
    /// A path discarded while the link lives; with `keep`, its connection
    /// stays open.
    Release { keep: bool },
    /// The peer removed with nothing installed in its place.
    Remove { why: Why },
}

listed! {
    /// A row of the record each peer holds, `PeerData`: the state a transition
    /// sets through the record's `settle`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(not(test), allow(dead_code))]
    DataRow {
        /// The link's MMP counters.
        Mmp,
        /// The peer's filter, its sequence and when it was received.
        PeerFilter,
        /// `pending_filter_update`.
        FilterPending,
        /// The peer's declaration and ancestry.
        TreePosition,
        /// `pending_tree_announce`.
        TreePending,
        /// When a tree announce last went to the peer.
        TreeStamp,
        /// The interval between tree announces.
        TreeInterval,
        /// `frame_heard`, `heard_at`.
        Heard,
        /// The stored msg2.
        StoredSetup,
        /// `link_stats`, `authenticated_at`, `last_seen`, the heartbeat stamps
        /// and `failed_idx`.
        Stats,
        /// The peer's negotiated profile and which reports go to it.
        Profile,
        /// `prev_frames`.
        PrevFrames,
        /// `hs_lines`.
        HsLines,
        /// `replay_base`.
        ReplayBase,
        /// `replay_total`, the count decrypt workers hold a clone of.
        ReplayTotal,
    }
}

/// Declares [`Row`] with the record's rows under `Data`, and in test builds
/// `Row::all`, so that a row cannot be left off the list.
macro_rules! rows {
    ($($(#[$inner:meta])* $variant:ident,)*) => {
        /// One piece of what the node holds per peer.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[cfg_attr(not(test), allow(dead_code))]
        pub(crate) enum Row {
            /// A row of the peer's record.
            Data(DataRow),
            $($(#[$inner])* $variant,)*
        }

        impl Row {
            /// Every row, the record's first.
            #[cfg(test)]
            pub(crate) fn all() -> Vec<Row> {
                DataRow::ALL
                    .iter()
                    .copied()
                    .map(Row::Data)
                    .chain([$(Row::$variant),*])
                    .collect()
            }
        }
    };
}

rows! {
    /// The link record and the peer's `link_id`.
    Link,
    /// The reverse lookup's entries for the peer's link.
    Index,
    /// The bundle's paths and which is active.
    Paths,
    /// The bundle's capability, candidates, dwell and peer-active.
    Capability,
    /// The bundle's operator pin and cost hold.
    Pin,
    /// The bundle's failure count per path.
    PathFailures,
    /// The bundle's connected UDP socket per path.
    ConnectedUdp,
    /// The peer's rekey machine and its indices.
    RekeyMachine,
    /// The setup record inside the rekey machine.
    SetupRecord,
    /// The peer's identity and npub.
    Identity,
    /// The handshake leg and the control machine.
    ControlMachine,
    /// The transport's connection.
    Connection,
    /// The BLE transport's verified mark.
    BleMark,
    /// The bootstrap transport's cleanup.
    Bootstrap,
    /// This node's own dials.
    Dials,
    /// The path MTU seed and clamp.
    PathMtu,
    /// The filter's send state.
    FilterSend,
    /// The tree state and this node's announce.
    Tree,
    /// The end-to-end session.
    Session,
    /// The restart dampener.
    Dampener,
    /// The note of a session that ended with no frame.
    Silent,
    /// The reconnect schedule.
    Reconnect,
    /// The identity cache.
    IdentityCache,
    /// The lookup backoff.
    LookupBackoff,
    /// `paths.connecting`.
    PathConnects,
    /// `paths.closing`.
    PathCloses,
    /// `paths.listings`.
    PathListings,
    /// `paths.carrier`.
    PathCarrier,
}

/// What a transition does to a row of the record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum DataCell {
    /// Nothing.
    Keep,
    /// Starts again, keeping what the row's own reset says it carries.
    Reset,
    /// Rolled over to a new period.
    Roll,
    /// The base moves up to the total, which stays.
    Base,
    /// Emptied.
    Clear,
    /// A new record's value.
    New,
    /// Ends with the record.
    Drop,
}

/// What a transition does to a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Cell {
    /// A row of the record.
    Data(DataCell),
    /// No code at this transition reaches this cause.
    NoSite,
    /// Nothing.
    Keep,
    /// The row has no meaning at this transition.
    NotApplicable,
    /// Starts anew.
    New,
    /// Starts anew, holding nothing.
    Empty,
    /// Starts at zero.
    Zero,
    /// Ends with the peer.
    Gone,
    /// Dropped.
    Dropped,
    /// Closed.
    Closed,
    /// Removed.
    Removed,
    /// Cleared.
    Cleared,

    /// The handshake's link becomes the peer's.
    HandshakeLink,
    /// The old link closed, the new one adopted.
    OldClosedNewAdopted,
    /// The dial's link closed, the peer's kept.
    DialClosed,

    /// The dial's entry, carried from the dial.
    FromDial,
    /// The inbound leg's entry, opened at its msg1, carried from the leg.
    FromLeg,
    /// The old entry dropped, then as [`Cell::FromDial`].
    OldDroppedFromDial,
    /// The old entry dropped, then as [`Cell::FromLeg`].
    OldDroppedFromLeg,
    /// Each released pair's entry unclaimed, the new pair not claimed and the
    /// dial's dropped.
    ReleasedUnclaimedDialDropped,
    /// Each released pair's entry unclaimed, the new pair not claimed and the
    /// leg's dropped, its key handed back to a live link it displaced.
    ReleasedUnclaimedLegDropped,
    /// The dial's entry dropped.
    DialDropped,
    /// The leg's entry dropped, its key handed back to a live link it
    /// displaced.
    LegDropped,
    /// The entry moved, if it names the link.
    Followed,
    /// The new pair claimed, if free.
    Claimed,
    /// The entry unclaimed, only if it names the link and is not the pair of
    /// the link's own record, which keeps naming it while it lives.
    UnclaimedOffRecord,

    /// A new path at the handshake's source.
    NewAtSource,
    /// The old paths closed, a new one at the handshake's source.
    OldClosedNew,
    /// Renewed to the new pair.
    Renewed,
    /// The one path re-addressed.
    OnePathReaddressed,
    /// One of several paths re-addressed.
    PathReaddressed,
    /// A different path is active.
    ActiveChanged,
    /// That path gone.
    PathGone,

    /// Reset by the bundle's renew.
    ResetByRenew,
    /// The discarded pair is held back among the candidates, or, where its
    /// transport was removed, that transport's candidates are forgotten.
    HeldBackOrForgotten,
    /// The operator's pin ends.
    PinEnds,
    /// The cost hold starts at the change of active path; a pin that made
    /// the change was set in the same step.
    HoldStarts,
    /// Kept if the new pair's path was held, otherwise zero.
    KeptIfHeld,
    /// Gone with its path.
    GoneWithPath,

    /// Released slots cleared, and the active slot if the pair changed.
    ReleasedClearedActiveIfChanged,
    /// Cleared if the pair changed; a standby path's slot is cleared.
    ClearedIfChanged,
    /// The moved path's slot cleared.
    MovedCleared,
    /// The slot of the path that was active cleared.
    OldActiveCleared,
    /// The discarded path's slot cleared.
    PathCleared,

    /// Built new, with an empty replay record.
    NewEmptyRecord,
    /// The old one closed, a new one built with an empty replay record.
    OldClosedNewEmptyRecord,
    /// Closed as a move and rebuilt from what it carried.
    ClosedRebuilt,
    /// The new session's lease released.
    LeaseReleased,
    /// The dial's lease freed.
    DialLeaseFreed,
    /// The leg's lease freed.
    LegLeaseFreed,
    /// Stepped by its owner.
    Stepped,
    /// Kept, with later bindings on the new active transport.
    KeptBindingsFollow,

    /// Carried across the rebuild.
    Carried,

    /// The leg's machine survives as the peer's.
    LegSurvives,
    /// The old peer's removed, then as [`Cell::LegSurvives`].
    OldRemovedLegSurvives,
    /// The dial's removed, the peer's told how the crossing resolved.
    DialRemovedPeerStepped,
    /// The leg's machine removed; the peer's is not told.
    LegRemoved,
    /// Stepped first and then removed.
    SteppedThenRemoved,

    /// Paths the peer is not active on queued to close, unless another peer
    /// proves the pair. A link not known capable keeps them all.
    UnkeptQueued,
    /// As [`Cell::UnkeptQueued`], and the current pair closed, unguarded.
    UnkeptQueuedCurrentClosed,
    /// The dial's connection closed unless another peer proves its pair.
    DialClosedUnlessProven,
    /// As [`Cell::DialClosedUnlessProven`], with released paths as
    /// [`Cell::UnkeptQueued`].
    DialClosedReleasedQueued,
    /// Released paths as [`Cell::UnkeptQueued`]; the leg's connection is the
    /// one the peer moves onto, and stays.
    ReleasedQueued,
    /// Queued unless another peer proves it, and drained in the same step.
    QueuedDrained,

    /// Marked.
    Marked,
    /// Marked at the peer's first frame.
    MarkedAtFirstFrame,
    /// The old mark cleared, then as [`Cell::Marked`].
    OldClearedMarked,
    /// The old mark cleared, then as [`Cell::MarkedAtFirstFrame`].
    OldClearedMarkedAtFirstFrame,
    /// The mark moved from the link the peer left to the one it is on.
    Relinked,
    /// Cleared if the drain closes the connection.
    ClearedIfDrained,

    /// Checked: unused means no path of any link on it.
    Checked,
    /// The check does not run.
    NotRun,

    /// The answered dial removed.
    AnsweredRemoved,

    /// Seeded.
    Seeded,
    /// Released, and seeded.
    ReleasedThenSeeded,
    /// Seeded again if the pair moved.
    ReseededIfMoved,
    /// Released and seeded again, by closing the session.
    ReleasedReseeded,
    /// Not seeded again.
    NotReseeded,
    /// Seeded again outright, every session through the peer tightened.
    ReseededTightened,
    /// Released.
    Released,

    /// The peer's state removed, all others marked, and then the peer marked.
    RemovedOthersMarkedThenMarked,
    /// The peer's state removed, all others marked.
    RemovedOthersMarked,
    /// What was sent forgotten, all marked.
    ForgottenAllMarked,

    /// An announce sent.
    Announced,
    /// Cleaned up, others pending if it changed, and an announce sent.
    CleanedOthersPendingAnnounced,
    /// Cleaned up, others pending if it changed.
    CleanedOthersPending,

    /// Stamped.
    Stamped,
    /// Not stamped.
    NotStamped,
    /// Noted if no frame arrived since the promotion.
    NotedIfNoFrame,

    /// Noted as a dead link.
    NotedDead,
    /// Noted as a dead link, then removed.
    NotedDeadThenRemoved,

    /// Registered.
    Registered,
    /// Reset.
    BackoffReset,

    /// Forgotten.
    Forgotten,
    /// Queued.
    Queued,
    /// Queued; with multipath on, and the peer's pair moved, the step that
    /// offers the pair it left drains the queue.
    QueuedDrainedIfMoved,

    /// Forgotten and offered again, with multipath on.
    ForgottenOffered,
    /// Goes at the next discovery tick.
    GoneAtDiscovery,
    /// Goes at the next read.
    GoneAtNextRead,
}

listed! {
    /// The node's state outside the peer that a row names, one field or map
    /// each.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[cfg_attr(not(test), allow(dead_code))]
    Facet {
        /// `sessions`.
        Session,
        /// `path_mtu_lookup` and `path_mtu_seeded_by`.
        PathMtu,
        /// `bloom_state`.
        Bloom,
        /// The tree state.
        Tree,
        /// `restart_dampener`.
        Dampener,
        /// `silent_sessions`.
        Silent,
        /// The reconnect schedule.
        Reconnect,
        /// The BLE transport's verified marks.
        Verified,
        /// The bootstrap transports.
        Bootstrap,
        /// The transport's connections.
        Connection,
        /// The identity cache.
        Identity,
        /// The lookup backoff.
        LookupBackoff,
        /// `paths.connecting`.
        PathConnects,
        /// `paths.closing`.
        PathCloses,
        /// `paths.listings`.
        PathListings,
        /// `paths.carrier`.
        PathCarrier,
    }
}

/// Who holds a row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum Owner {
    /// `ActivePeer` itself, and nothing writes it after construction.
    Identity,
    /// The peer's rekey machine.
    Rekey,
    /// The peer's path bundle.
    Bundle,
    /// One of the node's per-peer map wrappers in this module.
    Table,
    /// The peer's record.
    Data,
    /// A part of `Node` named by the facet.
    Facet(Facet),
}

/// Whether code at the transition reaches its cause. A cause with no site has
/// [`Cell::NoSite`] in every row outside the record.
#[cfg_attr(not(test), allow(dead_code))]
fn reached(t: &Transition) -> bool {
    match t {
        Transition::Replace { initiator, why, .. } => match why {
            Why::Restart => !initiator,
            Why::OwnRestart => *initiator,
            Why::Replacement
            | Why::Ended
            | Why::Orphaned
            | Why::Disconnect
            | Why::Dead
            | Why::Admin
            | Why::Closed => false,
        },
        // The tie-break alone moves a peer here: no site sets `own`.
        Transition::Move { own, .. } => !own,
        Transition::Remove { why } => match why {
            Why::Ended | Why::Orphaned | Why::Disconnect | Why::Dead | Why::Admin => true,
            Why::Restart | Why::Replacement | Why::OwnRestart | Why::Closed => false,
        },
        Transition::Promote { .. }
        | Transition::Keep { .. }
        | Transition::Cutover { .. }
        | Transition::Restarted
        | Transition::Roam
        | Transition::Follow
        | Transition::Switch
        | Transition::Release { .. } => true,
    }
}

/// What `t` does to a row of the record. A record ends whatever the cause, so
/// a cause with no site reads the same as one with.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn data_cell(row: DataRow, t: &Transition) -> DataCell {
    match t {
        Transition::Promote { .. } | Transition::Replace { .. } => DataCell::New,
        Transition::Remove { .. } => DataCell::Drop,
        Transition::Keep { .. }
        | Transition::Roam
        | Transition::Follow
        | Transition::Switch
        | Transition::Release { .. } => DataCell::Keep,
        Transition::Move { built, .. } => match row {
            DataRow::Mmp if *built => DataCell::Reset,
            DataRow::HsLines => DataCell::Roll,
            DataRow::ReplayBase => DataCell::Base,
            DataRow::Mmp
            | DataRow::PeerFilter
            | DataRow::FilterPending
            | DataRow::TreePosition
            | DataRow::TreePending
            | DataRow::TreeStamp
            | DataRow::TreeInterval
            | DataRow::Heard
            | DataRow::StoredSetup
            | DataRow::Stats
            | DataRow::Profile
            | DataRow::PrevFrames
            | DataRow::ReplayTotal => DataCell::Keep,
        },
        Transition::Cutover { .. } => match row {
            DataRow::Mmp | DataRow::PrevFrames => DataCell::Reset,
            DataRow::HsLines => DataCell::Roll,
            DataRow::ReplayBase => DataCell::Base,
            DataRow::PeerFilter
            | DataRow::FilterPending
            | DataRow::TreePosition
            | DataRow::TreePending
            | DataRow::TreeStamp
            | DataRow::TreeInterval
            | DataRow::Heard
            | DataRow::StoredSetup
            | DataRow::Stats
            | DataRow::Profile
            | DataRow::ReplayTotal => DataCell::Keep,
        },
        Transition::Restarted => match row {
            DataRow::PeerFilter | DataRow::TreePosition => DataCell::Clear,
            DataRow::Mmp
            | DataRow::FilterPending
            | DataRow::TreePending
            | DataRow::TreeStamp
            | DataRow::TreeInterval
            | DataRow::Heard
            | DataRow::StoredSetup
            | DataRow::Stats
            | DataRow::Profile
            | DataRow::PrevFrames
            | DataRow::HsLines
            | DataRow::ReplayBase
            | DataRow::ReplayTotal => DataCell::Keep,
        },
    }
}

/// What `t` does to `row`. For the record's rows this is [`data_cell`]; for
/// the others, a cause no code reaches gives [`Cell::NoSite`].
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn cell(row: Row, t: &Transition) -> Cell {
    use Transition as T;
    if !reached(t) && !matches!(row, Row::Data(_)) {
        return Cell::NoSite;
    }
    match row {
        Row::Data(data) => Cell::Data(data_cell(data, t)),
        Row::Link => match t {
            T::Promote { .. } => Cell::HandshakeLink,
            T::Replace { .. } => Cell::OldClosedNewAdopted,
            T::Move { .. } | T::Keep { .. } => Cell::DialClosed,
            T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
            T::Remove { .. } => Cell::Closed,
        },
        Row::Index => match t {
            T::Promote { initiator, .. } => {
                if *initiator {
                    Cell::FromDial
                } else {
                    Cell::FromLeg
                }
            }
            T::Replace { initiator, .. } => {
                if *initiator {
                    Cell::OldDroppedFromDial
                } else {
                    Cell::OldDroppedFromLeg
                }
            }
            T::Move {
                built: true,
                inbound,
                ..
            } => {
                if *inbound {
                    Cell::ReleasedUnclaimedLegDropped
                } else {
                    Cell::ReleasedUnclaimedDialDropped
                }
            }
            T::Move {
                built: false,
                inbound,
                ..
            }
            | T::Keep { inbound, .. } => {
                if *inbound {
                    Cell::LegDropped
                } else {
                    Cell::DialDropped
                }
            }
            T::Cutover { .. } | T::Restarted | T::Roam => Cell::Keep,
            T::Follow => Cell::Followed,
            T::Switch => Cell::Claimed,
            T::Release { .. } => Cell::UnclaimedOffRecord,
            T::Remove { .. } => Cell::Dropped,
        },
        Row::Paths => match t {
            T::Promote { .. } => Cell::NewAtSource,
            T::Replace { .. } => Cell::OldClosedNew,
            T::Move { built: true, .. } => Cell::Renewed,
            T::Move { built: false, .. } | T::Keep { .. } | T::Cutover { .. } | T::Restarted => {
                Cell::Keep
            }
            T::Roam => Cell::OnePathReaddressed,
            T::Follow => Cell::PathReaddressed,
            T::Switch => Cell::ActiveChanged,
            T::Release { .. } => Cell::PathGone,
            T::Remove { .. } => Cell::Closed,
        },
        Row::Capability => match t {
            T::Promote { .. } | T::Replace { .. } => Cell::New,
            T::Move { built: true, .. } => Cell::ResetByRenew,
            T::Move { built: false, .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch => Cell::Keep,
            T::Release { .. } => Cell::HeldBackOrForgotten,
            T::Remove { .. } => Cell::Gone,
        },
        Row::Pin => match t {
            T::Promote { .. } | T::Replace { .. } => Cell::Empty,
            T::Move {
                own: true,
                built: true,
                ..
            }
            | T::Restarted => Cell::PinEnds,
            T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Roam
            | T::Follow
            | T::Release { .. } => Cell::Keep,
            T::Switch => Cell::HoldStarts,
            T::Remove { .. } => Cell::Gone,
        },
        Row::PathFailures => match t {
            T::Promote { .. } | T::Replace { .. } => Cell::Zero,
            T::Move { built: true, .. } => Cell::KeptIfHeld,
            T::Move { built: false, .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch => Cell::Keep,
            T::Release { .. } => Cell::GoneWithPath,
            T::Remove { .. } => Cell::Gone,
        },
        Row::ConnectedUdp => match t {
            T::Promote { .. } => Cell::Empty,
            T::Replace { .. } | T::Remove { .. } => Cell::Dropped,
            T::Move { built: true, .. } => Cell::ReleasedClearedActiveIfChanged,
            T::Move { built: false, .. } | T::Keep { .. } | T::Cutover { .. } | T::Restarted => {
                Cell::Keep
            }
            T::Roam => Cell::ClearedIfChanged,
            T::Follow => Cell::MovedCleared,
            T::Switch => Cell::OldActiveCleared,
            T::Release { .. } => Cell::PathCleared,
        },
        Row::RekeyMachine => match t {
            T::Promote { .. } => Cell::NewEmptyRecord,
            T::Replace { .. } => Cell::OldClosedNewEmptyRecord,
            T::Move { built: true, .. } => Cell::ClosedRebuilt,
            T::Move { built: false, .. } => Cell::LeaseReleased,
            T::Keep { inbound, .. } => {
                if *inbound {
                    Cell::LegLeaseFreed
                } else {
                    Cell::DialLeaseFreed
                }
            }
            T::Cutover { .. } | T::Restarted => Cell::Stepped,
            T::Roam | T::Follow | T::Release { .. } => Cell::Keep,
            T::Switch => Cell::KeptBindingsFollow,
            T::Remove { .. } => Cell::Closed,
        },
        Row::SetupRecord => match t {
            T::Promote { .. } | T::Replace { .. } => Cell::Empty,
            T::Move { built: true, .. } => Cell::Carried,
            // The machine takes the peer's rekey from the leg that read its
            // msg3, and so answers no msg1 whose ephemeral it would file.
            T::Move { built: false, .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
            T::Remove { .. } => Cell::Gone,
        },
        Row::Identity => match t {
            T::Promote { .. } | T::Replace { .. } => Cell::New,
            T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
            T::Remove { .. } => Cell::Dropped,
        },
        Row::ControlMachine => match t {
            T::Promote { .. } => Cell::LegSurvives,
            T::Replace { .. } => Cell::OldRemovedLegSurvives,
            T::Move { inbound, .. } | T::Keep { inbound, .. } => {
                if *inbound {
                    Cell::LegRemoved
                } else {
                    Cell::DialRemovedPeerStepped
                }
            }
            T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
            T::Remove { why } => match why {
                Why::Dead => Cell::SteppedThenRemoved,
                Why::Restart
                | Why::Replacement
                | Why::OwnRestart
                | Why::Ended
                | Why::Orphaned
                | Why::Disconnect
                | Why::Admin
                | Why::Closed => Cell::Removed,
            },
        },
        Row::Connection => match t {
            T::Replace { .. } => Cell::UnkeptQueued,
            T::Move {
                built: true,
                inbound,
                ..
            } => {
                if *inbound {
                    Cell::ReleasedQueued
                } else {
                    Cell::DialClosedReleasedQueued
                }
            }
            // A crossing settled at the msg3 leaves the leg's connection open.
            T::Move {
                built: false,
                inbound: false,
                ..
            }
            | T::Keep { inbound: false, .. } => Cell::DialClosedUnlessProven,
            T::Release { keep: false } => Cell::QueuedDrained,
            T::Move {
                built: false,
                inbound: true,
                ..
            }
            | T::Keep { inbound: true, .. }
            | T::Promote { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { keep: true } => Cell::Keep,
            T::Remove { why } => match why {
                Why::Admin => Cell::UnkeptQueuedCurrentClosed,
                Why::Restart
                | Why::Replacement
                | Why::OwnRestart
                | Why::Ended
                | Why::Orphaned
                | Why::Disconnect
                | Why::Dead
                | Why::Closed => Cell::UnkeptQueued,
            },
        },
        Row::BleMark => match t {
            T::Promote { initiator, .. } => {
                if *initiator {
                    Cell::Marked
                } else {
                    Cell::MarkedAtFirstFrame
                }
            }
            T::Replace { initiator, .. } => {
                if *initiator {
                    Cell::OldClearedMarked
                } else {
                    Cell::OldClearedMarkedAtFirstFrame
                }
            }
            T::Move { built: true, .. } | T::Roam => Cell::Relinked,
            T::Release { keep: false } => Cell::ClearedIfDrained,
            T::Move { built: false, .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Follow
            | T::Switch
            | T::Release { keep: true } => Cell::Keep,
            T::Remove { why } => match why {
                Why::Dead | Why::Disconnect => Cell::Cleared,
                // An orphaned link has no active path left, so the removal
                // reads no pair to clear, and only a drained close clears.
                Why::Restart
                | Why::Replacement
                | Why::OwnRestart
                | Why::Ended
                | Why::Orphaned
                | Why::Admin
                | Why::Closed => Cell::ClearedIfDrained,
            },
        },
        Row::Bootstrap => match t {
            T::Promote { .. } | T::Cutover { .. } | T::Restarted => Cell::NotApplicable,
            T::Replace { .. } | T::Remove { .. } => Cell::Checked,
            T::Move { .. }
            | T::Keep { .. }
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::NotRun,
        },
        Row::Dials => match t {
            T::Promote { initiator, .. } | T::Replace { initiator, .. } => {
                if *initiator {
                    Cell::AnsweredRemoved
                } else {
                    Cell::Keep
                }
            }
            T::Move { inbound, .. } | T::Keep { inbound, .. } => {
                if *inbound {
                    Cell::Keep
                } else {
                    Cell::AnsweredRemoved
                }
            }
            T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. }
            | T::Remove { .. } => Cell::Keep,
        },
        Row::PathMtu => match t {
            T::Promote { .. } => Cell::Seeded,
            T::Replace { .. } => Cell::ReleasedThenSeeded,
            T::Move { built: true, .. } => Cell::ReseededIfMoved,
            T::Move { built: false, .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Release { .. } => Cell::Keep,
            T::Restarted => Cell::ReleasedReseeded,
            T::Roam | T::Follow => Cell::NotReseeded,
            T::Switch => Cell::ReseededTightened,
            T::Remove { .. } => Cell::Released,
        },
        Row::FilterSend => match t {
            T::Promote { .. } | T::Move { inbound: false, .. } | T::Keep { inbound: false, .. } => {
                Cell::Marked
            }
            T::Replace { .. } => Cell::RemovedOthersMarkedThenMarked,
            // A redial is never answered as a rekey here, so neither role's
            // cutover owes the peer the filter again.
            T::Cutover { role } => match role {
                Role::Responder | Role::Initiator => Cell::Keep,
            },
            T::Move { inbound: true, .. } | T::Keep { inbound: true, .. } => Cell::Keep,
            T::Restarted => Cell::ForgottenAllMarked,
            T::Roam | T::Follow | T::Switch | T::Release { .. } => Cell::Keep,
            T::Remove { .. } => Cell::RemovedOthersMarked,
        },
        Row::Tree => match t {
            T::Promote { .. } | T::Move { inbound: false, .. } | T::Keep { inbound: false, .. } => {
                Cell::Announced
            }
            T::Replace { .. } | T::Restarted => Cell::CleanedOthersPendingAnnounced,
            T::Move { inbound: true, .. }
            | T::Keep { inbound: true, .. }
            | T::Cutover { .. }
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
            T::Remove { .. } => Cell::CleanedOthersPending,
        },
        Row::Session => match t {
            T::Replace { .. } | T::Remove { .. } | T::Restarted => Cell::Closed,
            T::Promote { .. }
            | T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
        },
        Row::Dampener => match t {
            T::Replace { initiator, .. } => {
                if *initiator {
                    Cell::NotStamped
                } else {
                    Cell::Stamped
                }
            }
            T::Restarted => Cell::NotStamped,
            T::Promote { .. }
            | T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. }
            | T::Remove { .. } => Cell::NotApplicable,
        },
        Row::Silent => match t {
            T::Replace { .. } | T::Remove { .. } => Cell::NotedIfNoFrame,
            T::Promote { .. }
            | T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::NotApplicable,
        },
        Row::Reconnect => match t {
            T::Promote { .. } => Cell::Removed,
            T::Replace { .. } => Cell::NotedDeadThenRemoved,
            T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
            T::Remove { why } => match why {
                Why::Dead | Why::Disconnect | Why::Orphaned => Cell::NotedDead,
                Why::Admin => Cell::Removed,
                Why::Restart | Why::Replacement | Why::OwnRestart | Why::Ended | Why::Closed => {
                    Cell::Keep
                }
            },
        },
        Row::IdentityCache => match t {
            T::Promote { .. } | T::Replace { .. } => Cell::Registered,
            T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. }
            | T::Remove { .. } => Cell::Keep,
        },
        Row::LookupBackoff => match t {
            T::Promote { .. }
            | T::Replace { .. }
            | T::Move { inbound: false, .. }
            | T::Keep { inbound: false, .. } => Cell::BackoffReset,
            T::Move { inbound: true, .. }
            | T::Keep { inbound: true, .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. }
            | T::Remove { .. } => Cell::Keep,
        },
        Row::PathConnects => match t {
            T::Replace { .. } | T::Remove { .. } => Cell::Forgotten,
            T::Promote { .. }
            | T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
        },
        Row::PathCloses => match t {
            T::Move {
                built: true,
                inbound: false,
                ..
            } => Cell::QueuedDrainedIfMoved,
            T::Replace { .. }
            | T::Move {
                built: true,
                inbound: true,
                ..
            }
            | T::Release { keep: false }
            | T::Remove { .. } => Cell::Queued,
            T::Promote { .. }
            | T::Move { built: false, .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { keep: true } => Cell::Keep,
        },
        Row::PathListings => match t {
            T::Promote { .. } | T::Replace { .. } | T::Move { .. } => Cell::ForgottenOffered,
            T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
            T::Remove { .. } => Cell::GoneAtDiscovery,
        },
        Row::PathCarrier => match t {
            T::Replace { .. } | T::Remove { .. } => Cell::GoneAtNextRead,
            T::Promote { .. }
            | T::Move { .. }
            | T::Keep { .. }
            | T::Cutover { .. }
            | T::Restarted
            | T::Roam
            | T::Follow
            | T::Switch
            | T::Release { .. } => Cell::Keep,
        },
    }
}

/// Who holds `row`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn owner(row: Row) -> Owner {
    match row {
        Row::Data(_) => Owner::Data,
        Row::Link | Row::Index | Row::ControlMachine | Row::Dials => Owner::Table,
        Row::Paths | Row::Capability | Row::Pin | Row::PathFailures | Row::ConnectedUdp => {
            Owner::Bundle
        }
        Row::RekeyMachine | Row::SetupRecord => Owner::Rekey,
        Row::Identity => Owner::Identity,
        Row::Connection => Owner::Facet(Facet::Connection),
        Row::BleMark => Owner::Facet(Facet::Verified),
        Row::Bootstrap => Owner::Facet(Facet::Bootstrap),
        Row::PathMtu => Owner::Facet(Facet::PathMtu),
        Row::FilterSend => Owner::Facet(Facet::Bloom),
        Row::Tree => Owner::Facet(Facet::Tree),
        Row::Session => Owner::Facet(Facet::Session),
        Row::Dampener => Owner::Facet(Facet::Dampener),
        Row::Silent => Owner::Facet(Facet::Silent),
        Row::Reconnect => Owner::Facet(Facet::Reconnect),
        Row::IdentityCache => Owner::Facet(Facet::Identity),
        Row::LookupBackoff => Owner::Facet(Facet::LookupBackoff),
        Row::PathConnects => Owner::Facet(Facet::PathConnects),
        Row::PathCloses => Owner::Facet(Facet::PathCloses),
        Row::PathListings => Owner::Facet(Facet::PathListings),
        Row::PathCarrier => Owner::Facet(Facet::PathCarrier),
    }
}

#[cfg(test)]
#[path = "tests/table.rs"]
pub(crate) mod tests;
