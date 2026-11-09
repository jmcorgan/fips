//! A peer's record: everything held about an authenticated peer but its
//! identity and its two machines.
//!
//! `ActivePeer` keeps this in a private field, so the record is reachable
//! only from `active.rs`, its test module and this file, however open the
//! fields are to `crate::peer`. Its accessors live on `ActivePeer`.
//!
//! The fields are plain members with no pointer between them and the peer, so
//! a per-frame write reaches them as it would a field of `ActivePeer`.
//!
//! [`PeerData::settle`] applies the transition table's cell for a transition
//! to each of the record's rows; between transitions the per-event methods on
//! `ActivePeer` write it. [`PeerData::depart`] ends the record at a removal
//! and hands over what the removal reads of it, as a [`Departed`]. Both
//! destructure the record with no rest pattern, so a field added here does
//! not compile until it takes a side in each.

#![deny(clippy::wildcard_enum_match_arm)]

use super::PeerInstant;
use crate::node::diag::{HsLineCounts, Withheld};
use crate::node::settle::table::{DataCell, DataRow, Transition, data_cell};
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::EphemeralDigest;
use crate::proto::mmp::MmpPeerState;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use crate::transport::LinkStats;
use crate::utils::index::SessionIndex;
use portable_atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// What a node holds about one authenticated peer, its identity and its
/// rekey and path machines apart.
#[derive(Debug)]
pub(super) struct PeerData {
    // === Spanning Tree ===
    /// Their latest parent declaration.
    pub(super) declaration: Option<ParentDeclaration>,
    /// Their path to root.
    pub(super) ancestry: Option<TreeCoordinate>,

    // === Tree Announce Rate Limiting ===
    /// Minimum interval between TreeAnnounce messages (milliseconds).
    pub(super) tree_announce_min_interval_ms: u64,
    /// When we last sent a TreeAnnounce to this peer, in milliseconds of the
    /// monotonic clock (`crate::time::mono_ms`); `None` if we never have.
    pub(super) last_tree_announce_sent_ms: Option<u64>,
    /// Whether a tree announce is pending (deferred due to rate limit).
    pub(super) pending_tree_announce: bool,

    // === Bloom Filter ===
    /// What's reachable through them (inbound filter).
    pub(super) inbound_filter: Option<BloomFilter>,
    /// Their filter's sequence number.
    pub(super) filter_sequence: u64,
    /// When we received their last filter (Unix milliseconds).
    pub(super) filter_received_at: u64,
    /// Whether we owe them a filter update.
    pub(super) pending_filter_update: bool,

    // === Statistics ===
    /// When this peer was authenticated (Unix milliseconds), as shown to
    /// operators.
    pub(super) authenticated_at: u64,
    /// Link statistics.
    pub(super) link_stats: LinkStats,
    /// When this peer was last seen (any activity, Unix milliseconds).
    pub(super) last_seen: u64,

    // === Heartbeat ===
    /// When a heartbeat to this peer last *succeeded*. A send that failed does
    /// not move this: it told the peer nothing, and treating it as if it had
    /// would leave the peer un-heartbeated for a full interval on the strength
    /// of a send that never landed.
    pub(super) last_heartbeat_sent: Option<Instant>,
    /// When a heartbeat to this peer was last *attempted*, whatever came of it.
    /// Paired with the above so a peer whose send failed is retried sooner than
    /// the heartbeat interval without being retried on every tick — see
    /// `HEARTBEAT_RETRY_INTERVAL`.
    pub(super) last_heartbeat_attempt: Option<Instant>,

    // === Heard ===
    /// When this peer was promoted, on the peer clock. The restart gate ages
    /// a peering not yet heard from by it.
    pub(super) promoted_at: PeerInstant,
    /// When an authenticated frame from this peer last arrived, on the peer
    /// clock, or the promotion instant before the first. The restart gate
    /// measures a heard peering's quiet time by it.
    pub(super) heard_at: PeerInstant,
    /// Whether this peering has given any evidence that its peer is present
    /// now: an authenticated frame on its session, or, for a peering this
    /// node initiated, the msg2 that answered our fresh ephemeral. A
    /// responder promotion is not such evidence, because the msg1 it was
    /// promoted from carries nothing fresh and may be a replayed capture.
    pub(super) heard: bool,
    /// Whether an authenticated frame from this peer has arrived since it was
    /// promoted.
    pub(super) frame_heard: bool,

    // === Handshake Resend ===
    /// Wire-format msg2 for resend on duplicate msg1 (responder only).
    /// Kept for the life of the peering: nothing clears it.
    pub(super) handshake_msg2: Option<Vec<u8>>,
    /// Digest of the ephemeral in the link-setup msg1 the peering was
    /// promoted from, by which the silent-session record counts a session
    /// once however a copy's header was rewritten.
    pub(super) setup_ephemeral: Option<EphemeralDigest>,

    // === Counts ===
    /// Repeated handshake lines logged for this peer, by kind, so a peer
    /// repeating one msg1 outcome logs it a bounded number of times.
    pub(super) hs_lines: HsLineCounts,
    /// Replays refused from this peer since it was promoted, on the inline
    /// path and in the decrypt workers, which hold a clone of it.
    pub(super) replay_total: Arc<AtomicU64>,
    /// `replay_total` at the last session reset.
    pub(super) replay_base: u64,
    /// Frames authenticated on the previous session since the last cutover.
    pub(super) prev_frames: u64,
    /// The receiver index of the last frame that failed to decrypt.
    pub(super) failed_idx: Option<SessionIndex>,

    // === Metrics ===
    /// Per-peer MMP state (None for legacy peers without Noise sessions).
    pub(super) mmp: Option<MmpPeerState>,
}

impl PeerData {
    /// The record of a peer authenticated at `authenticated_at` and promoted
    /// at `now`, `heard` saying whether the promotion itself is evidence the
    /// peer is present: nothing known of the peer yet, a filter owed, no MMP.
    pub(super) fn new(authenticated_at: u64, now: PeerInstant, heard: bool) -> Self {
        Self {
            declaration: None,
            ancestry: None,
            tree_announce_min_interval_ms: 500,
            last_tree_announce_sent_ms: None,
            pending_tree_announce: false,
            inbound_filter: None,
            filter_sequence: 0,
            filter_received_at: 0,
            pending_filter_update: true, // Send filter on new connection
            authenticated_at,
            link_stats: LinkStats::new(),
            last_seen: authenticated_at,
            last_heartbeat_sent: None,
            last_heartbeat_attempt: None,
            promoted_at: now,
            heard_at: now,
            heard,
            frame_heard: false,
            handshake_msg2: None,
            setup_ephemeral: None,
            hs_lines: HsLineCounts::default(),
            replay_total: Arc::new(AtomicU64::new(0)),
            replay_base: 0,
            prev_frames: 0,
            failed_idx: None,
            mmp: None,
        }
    }

    /// Apply `t`'s cell to every row of the record, `now_ms` being the
    /// monotonic reading an MMP reset starts its jitter grace from. Names
    /// every field: a new one does not compile. A new record comes from
    /// [`PeerData::new`], so a transition whose cell is a new record or the
    /// record's end is not one to settle.
    pub(super) fn settle(&mut self, t: &Transition, now_ms: u64) {
        let PeerData {
            declaration,
            ancestry,
            tree_announce_min_interval_ms: _,
            last_tree_announce_sent_ms: _,
            pending_tree_announce: _,
            inbound_filter,
            filter_sequence,
            filter_received_at,
            pending_filter_update: _,
            authenticated_at: _,
            link_stats: _,
            last_seen: _,
            last_heartbeat_sent: _,
            last_heartbeat_attempt: _,
            promoted_at: _,
            heard_at: _,
            heard: _,
            frame_heard: _,
            handshake_msg2: _,
            setup_ephemeral: _,
            hs_lines,
            replay_total,
            replay_base,
            prev_frames,
            failed_idx: _,
            mmp,
        } = self;

        for row in ROWS {
            let cell = data_cell(row, t);
            match row {
                DataRow::Mmp => match cell {
                    DataCell::Keep => {}
                    // Which fields a reset keeps is MMP's business: its own
                    // test lists them.
                    DataCell::Reset => {
                        if let Some(mmp) = mmp.as_mut()
                            && !skips_mmp_reset(t)
                        {
                            mmp.reset_for_rekey(now_ms);
                        }
                    }
                    DataCell::Roll
                    | DataCell::Base
                    | DataCell::Clear
                    | DataCell::New
                    | DataCell::Drop => unsettled(row, t),
                },
                DataRow::Spin => match cell {
                    DataCell::Keep => {}
                    // The spin bit is part of MMP's state and restarts in
                    // its reset.
                    DataCell::Reset => debug_assert_eq!(
                        data_cell(DataRow::Mmp, t),
                        DataCell::Reset,
                        "the spin bit restarts only with the MMP reset, at {t:?}"
                    ),
                    DataCell::Roll
                    | DataCell::Base
                    | DataCell::Clear
                    | DataCell::New
                    | DataCell::Drop => unsettled(row, t),
                },
                DataRow::PeerFilter => match cell {
                    DataCell::Keep => {}
                    DataCell::Clear => {
                        *inbound_filter = None;
                        *filter_sequence = 0;
                        *filter_received_at = 0;
                    }
                    DataCell::Reset
                    | DataCell::Roll
                    | DataCell::Base
                    | DataCell::New
                    | DataCell::Drop => unsettled(row, t),
                },
                DataRow::TreePosition => match cell {
                    DataCell::Keep => {}
                    DataCell::Clear => {
                        *declaration = None;
                        *ancestry = None;
                    }
                    DataCell::Reset
                    | DataCell::Roll
                    | DataCell::Base
                    | DataCell::New
                    | DataCell::Drop => unsettled(row, t),
                },
                DataRow::PrevFrames => match cell {
                    DataCell::Keep => {}
                    DataCell::Reset => *prev_frames = 0,
                    DataCell::Roll
                    | DataCell::Base
                    | DataCell::Clear
                    | DataCell::New
                    | DataCell::Drop => unsettled(row, t),
                },
                DataRow::HsLines => match cell {
                    DataCell::Keep => {}
                    DataCell::Roll => hs_lines.roll(),
                    DataCell::Reset
                    | DataCell::Base
                    | DataCell::Clear
                    | DataCell::New
                    | DataCell::Drop => unsettled(row, t),
                },
                DataRow::ReplayBase => match cell {
                    DataCell::Keep => {}
                    // The total stays, and with it the clone each decrypt
                    // worker holds: only the base moves.
                    DataCell::Base => *replay_base = replay_total.load(Ordering::Relaxed),
                    DataCell::Reset
                    | DataCell::Roll
                    | DataCell::Clear
                    | DataCell::New
                    | DataCell::Drop => unsettled(row, t),
                },
                // Rows only a new record or the record's end changes.
                DataRow::FilterPending
                | DataRow::TreePending
                | DataRow::TreeStamp
                | DataRow::TreeInterval
                | DataRow::Heard
                | DataRow::StoredSetup
                | DataRow::Stats
                | DataRow::ReplayTotal => match cell {
                    DataCell::Keep => {}
                    DataCell::Reset
                    | DataCell::Roll
                    | DataCell::Base
                    | DataCell::Clear
                    | DataCell::New
                    | DataCell::Drop => unsettled(row, t),
                },
            }
        }
    }
}

/// What a removal reads of a peer's record, and nothing else, handed over as
/// the record ends: whether the peering was heard from and whether a frame
/// arrived, the setup's ephemeral, the replays refused since the last session
/// reset, the handshake lines withheld, and the MMP state its teardown logs.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug)]
pub(crate) struct Departed {
    /// Whether the peering was heard from: a frame arrived, or this node
    /// initiated it (`ActivePeer::is_heard`).
    pub heard: bool,
    /// Whether an authenticated frame arrived since the promotion
    /// (`ActivePeer::heard`).
    pub frame_heard: bool,
    /// The digest of the ephemeral the peering was promoted from.
    pub ephemeral: Option<EphemeralDigest>,
    /// Replays refused since the last session reset
    /// (`ActivePeer::replay_suppressed_count`).
    pub suppressed: u32,
    /// The handshake lines withheld and not yet reported.
    pub withheld: Option<Withheld>,
    /// The link's MMP state.
    pub mmp: Option<MmpPeerState>,
}

impl PeerData {
    /// End the record at a removal, handing over what the removal reads of
    /// it. Names every field: a new one does not compile until it is read or
    /// dropped here. A decrypt worker's clone of the replay total lives on
    /// until the worker is revoked; this record's is dropped.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(super) fn depart(self) -> Departed {
        let PeerData {
            declaration: _,
            ancestry: _,
            tree_announce_min_interval_ms: _,
            last_tree_announce_sent_ms: _,
            pending_tree_announce: _,
            inbound_filter: _,
            filter_sequence: _,
            filter_received_at: _,
            pending_filter_update: _,
            authenticated_at: _,
            link_stats: _,
            last_seen: _,
            last_heartbeat_sent: _,
            last_heartbeat_attempt: _,
            promoted_at: _,
            heard_at: _,
            heard,
            frame_heard,
            handshake_msg2: _,
            setup_ephemeral,
            hs_lines,
            replay_total,
            replay_base,
            prev_frames: _,
            failed_idx: _,
            mmp,
        } = self;
        let total = replay_total.load(Ordering::Relaxed);
        Departed {
            heard,
            frame_heard,
            ephemeral: setup_ephemeral,
            suppressed: u32::try_from(total.saturating_sub(replay_base)).unwrap_or(u32::MAX),
            withheld: hs_lines.unreported(),
            mmp,
        }
    }
}

/// Every row of the record, in the order `settle` applies them. A test holds
/// it to the table's own list.
const ROWS: [DataRow; 15] = [
    DataRow::Mmp,
    DataRow::Spin,
    DataRow::PeerFilter,
    DataRow::FilterPending,
    DataRow::TreePosition,
    DataRow::TreePending,
    DataRow::TreeStamp,
    DataRow::TreeInterval,
    DataRow::Heard,
    DataRow::StoredSetup,
    DataRow::Stats,
    DataRow::PrevFrames,
    DataRow::HsLines,
    DataRow::ReplayBase,
    DataRow::ReplayTotal,
];

/// A cell `settle` has no way to apply: a new record, the record's end, or a
/// value the row never takes. A debug build stops; a release build leaves the
/// row as it was.
fn unsettled(row: DataRow, t: &Transition) {
    debug_assert!(
        false,
        "{row:?} has no change to settle at {t:?}: {:?}",
        data_cell(row, t)
    );
}

/// Whether the mutation lane's break for `t` skips the MMP reset: at a
/// cutover, or at a move.
fn skips_mmp_reset(t: &Transition) -> bool {
    match t {
        Transition::Cutover { .. } => node_fault!(CutoverSkipsMmpReset),
        Transition::Move { .. } => node_fault!(MoveSkipsMmpReset),
        Transition::Promote { .. }
        | Transition::Replace { .. }
        | Transition::Keep { .. }
        | Transition::Restarted
        | Transition::Roam
        | Transition::Follow
        | Transition::Switch
        | Transition::Release { .. }
        | Transition::Remove { .. } => false,
    }
}

#[cfg(test)]
#[path = "tests/data.rs"]
mod tests;
