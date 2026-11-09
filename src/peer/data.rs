//! A peer's record: everything held about an authenticated peer but its
//! identity and its two machines.
//!
//! `ActivePeer` keeps this in a private field, so the record is reachable
//! only from `active.rs`, its test module and this file, however open the
//! fields are to `crate::peer`. Its accessors live on `ActivePeer`.
//!
//! The fields are plain members with no pointer between them and the peer, so
//! a per-frame write reaches them as it would a field of `ActivePeer`.

use super::PeerInstant;
use crate::node::diag::HsLineCounts;
use crate::proto::bloom::BloomFilter;
use crate::proto::fmp::EphemeralDigest;
use crate::proto::mmp::MmpPeerState;
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};
use crate::transport::LinkStats;
use crate::utils::index::SessionIndex;
use portable_atomic::AtomicU64;
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
}

#[cfg(test)]
#[path = "tests/data.rs"]
mod tests;
