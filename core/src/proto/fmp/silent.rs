//! Per-identity memory of link sessions that ended without one authenticated
//! frame, and the msg1 refusal it drives.
//!
//! A peer that completes msg1 and then never sends a frame is promoted again
//! on every fresh msg1, and each promotion costs a msg2, a TreeAnnounce and a
//! stale peer entry until the link-dead reaper removes it. After
//! [`SILENT_SESSION_LIMIT`] such sessions in a row at one startup epoch, the
//! identity's msg1s at that epoch are refused for a back-off that starts at
//! [`SILENT_BACKOFF_BASE_MS`] and doubles with each further silent session,
//! up to [`SILENT_BACKOFF_CAP_MS`]. Any authenticated frame from the identity
//! drops its record.
//!
//! The record outlives the peer entry it was built from, since the removal it
//! counts destroys that entry. Every clock is passed in as monotonic
//! milliseconds; the shell reads the clock.

use super::core::EphemeralDigest;
use super::limits::backoff_ms;
use crate::identity::NodeAddr;
use alloc::collections::{BTreeMap, VecDeque};

/// Consecutive silent sessions of one identity at one epoch before its msg1s
/// are refused. Decided with the cap; a later capture may recalibrate both.
pub const SILENT_SESSION_LIMIT: u32 = 3;

/// The first refusal's length. Equal to the default link-dead timeout, so a
/// first refusal costs a peer wrongly judged silent no more than one more
/// silent session would have; a step below the peer's redial interval would
/// refuse nothing.
pub const SILENT_BACKOFF_BASE_MS: u64 = 30_000;

/// The longest refusal, reached after five doublings.
pub const SILENT_BACKOFF_CAP_MS: u64 = 600_000;

/// How long a record is kept after its refusal ends, or after its last silent
/// session when it has not reached the limit. Measured from the refusal's end
/// so a record held at the cap survives the gap until the next silent session.
const RECORD_HORIZON_MS: u64 = SILENT_BACKOFF_CAP_MS;

/// Link-setup msg1 ephemerals a record remembers, so a replayed msg1 promotes
/// a session that is counted only once, whatever its header says. A sender cycling more distinct msg1s
/// than this can be counted again; that needs more captured msg1s of one
/// identity's epoch than the limit needs to start a refusal at all.
const COUNTED_SETUP_RECORD: usize = 8;

/// A refusal in force for one identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ActiveBackoff {
    /// The startup epoch of the silent sessions counted; msg1s at another
    /// epoch are not refused. `None` when none of them carried one.
    pub epoch: Option<[u8; 8]>,
    /// Silent sessions counted in a row at that epoch.
    pub silent: u32,
    /// Milliseconds the refusal still has to run.
    pub remaining_ms: u64,
}

/// A refusal started or extended by a silent session's end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefusalStart {
    /// The refusal now in force.
    pub backoff: ActiveBackoff,
    /// Msg1s refused while the record's previous refusal was in force, or
    /// since then; the count starts again with this refusal.
    pub prior_refused: u32,
}

/// What is remembered about one identity's recent silent sessions.
#[derive(Debug)]
struct SilentRecord {
    epoch: Option<[u8; 8]>,
    silent: u32,
    last_end_ms: u64,
    until_ms: Option<u64>,
    counted: VecDeque<EphemeralDigest>,
    /// Msg1s refused since the current refusal started, for the log line
    /// that reports them.
    refused: u32,
}

impl SilentRecord {
    fn new(epoch: Option<[u8; 8]>) -> Self {
        Self {
            epoch,
            silent: 0,
            last_end_ms: 0,
            until_ms: None,
            counted: VecDeque::new(),
            refused: 0,
        }
    }

    /// Whether the record can be dropped at `now_ms`.
    fn expired(&self, now_ms: u64) -> bool {
        let from = self.until_ms.unwrap_or(self.last_end_ms);
        now_ms >= from.saturating_add(RECORD_HORIZON_MS)
    }

    /// Remember `setup` as counted, dropping the oldest at the bound.
    fn note_counted(&mut self, setup: EphemeralDigest) {
        if self.counted.len() == COUNTED_SETUP_RECORD {
            self.counted.pop_front();
        }
        self.counted.push_back(setup);
    }
}

/// Whether two startup epochs name different runs of a peer: both present and
/// unequal. A missing epoch on either side counts as the same, as it does for
/// a restart.
pub fn epochs_differ(a: Option<[u8; 8]>, b: Option<[u8; 8]>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x != y)
}

/// Silent-session records, keyed by peer identity.
#[derive(Debug, Default)]
pub struct SilentSessions {
    records: BTreeMap<NodeAddr, SilentRecord>,
}

impl SilentSessions {
    /// An empty set of records.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one session of `peer` that ended without an authenticated frame.
    ///
    /// `epoch` is the peer's startup epoch on that session and `setup` the
    /// digest of the ephemeral in the msg1 it was promoted from (`None` for a
    /// session this node dialled). A session promoted from a msg1 already
    /// counted is not counted again: a captured msg1 replays with the same
    /// ephemeral, which its AEAD binds, even when its unauthenticated header
    /// (`sender_idx`) is rewritten. A session
    /// at a different epoch from the record's starts the count again. Returns
    /// the refusal this end starts or extends, if any, with the number of
    /// msg1s refused before it; the refused count starts again at zero.
    pub fn ended(
        &mut self,
        peer: NodeAddr,
        epoch: Option<[u8; 8]>,
        setup: Option<EphemeralDigest>,
        now_ms: u64,
    ) -> Option<RefusalStart> {
        self.records.retain(|_, r| !r.expired(now_ms));
        let record = self
            .records
            .entry(peer)
            .or_insert_with(|| SilentRecord::new(epoch));
        if epochs_differ(record.epoch, epoch) {
            *record = SilentRecord::new(epoch);
        }
        if record.epoch.is_none() {
            record.epoch = epoch;
        }
        if let Some(setup) = setup {
            if record.counted.contains(&setup) {
                return None;
            }
            record.note_counted(setup);
        }
        record.silent = record.silent.saturating_add(1);
        record.last_end_ms = now_ms;
        if record.silent < SILENT_SESSION_LIMIT {
            return None;
        }
        let length = backoff_ms(
            record.silent - SILENT_SESSION_LIMIT,
            SILENT_BACKOFF_BASE_MS,
            SILENT_BACKOFF_CAP_MS,
        );
        record.until_ms = Some(now_ms.saturating_add(length));
        Some(RefusalStart {
            backoff: ActiveBackoff {
                epoch: record.epoch,
                silent: record.silent,
                remaining_ms: length,
            },
            prior_refused: core::mem::take(&mut record.refused),
        })
    }

    /// An authenticated frame arrived from `peer`: forget its silent sessions.
    /// Returns how many msg1s the record had refused since its last refusal
    /// started, 0 with no record.
    pub fn heard(&mut self, peer: &NodeAddr) -> u32 {
        self.records.remove(peer).map_or(0, |r| r.refused)
    }

    /// Count one msg1 of `peer` refused, returning how many its record has
    /// refused since its refusal started, or `None` with no record.
    pub fn note_refused(&mut self, peer: &NodeAddr) -> Option<u32> {
        let record = self.records.get_mut(peer)?;
        record.refused = record.refused.saturating_add(1);
        Some(record.refused)
    }

    /// The refusal in force for `peer` at `now_ms`, if one is.
    pub fn refusing(&self, peer: &NodeAddr, now_ms: u64) -> Option<ActiveBackoff> {
        let record = self.records.get(peer)?;
        let until = record.until_ms?;
        (until > now_ms).then(|| ActiveBackoff {
            epoch: record.epoch,
            silent: record.silent,
            remaining_ms: until - now_ms,
        })
    }

    /// The identities a record is held for, for a shell's comparison of
    /// this memory with another.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn known(&self) -> impl Iterator<Item = &NodeAddr> {
        self.records.keys()
    }

    /// Silent sessions counted for `peer`, or `None` with no record.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn count(&self, peer: &NodeAddr) -> Option<u32> {
        self.records.get(peer).map(|r| r.silent)
    }

    /// Number of identities with a record.
    #[cfg(test)]
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.records.len()
    }
}
