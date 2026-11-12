//! Bounds applied to configured values before a node runs with them.
//!
//! A value outside its bound is not refused: the node runs with the bound's
//! value instead and logs one warning naming the key, the configured value
//! and the value used, so a deployed config that sets it keeps starting.

use super::{Config, LookupConfig};
use crate::proto::bloom::ACCEPT_FPR_CAP;

/// Least interval in ms between two filter announcements to one peer
/// (FRC-1402 Section 4.5.2).
const DEBOUNCE_FLOOR: u64 = 500;

/// Most entries of the lookup retry ladder that are run. A lookup counts its
/// attempts in a `u8`.
const LADDER_CAP: usize = u8::MAX as usize;

impl Config {
    /// Replace every value outside its bound with the bound's value, warning
    /// once for each.
    pub(crate) fn apply_floors(&mut self) {
        self.floor_debounce();
        self.floor_fpr();
        self.floor_ladder();
    }

    /// Raise `node.bloom.update_debounce_ms` to the 500 ms send interval.
    fn floor_debounce(&mut self) {
        let configured = self.node.bloom.update_debounce_ms;
        if configured < DEBOUNCE_FLOOR {
            self.node.bloom.update_debounce_ms = DEBOUNCE_FLOOR;
            tracing::warn!(
                target: "fips::config",
                key = "node.bloom.update_debounce_ms",
                configured,
                used = DEBOUNCE_FLOOR,
                "configured value is below the 500 ms send interval; running at 500 ms"
            );
        }
    }

    /// Bring `node.bloom.max_inbound_fpr` into `[0.20, 1.0)`.
    ///
    /// Below 0.20 the cap discards conformant peers' filters (FRC-1402
    /// Section 4.7.1); at 1.0 and above, or NaN, it never fires and the
    /// poisoning check is off. Both run as 0.20, which is the floor and also
    /// the default, so one branch serves both.
    fn floor_fpr(&mut self) {
        let configured = self.node.bloom.max_inbound_fpr;
        if !(ACCEPT_FPR_CAP..1.0).contains(&configured) {
            self.node.bloom.max_inbound_fpr = ACCEPT_FPR_CAP;
            tracing::warn!(
                target: "fips::config",
                key = "node.bloom.max_inbound_fpr",
                configured,
                used = ACCEPT_FPR_CAP,
                "configured value is outside [0.20, 1.0); running at 0.20"
            );
        }
    }

    /// Bound `node.lookup.attempt_timeouts_secs` to between one and 255
    /// entries.
    ///
    /// An empty ladder would fail nearly every lookup at the next tick, so it
    /// runs as the default ladder. A lookup counts its attempts in a `u8`, so
    /// a ladder over 255 entries runs its first 255. Every reader of the
    /// ladder (the lookup retries, the hold time for queued packets and the
    /// probe's discovery budget) sees the bounded value. Entry sizes are not
    /// bounded here; those readers saturate.
    fn floor_ladder(&mut self) {
        let ladder = &mut self.node.lookup.attempt_timeouts_secs;
        if ladder.is_empty() {
            *ladder = LookupConfig::default().attempt_timeouts_secs;
            tracing::warn!(
                target: "fips::config",
                key = "node.lookup.attempt_timeouts_secs",
                configured = ?Vec::<u64>::new(),
                used = ?ladder,
                "configured lookup ladder is empty; running the default ladder"
            );
        } else if ladder.len() > LADDER_CAP {
            let configured = ladder.len();
            ladder.truncate(LADDER_CAP);
            tracing::warn!(
                target: "fips::config",
                key = "node.lookup.attempt_timeouts_secs",
                configured,
                used = LADDER_CAP,
                "configured lookup ladder has more than 255 entries (configured and used are \
                 lengths); running its first 255"
            );
        }
    }
}

#[cfg(test)]
#[path = "tests/floors.rs"]
mod tests;
