//! Bounds applied to configured values before a node runs with them.
//!
//! A value outside its bound is not refused: the node runs with the bound's
//! value instead and logs one warning naming the key, the configured value
//! and the value used, so a deployed config that sets it keeps starting.

use super::Config;
use crate::proto::bloom::ACCEPT_FPR_CAP;

/// Least interval in ms between two filter announcements to one peer
/// (FRC-1402 Section 4.5.2).
const DEBOUNCE_FLOOR: u64 = 500;

impl Config {
    /// Replace every value outside its bound with the bound's value, warning
    /// once for each.
    pub(crate) fn apply_floors(&mut self) {
        self.floor_debounce();
        self.floor_fpr();
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
}

#[cfg(test)]
#[path = "tests/floors.rs"]
mod tests;
