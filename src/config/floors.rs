//! Bounds applied to configured values before a node runs with them.
//!
//! A value outside its bound is not refused: the node runs at the bound and
//! logs one warning naming the key, the configured value and the value used,
//! so a deployed config that sets it keeps starting.

use super::Config;
use std::fmt::Display;

/// Least time in seconds a link must stay silent before it is declared dead
/// (FRC-1201 Section 6.4).
const DEAD_FLOOR: u64 = 30;

impl Config {
    /// Bring every value a protocol bound covers inside its bound, warning
    /// once for each one changed.
    ///
    /// A second call changes and logs nothing.
    pub(crate) fn apply_floors(&mut self) {
        self.floor_linkdead();
    }

    /// Raise `node.link_dead_timeout_secs` to 30 s.
    fn floor_linkdead(&mut self) {
        raise(
            "node.link_dead_timeout_secs",
            &mut self.node.link_dead_timeout_secs,
            DEAD_FLOOR,
            "configured value is below the 30 s a link must stay silent before it is declared dead; running at 30 s",
        );
    }
}

/// Raise `value`, configured as `key`, to `floor` when it is below it,
/// logging `why` with the key, the configured value and the value used.
fn raise<T: Copy + PartialOrd + Display>(key: &'static str, value: &mut T, floor: T, why: &str) {
    if *value < floor {
        clamped(key, *value, floor, why);
        *value = floor;
    }
}

/// Log that `key` was configured as `configured` and is used as `used`, for
/// the reason `why`.
fn clamped(key: &'static str, configured: impl Display, used: impl Display, why: &str) {
    tracing::warn!(
        target: "fips::config",
        key,
        configured = %configured,
        used = %used,
        "{why}"
    );
}

#[cfg(test)]
#[path = "tests/floors.rs"]
mod tests;
