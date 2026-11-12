//! The limit on the suspicious-offer warning: one a minute, with a count of
//! the offers logged at debug level in between.

use core::time::Duration;

use fips_core::time::Instant;

use super::plan::PunchTargetTally;

/// The minimum spacing of the suspicious-offer warning.
const REFUSAL_WARN_INTERVAL: Duration = Duration::from_secs(60);

/// Limits the suspicious-offer warning to one a minute.
///
/// The offer semaphore bounds how many offers run at once, not how often
/// they arrive, so a stranger sending refused offers would otherwise get a
/// warning per offer. The limit is per process; every refused offer is still
/// logged at debug level.
#[derive(Debug)]
pub struct RefusalWarnGate<I> {
    last_warn: Option<I>,
    suppressed: u64,
}

impl<I> Default for RefusalWarnGate<I> {
    /// A gate that has given no warning yet.
    fn default() -> Self {
        Self {
            last_warn: None,
            suppressed: 0,
        }
    }
}

impl<I: Instant> RefusalWarnGate<I> {
    /// Whether a suspicious offer seen at `now` should be the warning.
    ///
    /// Returns `Some(suppressed)`, the number of suspicious offers logged at
    /// debug level since the last warning, when none has been given in the
    /// last minute; otherwise counts this one and returns `None`. `now` is
    /// monotonic, so a wall-clock step neither silences nor repeats the line.
    pub fn admit(&mut self, now: I) -> Option<u64> {
        let due = self
            .last_warn
            .is_none_or(|last| now.saturating_duration_since(last) >= REFUSAL_WARN_INTERVAL);
        if !due {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        self.last_warn = Some(now);
        Some(core::mem::take(&mut self.suppressed))
    }

    /// The warning decision for one planning call's tally.
    ///
    /// Only a tally that is both logged and suspicious is put to the gate,
    /// so an offer that logs nothing cannot spend the minute's warning.
    pub fn decide(&mut self, tally: &PunchTargetTally, now: I) -> Option<u64> {
        if tally.has_refusals() && tally.suspicious() {
            self.admit(now)
        } else {
            None
        }
    }
}

#[cfg(test)]
#[path = "tests/refusal.rs"]
mod tests;
