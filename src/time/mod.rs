//! Shell-side time seam: the host's clocks, read here and passed into the
//! sans-IO cores as arguments.
//!
//! - [`HostClock`] is the process's monotonic clock, as the core's
//!   [`fips_core::time::Clock`]; [`mono_ms`] reads the same clock as `u64`
//!   milliseconds for the cores that still take them.
//! - [`wall_ms`] is Unix time in milliseconds, for wire timestamps and for
//!   what the control API reports.

use std::sync::LazyLock;
use std::time::{Duration, Instant as StdInstant};

use fips_core::time::{Clock, Instant};

/// The process's monotonic epoch: the first read of [`mono_ms`] or of the
/// test epoch.
static START: LazyLock<StdInstant> = LazyLock::new(StdInstant::now);

/// The furthest a [`deadline`] reaches: 100 years, which neither host instant
/// type can overflow from a current reading.
pub(crate) const CEILING: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

/// Monotonic millisecond clock for the MMP time seam.
///
/// The owned `proto::mmp` state takes injected `u64` milliseconds rather than
/// reading a clock. The shell reads this process-monotonic clock at each edge
/// and passes the value in; only deltas between two `mono_ms()` reads are ever
/// compared, so the (process-relative) epoch is immaterial. It reads
/// [`HostClock`], so the two agree.
pub(crate) fn mono_ms() -> u64 {
    let start = *START;
    HostClock
        .now()
        .0
        .saturating_duration_since(start)
        .as_millis() as u64
}

/// The [`mono_ms`] reading of `instant`: its milliseconds from the same
/// epoch, truncated the same way, so it compares exactly with a `mono_ms`
/// value. An instant before the epoch reads 0.
pub(crate) fn mono_ms_at(instant: HostInstant) -> u64 {
    instant.0.saturating_duration_since(*START).as_millis() as u64
}

/// Current Unix time in milliseconds, or 0 if the system clock reads before
/// the epoch.
pub(crate) fn wall_ms() -> u64 {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    #[cfg(test)]
    let ms = ms.saturating_add_signed(hooks::WALL_STEP.with(|s| s.get()));
    ms
}

/// The process's monotonic clock.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct HostClock;

impl Clock for HostClock {
    type Instant = HostInstant;

    fn now(&self) -> HostInstant {
        let now = StdInstant::now();
        #[cfg(test)]
        let now = now + hooks::MONO_ADVANCE.with(|a| a.get());
        HostInstant(now)
    }
}

/// An instant of [`HostClock`]: a `std::time::Instant`, wrapped so it can
/// implement the core's trait.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct HostInstant(StdInstant);

impl Instant for HostInstant {
    fn saturating_duration_since(self, earlier: Self) -> Duration {
        self.0.saturating_duration_since(earlier.0)
    }

    fn checked_add(self, d: Duration) -> Option<Self> {
        self.0.checked_add(d).map(Self)
    }

    fn checked_sub(self, d: Duration) -> Option<Self> {
        self.0.checked_sub(d).map(Self)
    }
}

impl From<StdInstant> for HostInstant {
    fn from(instant: StdInstant) -> Self {
        Self(instant)
    }
}

impl From<HostInstant> for StdInstant {
    fn from(instant: HostInstant) -> Self {
        instant.0
    }
}

/// Unix milliseconds of an instant, for the control API and logs, which
/// report times as wall-clock stamps.
pub(crate) trait WallStamp {
    /// The instant as Unix time in milliseconds.
    fn wall_ms(self) -> u64;
}

impl WallStamp for HostInstant {
    /// The wall clock now, less the monotonic time since `self` (or plus the
    /// time until it). Two clock reads, so the value can be off by the time
    /// between them.
    fn wall_ms(self) -> u64 {
        let wall = wall_ms();
        let now = HostClock.now();
        if self <= now {
            wall.saturating_sub(now.saturating_duration_since(self).as_millis() as u64)
        } else {
            wall.saturating_add(self.saturating_duration_since(now).as_millis() as u64)
        }
    }
}

/// `now + d`, with `d` capped at [`CEILING`].
///
/// Below the cap this is exactly `now + d`. An instant type whose range ends
/// within the cap of `now` gets a deadline at or before that end instead of a
/// panic: the step is halved until it fits.
pub(crate) fn deadline<I: Instant>(now: I, d: Duration) -> I {
    let mut step = d.min(CEILING);
    loop {
        if let Some(at) = now.checked_add(step) {
            return at;
        }
        if step.is_zero() {
            return now;
        }
        step /= 2;
    }
}

/// Test hooks: per-thread offsets on the two clocks, so a test can step the
/// wall clock or advance the monotonic one without waiting.
///
/// Each `#[test]` runs on its own thread, so an offset reaches only the test
/// that set it. It does not reach the worker threads of a multi-thread
/// runtime.
#[cfg(test)]
mod hooks {
    use std::cell::Cell;
    use std::time::Duration;

    thread_local! {
        /// Signed milliseconds added to `wall_ms`.
        pub(super) static WALL_STEP: Cell<i64> = const { Cell::new(0) };
        /// Time added to `HostClock` and `mono_ms`.
        pub(super) static MONO_ADVANCE: Cell<Duration> = const { Cell::new(Duration::ZERO) };
    }
}

/// Step this thread's wall clock by `ms` milliseconds, either way. Moves
/// [`wall_ms`], and not [`HostClock`] or [`mono_ms`].
#[cfg(test)]
pub(crate) fn step_wall(ms: i64) {
    hooks::WALL_STEP.with(|s| s.set(s.get() + ms));
}

/// Advance this thread's monotonic clock by `d`. Moves [`HostClock`] and
/// [`mono_ms`], and not [`wall_ms`].
#[cfg(test)]
pub(crate) fn advance(d: Duration) {
    hooks::MONO_ADVANCE.with(|a| a.set(a.get() + d));
}

/// A clock with a fixed instant to count test times from, so a test can name
/// an instant in milliseconds whichever clock the code under test runs on.
#[cfg(test)]
pub(crate) trait TestEpoch: Clock {
    /// The instant that [`at`] counts from.
    fn epoch() -> Self::Instant;
}

#[cfg(test)]
impl TestEpoch for HostClock {
    fn epoch() -> HostInstant {
        HostInstant(*START)
    }
}

/// The instant `ms` milliseconds after `C`'s test epoch.
#[cfg(test)]
pub(crate) fn at<C: TestEpoch>(ms: u64) -> C::Instant {
    C::epoch()
        .checked_add(Duration::from_millis(ms))
        .expect("a test instant fits the clock's range")
}

#[cfg(test)]
mod tests;
