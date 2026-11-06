//! Time, supplied by the host.
//!
//! The core never reads a clock. A type that measures time takes the host's
//! clock as a type parameter bounded by [`Clock`] and takes the clock's
//! instants as method arguments; the host reads its clock and passes the
//! instant in. A type that only holds the instants it is handed takes the
//! instant type, bounded by [`Instant`], instead. The host fixes the
//! parameter once, in a type alias at the path its callers already use, as it
//! does for [`crate::entropy::EntropySource`].
//!
//! Durations are [`core::time::Duration`], which needs neither `std` nor an
//! allocator. The arithmetic between instants and durations is the three
//! methods on [`Instant`]; [`deadline`] builds a deadline from them that
//! never overflows, and [`backoff`] is the doubling, capped wait that
//! retries and abandons share.

pub use core::time::Duration;

/// A point on a host's monotonic clock.
///
/// Opaque: only differences between two instants of one clock mean anything.
/// An implementation is a small `Copy` value, such as a tick count, and never
/// allocates.
pub trait Instant: Copy + Ord + core::fmt::Debug + Send + Sync + 'static {
    /// Time from `earlier` to `self`, or zero when `earlier` is the later one.
    fn saturating_duration_since(self, earlier: Self) -> Duration;

    /// `self + d`, or `None` past the end of the representation.
    fn checked_add(self, d: Duration) -> Option<Self>;

    /// `self - d`, or `None` before its start.
    fn checked_sub(self, d: Duration) -> Option<Self>;
}

/// A host's monotonic clock.
///
/// Successive reads never go backwards. The core names a clock only as a type
/// parameter and takes its instants as arguments; it never calls `now`, which
/// is for the host.
pub trait Clock {
    /// The instants this clock reads.
    type Instant: Instant;

    /// The current instant.
    fn now(&self) -> Self::Instant;
}

/// The furthest a [`deadline`] reaches: 100 years. No host instant type
/// overflows that far from a current reading; one whose range ends sooner
/// gets a deadline at that end instead.
pub const CEILING: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);

/// `now + d`, with `d` capped at [`CEILING`].
///
/// Below the cap this is exactly `now + d`. An instant type whose range ends
/// within the cap of `now` gets a deadline at or before that end instead of a
/// panic: the step is halved until it fits.
pub fn deadline<I: Instant>(now: I, d: Duration) -> I {
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

/// `base` doubled `exponent` times, capped at `cap`. The doubling factor
/// saturates at `u32::MAX` and the product at `Duration::MAX`, so any
/// exponent gives the cap once the doubling reaches it.
pub fn backoff(exponent: u32, base: Duration, cap: Duration) -> Duration {
    let factor = 1u32.checked_shl(exponent).unwrap_or(u32::MAX);
    base.saturating_mul(factor).min(cap)
}

#[cfg(test)]
mod tests;
