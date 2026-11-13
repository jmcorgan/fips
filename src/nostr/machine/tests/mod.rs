//! Helpers the machine's unit tests share.

use std::cell::RefCell;

use fips_core::entropy::EntropySource;
use fips_core::time::{Duration, Instant};
use rand::SeedableRng;
use rand::rngs::StdRng;

/// An entropy source of zero bytes, for the hash keys of the machine's maps:
/// no test depends on a particular key.
pub(crate) struct ZeroEntropy;

impl EntropySource for ZeroEntropy {
    fn fill(dest: &mut [u8]) {
        dest.fill(0);
    }
}

std::thread_local! {
    /// The generator behind [`SeededEntropy`], one per test thread.
    static SEEDED: RefCell<StdRng> = RefCell::new(StdRng::seed_from_u64(0));
}

/// An entropy source drawing from a seeded generator, for tests of the
/// pieces that draw at random: a test seeds it, and every draw on that
/// thread follows from the seed.
pub(crate) struct SeededEntropy;

impl SeededEntropy {
    /// Restart this thread's generator from `seed`.
    pub(crate) fn seed(seed: u64) {
        SEEDED.with(|rng| *rng.borrow_mut() = StdRng::seed_from_u64(seed));
    }
}

impl EntropySource for SeededEntropy {
    fn fill(dest: &mut [u8]) {
        SEEDED.with(|rng| rand::Rng::fill_bytes(&mut *rng.borrow_mut(), dest));
    }
}

/// A test instant: whole milliseconds from 0. A duration converts to whole
/// milliseconds, dropping any fraction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TestInstant(pub(crate) u64);

impl Instant for TestInstant {
    fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    fn checked_add(self, d: Duration) -> Option<Self> {
        let ms = u64::try_from(d.as_millis()).ok()?;
        self.0.checked_add(ms).map(Self)
    }

    fn checked_sub(self, d: Duration) -> Option<Self> {
        let ms = u64::try_from(d.as_millis()).ok()?;
        self.0.checked_sub(ms).map(Self)
    }
}
