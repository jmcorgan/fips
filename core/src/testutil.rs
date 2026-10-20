//! Test fixtures shared by the crate's unit tests.

use crate::identity::NodeAddr;

/// Build a `NodeAddr` from a single discriminating byte in position 0.
pub(crate) fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

/// A random secp256k1 keypair, built the way `Identity::generate` builds one.
pub(crate) fn make_keypair() -> secp256k1::Keypair {
    let mut secret = [0u8; 32];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut secret);
    let key =
        secp256k1::SecretKey::from_slice(&secret).expect("32 random bytes is a valid secret key");
    secp256k1::Keypair::from_secret_key(crate::identity::secp(), &key)
}

/// An entropy source that fills every byte with `B`, so a test can tell
/// which source a value was drawn from.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct FixedEntropy<const B: u8>;

impl<const B: u8> crate::entropy::EntropySource for FixedEntropy<B> {
    fn fill(dest: &mut [u8]) {
        dest.fill(B);
    }
}

/// The random source for tests: `rand`'s thread-local generator.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct TestEntropy;

impl crate::entropy::EntropySource for TestEntropy {
    fn fill(dest: &mut [u8]) {
        rand::Rng::fill_bytes(&mut rand::rng(), dest);
    }
}

/// An instant of [`TestClock`]: whole milliseconds from 0.
///
/// Durations convert to whole milliseconds; a fraction of a millisecond is
/// dropped.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TestInstant(pub(crate) u64);

impl crate::time::Instant for TestInstant {
    fn saturating_duration_since(self, earlier: Self) -> crate::time::Duration {
        crate::time::Duration::from_millis(self.0.saturating_sub(earlier.0))
    }

    fn checked_add(self, d: crate::time::Duration) -> Option<Self> {
        let ms = u64::try_from(d.as_millis()).ok()?;
        self.0.checked_add(ms).map(Self)
    }

    fn checked_sub(self, d: crate::time::Duration) -> Option<Self> {
        let ms = u64::try_from(d.as_millis()).ok()?;
        self.0.checked_sub(ms).map(Self)
    }
}

/// The clock for tests: it reads what the test last set, starting at 0, and
/// moves only when the test advances it.
#[derive(Debug, Default)]
pub(crate) struct TestClock {
    now: core::cell::Cell<TestInstant>,
}

impl TestClock {
    /// Move the clock forward by `ms` milliseconds.
    pub(crate) fn advance(&self, ms: u64) {
        self.now.set(TestInstant(self.now.get().0 + ms));
    }
}

impl crate::time::Clock for TestClock {
    type Instant = TestInstant;

    fn now(&self) -> TestInstant {
        self.now.get()
    }
}

/// A SplitMix64 generator: a seeded, reproducible source for simulations.
///
/// Twenty lines with no dependency give byte-identical sequences across
/// toolchains and dependency upgrades, which stored regression seeds need.
/// `TestEntropy` draws from the thread RNG and cannot be replayed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SplitMix64(u64);

impl SplitMix64 {
    /// The generator seeded with `seed`.
    pub(crate) const fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 random bits.
    pub(crate) fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A value drawn from `[0, n)`; 0 when `n` is 0.
    pub(crate) fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }

    /// True with probability `per_mille` / 1000.
    pub(crate) fn chance(&mut self, per_mille: u64) -> bool {
        self.below(1000) < per_mille
    }

    /// One value derived from `seed` and `parts` alone, so a decision keyed
    /// by stable identifiers does not move when an unrelated draw is added
    /// or removed.
    pub(crate) fn mix(seed: u64, parts: &[u64]) -> u64 {
        let mut g = Self::new(seed);
        for &p in parts {
            g.0 ^= p;
            g.next_u64();
        }
        g.next_u64()
    }
}

std::thread_local! {
    /// The generator [`SeededEntropy`] draws from, per test thread.
    static SEEDED: core::cell::Cell<SplitMix64> = const { core::cell::Cell::new(SplitMix64::new(0)) };
}

/// An entropy source drawing from a per-thread SplitMix64, so a simulation
/// that makes real Noise handshakes and session indices replays byte for
/// byte from its seed. Seed it with [`seed_entropy`] before the run.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SeededEntropy;

impl crate::entropy::EntropySource for SeededEntropy {
    fn fill(dest: &mut [u8]) {
        SEEDED.with(|cell| {
            let mut g = cell.get();
            for chunk in dest.chunks_mut(8) {
                let bytes = g.next_u64().to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            cell.set(g);
        });
    }
}

/// Reseed this thread's [`SeededEntropy`].
pub(crate) fn seed_entropy(seed: u64) {
    SEEDED.with(|cell| cell.set(SplitMix64::new(seed)));
}

/// A secp256k1 keypair derived from `seed`, the same on every run.
pub(crate) fn seeded_keypair(seed: u64) -> secp256k1::Keypair {
    let mut g = SplitMix64::new(seed ^ 0x6b65_7970_6169_7273);
    let mut secret = [0u8; 32];
    for chunk in secret.chunks_mut(8) {
        chunk.copy_from_slice(&g.next_u64().to_le_bytes());
    }
    let key = secp256k1::SecretKey::from_slice(&secret).expect("a valid secret key");
    secp256k1::Keypair::from_secret_key(crate::identity::secp(), &key)
}
