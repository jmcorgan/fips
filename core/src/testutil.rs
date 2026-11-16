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

std::thread_local! {
    /// Allocations this thread has made, for tests that a method allocates
    /// nothing.
    static ALLOCATIONS: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// The test binary's allocator: the system's, counting each thread's
/// allocations.
struct Counting;

// SAFETY: every call is passed to the system allocator unchanged.
unsafe impl std::alloc::GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        // A thread whose counter is already gone, as it exits, counts
        // nothing.
        let _ = ALLOCATIONS.try_with(|n| n.set(n.get() + 1));
        // SAFETY: the caller's contract is the system allocator's.
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        // SAFETY: as above.
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// Allocations this thread has made so far, through any of the
/// allocator's entry points: `alloc_zeroed` and `realloc` reach `alloc`.
pub(crate) fn allocations() -> u64 {
    ALLOCATIONS.with(core::cell::Cell::get)
}

/// The most threads [`bounded`] runs at once: what `threads-required`
/// declares for the explorers that use it in `.config/nextest.toml`, so a
/// test runner that counts the threads a test takes counts these.
pub(crate) const WORKERS: usize = 4;

/// Run `job` on each of `items`, each on a fresh thread of its own, at
/// most [`WORKERS`] at once (fewer on a host with fewer CPUs), and return
/// the results in the order of `items`. A job that panics frees its place
/// and the panic is raised once every job has ended.
///
/// The explorers' starts differ in cost by a hundredfold, so a thread per
/// start, all at once, put twenty runnable threads behind each test that
/// nextest counted as one, and a test's time became that of every explorer
/// it ran beside. A fresh thread per job keeps each job's thread-local
/// state (seeded entropy, fault switches, caches) as it was when every job
/// had a thread of its own from the start.
pub(crate) fn bounded<T: Sync, R: Send>(
    items: &[T],
    job: impl Fn(&T) -> R + Sync,
) -> alloc::vec::Vec<R> {
    /// Tells the spawning loop that a job has ended, on return or unwind.
    struct Done(std::sync::mpsc::Sender<()>);
    impl Drop for Done {
        fn drop(&mut self) {
            let _ = self.0.send(());
        }
    }
    let most = std::thread::available_parallelism().map_or(1, |n| n.get().min(WORKERS));
    let job = &job;
    std::thread::scope(|s| {
        let (done, ended) = std::sync::mpsc::channel();
        let mut handles = alloc::vec::Vec::with_capacity(items.len());
        for (i, item) in items.iter().enumerate() {
            if i >= most {
                // A place frees only when a job ends, and `done` is held
                // here, so this returns once one has.
                let _ = ended.recv();
            }
            let done = Done(done.clone());
            handles.push(s.spawn(move || {
                let _done = done;
                job(item)
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect()
    })
}

/// The full path of every test this test binary compiles, read from its own
/// `--list`. The guard-switch meta-tests read it to tell a named test that
/// only the explorers' build compiles (the core's `slow-explorers` feature)
/// from one this build runs.
#[cfg(feature = "slow-tests")]
pub(crate) fn compiled_tests() -> alloc::vec::Vec<alloc::string::String> {
    let exe = std::env::current_exe().expect("the test binary's path");
    let out = std::process::Command::new(exe)
        .args(["--list", "--format", "terse"])
        .output()
        .expect("the test binary lists its tests");
    assert!(out.status.success(), "the test binary lists its tests");
    alloc::string::String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.strip_suffix(": test"))
        .map(alloc::string::String::from)
        .collect()
}

/// The attribute that compiles an item only in the explorers' build.
#[cfg(feature = "slow-tests")]
const EXPLORERS_GATE: &str = "#[cfg(feature = \"slow-explorers\")]";

/// The attribute and comment lines directly above line `at`, trimmed.
#[cfg(feature = "slow-tests")]
fn attributes<'a>(lines: &[&'a str], at: usize) -> impl Iterator<Item = &'a str> {
    lines[..at]
        .iter()
        .rev()
        .map(|l| l.trim())
        .take_while(|l| l.starts_with("#[") || l.starts_with("//"))
}

/// Whether `line` declares the module `name`, as `mod name;` or
/// `mod name {`, with any visibility.
#[cfg(feature = "slow-tests")]
fn declares(line: &str, name: &str) -> bool {
    let line = line.trim();
    let rest = if line.starts_with("pub") {
        line.split_once(' ').map_or("", |(_, r)| r)
    } else {
        line
    };
    rest.strip_prefix("mod ")
        .and_then(|r| r.strip_prefix(name))
        .is_some_and(|r| r == ";" || r.trim_start().starts_with('{'))
}

/// Whether the sources show the test at `path`, a path as `--list` prints
/// it, compiled only by the explorers' build (the core's `slow-explorers`
/// feature): its function is in the file its module path leads to, and the
/// function, a module on the path, or that whole file carries the feature's
/// `cfg`. The guard-switch meta-tests accept a named test this build does
/// not compile only when this holds, so a misspelled or renamed name fails
/// them in every build. Modules are followed through `mod name;` (to
/// `name.rs` or `name/mod.rs`), `#[path = "..."]` and inline `mod name {`;
/// a layout it cannot follow answers false, which fails the meta-test.
#[cfg(feature = "slow-tests")]
pub(crate) fn explorer_only(path: &str) -> bool {
    use alloc::vec::Vec;
    use std::path::{Path, PathBuf};

    let mut segs: Vec<&str> = path.split("::").collect();
    let Some(name) = segs.pop() else {
        return false;
    };
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut file: PathBuf = src.join("lib.rs");
    let mut dir = src;
    let Ok(mut text) = std::fs::read_to_string(&file) else {
        return false;
    };
    let mut gated = false;
    for seg in segs {
        let lines: Vec<&str> = text.lines().collect();
        let Some(at) = lines.iter().position(|l| declares(l, seg)) else {
            return false;
        };
        gated |= attributes(&lines, at).any(|a| a == EXPLORERS_GATE);
        if lines[at].trim_end().ends_with('{') {
            dir = dir.join(seg);
            continue;
        }
        let named = attributes(&lines, at).find_map(|a| {
            a.strip_prefix("#[path = \"")
                .and_then(|r| r.strip_suffix("\"]"))
        });
        let next = match named {
            Some(p) => file.parent().map(|d| d.join(p)),
            None => [
                dir.join(alloc::format!("{seg}.rs")),
                dir.join(seg).join("mod.rs"),
            ]
            .into_iter()
            .find(|p| p.is_file()),
        };
        let Some(next) = next else {
            return false;
        };
        let Ok(t) = std::fs::read_to_string(&next) else {
            return false;
        };
        dir = dir.join(seg);
        file = next;
        text = t;
    }
    let lines: Vec<&str> = text.lines().collect();
    gated |= lines
        .iter()
        .any(|l| l.trim() == "#![cfg(feature = \"slow-explorers\")]");
    let def = alloc::format!("fn {name}(");
    let Some(at) = lines.iter().position(|l| l.trim_start().starts_with(&def)) else {
        return false;
    };
    gated || attributes(&lines, at).any(|a| a == EXPLORERS_GATE)
}

#[cfg(test)]
#[path = "tests/testutil.rs"]
mod tests;
