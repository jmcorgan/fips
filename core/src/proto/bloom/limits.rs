//! v1 bloom filter sizing constants (the tunables).

/// Default filter size in bits (1KB = 8,192 bits).
///
/// Sized for ~800-1,600 entries. FPR ~0.05% at 400 entries, ~0.9% at 800.
/// This is v1 protocol default (size_class=1).
pub const DEFAULT_FILTER_SIZE_BITS: usize = 8192;

/// Default filter size in bytes (1KB).
///
/// Retained for completeness of the v1 tunable set; no current consumer.
#[allow(dead_code)]
pub const DEFAULT_FILTER_SIZE_BYTES: usize = DEFAULT_FILTER_SIZE_BITS / 8;

/// Default number of hash functions.
///
/// k=5 is optimal at ~1,200 entries and a good compromise for 800-1,600.
/// At 400 entries: FPR ~0.05%. At 800 entries: FPR ~0.9%.
pub const DEFAULT_HASH_COUNT: u8 = 5;

/// The v1 acceptance cap on a filter's false-positive rate.
///
/// The default for `node.bloom.max_inbound_fpr`. Only a receiver applies a
/// cap: a sender sends its outgoing filter whatever its fill. 0.20 is fill
/// 0.7248 at k=5, about 2,114 entries.
pub const ACCEPT_FPR_CAP: f64 = 0.20;

/// Size class for v1 protocol (1 KB filters).
pub const V1_SIZE_CLASS: u8 = 1;

/// Filter sizes by size_class: bytes = 512 << size_class
///
/// Retained for completeness of the v1 tunable set; no current consumer.
#[allow(dead_code)]
pub const SIZE_CLASS_BYTES: [usize; 4] = [512, 1024, 2048, 4096];

/// Fewest set bits a filter we sent a tree child must have before that
/// child's announce is checked for echoing it back
/// ([`BloomFilter::echoes`](super::BloomFilter::echoes)).
///
/// About 26 entries at k=5. Below it an honest child can contain every sent
/// bit by chance: a 5-bit filter (one address) is fully covered at the cap's
/// fill 0.7248 with probability 0.2. At 128 bits, with the default threshold
/// 0.8, an honest filter at cap fill crosses the bound (121 of 128 bits) with
/// probability about 1.6e-10 per announce. A returned filter below the floor
/// adds at most about 26 entries upward, which is bounded.
pub const ECHO_MIN_BITS: usize = 128;

/// How many distinct filters sent to each peer are kept for the child echo
/// check.
///
/// A tree child whose view lags can return an earlier filter we sent it
/// rather than the latest, so an announce is tested against each kept filter
/// with the same bound. Each comparison keeps its own false-cross chance, so
/// across the history the chance is at most this many times one comparison's
/// (`core/src/proto/bloom/README.md` gives the figures). An echo of a filter
/// older than the history still passes. Costs one filter (1 KB) per kept
/// filter per peer.
pub const SENT_HISTORY: usize = 4;

/// How long after a child echo refusal from a peer is logged at WARN the
/// later refusals from that peer are logged at DEBUG, in milliseconds.
///
/// Most peers that trip the guard do so transiently: a child that changed
/// parent sends its next filter, the one it sends a non-parent, before its
/// TreeAnnounce reaches us, and the burst ends when the announce lands,
/// usually within a minute. A lasting one can refuse hundreds an hour. A
/// refusal cannot tell the two apart when it happens, so the first refusal
/// in each interval is a warning and the rest are not.
/// The `bloom.child_role_rejected` counter counts every refusal.
pub const ECHO_WARN_MS: u64 = 300_000;
