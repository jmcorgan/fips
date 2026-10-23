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
/// The default for `node.bloom.max_inbound_fpr`, and the threshold above
/// which an outgoing filter is held rather than sent, whatever this node's
/// own inbound cap. 0.20 is fill 0.7248 at k=5, about 2,114 entries.
pub const ACCEPT_FPR_CAP: f64 = 0.20;

/// Size class for v1 protocol (1 KB filters).
pub const V1_SIZE_CLASS: u8 = 1;

/// Filter sizes by size_class: bytes = 512 << size_class
///
/// Retained for completeness of the v1 tunable set; no current consumer.
#[allow(dead_code)]
pub const SIZE_CLASS_BYTES: [usize; 4] = [512, 1024, 2048, 4096];
