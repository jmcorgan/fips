//! Bloom Filter Implementation
//!
//! 1KB Bloom filters for reachability in FIPS routing. Each node
//! maintains filters that summarize which destinations are reachable
//! through each peer, enabling efficient routing decisions without
//! global network knowledge.
//!
//! ## v1 Parameters
//!
//! - Size: 1 KB (8,192 bits) - sized for actual ~400-800 entry occupancy
//! - Hash functions: k=5 - optimal for 800-1,600 entries at 1KB
//! - Bandwidth: 1 KB/announce (75% reduction from original 4KB design)
//!
//! These parameters are right-sized for typical network occupancy of
//! ~250-800 entries per node.

mod filter;
mod state;

use thiserror::Error;

pub use filter::BloomFilter;
pub use state::BloomState;

/// Default filter size in bits (1KB = 8,192 bits).
///
/// Sized for ~800-1,600 entries with <5% FPR at typical occupancy (~400 entries).
/// This is v1 protocol default (size_class=1).
pub const DEFAULT_FILTER_SIZE_BITS: usize = 8192;

/// Default filter size in bytes (1KB).
pub const DEFAULT_FILTER_SIZE_BYTES: usize = DEFAULT_FILTER_SIZE_BITS / 8;

/// Default number of hash functions.
///
/// k=5 is optimal for 800-1,600 entries at 1KB filter size.
/// At 400 entries: FPR ~0.3%. At 800 entries: FPR ~2.4%.
pub const DEFAULT_HASH_COUNT: u8 = 5;

/// Size class for v1 protocol (1 KB filters).
pub const V1_SIZE_CLASS: u8 = 1;

/// Filter sizes by size_class: bytes = 512 << size_class
pub const SIZE_CLASS_BYTES: [usize; 4] = [512, 1024, 2048, 4096];

/// Errors related to Bloom filter operations.
#[derive(Debug, Error)]
pub enum BloomError {
    #[error("invalid filter size: expected {expected} bits, got {got}")]
    InvalidSize { expected: usize, got: usize },

    #[error("filter size must be a multiple of 8, got {0}")]
    SizeNotByteAligned(usize),

    #[error("hash count must be positive")]
    ZeroHashCount,
}

#[cfg(test)]
mod tests;
