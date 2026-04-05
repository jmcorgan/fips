//! Bloom Filter Implementation
//!
//! Variable-size Bloom filters for reachability in FIPS routing. Each
//! node maintains filters that summarize which destinations are reachable
//! through each peer, enabling efficient routing decisions without
//! global network knowledge.
//!
//! Filter sizes range from 512 bytes (size_class 0) to 32 KB
//! (size_class 6), in power-of-two steps. Nodes choose their own
//! size class based on subtree load and adapt dynamically.
//!
//! ## Parameters
//!
//! - Hash functions: k=5 (network-wide constant)
//! - Default size: 1 KB (size_class 1)

pub mod codec;
mod filter;
mod state;

use thiserror::Error;

pub use filter::BloomFilter;
pub use state::BloomState;

/// Default filter size in bits (1KB = 8,192 bits).
pub const DEFAULT_FILTER_SIZE_BITS: usize = 8192;

/// Default filter size in bytes (1KB).
pub const DEFAULT_FILTER_SIZE_BYTES: usize = DEFAULT_FILTER_SIZE_BITS / 8;

/// Default number of hash functions.
///
/// k=5 is a network-wide constant. Optimal at ~7.2 bits per element.
pub const DEFAULT_HASH_COUNT: u8 = 5;

/// Size class for v1 protocol (1 KB filters).
pub const V1_SIZE_CLASS: u8 = 1;

/// Minimum size class (512 bytes).
pub const MIN_SIZE_CLASS: u8 = 0;

/// Maximum size class (32 KB).
pub const MAX_SIZE_CLASS: u8 = 6;

/// Filter sizes by size_class: bytes = 512 << size_class
pub const SIZE_CLASS_BYTES: [usize; 7] = [512, 1024, 2048, 4096, 8192, 16384, 32768];

/// Convert a size class to filter size in bits.
pub fn size_class_to_bits(size_class: u8) -> usize {
    SIZE_CLASS_BYTES[size_class as usize] * 8
}

/// Convert a filter size in bits to its size class, if valid.
pub fn bits_to_size_class(num_bits: usize) -> Option<u8> {
    let num_bytes = num_bits / 8;
    SIZE_CLASS_BYTES
        .iter()
        .position(|&s| s == num_bytes)
        .map(|i| i as u8)
}

/// Errors related to Bloom filter operations.
#[derive(Debug, Error)]
pub enum BloomError {
    #[error("invalid filter size: expected {expected} bits, got {got}")]
    InvalidSize { expected: usize, got: usize },

    #[error("filter size must be a multiple of 8, got {0}")]
    SizeNotByteAligned(usize),

    #[error("filter size must be a multiple of 64, got {0}")]
    SizeNotWordAligned(usize),

    #[error("hash count must be positive")]
    ZeroHashCount,

    #[error("cannot fold: filter is already at minimum size ({0} bits)")]
    CannotFold(usize),

    #[error("cannot duplicate: filter is already at maximum size ({0} bits)")]
    CannotDuplicate(usize),

    #[error("target size {0} bits is not a valid power-of-two filter size")]
    InvalidTargetSize(usize),
}

#[cfg(test)]
mod tests;
