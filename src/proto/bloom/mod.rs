//! Sans-IO bloom filter subsystem.
//!
//! 1KB Bloom filters for reachability in FIPS routing. Each node maintains
//! filters that summarize which destinations are reachable through each peer,
//! enabling efficient routing decisions without global network knowledge.
//!
//! ## v1 Parameters
//!
//! - Size: 1 KB (8,192 bits) - sized for actual ~400-800 entry occupancy
//! - Hash functions: k=5 - optimal at ~1,200 entries, good for 800-1,600
//! - Bandwidth: 1 KB/announce (75% reduction from original 4KB design)
//!
//! - `core.rs` — the pure `BloomFilter` data structure.
//! - `state.rs` — `BloomState` (per-peer inbound store + outgoing filter
//!   computation + the send-debounce decision).
//! - `limits.rs` — the v1 sizing constants.
//! - `wire.rs` — `FilterAnnounce` + `encode`/`decode` (the std-tethered file).
//!   It imports the shared [`crate::proto::Error`] and
//!   [`crate::proto::link::LinkMessageType`] downward.

mod core;
mod limits;
mod state;
mod wire;

#[cfg(test)]
mod tests;

pub use core::BloomFilter;
pub use limits::{DEFAULT_FILTER_SIZE_BITS, DEFAULT_HASH_COUNT, V1_SIZE_CLASS};
pub use state::BloomState;
pub use wire::FilterAnnounce;

/// Errors related to Bloom filter operations.
#[derive(Debug)]
pub enum BloomError {
    /// Filter bit length did not match the expected size.
    InvalidSize {
        /// Expected number of bits.
        expected: usize,
        /// Number of bits received.
        got: usize,
    },

    /// Filter size was not a multiple of 8 bits.
    SizeNotByteAligned(usize),

    /// Hash count was zero.
    ZeroHashCount,
}

impl ::core::fmt::Display for BloomError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        match self {
            BloomError::InvalidSize { expected, got } => {
                write!(
                    f,
                    "invalid filter size: expected {expected} bits, got {got}"
                )
            }
            BloomError::SizeNotByteAligned(n) => {
                write!(f, "filter size must be a multiple of 8, got {n}")
            }
            BloomError::ZeroHashCount => write!(f, "hash count must be positive"),
        }
    }
}

impl ::core::error::Error for BloomError {}
