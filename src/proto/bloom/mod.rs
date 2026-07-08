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

use thiserror::Error;

pub use core::BloomFilter;
pub use limits::{DEFAULT_FILTER_SIZE_BITS, DEFAULT_HASH_COUNT, V1_SIZE_CLASS};
pub use state::BloomState;
pub use wire::FilterAnnounce;

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
