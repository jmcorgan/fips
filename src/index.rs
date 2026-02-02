//! Session Index Allocator
//!
//! Manages allocation of 32-bit session indices for O(1) packet dispatch.
//! Each Noise session receives a unique index chosen by the receiver;
//! incoming encrypted packets include the receiver's index for fast lookup.
//!
//! ## Design
//!
//! - Indices are random (cryptographically secure) to prevent guessing
//! - Unique per transport to avoid collision between transports
//! - 32-bit space supports ~65K concurrent sessions before birthday collision
//! - Indices are rotated on rekey for anti-correlation
//!
//! ## Wire Format
//!
//! Encrypted frames include receiver_idx for session lookup:
//!
//! ```text
//! [0x00][receiver_idx:4 LE][counter:8 LE][ciphertext+tag]
//! ```

use rand::Rng;
use std::collections::HashSet;
use thiserror::Error;

/// Errors related to index allocation.
#[derive(Debug, Error)]
pub enum IndexError {
    #[error("no available indices (too many active sessions)")]
    Exhausted,

    #[error("index {0} not found")]
    NotFound(u32),

    #[error("index {0} already in use")]
    AlreadyInUse(u32),
}

/// A 32-bit session index.
///
/// Wrapper type for type safety and clarity in APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionIndex(u32);

impl SessionIndex {
    /// Create from raw u32.
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get the raw u32 value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }

    /// Convert to little-endian bytes.
    pub fn to_le_bytes(&self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    /// Create from little-endian bytes.
    pub fn from_le_bytes(bytes: [u8; 4]) -> Self {
        Self(u32::from_le_bytes(bytes))
    }
}

impl std::fmt::Display for SessionIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

/// Allocator for session indices within a single transport.
///
/// Manages a pool of random 32-bit indices, tracking which are in use
/// to prevent collision. Thread-safe for single-threaded async use.
#[derive(Debug)]
pub struct IndexAllocator {
    /// Set of currently allocated indices.
    in_use: HashSet<u32>,
    /// Maximum allocation attempts before giving up.
    max_attempts: usize,
}

impl IndexAllocator {
    /// Create a new index allocator.
    pub fn new() -> Self {
        Self {
            in_use: HashSet::new(),
            max_attempts: 100,
        }
    }

    /// Create with a specific max attempts limit.
    pub fn with_max_attempts(max_attempts: usize) -> Self {
        Self {
            in_use: HashSet::new(),
            max_attempts,
        }
    }

    /// Allocate a new random index.
    ///
    /// Returns a cryptographically random 32-bit index that is not
    /// currently in use. Returns error if allocation fails after
    /// max_attempts tries (indicates too many active sessions).
    pub fn allocate(&mut self) -> Result<SessionIndex, IndexError> {
        let mut rng = rand::thread_rng();

        for _ in 0..self.max_attempts {
            let candidate = rng.r#gen::<u32>();
            if !self.in_use.contains(&candidate) {
                self.in_use.insert(candidate);
                return Ok(SessionIndex(candidate));
            }
        }

        Err(IndexError::Exhausted)
    }

    /// Free an index, returning it to the available pool.
    ///
    /// Returns error if the index was not allocated.
    pub fn free(&mut self, index: SessionIndex) -> Result<(), IndexError> {
        if self.in_use.remove(&index.0) {
            Ok(())
        } else {
            Err(IndexError::NotFound(index.0))
        }
    }

    /// Check if an index is currently allocated.
    pub fn is_allocated(&self, index: SessionIndex) -> bool {
        self.in_use.contains(&index.0)
    }

    /// Number of currently allocated indices.
    pub fn count(&self) -> usize {
        self.in_use.len()
    }

    /// Check if the allocator is empty (no indices allocated).
    pub fn is_empty(&self) -> bool {
        self.in_use.is_empty()
    }

    /// Reserve a specific index (for testing or migration).
    ///
    /// Returns error if the index is already in use.
    pub fn reserve(&mut self, index: SessionIndex) -> Result<(), IndexError> {
        if self.in_use.contains(&index.0) {
            Err(IndexError::AlreadyInUse(index.0))
        } else {
            self.in_use.insert(index.0);
            Ok(())
        }
    }

    /// Clear all allocations (use with caution).
    pub fn clear(&mut self) {
        self.in_use.clear();
    }
}

impl Default for IndexAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_index_roundtrip() {
        let idx = SessionIndex::new(0x12345678);
        assert_eq!(idx.as_u32(), 0x12345678);

        let bytes = idx.to_le_bytes();
        assert_eq!(bytes, [0x78, 0x56, 0x34, 0x12]);

        let restored = SessionIndex::from_le_bytes(bytes);
        assert_eq!(restored, idx);
    }

    #[test]
    fn test_session_index_display() {
        let idx = SessionIndex::new(0x000000ff);
        assert_eq!(format!("{}", idx), "000000ff");

        let idx = SessionIndex::new(0xdeadbeef);
        assert_eq!(format!("{}", idx), "deadbeef");
    }

    #[test]
    fn test_allocator_basic() {
        let mut alloc = IndexAllocator::new();
        assert!(alloc.is_empty());
        assert_eq!(alloc.count(), 0);

        let idx1 = alloc.allocate().unwrap();
        assert!(!alloc.is_empty());
        assert_eq!(alloc.count(), 1);
        assert!(alloc.is_allocated(idx1));

        let idx2 = alloc.allocate().unwrap();
        assert_eq!(alloc.count(), 2);
        assert!(alloc.is_allocated(idx2));
        assert_ne!(idx1, idx2);

        alloc.free(idx1).unwrap();
        assert_eq!(alloc.count(), 1);
        assert!(!alloc.is_allocated(idx1));
        assert!(alloc.is_allocated(idx2));
    }

    #[test]
    fn test_allocator_free_not_found() {
        let mut alloc = IndexAllocator::new();
        let result = alloc.free(SessionIndex::new(12345));
        assert!(matches!(result, Err(IndexError::NotFound(12345))));
    }

    #[test]
    fn test_allocator_reserve() {
        let mut alloc = IndexAllocator::new();

        let idx = SessionIndex::new(0xdeadbeef);
        alloc.reserve(idx).unwrap();
        assert!(alloc.is_allocated(idx));

        // Double reserve fails
        let result = alloc.reserve(idx);
        assert!(matches!(result, Err(IndexError::AlreadyInUse(0xdeadbeef))));
    }

    #[test]
    fn test_allocator_uniqueness() {
        let mut alloc = IndexAllocator::new();
        let mut indices = Vec::new();

        // Allocate 1000 indices and verify all unique
        for _ in 0..1000 {
            let idx = alloc.allocate().unwrap();
            assert!(!indices.contains(&idx));
            indices.push(idx);
        }

        assert_eq!(alloc.count(), 1000);
    }

    #[test]
    fn test_allocator_clear() {
        let mut alloc = IndexAllocator::new();

        for _ in 0..10 {
            alloc.allocate().unwrap();
        }
        assert_eq!(alloc.count(), 10);

        alloc.clear();
        assert!(alloc.is_empty());
        assert_eq!(alloc.count(), 0);
    }

    #[test]
    fn test_allocator_reuse_after_free() {
        let mut alloc = IndexAllocator::new();

        let idx = alloc.allocate().unwrap();
        alloc.free(idx).unwrap();

        // The specific index might not be reused immediately (random),
        // but the count should allow allocation
        let idx2 = alloc.allocate().unwrap();
        assert_eq!(alloc.count(), 1);

        // Can now reserve the original index if it wasn't randomly reused
        if idx != idx2 {
            alloc.reserve(idx).unwrap();
        }
    }
}
