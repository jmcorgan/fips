//! Generic Bloom filter data structure.

use std::fmt;

use super::{BloomError, DEFAULT_FILTER_SIZE_BITS, DEFAULT_HASH_COUNT};
use crate::NodeAddr;

/// A Bloom filter for probabilistic set membership.
///
/// Used in FIPS to track which destinations are reachable through a peer.
/// The filter uses double hashing to generate k hash functions from two
/// base hashes derived from the input.
#[derive(Clone)]
pub struct BloomFilter {
    /// Bit array storage (packed as bytes).
    bits: Vec<u8>,
    /// Number of bits in the filter.
    num_bits: usize,
    /// Number of hash functions to use.
    hash_count: u8,
}

impl BloomFilter {
    /// Create a new empty Bloom filter with default parameters.
    pub fn new() -> Self {
        Self::with_params(DEFAULT_FILTER_SIZE_BITS, DEFAULT_HASH_COUNT)
            .expect("default params are valid")
    }

    /// Create a Bloom filter with custom parameters.
    pub fn with_params(num_bits: usize, hash_count: u8) -> Result<Self, BloomError> {
        if num_bits == 0 || !num_bits.is_multiple_of(8) {
            return Err(BloomError::SizeNotByteAligned(num_bits));
        }
        if hash_count == 0 {
            return Err(BloomError::ZeroHashCount);
        }

        let num_bytes = num_bits / 8;
        Ok(Self {
            bits: vec![0u8; num_bytes],
            num_bits,
            hash_count,
        })
    }

    /// Create a Bloom filter from raw bytes.
    pub fn from_bytes(bytes: Vec<u8>, hash_count: u8) -> Result<Self, BloomError> {
        if hash_count == 0 {
            return Err(BloomError::ZeroHashCount);
        }
        if bytes.is_empty() {
            return Err(BloomError::SizeNotByteAligned(0));
        }
        let num_bits = bytes.len() * 8;
        Ok(Self {
            bits: bytes,
            num_bits,
            hash_count,
        })
    }

    /// Create a Bloom filter from a byte slice.
    pub fn from_slice(bytes: &[u8], hash_count: u8) -> Result<Self, BloomError> {
        Self::from_bytes(bytes.to_vec(), hash_count)
    }

    /// Insert a NodeAddr into the filter.
    pub fn insert(&mut self, node_addr: &NodeAddr) {
        for i in 0..self.hash_count {
            let bit_index = self.hash(node_addr.as_bytes(), i);
            self.set_bit(bit_index);
        }
    }

    /// Insert raw bytes into the filter.
    pub fn insert_bytes(&mut self, data: &[u8]) {
        for i in 0..self.hash_count {
            let bit_index = self.hash(data, i);
            self.set_bit(bit_index);
        }
    }

    /// Check if the filter might contain a NodeAddr.
    ///
    /// Returns `true` if the item might be in the set (possible false positive).
    /// Returns `false` if the item is definitely not in the set.
    pub fn contains(&self, node_addr: &NodeAddr) -> bool {
        self.contains_bytes(node_addr.as_bytes())
    }

    /// Check if the filter might contain raw bytes.
    pub fn contains_bytes(&self, data: &[u8]) -> bool {
        for i in 0..self.hash_count {
            let bit_index = self.hash(data, i);
            if !self.get_bit(bit_index) {
                return false;
            }
        }
        true
    }

    /// Merge another filter into this one (OR operation).
    ///
    /// After merge, this filter contains all elements from both filters.
    pub fn merge(&mut self, other: &BloomFilter) -> Result<(), BloomError> {
        if self.num_bits != other.num_bits {
            return Err(BloomError::InvalidSize {
                expected: self.num_bits,
                got: other.num_bits,
            });
        }

        for (a, b) in self.bits.iter_mut().zip(other.bits.iter()) {
            *a |= b;
        }
        Ok(())
    }

    /// Create a new filter that is the union of this and another.
    pub fn union(&self, other: &BloomFilter) -> Result<Self, BloomError> {
        let mut result = self.clone();
        result.merge(other)?;
        Ok(result)
    }

    /// Clear all bits in the filter.
    pub fn clear(&mut self) {
        self.bits.fill(0);
    }

    /// Count the number of set bits (population count).
    pub fn count_ones(&self) -> usize {
        self.bits.iter().map(|b| b.count_ones() as usize).sum()
    }

    /// Estimate the fill ratio (set bits / total bits).
    pub fn fill_ratio(&self) -> f64 {
        self.count_ones() as f64 / self.num_bits as f64
    }

    /// Estimate the number of elements in the filter.
    ///
    /// Uses the formula: n = -(m/k) * ln(1 - X/m)
    /// where m = num_bits, k = hash_count, X = count_ones
    pub fn estimated_count(&self) -> f64 {
        let m = self.num_bits as f64;
        let k = self.hash_count as f64;
        let x = self.count_ones() as f64;

        if x >= m {
            return f64::INFINITY;
        }

        -(m / k) * (1.0 - x / m).ln()
    }

    /// Check if the filter is empty.
    pub fn is_empty(&self) -> bool {
        self.bits.iter().all(|&b| b == 0)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bits
    }

    /// Get the filter size in bits.
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Get the filter size in bytes.
    pub fn num_bytes(&self) -> usize {
        self.bits.len()
    }

    /// Get the number of hash functions.
    pub fn hash_count(&self) -> u8 {
        self.hash_count
    }

    /// Compute a hash index for the given data and hash function number.
    ///
    /// Uses double hashing: h(x,i) = (h1(x) + i*h2(x)) mod m
    fn hash(&self, data: &[u8], k: u8) -> usize {
        // Use first 16 bytes of SHA-256 for h1 and h2
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // h1 from first 8 bytes
        let h1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        // h2 from next 8 bytes
        let h2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());

        let combined = h1.wrapping_add((k as u64).wrapping_mul(h2));
        (combined as usize) % self.num_bits
    }

    fn set_bit(&mut self, index: usize) {
        let byte_index = index / 8;
        let bit_offset = index % 8;
        self.bits[byte_index] |= 1 << bit_offset;
    }

    fn get_bit(&self, index: usize) -> bool {
        let byte_index = index / 8;
        let bit_offset = index % 8;
        (self.bits[byte_index] >> bit_offset) & 1 == 1
    }
}

impl Default for BloomFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl PartialEq for BloomFilter {
    fn eq(&self, other: &Self) -> bool {
        self.num_bits == other.num_bits
            && self.hash_count == other.hash_count
            && self.bits == other.bits
    }
}

impl Eq for BloomFilter {}

impl fmt::Debug for BloomFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BloomFilter")
            .field("bits", &self.num_bits)
            .field("hash_count", &self.hash_count)
            .field("fill_ratio", &format!("{:.2}%", self.fill_ratio() * 100.0))
            .field("est_count", &format!("{:.0}", self.estimated_count()))
            .finish()
    }
}
