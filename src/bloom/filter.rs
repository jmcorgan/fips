//! Generic Bloom filter data structure.

use std::fmt;

use tracing::trace;

use super::{
    BloomError, DEFAULT_FILTER_SIZE_BITS, DEFAULT_HASH_COUNT, MAX_SIZE_CLASS, MIN_SIZE_CLASS,
    SIZE_CLASS_BYTES,
};
use crate::NodeAddr;

/// A Bloom filter for probabilistic set membership.
///
/// Used in FIPS to track which destinations are reachable through a peer.
/// The filter uses double hashing to generate k hash functions from two
/// base hashes derived from the input.
///
/// Internal storage uses 64-bit words for efficient bitwise operations
/// and word-level RLE compression.
#[derive(Clone)]
pub struct BloomFilter {
    /// Bit array storage (packed as 64-bit words, little-endian bit order).
    words: Vec<u64>,
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
        if !num_bits.is_multiple_of(64) {
            return Err(BloomError::SizeNotWordAligned(num_bits));
        }
        if hash_count == 0 {
            return Err(BloomError::ZeroHashCount);
        }

        let num_words = num_bits / 64;
        Ok(Self {
            words: vec![0u64; num_words],
            num_bits,
            hash_count,
        })
    }

    /// Create a Bloom filter from raw bytes (little-endian byte order).
    pub fn from_bytes(bytes: Vec<u8>, hash_count: u8) -> Result<Self, BloomError> {
        if hash_count == 0 {
            return Err(BloomError::ZeroHashCount);
        }
        if bytes.is_empty() {
            return Err(BloomError::SizeNotByteAligned(0));
        }
        let num_bits = bytes.len() * 8;
        if !num_bits.is_multiple_of(64) {
            return Err(BloomError::SizeNotWordAligned(num_bits));
        }

        let num_words = num_bits / 64;
        let mut words = Vec::with_capacity(num_words);
        for chunk in bytes.chunks_exact(8) {
            words.push(u64::from_le_bytes(chunk.try_into().unwrap()));
        }

        Ok(Self {
            words,
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
    /// If the other filter is a different size, it is converted to this
    /// filter's size first (fold if larger, duplicate if smaller).
    /// After merge, this filter contains all elements from both filters.
    pub fn merge(&mut self, other: &BloomFilter) -> Result<(), BloomError> {
        if self.num_bits == other.num_bits {
            for (a, b) in self.words.iter_mut().zip(other.words.iter()) {
                *a |= b;
            }
        } else {
            let converted = other.convert_to(self.num_bits)?;
            for (a, b) in self.words.iter_mut().zip(converted.words.iter()) {
                *a |= b;
            }
        }
        Ok(())
    }

    /// Create a new filter that is the union of this and another.
    pub fn union(&self, other: &BloomFilter) -> Result<Self, BloomError> {
        let mut result = self.clone();
        result.merge(other)?;
        Ok(result)
    }

    /// Fold the filter in half (large → small).
    ///
    /// ORs the top half of words with the bottom half, halving the filter
    /// size. No false negatives are introduced, but the fill ratio roughly
    /// doubles.
    pub fn fold(&self) -> Result<BloomFilter, BloomError> {
        let min_bits = SIZE_CLASS_BYTES[MIN_SIZE_CLASS as usize] * 8;
        if self.num_bits <= min_bits {
            return Err(BloomError::CannotFold(self.num_bits));
        }

        let half = self.words.len() / 2;
        let words: Vec<u64> = self.words[..half]
            .iter()
            .zip(self.words[half..].iter())
            .map(|(a, b)| a | b)
            .collect();

        Ok(BloomFilter {
            words,
            num_bits: self.num_bits / 2,
            hash_count: self.hash_count,
        })
    }

    /// Fold repeatedly to reach the target size in bits.
    pub fn fold_to(&self, target_bits: usize) -> Result<BloomFilter, BloomError> {
        if target_bits >= self.num_bits {
            return Err(BloomError::InvalidTargetSize(target_bits));
        }
        if !target_bits.is_power_of_two()
            || target_bits < SIZE_CLASS_BYTES[MIN_SIZE_CLASS as usize] * 8
        {
            return Err(BloomError::InvalidTargetSize(target_bits));
        }

        let mut result = self.fold()?;
        while result.num_bits > target_bits {
            result = result.fold()?;
        }
        Ok(result)
    }

    /// Duplicate the filter (small → large).
    ///
    /// Concatenates the filter with itself, doubling the size.
    /// The duplicated filter is compatible with the larger hash space:
    /// `h(x) mod 2m` maps to either `h(x) mod m` or `h(x) mod m + m`,
    /// and both positions have the bit set.
    pub fn duplicate(&self) -> Result<BloomFilter, BloomError> {
        let max_bits = SIZE_CLASS_BYTES[MAX_SIZE_CLASS as usize] * 8;
        if self.num_bits >= max_bits {
            return Err(BloomError::CannotDuplicate(self.num_bits));
        }

        let mut words = Vec::with_capacity(self.words.len() * 2);
        words.extend_from_slice(&self.words);
        words.extend_from_slice(&self.words);

        Ok(BloomFilter {
            words,
            num_bits: self.num_bits * 2,
            hash_count: self.hash_count,
        })
    }

    /// Duplicate repeatedly to reach the target size in bits.
    pub fn duplicate_to(&self, target_bits: usize) -> Result<BloomFilter, BloomError> {
        if target_bits <= self.num_bits {
            return Err(BloomError::InvalidTargetSize(target_bits));
        }
        if !target_bits.is_power_of_two()
            || target_bits > SIZE_CLASS_BYTES[MAX_SIZE_CLASS as usize] * 8
        {
            return Err(BloomError::InvalidTargetSize(target_bits));
        }

        let mut result = self.duplicate()?;
        while result.num_bits < target_bits {
            result = result.duplicate()?;
        }
        Ok(result)
    }

    /// Convert the filter to a different size.
    ///
    /// Folds (if target is smaller) or duplicates (if target is larger).
    /// Returns a clone if the target matches the current size.
    pub fn convert_to(&self, target_bits: usize) -> Result<BloomFilter, BloomError> {
        if target_bits == self.num_bits {
            return Ok(self.clone());
        }
        if target_bits < self.num_bits {
            self.fold_to(target_bits)
        } else {
            self.duplicate_to(target_bits)
        }
    }

    /// Compute the XOR diff between this filter and another.
    ///
    /// The result contains only the bits that differ between the two filters.
    /// Used for delta compression: `old.xor_diff(&new)` produces a diff that
    /// can be applied to `old` to reconstruct `new`.
    pub fn xor_diff(&self, other: &BloomFilter) -> Result<BloomFilter, BloomError> {
        if self.num_bits != other.num_bits {
            return Err(BloomError::InvalidSize {
                expected: self.num_bits,
                got: other.num_bits,
            });
        }

        let words: Vec<u64> = self
            .words
            .iter()
            .zip(other.words.iter())
            .map(|(a, b)| a ^ b)
            .collect();

        Ok(BloomFilter {
            words,
            num_bits: self.num_bits,
            hash_count: self.hash_count,
        })
    }

    /// Apply a XOR diff to this filter in place.
    ///
    /// This is the inverse of `xor_diff()`: if `diff = old.xor_diff(&new)`,
    /// then `old.apply_diff(&diff)` transforms `old` into `new`.
    pub fn apply_diff(&mut self, diff: &BloomFilter) -> Result<(), BloomError> {
        if self.num_bits != diff.num_bits {
            return Err(BloomError::InvalidSize {
                expected: self.num_bits,
                got: diff.num_bits,
            });
        }

        for (a, b) in self.words.iter_mut().zip(diff.words.iter()) {
            *a ^= b;
        }
        Ok(())
    }

    /// Clear all bits in the filter.
    pub fn clear(&mut self) {
        self.words.fill(0);
    }

    /// Count the number of set bits (population count).
    pub fn count_ones(&self) -> usize {
        self.words.iter().map(|w| w.count_ones() as usize).sum()
    }

    /// Estimate the fill ratio (set bits / total bits).
    pub fn fill_ratio(&self) -> f64 {
        self.count_ones() as f64 / self.num_bits as f64
    }

    /// Estimate the number of elements in the filter.
    ///
    /// Uses the formula: n = -(m/k) * ln(1 - X/m)
    /// where m = num_bits, k = hash_count, X = count_ones
    ///
    /// Returns `None` when the filter's FPR exceeds `max_fpr` (antipoison
    /// cap) or the filter is saturated (`count_ones() >= num_bits`). Pass
    /// `f64::INFINITY` for `max_fpr` to disable the cap — useful in
    /// Debug/log contexts where no policy is in scope. The saturated
    /// branch is always honored regardless of `max_fpr`, preventing the
    /// `f64::INFINITY` return that the previous signature produced.
    pub fn estimated_count(&self, max_fpr: f64) -> Option<f64> {
        let m = self.num_bits as f64;
        let k = self.hash_count as f64;
        let x = self.count_ones() as f64;

        if x >= m {
            return None;
        }

        let fill = x / m;
        let fpr = fill.powi(self.hash_count as i32);
        if fpr > max_fpr {
            trace!(fill, fpr, max_fpr, "estimated_count: filter above cap");
            return None;
        }

        Some(-(m / k) * (1.0 - fill).ln())
    }

    /// Check if the filter is empty.
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Get the filter contents as bytes (little-endian byte order).
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(self.words.len() * 8);
        for &word in &self.words {
            bytes.extend_from_slice(&word.to_le_bytes());
        }
        bytes
    }

    /// Get the internal word storage.
    pub fn as_words(&self) -> &[u64] {
        &self.words
    }

    /// Get the number of 64-bit words in the filter.
    pub fn num_words(&self) -> usize {
        self.words.len()
    }

    /// Get the filter size in bits.
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// Get the filter size in bytes.
    pub fn num_bytes(&self) -> usize {
        self.words.len() * 8
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
        let word_index = index / 64;
        let bit_offset = index % 64;
        self.words[word_index] |= 1 << bit_offset;
    }

    fn get_bit(&self, index: usize) -> bool {
        let word_index = index / 64;
        let bit_offset = index % 64;
        (self.words[word_index] >> bit_offset) & 1 == 1
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
            && self.words == other.words
    }
}

impl Eq for BloomFilter {}

impl fmt::Debug for BloomFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BloomFilter")
            .field("bits", &self.num_bits)
            .field("hash_count", &self.hash_count)
            .field("fill_ratio", &format!("{:.2}%", self.fill_ratio() * 100.0))
            .field(
                "est_count",
                &match self.estimated_count(f64::INFINITY) {
                    Some(n) => format!("{:.0}", n),
                    None => "saturated".to_string(),
                },
            )
            .finish()
    }
}
