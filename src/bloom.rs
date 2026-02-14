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

use crate::NodeAddr;
use std::collections::{HashMap, HashSet};
use std::fmt;
use thiserror::Error;

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

/// State for managing Bloom filter announcements.
///
/// Tracks local filter state and what needs to be sent to peers.
#[derive(Clone, Debug)]
pub struct BloomState {
    /// This node's NodeAddr (always included in outgoing filters).
    own_node_addr: NodeAddr,
    /// Leaf-only nodes we speak for (included in our filter).
    leaf_dependents: HashSet<NodeAddr>,
    /// Whether this node operates in leaf-only mode.
    is_leaf_only: bool,
    /// Rate limiting: minimum interval between outgoing updates (milliseconds).
    update_debounce_ms: u64,
    /// Timestamp of last update sent (per peer, in milliseconds).
    last_update_sent: HashMap<NodeAddr, u64>,
    /// Peers that need a filter update.
    pending_updates: HashSet<NodeAddr>,
    /// Current sequence number for outgoing filters.
    sequence: u64,
    /// Last outgoing filter sent to each peer (for change detection).
    last_sent_filters: HashMap<NodeAddr, BloomFilter>,
}

impl BloomState {
    /// Create new Bloom state for a node.
    pub fn new(own_node_addr: NodeAddr) -> Self {
        Self {
            own_node_addr,
            leaf_dependents: HashSet::new(),
            is_leaf_only: false,
            update_debounce_ms: 500,
            last_update_sent: HashMap::new(),
            pending_updates: HashSet::new(),
            sequence: 0,
            last_sent_filters: HashMap::new(),
        }
    }

    /// Create state for a leaf-only node.
    pub fn leaf_only(own_node_addr: NodeAddr) -> Self {
        let mut state = Self::new(own_node_addr);
        state.is_leaf_only = true;
        state
    }

    /// Get the node's own ID.
    pub fn own_node_addr(&self) -> &NodeAddr {
        &self.own_node_addr
    }

    /// Check if this is a leaf-only node.
    pub fn is_leaf_only(&self) -> bool {
        self.is_leaf_only
    }

    /// Get the current sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Increment and return the next sequence number.
    pub fn next_sequence(&mut self) -> u64 {
        self.sequence += 1;
        self.sequence
    }

    /// Get the update debounce interval in milliseconds.
    pub fn update_debounce_ms(&self) -> u64 {
        self.update_debounce_ms
    }

    /// Set the update debounce interval.
    pub fn set_update_debounce_ms(&mut self, ms: u64) {
        self.update_debounce_ms = ms;
    }

    /// Add a leaf dependent that we'll include in our filter.
    pub fn add_leaf_dependent(&mut self, node_addr: NodeAddr) {
        self.leaf_dependents.insert(node_addr);
    }

    /// Remove a leaf dependent.
    pub fn remove_leaf_dependent(&mut self, node_addr: &NodeAddr) -> bool {
        self.leaf_dependents.remove(node_addr)
    }

    /// Get the set of leaf dependents.
    pub fn leaf_dependents(&self) -> &HashSet<NodeAddr> {
        &self.leaf_dependents
    }

    /// Number of leaf dependents.
    pub fn leaf_dependent_count(&self) -> usize {
        self.leaf_dependents.len()
    }

    /// Mark that a peer needs an update.
    pub fn mark_update_needed(&mut self, peer_id: NodeAddr) {
        self.pending_updates.insert(peer_id);
    }

    /// Mark all peers as needing updates.
    pub fn mark_all_updates_needed(&mut self, peer_ids: impl IntoIterator<Item = NodeAddr>) {
        self.pending_updates.extend(peer_ids);
    }

    /// Check if a peer needs an update.
    pub fn needs_update(&self, peer_id: &NodeAddr) -> bool {
        self.pending_updates.contains(peer_id)
    }

    /// Check if we should send an update to a peer (respecting debounce).
    pub fn should_send_update(&self, peer_id: &NodeAddr, current_time_ms: u64) -> bool {
        if !self.pending_updates.contains(peer_id) {
            return false;
        }

        match self.last_update_sent.get(peer_id) {
            Some(&last_time) => current_time_ms >= last_time + self.update_debounce_ms,
            None => true,
        }
    }

    /// Record that we sent an update to a peer.
    pub fn record_update_sent(&mut self, peer_id: NodeAddr, current_time_ms: u64) {
        self.last_update_sent.insert(peer_id, current_time_ms);
        self.pending_updates.remove(&peer_id);
    }

    /// Clear all pending updates.
    pub fn clear_pending_updates(&mut self) {
        self.pending_updates.clear();
    }

    /// Record the outgoing filter that was sent to a peer.
    pub fn record_sent_filter(&mut self, peer_id: NodeAddr, filter: BloomFilter) {
        self.last_sent_filters.insert(peer_id, filter);
    }

    /// Remove stored filter state for a peer that was removed.
    pub fn remove_peer_state(&mut self, peer_id: &NodeAddr) {
        self.last_sent_filters.remove(peer_id);
        self.last_update_sent.remove(peer_id);
        self.pending_updates.remove(peer_id);
    }

    /// Mark only peers whose outgoing filter has actually changed.
    ///
    /// Computes the outgoing filter for each peer and compares it
    /// against what was last sent. Only marks peers where the filter
    /// differs. This prevents cascading update loops in steady state.
    pub fn mark_changed_peers(
        &mut self,
        exclude_from: &NodeAddr,
        peer_addrs: &[NodeAddr],
        peer_filters: &HashMap<NodeAddr, BloomFilter>,
    ) {
        for peer_addr in peer_addrs {
            if peer_addr == exclude_from {
                continue;
            }
            let new_filter = self.compute_outgoing_filter(peer_addr, peer_filters);
            let changed = match self.last_sent_filters.get(peer_addr) {
                Some(last) => *last != new_filter,
                None => true, // never sent → must send
            };
            if changed {
                self.pending_updates.insert(*peer_addr);
            }
        }
    }

    /// Compute the outgoing filter for a specific peer.
    ///
    /// The filter includes:
    /// - This node's own ID
    /// - All leaf dependents
    /// - Entries from other peers' inbound filters (excluding the destination peer)
    ///
    /// The `peer_filters` map contains inbound filters from each peer.
    /// The filter for `exclude_peer` is excluded to prevent routing loops.
    pub fn compute_outgoing_filter(
        &self,
        exclude_peer: &NodeAddr,
        peer_filters: &HashMap<NodeAddr, BloomFilter>,
    ) -> BloomFilter {
        let mut filter = BloomFilter::new();

        // Always include ourselves
        filter.insert(&self.own_node_addr);

        // Include leaf dependents
        for dep in &self.leaf_dependents {
            filter.insert(dep);
        }

        // Merge filters from other peers
        for (peer_id, peer_filter) in peer_filters {
            if peer_id != exclude_peer {
                // Ignore merge errors (size mismatches) - just skip that filter
                let _ = filter.merge(peer_filter);
            }
        }

        filter
    }

    /// Create a base filter containing just this node and its dependents.
    pub fn base_filter(&self) -> BloomFilter {
        let mut filter = BloomFilter::new();
        filter.insert(&self.own_node_addr);
        for dep in &self.leaf_dependents {
            filter.insert(dep);
        }
        filter
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    // ===== BloomFilter Tests =====

    #[test]
    fn test_bloom_filter_new() {
        let filter = BloomFilter::new();
        assert_eq!(filter.num_bits(), DEFAULT_FILTER_SIZE_BITS);
        assert_eq!(filter.hash_count(), DEFAULT_HASH_COUNT);
        assert_eq!(filter.count_ones(), 0);
        assert!(filter.is_empty());
    }

    #[test]
    fn test_bloom_filter_insert_contains() {
        let mut filter = BloomFilter::new();
        let node1 = make_node_addr(1);
        let node2 = make_node_addr(2);

        assert!(!filter.contains(&node1));
        assert!(!filter.contains(&node2));

        filter.insert(&node1);

        assert!(filter.contains(&node1));
        // node2 might have false positive, but very unlikely with single insert
        assert!(!filter.is_empty());
    }

    #[test]
    fn test_bloom_filter_multiple_inserts() {
        let mut filter = BloomFilter::new();

        for i in 0..100 {
            let node = make_node_addr(i);
            filter.insert(&node);
        }

        // All inserted items should be found
        for i in 0..100 {
            let node = make_node_addr(i);
            assert!(filter.contains(&node), "Node {} not found", i);
        }

        // Fill ratio should be reasonable
        let fill = filter.fill_ratio();
        assert!(fill > 0.0 && fill < 0.5, "Unexpected fill ratio: {}", fill);
    }

    #[test]
    fn test_bloom_filter_merge() {
        let mut filter1 = BloomFilter::new();
        let mut filter2 = BloomFilter::new();

        let node1 = make_node_addr(1);
        let node2 = make_node_addr(2);

        filter1.insert(&node1);
        filter2.insert(&node2);

        filter1.merge(&filter2).unwrap();

        assert!(filter1.contains(&node1));
        assert!(filter1.contains(&node2));
    }

    #[test]
    fn test_bloom_filter_union() {
        let mut filter1 = BloomFilter::new();
        let mut filter2 = BloomFilter::new();

        let node1 = make_node_addr(1);
        let node2 = make_node_addr(2);

        filter1.insert(&node1);
        filter2.insert(&node2);

        let union = filter1.union(&filter2).unwrap();

        assert!(union.contains(&node1));
        assert!(union.contains(&node2));
        // Original filters unchanged
        assert!(!filter1.contains(&node2));
        assert!(!filter2.contains(&node1));
    }

    #[test]
    fn test_bloom_filter_clear() {
        let mut filter = BloomFilter::new();
        let node = make_node_addr(1);

        filter.insert(&node);
        assert!(!filter.is_empty());

        filter.clear();
        assert!(filter.is_empty());
        assert_eq!(filter.count_ones(), 0);
        assert!(!filter.contains(&node));
    }

    #[test]
    fn test_bloom_filter_merge_size_mismatch() {
        let mut filter1 = BloomFilter::with_params(1024, 7).unwrap();
        let filter2 = BloomFilter::with_params(2048, 7).unwrap();

        let result = filter1.merge(&filter2);
        assert!(matches!(result, Err(BloomError::InvalidSize { .. })));
    }

    #[test]
    fn test_bloom_filter_custom_params() {
        let filter = BloomFilter::with_params(1024, 5).unwrap();
        assert_eq!(filter.num_bits(), 1024);
        assert_eq!(filter.num_bytes(), 128);
        assert_eq!(filter.hash_count(), 5);
    }

    #[test]
    fn test_bloom_filter_invalid_params() {
        // Not byte-aligned (1001 is not divisible by 8)
        assert!(matches!(
            BloomFilter::with_params(1001, 7),
            Err(BloomError::SizeNotByteAligned(1001))
        ));

        // Zero size
        assert!(matches!(
            BloomFilter::with_params(0, 7),
            Err(BloomError::SizeNotByteAligned(0))
        ));

        // Zero hash count
        assert!(matches!(
            BloomFilter::with_params(1024, 0),
            Err(BloomError::ZeroHashCount)
        ));
    }

    #[test]
    fn test_bloom_filter_from_bytes() {
        let original = BloomFilter::new();
        let bytes = original.as_bytes().to_vec();

        let restored =
            BloomFilter::from_bytes(bytes, original.hash_count()).unwrap();

        assert_eq!(original, restored);
    }

    #[test]
    fn test_bloom_filter_estimated_count() {
        let mut filter = BloomFilter::new();

        // Empty filter
        assert_eq!(filter.estimated_count(), 0.0);

        // Insert some items
        for i in 0..50 {
            filter.insert(&make_node_addr(i));
        }

        // Estimate should be reasonably close to 50
        let estimate = filter.estimated_count();
        assert!(
            estimate > 30.0 && estimate < 100.0,
            "Unexpected estimate: {}",
            estimate
        );
    }

    #[test]
    fn test_bloom_filter_equality() {
        let mut filter1 = BloomFilter::new();
        let mut filter2 = BloomFilter::new();

        assert_eq!(filter1, filter2);

        filter1.insert(&make_node_addr(1));
        assert_ne!(filter1, filter2);

        filter2.insert(&make_node_addr(1));
        assert_eq!(filter1, filter2);
    }

    // ===== BloomState Tests =====

    #[test]
    fn test_bloom_state_new() {
        let node = make_node_addr(0);
        let state = BloomState::new(node);

        assert_eq!(state.own_node_addr(), &node);
        assert!(!state.is_leaf_only());
        assert_eq!(state.sequence(), 0);
        assert_eq!(state.leaf_dependent_count(), 0);
    }

    #[test]
    fn test_bloom_state_leaf_only() {
        let node = make_node_addr(0);
        let state = BloomState::leaf_only(node);

        assert!(state.is_leaf_only());
    }

    #[test]
    fn test_bloom_state_leaf_dependents() {
        let node = make_node_addr(0);
        let mut state = BloomState::new(node);

        let leaf1 = make_node_addr(1);
        let leaf2 = make_node_addr(2);

        state.add_leaf_dependent(leaf1);
        state.add_leaf_dependent(leaf2);
        assert_eq!(state.leaf_dependent_count(), 2);

        assert!(state.remove_leaf_dependent(&leaf1));
        assert_eq!(state.leaf_dependent_count(), 1);

        assert!(!state.remove_leaf_dependent(&leaf1)); // already removed
    }

    #[test]
    fn test_bloom_state_debounce() {
        let node = make_node_addr(0);
        let peer = make_node_addr(1);
        let mut state = BloomState::new(node);
        state.set_update_debounce_ms(500);

        state.mark_update_needed(peer);

        // Should send initially
        assert!(state.should_send_update(&peer, 1000));

        // Record send
        state.record_update_sent(peer, 1000);
        state.mark_update_needed(peer);

        // Should not send immediately (within debounce)
        assert!(!state.should_send_update(&peer, 1200));

        // Should send after debounce period
        assert!(state.should_send_update(&peer, 1600));
    }

    #[test]
    fn test_bloom_state_sequence() {
        let node = make_node_addr(0);
        let mut state = BloomState::new(node);

        assert_eq!(state.sequence(), 0);
        assert_eq!(state.next_sequence(), 1);
        assert_eq!(state.next_sequence(), 2);
        assert_eq!(state.sequence(), 2);
    }

    #[test]
    fn test_bloom_state_pending_updates() {
        let node = make_node_addr(0);
        let mut state = BloomState::new(node);

        let peer1 = make_node_addr(1);
        let peer2 = make_node_addr(2);

        assert!(!state.needs_update(&peer1));

        state.mark_update_needed(peer1);
        assert!(state.needs_update(&peer1));
        assert!(!state.needs_update(&peer2));

        state.mark_all_updates_needed(vec![peer1, peer2]);
        assert!(state.needs_update(&peer1));
        assert!(state.needs_update(&peer2));

        state.clear_pending_updates();
        assert!(!state.needs_update(&peer1));
        assert!(!state.needs_update(&peer2));
    }

    #[test]
    fn test_bloom_state_base_filter() {
        let node = make_node_addr(0);
        let mut state = BloomState::new(node);

        let leaf = make_node_addr(1);
        state.add_leaf_dependent(leaf);

        let filter = state.base_filter();

        assert!(filter.contains(&node));
        assert!(filter.contains(&leaf));
        assert!(!filter.contains(&make_node_addr(99)));
    }

    #[test]
    fn test_bloom_state_compute_outgoing_filter() {
        let my_node = make_node_addr(0);
        let mut state = BloomState::new(my_node);

        let leaf = make_node_addr(1);
        state.add_leaf_dependent(leaf);

        let peer1 = make_node_addr(10);
        let peer2 = make_node_addr(20);

        // Create peer filters
        let mut filter1 = BloomFilter::new();
        filter1.insert(&make_node_addr(100));
        filter1.insert(&make_node_addr(101));

        let mut filter2 = BloomFilter::new();
        filter2.insert(&make_node_addr(200));

        let mut peer_filters = HashMap::new();
        peer_filters.insert(peer1, filter1);
        peer_filters.insert(peer2, filter2);

        // Filter for peer1 should exclude peer1's contributions
        let outgoing1 = state.compute_outgoing_filter(&peer1, &peer_filters);
        assert!(outgoing1.contains(&my_node)); // self
        assert!(outgoing1.contains(&leaf)); // leaf dependent
        assert!(outgoing1.contains(&make_node_addr(200))); // from peer2
        // peer1's nodes may or may not be present (depends on split brain)

        // Filter for peer2 should exclude peer2's contributions
        let outgoing2 = state.compute_outgoing_filter(&peer2, &peer_filters);
        assert!(outgoing2.contains(&my_node));
        assert!(outgoing2.contains(&leaf));
        assert!(outgoing2.contains(&make_node_addr(100))); // from peer1
        assert!(outgoing2.contains(&make_node_addr(101))); // from peer1
    }

}
