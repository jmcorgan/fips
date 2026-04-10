//! FIPS-specific Bloom filter announcement state management.

use std::collections::{HashMap, HashSet};

use super::{BloomFilter, MAX_SIZE_CLASS, MIN_SIZE_CLASS, V1_SIZE_CLASS, size_class_to_bits};
use crate::NodeAddr;

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
    /// This node's filter size class.
    size_class: u8,
    /// Rate limiting: minimum interval between outgoing updates (milliseconds).
    update_debounce_ms: u64,
    /// Timestamp of last update sent (per peer, in milliseconds).
    last_update_sent: HashMap<NodeAddr, u64>,
    /// Peers that need a filter update.
    pending_updates: HashSet<NodeAddr>,
    /// Current sequence number for outgoing filters.
    sequence: u64,
    /// Last outgoing filter sent to each peer (for change detection and delta computation).
    last_sent_filters: HashMap<NodeAddr, BloomFilter>,
    /// Sequence number of the last filter sent to each peer.
    last_sent_seq: HashMap<NodeAddr, u64>,
    /// Fill ratio threshold above which to step up to a larger size class.
    step_up_threshold: f64,
    /// Fill ratio threshold below which to step down to a smaller size class.
    step_down_threshold: f64,
}

impl BloomState {
    /// Create new Bloom state for a node.
    pub fn new(own_node_addr: NodeAddr) -> Self {
        Self {
            own_node_addr,
            leaf_dependents: HashSet::new(),
            is_leaf_only: false,
            size_class: V1_SIZE_CLASS,
            update_debounce_ms: 500,
            last_update_sent: HashMap::new(),
            pending_updates: HashSet::new(),
            sequence: 0,
            last_sent_filters: HashMap::new(),
            last_sent_seq: HashMap::new(),
            step_up_threshold: 0.20,
            step_down_threshold: 0.05,
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

    /// Get the current filter size class.
    pub fn size_class(&self) -> u8 {
        self.size_class
    }

    /// Set the filter size class.
    ///
    /// This does NOT trigger re-sends; the caller must clear sent filters
    /// and mark all peers for update.
    pub fn set_size_class(&mut self, size_class: u8) {
        self.size_class = size_class;
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

    /// Record the outgoing filter and sequence that was sent to a peer.
    pub fn record_sent_filter(&mut self, peer_id: NodeAddr, filter: BloomFilter) {
        let seq = self.sequence;
        self.last_sent_filters.insert(peer_id, filter);
        self.last_sent_seq.insert(peer_id, seq);
    }

    /// Get the last filter sent to a peer (for delta computation).
    pub fn last_sent_filter(&self, peer_id: &NodeAddr) -> Option<&BloomFilter> {
        self.last_sent_filters.get(peer_id)
    }

    /// Get the sequence number of the last filter sent to a peer.
    pub fn last_sent_seq(&self, peer_id: &NodeAddr) -> Option<u64> {
        self.last_sent_seq.get(peer_id).copied()
    }

    /// Clear the sent filter for a specific peer (e.g., on NACK).
    ///
    /// Forces the next send to be a full filter.
    pub fn clear_sent_filter(&mut self, peer_id: &NodeAddr) {
        self.last_sent_filters.remove(peer_id);
        self.last_sent_seq.remove(peer_id);
    }

    /// Clear all sent filters (e.g., on size class change).
    ///
    /// Forces full sends to all peers.
    pub fn clear_all_sent_filters(&mut self) {
        self.last_sent_filters.clear();
        self.last_sent_seq.clear();
    }

    /// Remove stored filter state for a peer that was removed.
    pub fn remove_peer_state(&mut self, peer_id: &NodeAddr) {
        self.last_sent_filters.remove(peer_id);
        self.last_sent_seq.remove(peer_id);
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
    /// The filter is created at this node's size class. Peer filters of
    /// different sizes are automatically converted (folded or duplicated)
    /// during the merge operation.
    ///
    /// The filter includes:
    /// - This node's own ID
    /// - All leaf dependents
    /// - Entries from other peers' inbound filters (excluding the destination peer)
    pub fn compute_outgoing_filter(
        &self,
        exclude_peer: &NodeAddr,
        peer_filters: &HashMap<NodeAddr, BloomFilter>,
    ) -> BloomFilter {
        let mut filter = self.base_filter();

        // Merge filters from other peers (auto-converting sizes)
        for (peer_id, peer_filter) in peer_filters {
            if peer_id != exclude_peer {
                let _ = filter.merge(peer_filter);
            }
        }

        filter
    }

    /// Evaluate whether the filter size class should change.
    ///
    /// Returns `Some(new_class)` if the outgoing fill ratio crosses a
    /// threshold, `None` if no change is needed.
    pub fn evaluate_size_change(&self, fill_ratio: f64) -> Option<u8> {
        if fill_ratio > self.step_up_threshold && self.size_class < MAX_SIZE_CLASS {
            Some(self.size_class + 1)
        } else if fill_ratio < self.step_down_threshold && self.size_class > MIN_SIZE_CLASS {
            Some(self.size_class - 1)
        } else {
            None
        }
    }

    /// Create a base filter containing just this node and its dependents.
    ///
    /// The filter is created at this node's size class.
    pub fn base_filter(&self) -> BloomFilter {
        let num_bits = size_class_to_bits(self.size_class);
        let mut filter = BloomFilter::with_params(num_bits, super::DEFAULT_HASH_COUNT)
            .expect("size_class produces valid params");
        filter.insert(&self.own_node_addr);
        for dep in &self.leaf_dependents {
            filter.insert(dep);
        }
        filter
    }
}
