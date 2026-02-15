//! FIPS-specific Bloom filter announcement state management.

use std::collections::{HashMap, HashSet};

use super::BloomFilter;
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
