//! FIPS-specific Bloom filter announcement state management.

use alloc::collections::{BTreeMap, BTreeSet};

use super::BloomFilter;
use crate::NodeAddr;
use crate::proto::mmp::delivery::{Acks, LinkEvidence, ResendReason};

/// State for managing Bloom filter announcements.
///
/// Tracks local filter state and what needs to be sent to peers.
#[derive(Clone, Debug)]
pub struct BloomState {
    /// This node's NodeAddr (always included in outgoing filters).
    own_node_addr: NodeAddr,
    /// Leaf-only nodes we speak for (included in our filter).
    leaf_dependents: BTreeSet<NodeAddr>,
    /// Whether this node operates in leaf-only mode.
    is_leaf_only: bool,
    /// Rate limiting: minimum interval between outgoing updates (milliseconds).
    update_debounce_ms: u64,
    /// Timestamp of last update sent (per peer, in milliseconds).
    last_update_sent: BTreeMap<NodeAddr, u64>,
    /// Peers that need a filter update.
    pending_updates: BTreeSet<NodeAddr>,
    /// Count of outgoing announces built since start. Local only: the value
    /// sent to a peer comes from `peer_sequences`.
    sequence: u64,
    /// Last FilterAnnounce sequence sent to each current peer. Dropped with
    /// the peer, so it holds one entry per peer rather than one per address
    /// ever seen; a returning peer is reseeded from a later floor.
    peer_sequences: BTreeMap<NodeAddr, u64>,
    /// Last outgoing filter sent to each peer (for change detection).
    last_sent_filters: BTreeMap<NodeAddr, BloomFilter>,
    /// Per-peer delivery tracking for sent announces.
    acks: Acks,
    /// Set when an accepted inbound filter may have changed outgoing
    /// filters; the recompute runs once on the next send pass.
    inbound_dirty: bool,
    /// Number of `mark_changed` passes run, each a full outgoing-filter
    /// recompute. Read by tests to check recompute pacing.
    inbound_recomputes: u64,
}

impl BloomState {
    /// Create new Bloom state for a node.
    pub fn new(own_node_addr: NodeAddr) -> Self {
        Self {
            own_node_addr,
            leaf_dependents: BTreeSet::new(),
            is_leaf_only: false,
            update_debounce_ms: 500,
            last_update_sent: BTreeMap::new(),
            pending_updates: BTreeSet::new(),
            sequence: 0,
            peer_sequences: BTreeMap::new(),
            last_sent_filters: BTreeMap::new(),
            acks: Acks::new(),
            inbound_dirty: false,
            inbound_recomputes: 0,
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

    /// Number of outgoing announces built since start, across all peers.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Take the sequence for the next FilterAnnounce to `peer`.
    ///
    /// A peer with no entry starts at `floor`; after that each value is one
    /// more than the last sent to that peer, so a peer sees no gap for
    /// announces built for other peers. The caller supplies a floor that
    /// grows with time faster than any one peer's sequence can, so a peer
    /// removed and re-established is reseeded above every value it was sent
    /// before.
    pub fn next_sequence(&mut self, peer: &NodeAddr, floor: u64) -> u64 {
        self.sequence += 1;
        let next = match self.peer_sequences.get(peer) {
            Some(&last) => last.saturating_add(1),
            None => floor,
        };
        self.peer_sequences.insert(*peer, next);
        next
    }

    /// Get the update debounce interval in milliseconds.
    pub fn update_debounce_ms(&self) -> u64 {
        self.update_debounce_ms
    }

    /// Set the update debounce interval.
    pub fn set_update_debounce_ms(&mut self, ms: u64) {
        self.update_debounce_ms = ms;
    }

    /// Set how long an announce the receiver reports cannot check waits
    /// before its fallback resend. Defaults to
    /// [`FALLBACK_MS`](crate::proto::mmp::delivery::FALLBACK_MS).
    pub fn set_fallback(&mut self, ms: u64) {
        self.acks.set_fallback(ms);
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
    pub fn leaf_dependents(&self) -> &BTreeSet<NodeAddr> {
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
    ///
    /// A time earlier than the last send permits the send rather than holding
    /// the update until the clock catches up; the send then restamps and the
    /// ordinary debounce resumes. The comparison takes a difference rather
    /// than adding the debounce, so a very large debounce cannot overflow.
    pub fn should_send_update(&self, peer_id: &NodeAddr, current_time_ms: u64) -> bool {
        if !self.pending_updates.contains(peer_id) {
            return false;
        }

        match self.last_update_sent.get(peer_id) {
            Some(&last_time) => current_time_ms
                .checked_sub(last_time)
                .is_none_or(|elapsed| elapsed >= self.update_debounce_ms),
            None => true,
        }
    }

    /// Record that we sent an update to a peer.
    pub fn record_update_sent(&mut self, peer_id: NodeAddr, current_time_ms: u64) {
        self.last_update_sent.insert(peer_id, current_time_ms);
        self.pending_updates.remove(&peer_id);
    }

    /// Read back the time of the last update sent to a peer, if any.
    #[cfg(test)]
    pub(crate) fn last_update_sent(&self, peer_id: &NodeAddr) -> Option<u64> {
        self.last_update_sent.get(peer_id).copied()
    }

    /// Note that an accepted inbound filter may have changed outgoing filters.
    ///
    /// The recompute is deferred to the next send pass, so a burst of
    /// announces costs one recompute instead of one each.
    pub fn note_inbound_change(&mut self) {
        self.inbound_dirty = true;
    }

    /// Whether an inbound change is waiting to be recomputed, clearing it.
    pub fn take_inbound_change(&mut self) -> bool {
        core::mem::take(&mut self.inbound_dirty)
    }

    /// Number of outgoing-filter recomputes `mark_changed` has run.
    #[cfg(test)]
    pub(crate) fn inbound_recomputes(&self) -> u64 {
        self.inbound_recomputes
    }

    /// Clear all pending updates.
    pub fn clear_pending_updates(&mut self) {
        self.pending_updates.clear();
    }

    /// Record the outgoing filter that was sent to a peer.
    pub fn record_sent_filter(&mut self, peer_id: NodeAddr, filter: BloomFilter) {
        self.last_sent_filters.insert(peer_id, filter);
    }

    /// Read back the last outgoing filter actually sent to a peer, if any.
    ///
    /// Returns the filter recorded by [`record_sent_filter`](Self::record_sent_filter),
    /// or `None` when no announce has been sent to that peer yet (or the node
    /// is root, with no parent to send to). A peer whose cap the filter
    /// exceeds discards it and keeps the one it accepted before, so this is
    /// not always what the peer holds.
    pub fn last_sent_filter(&self, peer_id: &NodeAddr) -> Option<&BloomFilter> {
        self.last_sent_filters.get(peer_id)
    }

    /// Remove stored filter state for a peer that was removed.
    pub fn remove_peer_state(&mut self, peer_id: &NodeAddr) {
        self.last_sent_filters.remove(peer_id);
        self.last_update_sent.remove(peer_id);
        self.pending_updates.remove(peer_id);
        self.peer_sequences.remove(peer_id);
        self.acks.remove(peer_id);
    }

    /// Record an announce the transport accepted for `peer`, sent with link
    /// counter `counter`, so it stays outstanding until the peer's receiver
    /// reports show it arrived.
    ///
    /// The transport accepting a frame is not delivery: a datagram can still
    /// be lost, and announces are sent only when a filter changes, so a lost
    /// one would otherwise leave the peer's filter stale indefinitely.
    ///
    /// Call this before [`record_sent_filter`](Self::record_sent_filter) for
    /// the same send: it compares `filter` with the last one sent, and new
    /// content starts a new lineage with fresh resend budgets. The budgets
    /// also refill when the session changes, and never otherwise, so a resend
    /// of the same content spends from its lineage's budget.
    pub fn record_announce(
        &mut self,
        peer: NodeAddr,
        filter: &BloomFilter,
        counter: u64,
        link: &LinkEvidence,
        now_ms: u64,
    ) {
        let fresh = self.last_sent_filters.get(&peer) != Some(filter);
        self.acks.record(peer, fresh, counter, link, now_ms);
    }

    /// Decide whether the outstanding announce to `peer` must be resent.
    ///
    /// Confirms the announce when a usable report covering its counter shows
    /// every counter since its base arrived. Resends on a covering report that
    /// shows a loss; once, as soon as a usable report arrives, for an announce
    /// the reports cannot check; and once after the fallback interval when no
    /// usable report checks it. A usable report that does not yet cover an
    /// announce sent in the current session becomes its base instead of
    /// triggering a resend. A report from another session, or a pair of
    /// reports that is inconsistent or cannot tell a late frame from before
    /// the base from one inside the window, is no evidence. Each announce lineage
    /// gets [`UNVERIFIED_BUDGET`](crate::proto::mmp::delivery::UNVERIFIED_BUDGET)
    /// unchecked and [`LOSS_BUDGET`](crate::proto::mmp::delivery::LOSS_BUDGET)
    /// loss resends per session, and a per-peer backoff spaces all resends by
    /// 1, 2, 4 ... up to 60 s until
    /// [`QUIET_MS`](crate::proto::mmp::delivery::QUIET_MS) passes with none.
    ///
    /// On `Some`, the peer has been marked for an update; the ordinary send
    /// path delivers the resend.
    pub fn check_announce(
        &mut self,
        peer: &NodeAddr,
        link: &LinkEvidence,
        now_ms: u64,
    ) -> Option<ResendReason> {
        let reason = self.acks.check(peer, link, now_ms)?;
        self.mark_update_needed(*peer);
        Some(reason)
    }

    /// Whether an announce to `peer` is still awaiting confirmation.
    pub fn announce_outstanding(&self, peer: &NodeAddr) -> bool {
        self.outstanding_counter(peer).is_some()
    }

    /// The link counter of the announce to `peer` awaiting confirmation.
    pub fn outstanding_counter(&self, peer: &NodeAddr) -> Option<u64> {
        self.acks.outstanding(peer)
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
        peer_filters: &BTreeMap<NodeAddr, BloomFilter>,
    ) {
        let targets: Vec<NodeAddr> = peer_addrs
            .iter()
            .filter(|addr| *addr != exclude_from)
            .copied()
            .collect();
        self.mark_changed(&targets, peer_filters);
    }

    /// Mark every target whose outgoing filter differs from what was last sent.
    ///
    /// A target never sent to counts as changed. Unlike
    /// [`mark_changed_peers`](Self::mark_changed_peers), no peer is excluded.
    pub fn mark_changed(
        &mut self,
        targets: &[NodeAddr],
        peer_filters: &BTreeMap<NodeAddr, BloomFilter>,
    ) {
        self.inbound_recomputes += 1;
        for (peer_addr, new_filter) in self.compute_outgoing_filters(targets, peer_filters) {
            let changed = match self.last_sent_filters.get(&peer_addr) {
                Some(last) => *last != new_filter,
                None => true, // never sent → must send
            };
            if changed {
                self.pending_updates.insert(peer_addr);
            }
        }
    }

    /// Compute the outgoing filter for many peers in one pass.
    ///
    /// Equivalent to calling [`compute_outgoing_filter`](Self::compute_outgoing_filter)
    /// once per target, but linear in the number of contributing peer
    /// filters instead of quadratic. The per-peer call rebuilds the whole
    /// union from scratch, so computing it for every peer costs
    /// O(targets × filters) 1 KB merges; announce fan-out on a
    /// large node does exactly that, once per tick and again on every
    /// inbound announce.
    ///
    /// The split-horizon exclusion is the only thing that differs between
    /// targets, so the union of "everything except peer i" is assembled
    /// from a running prefix union and a precomputed suffix union. Merging
    /// is a bytewise OR, which is commutative and associative, so the
    /// result is bit-identical to the per-peer computation.
    pub fn compute_outgoing_filters(
        &self,
        targets: &[NodeAddr],
        peer_filters: &BTreeMap<NodeAddr, BloomFilter>,
    ) -> BTreeMap<NodeAddr, BloomFilter> {
        let base = self.base_filter();
        let keys: Vec<NodeAddr> = peer_filters.keys().copied().collect();
        let n = keys.len();

        // suffix[i] = union of peer_filters[keys[i..]]; suffix[n] is empty.
        let mut suffix = vec![BloomFilter::new(); n + 1];
        for i in (0..n).rev() {
            let mut acc = suffix[i + 1].clone();
            // Size mismatches are skipped, exactly as in the per-peer path.
            let _ = acc.merge(&peer_filters[&keys[i]]);
            suffix[i] = acc;
        }

        // Filter for a target that contributes nothing: everything merged.
        let mut all = base.clone();
        let _ = all.merge(&suffix[0]);

        let mut per_key: BTreeMap<NodeAddr, BloomFilter> = BTreeMap::new();
        let mut prefix = BloomFilter::new();
        for i in 0..n {
            let mut outgoing = base.clone();
            let _ = outgoing.merge(&prefix);
            let _ = outgoing.merge(&suffix[i + 1]);
            per_key.insert(keys[i], outgoing);
            let _ = prefix.merge(&peer_filters[&keys[i]]);
        }

        targets
            .iter()
            .map(|target| {
                let filter = per_key.get(target).cloned().unwrap_or_else(|| all.clone());
                (*target, filter)
            })
            .collect()
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
        peer_filters: &BTreeMap<NodeAddr, BloomFilter>,
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
