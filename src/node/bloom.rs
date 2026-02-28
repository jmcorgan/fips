//! Bloom filter announce send/receive logic.
//!
//! Handles building, sending, and receiving FilterAnnounce messages,
//! including debounced propagation to peers.

use crate::bloom::BloomFilter;
use crate::protocol::FilterAnnounce;
use crate::NodeAddr;

use super::{Node, NodeError};
use std::collections::HashMap;
use tracing::debug;

impl Node {
    /// Collect inbound filters from all peers for outgoing filter computation.
    ///
    /// Returns a map of (peer_node_addr -> filter) for peers that
    /// have sent us a FilterAnnounce.
    fn peer_inbound_filters(&self) -> HashMap<NodeAddr, BloomFilter> {
        let mut filters = HashMap::new();
        for (addr, peer) in &self.peers {
            if self.is_tree_peer(addr)
                && let Some(filter) = peer.inbound_filter()
            {
                filters.insert(*addr, filter.clone());
            }
        }
        filters
    }

    /// Build a FilterAnnounce for a specific peer.
    ///
    /// The outgoing filter excludes the destination peer's own filter
    /// to prevent routing loops (don't tell a peer about destinations
    /// reachable only through them).
    fn build_filter_announce(&mut self, exclude_peer: &NodeAddr) -> FilterAnnounce {
        let peer_filters = self.peer_inbound_filters();
        let filter = self
            .bloom_state
            .compute_outgoing_filter(exclude_peer, &peer_filters);
        let sequence = self.bloom_state.next_sequence();
        FilterAnnounce::new(filter, sequence)
    }

    /// Send a FilterAnnounce to a specific peer, respecting debounce.
    ///
    /// If the peer is rate-limited, the update stays pending for
    /// delivery on the next tick cycle.
    pub(super) async fn send_filter_announce_to_peer(
        &mut self,
        peer_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Check debounce
        if !self.bloom_state.should_send_update(peer_addr, now_ms) {
            self.stats_mut().bloom.debounce_suppressed += 1;
            // Either not pending or rate-limited; will retry on tick
            return Ok(());
        }

        // Build and encode
        let announce = self.build_filter_announce(peer_addr);
        let sent_filter = announce.filter.clone();
        let encoded = announce.encode().map_err(|e| NodeError::SendFailed {
            node_addr: *peer_addr,
            reason: format!("FilterAnnounce encode failed: {}", e),
        })?;

        // Send
        if let Err(e) = self.send_encrypted_link_message(peer_addr, &encoded).await {
            self.stats_mut().bloom.send_failed += 1;
            return Err(e);
        }

        self.stats_mut().bloom.sent += 1;

        // Record send and store the filter for change detection
        debug!(
            peer = %self.peer_display_name(peer_addr),
            seq = announce.sequence,
            est_entries = format_args!("{:.0}", sent_filter.estimated_count()),
            set_bits = sent_filter.count_ones(),
            fill = format_args!("{:.1}%", sent_filter.fill_ratio() * 100.0),
            tree_peer = self.is_tree_peer(peer_addr),
            "Sent FilterAnnounce"
        );
        self.bloom_state.record_update_sent(*peer_addr, now_ms);
        self.bloom_state.record_sent_filter(*peer_addr, sent_filter);
        if let Some(peer) = self.peers.get_mut(peer_addr) {
            peer.clear_filter_update_needed();
        }

        Ok(())
    }

    /// Send pending rate-limited filter announces whose debounce has expired.
    pub(super) async fn send_pending_filter_announces(&mut self) {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let ready: Vec<NodeAddr> = self
            .peers
            .keys()
            .filter(|addr| self.bloom_state.should_send_update(addr, now_ms))
            .copied()
            .collect();

        for peer_addr in ready {
            if let Err(e) = self.send_filter_announce_to_peer(&peer_addr).await {
                debug!(
                    peer = %self.peer_display_name(&peer_addr),
                    error = %e,
                    "Failed to send pending FilterAnnounce"
                );
            }
        }
    }

    /// Handle an inbound FilterAnnounce from an authenticated peer.
    ///
    /// 1. Decode and validate the message
    /// 2. Check sequence freshness (reject stale/replay)
    /// 3. Store the filter on the peer
    /// 4. Mark other peers for outgoing filter update
    pub(super) async fn handle_filter_announce(&mut self, from: &NodeAddr, payload: &[u8]) {
        self.stats_mut().bloom.received += 1;

        let announce = match FilterAnnounce::decode(payload) {
            Ok(a) => a,
            Err(e) => {
                self.stats_mut().bloom.decode_error += 1;
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed FilterAnnounce");
                return;
            }
        };

        // Validate
        if !announce.is_valid() {
            self.stats_mut().bloom.invalid += 1;
            debug!(from = %self.peer_display_name(from), "FilterAnnounce filter/size_class mismatch");
            return;
        }
        if !announce.is_v1_compliant() {
            self.stats_mut().bloom.non_v1 += 1;
            debug!(from = %self.peer_display_name(from), size_class = announce.size_class, "Non-v1 FilterAnnounce rejected");
            return;
        }

        // Check peer exists
        let current_seq = match self.peers.get(from) {
            Some(peer) => peer.filter_sequence(),
            None => {
                self.stats_mut().bloom.unknown_peer += 1;
                debug!(from = %self.peer_display_name(from), "FilterAnnounce from unknown peer");
                return;
            }
        };

        // Reject stale/replay
        if announce.sequence <= current_seq {
            self.stats_mut().bloom.stale += 1;
            debug!(
                from = %self.peer_display_name(from),
                received_seq = announce.sequence,
                current_seq = current_seq,
                "Stale FilterAnnounce rejected"
            );
            return;
        }

        self.stats_mut().bloom.accepted += 1;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        debug!(
            from = %self.peer_display_name(from),
            seq = announce.sequence,
            est_entries = format_args!("{:.0}", announce.filter.estimated_count()),
            set_bits = announce.filter.count_ones(),
            fill = format_args!("{:.1}%", announce.filter.fill_ratio() * 100.0),
            tree_peer = self.is_tree_peer(from),
            "Received FilterAnnounce"
        );

        // Store on peer
        if let Some(peer) = self.peers.get_mut(from) {
            peer.update_filter(announce.filter, announce.sequence, now_ms);
        }

        // Check which peers' outgoing filters actually changed.
        // All peers receive filters, but only tree peers' inbound filters
        // are merged into outgoing computation (tree-only propagation).
        let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();
        let peer_filters = self.peer_inbound_filters();
        self.bloom_state
            .mark_changed_peers(from, &peer_addrs, &peer_filters);
    }

    /// Check bloom filter state on tick (called from event loop).
    ///
    /// Sends any pending debounced filter announces.
    pub(super) async fn check_bloom_state(&mut self) {
        self.send_pending_filter_announces().await;
    }
}
