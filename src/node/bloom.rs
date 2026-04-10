//! Bloom filter announce send/receive logic.
//!
//! Handles building, sending, and receiving FilterAnnounce messages,
//! including delta compression with NACK-based recovery and debounced
//! propagation to peers.

use crate::NodeAddr;
use crate::bloom::BloomFilter;
use crate::protocol::{FilterAnnounce, FilterNack};

use super::{Node, NodeError};
use std::collections::HashMap;
use tracing::{debug, trace, warn};

impl Node {
    /// Collect inbound filters from full tree peers for outgoing filter computation.
    ///
    /// Returns a map of (peer_node_addr -> filter) for peers that
    /// have sent us a FilterAnnounce. Non-routing and leaf peers are
    /// excluded (they don't send filters; their identity is covered
    /// via leaf_dependents).
    fn peer_inbound_filters(&self) -> HashMap<NodeAddr, BloomFilter> {
        let mut filters = HashMap::new();
        for (addr, peer) in &self.peers {
            if self.is_tree_peer(addr)
                && peer.peer_profile() == crate::protocol::NodeProfile::Full
                && let Some(filter) = peer.inbound_filter()
            {
                filters.insert(*addr, filter.clone());
            }
        }
        filters
    }

    /// Build a FilterAnnounce for a specific peer.
    ///
    /// Returns a delta (XOR diff) if we have a previous filter for this peer
    /// at the same size class. Otherwise returns a full send.
    fn build_filter_announce(&mut self, exclude_peer: &NodeAddr) -> FilterAnnounce {
        let peer_filters = self.peer_inbound_filters();
        let filter = self
            .bloom_state
            .compute_outgoing_filter(exclude_peer, &peer_filters);
        let sequence = self.bloom_state.next_sequence();
        let size_class = self.bloom_state.size_class();

        // Try delta if we have a previous filter for this peer at the same size
        if let Some(last_filter) = self.bloom_state.last_sent_filter(exclude_peer)
            && last_filter.num_bits() == filter.num_bits()
            && let (Some(base_seq), Ok(diff)) = (
                self.bloom_state.last_sent_seq(exclude_peer),
                last_filter.xor_diff(&filter),
            )
        {
            return FilterAnnounce::delta(diff, sequence, base_seq, size_class);
        }

        // Full send
        FilterAnnounce::full(filter, sequence, size_class)
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
        let is_delta = announce.is_delta;
        let sent_filter = if is_delta {
            // For deltas, reconstruct the actual filter for change detection:
            // apply the diff to the last-sent filter
            let mut reconstructed = self
                .bloom_state
                .last_sent_filter(peer_addr)
                .cloned()
                .unwrap_or_default();
            let _ = reconstructed.apply_diff(&announce.filter);
            reconstructed
        } else {
            announce.filter.clone()
        };

        let (encoded, stats) = announce.encode().map_err(|e| NodeError::SendFailed {
            node_addr: *peer_addr,
            reason: format!("FilterAnnounce encode failed: {}", e),
        })?;

        // Send
        if let Err(e) = self.send_encrypted_link_message(peer_addr, &encoded).await {
            self.stats_mut().bloom.send_failed += 1;
            return Err(e);
        }

        self.stats_mut().bloom.sent += 1;
        if is_delta {
            self.stats_mut().bloom.deltas_sent += 1;
        } else {
            self.stats_mut().bloom.full_sends += 1;
        }

        // Record send and store the filter for change detection
        debug!(
            peer = %self.peer_display_name(peer_addr),
            seq = announce.sequence,
            delta = is_delta,
            compressed = stats.compressed_bytes,
            runs = stats.run_count,
            est_entries = format_args!("{:.0}", sent_filter.estimated_count()),
            fill = format_args!("{:.1}%", sent_filter.fill_ratio() * 100.0),
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
    ///
    /// Non-routing nodes do not send filters (they receive only).
    pub(super) async fn send_pending_filter_announces(&mut self) {
        // Non-routing and leaf nodes don't send bloom filters
        if self.node_profile != crate::protocol::NodeProfile::Full {
            return;
        }

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
    /// Supports both full sends and delta (XOR diff) updates.
    /// On out-of-sequence delta, sends a NACK to request full retransmission.
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

        // Check peer exists
        let peer = match self.peers.get(from) {
            Some(p) => p,
            None => {
                self.stats_mut().bloom.unknown_peer += 1;
                debug!(from = %self.peer_display_name(from), "FilterAnnounce from unknown peer");
                return;
            }
        };
        let current_seq = peer.filter_sequence();

        // Reject stale/replay
        if announce.sequence <= current_seq {
            self.stats_mut().bloom.stale += 1;
            trace!(
                from = %self.peer_display_name(from),
                received_seq = announce.sequence,
                current_seq = current_seq,
                "Stale FilterAnnounce rejected"
            );
            return;
        }

        // Handle delta vs full
        let resolved_filter = if announce.is_delta {
            // Delta: apply XOR diff to stored inbound filter
            let expected_base = current_seq;
            if announce.base_seq != expected_base {
                // Out-of-sequence delta — send NACK
                debug!(
                    from = %self.peer_display_name(from),
                    expected_base = expected_base,
                    got_base = announce.base_seq,
                    "Out-of-sequence delta, sending NACK"
                );
                let nack = FilterNack {
                    expected_seq: expected_base,
                };
                let nack_encoded = nack.encode();
                let _ = self.send_encrypted_link_message(from, &nack_encoded).await;
                self.stats_mut().bloom.nacks_sent += 1;
                return;
            }

            // Apply diff to current inbound filter
            match self.peers.get(from).and_then(|p| p.inbound_filter()) {
                Some(current) => {
                    let mut result = current.clone();
                    if let Err(e) = result.apply_diff(&announce.filter) {
                        warn!(
                            from = %self.peer_display_name(from),
                            error = %e,
                            "Failed to apply filter delta"
                        );
                        // Send NACK to request full retransmit
                        let nack = FilterNack {
                            expected_seq: current_seq,
                        };
                        let _ = self.send_encrypted_link_message(from, &nack.encode()).await;
                        self.stats_mut().bloom.nacks_sent += 1;
                        return;
                    }
                    result
                }
                None => {
                    // No stored filter to apply delta to — NACK
                    debug!(
                        from = %self.peer_display_name(from),
                        "Delta received but no stored filter, sending NACK"
                    );
                    let nack = FilterNack { expected_seq: 0 };
                    let _ = self.send_encrypted_link_message(from, &nack.encode()).await;
                    self.stats_mut().bloom.nacks_sent += 1;
                    return;
                }
            }
        } else {
            // Full send: use directly
            announce.filter.clone()
        };

        self.stats_mut().bloom.accepted += 1;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        debug!(
            from = %self.peer_display_name(from),
            seq = announce.sequence,
            delta = announce.is_delta,
            est_entries = format_args!("{:.0}", resolved_filter.estimated_count()),
            fill = format_args!("{:.1}%", resolved_filter.fill_ratio() * 100.0),
            "Received FilterAnnounce"
        );

        // Store resolved filter on peer
        if let Some(peer) = self.peers.get_mut(from) {
            peer.update_filter(resolved_filter, announce.sequence, now_ms);
        }

        // Check which peers' outgoing filters actually changed
        let peer_addrs: Vec<NodeAddr> = self.peers.keys().copied().collect();
        let peer_filters = self.peer_inbound_filters();
        self.bloom_state
            .mark_changed_peers(from, &peer_addrs, &peer_filters);
    }

    /// Handle an inbound FilterNack from a peer.
    ///
    /// Clears the last-sent filter for that peer, forcing a full re-send
    /// on the next tick.
    pub(super) async fn handle_filter_nack(&mut self, from: &NodeAddr, payload: &[u8]) {
        let nack = match FilterNack::decode(payload) {
            Ok(n) => n,
            Err(e) => {
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed FilterNack");
                return;
            }
        };

        debug!(
            from = %self.peer_display_name(from),
            expected_seq = nack.expected_seq,
            "Received FilterNack, scheduling full re-send"
        );

        self.stats_mut().bloom.nacks_received += 1;
        // Clear sent state for this peer → next send will be full
        self.bloom_state.clear_sent_filter(from);
        self.bloom_state.mark_update_needed(*from);
    }

    /// Evaluate adaptive filter sizing and adjust if needed.
    ///
    /// Checks the outgoing fill ratio for a representative peer and
    /// steps up or down the size class if thresholds are crossed.
    /// On size change, clears all sent filters (forcing full re-sends)
    /// and marks all peers for update.
    fn check_adaptive_sizing(&mut self) {
        // Only Full nodes participate in filter sizing
        if self.node_profile != crate::protocol::NodeProfile::Full {
            return;
        }

        // Use an arbitrary peer to compute a representative outgoing filter
        let representative_peer = match self.peers.keys().next() {
            Some(addr) => *addr,
            None => return,
        };

        let peer_filters = self.peer_inbound_filters();
        let outgoing = self
            .bloom_state
            .compute_outgoing_filter(&representative_peer, &peer_filters);
        let fill = outgoing.fill_ratio();

        if let Some(new_class) = self.bloom_state.evaluate_size_change(fill) {
            let old_class = self.bloom_state.size_class();
            debug!(
                old_class = old_class,
                new_class = new_class,
                fill = format_args!("{:.1}%", fill * 100.0),
                "Adaptive bloom filter resize"
            );
            self.bloom_state.set_size_class(new_class);
            self.bloom_state.clear_all_sent_filters();
            self.stats_mut().bloom.size_changes += 1;
            let all_peers: Vec<NodeAddr> = self.peers.keys().copied().collect();
            self.bloom_state.mark_all_updates_needed(all_peers);
        }
    }

    /// Check bloom filter state on tick (called from event loop).
    ///
    /// Evaluates adaptive sizing, then sends any pending filter announces.
    pub(super) async fn check_bloom_state(&mut self) {
        self.check_adaptive_sizing();
        self.send_pending_filter_announces().await;
    }
}
