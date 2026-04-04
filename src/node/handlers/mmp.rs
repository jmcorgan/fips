//! MMP report dispatch, periodic report generation, and operator logging.
//!
//! Handles incoming SenderReport / ReceiverReport messages, drives
//! periodic report generation on the tick timer, and emits periodic
//! and teardown metric logs.

use crate::NodeAddr;
use crate::mmp::MmpMode;
use crate::mmp::MmpSessionState;
use crate::mmp::report::{ReceiverReport, SenderReport};
use crate::node::Node;
use crate::protocol::{
    LinkMessageType, PathMtuNotification, SessionMessageType, SessionReceiverReport,
    SessionSenderReport,
};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Format bytes/sec as human-readable throughput.
fn format_throughput(bps: f64) -> String {
    if bps == 0.0 {
        "n/a".to_string()
    } else if bps >= 1_000_000.0 {
        format!("{:.1}MB/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1}KB/s", bps / 1_000.0)
    } else {
        format!("{:.0}B/s", bps)
    }
}

impl Node {
    /// Handle an incoming SenderReport from a peer.
    ///
    /// The peer is telling us about what they sent. We feed this to our
    /// receiver state for cross-reference (not currently used for metrics,
    /// but stored for future use).
    pub(in crate::node) fn handle_sender_report(&mut self, from: &NodeAddr, payload: &[u8]) {
        let sr = match SenderReport::decode(payload) {
            Ok(sr) => sr,
            Err(e) => {
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed SenderReport");
                return;
            }
        };

        let peer = match self.peers.get_mut(from) {
            Some(p) => p,
            None => {
                debug!(from = %self.peer_display_name(from), "SenderReport from unknown peer");
                return;
            }
        };

        if peer.mmp().is_none() {
            return;
        }

        trace!(
            from = %self.peer_display_name(from),
            cum_pkts = sr.cumulative_packets_sent,
            interval_bytes = sr.interval_bytes_sent,
            "Received SenderReport"
        );

        // Store sender's report in receiver state for cross-reference.
        // Currently informational; the receiver already tracks its own
        // counters and echoes timestamps from data frames.
    }

    /// Handle an incoming ReceiverReport from a peer.
    ///
    /// The peer is telling us about what they received from us. We feed
    /// this to our metrics to compute RTT, loss rate, and trend indicators.
    pub(in crate::node) async fn handle_receiver_report(
        &mut self,
        from: &NodeAddr,
        payload: &[u8],
    ) {
        let rr = match ReceiverReport::decode(payload) {
            Ok(rr) => rr,
            Err(e) => {
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed ReceiverReport");
                return;
            }
        };

        let peer_name = self.peer_display_name(from);

        let peer = match self.peers.get_mut(from) {
            Some(p) => p,
            None => {
                debug!(from = %peer_name, "ReceiverReport from unknown peer");
                return;
            }
        };

        // Get session timestamp before taking mutable borrow on MMP
        let our_timestamp_ms = peer.session_elapsed_ms();

        let Some(mmp) = peer.mmp_mut() else {
            return;
        };

        // Process the report: computes RTT from timestamp echo, updates
        // loss rate, goodput rate, jitter trend, and ETX.
        let now = Instant::now();
        let first_rtt = mmp
            .metrics
            .process_receiver_report(&rr, our_timestamp_ms, now);

        // Feed SRTT back to sender/receiver report interval tuning
        if let Some(srtt_ms) = mmp.metrics.srtt_ms() {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_from_srtt(srtt_us);
            mmp.receiver.update_report_interval_from_srtt(srtt_us);
        }

        // Update reverse delivery ratio from our own receiver state
        // (what fraction of peer's frames we received), using per-interval deltas.
        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);

        trace!(
            from = %peer_name,
            rtt_ms = ?mmp.metrics.srtt_ms(),
            loss = format_args!("{:.1}%", mmp.metrics.loss_rate() * 100.0),
            etx = format_args!("{:.2}", mmp.metrics.etx),
            "Processed ReceiverReport"
        );

        // First RTT sample — peer is now eligible for parent selection.
        // Trigger re-evaluation so the node doesn't wait for the next
        // periodic tick or TreeAnnounce.
        if first_rtt {
            let peer_costs: std::collections::HashMap<crate::NodeAddr, f64> = self
                .peers
                .iter()
                .filter(|(_, p)| p.has_srtt())
                .map(|(a, p)| (*a, p.link_cost()))
                .collect();
            let skip = self.non_full_peers();
            if let Some(new_parent) = self.tree_state.evaluate_parent(&peer_costs, &skip) {
                let new_seq = self.tree_state.my_declaration().sequence() + 1;
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let flap_dampened = self.tree_state.set_parent(new_parent, new_seq, timestamp);
                if let Err(e) = self.tree_state.sign_declaration(&self.identity) {
                    warn!(error = %e, "Failed to sign declaration after first-RTT parent eval");
                    return;
                }
                self.tree_state.recompute_coords();
                self.coord_cache.clear();
                self.reset_discovery_backoff();
                self.stats_mut().tree.parent_switched += 1;
                self.stats_mut().tree.parent_switches += 1;
                info!(
                    new_parent = %self.peer_display_name(&new_parent),
                    new_seq = new_seq,
                    new_root = %self.tree_state.root(),
                    depth = self.tree_state.my_coords().depth(),
                    trigger = "first-rtt",
                    "Parent switched after first RTT measurement"
                );
                if flap_dampened {
                    self.stats_mut().tree.flap_dampened += 1;
                    warn!("Flap dampening engaged: excessive parent switches detected");
                }
                self.send_tree_announce_to_all().await;
                let all_peers: Vec<crate::NodeAddr> = self.peers.keys().copied().collect();
                self.bloom_state.mark_all_updates_needed(all_peers);
            }
        }
    }

    /// Check all peers for pending MMP reports and send them.
    ///
    /// Called from the tick handler. Also emits periodic operator logs.
    pub(in crate::node) async fn check_mmp_reports(&mut self) {
        let now = Instant::now();

        // Collect peers that need reports (can't borrow self mutably while iterating)
        let mut sender_reports: Vec<(NodeAddr, Vec<u8>)> = Vec::new();
        let mut receiver_reports: Vec<(NodeAddr, Vec<u8>)> = Vec::new();

        for (node_addr, peer) in self.peers.iter_mut() {
            // Compute display name before taking mutable MMP borrow
            let peer_name = self
                .peer_aliases
                .get(node_addr)
                .cloned()
                .unwrap_or_else(|| peer.identity().short_npub());

            let send_sr = peer.send_sr();
            let send_rr = peer.send_rr();

            let Some(mmp) = peer.mmp_mut() else {
                continue;
            };

            let mode = mmp.mode();

            // Sender reports: gated by mode, profile wants/provides, and timing
            if mode == MmpMode::Full
                && send_sr
                && mmp.sender.should_send_report(now)
                && let Some(sr) = mmp.sender.build_report(now)
            {
                sender_reports.push((*node_addr, sr.encode()));
            }

            // Receiver reports: gated by mode, profile wants/provides, and timing
            if mode != MmpMode::Minimal
                && send_rr
                && mmp.receiver.should_send_report(now)
                && let Some(rr) = mmp.receiver.build_report(now)
            {
                receiver_reports.push((*node_addr, rr.encode()));
            }

            // Periodic operator logging
            if mmp.should_log(now) {
                Self::log_mmp_metrics(&peer_name, mmp);
                mmp.mark_logged(now);
            }
        }

        // Send collected reports
        for (node_addr, encoded) in sender_reports {
            if let Err(e) = self.send_encrypted_link_message(&node_addr, &encoded).await {
                debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send SenderReport");
            }
        }

        for (node_addr, encoded) in receiver_reports {
            if let Err(e) = self.send_encrypted_link_message(&node_addr, &encoded).await {
                debug!(peer = %self.peer_display_name(&node_addr), error = %e, "Failed to send ReceiverReport");
            }
        }
    }

    /// Emit periodic MMP metrics for a peer.
    fn log_mmp_metrics(peer_name: &str, mmp: &crate::mmp::MmpPeerState) {
        let m = &mmp.metrics;

        let rtt_str = if m.rtt_trend.initialized() {
            format!("{:.1}ms", m.rtt_trend.long() / 1000.0)
        } else {
            "n/a".to_string()
        };
        let loss_str = if m.loss_trend.initialized() {
            format!("{:.1}%", m.loss_trend.long() * 100.0)
        } else {
            "n/a".to_string()
        };
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        debug!(
            peer = %peer_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            goodput = %format_throughput(m.goodput_bps()),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            "MMP link metrics"
        );
    }

    /// Emit a teardown log summarizing lifetime MMP metrics for a removed peer.
    pub(in crate::node) fn log_mmp_teardown(peer_name: &str, mmp: &crate::mmp::MmpPeerState) {
        let m = &mmp.metrics;
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        let rtt_str = match m.srtt_ms() {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };
        let loss_str = format!("{:.1}%", m.loss_rate() * 100.0);

        debug!(
            peer = %peer_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            etx = format_args!("{:.2}", m.etx),
            goodput = %format_throughput(m.goodput_bps()),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            tx_bytes = mmp.sender.cumulative_bytes_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            rx_bytes = mmp.receiver.cumulative_bytes_recv(),
            "MMP link teardown"
        );
    }

    // === Session-layer MMP ===

    /// Check all sessions for pending MMP reports and send them.
    ///
    /// Called from the tick handler. Also emits periodic session MMP logs.
    /// Uses the collect-then-send pattern to avoid borrowing conflicts.
    pub(in crate::node) async fn check_session_mmp_reports(&mut self) {
        let now = Instant::now();

        // Collect reports to send: (dest_addr, msg_type, encoded_body)
        let mut reports: Vec<(NodeAddr, u8, Vec<u8>)> = Vec::new();

        for (dest_addr, entry) in self.sessions.iter_mut() {
            // Compute display name before taking mutable MMP borrow
            let session_name = self
                .peer_aliases
                .get(dest_addr)
                .cloned()
                .unwrap_or_else(|| {
                    let (xonly, _) = entry.remote_pubkey().x_only_public_key();
                    crate::PeerIdentity::from_pubkey(xonly).short_npub()
                });

            let Some(mmp) = entry.mmp_mut() else {
                continue;
            };

            let mode = mmp.mode();

            // Sender reports: Full mode only
            if mode == MmpMode::Full
                && mmp.sender.should_send_report(now)
                && let Some(sr) = mmp.sender.build_report(now)
            {
                let session_sr: SessionSenderReport = SessionSenderReport::from(&sr);
                reports.push((
                    *dest_addr,
                    SessionMessageType::SenderReport.to_byte(),
                    session_sr.encode(),
                ));
            }

            // Receiver reports: Full and Lightweight modes
            if mode != MmpMode::Minimal
                && mmp.receiver.should_send_report(now)
                && let Some(rr) = mmp.receiver.build_report(now)
            {
                let session_rr: SessionReceiverReport = SessionReceiverReport::from(&rr);
                reports.push((
                    *dest_addr,
                    SessionMessageType::ReceiverReport.to_byte(),
                    session_rr.encode(),
                ));
            }

            // PathMtu notifications (all modes)
            if mmp.path_mtu.should_send_notification(now)
                && let Some(mtu_value) = mmp.path_mtu.build_notification(now)
            {
                let notif = PathMtuNotification::new(mtu_value);
                reports.push((
                    *dest_addr,
                    SessionMessageType::PathMtuNotification.to_byte(),
                    notif.encode(),
                ));
            }

            // Periodic operator logging
            if mmp.should_log(now) {
                Self::log_session_mmp_metrics(&session_name, mmp);
                mmp.mark_logged(now);
            }
        }

        // Send collected reports via session-layer encryption.
        // Track per-destination success/failure for backoff and log suppression.
        let mut send_results: Vec<(NodeAddr, bool)> = Vec::new();
        for (dest_addr, msg_type, body) in reports {
            match self.send_session_msg(&dest_addr, msg_type, &body).await {
                Ok(()) => {
                    send_results.push((dest_addr, true));
                }
                Err(e) => {
                    // Peek at current failure count for log suppression
                    let failures = self
                        .sessions
                        .get(&dest_addr)
                        .and_then(|entry| entry.mmp())
                        .map(|mmp| mmp.sender.consecutive_send_failures())
                        .unwrap_or(0);

                    if failures < 3 {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            msg_type,
                            error = %e,
                            "Failed to send session MMP report"
                        );
                    } else if failures == 3 {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            "Suppressing further session MMP send failure logs"
                        );
                    }
                    // failures > 3: silently suppressed

                    send_results.push((dest_addr, false));
                }
            }
        }

        // Update backoff state from send results.
        // Deduplicate: a destination counts as success if ANY report succeeded,
        // failure only if ALL reports for that destination failed.
        let mut dest_success: std::collections::HashMap<NodeAddr, bool> =
            std::collections::HashMap::new();
        for (dest, ok) in &send_results {
            let entry = dest_success.entry(*dest).or_insert(false);
            if *ok {
                *entry = true;
            }
        }
        for (dest_addr, success) in dest_success {
            if let Some(entry) = self.sessions.get_mut(&dest_addr)
                && let Some(mmp) = entry.mmp_mut()
            {
                if success {
                    let prev = mmp.sender.record_send_success();
                    if prev > 3 {
                        debug!(
                            dest = %self.peer_display_name(&dest_addr),
                            consecutive_failures = prev,
                            "Resumed session MMP reporting"
                        );
                    }
                } else {
                    mmp.sender.record_send_failure();
                }
            }
        }
    }

    /// Emit periodic session MMP metrics.
    fn log_session_mmp_metrics(session_name: &str, mmp: &MmpSessionState) {
        let m = &mmp.metrics;

        let rtt_str = if m.rtt_trend.initialized() {
            format!("{:.1}ms", m.rtt_trend.long() / 1000.0)
        } else {
            "n/a".to_string()
        };
        let loss_str = if m.loss_trend.initialized() {
            format!("{:.1}%", m.loss_trend.long() * 100.0)
        } else {
            "n/a".to_string()
        };
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        debug!(
            session = %session_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            goodput = %format_throughput(m.goodput_bps()),
            mtu = mmp.path_mtu.last_observed_mtu(),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            "MMP session metrics"
        );
    }

    /// Emit a teardown log summarizing lifetime session MMP metrics.
    pub(in crate::node) fn log_session_mmp_teardown(session_name: &str, mmp: &MmpSessionState) {
        let m = &mmp.metrics;
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        let rtt_str = match m.srtt_ms() {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };
        let loss_str = format!("{:.1}%", m.loss_rate() * 100.0);

        debug!(
            session = %session_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            etx = format_args!("{:.2}", m.etx),
            goodput = %format_throughput(m.goodput_bps()),
            send_mtu = mmp.path_mtu.current_mtu(),
            observed_mtu = mmp.path_mtu.last_observed_mtu(),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            tx_bytes = mmp.sender.cumulative_bytes_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            rx_bytes = mmp.receiver.cumulative_bytes_recv(),
            "MMP session teardown"
        );
    }

    /// Send heartbeats and remove dead peers.
    ///
    /// Called from the tick handler. Sends a 1-byte heartbeat to each peer
    /// whose heartbeat interval has elapsed, and removes any peer that
    /// hasn't sent us a frame within the link dead timeout.
    pub(in crate::node) async fn check_link_heartbeats(&mut self) {
        let now = Instant::now();
        let heartbeat_interval = Duration::from_secs(self.config.node.heartbeat_interval_secs);
        let dead_timeout = Duration::from_secs(self.config.node.link_dead_timeout_secs);
        let heartbeat_msg = [LinkMessageType::Heartbeat.to_byte()];

        // Collect heartbeats to send and dead peers to remove
        let mut heartbeats: Vec<NodeAddr> = Vec::new();
        let mut dead_peers: Vec<NodeAddr> = Vec::new();

        for (node_addr, peer) in self.peers.iter() {
            // Check liveness via MMP receiver last_recv_time.
            // Fall back to session_start for peers that never sent data.
            let is_dead = if let Some(mmp) = peer.mmp() {
                let reference_time = mmp
                    .receiver
                    .last_recv_time()
                    .unwrap_or(peer.session_start());
                now.duration_since(reference_time) >= dead_timeout
            } else {
                false
            };
            if is_dead {
                dead_peers.push(*node_addr);
                continue;
            }

            // Check if heartbeat is due
            let needs_heartbeat = match peer.last_heartbeat_sent() {
                None => true,
                Some(last) => now.duration_since(last) >= heartbeat_interval,
            };
            if needs_heartbeat {
                heartbeats.push(*node_addr);
            }
        }

        // Remove dead peers and schedule auto-reconnect
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        for addr in &dead_peers {
            warn!(
                peer = %self.peer_display_name(addr),
                timeout_secs = self.config.node.link_dead_timeout_secs,
                "Removing peer: link dead timeout"
            );
            self.remove_active_peer(addr);
            self.schedule_reconnect(*addr, now_ms);
        }

        // Send heartbeats (skip peers we just removed)
        for addr in heartbeats {
            if dead_peers.contains(&addr) {
                continue;
            }
            if let Some(peer) = self.peers.get_mut(&addr) {
                peer.mark_heartbeat_sent(now);
            }
            if let Err(e) = self
                .send_encrypted_link_message(&addr, &heartbeat_msg)
                .await
            {
                trace!(peer = %self.peer_display_name(&addr), error = %e, "Failed to send heartbeat");
            }
        }
    }
}
