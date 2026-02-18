//! MMP report dispatch, periodic report generation, and operator logging.
//!
//! Handles incoming SenderReport / ReceiverReport messages, drives
//! periodic report generation on the tick timer, and emits periodic
//! and teardown metric logs.

use crate::mmp::MmpMode;
use crate::mmp::report::{ReceiverReport, SenderReport};
use crate::node::Node;
use crate::NodeAddr;
use std::time::Instant;
use tracing::{debug, info, warn};

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
                debug!(from = %from, error = %e, "Malformed SenderReport");
                return;
            }
        };

        let peer = match self.peers.get_mut(from) {
            Some(p) => p,
            None => {
                debug!(from = %from, "SenderReport from unknown peer");
                return;
            }
        };

        if peer.mmp().is_none() {
            return;
        }

        debug!(
            from = %from,
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
    pub(in crate::node) fn handle_receiver_report(&mut self, from: &NodeAddr, payload: &[u8]) {
        let rr = match ReceiverReport::decode(payload) {
            Ok(rr) => rr,
            Err(e) => {
                debug!(from = %from, error = %e, "Malformed ReceiverReport");
                return;
            }
        };

        let peer = match self.peers.get_mut(from) {
            Some(p) => p,
            None => {
                debug!(from = %from, "ReceiverReport from unknown peer");
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
        mmp.metrics.process_receiver_report(&rr, our_timestamp_ms, now);

        // Feed SRTT back to sender/receiver report interval tuning
        if let Some(srtt_ms) = mmp.metrics.srtt_ms() {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_from_srtt(srtt_us);
            mmp.receiver.update_report_interval_from_srtt(srtt_us);
        }

        // Update reverse delivery ratio from our own receiver state
        // (what fraction of peer's frames we received).
        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        if peer_highest > 0 {
            let reverse_ratio = (our_recv_packets as f64) / (peer_highest as f64);
            mmp.metrics.set_delivery_ratio_reverse(reverse_ratio);
        }

        debug!(
            from = %from,
            rtt_ms = ?mmp.metrics.srtt_ms(),
            loss = format_args!("{:.1}%", mmp.metrics.loss_rate() * 100.0),
            etx = format_args!("{:.2}", mmp.metrics.etx),
            "Processed ReceiverReport"
        );
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
            let Some(mmp) = peer.mmp_mut() else {
                continue;
            };

            let mode = mmp.mode();

            // Sender reports: Full mode only
            if mode == MmpMode::Full && mmp.sender.should_send_report(now) {
                if let Some(sr) = mmp.sender.build_report(now) {
                    sender_reports.push((*node_addr, sr.encode()));
                }
            }

            // Receiver reports: Full and Lightweight modes
            if mode != MmpMode::Minimal && mmp.receiver.should_send_report(now) {
                if let Some(rr) = mmp.receiver.build_report(now) {
                    receiver_reports.push((*node_addr, rr.encode()));
                }
            }

            // Periodic operator logging
            if mmp.should_log(now) {
                Self::log_mmp_metrics(node_addr, mmp);
                mmp.mark_logged(now);
            }
        }

        // Send collected reports
        for (node_addr, encoded) in sender_reports {
            if let Err(e) = self.send_encrypted_link_message(&node_addr, &encoded).await {
                warn!(peer = %node_addr, error = %e, "Failed to send SenderReport");
            }
        }

        for (node_addr, encoded) in receiver_reports {
            if let Err(e) = self.send_encrypted_link_message(&node_addr, &encoded).await {
                warn!(peer = %node_addr, error = %e, "Failed to send ReceiverReport");
            }
        }
    }

    /// Emit periodic MMP metrics for a peer at info and debug levels.
    fn log_mmp_metrics(node_addr: &NodeAddr, mmp: &crate::mmp::MmpPeerState) {
        let m = &mmp.metrics;

        let rtt_str = match m.srtt_ms() {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };
        let loss_pct = m.loss_rate() * 100.0;
        let tx_pkts = mmp.sender.cumulative_packets_sent();
        let rx_pkts = mmp.receiver.cumulative_packets_recv();

        let goodput_bps = m.goodput_bps();
        let goodput_str = format_throughput(goodput_bps);

        // Info-level: concise summary
        info!(
            peer = %node_addr,
            rtt = %rtt_str,
            loss = format_args!("{:.1}%", loss_pct),
            goodput = %goodput_str,
            tx_pkts = tx_pkts,
            rx_pkts = rx_pkts,
            "MMP link metrics"
        );

        // Debug-level: extended details
        debug!(
            peer = %node_addr,
            jitter_us = mmp.receiver.jitter_us(),
            reorder = mmp.receiver.cumulative_packets_recv(),
            rtt_trend = format_args!("{}", if m.rtt_trend.initialized() {
                format!("short={:.1} long={:.1}", m.rtt_trend.short(), m.rtt_trend.long())
            } else {
                "n/a".to_string()
            }),
            loss_trend = format_args!("{}", if m.loss_trend.initialized() {
                format!("short={:.4} long={:.4}", m.loss_trend.short(), m.loss_trend.long())
            } else {
                "n/a".to_string()
            }),
            delivery_fwd = format_args!("{:.3}", m.delivery_ratio_forward),
            delivery_rev = format_args!("{:.3}", m.delivery_ratio_reverse),
            mode = %mmp.mode(),
            "MMP link metrics (detail)"
        );
    }

    /// Emit a teardown log summarizing lifetime MMP metrics for a removed peer.
    pub(in crate::node) fn log_mmp_teardown(node_addr: &NodeAddr, mmp: &crate::mmp::MmpPeerState) {
        let m = &mmp.metrics;

        let rtt_str = match m.srtt_ms() {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };

        info!(
            peer = %node_addr,
            rtt = %rtt_str,
            loss = format_args!("{:.1}%", m.loss_rate() * 100.0),
            etx = format_args!("{:.2}", m.etx),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            tx_bytes = mmp.sender.cumulative_bytes_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            rx_bytes = mmp.receiver.cumulative_bytes_recv(),
            jitter_us = mmp.receiver.jitter_us(),
            "MMP link teardown"
        );
    }
}
