//! MMP report dispatch, periodic report generation, and operator logging.
//!
//! Handles incoming SenderReport / ReceiverReport messages, drives
//! periodic report generation on the tick timer, and emits periodic
//! and teardown metric logs.

use crate::NodeAddr;
use crate::node::Node;
use crate::node::reject::{MmpReject, RejectReason, TreeReject};
use crate::node::tree::sign_declaration;
use crate::proto::mmp::{
    BackoffUpdate, LinkReportKind, LinkReportSnapshot, MmpAction, MmpSessionState,
    PathMtuNotification, PeerLivenessSnapshot, ReceiverReport, RrLog, SendResult, SenderReport,
    SessionReceiverReport, SessionReportKind, SessionReportSnapshot, SessionSenderReport,
};
use crate::protocol::{LinkMessageType, SessionMessageType};
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};

/// Emit the operator `trace!` point for a processed ReceiverReport outcome.
///
/// These log points used to live inside `MmpMetrics::process_receiver_report`;
/// the sans-IO migration returns the outcome as an [`RrLog`] and re-emits it
/// here, shell-side, preserving the original field set, content, and (relative
/// to the surrounding handler logs) ordering. The original traces carried no
/// peer identifier, so none is added here.
pub(super) fn log_rr_outcome(rr: &ReceiverReport, our_timestamp_ms: u32, log: RrLog) {
    match log {
        RrLog::Stale {
            prev_highest,
            prev_packets,
            prev_bytes,
        } => trace!(
            highest_counter = rr.highest_counter,
            prev_highest_counter = prev_highest,
            cumulative_packets_recv = rr.cumulative_packets_recv,
            prev_cumulative_packets_recv = prev_packets,
            cumulative_bytes_recv = rr.cumulative_bytes_recv,
            prev_cumulative_bytes_recv = prev_bytes,
            "Ignoring stale MMP ReceiverReport"
        ),
        RrLog::RttSample { rtt_ms, srtt_ms } => trace!(
            our_ts = our_timestamp_ms,
            echo = rr.timestamp_echo,
            dwell = u32::from(rr.dwell_time),
            rtt_ms = rtt_ms,
            srtt_ms = srtt_ms,
            "RTT sample from timestamp echo"
        ),
        RrLog::InvalidRtt => trace!(
            our_ts = our_timestamp_ms,
            echo = rr.timestamp_echo,
            dwell = u32::from(rr.dwell_time),
            "Ignoring invalid MMP RTT sample"
        ),
        RrLog::None => {}
    }
}

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
                self.stats_mut()
                    .record_reject(RejectReason::Mmp(MmpReject::DecodeError));
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed SenderReport");
                return;
            }
        };

        let peer = match self.peers.get_mut(from) {
            Some(p) => p,
            None => {
                self.stats_mut()
                    .record_reject(RejectReason::Mmp(MmpReject::UnknownPeer));
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
            interval_pkts = sr.interval_packets_sent,
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
                self.stats_mut()
                    .record_reject(RejectReason::Mmp(MmpReject::DecodeError));
                debug!(from = %self.peer_display_name(from), error = %e, "Malformed ReceiverReport");
                return;
            }
        };

        let peer_name = self.peer_display_name(from);

        let peer = match self.peers.get_mut(from) {
            Some(p) => p,
            None => {
                self.stats_mut()
                    .record_reject(RejectReason::Mmp(MmpReject::UnknownPeer));
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
        let now_ms = crate::mmp::mono_ms();
        let (first_rtt, rr_log) =
            mmp.metrics
                .process_receiver_report(&rr, our_timestamp_ms, now_ms);
        // Re-emit the operator trace the core used to log mid-decision.
        log_rr_outcome(&rr, our_timestamp_ms, rr_log);

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
            let peer_costs: std::collections::BTreeMap<crate::NodeAddr, f64> = self
                .peers
                .iter()
                .filter(|(_, p)| p.has_srtt())
                .map(|(a, p)| (*a, p.link_cost()))
                .collect();
            // Wall-clock seconds for the escaping declaration timestamp;
            // monotonic ms for the flap-dampening / hold-down timers.
            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let mono_now_ms = crate::mmp::mono_ms();
            let skip = self.non_full_peers();
            if let Some(new_parent) =
                self.tree_state
                    .evaluate_parent(&peer_costs, &skip, mono_now_ms)
            {
                let new_seq = self.tree_state.my_declaration().sequence() + 1;
                let flap_dampened =
                    self.tree_state
                        .set_parent(new_parent, new_seq, now_secs, mono_now_ms);
                self.tree_state.recompute_coords();
                // Clone identity once: sign_declaration borrows &mut tree_state while
                // the identity() accessor borrows all of &self, so an owned copy avoids
                // the split-borrow conflict on this infrequent parent-switch path.
                let our_identity = self.identity().clone();
                if let Err(e) =
                    sign_declaration(self.tree_state.my_declaration_mut(), &our_identity)
                {
                    warn!(error = %e, "Failed to sign declaration after first-RTT parent eval");
                    self.metrics()
                        .tree
                        .record_reject(TreeReject::OutboundSignFailed);
                    return;
                }
                // Surgical invalidation — see CoordCache::invalidate_via_node doc.
                self.coord_cache
                    .invalidate_via_node(our_identity.node_addr());
                self.reset_discovery_backoff();
                self.metrics().tree.parent_switched.inc();
                self.metrics().tree.parent_switches.inc();
                info!(
                    new_parent = %self.peer_display_name(&new_parent),
                    new_seq = new_seq,
                    new_root = %self.tree_state.root(),
                    depth = self.tree_state.my_coords().depth(),
                    trigger = "first-rtt",
                    "Parent switched after first RTT measurement"
                );
                if flap_dampened {
                    self.metrics().tree.flap_dampened.inc();
                    warn!("Flap dampening engaged: excessive parent switches detected");
                }
                self.send_tree_announce_to_all().await;
                let all_peers: Vec<crate::NodeAddr> = self.peers.keys().copied().collect();
                self.bloom_state.mark_all_updates_needed(all_peers);
            } else if !self.tree_state.is_root() && self.tree_state.should_be_root() {
                self.tree_state.become_root(now_secs);
                // Clone identity once (see the parent-switch branch above for why).
                let our_identity = self.identity().clone();
                if let Err(e) =
                    sign_declaration(self.tree_state.my_declaration_mut(), &our_identity)
                {
                    warn!(error = %e, "Failed to sign self-root declaration after first-RTT");
                    self.metrics()
                        .tree
                        .record_reject(TreeReject::OutboundSignFailed);
                    return;
                }
                // Surgical invalidation — see CoordCache::invalidate_other_roots doc.
                self.coord_cache
                    .invalidate_other_roots(our_identity.node_addr());
                self.reset_discovery_backoff();
                self.metrics().tree.parent_switched.inc();
                self.metrics().tree.parent_switches.inc();
                info!(
                    new_root = %self.tree_state.root(),
                    trigger = "first-rtt",
                    "Self-promoted to root after first RTT: smallest visible NodeAddr"
                );
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
        let now_ms = crate::mmp::mono_ms();

        // Build one report-gating snapshot per peer, resolving every timing read
        // shell-side into a `bool`. `send_sr`/`send_rr` come from the peer's
        // negotiated profile (whether it provides/wants each report); the core
        // ANDs them into the mode/timing gate. The snapshots own only
        // `NodeAddr`/`MmpMode`/`bool`, so the peer-iteration borrow is released
        // before the pure decision runs and the driving loop mutates the
        // reporting state.
        let snapshots: Vec<LinkReportSnapshot> = self
            .peers
            .iter()
            .filter_map(|(node_addr, peer)| {
                let mmp = peer.mmp()?;
                Some(LinkReportSnapshot {
                    peer: *node_addr,
                    mode: mmp.mode(),
                    send_sr: peer.send_sr(),
                    send_rr: peer.send_rr(),
                    sr_due: mmp.sender.should_send_report(now_ms),
                    rr_due: mmp.receiver.should_send_report(now_ms),
                    log_due: mmp.should_log(now_ms),
                })
            })
            .collect();

        let actions = self.mmp.plan_link_reports(&snapshots);

        // Drive the planned actions in their phase-grouped order (all logs, then
        // all SenderReports, then all ReceiverReports). Logs run first because the
        // operator log reads cumulative_packets_sent, which each report send
        // advances (send_encrypted_link_message -> sender.record_sent); the
        // pre-refactor handler logged during its collect pass, before any send.
        // `build_report` (which advances the interval state) is called only on a
        // SendLinkReport action, exactly as the pre-refactor gate did.
        for action in actions {
            match action {
                MmpAction::SendLinkReport { peer, kind } => {
                    let encoded = self
                        .peers
                        .get_mut(&peer)
                        .and_then(|p| p.mmp_mut())
                        .and_then(|mmp| match kind {
                            LinkReportKind::Sender => {
                                mmp.sender.build_report(now_ms).map(|sr| sr.encode())
                            }
                            LinkReportKind::Receiver => {
                                mmp.receiver.build_report(now_ms).map(|rr| rr.encode())
                            }
                        });
                    if let Some(encoded) = encoded
                        && let Err(e) = self.send_encrypted_link_message(&peer, &encoded).await
                    {
                        let label = match kind {
                            LinkReportKind::Sender => "Failed to send SenderReport",
                            LinkReportKind::Receiver => "Failed to send ReceiverReport",
                        };
                        debug!(peer = %self.peer_display_name(&peer), error = %e, "{}", label);
                    }
                }
                MmpAction::LogLink { peer } => {
                    // Resolve the display name exactly as the pre-refactor loop
                    // did (alias, else short_npub) — not `peer_display_name`,
                    // which also consults the host map.
                    let peer_name = self.peer_aliases.get(&peer).cloned().unwrap_or_else(|| {
                        self.peers
                            .get(&peer)
                            .map(|p| p.identity().short_npub())
                            .unwrap_or_default()
                    });
                    if let Some(mmp) = self.peers.get_mut(&peer).and_then(|p| p.mmp_mut()) {
                        Self::log_mmp_metrics(&peer_name, mmp);
                        mmp.mark_logged(now_ms);
                    }
                }
                MmpAction::ReapPeer { .. }
                | MmpAction::Heartbeat { .. }
                | MmpAction::SendSessionReport { .. }
                | MmpAction::LogSession { .. } => {}
            }
        }
    }

    /// Emit periodic MMP metrics for a peer.
    fn log_mmp_metrics(peer_name: &str, mmp: &crate::proto::mmp::MmpPeerState) {
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
    pub(in crate::node) fn log_mmp_teardown(
        peer_name: &str,
        mmp: &crate::proto::mmp::MmpPeerState,
    ) {
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
        let now_ms = crate::mmp::mono_ms();

        // Build one report-gating snapshot per session, resolving every timing
        // read shell-side into a `bool`. The snapshots own only
        // `NodeAddr`/`MmpMode`/`bool`, so the session-iteration borrow is released
        // before the pure decision runs and the driving loop mutates the
        // reporting state / performs the sends.
        let snapshots: Vec<SessionReportSnapshot> = self
            .sessions
            .iter()
            .filter_map(|(dest_addr, entry)| {
                let mmp = entry.mmp()?;
                Some(SessionReportSnapshot {
                    dest: *dest_addr,
                    mode: mmp.mode(),
                    sr_due: mmp.sender.should_send_report(now_ms),
                    rr_due: mmp.receiver.should_send_report(now_ms),
                    mtu_due: mmp.path_mtu.should_send_notification(now_ms),
                    log_due: mmp.should_log(now_ms),
                })
            })
            .collect();

        let actions = self.mmp.plan_session_reports(&snapshots);

        // Drive the planned actions in phase-grouped order (all logs, then the
        // sends in per-session SR/RR/MTU order). Logs run first because the
        // session operator log reads cumulative_packets_sent, which each send
        // advances (send_session_msg -> sender.record_sent); the pre-refactor
        // handler logged during its collect pass, before any send. Each build
        // (`build_report`/`build_notification`, which advance interval/
        // notification state) runs only on its SendSessionReport action, exactly
        // as the pre-refactor collect pass did. Per-destination success/failure
        // is collected for the backoff dedup + failure-log suppression.
        let mut send_results: Vec<SendResult> = Vec::new();
        for action in actions {
            match action {
                MmpAction::LogSession { dest } => {
                    // Resolve the display name exactly as the pre-refactor loop
                    // did (alias, else short_npub from the session's remote key).
                    let session_name = self.peer_aliases.get(&dest).cloned().unwrap_or_else(|| {
                        self.sessions
                            .get(&dest)
                            .map(|entry| {
                                let (xonly, _) = entry.remote_pubkey().x_only_public_key();
                                crate::PeerIdentity::from_pubkey(xonly).short_npub()
                            })
                            .unwrap_or_default()
                    });
                    if let Some(mmp) = self.sessions.get_mut(&dest).and_then(|e| e.mmp_mut()) {
                        Self::log_session_mmp_metrics(&session_name, mmp);
                        mmp.mark_logged(now_ms);
                    }
                }
                MmpAction::SendSessionReport { dest, kind } => {
                    let built = self
                        .sessions
                        .get_mut(&dest)
                        .and_then(|entry| entry.mmp_mut())
                        .and_then(|mmp| match kind {
                            SessionReportKind::Sender => {
                                mmp.sender.build_report(now_ms).map(|sr| {
                                    (
                                        SessionMessageType::SenderReport.to_byte(),
                                        SessionSenderReport::from(&sr).encode(),
                                    )
                                })
                            }
                            SessionReportKind::Receiver => {
                                mmp.receiver.build_report(now_ms).map(|rr| {
                                    (
                                        SessionMessageType::ReceiverReport.to_byte(),
                                        SessionReceiverReport::from(&rr).encode(),
                                    )
                                })
                            }
                            SessionReportKind::PathMtu => {
                                mmp.path_mtu.build_notification(now_ms).map(|mtu_value| {
                                    (
                                        SessionMessageType::PathMtuNotification.to_byte(),
                                        PathMtuNotification::new(mtu_value).encode(),
                                    )
                                })
                            }
                        });

                    let Some((msg_type, body)) = built else {
                        continue;
                    };

                    match self.send_session_msg(&dest, msg_type, &body).await {
                        Ok(()) => send_results.push(SendResult { dest, ok: true }),
                        Err(e) => {
                            // Peek at current failure count for log suppression
                            // (unchanged by the backoff apply, which runs later).
                            let failures = self
                                .sessions
                                .get(&dest)
                                .and_then(|entry| entry.mmp())
                                .map(|mmp| mmp.sender.consecutive_send_failures())
                                .unwrap_or(0);

                            if failures < 3 {
                                debug!(
                                    dest = %self.peer_display_name(&dest),
                                    msg_type,
                                    error = %e,
                                    "Failed to send session MMP report"
                                );
                            } else if failures == 3 {
                                debug!(
                                    dest = %self.peer_display_name(&dest),
                                    "Suppressing further session MMP send failure logs"
                                );
                            }
                            // failures > 3: silently suppressed

                            send_results.push(SendResult { dest, ok: false });
                        }
                    }
                }
                MmpAction::ReapPeer { .. }
                | MmpAction::Heartbeat { .. }
                | MmpAction::SendLinkReport { .. }
                | MmpAction::LogLink { .. } => {}
            }
        }

        // Deduplicate send results per destination (any-ok -> success, all-fail
        // -> failure) and apply the backoff state transition for each dest.
        for update in self.mmp.plan_backoff(&send_results) {
            match update {
                BackoffUpdate::Success { dest } => {
                    if let Some(mmp) = self.sessions.get_mut(&dest).and_then(|e| e.mmp_mut()) {
                        let prev = mmp.sender.record_send_success();
                        if prev > 3 {
                            debug!(
                                dest = %self.peer_display_name(&dest),
                                consecutive_failures = prev,
                                "Resumed session MMP reporting"
                            );
                        }
                    }
                }
                BackoffUpdate::Failure { dest } => {
                    if let Some(mmp) = self.sessions.get_mut(&dest).and_then(|e| e.mmp_mut()) {
                        mmp.sender.record_send_failure();
                    }
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
        // Monotonic ms for the MMP receiver's injected-`u64` liveness clock; the
        // Instant `now` is still used for the shell-owned heartbeat timing and
        // the session-start fallback (both `ActivePeer` Instants).
        let now_ms = crate::mmp::mono_ms();
        let heartbeat_interval = Duration::from_secs(self.config().node.heartbeat_interval_secs);
        let dead_timeout = Duration::from_secs(self.config().node.link_dead_timeout_secs);
        let dead_timeout_ms = dead_timeout.as_millis() as u64;
        let max_resends = self.config().node.rate_limit.handshake_max_resends;
        let heartbeat_msg = [LinkMessageType::Heartbeat.to_byte()];

        // Build one liveness snapshot per peer, resolving every clock read and
        // the rekey-suppression predicate shell-side. The snapshots own only
        // `NodeAddr`/`bool`, so the peer-iteration borrow is released before the
        // pure decision runs and the driving loop mutates the registry.
        let snapshots: Vec<PeerLivenessSnapshot> = self
            .peers
            .iter()
            .map(|(node_addr, peer)| {
                // Check liveness via the MMP receiver's last-received monotonic
                // ms. Fall back to session_start (an `ActivePeer` Instant) for
                // peers that never sent data, keeping that branch in Instant
                // space so no monotonic-ms epoch conversion is needed.
                let time_dead = if let Some(mmp) = peer.mmp() {
                    match mmp.receiver.last_recv_ms() {
                        Some(last_ms) => now_ms.saturating_sub(last_ms) >= dead_timeout_ms,
                        None => now.duration_since(peer.session_start()) >= dead_timeout,
                    }
                } else {
                    false
                };

                // Suppress teardown while an FMP rekey is genuinely in flight
                // with budget left: a rekey-handshake link is not silent —
                // whether mid-msg1 or mid-msg3 retransmit. The resend caps
                // guarantee this terminates (abandon on exhaustion or cutover on
                // completion clears the rekey state), so a truly dead link is
                // reaped on the next cycle.
                let rekey_active = (peer.rekey_in_progress()
                    && peer.rekey_msg1_resend_count() < max_resends
                    && peer.rekey_msg1().is_some())
                    || (peer.rekey_msg3_payload().is_some()
                        && peer.rekey_msg3_resend_count() < max_resends);

                // Check if heartbeat is due.
                let heartbeat_due = match peer.last_heartbeat_sent() {
                    None => true,
                    Some(last) => now.duration_since(last) >= heartbeat_interval,
                };

                PeerLivenessSnapshot {
                    peer: *node_addr,
                    time_dead,
                    rekey_active,
                    heartbeat_due,
                }
            })
            .collect();

        let actions = self.mmp.plan_heartbeats(&snapshots);

        // Wall-clock basis for reconnect scheduling, sourced once (as before).
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        // Drive the planned actions: all reaps first (each removed +
        // reconnect-scheduled), then all heartbeats (a just-reaped peer is never
        // heartbeated — the core never emits both for the same peer).
        for action in actions {
            match action {
                MmpAction::ReapPeer { peer } => {
                    debug!(
                        peer = %self.peer_display_name(&peer),
                        timeout_secs = self.config().node.link_dead_timeout_secs,
                        "Removing peer: link dead timeout"
                    );
                    self.remove_active_peer(&peer);
                    self.schedule_reconnect(peer, now_ms);
                }
                MmpAction::Heartbeat { peer } => {
                    if let Some(p) = self.peers.get_mut(&peer) {
                        p.mark_heartbeat_sent(now);
                    }
                    if let Err(e) = self
                        .send_encrypted_link_message(&peer, &heartbeat_msg)
                        .await
                    {
                        trace!(peer = %self.peer_display_name(&peer), error = %e, "Failed to send heartbeat");
                    }
                }
                MmpAction::SendLinkReport { .. }
                | MmpAction::LogLink { .. }
                | MmpAction::SendSessionReport { .. }
                | MmpAction::LogSession { .. } => {}
            }
        }
    }
}
