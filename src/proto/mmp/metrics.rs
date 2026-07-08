//! Derived MMP metrics (sans-IO).
//!
//! Sender-side derived metrics (RTT, loss, goodput, ETX, trends) computed from
//! incoming `ReceiverReport`s, plus the [`RrLog`] observability outcome returned
//! to the shell so the operator `trace!` points can fire there rather than
//! mid-decision. All time inputs are injected `u64` milliseconds.

use super::algorithms::{DualEwma, SrttEstimator, compute_etx};
use super::wire::ReceiverReport;

// ============================================================================
// ReceiverReport processing outcome (observability hoisted to the shell)
// ============================================================================

/// The observability outcome of [`MmpMetrics::process_receiver_report`], returned
/// so the async shell can emit the operator `trace!` points that used to live
/// mid-decision (per the sans-IO rule that migrated code carries no `tracing`).
///
/// Exactly one variant applies per call; the shell has the incoming report and
/// our timestamp, so this only carries the values the shell cannot otherwise
/// reconstruct (the previous cumulative snapshot / the derived RTT).
pub enum RrLog {
    /// No RTT log point fires (the report carried no timestamp echo).
    None,
    /// The report was ignored as stale/duplicate. Carries the previous
    /// cumulative snapshot for the operator trace.
    Stale {
        prev_highest: u64,
        prev_packets: u64,
        prev_bytes: u64,
    },
    /// A valid RTT sample was taken; carries the derived RTT and the SRTT as it
    /// stood **before** this sample was folded in (matching the original log,
    /// which read `srtt` before `update`).
    RttSample { rtt_ms: u32, srtt_ms: f64 },
    /// The report carried an echo but the derived RTT was invalid (wrapped /
    /// non-positive).
    InvalidRtt,
}

// ============================================================================
// MmpMetrics (derived metrics)
// ============================================================================

/// Derived MMP metrics, updated from incoming ReceiverReports.
///
/// This lives on the sender side: when we receive a ReceiverReport from
/// our peer describing what they observed about our traffic, we process
/// it here to compute RTT, loss, goodput, and trend indicators.
pub struct MmpMetrics {
    /// Smoothed RTT from timestamp echo.
    pub srtt: SrttEstimator,

    /// Dual EWMA trend detectors.
    pub rtt_trend: DualEwma,
    pub loss_trend: DualEwma,
    pub goodput_trend: DualEwma,
    pub jitter_trend: DualEwma,
    pub etx_trend: DualEwma,

    /// Forward delivery ratio (what fraction of our frames the peer received).
    pub delivery_ratio_forward: f64,
    /// Reverse delivery ratio (set when we compute from our own receiver state).
    pub delivery_ratio_reverse: f64,
    /// ETX computed from bidirectional delivery ratios.
    pub etx: f64,

    /// Smoothed goodput in bytes/sec (forward direction: what the peer received from us).
    pub goodput_bps: f64,

    // --- State for delta computation ---
    /// Previous ReceiverReport's cumulative counters (for computing interval deltas).
    prev_rr_cum_packets: u64,
    prev_rr_cum_bytes: u64,
    prev_rr_highest_counter: u64,
    prev_rr_ecn_ce: u32,
    prev_rr_reorder: u32,
    /// Time (injected `u64` ms) of previous ReceiverReport (for goodput rate).
    prev_rr_ms: Option<u64>,
    /// Whether we have a previous ReceiverReport for delta computation.
    has_prev_rr: bool,

    // --- State for reverse delivery ratio delta computation ---
    /// Previous reverse-side cumulative packets received (our receiver state).
    prev_reverse_packets: u64,
    /// Previous reverse-side highest counter (our receiver state).
    prev_reverse_highest: u64,
    /// Whether we have a previous reverse-side snapshot for delta computation.
    has_prev_reverse: bool,
}

impl MmpMetrics {
    /// Reset state derived from ReceiverReport counters for rekey cutover.
    ///
    /// The new session starts with counter 0, so the prev_rr deltas must
    /// be reset to avoid computing bogus loss/goodput from the counter
    /// discontinuity. RTT (SRTT) is preserved since it remains valid.
    pub fn reset_for_rekey(&mut self) {
        self.prev_rr_cum_packets = 0;
        self.prev_rr_cum_bytes = 0;
        self.prev_rr_highest_counter = 0;
        self.prev_rr_ecn_ce = 0;
        self.prev_rr_reorder = 0;
        self.prev_rr_ms = None;
        self.has_prev_rr = false;
        self.delivery_ratio_forward = 1.0;
        self.prev_reverse_packets = 0;
        self.prev_reverse_highest = 0;
        self.has_prev_reverse = false;
        // Keep srtt, etx, trends, goodput_bps — they'll refresh from data
    }

    pub fn new() -> Self {
        Self {
            srtt: SrttEstimator::new(),
            rtt_trend: DualEwma::new(),
            loss_trend: DualEwma::new(),
            goodput_trend: DualEwma::new(),
            jitter_trend: DualEwma::new(),
            etx_trend: DualEwma::new(),
            delivery_ratio_forward: 1.0,
            delivery_ratio_reverse: 1.0,
            etx: 1.0,
            goodput_bps: 0.0,
            prev_rr_cum_packets: 0,
            prev_rr_cum_bytes: 0,
            prev_rr_highest_counter: 0,
            prev_rr_ecn_ce: 0,
            prev_rr_reorder: 0,
            prev_rr_ms: None,
            has_prev_rr: false,
            prev_reverse_packets: 0,
            prev_reverse_highest: 0,
            has_prev_reverse: false,
        }
    }

    /// Process an incoming ReceiverReport (from the peer about our traffic).
    ///
    /// `our_timestamp_ms` is the current session-relative time in ms (for RTT).
    /// `now_ms` is the injected monotonic time in ms (for goodput rate).
    ///
    /// Returns `(first_srtt, log)`: `first_srtt` is `true` if this report
    /// produced the first SRTT measurement (transition from uninitialized to
    /// initialized); `log` is the [`RrLog`] observability outcome the shell
    /// emits (the `tracing` that used to fire here now lives shell-side).
    pub fn process_receiver_report(
        &mut self,
        rr: &ReceiverReport,
        our_timestamp_ms: u32,
        now_ms: u64,
    ) -> (bool, RrLog) {
        let had_srtt = self.srtt.initialized();

        if self.has_prev_rr {
            let counters_regressed = rr.highest_counter < self.prev_rr_highest_counter
                || rr.cumulative_packets_recv < self.prev_rr_cum_packets
                || rr.cumulative_bytes_recv < self.prev_rr_cum_bytes
                || rr.ecn_ce_count < self.prev_rr_ecn_ce
                || rr.cumulative_reorder_count < self.prev_rr_reorder;
            let duplicate_counters = rr.highest_counter == self.prev_rr_highest_counter
                && rr.cumulative_packets_recv == self.prev_rr_cum_packets
                && rr.cumulative_bytes_recv == self.prev_rr_cum_bytes
                && rr.ecn_ce_count == self.prev_rr_ecn_ce
                && rr.cumulative_reorder_count == self.prev_rr_reorder;
            // Safe to drop: reports are only built after interval data, so
            // a fresh report always advances at least one cumulative counter.
            if counters_regressed || duplicate_counters {
                return (
                    false,
                    RrLog::Stale {
                        prev_highest: self.prev_rr_highest_counter,
                        prev_packets: self.prev_rr_cum_packets,
                        prev_bytes: self.prev_rr_cum_bytes,
                    },
                );
            }
        }

        let mut log = RrLog::None;

        // --- RTT from timestamp echo ---
        // RTT = now - echoed_timestamp - dwell_time
        if rr.timestamp_echo > 0 {
            let echo_ms = rr.timestamp_echo;
            let dwell_ms = u32::from(rr.dwell_time);
            let rtt_sample_ms = echo_ms
                .checked_add(dwell_ms)
                .and_then(|send_done_ms| our_timestamp_ms.checked_sub(send_done_ms));

            match rtt_sample_ms {
                Some(rtt_ms) if rtt_ms > 0 => {
                    let rtt_us = (rtt_ms as i64) * 1000;
                    // Capture SRTT before folding in this sample (the original
                    // trace read `srtt` before `update`).
                    let srtt_ms = self.srtt.srtt_us() as f64 / 1000.0;
                    log = RrLog::RttSample { rtt_ms, srtt_ms };
                    self.srtt.update(rtt_us);
                    self.rtt_trend.update(rtt_us as f64);
                }
                _ => {
                    log = RrLog::InvalidRtt;
                }
            }
        }

        // --- Loss rate from cumulative counters ---
        // Delta: frames the peer should have received vs. actually received
        if self.has_prev_rr {
            let counter_span = rr
                .highest_counter
                .saturating_sub(self.prev_rr_highest_counter);
            let packets_delta = rr
                .cumulative_packets_recv
                .saturating_sub(self.prev_rr_cum_packets);

            if counter_span > 0 {
                let delivery = (packets_delta as f64) / (counter_span as f64);
                self.delivery_ratio_forward = delivery.clamp(0.0, 1.0);
                let loss_rate = 1.0 - self.delivery_ratio_forward;
                self.loss_trend.update(loss_rate);
                self.etx = compute_etx(self.delivery_ratio_forward, self.delivery_ratio_reverse);
                self.etx_trend.update(self.etx);
            }
        }

        // --- Goodput from cumulative bytes + time delta ---
        if self.has_prev_rr {
            let bytes_delta = rr
                .cumulative_bytes_recv
                .saturating_sub(self.prev_rr_cum_bytes);
            self.goodput_trend.update(bytes_delta as f64);

            // Compute bytes/sec if we have a time reference
            if let Some(prev_ms) = self.prev_rr_ms {
                let secs = (now_ms.saturating_sub(prev_ms) as f64) / 1000.0;
                if secs > 0.0 {
                    let bps = bytes_delta as f64 / secs;
                    // EWMA smoothing: α = 1/4
                    if self.goodput_bps == 0.0 {
                        self.goodput_bps = bps;
                    } else {
                        self.goodput_bps += (bps - self.goodput_bps) * 0.25;
                    }
                }
            }
        }

        // --- Jitter trend ---
        self.jitter_trend.update(rr.jitter as f64);

        // --- Save for next delta ---
        self.prev_rr_cum_packets = rr.cumulative_packets_recv;
        self.prev_rr_cum_bytes = rr.cumulative_bytes_recv;
        self.prev_rr_highest_counter = rr.highest_counter;
        self.prev_rr_ecn_ce = rr.ecn_ce_count;
        self.prev_rr_reorder = rr.cumulative_reorder_count;
        self.prev_rr_ms = Some(now_ms);
        self.has_prev_rr = true;

        (!had_srtt && self.srtt.initialized(), log)
    }

    /// Update the reverse delivery ratio from our own receiver state.
    ///
    /// Computes a per-interval delta (same as forward ratio) rather than
    /// a lifetime cumulative ratio, so ETX responds to recent conditions.
    pub fn update_reverse_delivery(&mut self, our_recv_packets: u64, peer_highest: u64) {
        if self.has_prev_reverse {
            let counter_span = peer_highest.saturating_sub(self.prev_reverse_highest);
            let packets_delta = our_recv_packets.saturating_sub(self.prev_reverse_packets);

            if counter_span > 0 {
                let delivery = (packets_delta as f64) / (counter_span as f64);
                self.delivery_ratio_reverse = delivery.clamp(0.0, 1.0);
                self.etx = compute_etx(self.delivery_ratio_forward, self.delivery_ratio_reverse);
                self.etx_trend.update(self.etx);
            }
        }

        self.prev_reverse_packets = our_recv_packets;
        self.prev_reverse_highest = peer_highest;
        self.has_prev_reverse = true;
    }

    /// Current smoothed RTT in milliseconds, or `None` if not yet measured.
    pub fn srtt_ms(&self) -> Option<f64> {
        if self.srtt.initialized() {
            Some(self.srtt.srtt_us() as f64 / 1000.0)
        } else {
            None
        }
    }

    /// Current loss rate (0.0 = no loss, 1.0 = total loss).
    pub fn loss_rate(&self) -> f64 {
        1.0 - self.delivery_ratio_forward
    }

    /// Smoothed loss rate (long-term EWMA), or `None` if not yet initialized.
    pub fn smoothed_loss(&self) -> Option<f64> {
        if self.loss_trend.initialized() {
            Some(self.loss_trend.long())
        } else {
            None
        }
    }

    /// Smoothed ETX (long-term EWMA), or `None` if not yet initialized.
    pub fn smoothed_etx(&self) -> Option<f64> {
        if self.etx_trend.initialized() {
            Some(self.etx_trend.long())
        } else {
            None
        }
    }

    /// Current smoothed goodput in bytes/sec, or 0 if not yet measured.
    pub fn goodput_bps(&self) -> f64 {
        self.goodput_bps
    }

    /// Cumulative ECN CE count from the most recent ReceiverReport.
    pub fn last_ecn_ce_count(&self) -> u32 {
        self.prev_rr_ecn_ce
    }
}

impl Default for MmpMetrics {
    fn default() -> Self {
        Self::new()
    }
}
