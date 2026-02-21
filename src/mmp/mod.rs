//! Metrics Measurement Protocol (MMP) — link-layer instantiation.
//!
//! Measures link quality between adjacent peers: RTT, loss, jitter,
//! throughput, one-way delay trend, and ETX. Operates on the per-frame
//! hooks (counter, timestamp, flags) introduced by the FMP wire format
//! revision.
//!
//! Three operating modes trade measurement fidelity for overhead:
//! - **Full**: sender + receiver reports at RTT-adaptive intervals
//! - **Lightweight**: receiver reports only (infer loss from counters)
//! - **Minimal**: spin bit + CE echo only, no reports

use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};
use std::time::{Duration, Instant};

// Sub-modules
pub mod algorithms;
pub mod metrics;
pub mod receiver;
pub mod report;
pub mod sender;

// Re-exports
pub use algorithms::{
    DualEwma, JitterEstimator, OwdTrendDetector, SpinBitState, SrttEstimator, compute_etx,
};
pub use metrics::MmpMetrics;
pub use receiver::ReceiverState;
pub use report::{ReceiverReport, SenderReport};
pub use sender::SenderState;

// Session-layer re-exports
// MmpSessionState and PathMtuState are defined in this file

// ============================================================================
// Constants
// ============================================================================

/// SenderReport body size (after msg_type byte): 3 reserved + 44 payload = 47.
pub const SENDER_REPORT_BODY_SIZE: usize = 47;

/// ReceiverReport body size (after msg_type byte): 3 reserved + 64 payload = 67.
pub const RECEIVER_REPORT_BODY_SIZE: usize = 67;

/// SenderReport total wire size including inner header: 5 + 47 = 52.
pub const SENDER_REPORT_WIRE_SIZE: usize = 52;

/// ReceiverReport total wire size including inner header: 5 + 67 = 72.
pub const RECEIVER_REPORT_WIRE_SIZE: usize = 72;

// --- EWMA parameters (as shift amounts for integer arithmetic) ---

/// Jitter EWMA: α = 1/16 (RFC 3550 §6.4.1).
pub const JITTER_ALPHA_SHIFT: u32 = 4;

/// SRTT: α = 1/8 (Jacobson, RFC 6298).
pub const SRTT_ALPHA_SHIFT: u32 = 3;

/// RTTVAR: β = 1/4 (Jacobson, RFC 6298).
pub const RTTVAR_BETA_SHIFT: u32 = 2;

/// Dual EWMA short-term: α = 1/4.
pub const EWMA_SHORT_ALPHA: f64 = 0.25;

/// Dual EWMA long-term: α = 1/32.
pub const EWMA_LONG_ALPHA: f64 = 1.0 / 32.0;

// --- Timing defaults (milliseconds) ---

/// Default report interval before SRTT is available (cold start).
pub const DEFAULT_COLD_START_INTERVAL_MS: u64 = 200;

/// Minimum report interval (SRTT clamp floor).
pub const MIN_REPORT_INTERVAL_MS: u64 = 100;

/// Maximum report interval (SRTT clamp ceiling).
pub const MAX_REPORT_INTERVAL_MS: u64 = 2_000;

/// Default OWD ring buffer capacity.
pub const DEFAULT_OWD_WINDOW_SIZE: usize = 32;

/// Default operator log interval in seconds.
pub const DEFAULT_LOG_INTERVAL_SECS: u64 = 30;

// --- Session-layer timing defaults ---
// Session reports are routed end-to-end (bandwidth cost on every transit link),
// so intervals are higher than link-layer.

/// Session-layer minimum report interval.
pub const MIN_SESSION_REPORT_INTERVAL_MS: u64 = 500;

/// Session-layer maximum report interval.
pub const MAX_SESSION_REPORT_INTERVAL_MS: u64 = 10_000;

/// Session-layer cold-start report interval (before SRTT is available).
pub const SESSION_COLD_START_INTERVAL_MS: u64 = 1_000;

// ============================================================================
// Operating Mode
// ============================================================================

/// MMP operating mode.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MmpMode {
    /// Sender + receiver reports at RTT-adaptive intervals. Maximum fidelity.
    #[default]
    Full,
    /// Receiver reports only. Loss inferred from counter gaps.
    Lightweight,
    /// Spin bit + CE echo only. No reports exchanged.
    Minimal,
}

impl fmt::Display for MmpMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MmpMode::Full => write!(f, "full"),
            MmpMode::Lightweight => write!(f, "lightweight"),
            MmpMode::Minimal => write!(f, "minimal"),
        }
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// MMP configuration (`node.mmp.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmpConfig {
    /// Operating mode (`node.mmp.mode`).
    #[serde(default)]
    pub mode: MmpMode,

    /// Periodic operator log interval in seconds (`node.mmp.log_interval_secs`).
    #[serde(default = "MmpConfig::default_log_interval_secs")]
    pub log_interval_secs: u64,

    /// OWD trend ring buffer size (`node.mmp.owd_window_size`).
    #[serde(default = "MmpConfig::default_owd_window_size")]
    pub owd_window_size: usize,
}

impl Default for MmpConfig {
    fn default() -> Self {
        Self {
            mode: MmpMode::default(),
            log_interval_secs: DEFAULT_LOG_INTERVAL_SECS,
            owd_window_size: DEFAULT_OWD_WINDOW_SIZE,
        }
    }
}

impl MmpConfig {
    fn default_log_interval_secs() -> u64 {
        DEFAULT_LOG_INTERVAL_SECS
    }
    fn default_owd_window_size() -> usize {
        DEFAULT_OWD_WINDOW_SIZE
    }
}

// ============================================================================
// Per-Peer MMP State
// ============================================================================

/// Combined MMP state for a single peer link.
///
/// Wraps sender, receiver, metrics, and spin bit state. One instance
/// per `ActivePeer`.
pub struct MmpPeerState {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub metrics: MmpMetrics,
    pub spin_bit: SpinBitState,
    mode: MmpMode,
    log_interval: Duration,
    last_log_time: Option<Instant>,
}

impl MmpPeerState {
    /// Create MMP state for a new peer link.
    ///
    /// `is_initiator`: true if this node initiated the Noise handshake
    /// (determines spin bit role).
    pub fn new(config: &MmpConfig, is_initiator: bool) -> Self {
        Self {
            sender: SenderState::new(),
            receiver: ReceiverState::new(config.owd_window_size),
            metrics: MmpMetrics::new(),
            spin_bit: SpinBitState::new(is_initiator),
            mode: config.mode,
            log_interval: Duration::from_secs(config.log_interval_secs),
            last_log_time: None,
        }
    }

    /// Current operating mode.
    pub fn mode(&self) -> MmpMode {
        self.mode
    }

    /// Check if it's time to emit a periodic metrics log.
    pub fn should_log(&self, now: Instant) -> bool {
        match self.last_log_time {
            None => true,
            Some(last) => now.duration_since(last) >= self.log_interval,
        }
    }

    /// Mark that a periodic log was emitted.
    pub fn mark_logged(&mut self, now: Instant) {
        self.last_log_time = Some(now);
    }
}

// ============================================================================
// Per-Session MMP State (session-layer instantiation)
// ============================================================================

/// Combined MMP state for a single end-to-end session.
///
/// Wraps sender, receiver, metrics, spin bit, and path MTU state.
/// One instance per established `SessionEntry`.
pub struct MmpSessionState {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub metrics: MmpMetrics,
    pub spin_bit: SpinBitState,
    mode: MmpMode,
    log_interval: Duration,
    last_log_time: Option<Instant>,
    pub path_mtu: PathMtuState,
}

impl MmpSessionState {
    /// Create MMP state for a new session.
    ///
    /// `is_initiator`: true if this node initiated the Noise handshake
    /// (determines spin bit role).
    pub fn new(config: &crate::config::SessionMmpConfig, is_initiator: bool) -> Self {
        Self {
            sender: SenderState::new_with_cold_start(SESSION_COLD_START_INTERVAL_MS),
            receiver: ReceiverState::new_with_cold_start(
                config.owd_window_size,
                SESSION_COLD_START_INTERVAL_MS,
            ),
            metrics: MmpMetrics::new(),
            spin_bit: SpinBitState::new(is_initiator),
            mode: config.mode,
            log_interval: Duration::from_secs(config.log_interval_secs),
            last_log_time: None,
            path_mtu: PathMtuState::new(),
        }
    }

    /// Current operating mode.
    pub fn mode(&self) -> MmpMode {
        self.mode
    }

    /// Check if it's time to emit a periodic metrics log.
    pub fn should_log(&self, now: Instant) -> bool {
        match self.last_log_time {
            None => true,
            Some(last) => now.duration_since(last) >= self.log_interval,
        }
    }

    /// Mark that a periodic log was emitted.
    pub fn mark_logged(&mut self, now: Instant) {
        self.last_log_time = Some(now);
    }
}

impl Debug for MmpSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmpSessionState")
            .field("mode", &self.mode)
            .field("path_mtu", &self.path_mtu.current_mtu())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Path MTU State (session-layer only)
// ============================================================================

/// Path MTU tracking for a single session.
///
/// Destination side: observes `path_mtu` from incoming SessionDatagram envelopes
/// and generates PathMtuNotification messages back to the source.
///
/// Source side: applies received PathMtuNotification to limit outbound datagram
/// size. Decrease is immediate; increase requires 3 consecutive notifications.
pub struct PathMtuState {
    /// Current effective path MTU (what we use for sending).
    current_mtu: u16,
    /// Last observed path MTU from incoming datagrams (destination-side).
    last_observed_mtu: u16,
    /// Whether the observed MTU has changed since the last notification.
    observed_changed: bool,
    /// Last time a PathMtuNotification was sent.
    last_notification_time: Option<Instant>,
    /// Notification interval: max(10s, 5 * SRTT). Default 10s.
    notification_interval: Duration,
    /// For source-side increase tracking: consecutive higher-value notifications.
    consecutive_increase_count: u8,
    /// Time of the first notification in the current increase sequence.
    first_increase_time: Option<Instant>,
    /// The MTU value being proposed for increase.
    pending_increase_mtu: u16,
}

impl PathMtuState {
    /// Create path MTU state with no initial measurement.
    pub fn new() -> Self {
        Self {
            current_mtu: u16::MAX,
            last_observed_mtu: u16::MAX,
            observed_changed: false,
            last_notification_time: None,
            notification_interval: Duration::from_secs(10),
            consecutive_increase_count: 0,
            first_increase_time: None,
            pending_increase_mtu: 0,
        }
    }

    /// Current effective path MTU (source-side, for sending).
    pub fn current_mtu(&self) -> u16 {
        self.current_mtu
    }

    /// Last observed incoming path MTU (destination-side).
    pub fn last_observed_mtu(&self) -> u16 {
        self.last_observed_mtu
    }

    /// Update notification interval from SRTT: max(10s, 5 * SRTT).
    pub fn update_interval_from_srtt(&mut self, srtt_ms: f64) {
        let five_srtt = Duration::from_millis((srtt_ms * 5.0) as u64);
        self.notification_interval = five_srtt.max(Duration::from_secs(10));
    }

    /// Seed source-side current_mtu from outbound transport MTU.
    ///
    /// Called on each send. Only decreases (never increases) the current_mtu
    /// so the destination's PathMtuNotification can still raise it later.
    /// Ensures current_mtu doesn't stay at u16::MAX before any notification
    /// arrives from the destination.
    pub fn seed_source_mtu(&mut self, outbound_mtu: u16) {
        if outbound_mtu < self.current_mtu {
            self.current_mtu = outbound_mtu;
        }
    }

    // --- Destination side ---

    /// Observe the path_mtu from an incoming SessionDatagram envelope.
    ///
    /// Called on the destination (receiver) side for every session message.
    pub fn observe_incoming_mtu(&mut self, path_mtu: u16) {
        if path_mtu != self.last_observed_mtu {
            self.observed_changed = true;
            self.last_observed_mtu = path_mtu;
        }
    }

    /// Check if a PathMtuNotification should be sent.
    ///
    /// Send on first measurement, on decrease (immediate), or periodic
    /// confirmation at the notification interval.
    pub fn should_send_notification(&self, now: Instant) -> bool {
        if self.last_observed_mtu == u16::MAX {
            return false; // No measurement yet
        }
        match self.last_notification_time {
            None => true, // First measurement
            Some(last) => {
                // Immediate on decrease
                if self.observed_changed && self.last_observed_mtu < self.current_mtu {
                    return true;
                }
                // Periodic confirmation
                now.duration_since(last) >= self.notification_interval
            }
        }
    }

    /// Build a PathMtuNotification from current state.
    ///
    /// Returns the path_mtu value to send. Caller handles encoding.
    pub fn build_notification(&mut self, now: Instant) -> Option<u16> {
        if self.last_observed_mtu == u16::MAX {
            return None;
        }
        self.last_notification_time = Some(now);
        self.observed_changed = false;
        Some(self.last_observed_mtu)
    }

    // --- Source side ---

    /// Apply a received PathMtuNotification.
    ///
    /// - Decrease: immediate (take the lower value).
    /// - Increase: require 3 consecutive notifications with the same higher
    ///   value, spanning at least 2 * notification_interval.
    ///
    /// Returns `true` if the effective MTU changed.
    pub fn apply_notification(&mut self, reported_mtu: u16, now: Instant) -> bool {
        if reported_mtu < self.current_mtu {
            // Decrease: immediate
            self.current_mtu = reported_mtu;
            self.consecutive_increase_count = 0;
            self.first_increase_time = None;
            return true;
        }

        if reported_mtu > self.current_mtu {
            // Increase: track consecutive notifications
            if reported_mtu == self.pending_increase_mtu {
                self.consecutive_increase_count += 1;
            } else {
                // Different value: reset sequence
                self.pending_increase_mtu = reported_mtu;
                self.consecutive_increase_count = 1;
                self.first_increase_time = Some(now);
            }

            // Accept increase after 3 consecutive spanning 2 * interval
            if self.consecutive_increase_count >= 3
                && let Some(first_time) = self.first_increase_time
            {
                let required = self.notification_interval * 2;
                if now.duration_since(first_time) >= required {
                    self.current_mtu = reported_mtu;
                    self.consecutive_increase_count = 0;
                    self.first_increase_time = None;
                    return true;
                }
            }
        }

        // No change (equal or increase not yet confirmed)
        false
    }
}

impl Default for PathMtuState {
    fn default() -> Self {
        Self::new()
    }
}

impl Debug for MmpPeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MmpPeerState")
            .field("mode", &self.mode)
            .finish_non_exhaustive()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mode_default() {
        assert_eq!(MmpMode::default(), MmpMode::Full);
    }

    #[test]
    fn test_mode_display() {
        assert_eq!(MmpMode::Full.to_string(), "full");
        assert_eq!(MmpMode::Lightweight.to_string(), "lightweight");
        assert_eq!(MmpMode::Minimal.to_string(), "minimal");
    }

    #[test]
    fn test_mode_serde_roundtrip() {
        let yaml = "full";
        let mode: MmpMode = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(mode, MmpMode::Full);

        let yaml = "lightweight";
        let mode: MmpMode = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(mode, MmpMode::Lightweight);

        let yaml = "minimal";
        let mode: MmpMode = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(mode, MmpMode::Minimal);
    }

    #[test]
    fn test_config_default() {
        let config = MmpConfig::default();
        assert_eq!(config.mode, MmpMode::Full);
        assert_eq!(config.log_interval_secs, 30);
        assert_eq!(config.owd_window_size, 32);
    }

    #[test]
    fn test_config_yaml_parse() {
        let yaml = r#"
mode: lightweight
log_interval_secs: 60
owd_window_size: 48
"#;
        let config: MmpConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, MmpMode::Lightweight);
        assert_eq!(config.log_interval_secs, 60);
        assert_eq!(config.owd_window_size, 48);
    }

    #[test]
    fn test_config_yaml_partial() {
        let yaml = "mode: minimal";
        let config: MmpConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.mode, MmpMode::Minimal);
        assert_eq!(config.log_interval_secs, DEFAULT_LOG_INTERVAL_SECS);
        assert_eq!(config.owd_window_size, DEFAULT_OWD_WINDOW_SIZE);
    }
}
