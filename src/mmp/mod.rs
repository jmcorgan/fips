//! Metrics Measurement Protocol (MMP) — link-layer instantiation.
//!
//! Measures link quality between adjacent peers: RTT, loss, jitter,
//! throughput, one-way delay trend, and ETX. Operates on the per-frame
//! hooks (counter, timestamp, flags) introduced by the FLP wire format
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

// ============================================================================
// Operating Mode
// ============================================================================

/// MMP operating mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MmpMode {
    /// Sender + receiver reports at RTT-adaptive intervals. Maximum fidelity.
    Full,
    /// Receiver reports only. Loss inferred from counter gaps.
    Lightweight,
    /// Spin bit + CE echo only. No reports exchanged.
    Minimal,
}

impl Default for MmpMode {
    fn default() -> Self {
        MmpMode::Full
    }
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
