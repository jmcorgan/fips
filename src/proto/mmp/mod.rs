//! Sans-IO MMP (metrics protocol) reporting subsystem.
//!
//! Pure, runtime-agnostic report-fan-out / liveness / heartbeat decisions plus
//! the owned per-peer/per-session protocol state, migrated out of the async node
//! shell. The async I/O adapters remain in `node::handlers::mmp`.
//!
//! - `core.rs` — the snapshot read-seams, the [`MmpAction`] effect vocabulary,
//!   and the pure `plan_*` decisions (line-invariant across the master/next
//!   report shapes).
//! - `state.rs` — [`Mmp`] (the reporting anchor) plus the owned sender/receiver/
//!   metrics/path-MTU state machines (`u64`-ms time seam, `no_std`+`alloc`).
//! - `algorithms.rs` — the pure estimators (jitter/SRTT/dual-EWMA/OWD-trend/ETX;
//!   `no_std`+`alloc`).
//! - `wire.rs` — the link-layer and session-layer report codecs.
//!
//! `MmpConfig` (serde node config) stays shell-side in `crate::mmp`; only the
//! plain values it carries reach the owned state constructors.

// Leading `::` disambiguates the extern `core` crate from the child `mod core`.
use ::core::fmt;

use serde::{Deserialize, Serialize};

mod algorithms;
mod core;
mod state;
mod wire;

#[cfg(test)]
mod tests;

pub(crate) use algorithms::DualEwma;
pub(crate) use core::{
    BackoffUpdate, LinkReportKind, LinkReportSnapshot, MmpAction, PeerLivenessSnapshot, SendResult,
    SessionReportKind, SessionReportSnapshot,
};
pub(crate) use state::{Mmp, MmpMetrics, MmpPeerState, MmpSessionState, RrLog};
pub use wire::{
    PathMtuNotification, ReceiverReport, SenderReport, SessionReceiverReport, SessionSenderReport,
};

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
    /// CE echo only. No reports exchanged.
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
// Constants
// ============================================================================

// --- EWMA parameters ---

/// Dual EWMA short-term: α = 1/4.
pub const EWMA_SHORT_ALPHA: f64 = 0.25;

/// Dual EWMA long-term: α = 1/32.
pub const EWMA_LONG_ALPHA: f64 = 1.0 / 32.0;

// --- Timing defaults (milliseconds) ---

/// Default report interval before SRTT is available (cold start).
pub const DEFAULT_COLD_START_INTERVAL_MS: u64 = 200;

/// Minimum report interval (SRTT clamp floor).
///
/// Raised from 100ms to 1000ms: parent re-evaluation runs every 60s,
/// so 60 samples/cycle is more than sufficient for EWMA convergence (~10).
/// The cold-start phase uses `DEFAULT_COLD_START_INTERVAL_MS` (200ms) for
/// fast initial SRTT convergence before transitioning to this floor.
pub const MIN_REPORT_INTERVAL_MS: u64 = 1_000;

/// Maximum report interval (SRTT clamp ceiling).
pub const MAX_REPORT_INTERVAL_MS: u64 = 5_000;

/// Number of SRTT samples before transitioning from cold-start to normal floor.
///
/// During cold-start, report intervals use `DEFAULT_COLD_START_INTERVAL_MS` as
/// the floor to gather SRTT samples quickly. After this many updates, the floor
/// switches to `MIN_REPORT_INTERVAL_MS`.
pub const COLD_START_SAMPLES: u32 = 5;

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
