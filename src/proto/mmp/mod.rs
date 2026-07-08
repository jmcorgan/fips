//! Sans-IO MMP (metrics protocol) reporting subsystem.
//!
//! Pure, runtime-agnostic report-fan-out / liveness / heartbeat decisions plus
//! the owned per-peer/per-session protocol state, migrated out of the async node
//! shell. The async I/O adapters remain in `node::handlers::mmp`.
//!
//! - `core.rs` — the snapshot read-seams, the [`MmpAction`] effect vocabulary,
//!   and the pure `plan_*` decisions (line-invariant across the master/next
//!   report shapes).
//! - `state.rs` — [`Mmp`] (the reporting anchor) plus the [`MmpPeerState`]/
//!   [`MmpSessionState`] per-entity aggregates.
//! - `sender.rs`/`receiver.rs`/`metrics.rs`/`path_mtu.rs` — the owned sender/
//!   receiver/derived-metrics/path-MTU role state machines (`u64`-ms time seam,
//!   `no_std`+`alloc`).
//! - `limits.rs` — the module tuning constants.
//! - `algorithms.rs` — the pure estimators (jitter/SRTT/dual-EWMA/OWD-trend/ETX)
//!   and the spin-bit state (`no_std`+`alloc`).
//! - `wire.rs` — the link-layer and session-layer report codecs.
//!
//! `MmpConfig` (serde node config) stays shell-side in `crate::mmp`; only the
//! plain values it carries reach the owned state constructors.

// Leading `::` disambiguates the extern `core` crate from the child `mod core`.
use ::core::fmt;

use serde::{Deserialize, Serialize};

mod algorithms;
mod core;
mod limits;
mod metrics;
mod path_mtu;
mod receiver;
mod sender;
mod state;
mod wire;

#[cfg(test)]
mod tests;

pub(crate) use algorithms::DualEwma;
pub(crate) use core::{
    BackoffUpdate, LinkReportKind, LinkReportSnapshot, MmpAction, PeerLivenessSnapshot, SendResult,
    SessionReportKind, SessionReportSnapshot,
};
pub(crate) use metrics::{MmpMetrics, RrLog};
pub(crate) use state::{Mmp, MmpPeerState, MmpSessionState};
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
// Constants
// ============================================================================

// The module tuning constants live in `limits.rs`; re-exported here so external
// callers keep the `crate::proto::mmp::<CONST>` path.
pub use limits::{
    COLD_START_SAMPLES, DEFAULT_COLD_START_INTERVAL_MS, DEFAULT_LOG_INTERVAL_SECS,
    DEFAULT_OWD_WINDOW_SIZE, EWMA_LONG_ALPHA, EWMA_SHORT_ALPHA, MAX_REPORT_INTERVAL_MS,
    MAX_SESSION_REPORT_INTERVAL_MS, MIN_REPORT_INTERVAL_MS, MIN_SESSION_REPORT_INTERVAL_MS,
    SESSION_COLD_START_INTERVAL_MS,
};
