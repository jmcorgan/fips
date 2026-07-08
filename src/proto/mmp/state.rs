//! Owned MMP protocol state anchor and per-peer/per-session aggregates (sans-IO).
//!
//! [`Mmp`] is the stateless reporting anchor owned by `Node`; the per-entity
//! aggregates [`MmpPeerState`]/[`MmpSessionState`] wrap the owned role state
//! machines that live in sibling modules (`sender`, `receiver`, `metrics`,
//! `path_mtu`). All time inputs are injected `u64` milliseconds (the shell reads
//! its monotonic clock at the edge and passes the value in); nothing here reads a
//! clock, logs, or bumps a counter. `no_std`+`alloc`-clean.
//!
//! [`Mmp`] itself remains the stateless reporting anchor owned by `Node` (the
//! live per-entity state lives on the peers'/sessions' shell structs); it exists
//! so the reporting decisions can hang off a `Node` field in the same shape the
//! other migrated subsystems use.

use core::fmt::{self, Debug};

use super::metrics::MmpMetrics;
use super::path_mtu::PathMtuState;
use super::receiver::ReceiverState;
use super::sender::SenderState;
use super::{MmpMode, SESSION_COLD_START_INTERVAL_MS};

/// MMP reporting subsystem anchor owned by [`Node`](crate::node::Node).
///
/// Like [`Fmp`](crate::proto::fmp::Fmp), the MMP reporting core owns **no**
/// mutable state: the per-peer/per-session timing and backoff state lives on
/// the peers'/sessions' [`MmpPeerState`]/[`MmpSessionState`] structs (defined in
/// this module, held shell-side), and every registry mutation and send stays
/// shell-side, driven by the [`MmpAction`](super::MmpAction)s the pure `plan_*`
/// decisions emit. `Mmp` is therefore an empty namespace anchor: it exists so
/// the reporting decisions can hang off a `Node` field (`self.mmp`) in the same
/// shape the other migrated subsystems use, not to hold data.
pub(crate) struct Mmp;

impl Mmp {
    /// Create the (stateless) MMP reporting anchor.
    pub(crate) fn new() -> Self {
        Self
    }
}

// ============================================================================
// Per-Peer MMP State
// ============================================================================

/// Combined MMP state for a single peer link.
///
/// Wraps sender, receiver, and metrics. One instance
/// per `ActivePeer`.
pub struct MmpPeerState {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub metrics: MmpMetrics,
    mode: MmpMode,
    log_interval_ms: u64,
    last_log_ms: Option<u64>,
}

impl MmpPeerState {
    /// Create MMP state for a new peer link.
    ///
    /// `mode`/`log_interval_secs`/`owd_window_size`
    /// are the shell's config values, passed as plain data so this owned state
    /// carries no dependency on the shell config struct.
    pub fn new(mode: MmpMode, log_interval_secs: u64, owd_window_size: usize) -> Self {
        Self {
            sender: SenderState::new(),
            receiver: ReceiverState::new(owd_window_size),
            metrics: MmpMetrics::new(),
            mode,
            log_interval_ms: log_interval_secs * 1000,
            last_log_ms: None,
        }
    }

    /// Reset counter-dependent state for rekey cutover.
    pub fn reset_for_rekey(&mut self, now_ms: u64) {
        self.receiver.reset_for_rekey(now_ms);
        self.metrics.reset_for_rekey();
    }

    /// Current operating mode.
    pub fn mode(&self) -> MmpMode {
        self.mode
    }

    /// Check if it's time to emit a periodic metrics log.
    pub fn should_log(&self, now_ms: u64) -> bool {
        match self.last_log_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= self.log_interval_ms,
        }
    }

    /// Mark that a periodic log was emitted.
    pub fn mark_logged(&mut self, now_ms: u64) {
        self.last_log_ms = Some(now_ms);
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
// Per-Session MMP State (session-layer instantiation)
// ============================================================================

/// Combined MMP state for a single end-to-end session.
///
/// Wraps sender, receiver, metrics, and path MTU state.
/// One instance per established `SessionEntry`.
pub struct MmpSessionState {
    pub sender: SenderState,
    pub receiver: ReceiverState,
    pub metrics: MmpMetrics,
    mode: MmpMode,
    log_interval_ms: u64,
    last_log_ms: Option<u64>,
    pub path_mtu: PathMtuState,
}

impl MmpSessionState {
    /// Create MMP state for a new session.
    ///
    /// `mode`/`log_interval_secs`/`owd_window_size`
    /// are the shell's config values, passed as plain data.
    pub fn new(mode: MmpMode, log_interval_secs: u64, owd_window_size: usize) -> Self {
        Self {
            sender: SenderState::new_with_cold_start(SESSION_COLD_START_INTERVAL_MS),
            receiver: ReceiverState::new_with_cold_start(
                owd_window_size,
                SESSION_COLD_START_INTERVAL_MS,
            ),
            metrics: MmpMetrics::new(),
            mode,
            log_interval_ms: log_interval_secs * 1000,
            last_log_ms: None,
            path_mtu: PathMtuState::new(),
        }
    }

    /// Reset counter-dependent state for rekey cutover.
    pub fn reset_for_rekey(&mut self, now_ms: u64) {
        self.receiver.reset_for_rekey(now_ms);
        self.metrics.reset_for_rekey();
    }

    /// Current operating mode.
    pub fn mode(&self) -> MmpMode {
        self.mode
    }

    /// Check if it's time to emit a periodic metrics log.
    pub fn should_log(&self, now_ms: u64) -> bool {
        match self.last_log_ms {
            None => true,
            Some(last) => now_ms.saturating_sub(last) >= self.log_interval_ms,
        }
    }

    /// Mark that a periodic log was emitted.
    pub fn mark_logged(&mut self, now_ms: u64) {
        self.last_log_ms = Some(now_ms);
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
