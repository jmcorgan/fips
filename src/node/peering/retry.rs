//! Cross-attempt retry state for auto-connect peers.
//!
//! [`RetryState`] is the durable per-peer schedule entry the peering reconciler
//! owns (it lives in [`crate::node::peering::reconcile::PeeringReconciler`], not
//! on a per-connection object, because a fresh connection is created per re-dial
//! so the escalating backoff count must persist across attempts). The decision
//! logic that reads and mutates it — the retry-dial phase and the
//! `on_handshake_timeout` / `on_link_dead` reflexes — lives in the sans-IO
//! reconciler core; the driver wrappers that feed it (retry-dial I/O, the
//! gate-guarded reflex call sites) live in [`super::driver`].

use crate::config::PeerConfig;

/// Per-tick cap on retry-dial connection attempts (design §6 ceiling).
pub(in crate::node) const MAX_RETRY_CONNECTIONS_PER_TICK: usize = 16;

/// Tracks retry state for a peer across connection attempts.
pub struct RetryState {
    /// The peer config to use for initiating retries.
    pub peer_config: PeerConfig,

    /// Number of retries attempted so far.
    pub retry_count: u32,

    /// Timestamp (Unix ms) when the next retry should be attempted.
    pub retry_after_ms: u64,

    /// Whether this is an auto-reconnect (unlimited retries, ignores max_retries).
    pub reconnect: bool,

    /// Optional absolute expiry for this retry entry (Unix ms).
    ///
    /// When set, retries are dropped after this point even if reconnect logic
    /// would otherwise continue.
    pub expires_at_ms: Option<u64>,
}

impl RetryState {
    /// Create a new retry state for a peer.
    pub fn new(peer_config: PeerConfig) -> Self {
        Self {
            peer_config,
            retry_count: 0,
            retry_after_ms: 0,
            reconnect: false,
            expires_at_ms: None,
        }
    }
}
