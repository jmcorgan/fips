//! Mesh lookup subsystem state owned by [`Node`](crate::node::Node).
//!
//! Groups the four lookup-related state fields (recent-request dedup
//! cache, in-flight lookups, originator-side backoff, transit-side forward
//! rate limiter) behind a single struct so the lookup handlers can
//! evolve toward a sans-IO core without threading four fields through
//! `Node`.

use alloc::collections::BTreeMap;

use super::limits::{LookupBackoff, LookupForwardRateLimiter};
use crate::NodeAddr;

/// Recent request tracking for dedup and reverse-path forwarding.
///
/// When a LookupRequest is forwarded through a node, the node stores the
/// request_id and which peer sent it. When the corresponding LookupResponse
/// arrives, it's forwarded back to that peer (reverse-path forwarding).
/// The `response_forwarded` flag prevents response routing loops.
#[derive(Clone, Debug)]
pub(crate) struct RecentRequest {
    /// The peer who sent this request to us.
    pub(crate) from_peer: NodeAddr,
    /// When we received this request (Unix milliseconds).
    pub(crate) timestamp_ms: u64,
    /// Whether we've already forwarded a response for this request.
    /// Prevents response routing loops when convergent request paths
    /// create bidirectional entries in recent_requests.
    pub(crate) response_forwarded: bool,
}

impl RecentRequest {
    pub(crate) fn new(from_peer: NodeAddr, timestamp_ms: u64) -> Self {
        Self {
            from_peer,
            timestamp_ms,
            response_forwarded: false,
        }
    }

    /// Check if this entry has expired (older than expiry_ms).
    pub(crate) fn is_expired(&self, current_time_ms: u64, expiry_ms: u64) -> bool {
        current_time_ms.saturating_sub(self.timestamp_ms) > expiry_ms
    }
}

/// Tracks a pending lookup with retry state.
pub struct PendingLookup {
    /// When the lookup was first initiated.
    pub initiated_ms: u64,
    /// When the last attempt was sent.
    pub last_sent_ms: u64,
    /// Current attempt number (1 = initial, 2 = first retry, ...).
    pub attempt: u8,
}

impl PendingLookup {
    pub fn new(now_ms: u64) -> Self {
        Self {
            initiated_ms: now_ms,
            last_sent_ms: now_ms,
            attempt: 1,
        }
    }
}

/// Mesh lookup subsystem state.
pub(crate) struct Lookup {
    /// Recent lookup requests (dedup + reverse-path forwarding).
    /// Maps request_id → RecentRequest.
    pub(crate) recent_requests: BTreeMap<u64, RecentRequest>,
    /// Tracks in-flight lookups. Maps target NodeAddr to the
    /// initiation timestamp (Unix ms). Prevents duplicate flood queries.
    pub(crate) pending_lookups: BTreeMap<NodeAddr, PendingLookup>,
    /// Backoff for failed lookups (originator-side).
    pub(crate) backoff: LookupBackoff,
    /// Rate limiter for forwarded lookup requests (transit-side).
    pub(crate) forward_limiter: LookupForwardRateLimiter,
}

impl Lookup {
    /// Create mesh lookup state with the given backoff and forward limiter.
    ///
    /// The two limiters are constructed by the caller so each `Node`
    /// constructor can supply its own configured/default variant, matching
    /// the pre-refactor initialization exactly.
    pub(crate) fn new(backoff: LookupBackoff, forward_limiter: LookupForwardRateLimiter) -> Self {
        Self {
            recent_requests: BTreeMap::new(),
            pending_lookups: BTreeMap::new(),
            backoff,
            forward_limiter,
        }
    }

    /// Reset lookup backoff on topology changes. Returns the number of
    /// entries cleared (0 if already empty) so the shell can log the reset —
    /// observability stays out of the pure core.
    pub(crate) fn reset_backoff(&mut self) -> usize {
        if self.backoff.is_empty() {
            return 0;
        }
        let cleared = self.backoff.entry_count();
        self.backoff.reset_all();
        cleared
    }
}
