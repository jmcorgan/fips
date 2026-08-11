//! BLE transport statistics.
//!
//! Counters reach an operator through `show_transports`, which serves them
//! off the control socket. Each connect outcome also emits a `debug!` at the
//! moment it happens, carrying a uniform field set — `addr`, `role`
//! (`central` for a dial, `peripheral` for an accept), `outcome` (a stable
//! kebab-case string matching the counter name), and `discovery_ms` where a
//! probe stamp exists. The counters give the aggregate; the trace stream
//! gives the same taxonomy per event and per peer.

use portable_atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Statistics for a BLE transport instance.
///
/// Uses atomic counters for lock-free updates from per-connection
/// receive loops and the send path concurrently.
pub struct BleStats {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub send_errors: AtomicU64,
    pub recv_errors: AtomicU64,
    pub mtu_exceeded: AtomicU64,
    pub connections_established: AtomicU64,
    pub connections_accepted: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub connect_timeouts: AtomicU64,
    /// Outbound connects that failed with an error rather than timing out.
    pub connect_errors: AtomicU64,
    /// Connections dropped because the pre-handshake pubkey exchange failed.
    pub pubkey_exchange_failures: AtomicU64,
    /// Outbound connections stood down by the cross-probe tie-breaker.
    pub tiebreaker_yields: AtomicU64,
    /// Inbound connections stood down by the cross-probe tie-breaker.
    pub tiebreaker_drops: AtomicU64,
    pub pool_evictions: AtomicU64,
    pub advertisements_sent: AtomicU64,
    pub scan_results: AtomicU64,
    /// Connections declined because the peer was already linked on another
    /// link address (see `ConnectionPool::find_by_node`).
    pub duplicate_node_declines: AtomicU64,
}

impl BleStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            packets_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            packets_recv: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
            mtu_exceeded: AtomicU64::new(0),
            connections_established: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            connect_timeouts: AtomicU64::new(0),
            connect_errors: AtomicU64::new(0),
            pubkey_exchange_failures: AtomicU64::new(0),
            tiebreaker_yields: AtomicU64::new(0),
            tiebreaker_drops: AtomicU64::new(0),
            pool_evictions: AtomicU64::new(0),
            advertisements_sent: AtomicU64::new(0),
            scan_results: AtomicU64::new(0),
            duplicate_node_declines: AtomicU64::new(0),
        }
    }

    /// Record a successful send.
    pub fn record_send(&self, bytes: usize) {
        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a successful receive.
    pub fn record_recv(&self, bytes: usize) {
        self.packets_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a send error.
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a receive error.
    pub fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an MTU exceeded rejection.
    pub fn record_mtu_exceeded(&self) {
        self.mtu_exceeded.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful outbound connection.
    pub fn record_connection_established(&self) {
        self.connections_established.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a successful inbound connection.
    pub fn record_connection_accepted(&self) {
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejected inbound connection (pool full).
    pub fn record_connection_rejected(&self) {
        self.connections_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connect timeout.
    pub fn record_connect_timeout(&self) {
        self.connect_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an outbound connect that failed with an error.
    ///
    /// Kept separate from [`Self::record_connect_timeout`]: a refusal and a
    /// silence are different faults and blur into one useless number if
    /// merged.
    pub fn record_connect_error(&self) {
        self.connect_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a failed pre-handshake pubkey exchange.
    ///
    /// The link came up and then produced nothing usable — a different fault
    /// from never connecting at all.
    pub fn record_pubkey_exchange_failure(&self) {
        self.pubkey_exchange_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record an outbound connection stood down by the cross-probe
    /// tie-breaker.
    ///
    /// Read together with [`Self::record_tiebreaker_drop`] across a pair of
    /// nodes: one yield and one drop is the two sides agreeing; two yields or
    /// two drops is the disagreement that leaves no other evidence.
    pub fn record_tiebreaker_yield(&self) {
        self.tiebreaker_yields.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an inbound connection stood down by the cross-probe
    /// tie-breaker. See [`Self::record_tiebreaker_yield`].
    pub fn record_tiebreaker_drop(&self) {
        self.tiebreaker_drops.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a pool eviction (non-static peer displaced).
    pub fn record_pool_eviction(&self) {
        self.pool_evictions.fetch_add(1, Ordering::Relaxed);
    }

    /// Record an advertisement broadcast.
    pub fn record_advertisement(&self) {
        self.advertisements_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a scan result received.
    pub fn record_scan_result(&self) {
        self.scan_results.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection declined as a duplicate of a peer already linked
    /// under a different link address.
    ///
    /// A peer using resolvable private addresses rotates continually, so a
    /// climbing count against a busy mesh is that rotation being absorbed —
    /// not an error.
    pub fn record_duplicate_node_decline(&self) {
        self.duplicate_node_declines.fetch_add(1, Ordering::Relaxed);
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> BleStatsSnapshot {
        BleStatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            mtu_exceeded: self.mtu_exceeded.load(Ordering::Relaxed),
            connections_established: self.connections_established.load(Ordering::Relaxed),
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_rejected: self.connections_rejected.load(Ordering::Relaxed),
            connect_timeouts: self.connect_timeouts.load(Ordering::Relaxed),
            connect_errors: self.connect_errors.load(Ordering::Relaxed),
            pubkey_exchange_failures: self.pubkey_exchange_failures.load(Ordering::Relaxed),
            tiebreaker_yields: self.tiebreaker_yields.load(Ordering::Relaxed),
            tiebreaker_drops: self.tiebreaker_drops.load(Ordering::Relaxed),
            pool_evictions: self.pool_evictions.load(Ordering::Relaxed),
            advertisements_sent: self.advertisements_sent.load(Ordering::Relaxed),
            scan_results: self.scan_results.load(Ordering::Relaxed),
            duplicate_node_declines: self.duplicate_node_declines.load(Ordering::Relaxed),
        }
    }
}

impl Default for BleStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of BLE stats (non-atomic, copyable).
#[derive(Clone, Debug, Default, Serialize)]
pub struct BleStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub mtu_exceeded: u64,
    pub connections_established: u64,
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub connect_timeouts: u64,
    pub connect_errors: u64,
    pub pubkey_exchange_failures: u64,
    pub tiebreaker_yields: u64,
    pub tiebreaker_drops: u64,
    pub pool_evictions: u64,
    pub advertisements_sent: u64,
    pub scan_results: u64,
    pub duplicate_node_declines: u64,
}
