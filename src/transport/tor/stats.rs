//! Tor transport statistics.

use portable_atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::transport::PoolCounters;
use crate::transport::socks5::{ProxiedStats, ProxiedStatsBase};

/// Statistics for a Tor transport instance.
///
/// Uses atomic counters for lock-free updates from per-connection
/// receive loops and the send path concurrently.
pub struct TorStats {
    /// Shared send/receive/connect counters common to proxied transports.
    base: ProxiedStatsBase,
    pub connect_refused: AtomicU64,
    pub connections_accepted: AtomicU64,
    pub connections_rejected: AtomicU64,
    pub control_errors: AtomicU64,
    /// Inbound (accepted via onion service) / outbound (SOCKS5 connect)
    /// connection-pool occupancy. Inbound drives the
    /// `max_inbound_connections` admission check.
    pub pool: PoolCounters,
}

impl TorStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            base: ProxiedStatsBase::new(),
            connect_refused: AtomicU64::new(0),
            connections_accepted: AtomicU64::new(0),
            connections_rejected: AtomicU64::new(0),
            control_errors: AtomicU64::new(0),
            pool: PoolCounters::new(),
        }
    }

    /// Record a successful send.
    pub fn record_send(&self, bytes: usize) {
        self.base.record_send(bytes);
    }

    /// Record a successful receive.
    pub fn record_recv(&self, bytes: usize) {
        self.base.record_recv(bytes);
    }

    /// Record a send error.
    pub fn record_send_error(&self) {
        self.base.record_send_error();
    }

    /// Record a receive error.
    pub fn record_recv_error(&self) {
        self.base.record_recv_error();
    }

    /// Record an MTU exceeded rejection.
    pub fn record_mtu_exceeded(&self) {
        self.base.record_mtu_exceeded();
    }

    /// Record a successful outbound connection.
    pub fn record_connection_established(&self) {
        self.base.record_connection_established();
    }

    /// Record a connect timeout.
    pub fn record_connect_timeout(&self) {
        self.base.record_connect_timeout();
    }

    /// Record a connection refused.
    pub fn record_connect_refused(&self) {
        self.connect_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a SOCKS5 protocol error.
    pub fn record_socks5_error(&self) {
        self.base.record_socks5_error();
    }

    /// Record a successful inbound connection via onion service.
    pub fn record_connection_accepted(&self) {
        self.connections_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a rejected inbound connection (max_inbound limit).
    pub fn record_connection_rejected(&self) {
        self.connections_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a control port error.
    pub fn record_control_error(&self) {
        self.control_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment the inbound pool count (called on accept).
    pub fn record_pool_inbound_added(&self) {
        self.pool.record_inbound_added();
    }

    /// Decrement the inbound pool count (called on inbound receive-loop exit).
    pub fn record_pool_inbound_removed(&self) {
        self.pool.record_inbound_removed();
    }

    /// Increment the outbound pool count (called on SOCKS5-connect promote).
    pub fn record_pool_outbound_added(&self) {
        self.pool.record_outbound_added();
    }

    /// Decrement the outbound pool count (called on outbound receive-loop exit).
    pub fn record_pool_outbound_removed(&self) {
        self.pool.record_outbound_removed();
    }

    /// Load the current inbound pool count for the admission gate.
    pub fn pool_inbound_count(&self) -> u64 {
        self.pool.inbound_count()
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> TorStatsSnapshot {
        TorStatsSnapshot {
            packets_sent: self.base.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.base.bytes_sent.load(Ordering::Relaxed),
            packets_recv: self.base.packets_recv.load(Ordering::Relaxed),
            bytes_recv: self.base.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.base.send_errors.load(Ordering::Relaxed),
            recv_errors: self.base.recv_errors.load(Ordering::Relaxed),
            mtu_exceeded: self.base.mtu_exceeded.load(Ordering::Relaxed),
            connections_established: self.base.connections_established.load(Ordering::Relaxed),
            connect_timeouts: self.base.connect_timeouts.load(Ordering::Relaxed),
            connect_refused: self.connect_refused.load(Ordering::Relaxed),
            socks5_errors: self.base.socks5_errors.load(Ordering::Relaxed),
            connections_accepted: self.connections_accepted.load(Ordering::Relaxed),
            connections_rejected: self.connections_rejected.load(Ordering::Relaxed),
            control_errors: self.control_errors.load(Ordering::Relaxed),
            pool_inbound: self.pool.inbound_count(),
            pool_outbound: self.pool.outbound_count(),
        }
    }
}

impl Default for TorStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxiedStats for TorStats {
    fn record_recv(&self, bytes: usize) {
        self.base.record_recv(bytes);
    }

    fn record_recv_error(&self) {
        self.base.record_recv_error();
    }
}

/// Point-in-time snapshot of Tor stats (non-atomic, copyable).
#[derive(Clone, Debug, Default, Serialize)]
pub struct TorStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub mtu_exceeded: u64,
    pub connections_established: u64,
    pub connect_timeouts: u64,
    pub connect_refused: u64,
    pub socks5_errors: u64,
    pub connections_accepted: u64,
    pub connections_rejected: u64,
    pub control_errors: u64,
    pub pool_inbound: u64,
    pub pool_outbound: u64,
}
