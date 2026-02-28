//! TCP transport statistics.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Statistics for a TCP transport instance.
///
/// Uses atomic counters for lock-free updates from per-connection
/// receive loops and the send path concurrently.
pub struct TcpStats {
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
    pub connect_refused: AtomicU64,
}

impl TcpStats {
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
            connect_refused: AtomicU64::new(0),
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

    /// Record a rejected inbound connection.
    pub fn record_connection_rejected(&self) {
        self.connections_rejected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connect timeout.
    pub fn record_connect_timeout(&self) {
        self.connect_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a connection refused.
    pub fn record_connect_refused(&self) {
        self.connect_refused.fetch_add(1, Ordering::Relaxed);
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> TcpStatsSnapshot {
        TcpStatsSnapshot {
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
            connect_refused: self.connect_refused.load(Ordering::Relaxed),
        }
    }
}

impl Default for TcpStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of TCP stats (non-atomic, copyable).
#[derive(Clone, Debug, Default, Serialize)]
pub struct TcpStatsSnapshot {
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
    pub connect_refused: u64,
}
