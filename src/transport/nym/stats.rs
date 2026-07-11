//! Nym transport statistics.

use portable_atomic::Ordering;

use serde::Serialize;

use crate::transport::socks5::{ProxiedStats, ProxiedStatsBase};

/// Statistics for a Nym transport instance.
///
/// Uses atomic counters for lock-free updates from per-connection
/// receive loops and the send path concurrently.
pub struct NymStats {
    /// Shared send/receive/connect counters common to proxied transports.
    base: ProxiedStatsBase,
}

impl NymStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            base: ProxiedStatsBase::new(),
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

    /// Record a SOCKS5 protocol error.
    pub fn record_socks5_error(&self) {
        self.base.record_socks5_error();
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> NymStatsSnapshot {
        NymStatsSnapshot {
            packets_sent: self.base.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.base.bytes_sent.load(Ordering::Relaxed),
            packets_recv: self.base.packets_recv.load(Ordering::Relaxed),
            bytes_recv: self.base.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.base.send_errors.load(Ordering::Relaxed),
            recv_errors: self.base.recv_errors.load(Ordering::Relaxed),
            mtu_exceeded: self.base.mtu_exceeded.load(Ordering::Relaxed),
            connections_established: self.base.connections_established.load(Ordering::Relaxed),
            connect_timeouts: self.base.connect_timeouts.load(Ordering::Relaxed),
            socks5_errors: self.base.socks5_errors.load(Ordering::Relaxed),
        }
    }
}

impl Default for NymStats {
    fn default() -> Self {
        Self::new()
    }
}

impl ProxiedStats for NymStats {
    fn record_recv(&self, bytes: usize) {
        self.base.record_recv(bytes);
    }

    fn record_recv_error(&self) {
        self.base.record_recv_error();
    }
}

/// Point-in-time snapshot of Nym stats (non-atomic, copyable).
#[derive(Clone, Debug, Default, Serialize)]
pub struct NymStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub mtu_exceeded: u64,
    pub connections_established: u64,
    pub connect_timeouts: u64,
    pub socks5_errors: u64,
}
