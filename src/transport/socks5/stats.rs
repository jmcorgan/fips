//! Shared atomic counter base for the proxied (Tor / Nym) transports.
//!
//! The two SOCKS5-proxied transports share an identical set of ten
//! send/receive/connect counters. That counter logic is defined once here and
//! embedded as `base` in each transport's stats struct; the transport-specific
//! counters (tor's refused/accepted/rejected/control + pool occupancy) stay in
//! the per-transport struct. The flat per-transport snapshot structs are left
//! unchanged so the emitted metric JSON is byte-identical.

use portable_atomic::{AtomicU64, Ordering};

/// Atomic counters common to every SOCKS5-proxied transport.
pub(crate) struct ProxiedStatsBase {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub send_errors: AtomicU64,
    pub recv_errors: AtomicU64,
    pub mtu_exceeded: AtomicU64,
    pub connections_established: AtomicU64,
    pub connect_timeouts: AtomicU64,
    pub socks5_errors: AtomicU64,
}

impl ProxiedStatsBase {
    /// Create a base with all counters at zero.
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
            connect_timeouts: AtomicU64::new(0),
            socks5_errors: AtomicU64::new(0),
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

    /// Record a connect timeout.
    pub fn record_connect_timeout(&self) {
        self.connect_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a SOCKS5 protocol error.
    pub fn record_socks5_error(&self) {
        self.socks5_errors.fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for ProxiedStatsBase {
    fn default() -> Self {
        Self::new()
    }
}
