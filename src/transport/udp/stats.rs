//! UDP transport statistics.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Statistics for a UDP transport instance.
///
/// Uses atomic counters for lock-free updates from the receive loop
/// and send path concurrently.
pub struct UdpStats {
    pub packets_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub packets_recv: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub send_errors: AtomicU64,
    pub recv_errors: AtomicU64,
    pub mtu_exceeded: AtomicU64,
    pub kernel_drops: AtomicU64,
}

impl UdpStats {
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
            kernel_drops: AtomicU64::new(0),
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

    /// Update kernel drop count from SO_MEMINFO.
    ///
    /// Not yet wired up — requires `getsockopt(SO_MEMINFO)` on the raw fd
    /// (via socket2 or libc) to read `SK_MEMINFO_DROPS`. Linux-only.
    /// Until implemented, this counter will always be zero.
    pub fn set_kernel_drops(&self, drops: u64) {
        self.kernel_drops.store(drops, Ordering::Relaxed);
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> UdpStatsSnapshot {
        UdpStatsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_recv: self.packets_recv.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            mtu_exceeded: self.mtu_exceeded.load(Ordering::Relaxed),
            kernel_drops: self.kernel_drops.load(Ordering::Relaxed),
        }
    }
}

impl Default for UdpStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of UDP stats (non-atomic, copyable).
#[derive(Clone, Debug, Default, Serialize)]
pub struct UdpStatsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub mtu_exceeded: u64,
    pub kernel_drops: u64,
}
