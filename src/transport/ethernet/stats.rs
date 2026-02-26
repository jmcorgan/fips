//! Ethernet transport statistics.

use std::sync::atomic::{AtomicU64, Ordering};

/// Statistics for an Ethernet transport instance.
///
/// Uses atomic counters for lock-free updates from the receive loop
/// and send path concurrently.
pub struct EthernetStats {
    pub frames_sent: AtomicU64,
    pub frames_recv: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub send_errors: AtomicU64,
    pub recv_errors: AtomicU64,
    pub beacons_sent: AtomicU64,
    pub beacons_recv: AtomicU64,
    pub frames_too_short: AtomicU64,
    pub frames_too_long: AtomicU64,
}

impl EthernetStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            frames_sent: AtomicU64::new(0),
            frames_recv: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
            beacons_sent: AtomicU64::new(0),
            beacons_recv: AtomicU64::new(0),
            frames_too_short: AtomicU64::new(0),
            frames_too_long: AtomicU64::new(0),
        }
    }

    /// Record a successful send.
    pub fn record_send(&self, bytes: usize) {
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a successful receive.
    pub fn record_recv(&self, bytes: usize) {
        self.frames_recv.fetch_add(1, Ordering::Relaxed);
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

    /// Record a sent beacon.
    pub fn record_beacon_sent(&self) {
        self.beacons_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a received beacon.
    pub fn record_beacon_recv(&self) {
        self.beacons_recv.fetch_add(1, Ordering::Relaxed);
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> EthernetStatsSnapshot {
        EthernetStatsSnapshot {
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_recv: self.frames_recv.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            beacons_sent: self.beacons_sent.load(Ordering::Relaxed),
            beacons_recv: self.beacons_recv.load(Ordering::Relaxed),
            frames_too_short: self.frames_too_short.load(Ordering::Relaxed),
            frames_too_long: self.frames_too_long.load(Ordering::Relaxed),
        }
    }
}

impl Default for EthernetStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of Ethernet stats (non-atomic, copyable).
#[derive(Clone, Debug, Default)]
pub struct EthernetStatsSnapshot {
    pub frames_sent: u64,
    pub frames_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub beacons_sent: u64,
    pub beacons_recv: u64,
    pub frames_too_short: u64,
    pub frames_too_long: u64,
}
