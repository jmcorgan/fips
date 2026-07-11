//! Statistics helpers shared across transports.
//!
//! Counter logic that is identical across multiple transports lives here
//! rather than being copied into each transport's `stats.rs`.

use portable_atomic::{AtomicU64, Ordering};

/// Inbound/outbound connection-pool occupancy counters.
///
/// The connection-oriented transports (TCP, Tor) each track how many inbound
/// and outbound connections are currently held in their pool; the inbound
/// count drives the `max_inbound_connections` admission gate. The counter
/// logic is identical, so it is defined once here and embedded in each
/// transport's stats struct.
#[derive(Default)]
pub struct PoolCounters {
    inbound: AtomicU64,
    outbound: AtomicU64,
}

impl PoolCounters {
    /// Create counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment the inbound pool count (called on accept).
    pub fn record_inbound_added(&self) {
        self.inbound.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the inbound pool count (called on inbound receive-loop exit).
    pub fn record_inbound_removed(&self) {
        self.inbound.fetch_sub(1, Ordering::Relaxed);
    }

    /// Increment the outbound pool count (called on connect-on-send / promote).
    pub fn record_outbound_added(&self) {
        self.outbound.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the outbound pool count (called on outbound receive-loop exit).
    pub fn record_outbound_removed(&self) {
        self.outbound.fetch_sub(1, Ordering::Relaxed);
    }

    /// Load the current inbound pool count for the admission gate.
    pub fn inbound_count(&self) -> u64 {
        self.inbound.load(Ordering::Relaxed)
    }

    /// Load the current outbound pool count.
    pub fn outbound_count(&self) -> u64 {
        self.outbound.load(Ordering::Relaxed)
    }
}
