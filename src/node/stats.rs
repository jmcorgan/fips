//! Node-level statistics for routing, forwarding, and discovery operations.
//!
//! Unlike `EthernetStats` (which uses `AtomicU64` + `Arc` for cross-task
//! sharing), these counters use plain `u64` because `Node` handlers run
//! on a single `&mut self` context. A `snapshot()` method produces a
//! copyable struct for control socket queries.

use serde::Serialize;

/// Forwarding statistics — packets and bytes for each outcome.
#[derive(Default)]
pub struct ForwardingStats {
    pub received_packets: u64,
    pub received_bytes: u64,
    pub decode_error_packets: u64,
    pub decode_error_bytes: u64,
    pub ttl_exhausted_packets: u64,
    pub ttl_exhausted_bytes: u64,
    pub delivered_packets: u64,
    pub delivered_bytes: u64,
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub drop_no_route_packets: u64,
    pub drop_no_route_bytes: u64,
    pub drop_mtu_exceeded_packets: u64,
    pub drop_mtu_exceeded_bytes: u64,
    pub drop_send_error_packets: u64,
    pub drop_send_error_bytes: u64,
    pub originated_packets: u64,
    pub originated_bytes: u64,
}

impl ForwardingStats {
    pub fn record_received(&mut self, bytes: usize) {
        self.received_packets += 1;
        self.received_bytes += bytes as u64;
    }

    pub fn record_decode_error(&mut self, bytes: usize) {
        self.decode_error_packets += 1;
        self.decode_error_bytes += bytes as u64;
    }

    pub fn record_ttl_exhausted(&mut self, bytes: usize) {
        self.ttl_exhausted_packets += 1;
        self.ttl_exhausted_bytes += bytes as u64;
    }

    pub fn record_delivered(&mut self, bytes: usize) {
        self.delivered_packets += 1;
        self.delivered_bytes += bytes as u64;
    }

    pub fn record_forwarded(&mut self, bytes: usize) {
        self.forwarded_packets += 1;
        self.forwarded_bytes += bytes as u64;
    }

    pub fn record_drop_no_route(&mut self, bytes: usize) {
        self.drop_no_route_packets += 1;
        self.drop_no_route_bytes += bytes as u64;
    }

    pub fn record_drop_mtu_exceeded(&mut self, bytes: usize) {
        self.drop_mtu_exceeded_packets += 1;
        self.drop_mtu_exceeded_bytes += bytes as u64;
    }

    pub fn record_drop_send_error(&mut self, bytes: usize) {
        self.drop_send_error_packets += 1;
        self.drop_send_error_bytes += bytes as u64;
    }

    pub fn record_originated(&mut self, bytes: usize) {
        self.originated_packets += 1;
        self.originated_bytes += bytes as u64;
    }

    pub fn snapshot(&self) -> ForwardingStatsSnapshot {
        ForwardingStatsSnapshot {
            received_packets: self.received_packets,
            received_bytes: self.received_bytes,
            decode_error_packets: self.decode_error_packets,
            decode_error_bytes: self.decode_error_bytes,
            ttl_exhausted_packets: self.ttl_exhausted_packets,
            ttl_exhausted_bytes: self.ttl_exhausted_bytes,
            delivered_packets: self.delivered_packets,
            delivered_bytes: self.delivered_bytes,
            forwarded_packets: self.forwarded_packets,
            forwarded_bytes: self.forwarded_bytes,
            drop_no_route_packets: self.drop_no_route_packets,
            drop_no_route_bytes: self.drop_no_route_bytes,
            drop_mtu_exceeded_packets: self.drop_mtu_exceeded_packets,
            drop_mtu_exceeded_bytes: self.drop_mtu_exceeded_bytes,
            drop_send_error_packets: self.drop_send_error_packets,
            drop_send_error_bytes: self.drop_send_error_bytes,
            originated_packets: self.originated_packets,
            originated_bytes: self.originated_bytes,
        }
    }
}

/// Discovery statistics — packet counts for request and response handling.
#[derive(Default)]
pub struct DiscoveryStats {
    // Request counters
    pub req_received: u64,
    pub req_decode_error: u64,
    pub req_duplicate: u64,
    pub req_already_visited: u64,
    pub req_target_is_us: u64,
    pub req_forwarded: u64,
    pub req_ttl_exhausted: u64,
    pub req_initiated: u64,
    pub req_deduplicated: u64,
    // Response counters
    pub resp_received: u64,
    pub resp_decode_error: u64,
    pub resp_forwarded: u64,
    pub resp_identity_miss: u64,
    pub resp_proof_failed: u64,
    pub resp_accepted: u64,
    pub resp_timed_out: u64,
}

impl DiscoveryStats {
    pub fn snapshot(&self) -> DiscoveryStatsSnapshot {
        DiscoveryStatsSnapshot {
            req_received: self.req_received,
            req_decode_error: self.req_decode_error,
            req_duplicate: self.req_duplicate,
            req_already_visited: self.req_already_visited,
            req_target_is_us: self.req_target_is_us,
            req_forwarded: self.req_forwarded,
            req_ttl_exhausted: self.req_ttl_exhausted,
            req_initiated: self.req_initiated,
            req_deduplicated: self.req_deduplicated,
            resp_received: self.resp_received,
            resp_decode_error: self.resp_decode_error,
            resp_forwarded: self.resp_forwarded,
            resp_identity_miss: self.resp_identity_miss,
            resp_proof_failed: self.resp_proof_failed,
            resp_accepted: self.resp_accepted,
            resp_timed_out: self.resp_timed_out,
        }
    }
}

/// Spanning tree statistics — announce handling and parent tracking.
#[derive(Default)]
pub struct TreeStats {
    // Inbound announce handling
    pub received: u64,
    pub decode_error: u64,
    pub unknown_peer: u64,
    pub addr_mismatch: u64,
    pub sig_failed: u64,
    pub stale: u64,
    pub accepted: u64,
    pub parent_switched: u64,
    pub loop_detected: u64,
    pub ancestry_changed: u64,
    // Outbound announce sending
    pub sent: u64,
    pub rate_limited: u64,
    pub send_failed: u64,
    // Cumulative events
    pub parent_switches: u64,
    pub parent_losses: u64,
    pub flap_dampened: u64,
}

impl TreeStats {
    pub fn snapshot(&self) -> TreeStatsSnapshot {
        TreeStatsSnapshot {
            received: self.received,
            decode_error: self.decode_error,
            unknown_peer: self.unknown_peer,
            addr_mismatch: self.addr_mismatch,
            sig_failed: self.sig_failed,
            stale: self.stale,
            accepted: self.accepted,
            parent_switched: self.parent_switched,
            loop_detected: self.loop_detected,
            ancestry_changed: self.ancestry_changed,
            sent: self.sent,
            rate_limited: self.rate_limited,
            send_failed: self.send_failed,
            parent_switches: self.parent_switches,
            parent_losses: self.parent_losses,
            flap_dampened: self.flap_dampened,
        }
    }
}

/// Bloom filter statistics — filter announce handling.
#[derive(Default)]
pub struct BloomStats {
    // Inbound announce handling
    pub received: u64,
    pub decode_error: u64,
    pub invalid: u64,
    pub non_v1: u64,
    pub unknown_peer: u64,
    pub stale: u64,
    pub accepted: u64,
    // Outbound announce sending
    pub sent: u64,
    pub debounce_suppressed: u64,
    pub send_failed: u64,
}

impl BloomStats {
    pub fn snapshot(&self) -> BloomStatsSnapshot {
        BloomStatsSnapshot {
            received: self.received,
            decode_error: self.decode_error,
            invalid: self.invalid,
            non_v1: self.non_v1,
            unknown_peer: self.unknown_peer,
            stale: self.stale,
            accepted: self.accepted,
            sent: self.sent,
            debounce_suppressed: self.debounce_suppressed,
            send_failed: self.send_failed,
        }
    }
}

/// Error signal statistics — counts of each error signal type received.
#[derive(Default)]
pub struct ErrorSignalStats {
    pub coords_required: u64,
    pub path_broken: u64,
    pub mtu_exceeded: u64,
}

impl ErrorSignalStats {
    pub fn snapshot(&self) -> ErrorSignalStatsSnapshot {
        ErrorSignalStatsSnapshot {
            coords_required: self.coords_required,
            path_broken: self.path_broken,
            mtu_exceeded: self.mtu_exceeded,
        }
    }
}

/// Aggregate node statistics.
#[derive(Default)]
pub struct NodeStats {
    pub forwarding: ForwardingStats,
    pub discovery: DiscoveryStats,
    pub tree: TreeStats,
    pub bloom: BloomStats,
    pub errors: ErrorSignalStats,
}

impl NodeStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> NodeStatsSnapshot {
        NodeStatsSnapshot {
            forwarding: self.forwarding.snapshot(),
            discovery: self.discovery.snapshot(),
            tree: self.tree.snapshot(),
            bloom: self.bloom.snapshot(),
            errors: self.errors.snapshot(),
        }
    }
}

// --- Snapshot types (copyable, serializable) ---

#[derive(Clone, Debug, Default, Serialize)]
pub struct ForwardingStatsSnapshot {
    pub received_packets: u64,
    pub received_bytes: u64,
    pub decode_error_packets: u64,
    pub decode_error_bytes: u64,
    pub ttl_exhausted_packets: u64,
    pub ttl_exhausted_bytes: u64,
    pub delivered_packets: u64,
    pub delivered_bytes: u64,
    pub forwarded_packets: u64,
    pub forwarded_bytes: u64,
    pub drop_no_route_packets: u64,
    pub drop_no_route_bytes: u64,
    pub drop_mtu_exceeded_packets: u64,
    pub drop_mtu_exceeded_bytes: u64,
    pub drop_send_error_packets: u64,
    pub drop_send_error_bytes: u64,
    pub originated_packets: u64,
    pub originated_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiscoveryStatsSnapshot {
    pub req_received: u64,
    pub req_decode_error: u64,
    pub req_duplicate: u64,
    pub req_already_visited: u64,
    pub req_target_is_us: u64,
    pub req_forwarded: u64,
    pub req_ttl_exhausted: u64,
    pub req_initiated: u64,
    pub req_deduplicated: u64,
    pub resp_received: u64,
    pub resp_decode_error: u64,
    pub resp_forwarded: u64,
    pub resp_identity_miss: u64,
    pub resp_proof_failed: u64,
    pub resp_accepted: u64,
    pub resp_timed_out: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TreeStatsSnapshot {
    pub received: u64,
    pub decode_error: u64,
    pub unknown_peer: u64,
    pub addr_mismatch: u64,
    pub sig_failed: u64,
    pub stale: u64,
    pub accepted: u64,
    pub parent_switched: u64,
    pub loop_detected: u64,
    pub ancestry_changed: u64,
    pub sent: u64,
    pub rate_limited: u64,
    pub send_failed: u64,
    pub parent_switches: u64,
    pub parent_losses: u64,
    pub flap_dampened: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct BloomStatsSnapshot {
    pub received: u64,
    pub decode_error: u64,
    pub invalid: u64,
    pub non_v1: u64,
    pub unknown_peer: u64,
    pub stale: u64,
    pub accepted: u64,
    pub sent: u64,
    pub debounce_suppressed: u64,
    pub send_failed: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ErrorSignalStatsSnapshot {
    pub coords_required: u64,
    pub path_broken: u64,
    pub mtu_exceeded: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct NodeStatsSnapshot {
    pub forwarding: ForwardingStatsSnapshot,
    pub discovery: DiscoveryStatsSnapshot,
    pub tree: TreeStatsSnapshot,
    pub bloom: BloomStatsSnapshot,
    pub errors: ErrorSignalStatsSnapshot,
}
