//! Lock-free metric counters backed by atomics.
//!
//! Mirrors the `NodeStats` counter surface (`stats.rs`) but stores each
//! counter in an `AtomicU64`, so it can be bumped through `&self` and, in
//! a later step, sampled without dispatching through the rx_loop task. The
//! hottest counters are cache-line padded to avoid false sharing once
//! reads move off-thread.
//!
//! The forwarding, discovery, tree, bloom, congestion, and error families
//! live here exclusively and are both written and served from the registry.
//! The remaining families (session, handshake, mmp, transport) stay on
//! `NodeStats`.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::node::reject::{BloomReject, DiscoveryReject, ForwardingReject, TreeReject};
use crate::node::stats::{
    BloomStatsSnapshot, CongestionStatsSnapshot, ErrorSignalStatsSnapshot, ForwardingStatsSnapshot,
    LookupStatsSnapshot, TreeStatsSnapshot,
};

/// An atomic counter.
#[derive(Default)]
pub struct Counter(AtomicU64);

impl Counter {
    #[inline]
    pub fn inc(&self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn add(&self, n: u64) {
        self.0.fetch_add(n, Ordering::Relaxed);
    }

    #[inline]
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Cache-line padding wrapper for the hottest counters.
///
/// Padding keeps a hot counter off shared cache lines so that concurrent
/// reads (introduced when metric sampling moves off the rx_loop task) do
/// not false-share with the writer. With a single writer today the padding
/// is forward-looking insurance. Derefs to the inner counter so the call
/// sites are identical to an unpadded one.
#[repr(align(64))]
#[derive(Default)]
pub struct Padded<T>(pub T);

impl<T> std::ops::Deref for Padded<T> {
    type Target = T;

    #[inline]
    fn deref(&self) -> &T {
        &self.0
    }
}

/// Forwarding metric counters.
#[derive(Default)]
pub struct ForwardingMetrics {
    pub received_packets: Padded<Counter>,
    pub received_bytes: Counter,
    pub decode_error_packets: Counter,
    pub decode_error_bytes: Counter,
    pub ttl_exhausted_packets: Counter,
    pub ttl_exhausted_bytes: Counter,
    pub delivered_packets: Counter,
    pub delivered_bytes: Counter,
    pub forwarded_packets: Counter,
    pub forwarded_bytes: Counter,
    pub drop_no_route_packets: Counter,
    pub drop_no_route_bytes: Counter,
    pub drop_mtu_exceeded_packets: Counter,
    pub drop_mtu_exceeded_bytes: Counter,
    pub drop_send_error_packets: Counter,
    pub drop_send_error_bytes: Counter,
    pub originated_packets: Counter,
    pub originated_bytes: Counter,
    pub route_tree_up: Counter,
    pub route_tree_down: Counter,
    pub route_tree_down_cross: Counter,
    pub route_crosslink_descend: Counter,
    pub route_crosslink_ascend: Counter,
    pub route_direct_peer: Counter,
}

/// Route class of a transit-forwarded packet, classified from tree
/// coordinates at the forwarding decision point. Defined by the sans-IO
/// routing core and re-exported here for the forwarding-metrics counters
/// ([`ForwardingMetrics::record_route_class`]).
pub(crate) use crate::proto::routing::RouteClass;

impl ForwardingMetrics {
    /// Record a received packet of `bytes` payload (packets and bytes).
    #[inline]
    pub fn record_received(&self, bytes: usize) {
        self.received_packets.inc();
        self.received_bytes.add(bytes as u64);
    }

    /// Record a locally-delivered packet of `bytes` payload.
    #[inline]
    pub fn record_delivered(&self, bytes: usize) {
        self.delivered_packets.inc();
        self.delivered_bytes.add(bytes as u64);
    }

    /// Record a forwarded (transit) packet of `bytes` payload.
    #[inline]
    pub fn record_forwarded(&self, bytes: usize) {
        self.forwarded_packets.inc();
        self.forwarded_bytes.add(bytes as u64);
    }

    /// Record a locally-originated packet of `bytes` payload.
    #[inline]
    pub fn record_originated(&self, bytes: usize) {
        self.originated_packets.inc();
        self.originated_bytes.add(bytes as u64);
    }

    /// Record the route class of a transit-forwarded packet. The five
    /// classes partition `forwarded_packets`, so this is called exactly
    /// once per `record_forwarded` (transit chokepoint only).
    #[inline]
    pub fn record_route_class(&self, class: RouteClass) {
        match class {
            RouteClass::TreeUp => self.route_tree_up.inc(),
            RouteClass::TreeDown => self.route_tree_down.inc(),
            RouteClass::TreeDownCross => self.route_tree_down_cross.inc(),
            RouteClass::CrosslinkDescend => self.route_crosslink_descend.inc(),
            RouteClass::CrosslinkAscend => self.route_crosslink_ascend.inc(),
            RouteClass::DirectPeer => self.route_direct_peer.inc(),
        }
    }

    /// Mirror of `ForwardingStats::record_reject_bytes`: route a typed
    /// forwarding rejection of `bytes` payload to its packet and byte
    /// counters.
    #[inline]
    pub fn record_reject_bytes(&self, reason: ForwardingReject, bytes: usize) {
        let bytes = bytes as u64;
        match reason {
            ForwardingReject::DecodeError => {
                self.decode_error_packets.inc();
                self.decode_error_bytes.add(bytes);
            }
            ForwardingReject::TtlExhausted => {
                self.ttl_exhausted_packets.inc();
                self.ttl_exhausted_bytes.add(bytes);
            }
            ForwardingReject::NoRoute => {
                self.drop_no_route_packets.inc();
                self.drop_no_route_bytes.add(bytes);
            }
            ForwardingReject::MtuExceeded => {
                self.drop_mtu_exceeded_packets.inc();
                self.drop_mtu_exceeded_bytes.add(bytes);
            }
            ForwardingReject::SendError => {
                self.drop_send_error_packets.inc();
                self.drop_send_error_bytes.add(bytes);
            }
        }
    }

    /// Sample every counter into a serializable snapshot.
    pub fn snapshot(&self) -> ForwardingStatsSnapshot {
        ForwardingStatsSnapshot {
            received_packets: self.received_packets.get(),
            received_bytes: self.received_bytes.get(),
            decode_error_packets: self.decode_error_packets.get(),
            decode_error_bytes: self.decode_error_bytes.get(),
            ttl_exhausted_packets: self.ttl_exhausted_packets.get(),
            ttl_exhausted_bytes: self.ttl_exhausted_bytes.get(),
            delivered_packets: self.delivered_packets.get(),
            delivered_bytes: self.delivered_bytes.get(),
            forwarded_packets: self.forwarded_packets.get(),
            forwarded_bytes: self.forwarded_bytes.get(),
            drop_no_route_packets: self.drop_no_route_packets.get(),
            drop_no_route_bytes: self.drop_no_route_bytes.get(),
            drop_mtu_exceeded_packets: self.drop_mtu_exceeded_packets.get(),
            drop_mtu_exceeded_bytes: self.drop_mtu_exceeded_bytes.get(),
            drop_send_error_packets: self.drop_send_error_packets.get(),
            drop_send_error_bytes: self.drop_send_error_bytes.get(),
            originated_packets: self.originated_packets.get(),
            originated_bytes: self.originated_bytes.get(),
            route_tree_up: self.route_tree_up.get(),
            route_tree_down: self.route_tree_down.get(),
            route_tree_down_cross: self.route_tree_down_cross.get(),
            route_crosslink_descend: self.route_crosslink_descend.get(),
            route_crosslink_ascend: self.route_crosslink_ascend.get(),
            route_direct_peer: self.route_direct_peer.get(),
        }
    }
}

/// Discovery metric counters.
#[derive(Default)]
pub struct LookupMetrics {
    pub req_received: Padded<Counter>,
    pub req_decode_error: Counter,
    pub req_duplicate: Counter,
    pub req_dedup_cache_full: Counter,
    pub req_target_is_us: Counter,
    pub req_forwarded: Counter,
    pub req_ttl_exhausted: Counter,
    pub req_initiated: Counter,
    pub req_deduplicated: Counter,
    pub req_backoff_suppressed: Counter,
    pub req_forward_rate_limited: Counter,
    pub req_bloom_miss: Counter,
    pub req_no_tree_peer: Counter,
    pub req_fallback_forwarded: Counter,
    pub resp_received: Counter,
    pub resp_decode_error: Counter,
    pub resp_forwarded: Counter,
    pub resp_identity_miss: Counter,
    pub resp_proof_failed: Counter,
    pub resp_no_route: Counter,
    pub resp_accepted: Counter,
    pub resp_timed_out: Counter,
}

impl LookupMetrics {
    /// Mirror of `DiscoveryStats::record_reject`: route a typed discovery
    /// rejection to its counter.
    #[inline]
    pub fn record_reject(&self, reason: DiscoveryReject) {
        match reason {
            DiscoveryReject::ReqDecodeError => self.req_decode_error.inc(),
            DiscoveryReject::ReqDuplicate => self.req_duplicate.inc(),
            DiscoveryReject::ReqDedupCacheFull => self.req_dedup_cache_full.inc(),
            DiscoveryReject::ReqTtlExhausted => self.req_ttl_exhausted.inc(),
            DiscoveryReject::RespDecodeError => self.resp_decode_error.inc(),
            DiscoveryReject::RespIdentityMiss => self.resp_identity_miss.inc(),
            DiscoveryReject::RespProofFailed => self.resp_proof_failed.inc(),
            DiscoveryReject::RespNoRoute => self.resp_no_route.inc(),
        }
    }

    /// Sample every counter into a serializable snapshot.
    pub fn snapshot(&self) -> LookupStatsSnapshot {
        LookupStatsSnapshot {
            req_received: self.req_received.get(),
            req_decode_error: self.req_decode_error.get(),
            req_duplicate: self.req_duplicate.get(),
            req_dedup_cache_full: self.req_dedup_cache_full.get(),
            req_target_is_us: self.req_target_is_us.get(),
            req_forwarded: self.req_forwarded.get(),
            req_ttl_exhausted: self.req_ttl_exhausted.get(),
            req_initiated: self.req_initiated.get(),
            req_deduplicated: self.req_deduplicated.get(),
            req_backoff_suppressed: self.req_backoff_suppressed.get(),
            req_forward_rate_limited: self.req_forward_rate_limited.get(),
            req_bloom_miss: self.req_bloom_miss.get(),
            req_no_tree_peer: self.req_no_tree_peer.get(),
            req_fallback_forwarded: self.req_fallback_forwarded.get(),
            resp_received: self.resp_received.get(),
            resp_decode_error: self.resp_decode_error.get(),
            resp_forwarded: self.resp_forwarded.get(),
            resp_identity_miss: self.resp_identity_miss.get(),
            resp_proof_failed: self.resp_proof_failed.get(),
            resp_no_route: self.resp_no_route.get(),
            resp_accepted: self.resp_accepted.get(),
            resp_timed_out: self.resp_timed_out.get(),
        }
    }
}

/// Spanning-tree metric counters.
#[derive(Default)]
pub struct TreeMetrics {
    pub received: Counter,
    pub decode_error: Counter,
    pub unknown_peer: Counter,
    pub addr_mismatch: Counter,
    pub sig_failed: Counter,
    pub stale: Counter,
    pub ancestry_invalid: Counter,
    pub accepted: Counter,
    pub parent_switched: Counter,
    pub loop_detected: Counter,
    pub ancestry_changed: Counter,
    pub sent: Counter,
    pub rate_limited: Counter,
    pub send_failed: Counter,
    pub outbound_sign_failed: Counter,
    pub parent_switches: Counter,
    pub parent_losses: Counter,
    pub flap_dampened: Counter,
}

impl TreeMetrics {
    /// Mirror of `TreeStats::record_reject`: route a typed tree
    /// rejection to its counter.
    #[inline]
    pub fn record_reject(&self, reason: TreeReject) {
        match reason {
            TreeReject::AncestryInvalid => self.ancestry_invalid.inc(),
            TreeReject::OutboundSignFailed => self.outbound_sign_failed.inc(),
        }
    }

    /// Sample every counter into a serializable snapshot.
    pub fn snapshot(&self) -> TreeStatsSnapshot {
        TreeStatsSnapshot {
            received: self.received.get(),
            decode_error: self.decode_error.get(),
            unknown_peer: self.unknown_peer.get(),
            addr_mismatch: self.addr_mismatch.get(),
            sig_failed: self.sig_failed.get(),
            stale: self.stale.get(),
            ancestry_invalid: self.ancestry_invalid.get(),
            accepted: self.accepted.get(),
            parent_switched: self.parent_switched.get(),
            loop_detected: self.loop_detected.get(),
            ancestry_changed: self.ancestry_changed.get(),
            sent: self.sent.get(),
            rate_limited: self.rate_limited.get(),
            send_failed: self.send_failed.get(),
            outbound_sign_failed: self.outbound_sign_failed.get(),
            parent_switches: self.parent_switches.get(),
            parent_losses: self.parent_losses.get(),
            flap_dampened: self.flap_dampened.get(),
        }
    }
}

/// Bloom-filter metric counters.
#[derive(Default)]
pub struct BloomMetrics {
    pub received: Counter,
    pub decode_error: Counter,
    pub invalid: Counter,
    pub non_v1: Counter,
    pub unknown_peer: Counter,
    pub stale: Counter,
    pub fill_exceeded: Counter,
    pub accepted: Counter,
    pub sent: Counter,
    pub debounce_suppressed: Counter,
    pub send_failed: Counter,
    // Delta compression
    pub deltas_sent: Counter,
    pub full_sends: Counter,
    pub nacks_sent: Counter,
    pub nacks_received: Counter,
    // Adaptive sizing
    pub size_changes: Counter,
    // Compression tracking
    pub total_compressed_bytes: Counter,
    pub total_raw_bytes: Counter,
}

impl BloomMetrics {
    /// Mirror of `BloomStats::record_reject`: route a typed bloom
    /// rejection to its counter.
    #[inline]
    pub fn record_reject(&self, reason: BloomReject) {
        match reason {
            BloomReject::DecodeError => self.decode_error.inc(),
            BloomReject::Invalid => self.invalid.inc(),
            BloomReject::NonV1 => self.non_v1.inc(),
            BloomReject::UnknownPeer => self.unknown_peer.inc(),
            BloomReject::Stale => self.stale.inc(),
            BloomReject::FillExceeded => self.fill_exceeded.inc(),
        }
    }

    /// Sample every counter into a serializable snapshot.
    pub fn snapshot(&self) -> BloomStatsSnapshot {
        BloomStatsSnapshot {
            received: self.received.get(),
            decode_error: self.decode_error.get(),
            invalid: self.invalid.get(),
            non_v1: self.non_v1.get(),
            unknown_peer: self.unknown_peer.get(),
            stale: self.stale.get(),
            fill_exceeded: self.fill_exceeded.get(),
            accepted: self.accepted.get(),
            sent: self.sent.get(),
            debounce_suppressed: self.debounce_suppressed.get(),
            send_failed: self.send_failed.get(),
            deltas_sent: self.deltas_sent.get(),
            full_sends: self.full_sends.get(),
            nacks_sent: self.nacks_sent.get(),
            nacks_received: self.nacks_received.get(),
            size_changes: self.size_changes.get(),
            total_compressed_bytes: self.total_compressed_bytes.get(),
            total_raw_bytes: self.total_raw_bytes.get(),
        }
    }
}

/// Congestion metric counters.
#[derive(Default)]
pub struct CongestionMetrics {
    pub ce_forwarded: Counter,
    pub ce_received: Counter,
    pub congestion_detected: Counter,
    pub kernel_drop_events: Counter,
}

impl CongestionMetrics {
    /// Sample every counter into a serializable snapshot.
    pub fn snapshot(&self) -> CongestionStatsSnapshot {
        CongestionStatsSnapshot {
            ce_forwarded: self.ce_forwarded.get(),
            ce_received: self.ce_received.get(),
            congestion_detected: self.congestion_detected.get(),
            kernel_drop_events: self.kernel_drop_events.get(),
        }
    }
}

/// Error-signal metric counters.
#[derive(Default)]
pub struct ErrorMetrics {
    pub coords_required: Counter,
    pub path_broken: Counter,
    pub mtu_exceeded: Counter,
}

impl ErrorMetrics {
    /// Sample every counter into a serializable snapshot.
    pub fn snapshot(&self) -> ErrorSignalStatsSnapshot {
        ErrorSignalStatsSnapshot {
            coords_required: self.coords_required.get(),
            path_broken: self.path_broken.get(),
            mtu_exceeded: self.mtu_exceeded.get(),
        }
    }
}

/// Atomic counter registry shared across the node via `Arc`.
///
/// Sole storage for the forwarding, discovery, tree, bloom, congestion,
/// and error counter families; these were migrated off `NodeStats`, which
/// now holds only the session, handshake, mmp, and transport families.
#[derive(Default)]
pub struct MetricsRegistry {
    pub forwarding: ForwardingMetrics,
    pub lookup: LookupMetrics,
    pub tree: TreeMetrics,
    pub bloom: BloomMetrics,
    pub congestion: CongestionMetrics,
    pub errors: ErrorMetrics,
}

impl MetricsRegistry {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarding_received_tracks_packets_and_bytes() {
        let m = ForwardingMetrics::default();
        m.record_received(100);
        m.record_received(40);
        assert_eq!(m.received_packets.get(), 2);
        assert_eq!(m.received_bytes.get(), 140);
    }

    #[test]
    fn discovery_record_reject_routes_to_field() {
        let m = LookupMetrics::default();
        m.record_reject(DiscoveryReject::ReqDuplicate);
        m.record_reject(DiscoveryReject::ReqDuplicate);
        m.record_reject(DiscoveryReject::RespNoRoute);
        assert_eq!(m.req_duplicate.get(), 2);
        assert_eq!(m.resp_no_route.get(), 1);
        assert_eq!(m.req_decode_error.get(), 0);
    }

    #[test]
    fn discovery_direct_counters_increment() {
        let m = LookupMetrics::default();
        m.req_received.inc();
        m.req_forwarded.inc();
        m.req_forwarded.inc();
        assert_eq!(m.req_received.get(), 1);
        assert_eq!(m.req_forwarded.get(), 2);
    }

    #[test]
    fn tree_record_reject_routes_to_field() {
        let m = TreeMetrics::default();
        m.record_reject(TreeReject::OutboundSignFailed);
        m.record_reject(TreeReject::OutboundSignFailed);
        m.record_reject(TreeReject::AncestryInvalid);
        assert_eq!(m.outbound_sign_failed.get(), 2);
        assert_eq!(m.ancestry_invalid.get(), 1);
    }

    #[test]
    fn bloom_record_reject_routes_to_field() {
        let m = BloomMetrics::default();
        m.record_reject(BloomReject::Stale);
        m.record_reject(BloomReject::Stale);
        m.record_reject(BloomReject::DecodeError);
        assert_eq!(m.stale.get(), 2);
        assert_eq!(m.decode_error.get(), 1);
        assert_eq!(m.invalid.get(), 0);
    }

    #[test]
    fn registry_subcounters_are_independent() {
        let r = MetricsRegistry::new();
        r.forwarding.record_received(10);
        r.lookup.req_received.inc();
        assert_eq!(r.forwarding.received_packets.get(), 1);
        assert_eq!(r.forwarding.received_bytes.get(), 10);
        assert_eq!(r.lookup.req_received.get(), 1);
    }
}
