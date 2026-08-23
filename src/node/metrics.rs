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
    LookupStatsSnapshot, NativeStatsSnapshot, TreeStatsSnapshot,
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
    pub warm_malformed_packets: Counter,
    pub warm_malformed_bytes: Counter,
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

    /// Record a coordinate-cache warm attempt abandoned because the frame was
    /// not a well-formed encrypted FSP message.
    ///
    /// This is **not** a packet drop. The frame is still delivered or
    /// forwarded by the normal path; only the opportunistic warm attempt was
    /// abandoned, so this must never be folded into the rejection family or
    /// rendered as dropped traffic. `bytes` is the outer `SessionDatagram`
    /// payload of the frame whose warm attempt was abandoned — the buffer
    /// after `dispatch_link_message` strips the msg_type byte, not the inner
    /// FSP payload the warm path reads. That is the same basis as
    /// [`Self::record_received`] and [`Self::record_reject_bytes`], and it has
    /// to be: all three render through one `fwd_value` row on the fipstop
    /// Routing tab, where a mixed basis reads as a smaller flood than the one
    /// actually arriving. It is volume observed, not volume dropped, and is
    /// carried so the counter can be rendered as a packets-and-bytes pair like
    /// its siblings.
    #[inline]
    pub fn record_warm_malformed(&self, bytes: usize) {
        self.warm_malformed_packets.inc();
        self.warm_malformed_bytes.add(bytes as u64);
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
            warm_malformed_packets: self.warm_malformed_packets.get(),
            warm_malformed_bytes: self.warm_malformed_bytes.get(),
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
    pub req_dedup_evicted: Counter,
    pub req_sign_rate_limited: Counter,
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
    pub resp_unsolicited: Counter,
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
            DiscoveryReject::ReqSignRateLimited => self.req_sign_rate_limited.inc(),
            DiscoveryReject::ReqTtlExhausted => self.req_ttl_exhausted.inc(),
            DiscoveryReject::RespDecodeError => self.resp_decode_error.inc(),
            DiscoveryReject::RespIdentityMiss => self.resp_identity_miss.inc(),
            DiscoveryReject::RespProofFailed => self.resp_proof_failed.inc(),
            DiscoveryReject::RespUnsolicited => self.resp_unsolicited.inc(),
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
            req_dedup_evicted: self.req_dedup_evicted.get(),
            req_sign_rate_limited: self.req_sign_rate_limited.get(),
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
            resp_unsolicited: self.resp_unsolicited.get(),
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

/// Routing signals refused by the sender-binding admission gate, split by
/// signal type.
///
/// The sibling counters on `ErrorMetrics` count arrivals, incremented before
/// the gate runs; these count the subset that was refused. Read together they
/// give the refused fraction per signal type, which is what separates a node
/// nobody is talking to from a node with a genuinely broken path from a node
/// being fed forged signals.
#[derive(Default)]
pub struct UnboundSignals {
    /// `CoordsRequired` refused because this node has not bound the
    /// destination address the signal names.
    pub coords: Counter,
    /// `PathBroken` refused because this node has not bound the destination
    /// address the signal names.
    pub broken: Counter,
    /// `MtuExceeded` refused because this node has not bound the destination
    /// address the signal names.
    pub mtu: Counter,
    /// Subset of the above whose src/dest pairing is structurally impossible
    /// for a legitimate emitter: the signal names this node as the
    /// destination, or claims a source equal to the destination it names.
    /// Neither can arise from an honest on-path forwarder, so any count here
    /// is a fabricated signal rather than ordinary session churn.
    pub forged: Counter,
}

/// Error-signal metric counters.
#[derive(Default)]
pub struct ErrorMetrics {
    pub coords_required: Counter,
    pub path_broken: Counter,
    pub mtu_exceeded: Counter,
    /// `PathMtuNotification`s ignored for carrying a path MTU below the
    /// actionable floor. This signal arrives inside an established session
    /// on the decrypted path, so a rising count means an authenticated peer
    /// is misconfigured or misbehaving.
    pub path_mtu_notif_below_floor: Counter,
    /// `MtuExceeded` signals whose bottleneck was ignored for falling below
    /// the actionable floor. The signal is unencrypted, unauthenticated and
    /// unmetered, so a rising count on its own is the forged-signal
    /// signature; `mtu_exceeded` counts the whole population.
    pub mtu_exceeded_below_floor: Counter,
    /// `LookupResponse` path MTU annotations ignored for falling below the
    /// actionable floor. The response carried a verified proof, so a rising
    /// count means a forwarder on the reverse path is mangling the unsigned
    /// annotation.
    pub lookup_resp_mtu_below_floor: Counter,
    /// `MtuExceeded` signals ignored because this node has not sent a frame
    /// larger than the bottleneck they report since the last accepted
    /// decrease. An honest report cannot arise without such a frame, so a
    /// rising count is a forged or stale reactive signal.
    pub mtu_exceeded_uncorroborated: Counter,
    pub unbound: UnboundSignals,
    /// Routing errors this node declined to emit because the authenticated
    /// link peer that induced them had spent its budget. A rising count is
    /// either a peer flooding unroutable traffic or a hub relaying more
    /// simultaneously-broken destinations than the budget allows.
    pub emit_over_peer_budget: Counter,
    /// Routing errors this node declined to emit because one for the same
    /// destination went out within the per-destination interval. This is the
    /// aggregate suppression a real outage produces.
    pub emit_over_dest_interval: Counter,
    /// Routing errors emitted without recording their destination, because
    /// the per-destination limiter's map was full. The signal was still sent;
    /// what was lost is interval suppression for that destination.
    pub emit_limiter_at_capacity: Counter,
}

impl ErrorMetrics {
    /// Sample every counter into a serializable snapshot.
    pub fn snapshot(&self) -> ErrorSignalStatsSnapshot {
        ErrorSignalStatsSnapshot {
            coords_required: self.coords_required.get(),
            path_broken: self.path_broken.get(),
            mtu_exceeded: self.mtu_exceeded.get(),
            path_mtu_notif_below_floor: self.path_mtu_notif_below_floor.get(),
            mtu_exceeded_below_floor: self.mtu_exceeded_below_floor.get(),
            lookup_resp_mtu_below_floor: self.lookup_resp_mtu_below_floor.get(),
            unbound_coords: self.unbound.coords.get(),
            unbound_broken: self.unbound.broken.get(),
            unbound_mtu: self.unbound.mtu.get(),
            unbound_forged: self.unbound.forged.get(),
            emit_over_peer_budget: self.emit_over_peer_budget.get(),
            emit_over_dest_interval: self.emit_over_dest_interval.get(),
            emit_limiter_at_capacity: self.emit_limiter_at_capacity.get(),
            mtu_exceeded_uncorroborated: self.mtu_exceeded_uncorroborated.get(),
        }
    }
}

/// Native datagram API metric counters.
///
/// Every one of these is bumped on the rx_loop, in the native request handler,
/// the outbound handler and the inbound dispatch arm. No client task touches a
/// counter, so there is one path per counter rather than two.
///
/// `flows_accepted` counts flows promoted out of a listener's backlog, which
/// happens before the daemon writes the arrival that carries one to its client.
/// A hand-off that then fails is counted under `drop_listener_not_reading` or
/// `drop_listener_gone` and is not taken back off `flows_accepted`, so what a
/// client actually received is the first less the other two.
#[derive(Default)]
pub struct NativeMetrics {
    pub flows_opened: Counter,
    pub flows_accepted: Counter,
    pub flows_closed: Counter,
    pub flows_expired: Counter,
    pub sent_datagrams: Counter,
    pub sent_bytes: Counter,
    pub received_datagrams: Counter,
    pub received_bytes: Counter,
    pub drop_no_port: Counter,
    pub drop_backlog_full: Counter,
    pub drop_too_many_flows: Counter,
    pub drop_pending_queue_full: Counter,
    pub drop_flow_queue_full: Counter,
    pub drop_arrival_queue_full: Counter,
    pub drop_listener_not_reading: Counter,
    pub drop_listener_gone: Counter,
    pub drop_oversize: Counter,
}

impl NativeMetrics {
    /// Route a typed drop to its counter.
    ///
    /// Exhaustive over [`DropReason`](crate::native::link::DropReason) with no
    /// wildcard arm, which is what makes a variant added later a compile error
    /// here rather than a datagram that vanishes uncounted. `DropReason` rather
    /// than `DropCause` because delivery can also fail after the registry has
    /// agreed, and those cases are the ones a slow client causes.
    #[inline]
    pub fn record_drop(&self, reason: crate::native::link::DropReason) {
        use crate::native::link::DropReason;
        match reason {
            DropReason::NoPort => self.drop_no_port.inc(),
            DropReason::BacklogFull => self.drop_backlog_full.inc(),
            DropReason::TooManyFlows => self.drop_too_many_flows.inc(),
            DropReason::PendingQueueFull => self.drop_pending_queue_full.inc(),
            DropReason::FlowQueueFull => self.drop_flow_queue_full.inc(),
            DropReason::ArrivalQueueFull => self.drop_arrival_queue_full.inc(),
            DropReason::ListenerNotReading => self.drop_listener_not_reading.inc(),
            DropReason::ListenerGone => self.drop_listener_gone.inc(),
        }
    }

    /// Count one datagram leaving a client for the mesh.
    #[inline]
    pub fn record_sent(&self, bytes: usize) {
        self.sent_datagrams.inc();
        self.sent_bytes.add(bytes as u64);
    }

    /// Count one datagram reaching a client from the mesh.
    #[inline]
    pub fn record_received(&self, bytes: usize) {
        self.received_datagrams.inc();
        self.received_bytes.add(bytes as u64);
    }

    /// Sample every counter into a serializable snapshot.
    pub fn snapshot(&self) -> NativeStatsSnapshot {
        NativeStatsSnapshot {
            flows_opened: self.flows_opened.get(),
            flows_accepted: self.flows_accepted.get(),
            flows_closed: self.flows_closed.get(),
            flows_expired: self.flows_expired.get(),
            sent_datagrams: self.sent_datagrams.get(),
            sent_bytes: self.sent_bytes.get(),
            received_datagrams: self.received_datagrams.get(),
            received_bytes: self.received_bytes.get(),
            drop_no_port: self.drop_no_port.get(),
            drop_backlog_full: self.drop_backlog_full.get(),
            drop_too_many_flows: self.drop_too_many_flows.get(),
            drop_pending_queue_full: self.drop_pending_queue_full.get(),
            drop_flow_queue_full: self.drop_flow_queue_full.get(),
            drop_arrival_queue_full: self.drop_arrival_queue_full.get(),
            drop_listener_not_reading: self.drop_listener_not_reading.get(),
            drop_listener_gone: self.drop_listener_gone.get(),
            drop_oversize: self.drop_oversize.get(),
        }
    }
}

/// Atomic counter registry shared across the node via `Arc`.
///
/// Sole storage for the forwarding, discovery, tree, bloom, congestion,
/// error, and native counter families; these were migrated off `NodeStats`,
/// which now holds only the session, handshake, mmp, and transport families.
#[derive(Default)]
pub struct MetricsRegistry {
    pub forwarding: ForwardingMetrics,
    pub lookup: LookupMetrics,
    pub tree: TreeMetrics,
    pub bloom: BloomMetrics,
    pub congestion: CongestionMetrics,
    pub errors: ErrorMetrics,
    pub native: NativeMetrics,
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
    fn native_record_drop_routes_every_reason_to_its_own_counter() {
        use crate::native::link::DropReason;
        let m = NativeMetrics::default();
        for reason in [
            DropReason::NoPort,
            DropReason::BacklogFull,
            DropReason::TooManyFlows,
            DropReason::PendingQueueFull,
            DropReason::FlowQueueFull,
            DropReason::ArrivalQueueFull,
            DropReason::ListenerNotReading,
            DropReason::ListenerGone,
        ] {
            m.record_drop(reason);
        }
        let snap = m.snapshot();
        // Each reason lands in one counter and no reason lands in two, which is
        // what a shared counter would hide.
        assert_eq!(snap.drop_no_port, 1);
        assert_eq!(snap.drop_backlog_full, 1);
        assert_eq!(snap.drop_too_many_flows, 1);
        assert_eq!(snap.drop_pending_queue_full, 1);
        assert_eq!(snap.drop_flow_queue_full, 1);
        assert_eq!(snap.drop_arrival_queue_full, 1);
        assert_eq!(snap.drop_listener_not_reading, 1);
        assert_eq!(snap.drop_listener_gone, 1);
        // Nothing bumped the send-side refusal, which no DropReason reaches.
        assert_eq!(snap.drop_oversize, 0);
    }

    #[test]
    fn native_pending_and_flow_queue_drops_read_alike_to_a_client_and_apart_to_a_counter() {
        use crate::native::link::DropReason;
        // The two render identically on purpose, so the debug arrival command
        // answers the same strings it always has. A counter must still tell
        // them apart, because only one of them means a slow client.
        assert_eq!(
            DropReason::PendingQueueFull.as_str(),
            DropReason::FlowQueueFull.as_str()
        );
        let m = NativeMetrics::default();
        m.record_drop(DropReason::FlowQueueFull);
        let snap = m.snapshot();
        assert_eq!(snap.drop_flow_queue_full, 1);
        assert_eq!(snap.drop_pending_queue_full, 0);
    }

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
