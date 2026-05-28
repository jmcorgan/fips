//! Node-level statistics for routing, forwarding, and discovery operations.
//!
//! Unlike `EthernetStats` (which uses `AtomicU64` + `Arc` for cross-task
//! sharing), these counters use plain `u64` because `Node` handlers run
//! on a single `&mut self` context. A `snapshot()` method produces a
//! copyable struct for control socket queries.

use serde::Serialize;

use crate::node::reject::{
    BloomReject, DiscoveryReject, ForwardingReject, HandshakeReject, MmpReject, RejectReason,
    SessionReject, TransportReject, TreeReject,
};

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

    /// Dispatch a typed forwarding rejection to its packet counter.
    ///
    /// The byte-counted side of each outcome is recorded by the
    /// existing `record_*` methods at the call site (which know the
    /// payload size); `record_reject` only bumps the packet count and
    /// is paired with the byte-aware call at the call site for the
    /// duration of the typed-rejection rollout. A later change may collapse the
    /// two calls into a single typed entry point.
    pub(super) fn record_reject(&mut self, reason: ForwardingReject) {
        match reason {
            ForwardingReject::DecodeError => self.decode_error_packets += 1,
            ForwardingReject::TtlExhausted => self.ttl_exhausted_packets += 1,
            ForwardingReject::NoRoute => self.drop_no_route_packets += 1,
            ForwardingReject::MtuExceeded => self.drop_mtu_exceeded_packets += 1,
            ForwardingReject::SendError => self.drop_send_error_packets += 1,
        }
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
    pub req_target_is_us: u64,
    pub req_forwarded: u64,
    pub req_ttl_exhausted: u64,
    pub req_initiated: u64,
    pub req_deduplicated: u64,
    pub req_backoff_suppressed: u64,
    pub req_forward_rate_limited: u64,
    pub req_bloom_miss: u64,
    pub req_no_tree_peer: u64,
    pub req_fallback_forwarded: u64,
    // Response counters
    pub resp_received: u64,
    pub resp_decode_error: u64,
    pub resp_forwarded: u64,
    pub resp_identity_miss: u64,
    pub resp_proof_failed: u64,
    pub resp_no_route: u64,
    pub resp_accepted: u64,
    pub resp_timed_out: u64,
}

impl DiscoveryStats {
    pub(super) fn record_reject(&mut self, reason: DiscoveryReject) {
        match reason {
            DiscoveryReject::ReqDecodeError => self.req_decode_error += 1,
            DiscoveryReject::ReqDuplicate => self.req_duplicate += 1,
            DiscoveryReject::ReqTtlExhausted => self.req_ttl_exhausted += 1,
            DiscoveryReject::RespDecodeError => self.resp_decode_error += 1,
            DiscoveryReject::RespIdentityMiss => self.resp_identity_miss += 1,
            DiscoveryReject::RespProofFailed => self.resp_proof_failed += 1,
            DiscoveryReject::RespNoRoute => self.resp_no_route += 1,
        }
    }

    pub fn snapshot(&self) -> DiscoveryStatsSnapshot {
        DiscoveryStatsSnapshot {
            req_received: self.req_received,
            req_decode_error: self.req_decode_error,
            req_duplicate: self.req_duplicate,
            req_target_is_us: self.req_target_is_us,
            req_forwarded: self.req_forwarded,
            req_ttl_exhausted: self.req_ttl_exhausted,
            req_initiated: self.req_initiated,
            req_deduplicated: self.req_deduplicated,
            req_backoff_suppressed: self.req_backoff_suppressed,
            req_forward_rate_limited: self.req_forward_rate_limited,
            req_bloom_miss: self.req_bloom_miss,
            req_no_tree_peer: self.req_no_tree_peer,
            req_fallback_forwarded: self.req_fallback_forwarded,
            resp_received: self.resp_received,
            resp_decode_error: self.resp_decode_error,
            resp_forwarded: self.resp_forwarded,
            resp_identity_miss: self.resp_identity_miss,
            resp_proof_failed: self.resp_proof_failed,
            resp_no_route: self.resp_no_route,
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
    pub ancestry_invalid: u64,
    pub accepted: u64,
    pub parent_switched: u64,
    pub loop_detected: u64,
    pub ancestry_changed: u64,
    // Outbound announce sending
    pub sent: u64,
    pub rate_limited: u64,
    pub send_failed: u64,
    pub outbound_sign_failed: u64,
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
            ancestry_invalid: self.ancestry_invalid,
            accepted: self.accepted,
            parent_switched: self.parent_switched,
            loop_detected: self.loop_detected,
            ancestry_changed: self.ancestry_changed,
            sent: self.sent,
            rate_limited: self.rate_limited,
            send_failed: self.send_failed,
            outbound_sign_failed: self.outbound_sign_failed,
            parent_switches: self.parent_switches,
            parent_losses: self.parent_losses,
            flap_dampened: self.flap_dampened,
        }
    }

    pub(super) fn record_reject(&mut self, reason: TreeReject) {
        match reason {
            TreeReject::AncestryInvalid => self.ancestry_invalid += 1,
            TreeReject::OutboundSignFailed => self.outbound_sign_failed += 1,
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
    /// Non-v1-compliant size class. Reserved for symmetry with the
    /// master-side BloomStats shape; the next-side handler does not
    /// presently check `is_v1_compliant()` so the counter stays at
    /// zero. Kept as a field so `BloomReject::NonV1` dispatches to a
    /// real target and the cross-line enum shape is identical.
    pub non_v1: u64,
    pub unknown_peer: u64,
    pub stale: u64,
    pub fill_exceeded: u64,
    pub accepted: u64,
    // Outbound announce sending
    pub sent: u64,
    pub debounce_suppressed: u64,
    pub send_failed: u64,
    // Delta compression
    pub deltas_sent: u64,
    pub full_sends: u64,
    pub nacks_sent: u64,
    pub nacks_received: u64,
    // Adaptive sizing
    pub size_changes: u64,
    // Compression tracking
    pub total_compressed_bytes: u64,
    pub total_raw_bytes: u64,
}

impl BloomStats {
    pub(super) fn record_reject(&mut self, reason: BloomReject) {
        match reason {
            BloomReject::DecodeError => self.decode_error += 1,
            BloomReject::Invalid => self.invalid += 1,
            BloomReject::NonV1 => self.non_v1 += 1,
            BloomReject::UnknownPeer => self.unknown_peer += 1,
            BloomReject::Stale => self.stale += 1,
            BloomReject::FillExceeded => self.fill_exceeded += 1,
        }
    }

    pub fn snapshot(&self) -> BloomStatsSnapshot {
        BloomStatsSnapshot {
            received: self.received,
            decode_error: self.decode_error,
            invalid: self.invalid,
            non_v1: self.non_v1,
            unknown_peer: self.unknown_peer,
            stale: self.stale,
            fill_exceeded: self.fill_exceeded,
            accepted: self.accepted,
            sent: self.sent,
            debounce_suppressed: self.debounce_suppressed,
            send_failed: self.send_failed,
            deltas_sent: self.deltas_sent,
            full_sends: self.full_sends,
            nacks_sent: self.nacks_sent,
            nacks_received: self.nacks_received,
            size_changes: self.size_changes,
            total_compressed_bytes: self.total_compressed_bytes,
            total_raw_bytes: self.total_raw_bytes,
        }
    }
}

/// FSP session statistics — receive-path silent-rejection counters.
///
/// Covers the unknown-session and state-machine-mismatch rejection
/// sites in `handlers/session.rs`. Each counter increments once per
/// dropped inbound message; the WARN/DEBUG log line at the site is
/// preserved alongside the counter bump for operator visibility.
#[derive(Default)]
pub struct SessionStats {
    /// Inbound session-layer message arrived for a peer address with no
    /// matching `SessionEntry`. Aggregates across encrypted data,
    /// SessionAck, SessionMsg3, SessionReceiverReport, and
    /// PathMtuNotification.
    pub unknown_session: u64,
    /// Inbound session-layer message arrived for a `SessionEntry` whose
    /// state is incompatible with the message type (encrypted data
    /// before Established; SessionAck outside Initiating; SessionMsg3
    /// outside AwaitingMsg3).
    pub bad_state: u64,
}

impl SessionStats {
    pub fn snapshot(&self) -> SessionStatsSnapshot {
        SessionStatsSnapshot {
            unknown_session: self.unknown_session,
            bad_state: self.bad_state,
        }
    }

    pub(super) fn record_reject(&mut self, reason: SessionReject) {
        match reason {
            SessionReject::UnknownSession => self.unknown_session += 1,
            SessionReject::BadState => self.bad_state += 1,
        }
    }
}

/// Noise-handshake statistics — receive-path silent-rejection counters.
///
/// Covers the state-machine and lookup-miss rejection sites in
/// `handlers/handshake.rs` across msg1, msg2, and (on the XX side) msg3.
/// Each counter increments once per dropped inbound message; the
/// WARN/DEBUG log line at the site is preserved alongside the counter
/// bump for operator visibility.
#[derive(Default)]
pub struct HandshakeStats {
    /// Handshake state-machine rejection: header parse failed, Noise
    /// crypto step failed, identity could not be learned, index allocator
    /// returned an error, msg2/msg3 send failed, promote_connection
    /// returned an error, ACL gate rejected the peer, or the admission
    /// gate fired (max_peers / accept_connections).
    pub bad_state: u64,
    /// Inbound handshake message arrived but no matching connection was
    /// found by the receiver_idx (or addr) lookup: msg2 for an unknown
    /// pending-outbound index, duplicate msg1 with no stored msg2 to
    /// resend, msg3 for an unknown pending-inbound index without a
    /// matching rekey-responder slot.
    pub unknown_connection: u64,
}

impl HandshakeStats {
    pub fn snapshot(&self) -> HandshakeStatsSnapshot {
        HandshakeStatsSnapshot {
            bad_state: self.bad_state,
            unknown_connection: self.unknown_connection,
        }
    }

    pub(super) fn record_reject(&mut self, reason: HandshakeReject) {
        match reason {
            HandshakeReject::BadState => self.bad_state += 1,
            HandshakeReject::UnknownConnection => self.unknown_connection += 1,
        }
    }
}

/// MMP link-layer rejection statistics.
///
/// Covers the receive-path silent-rejection sites in
/// `src/node/handlers/mmp.rs::handle_sender_report` and
/// `handle_receiver_report`. Each counter increments once per
/// dropped inbound report; the WARN/DEBUG log line at the site is
/// preserved alongside the counter bump.
#[derive(Default)]
pub struct MmpStats {
    /// `SenderReport::decode` or `ReceiverReport::decode` returned
    /// an error. Aggregated across the two report types.
    pub decode_error: u64,
    /// SenderReport or ReceiverReport arrived from a peer with no
    /// `ActivePeer` record on this node.
    pub unknown_peer: u64,
}

impl MmpStats {
    pub fn snapshot(&self) -> MmpStatsSnapshot {
        MmpStatsSnapshot {
            decode_error: self.decode_error,
            unknown_peer: self.unknown_peer,
        }
    }

    pub(super) fn record_reject(&mut self, reason: MmpReject) {
        match reason {
            MmpReject::DecodeError => self.decode_error += 1,
            MmpReject::UnknownPeer => self.unknown_peer += 1,
        }
    }
}

/// Transport-layer rejection statistics aggregated at the node level.
///
/// Per-transport modules (`transport/tcp/stats.rs`, `transport/tor/stats.rs`)
/// keep their own `connections_accepted` / `connections_rejected` /
/// `pool_inbound` / `pool_outbound` counters at the transport layer.
/// `TransportStats` here collects node-level visibility for any future
/// admission-rejection paths that the node code itself decides to
/// register via `record_reject(RejectReason::Transport(...))`.
///
/// The `inbound_cap_exceeded` counter is the typed-dispatch parity
/// counterpart of the per-transport `connections_rejected` counter,
/// which lives in the accept-loop task with no `NodeStats` access.
/// Currently this node-side counter stays at zero; it exists so the
/// typed-rejection enum stays the canonical entry point and so a
/// future transport-to-node bridge (event or sampling) has a
/// well-known destination.
#[derive(Default)]
pub struct TransportStats {
    /// Reserved for node-side inbound-cap-exceeded admission rejection
    /// dispatch. Per-transport accept-loop cap rejections are tracked
    /// on the transport-level stats (`TcpStats::connections_rejected`,
    /// `TorStats::connections_rejected`) directly.
    pub inbound_cap_exceeded: u64,
}

impl TransportStats {
    pub fn snapshot(&self) -> TransportStatsSnapshot {
        TransportStatsSnapshot {
            inbound_cap_exceeded: self.inbound_cap_exceeded,
        }
    }

    pub(super) fn record_reject(&mut self, reason: TransportReject) {
        match reason {
            TransportReject::InboundCapExceeded => self.inbound_cap_exceeded += 1,
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

/// Congestion event statistics — ECN CE tracking and detection triggers.
#[derive(Default)]
pub struct CongestionStats {
    /// Packets forwarded with the CE flag set (incoming CE or locally detected).
    pub ce_forwarded: u64,
    /// CE-flagged packets received at this node as final destination.
    pub ce_received: u64,
    /// Number of times detect_congestion() returned true.
    pub congestion_detected: u64,
    /// Rising-edge transport kernel drop events (not-dropping → dropping).
    pub kernel_drop_events: u64,
}

impl CongestionStats {
    pub fn record_ce_forwarded(&mut self) {
        self.ce_forwarded += 1;
    }

    pub fn record_ce_received(&mut self) {
        self.ce_received += 1;
    }

    pub fn record_congestion_detected(&mut self) {
        self.congestion_detected += 1;
    }

    pub fn record_kernel_drop_event(&mut self) {
        self.kernel_drop_events += 1;
    }

    pub fn snapshot(&self) -> CongestionStatsSnapshot {
        CongestionStatsSnapshot {
            ce_forwarded: self.ce_forwarded,
            ce_received: self.ce_received,
            congestion_detected: self.congestion_detected,
            kernel_drop_events: self.kernel_drop_events,
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
    pub session: SessionStats,
    pub handshake: HandshakeStats,
    pub mmp: MmpStats,
    pub transport: TransportStats,
    pub errors: ErrorSignalStats,
    pub congestion: CongestionStats,
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
            session: self.session.snapshot(),
            handshake: self.handshake.snapshot(),
            mmp: self.mmp.snapshot(),
            transport: self.transport.snapshot(),
            errors: self.errors.snapshot(),
            congestion: self.congestion.snapshot(),
        }
    }

    /// Record a typed rejection from a silent-rejection site.
    ///
    /// Dispatches to the appropriate sub-stats `record_reject` based on
    /// the [`RejectReason`] top-level variant. Sub-enums that have not
    /// yet had any variants populated still use `match r {}` to keep
    /// the dispatch arm exhaustive without dead-code complaints.
    pub fn record_reject(&mut self, reason: RejectReason) {
        match reason {
            RejectReason::Tree(r) => self.tree.record_reject(r),
            RejectReason::Bloom(r) => self.bloom.record_reject(r),
            RejectReason::Discovery(r) => self.discovery.record_reject(r),
            RejectReason::Session(r) => self.session.record_reject(r),
            RejectReason::Handshake(r) => self.handshake.record_reject(r),
            RejectReason::Forwarding(r) => self.forwarding.record_reject(r),
            RejectReason::Transport(r) => self.transport.record_reject(r),
            RejectReason::Mmp(r) => self.mmp.record_reject(r),
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
    pub req_target_is_us: u64,
    pub req_forwarded: u64,
    pub req_ttl_exhausted: u64,
    pub req_initiated: u64,
    pub req_deduplicated: u64,
    pub req_backoff_suppressed: u64,
    pub req_forward_rate_limited: u64,
    pub req_bloom_miss: u64,
    pub req_no_tree_peer: u64,
    pub req_fallback_forwarded: u64,
    pub resp_received: u64,
    pub resp_decode_error: u64,
    pub resp_forwarded: u64,
    pub resp_identity_miss: u64,
    pub resp_proof_failed: u64,
    pub resp_no_route: u64,
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
    pub ancestry_invalid: u64,
    pub accepted: u64,
    pub parent_switched: u64,
    pub loop_detected: u64,
    pub ancestry_changed: u64,
    pub sent: u64,
    pub rate_limited: u64,
    pub send_failed: u64,
    pub outbound_sign_failed: u64,
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
    pub fill_exceeded: u64,
    pub accepted: u64,
    pub sent: u64,
    pub debounce_suppressed: u64,
    pub send_failed: u64,
    pub deltas_sent: u64,
    pub full_sends: u64,
    pub nacks_sent: u64,
    pub nacks_received: u64,
    pub size_changes: u64,
    pub total_compressed_bytes: u64,
    pub total_raw_bytes: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct SessionStatsSnapshot {
    pub unknown_session: u64,
    pub bad_state: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct HandshakeStatsSnapshot {
    pub bad_state: u64,
    pub unknown_connection: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct MmpStatsSnapshot {
    pub decode_error: u64,
    pub unknown_peer: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TransportStatsSnapshot {
    pub inbound_cap_exceeded: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ErrorSignalStatsSnapshot {
    pub coords_required: u64,
    pub path_broken: u64,
    pub mtu_exceeded: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CongestionStatsSnapshot {
    pub ce_forwarded: u64,
    pub ce_received: u64,
    pub congestion_detected: u64,
    pub kernel_drop_events: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct NodeStatsSnapshot {
    pub forwarding: ForwardingStatsSnapshot,
    pub discovery: DiscoveryStatsSnapshot,
    pub tree: TreeStatsSnapshot,
    pub bloom: BloomStatsSnapshot,
    pub session: SessionStatsSnapshot,
    pub handshake: HandshakeStatsSnapshot,
    pub mmp: MmpStatsSnapshot,
    pub transport: TransportStatsSnapshot,
    pub errors: ErrorSignalStatsSnapshot,
    pub congestion: CongestionStatsSnapshot,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_stats_record_reject_ancestry_invalid() {
        let mut stats = TreeStats::default();
        stats.record_reject(TreeReject::AncestryInvalid);
        stats.record_reject(TreeReject::AncestryInvalid);
        assert_eq!(stats.ancestry_invalid, 2);
        assert_eq!(stats.outbound_sign_failed, 0);
    }

    #[test]
    fn tree_stats_record_reject_outbound_sign_failed() {
        let mut stats = TreeStats::default();
        stats.record_reject(TreeReject::OutboundSignFailed);
        stats.record_reject(TreeReject::OutboundSignFailed);
        assert_eq!(stats.outbound_sign_failed, 2);
        assert_eq!(stats.ancestry_invalid, 0);
    }

    #[test]
    fn node_stats_record_reject_dispatches_to_tree() {
        let mut stats = NodeStats::new();
        stats.record_reject(RejectReason::Tree(TreeReject::OutboundSignFailed));
        assert_eq!(stats.tree.outbound_sign_failed, 1);
        assert_eq!(stats.tree.ancestry_invalid, 0);
    }

    #[test]
    fn session_stats_record_reject_unknown_session() {
        let mut stats = SessionStats::default();
        stats.record_reject(SessionReject::UnknownSession);
        stats.record_reject(SessionReject::UnknownSession);
        assert_eq!(stats.unknown_session, 2);
        assert_eq!(stats.bad_state, 0);
    }

    #[test]
    fn session_stats_record_reject_bad_state() {
        let mut stats = SessionStats::default();
        stats.record_reject(SessionReject::BadState);
        stats.record_reject(SessionReject::BadState);
        assert_eq!(stats.bad_state, 2);
        assert_eq!(stats.unknown_session, 0);
    }

    #[test]
    fn node_stats_record_reject_dispatches_to_session() {
        let mut stats = NodeStats::new();
        stats.record_reject(RejectReason::Session(SessionReject::UnknownSession));
        stats.record_reject(RejectReason::Session(SessionReject::BadState));
        assert_eq!(stats.session.unknown_session, 1);
        assert_eq!(stats.session.bad_state, 1);
        assert_eq!(stats.tree.ancestry_invalid, 0);
    }

    #[test]
    fn handshake_stats_record_reject_bad_state() {
        let mut stats = HandshakeStats::default();
        stats.record_reject(HandshakeReject::BadState);
        stats.record_reject(HandshakeReject::BadState);
        stats.record_reject(HandshakeReject::BadState);
        assert_eq!(stats.bad_state, 3);
        assert_eq!(stats.unknown_connection, 0);
    }

    #[test]
    fn handshake_stats_record_reject_unknown_connection() {
        let mut stats = HandshakeStats::default();
        stats.record_reject(HandshakeReject::UnknownConnection);
        stats.record_reject(HandshakeReject::UnknownConnection);
        assert_eq!(stats.unknown_connection, 2);
        assert_eq!(stats.bad_state, 0);
    }

    #[test]
    fn node_stats_record_reject_dispatches_to_handshake() {
        let mut stats = NodeStats::new();
        stats.record_reject(RejectReason::Handshake(HandshakeReject::BadState));
        stats.record_reject(RejectReason::Handshake(HandshakeReject::UnknownConnection));
        stats.record_reject(RejectReason::Handshake(HandshakeReject::BadState));
        assert_eq!(stats.handshake.bad_state, 2);
        assert_eq!(stats.handshake.unknown_connection, 1);
        assert_eq!(stats.session.unknown_session, 0);
        assert_eq!(stats.tree.ancestry_invalid, 0);
    }

    #[test]
    fn bloom_stats_record_reject_decode_error() {
        let mut s = BloomStats::default();
        s.record_reject(BloomReject::DecodeError);
        s.record_reject(BloomReject::DecodeError);
        assert_eq!(s.decode_error, 2);
        assert_eq!(s.invalid, 0);
    }

    #[test]
    fn bloom_stats_record_reject_invalid() {
        let mut s = BloomStats::default();
        s.record_reject(BloomReject::Invalid);
        assert_eq!(s.invalid, 1);
    }

    #[test]
    fn bloom_stats_record_reject_non_v1() {
        let mut s = BloomStats::default();
        s.record_reject(BloomReject::NonV1);
        assert_eq!(s.non_v1, 1);
    }

    #[test]
    fn bloom_stats_record_reject_unknown_peer() {
        let mut s = BloomStats::default();
        s.record_reject(BloomReject::UnknownPeer);
        assert_eq!(s.unknown_peer, 1);
    }

    #[test]
    fn bloom_stats_record_reject_stale() {
        let mut s = BloomStats::default();
        s.record_reject(BloomReject::Stale);
        assert_eq!(s.stale, 1);
    }

    #[test]
    fn bloom_stats_record_reject_fill_exceeded() {
        let mut s = BloomStats::default();
        s.record_reject(BloomReject::FillExceeded);
        assert_eq!(s.fill_exceeded, 1);
    }

    #[test]
    fn node_stats_record_reject_dispatches_to_bloom() {
        let mut stats = NodeStats::new();
        stats.record_reject(RejectReason::Bloom(BloomReject::DecodeError));
        stats.record_reject(RejectReason::Bloom(BloomReject::Stale));
        assert_eq!(stats.bloom.decode_error, 1);
        assert_eq!(stats.bloom.stale, 1);
        assert_eq!(stats.tree.ancestry_invalid, 0);
    }

    #[test]
    fn discovery_stats_record_reject_req_decode_error() {
        let mut s = DiscoveryStats::default();
        s.record_reject(DiscoveryReject::ReqDecodeError);
        assert_eq!(s.req_decode_error, 1);
    }

    #[test]
    fn discovery_stats_record_reject_req_duplicate() {
        let mut s = DiscoveryStats::default();
        s.record_reject(DiscoveryReject::ReqDuplicate);
        assert_eq!(s.req_duplicate, 1);
    }

    #[test]
    fn discovery_stats_record_reject_req_ttl_exhausted() {
        let mut s = DiscoveryStats::default();
        s.record_reject(DiscoveryReject::ReqTtlExhausted);
        assert_eq!(s.req_ttl_exhausted, 1);
    }

    #[test]
    fn discovery_stats_record_reject_resp_decode_error() {
        let mut s = DiscoveryStats::default();
        s.record_reject(DiscoveryReject::RespDecodeError);
        assert_eq!(s.resp_decode_error, 1);
    }

    #[test]
    fn discovery_stats_record_reject_resp_identity_miss() {
        let mut s = DiscoveryStats::default();
        s.record_reject(DiscoveryReject::RespIdentityMiss);
        assert_eq!(s.resp_identity_miss, 1);
    }

    #[test]
    fn discovery_stats_record_reject_resp_proof_failed() {
        let mut s = DiscoveryStats::default();
        s.record_reject(DiscoveryReject::RespProofFailed);
        assert_eq!(s.resp_proof_failed, 1);
    }

    #[test]
    fn node_stats_record_reject_dispatches_to_discovery() {
        let mut stats = NodeStats::new();
        stats.record_reject(RejectReason::Discovery(DiscoveryReject::ReqDecodeError));
        stats.record_reject(RejectReason::Discovery(DiscoveryReject::RespProofFailed));
        assert_eq!(stats.discovery.req_decode_error, 1);
        assert_eq!(stats.discovery.resp_proof_failed, 1);
        assert_eq!(stats.tree.ancestry_invalid, 0);
    }

    #[test]
    fn forwarding_stats_record_reject_decode_error() {
        let mut s = ForwardingStats::default();
        s.record_reject(ForwardingReject::DecodeError);
        assert_eq!(s.decode_error_packets, 1);
    }

    #[test]
    fn forwarding_stats_record_reject_ttl_exhausted() {
        let mut s = ForwardingStats::default();
        s.record_reject(ForwardingReject::TtlExhausted);
        assert_eq!(s.ttl_exhausted_packets, 1);
    }

    #[test]
    fn forwarding_stats_record_reject_no_route() {
        let mut s = ForwardingStats::default();
        s.record_reject(ForwardingReject::NoRoute);
        assert_eq!(s.drop_no_route_packets, 1);
    }

    #[test]
    fn forwarding_stats_record_reject_mtu_exceeded() {
        let mut s = ForwardingStats::default();
        s.record_reject(ForwardingReject::MtuExceeded);
        assert_eq!(s.drop_mtu_exceeded_packets, 1);
    }

    #[test]
    fn forwarding_stats_record_reject_send_error() {
        let mut s = ForwardingStats::default();
        s.record_reject(ForwardingReject::SendError);
        assert_eq!(s.drop_send_error_packets, 1);
    }

    #[test]
    fn node_stats_record_reject_dispatches_to_forwarding() {
        let mut stats = NodeStats::new();
        stats.record_reject(RejectReason::Forwarding(ForwardingReject::NoRoute));
        stats.record_reject(RejectReason::Forwarding(ForwardingReject::MtuExceeded));
        assert_eq!(stats.forwarding.drop_no_route_packets, 1);
        assert_eq!(stats.forwarding.drop_mtu_exceeded_packets, 1);
        assert_eq!(stats.tree.ancestry_invalid, 0);
    }

    #[test]
    fn mmp_stats_record_reject_decode_error() {
        let mut s = MmpStats::default();
        s.record_reject(MmpReject::DecodeError);
        s.record_reject(MmpReject::DecodeError);
        assert_eq!(s.decode_error, 2);
        assert_eq!(s.unknown_peer, 0);
    }

    #[test]
    fn mmp_stats_record_reject_unknown_peer() {
        let mut s = MmpStats::default();
        s.record_reject(MmpReject::UnknownPeer);
        assert_eq!(s.unknown_peer, 1);
        assert_eq!(s.decode_error, 0);
    }

    #[test]
    fn node_stats_record_reject_dispatches_to_mmp() {
        let mut stats = NodeStats::new();
        stats.record_reject(RejectReason::Mmp(MmpReject::DecodeError));
        stats.record_reject(RejectReason::Mmp(MmpReject::UnknownPeer));
        assert_eq!(stats.mmp.decode_error, 1);
        assert_eq!(stats.mmp.unknown_peer, 1);
        assert_eq!(stats.tree.ancestry_invalid, 0);
    }

    #[test]
    fn transport_stats_record_reject_inbound_cap_exceeded() {
        let mut s = TransportStats::default();
        s.record_reject(TransportReject::InboundCapExceeded);
        s.record_reject(TransportReject::InboundCapExceeded);
        assert_eq!(s.inbound_cap_exceeded, 2);
    }

    #[test]
    fn node_stats_record_reject_dispatches_to_transport() {
        let mut stats = NodeStats::new();
        stats.record_reject(RejectReason::Transport(TransportReject::InboundCapExceeded));
        assert_eq!(stats.transport.inbound_cap_exceeded, 1);
        assert_eq!(stats.tree.ancestry_invalid, 0);
    }
}
