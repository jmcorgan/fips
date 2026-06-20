//! Node-level statistics for the session, handshake, mmp, and transport
//! families. The forwarding, discovery, tree, bloom, congestion, and error
//! families have migrated to the atomic
//! [`MetricsRegistry`](crate::node::metrics::MetricsRegistry).
//!
//! Unlike `EthernetStats` (which uses `AtomicU64` + `Arc` for cross-task
//! sharing), these counters use plain `u64` because `Node` handlers run
//! on a single `&mut self` context. A `snapshot()` method produces a
//! copyable struct for control socket queries.

use serde::Serialize;

use crate::node::reject::{
    HandshakeReject, MmpReject, RejectReason, SessionReject, TransportReject,
};

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

/// Aggregate node statistics.
///
/// Holds only the families that have not migrated to the atomic
/// [`MetricsRegistry`](crate::node::metrics::MetricsRegistry): session,
/// handshake, mmp, and transport. The forwarding, discovery, tree,
/// bloom, congestion, and error families are served exclusively from
/// the registry.
#[derive(Default)]
pub struct NodeStats {
    pub session: SessionStats,
    pub handshake: HandshakeStats,
    pub mmp: MmpStats,
    pub transport: TransportStats,
}

impl NodeStats {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a typed rejection from a silent-rejection site.
    ///
    /// Dispatches to the appropriate sub-stats `record_reject` based on
    /// the [`RejectReason`] top-level variant. Only the families still
    /// stored on `NodeStats` (session, handshake, mmp, transport) are
    /// routed here; the migrated families are recorded directly on the
    /// [`MetricsRegistry`](crate::node::metrics::MetricsRegistry).
    pub fn record_reject(&mut self, reason: RejectReason) {
        match reason {
            RejectReason::Session(r) => self.session.record_reject(r),
            RejectReason::Handshake(r) => self.handshake.record_reject(r),
            RejectReason::Transport(r) => self.transport.record_reject(r),
            RejectReason::Mmp(r) => self.mmp.record_reject(r),
            // The forwarding, discovery, tree, and bloom families are
            // recorded directly on the MetricsRegistry and never reach
            // this NodeStats dispatch.
            RejectReason::Forwarding(_)
            | RejectReason::Discovery(_)
            | RejectReason::Tree(_)
            | RejectReason::Bloom(_) => {
                debug_assert!(false, "migrated reject family must use MetricsRegistry");
            }
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
    pub route_tree_up: u64,
    pub route_tree_down: u64,
    pub route_tree_down_cross: u64,
    pub route_crosslink_descend: u64,
    pub route_crosslink_ascend: u64,
    pub route_direct_peer: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DiscoveryStatsSnapshot {
    pub req_received: u64,
    pub req_decode_error: u64,
    pub req_duplicate: u64,
    pub req_dedup_cache_full: u64,
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

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
