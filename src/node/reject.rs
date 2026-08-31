//! Typed rejection reasons for silent-rejection sites across the node.
//!
//! Every rejection-and-return path in the node should classify its
//! reason via [`RejectReason`] and pass the result to
//! [`NodeStats::record_reject`](crate::node::stats::NodeStats::record_reject)
//! so operators can see *what* is being rejected via stats counters
//! rather than via log scraping.
//!
//! The top-level variant set mirrors the protocol-layer / subsystem
//! split that the [`NodeStats`](crate::node::stats::NodeStats)
//! sub-structures already follow, with additional categories
//! (`Handshake`/`Session`/`Mmp`/`Forwarding`/`Transport`) for known
//! silent-rejection clusters that don't yet have dedicated stats
//! sub-structures.
//!
//! The second-level enums are marked `#[non_exhaustive]` to keep the
//! door open for additions without semver concerns from any future
//! external crates.

/// Typed rejection reason for any silent-rejection site in the node.
///
/// Each top-level variant maps to a protocol layer or major subsystem;
/// the nested second-level enum classifies the specific reason within
/// that layer. The whole type is `Copy` so it can be passed through
/// match arms cheaply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use = "RejectReason values must be passed to NodeStats::record_reject"]
pub enum RejectReason {
    /// Spanning-tree TreeAnnounce processing rejection.
    Tree(TreeReject),
    /// Bloom-filter FilterAnnounce processing rejection.
    Bloom(BloomReject),
    /// Discovery request / response processing rejection.
    Discovery(DiscoveryReject),
    /// Noise handshake state-machine rejection.
    Handshake(HandshakeReject),
    /// FSP session state-machine rejection.
    Session(SessionReject),
    /// MMP link-layer rejection.
    Mmp(MmpReject),
    /// Forwarding-path rejection (no-route, TTL, MTU).
    Forwarding(ForwardingReject),
    /// Transport-layer rejection (admission caps, framing, etc.).
    Transport(TransportReject),
}

/// Spanning-tree rejection reasons.
///
/// `AncestryInvalid` covers the `validate_semantics` ancestry-structure
/// rejection; `OutboundSignFailed` covers the Tree and MMP
/// sign-failure cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TreeReject {
    /// `TreeAnnounce::validate_semantics` returned an error — the
    /// advertised ancestry is structurally invalid (advertised root
    /// must equal min path entry, parent-link consistency along the
    /// chain). Tracked via
    /// [`TreeStats::ancestry_invalid`](crate::node::stats::TreeStats).
    AncestryInvalid,
    /// Local outbound `TreeDeclaration` signing failed — the node's
    /// identity returned an error from `sign_declaration`. Tracked via
    /// [`TreeStats::outbound_sign_failed`](crate::node::stats::TreeStats).
    /// Fires on parent switch, self-root promotion, loop-detection
    /// recovery, parent update from inbound TreeAnnounce, periodic
    /// re-eval, parent-loss recovery, and first-RTT MMP parent eval.
    OutboundSignFailed,
}

/// Bloom-filter rejection reasons.
///
/// Each variant corresponds to a silent-rejection path in
/// `src/node/bloom.rs::handle_filter_announce`. The matching counters
/// already exist as direct fields on `BloomStats`; `record_reject`
/// dispatches into them so the typed enum stays the canonical entry
/// point for new rejection paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BloomReject {
    /// `FilterAnnounce::decode` returned an error. Tracked via
    /// [`BloomStats::decode_error`](crate::node::stats::BloomStats).
    DecodeError,
    /// Announce passed decode but the filter/size_class pair is
    /// internally inconsistent (`is_valid()` returned false). Tracked
    /// via [`BloomStats::invalid`](crate::node::stats::BloomStats).
    Invalid,
    /// Announce advertises a non-v1-compliant size class. Tracked via
    /// [`BloomStats::non_v1`](crate::node::stats::BloomStats).
    NonV1,
    /// Announce arrived from a peer with no `ActivePeer` record on
    /// this node. Tracked via
    /// [`BloomStats::unknown_peer`](crate::node::stats::BloomStats).
    UnknownPeer,
    /// Announce sequence number is not strictly greater than the
    /// peer's current stored sequence (replay or stale). Tracked via
    /// [`BloomStats::stale`](crate::node::stats::BloomStats).
    Stale,
    /// Announce filter's false-positive rate exceeds the configured
    /// `max_inbound_fpr` antipoison cap. Tracked via
    /// [`BloomStats::fill_exceeded`](crate::node::stats::BloomStats).
    FillExceeded,
}

/// Discovery rejection reasons.
///
/// Each variant corresponds to a silent-rejection path in
/// `src/node/handlers/discovery.rs` across request and response
/// processing. Matching counters already exist on `DiscoveryStats`;
/// `record_reject` dispatches into them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiscoveryReject {
    /// `LookupRequest::decode` returned an error. Tracked via
    /// [`DiscoveryStats::req_decode_error`](crate::node::stats::DiscoveryStats).
    ReqDecodeError,
    /// Request `request_id` already seen — dedup / loop protection.
    /// Tracked via
    /// [`DiscoveryStats::req_duplicate`](crate::node::stats::DiscoveryStats).
    ReqDuplicate,
    /// A request this node originated, flooded to its bloom-matching tree
    /// peers and circulated back to it by one of them. Dropped without being
    /// recorded, so the answer is accepted here rather than reverse-path
    /// forwarded to the peer that looped it. Tracked via
    /// [`DiscoveryStats::req_own_loopback`](crate::node::stats::DiscoveryStats).
    ///
    /// **This has a nonzero floor in healthy operation** and rises with the
    /// bloom fill ratio. It says nothing about the peer that delivered the
    /// copy, which is why it is not counted as [`Self::ReqDuplicate`].
    ReqOwnLoopback,
    /// Request dedup cache (`recent_requests`) is at capacity, so the
    /// `LookupRequest` is dropped without being forwarded. Tracked via
    /// [`DiscoveryStats::req_dedup_cache_full`](crate::node::stats::DiscoveryStats).
    ///
    /// Frozen at zero: a full cache now evicts its oldest entry and admits
    /// the request, counted as
    /// [`DiscoveryStats::req_dedup_evicted`](crate::node::stats::DiscoveryStats).
    /// The variant and its counter stay so an operator reading a dashboard
    /// across versions does not find the series missing.
    ReqDedupCacheFull,
    /// This node is the lookup target, but the link peer the request
    /// arrived from has spent its signing budget. Answering costs a fresh
    /// Schnorr signature per request, so the budget bounds what one
    /// neighbour can make this node sign. Tracked via
    /// [`DiscoveryStats::req_sign_rate_limited`](crate::node::stats::DiscoveryStats).
    ReqSignRateLimited,
    /// Request arrived with TTL=0 — no more forwarding hops allowed.
    /// Tracked via
    /// [`DiscoveryStats::req_ttl_exhausted`](crate::node::stats::DiscoveryStats).
    ReqTtlExhausted,
    /// `LookupResponse::decode` returned an error. Tracked via
    /// [`DiscoveryStats::resp_decode_error`](crate::node::stats::DiscoveryStats).
    RespDecodeError,
    /// Response arrived for an originated request but the target's
    /// public key was not in the identity cache, so the proof cannot
    /// be verified. Tracked via
    /// [`DiscoveryStats::resp_identity_miss`](crate::node::stats::DiscoveryStats).
    RespIdentityMiss,
    /// Response proof signature failed verification. Tracked via
    /// [`DiscoveryStats::resp_proof_failed`](crate::node::stats::DiscoveryStats).
    RespProofFailed,
    /// Response arrived on the originator path but carries no
    /// `request_id` this node has outstanding for the named target, so
    /// it answers no lookup of ours. Expected to be nonzero in healthy
    /// operation: the request is flooded to every qualifying tree peer,
    /// so duplicate replies land here after the first is accepted.
    /// Tracked via
    /// [`DiscoveryStats::resp_unsolicited`](crate::node::stats::DiscoveryStats).
    RespUnsolicited,
    /// Response could not be routed toward the origin: no reverse-path
    /// entry for the `request_id` and no greedy tree route to the
    /// origin. Tracked via
    /// [`DiscoveryStats::resp_no_route`](crate::node::stats::DiscoveryStats).
    RespNoRoute,
}

/// Noise-handshake rejection reasons.
///
/// Variants cover the state-machine cluster in
/// `handlers/handshake.rs` (msg1, msg2, and, on the next-side XX
/// handshake, msg3). `BadState` covers the bulk of the cluster: header
/// parse failures, crypto-step failures, identity not learned, index
/// allocator exhaustion, wire send failures, promotion failures, ACL
/// rejections, and admission-gate drops at max_peers / accept_connections.
/// `UnknownConnection` covers lookup-miss sites where an inbound message
/// arrived for a connection identifier we don't recognise (no pending
/// outbound for the receiver_idx in msg2; duplicate msg1 with no stored
/// msg2 to resend). `RekeyStaticMismatch` is carved out of the
/// `BadState` bulk so the one attacker-driven arm in the cluster has a
/// counter of its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HandshakeReject {
    /// Handshake state-machine rejection: header parse failed, crypto step
    /// failed, identity could not be learned, index allocator returned an
    /// error, msg2/msg3 send failed, promote_connection returned an error,
    /// ACL gate rejected the peer, or the admission gate fired
    /// (max_peers / accept_connections). The rekey static-key continuity
    /// gate also lived here until it was given its own
    /// [`RekeyStaticMismatch`](HandshakeReject::RekeyStaticMismatch)
    /// variant. Tracked via
    /// [`HandshakeStats::bad_state`](crate::node::stats::HandshakeStats).
    BadState,
    /// Inbound handshake message arrived but the connection identifier
    /// has no matching entry: msg2 for an unknown receiver_idx (no
    /// pending outbound handshake), duplicate msg1 with no stored msg2
    /// to resend, msg3 for an unknown receiver_idx (no pending inbound,
    /// no rekey-responder state). Tracked via
    /// [`HandshakeStats::unknown_connection`](crate::node::stats::HandshakeStats).
    UnknownConnection,
    /// Initiator-side rekey msg2 completed the Noise read, but the static
    /// key it revealed is not the key the established session is bound to
    /// — the msg2 did not come from the peer we are rekeying with. The
    /// rekey cycle is abandoned and the working session is left untouched.
    /// Unlike the rest of the cluster this arm cannot be reached by
    /// routine handshake noise: the rekey msg1 header travels in the
    /// clear, so a sustained rate here means an on-path attacker is
    /// forging rekey msg2 and suppressing key rotation. Tracked via
    /// [`HandshakeStats::rekey_static_mismatch`](crate::node::stats::HandshakeStats).
    RekeyStaticMismatch,
}

/// FSP session rejection reasons.
///
/// `UnknownSession` and `BadState` cover the session unknown-session
/// and state-machine cluster. `AddrMismatch` and `RekeyKeyMismatch`
/// cover the peer-identity binding checks on the XK msg3 receive path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SessionReject {
    /// Inbound session-layer message arrived for a remote address that
    /// has no corresponding `SessionEntry` — the session was never
    /// established, was torn down, or the peer is talking to a stale
    /// destination. Tracked via
    /// [`SessionStats::unknown_session`](crate::node::stats::SessionStats).
    /// Fires on encrypted data, SessionAck, SessionMsg3, SessionReceiverReport,
    /// and PathMtuNotification when the lookup returns `None`.
    UnknownSession,
    /// Inbound session-layer message arrived for a `SessionEntry` whose
    /// state is incompatible with the message type: encrypted data while
    /// the session is not yet `Established`, a SessionAck when the
    /// session is not `Initiating`, or a SessionMsg3 when the session
    /// is not `AwaitingMsg3`. Tracked via
    /// [`SessionStats::bad_state`](crate::node::stats::SessionStats).
    BadState,
    /// Inbound XK msg3 completed the handshake, but the initiator's
    /// static key does not derive the source address the datagram
    /// claimed — the peer is opening a session under another node's
    /// address. Tracked via
    /// [`SessionStats::addr_mismatch`](crate::node::stats::SessionStats).
    AddrMismatch,
    /// Inbound XK msg3 completed a responder-side rekey, but the
    /// initiator's static key differs from the key the session was
    /// established with — the rekey is not from the established peer.
    /// Tracked via
    /// [`SessionStats::rekey_key_mismatch`](crate::node::stats::SessionStats).
    RekeyKeyMismatch,
    /// A setup message named an established peer while our own rekey of
    /// that session was in flight, and our address sorted smaller, so the
    /// tie-break kept us as initiator and their msg1 was dropped. Tracked
    /// via [`SessionStats::rekey_tiebreak`](crate::node::stats::SessionStats).
    RekeyTiebreak,
    /// A setup message named an established peer while our own rekey of
    /// that session was in flight, and our address sorted larger, so we
    /// abandoned our rekey and answered as responder. The message carries
    /// no authenticator, so a sustained rate here means local key rotation
    /// is being suppressed. Tracked via
    /// [`SessionStats::rekey_yielded`](crate::node::stats::SessionStats).
    RekeyYielded,
    /// A setup message named an established peer that already holds a
    /// completed rekey awaiting cut-over, so the message was dropped
    /// rather than arming a second handshake. Tracked via
    /// [`SessionStats::rekey_pending`](crate::node::stats::SessionStats).
    RekeyPending,
    /// An inbound SessionAck naming a session we are initiating failed the
    /// XX msg2 read, or the negotiation payload carried with it. Neither
    /// carries an authenticator tying it to the initiation — on XX a msg2
    /// read proves the sender holds the static it presented, not that the
    /// static is the one we dialled — so the entry is kept and the handshake
    /// rolled back rather than discarded; a sustained rate here is either a
    /// broken path to the responder or somebody spraying forged acks to hold
    /// establishment down. Tracked via
    /// [`SessionStats::ack_handshake_failed`](crate::node::stats::SessionStats).
    AckHandshakeFailed,
    /// An inbound SessionAck read msg2 cleanly, but the static key it
    /// authenticated under is not the key we dialled. Separate from
    /// [`SessionReject::AckHandshakeFailed`] because it means something
    /// different: either a stale npub-to-address mapping is being retried,
    /// or somebody is answering our initiations under their own identity.
    /// The entry is kept, since the claimed source address is an envelope
    /// field and the second reading is available to anyone. Tracked via
    /// [`SessionStats::ack_identity_mismatch`](crate::node::stats::SessionStats).
    AckIdentityMismatch,
    /// A setup message was refused by the per-link-peer setup limiter
    /// before any handshake state was created or any ack sent. Tracked via
    /// [`SessionStats::setup_rate_limited`](crate::node::stats::SessionStats).
    SetupRateLimited,
    /// A session would have been created but the table is at
    /// `node.limits.max_sessions`. Refused rather than evicted: the
    /// deciding message is unauthenticated at this point, so evicting
    /// would hand a stranger a way to tear down established sessions.
    /// Tracked via
    /// [`SessionStats::table_full`](crate::node::stats::SessionStats).
    TableFull,
    /// A session would have been created but unauthenticated half-open
    /// entries already hold their share of the table. Bounds what a
    /// handshake flood can deny an established peer. Tracked via
    /// [`SessionStats::half_open_full`](crate::node::stats::SessionStats).
    HalfOpenFull,
}

/// MMP rejection reasons.
///
/// The outbound sign-failure sites in `handlers/mmp.rs` use
/// `RejectReason::Tree(TreeReject::OutboundSignFailed)` rather than
/// `RejectReason::Mmp(...)` because the outcome they represent
/// (tree-state side effect failed) is tree-classified. This enum
/// covers the receive-path silent-rejection sites in the same file:
/// `SenderReport` / `ReceiverReport` decode and unknown-peer drops.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MmpReject {
    /// `SenderReport::decode` or `ReceiverReport::decode` returned an
    /// error. Tracked via
    /// [`MmpStats::decode_error`](crate::node::stats::MmpStats).
    DecodeError,
    /// Report arrived from a peer with no `ActivePeer` record on this
    /// node. Tracked via
    /// [`MmpStats::unknown_peer`](crate::node::stats::MmpStats).
    UnknownPeer,
}

/// Forwarding-path rejection reasons.
///
/// Each variant corresponds to a silent-rejection path in
/// `src/node/dataplane/forwarding.rs::handle_session_datagram`. Matching
/// `ForwardingStats` counters already track packets and bytes for each
/// outcome; `record_reject` mirrors the packet-count side of the bump
/// for parity with the other rejection clusters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ForwardingReject {
    /// `SessionDatagramRef::decode` returned an error. Tracked via
    /// [`ForwardingStats::decode_error_packets`](crate::node::stats::ForwardingStats).
    DecodeError,
    /// Transit datagram whose TTL would reach zero on this hop, so it is
    /// dropped rather than forwarded. Charged for an arrival at TTL 1 as
    /// well as an already-exhausted arrival at TTL 0. Never charged for a
    /// datagram addressed to this node, whose delivery is not TTL-gated and
    /// is decided ahead of this test.
    /// Tracked via
    /// [`ForwardingStats::ttl_exhausted_packets`](crate::node::stats::ForwardingStats).
    TtlExhausted,
    /// `find_next_hop` returned None for the destination — no route.
    /// Tracked via
    /// [`ForwardingStats::drop_no_route_packets`](crate::node::stats::ForwardingStats).
    NoRoute,
    /// Outgoing link rejected the encoded datagram as larger than the
    /// link MTU. Tracked via
    /// [`ForwardingStats::drop_mtu_exceeded_packets`](crate::node::stats::ForwardingStats).
    MtuExceeded,
    /// Send call returned a non-MTU error (transport send failure,
    /// channel closed, etc.). Tracked via
    /// [`ForwardingStats::drop_send_error_packets`](crate::node::stats::ForwardingStats).
    SendError,
}

/// Transport-layer rejection reasons.
///
/// Currently covers the admission cap-hit path at the TCP and Tor
/// accept loops. Additional transport-side rejection variants
/// (framing errors, connection failures wired through to the node
/// stats path) can be added incrementally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TransportReject {
    /// Inbound TCP or Tor onion connection rejected because the
    /// per-transport inbound connection cap
    /// (`max_inbound_connections`) was already reached. Tracked via
    /// [`TransportStats::inbound_cap_exceeded`](crate::node::stats::TransportStats).
    InboundCapExceeded,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_reason_is_copy_and_eq() {
        fn requires_copy_eq_hash<T: Copy + Eq + std::hash::Hash>() {}
        requires_copy_eq_hash::<RejectReason>();
        requires_copy_eq_hash::<TreeReject>();
    }

    #[test]
    fn tree_ancestry_invalid_round_trips_through_match() {
        let r = RejectReason::Tree(TreeReject::AncestryInvalid);
        let matched = matches!(r, RejectReason::Tree(TreeReject::AncestryInvalid));
        assert!(matched);
    }

    #[test]
    fn reject_reason_equality_is_structural() {
        assert_eq!(
            RejectReason::Tree(TreeReject::AncestryInvalid),
            RejectReason::Tree(TreeReject::AncestryInvalid),
        );
    }

    #[test]
    fn bloom_reject_variants_round_trip() {
        let variants = [
            BloomReject::DecodeError,
            BloomReject::Invalid,
            BloomReject::NonV1,
            BloomReject::UnknownPeer,
            BloomReject::Stale,
            BloomReject::FillExceeded,
        ];
        for v in variants {
            let r = RejectReason::Bloom(v);
            assert!(matches!(r, RejectReason::Bloom(_)));
        }
    }

    #[test]
    fn discovery_reject_variants_round_trip() {
        let variants = [
            DiscoveryReject::ReqDecodeError,
            DiscoveryReject::ReqDuplicate,
            DiscoveryReject::ReqOwnLoopback,
            DiscoveryReject::ReqDedupCacheFull,
            DiscoveryReject::ReqTtlExhausted,
            DiscoveryReject::ReqSignRateLimited,
            DiscoveryReject::RespDecodeError,
            DiscoveryReject::RespIdentityMiss,
            DiscoveryReject::RespProofFailed,
            DiscoveryReject::RespUnsolicited,
        ];
        for v in variants {
            let r = RejectReason::Discovery(v);
            assert!(matches!(r, RejectReason::Discovery(_)));
        }
    }

    #[test]
    fn forwarding_reject_variants_round_trip() {
        let variants = [
            ForwardingReject::DecodeError,
            ForwardingReject::TtlExhausted,
            ForwardingReject::NoRoute,
            ForwardingReject::MtuExceeded,
            ForwardingReject::SendError,
        ];
        for v in variants {
            let r = RejectReason::Forwarding(v);
            assert!(matches!(r, RejectReason::Forwarding(_)));
        }
    }

    #[test]
    fn mmp_reject_variants_round_trip() {
        let variants = [MmpReject::DecodeError, MmpReject::UnknownPeer];
        for v in variants {
            let r = RejectReason::Mmp(v);
            assert!(matches!(r, RejectReason::Mmp(_)));
        }
    }

    #[test]
    fn transport_reject_inbound_cap_exceeded_round_trips() {
        let r = RejectReason::Transport(TransportReject::InboundCapExceeded);
        assert!(matches!(
            r,
            RejectReason::Transport(TransportReject::InboundCapExceeded)
        ));
    }
}
