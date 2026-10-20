//! End-to-end session message handlers.
//!
//! Handles locally-delivered session payloads from SessionDatagram envelopes.
//! Dispatches based on FSP common prefix phase to specific handlers for
//! SessionSetup (Noise XK msg1), SessionAck (msg2), SessionMsg3 (msg3),
//! encrypted data, and error signals (CoordsRequired, PathBroken).

use crate::NodeAddr;
use crate::cache::Funding;
use crate::ipv6tun::icmp::IcmpContext;
use crate::ipv6tun::outbound::{Mesh, Outcome, Route};
use crate::node::handlers::mmp::format_throughput;
use crate::node::rate_limit::Msg1Class;
use crate::node::reject::{RejectReason, SessionReject};
use crate::node::session::{
    SealFailure, SessionClock, SessionEntry, SessionInstant, session_params,
};
use crate::node::{Node, NodeError};
use crate::noise::{XK_HANDSHAKE_MSG1_SIZE, XK_HANDSHAKE_MSG2_SIZE, XK_HANDSHAKE_MSG3_SIZE};
#[cfg(unix)]
use crate::proto::fmp::wire::{
    ESTABLISHED_HEADER_SIZE, FLAG_KEY_EPOCH, FLAG_SP, build_established_header,
};
use crate::proto::framing::FIPS_OVERHEAD;
use crate::proto::fsp::quorum::QuorumVerdict;
use crate::proto::fsp::wire::{
    FSP_COMMON_PREFIX_SIZE, FSP_FLAG_CP, FSP_FLAG_K, FSP_HEADER_SIZE, FSP_PHASE_ESTABLISHED,
    FSP_PHASE_MSG1, FSP_PHASE_MSG2, FSP_PHASE_MSG3, FSP_PORT_HEADER_SIZE, FSP_PORT_IPV6_SHIM,
    FspCommonPrefix, FspEncryptedHeader, fsp_strip_inner_header, parse_encrypted_coords,
};
use crate::proto::fsp::{
    FspAction, FspInnerFlags, SessionAck, SessionMessageType, SessionMsg3, SessionSetup,
    mark_ipv6_ecn_ce,
};
#[cfg(unix)]
use crate::proto::link::LinkMessageType;
#[cfg(unix)]
use crate::proto::link::SESSION_DATAGRAM_HEADER_SIZE;
use crate::proto::link::SessionDatagram;
use crate::proto::mmp::{
    BackoffUpdate, MmpAction, MmpSessionState, PathMtuNotification, ReceiverReport, SendResult,
    SessionReceiverReport, SessionReportKind, SessionReportSnapshot, SessionSenderReport,
};
use crate::proto::mmp::{MAX_SESSION_REPORT_INTERVAL_MS, MIN_SESSION_REPORT_INTERVAL_MS};
use crate::proto::probe::LookupOutcomeKind;
use crate::proto::routing::{CoordsRequired, MtuExceeded, PathBroken, RoutingSignalType};
use crate::proto::stp::{coords_wire_size, encode_coords};
#[cfg(unix)]
use crate::transport::TransportHandle;
use fips_core::proto::rekey::{EpochTag, NodeKeys, Output, Params, Reason, Role};
use fips_core::time::Clock as _;
use secp256k1::PublicKey;
use tracing::{debug, info, trace, warn};

/// Minimum interval between path-MTU releases driven by `PathBroken` for one
/// destination.
///
/// `PathBroken` is unauthenticated, so a release is a remote party's claim
/// that the path a tightened MTU described is gone. Without an interval the
/// claim can be repeated at line rate, discarding a genuinely learned
/// bottleneck as fast as it is relearned. Raising it defers a legitimate
/// release after a second real break, which costs throughput on the new path
/// but never a blackhole, since the deferred value is the tighter one.
pub(in crate::node) const PATH_MTU_RELEASE_MIN_INTERVAL: std::time::Duration =
    std::time::Duration::from_millis(1000);

/// Bytes the link layer adds to an encoded `SessionDatagram` on its way to the
/// wire: the established FMP header, the 4-byte session-relative timestamp and
/// the AEAD tag. Mirrors the buffer `send_encrypted_link_message_with_ce`
/// builds.
///
/// Spelled out in full rather than through the `crate::proto::fmp::wire`
/// import above, which is `#[cfg(unix)]`. This constant feeds `link_wire_len`,
/// whose caller `send_session_datagram` is compiled on every platform, so
/// taking the name from that import fails to build on Windows.
const LINK_FRAME_OVERHEAD: usize =
    crate::proto::fmp::wire::ESTABLISHED_HEADER_SIZE + 4 + crate::noise::TAG_SIZE;

/// Wire size of an encoded `SessionDatagram` of `encoded_len` bytes.
fn link_wire_len(encoded_len: usize) -> usize {
    encoded_len + LINK_FRAME_OVERHEAD
}

/// Divisor giving the share of the session table that unauthenticated
/// half-open entries may hold, as `max_sessions / DIVISOR`.
///
/// Two means a reconnect storm, where every peer that had a session
/// initiates at once after a restart or a healed partition, still fits in
/// half the table; a tighter share bites four times sooner and is felt by
/// a hub before it is felt by an attacker. Half-open entries end with their
/// last candidate, 40 s after its setup, while established ones survive
/// `idle_timeout_secs`, so they turn over faster than the share suggests.
/// Lowering the divisor raises the share, which lets a handshake flood
/// crowd out peers that complete; raising it refuses legitimate initiators
/// sooner in a storm.
const HALF_OPEN_SHARE_DIVISOR: usize = 2;

/// How long after the node goes from no peers to at least one that a TUN
/// packet to a destination no lookup is running for (no tree peer's filter
/// reaches it, or its backoff window is open; see `held_fate`) is still held
/// rather than answered with ICMPv6 no-route.
///
/// A node's filters reach it only once its links complete their handshakes
/// (resends at 1, 2, 4, 8 and 16 s within the 30 s `handshake_timeout_secs`),
/// and each hop then forwards a changed filter after a 500 ms debounce
/// (`node.bloom.update_debounce_ms`), so 30 s after the first link comes up
/// covers the rest of the first links and a few hops of propagation behind
/// them. The value has no measured basis. The cost: inside the hold a sender
/// behind a gateway can fill the held-destination table, which the age bound
/// then releases.
const BLOOM_CONVERGENCE_HOLD: std::time::Duration = std::time::Duration::from_secs(30);

/// Whether routing information may still be arriving: the node has no peers,
/// or gained its first one less than [`BLOOM_CONVERGENCE_HOLD`] ago.
///
/// Sans-IO: the caller reports the peer table and the time.
#[derive(Default)]
pub(in crate::node) struct RoutingHold {
    /// When the node was first seen with peers after having none.
    peers_since: Option<std::time::Instant>,
}

impl RoutingHold {
    /// Note whether the node has peers at `now`. Going from none to some
    /// starts the hold; having none clears the start, so the next peer
    /// re-arms it.
    pub(in crate::node) fn observe(&mut self, has_peers: bool, now: std::time::Instant) {
        if !has_peers {
            self.peers_since = None;
        } else if self.peers_since.is_none() {
            self.peers_since = Some(now);
        }
    }

    /// Whether the hold applies at `now`.
    pub(in crate::node) fn active(&self, now: std::time::Instant) -> bool {
        match self.peers_since {
            None => true,
            Some(since) => now.saturating_duration_since(since) < BLOOM_CONVERGENCE_HOLD,
        }
    }

    /// Move the start of the hold back by `by`, so a test can stand outside
    /// it without waiting.
    #[cfg(test)]
    pub(in crate::node) fn backdate(&mut self, by: std::time::Duration) {
        if let Some(since) = self.peers_since.as_mut() {
            *since = since
                .checked_sub(by)
                .expect("host uptime exceeds the backdate");
        }
    }
}

/// What to do with a TUN packet whose destination has no session, given what
/// the lookup gate decided.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum HeldFate {
    /// Hold it: a lookup is pending, or routing may still be converging.
    Hold,
    /// Answer it with ICMPv6 no-route: nothing is working to reach it.
    Answer,
    /// Drop it unanswered: the destination is a direct peer or has a next
    /// hop, so the session setup failed on the link rather than for want of
    /// a route, and a retransmit retries it.
    Discard,
}

/// Decide a held packet's fate from the lookup outcome.
///
/// `Sent` and `Deduplicated` mean a lookup is pending and its timeout
/// releases the packets. The others mean no lookup is running: they are held
/// only while the routing hold applies, since the filter or tree that would
/// reach the target may still be arriving. `Suppressed` is held inside the
/// hold because, with backoff enabled, the first packet's bloom miss records
/// a failure and its retransmit is then suppressed.
///
/// `routed` says the destination is a direct peer or has a next hop, so the
/// session setup failed on its send, not for want of a route. A tree-only
/// lookup cannot vouch for a non-tree neighbour or a destination reached by
/// tree coordinates, so outside the hold such a packet is dropped rather
/// than answered: the failure may pass, and the next retransmit retries.
fn held_fate(kind: LookupOutcomeKind, in_hold: bool, routed: bool) -> HeldFate {
    match kind {
        LookupOutcomeKind::Sent | LookupOutcomeKind::Deduplicated => HeldFate::Hold,
        LookupOutcomeKind::BloomMiss
        | LookupOutcomeKind::ZeroFanout
        | LookupOutcomeKind::Suppressed => {
            if in_hold {
                HeldFate::Hold
            } else if routed {
                HeldFate::Discard
            } else {
                HeldFate::Answer
            }
        }
    }
}

/// When a held destination's age started, read by the held-packet backstop.
#[derive(Copy, Clone, Debug)]
pub(in crate::node) struct HeldStamp {
    /// When the destination was first held, or when the latest lookup or
    /// session that can settle it started.
    pub(in crate::node) since: std::time::Instant,
    /// Whether a lookup has already restarted the age since the destination
    /// was first held. A packet riding a pending lookup restarts it only when
    /// this is unset, so a stream of such packets cannot keep the destination
    /// young while that lookup is stalled.
    pub(in crate::node) lookup_stamped: bool,
}

impl HeldStamp {
    /// A stamp for a destination first held at `now`.
    pub(in crate::node) fn new(now: std::time::Instant) -> Self {
        Self {
            since: now,
            lookup_stamped: false,
        }
    }

    /// Restart the age at `now` because `cause` started work that can settle
    /// the destination.
    ///
    /// Riding a pending lookup restarts it only once per held destination:
    /// the lookup started before the packet, so a later packet riding it adds
    /// no new work, and restarting on each one would let a stream of packets
    /// hold the destination for as long as the lookup is stalled.
    fn restart(&mut self, cause: Restamp, now: std::time::Instant) {
        match cause {
            Restamp::LookupRidden if self.lookup_stamped => {}
            Restamp::LookupSent | Restamp::LookupRidden => {
                self.since = now;
                self.lookup_stamped = true;
            }
            Restamp::SessionStarted => self.since = now,
        }
    }
}

/// What started the work that restarts a held destination's age.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Restamp {
    /// This node sent a lookup for the destination.
    LookupSent,
    /// The packet rode a lookup already pending for the destination.
    LookupRidden,
    /// A session to the destination was started.
    SessionStarted,
}

/// Whether [`Node::queue_pending_packet`] held the packet.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[must_use = "a refused packet was dropped; a caller that leaves it dropped says why"]
pub(in crate::node) enum Held {
    /// Queued behind the destination's other packets.
    Queued,
    /// Dropped: the held-destination table is full and the destination is new.
    Refused,
}

#[cfg(test)]
mod held_tests {
    use super::{BLOOM_CONVERGENCE_HOLD, HeldFate, HeldStamp, Restamp, RoutingHold, held_fate};
    use crate::proto::probe::LookupOutcomeKind;
    use std::time::{Duration, Instant};

    #[test]
    fn held_fate_holds_only_while_a_lookup_is_pending_or_inside_the_hold_for_unconverged_routing() {
        use HeldFate::{Answer, Discard, Hold};
        use LookupOutcomeKind::*;
        let table = [
            (Sent, true, false, Hold),
            (Sent, false, false, Hold),
            (Sent, false, true, Hold),
            (Deduplicated, true, false, Hold),
            (Deduplicated, false, false, Hold),
            (Deduplicated, false, true, Hold),
            (BloomMiss, true, false, Hold),
            (BloomMiss, true, true, Hold),
            (BloomMiss, false, false, Answer),
            (BloomMiss, false, true, Discard),
            (ZeroFanout, true, false, Hold),
            (ZeroFanout, true, true, Hold),
            (ZeroFanout, false, false, Answer),
            (ZeroFanout, false, true, Discard),
            (Suppressed, true, false, Hold),
            (Suppressed, true, true, Hold),
            (Suppressed, false, false, Answer),
            (Suppressed, false, true, Discard),
        ];
        for (kind, in_hold, routed, want) in table {
            assert_eq!(
                held_fate(kind, in_hold, routed),
                want,
                "{kind:?}, in_hold={in_hold}, routed={routed}"
            );
        }
    }

    #[test]
    fn a_held_stamp_restarts_on_each_lookup_sent_and_session_started_but_only_once_for_packets_riding_a_lookup()
     {
        let t0 = Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);

        let mut ridden = HeldStamp::new(t0);
        ridden.restart(Restamp::LookupRidden, at(30));
        assert_eq!(ridden.since, at(30), "the first ride restarts the age");
        ridden.restart(Restamp::LookupRidden, at(60));
        ridden.restart(Restamp::LookupRidden, at(90));
        assert_eq!(ridden.since, at(30), "later rides leave it alone");

        let mut sent = HeldStamp::new(t0);
        sent.restart(Restamp::LookupSent, at(10));
        sent.restart(Restamp::LookupRidden, at(20));
        assert_eq!(
            sent.since,
            at(10),
            "a ride after a sent lookup adds nothing"
        );
        sent.restart(Restamp::LookupSent, at(40));
        assert_eq!(sent.since, at(40), "each new lookup restarts the age");
        sent.restart(Restamp::SessionStarted, at(50));
        assert_eq!(sent.since, at(50), "a session start restarts the age");
        sent.restart(Restamp::SessionStarted, at(70));
        assert_eq!(sent.since, at(70), "and so does each later one");

        let mut session = HeldStamp::new(t0);
        session.restart(Restamp::SessionStarted, at(5));
        session.restart(Restamp::LookupRidden, at(15));
        assert_eq!(
            session.since,
            at(15),
            "a session start does not use up the one ride"
        );
    }

    #[test]
    fn routing_hold_is_active_with_no_peers_and_for_the_hold_after_peers_appear_and_rearms_after_they_all_go()
     {
        let t0 = Instant::now();
        let mut hold = RoutingHold::default();
        assert!(hold.active(t0), "no observation yet means no peers");

        hold.observe(false, t0);
        assert!(hold.active(t0 + Duration::from_secs(600)), "no peers: held");

        let up = t0 + Duration::from_secs(1);
        hold.observe(true, up);
        assert!(hold.active(up));
        assert!(hold.active(up + BLOOM_CONVERGENCE_HOLD - Duration::from_millis(1)));
        assert!(!hold.active(up + BLOOM_CONVERGENCE_HOLD));

        // Still having peers does not move the start.
        hold.observe(true, up + Duration::from_secs(20));
        assert!(!hold.active(up + BLOOM_CONVERGENCE_HOLD));

        // All peers gone: held again, and the next peer re-arms the hold.
        let down = up + Duration::from_secs(100);
        hold.observe(false, down);
        assert!(hold.active(down));
        let back = down + Duration::from_secs(5);
        hold.observe(true, back);
        assert!(hold.active(back + BLOOM_CONVERGENCE_HOLD - Duration::from_millis(1)));
        assert!(!hold.active(back + BLOOM_CONVERGENCE_HOLD));
    }
}

/// Inputs to `try_send_session_data_pipelined` — the FSP+FMP pipelined
/// fast path that hands both AEAD operations to the encrypt worker
/// in a single dispatch.
#[cfg(unix)]
struct PipelinedSend<'a> {
    dest_addr: &'a NodeAddr,
    payload: &'a [u8],
    now: SessionInstant,
    fsp_flags: u8,
    /// The DataPacket body, port header included, before the inner header.
    body: &'a [u8],
    my_coords: Option<&'a crate::proto::stp::TreeCoordinate>,
    dest_coords: Option<&'a crate::proto::stp::TreeCoordinate>,
}

/// Outcome of the routing-signal admission test.
///
/// `Unbound` and `Forged` are both refusals, kept apart because they mean
/// different things to an operator. `Unbound` is consistent with a benign
/// race — a signal arriving just after a local session teardown. `Forged`
/// is not consistent with any honest emitter, so it is the sharper
/// indicator and is counted separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SignalVerdict {
    /// The named destination is an address this node bound itself.
    Admit,
    /// The src/dest pairing is structurally impossible for a legitimate
    /// emitter.
    Forged,
    /// No qualifying session entry exists for the named destination.
    Unbound,
}

impl SignalVerdict {
    /// Short stable label for the `verdict` log field.
    fn label(self) -> &'static str {
        match self {
            Self::Admit => "admit",
            Self::Forged => "forged",
            Self::Unbound => "unbound",
        }
    }
}

impl Node {
    /// Handle a locally-delivered session datagram payload.
    ///
    /// Called from `handle_session_datagram()` when `dest_addr == self.node_addr()`.
    /// Dispatches based on the 4-byte FSP common prefix:
    ///
    /// - Phase 0x1 → SessionSetup (handshake msg1)
    /// - Phase 0x2 → SessionAck (handshake msg2)
    /// - Phase 0x3 → SessionMsg3 (XK handshake msg3)
    /// - Phase 0x0 + U flag → plaintext error signal (CoordsRequired/PathBroken)
    /// - Phase 0x0 + !U → encrypted session message (data, reports, etc.)
    ///
    /// `src_addr` is the datagram's claimed source, an envelope field the
    /// sender chooses. `link_peer` is the authenticated FMP peer the datagram
    /// arrived over, and is the only identity on this path worth keying a
    /// limiter on.
    pub(in crate::node) async fn handle_session_payload(
        &mut self,
        src_addr: &NodeAddr,
        link_peer: &NodeAddr,
        payload: &[u8],
        path_mtu: u16,
        ce_flag: bool,
    ) {
        let prefix = match FspCommonPrefix::parse(payload) {
            Some(p) => p,
            None => {
                debug!(
                    len = payload.len(),
                    "Session payload too short for FSP prefix"
                );
                return;
            }
        };

        let inner = &payload[FSP_COMMON_PREFIX_SIZE..];

        match prefix.phase {
            FSP_PHASE_MSG1 => {
                self.handle_session_setup(src_addr, link_peer, inner).await;
            }
            FSP_PHASE_MSG2 => {
                self.handle_session_ack(src_addr, inner).await;
            }
            FSP_PHASE_MSG3 => {
                self.handle_session_msg3(src_addr, inner).await;
            }
            FSP_PHASE_ESTABLISHED if prefix.is_unencrypted() => {
                // Plaintext error signals: read msg_type from first byte after prefix
                if inner.is_empty() {
                    debug!("Empty plaintext error signal");
                    return;
                }
                let error_type = inner[0];
                let error_body = &inner[1..];
                match RoutingSignalType::from_byte(error_type) {
                    Some(RoutingSignalType::CoordsRequired) => {
                        self.handle_coords_required(src_addr, error_body).await;
                    }
                    Some(RoutingSignalType::PathBroken) => {
                        self.handle_path_broken(src_addr, link_peer, error_body)
                            .await;
                    }
                    Some(RoutingSignalType::MtuExceeded) => {
                        self.handle_mtu_exceeded(src_addr, error_body).await;
                    }
                    _ => {
                        debug!(error_type, "Unknown plaintext error signal type");
                    }
                }
            }
            FSP_PHASE_ESTABLISHED => {
                self.handle_encrypted_session_msg(src_addr, payload, path_mtu, ce_flag)
                    .await;
            }
            _ => {
                debug!(phase = prefix.phase, "Unknown FSP phase");
            }
        }
    }

    /// Handle an encrypted session message (phase 0x0, U flag clear).
    ///
    /// Full FSP receive pipeline:
    /// 1. Parse FspEncryptedHeader (12 bytes) → counter, flags, header_bytes
    /// 2. If CP flag: parse past the cleartext coords
    /// 3. Session lookup (must be Established)
    /// 4. AEAD decrypt with AAD = header_bytes
    /// 5. Strip FSP inner header → timestamp, msg_type, inner_flags
    /// 6. Dispatch by msg_type
    async fn handle_encrypted_session_msg(
        &mut self,
        src_addr: &NodeAddr,
        payload: &[u8],
        path_mtu: u16,
        ce_flag: bool,
    ) {
        // Parse the 12-byte encrypted header (includes the 4-byte prefix)
        let header = match FspEncryptedHeader::parse(payload) {
            Some(h) => h,
            None => {
                debug!(
                    len = payload.len(),
                    "Encrypted session message too short for FSP header"
                );
                return;
            }
        };

        // Determine where ciphertext starts (after header, optionally after coords)
        let mut ciphertext_offset = FSP_HEADER_SIZE;

        // If CP flag set, parse cleartext coords between header and ciphertext
        if header.has_coords() {
            let coord_data = &payload[FSP_HEADER_SIZE..];
            match parse_encrypted_coords(coord_data) {
                // Not cached here: the forwarding path's warm write has
                // already offered these coordinates to the cache, from this
                // same datagram and through the same checks.
                Ok((_, _, bytes_consumed)) => {
                    ciphertext_offset += bytes_consumed;
                }
                Err(e) => {
                    debug!(error = %e, "Failed to parse coords from encrypted session message");
                    return;
                }
            }
        }

        // Look up session entry — must be Established to decrypt
        {
            let entry = match self.sessions.get(src_addr) {
                Some(e) => e,
                None => {
                    debug!(src = %self.peer_display_name(src_addr), "Encrypted session message for unknown session");
                    self.stats_mut()
                        .record_reject(RejectReason::Session(SessionReject::UnknownSession));
                    return;
                }
            };
            // Drop encrypted data if session is not yet established.
            // With XK, the responder must wait for msg3 before it can decrypt.
            if !entry.is_established() {
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "Encrypted message but session not established (awaiting handshake completion)"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Session(SessionReject::BadState));
                return;
            }
        }

        // The received K-bit is only an ordering hint for the
        // trial-decrypt cascade — it picks which key epoch to try first.
        // Correctness never depends on it: the epoch is the one whose key
        // authenticates the frame.
        let received_k_bit = header.flags & FSP_FLAG_K != 0;

        let mut entry = match self.sessions.remove(src_addr) {
            Some(e) => e,
            None => return,
        };

        let now = Self::session_now();
        let local = self.session_node_keys();

        // The session's rekey machine tries every key it holds on the
        // unmodified frame, runs the row of the epoch that authenticated it
        // (a frame under the pending epoch is the cutover; one under the
        // current epoch is the peer heard there; one under the previous
        // epoch counts for nothing but itself), and writes the plaintext
        // into the frame's own buffer for delivery.
        let mut frame = payload.to_vec();
        let out = entry.step_frame(
            &mut frame,
            ciphertext_offset,
            header.counter,
            received_k_bit,
            now,
            &local,
        );
        let mut delivered = None;
        let mut rest_out = Vec::with_capacity(out.len());
        for output in out {
            match output {
                Output::Deliver { range, tag, .. } => delivered = Some((range, tag)),
                Output::Reject(reason @ (Reason::FrameUnauthenticated | Reason::Replay)) => {
                    // Every held epoch refused it — a genuine drop. The
                    // upper layer retransmits.
                    debug!(
                        src = %self.peer_display_name(src_addr),
                        counter = header.counter,
                        ?reason,
                        "Session AEAD decryption failed (all epochs)"
                    );
                }
                other => rest_out.push(other),
            }
        }

        self.sessions.insert(*src_addr, entry);
        self.run_session_outputs(src_addr, rest_out, false).await;

        let Some((range, tag)) = delivered else {
            return;
        };
        let Some(plaintext) = frame.get(range) else {
            return;
        };

        // Strip FSP inner header (6 bytes)
        let (timestamp, msg_type, inner_flags_byte, rest) = match fsp_strip_inner_header(plaintext)
        {
            Some(parts) => parts,
            None => {
                debug!(src = %self.peer_display_name(src_addr), "Decrypted payload too short for FSP inner header");
                return;
            }
        };

        // MMP per-message recording on RX path, for the epoch MMP measures
        // only: a frame the peer sealed under the epoch a cutover retired
        // carries that epoch's counter and timestamp, and recording it would
        // count every later frame of the new epoch as reordered.
        if let Some(entry) = self.sessions.get_mut(src_addr)
            && let Some(mmp) = entry.epoch_mmp(tag)
        {
            let now_ms = crate::time::mono_ms();
            mmp.receiver
                .record_recv(header.counter, timestamp, plaintext.len(), ce_flag, now_ms);
            // Spin bit: advance state machine for correct TX reflection.
            // RTT samples not fed into SRTT — timestamp-echo provides
            // accurate RTT; spin bit includes variable inter-frame delays.
            let inner_flags = FspInnerFlags::from_byte(inner_flags_byte);
            let _spin_rtt = mmp
                .spin_bit
                .rx_observe(inner_flags.spin_bit, header.counter, now_ms);
        }

        // Feed path_mtu from datagram envelope to MMP path MTU tracking.
        // Done for ALL session messages, not just DataPackets, so the
        // destination learns the path MTU even when only reports flow.
        if let Some(entry) = self.sessions.get_mut(src_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.path_mtu.observe_incoming_mtu(path_mtu);
        }

        // Dispatch by msg_type
        match SessionMessageType::from_byte(msg_type) {
            Some(SessionMessageType::DataPacket) => {
                // msg_type 0x10: port-multiplexed service dispatch
                if rest.len() < FSP_PORT_HEADER_SIZE {
                    debug!(len = rest.len(), "DataPacket too short for port header");
                    return;
                }
                let src_port = u16::from_le_bytes([rest[0], rest[1]]);
                let dst_port = u16::from_le_bytes([rest[2], rest[3]]);
                let service_payload = &rest[FSP_PORT_HEADER_SIZE..];

                match dst_port {
                    FSP_PORT_IPV6_SHIM => {
                        use crate::Ipv6Address;
                        let src_ipv6 = Ipv6Address::from_node_addr(src_addr).to_ipv6().octets();
                        let dst_ipv6 = Ipv6Address::from_node_addr(self.node_addr())
                            .to_ipv6()
                            .octets();

                        match crate::ipv6tun::ipv6_shim::decompress_ipv6(
                            service_payload,
                            src_ipv6,
                            dst_ipv6,
                        ) {
                            Some(mut packet) => {
                                if ce_flag {
                                    mark_ipv6_ecn_ce(&mut packet);
                                    self.metrics().congestion.ce_received.inc();
                                }
                                if let Some(tun_tx) = &self.supervisor.ipv6tun.tun_tx {
                                    if let Err(e) = tun_tx.send(packet) {
                                        debug!(error = %e, "Failed to deliver decompressed IPv6 packet to TUN");
                                    }
                                } else {
                                    trace!(
                                        src = %self.peer_display_name(src_addr),
                                        "IPv6 shim packet decompressed (no TUN interface)"
                                    );
                                }
                            }
                            None => {
                                debug!(
                                    src = %self.peer_display_name(src_addr),
                                    len = service_payload.len(),
                                    "IPv6 shim decompression failed"
                                );
                            }
                        }
                    }
                    _ => {
                        // Every other port belongs to the native datagram API,
                        // which decides between an established flow, a listener
                        // and a drop. The same decision serves the debug
                        // arrival command, so the rule was exercised before
                        // this call site existed.
                        // The peer's key comes from the session entry rather
                        // than from the wire: the handler above refuses
                        // anything but an Established session, and an
                        // Established entry holds the key its handshake
                        // attested. Nothing has to invert the node address.
                        let payload = service_payload.to_vec();
                        // The entry was removed for the trial-decrypt cascade
                        // and re-inserted above, and this arm is reached only
                        // for an Established session, so the lookup finds one.
                        // It is written as a lookup rather than an unwrap
                        // because a future path that skipped the re-insert
                        // would otherwise panic on a peer's datagram. Skipping
                        // is scoped to the native dispatch alone: the idle
                        // timer and the pending-outbound flush at the end of
                        // this function are this message's bookkeeping and are
                        // owed whether or not it had anywhere to go.
                        if let Some(peer_key) =
                            self.sessions.get(src_addr).and_then(SessionEntry::peer_key)
                        {
                            let outcome = self
                                .native_deliver(*src_addr, peer_key, src_port, dst_port, payload);
                            if let crate::native::link::Outcome::Dropped(why) = outcome {
                                debug!(
                                    src = %self.peer_display_name(src_addr),
                                    dst_port,
                                    why = why.as_str(),
                                    "Unknown FSP service port, dropping DataPacket"
                                );
                            }
                        }
                    }
                }
            }
            Some(SessionMessageType::SenderReport) => {
                self.handle_session_sender_report(src_addr, rest);
            }
            Some(SessionMessageType::ReceiverReport) => {
                self.handle_session_receiver_report(src_addr, tag, rest);
            }
            Some(SessionMessageType::PathMtuNotification) => {
                self.handle_session_path_mtu_notification(src_addr, rest);
            }
            Some(SessionMessageType::CoordsWarmup) => {
                // Standalone coordinate warming — coords already extracted
                // from CP flag by transit nodes. No action needed at endpoint.
                trace!(src = %self.peer_display_name(src_addr), "CoordsWarmup received");
            }
            _ => {
                debug!(src = %self.peer_display_name(src_addr), msg_type, "Unknown session message type, dropping");
            }
        }

        // Only application data resets the idle timer and traffic counters —
        // MMP reports (SenderReport, ReceiverReport, PathMtuNotification) do not.
        if msg_type == SessionMessageType::DataPacket.to_byte()
            && let Some(entry) = self.sessions.get_mut(src_addr)
        {
            entry.record_recv(rest.len());
            entry.touch(Self::session_now());
        }

        // Flush any pending outbound packets (e.g., simultaneous initiation
        // where responder also had queued outbound packets)
        self.flush_pending_packets(src_addr).await;
        self.flush_pending_native(src_addr).await;
    }

    /// Handle an incoming SessionSetup (Noise XK msg1).
    ///
    /// The remote node wants to establish an end-to-end session with us.
    /// We create an XK responder handshake, process msg1, send SessionAck with msg2,
    /// and hold the handshake as a responder candidate awaiting its msg3.
    async fn handle_session_setup(
        &mut self,
        src_addr: &NodeAddr,
        link_peer: &NodeAddr,
        inner: &[u8],
    ) {
        let setup = match SessionSetup::decode(inner) {
            Ok(s) => s,
            Err(e) => {
                debug!(error = %e, "Malformed SessionSetup");
                return;
            }
        };

        if setup.handshake_payload.len() != XK_HANDSHAKE_MSG1_SIZE {
            debug!(
                len = setup.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG1_SIZE,
                "Invalid handshake payload size in SessionSetup"
            );
            return;
        }

        // Catch the named session's machine up first. The 1 s tick can
        // process a deadline or start instant up to a second late, and a
        // setup admitted or judged in that second meets a table and a state
        // the overdue poll is about to change: the poll can end the session,
        // so the setup would open a new entry the admission below never
        // charged, and it can end a completed rekey of this node's, which the
        // smaller node would otherwise keep by refusing the setup. Start
        // instants are polled too, so the setup can meet a rekey of this
        // node's that the poll has just started; a shell that polls at the
        // machine's next wake starts it at that instant, before the setup
        // arrives, so this is the order the machine is built for. The poll
        // runs ahead of the limiter because it is no step of the setup: it
        // does only work already due, sends nothing for the setup, and leaves
        // nothing due until the machine's next instant, so a flood of setups
        // naming the address polls it no more often than a timer would.
        let now = Self::session_now();
        self.poll_overdue(src_addr, now).await;

        // Meter the setup before anything is spent on it. This sits ahead of
        // every step of the setup into a session machine, so of every ack it
        // asks for (the stored ack a resent setup draws, and a new
        // candidate's alike): a refused msg1 emits nothing at all, which is
        // what bounds the ack amplification. It also precedes every responder
        // handshake construction, so a refusal costs no crypto. Moving it
        // below the existing-entry lookup would leave the stored-ack resend
        // unmetered.
        //
        // The class is read from the session table but the *key* is the link
        // peer: `src_addr` is chosen by the sender, so keying on it would be
        // no limit at all. A setup naming an established peer cannot grow the
        // table and is metered separately, so that a stranger flood over a
        // shared link cannot stop that peer's rekey from arming.
        // Population cap, ahead of the limiter so a full table costs no
        // token, no responder handshake and no ack. The predicate is "would
        // admitting this grow the table", not "is this a stranger": `class`
        // is Stranger for an existing entry still being set up too, and
        // refusing those would break in-flight legitimate handshakes and
        // the duplicate-ack resend. A setup joining such an entry as a new
        // candidate is checked against the half-open share below, once its
        // machine has said it would hold it, so that refusal comes after the
        // limiter and costs the link peer a token. Same shape as the pending-destination cap
        // in `queue_pending_packet`. Refuse rather than evict: msg1 is
        // unauthenticated here, so evicting would hand a stranger a teardown
        // primitive it does not have.
        if !self.admit_new_session(src_addr) {
            return;
        }

        let class = if self
            .sessions
            .get(src_addr)
            .is_some_and(|e| e.is_established())
        {
            Msg1Class::EstablishedLink
        } else {
            Msg1Class::Stranger
        };
        if !self
            .setup_rate_limiter
            .try_admit(link_peer, class, self.setup_now())
        {
            debug!(
                link_peer = %self.peer_display_name(link_peer),
                src = %self.peer_display_name(src_addr),
                ?class,
                "SessionSetup rate limited"
            );
            self.stats_mut()
                .record_reject(RejectReason::Session(SessionReject::SetupRateLimited));
            return;
        }

        // Every setup naming the address is its session machine's: one
        // naming an established peer is a rekey setup, any other a first
        // handshake's, and either way the machine holds it as a candidate
        // and asks for its SessionAck, answers a resent setup with the ack it
        // already sent, or refuses it. It changes nothing else: a setup,
        // forged or genuine, never holds back or cancels this node's own
        // attempt, and only an authenticated msg3 completes a candidate. No
        // setup is ever answered with a msg3 this node retains: while its
        // first msg3 waits for the peer, the smaller node refuses the setup
        // and the larger holds it as a candidate.
        let local = self.session_node_keys();
        let Some(entry) = self.sessions.get(src_addr) else {
            self.open_inbound_session(src_addr, link_peer, &setup, &local, now)
                .await;
            return;
        };
        let established = entry.is_established();
        // A setup that would add a candidate to a session still being set
        // up takes one more place of the half-open share; a copy of a held
        // setup, a refused one and one replacing an evicted candidate take
        // none.
        if !established
            && entry.grows(now, &setup.handshake_payload, *link_peer)
            && !self.admit_half_open_candidate(src_addr)
        {
            return;
        }
        let entry = self.sessions.get_mut(src_addr).unwrap();
        let held = entry.candidate_count();
        let out = entry.step_setup(
            &setup.handshake_payload,
            *link_peer,
            setup.src_coords.clone(),
            now,
            &local,
        );
        let armed = entry.candidate_count() > held;
        let refused = out
            .iter()
            .any(|o| matches!(o, Output::Reject(Reason::TieBreakKept)));
        if established {
            if armed {
                self.stats_mut().session.rekey_armed += 1;
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "FSP rekey: answered the peer's setup, awaiting msg3"
                );
            }
            if refused {
                // The smaller node's own rekey has completed, or its msg3
                // is still resent, and waits for the peer under its keys: a
                // deployed peer commits on an ack, so the setup is refused
                // rather than answered.
                debug!(
                    src = %self.peer_display_name(src_addr),
                    "FSP setup refused: our own completed handshake waits for the peer"
                );
                self.stats_mut()
                    .record_reject(RejectReason::Session(SessionReject::RekeyPending));
            }
        } else if refused {
            debug!(
                src = %self.peer_display_name(src_addr),
                reason = "tie-break-won",
                "Simultaneous session initiation: our setup is young and the smaller, refusing theirs"
            );
        } else if armed {
            debug!(src = %self.peer_display_name(src_addr), "SessionSetup held, SessionAck sent, awaiting msg3");
        }
        self.run_session_outputs_answering(src_addr, out, !established, Some(&setup.src_coords))
            .await;
    }

    /// Open a session for the first setup naming `src_addr`, which arrived
    /// over `link_peer`: the machine holds it as a candidate and asks for its
    /// SessionAck. The admission caps were checked before. Nothing the setup
    /// says is proven, so the session names only the claimed address until
    /// a msg3 completes the candidate.
    async fn open_inbound_session(
        &mut self,
        src_addr: &NodeAddr,
        link_peer: &NodeAddr,
        setup: &SessionSetup,
        local: &NodeKeys,
        now: SessionInstant,
    ) {
        let (entry, out) = SessionEntry::answering(
            *src_addr,
            &setup.handshake_payload,
            *link_peer,
            setup.src_coords.clone(),
            self.session_params(),
            local,
            *self.node_addr(),
            now,
        );
        if entry.candidate_count() == 0 {
            // The machine refused the setup and asked for its own teardown:
            // there is no session to keep.
            debug!(src = %self.peer_display_name(src_addr), ?out, "SessionSetup refused, no session opened");
            return;
        }
        self.sessions.insert(*src_addr, entry);
        debug!(src = %self.peer_display_name(src_addr), "SessionSetup opened a session, SessionAck sent, awaiting msg3");
        self.run_session_outputs_answering(src_addr, out, true, Some(&setup.src_coords))
            .await;
    }

    /// Handle an incoming SessionAck (Noise XK msg2).
    ///
    /// Processes msg2, generates and sends msg3, then transitions to Established.
    async fn handle_session_ack(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let ack = match SessionAck::decode(inner) {
            Ok(a) => a,
            Err(e) => {
                debug!(error = %e, "Malformed SessionAck");
                return;
            }
        };

        if ack.handshake_payload.len() != XK_HANDSHAKE_MSG2_SIZE {
            debug!(
                len = ack.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG2_SIZE,
                "Invalid handshake payload size in SessionAck"
            );
            return;
        }

        // The reply to this node's own attempt, first handshake or rekey, is
        // the session machine's. Nothing in it is authenticated until it
        // reads on a fork of the attempt's handshake and bonds to the key
        // this node dialed, so a forged or corrupt ack changes nothing: the
        // attempt keeps its handshake, its schedule and its deadline, which
        // runs from the setup this node sent.
        let local = self.session_node_keys();
        let now = Self::session_now();
        let Some(entry) = self.sessions.get_mut(src_addr) else {
            debug!(src = %self.peer_display_name(src_addr), "SessionAck for unknown session");
            self.stats_mut()
                .record_reject(RejectReason::Session(SessionReject::UnknownSession));
            return;
        };
        let opening = !entry.is_established();
        let out = entry.step_reply(&ack.handshake_payload, ack.src_coords.clone(), now, &local);
        let established = opening && entry.is_established();
        if established {
            let warmup = self.config().node.session.coords_warmup_packets;
            let mmp = self.config().node.session_mmp.clone();
            if let Some(entry) = self.sessions.get_mut(src_addr) {
                entry.establish(warmup, &mmp, now);
            }
        }
        // The msg3 goes out before the packets held for the session: the
        // machine retains it and resends it until any frame from the peer
        // authenticates, since the responder is established only once it
        // arrives.
        self.run_session_outputs(src_addr, out, opening).await;
        if !established {
            return;
        }
        // Not charged to a link peer: this node started the handshake, and
        // msg2 has authenticated, so the write happens once per session.
        if self
            .insert_coord_hint(
                *src_addr,
                ack.src_coords.clone(),
                Self::now_ms(),
                Funding::Uncharged,
            )
            .is_none()
        {
            debug!(
                src = %self.peer_display_name(src_addr),
                reason = "foreign root",
                "SessionAck coordinate hint refused"
            );
        }
        self.flush_pending_packets(src_addr).await;
        self.flush_pending_native(src_addr).await;
        info!(src = %self.peer_display_name(src_addr), "Session established (initiator, XK)");
    }

    /// Handle an incoming SessionMsg3 (Noise XK msg3).
    ///
    /// The initiator reveals their encrypted static key. The responder
    /// processes msg3, learns the initiator's identity, and transitions
    /// to Established.
    async fn handle_session_msg3(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        let msg3 = match SessionMsg3::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed SessionMsg3");
                return;
            }
        };

        if msg3.handshake_payload.len() != XK_HANDSHAKE_MSG3_SIZE {
            debug!(
                len = msg3.handshake_payload.len(),
                expected = XK_HANDSHAKE_MSG3_SIZE,
                "Invalid handshake payload size in SessionMsg3"
            );
            return;
        }

        // Every candidate, first-handshake or rekey, is the session
        // machine's: one dispatcher tries the msg3 against each, newest
        // first, and the first that reads it and bonds completes it. Nothing
        // here has been authenticated until a read succeeds, so a msg3 none
        // of them reads changes nothing, and `touch()` is deliberately not
        // called, so a spray cannot push the session's deadlines out.
        let local = self.session_node_keys();
        let now = Self::session_now();
        let Some(entry) = self.sessions.get_mut(src_addr) else {
            debug!(src = %self.peer_display_name(src_addr), "SessionMsg3 for unknown session");
            self.stats_mut()
                .record_reject(RejectReason::Session(SessionReject::UnknownSession));
            return;
        };
        let opening = !entry.is_established();
        let completed = entry.has_pending();
        let out = entry.step_final(&msg3.handshake_payload, now, &local);
        let established = opening && entry.is_established();
        let peer_key = entry.peer_key();
        let answered = out.iter().any(|o| {
            matches!(
                o,
                Output::Installed {
                    role: Role::Responder,
                    ..
                }
            )
        });
        if completed && answered {
            // A completed rekey of this node's own, still waiting for the
            // peer, gave way to the peer's: only a msg3 carrying the
            // session's own peer key does this, and the keys it displaced
            // may have been in use.
            self.stats_mut().session.pending_replaced += 1;
            warn!(
                src = %self.peer_display_name(src_addr),
                "FSP rekey: newly completed session replaced one still awaiting cutover"
            );
        }
        for o in &out {
            match o {
                Output::Reject(Reason::TieBreakKept) if !opening => {
                    self.stats_mut()
                        .record_reject(RejectReason::Session(SessionReject::RekeyTiebreak));
                }
                Output::Reject(Reason::FinalNoAttempt) => {
                    debug!(
                        src = %self.peer_display_name(src_addr),
                        reason = "no-candidate",
                        "SessionMsg3 but session holds no candidate"
                    );
                    self.stats_mut()
                        .record_reject(RejectReason::Session(SessionReject::BadState));
                }
                Output::Reject(Reason::FinalUnauthenticated) => {
                    debug!(
                        src = %self.peer_display_name(src_addr),
                        reason = "no-candidate-matched",
                        "Failed to process Noise XK msg3 against any candidate, keeping them"
                    );
                }
                _ => {}
            }
        }
        if established {
            // The claimed address was checked against the key the msg3
            // authenticated: the machine's bond for a session a setup opened
            // is that address, so a msg3 under another node's key completes
            // nothing.
            if let Some(key) = peer_key {
                self.register_identity(*src_addr, key.public_key(secp256k1::Parity::Even));
            }
            let warmup = self.config().node.session.coords_warmup_packets;
            let mmp = self.config().node.session_mmp.clone();
            if let Some(entry) = self.sessions.get_mut(src_addr) {
                entry.establish(warmup, &mmp, now);
            }
        }
        self.run_session_outputs(src_addr, out, opening).await;
        if !established {
            return;
        }
        self.flush_pending_packets(src_addr).await;
        self.flush_pending_native(src_addr).await;
        info!(src = %self.peer_display_name(src_addr), "Session established (responder, XK)");
    }

    // === Session-layer MMP report handlers ===

    /// Check all sessions for pending MMP reports and send them.
    ///
    /// Called from the tick handler. Also emits periodic session MMP logs.
    /// Uses the collect-then-send pattern to avoid borrowing conflicts.
    pub(in crate::node) async fn check_session_mmp_reports(&mut self) {
        let now_ms = crate::time::mono_ms();

        // Build one report-gating snapshot per session, resolving every timing
        // read shell-side into a `bool`. The snapshots own only
        // `NodeAddr`/`MmpMode`/`bool`, so the session-iteration borrow is released
        // before the pure decision runs and the driving loop mutates the
        // reporting state / performs the sends.
        let snapshots: Vec<SessionReportSnapshot> = self
            .sessions
            .iter()
            .filter_map(|(dest_addr, entry)| {
                let mmp = entry.mmp()?;
                Some(SessionReportSnapshot {
                    dest: *dest_addr,
                    mode: mmp.mode(),
                    sr_due: mmp.sender.should_send_report(now_ms),
                    rr_due: mmp.receiver.should_send_report(now_ms),
                    mtu_due: mmp.path_mtu.should_send_notification(now_ms),
                    log_due: mmp.should_log(now_ms),
                })
            })
            .collect();

        let actions = self.mmp.plan_session_reports(&snapshots);

        // Drive the planned actions in phase-grouped order (all logs, then the
        // sends in per-session SR/RR/MTU order). Logs run first because the
        // session operator log reads cumulative_packets_sent, which each send
        // advances (send_session_msg -> sender.record_sent); the pre-refactor
        // handler logged during its collect pass, before any send. Each build
        // (`build_report`/`build_notification`, which advance interval/
        // notification state) runs only on its SendSessionReport action, exactly
        // as the pre-refactor collect pass did. Per-destination success/failure
        // is collected for the backoff dedup + failure-log suppression.
        let mut send_results: Vec<SendResult> = Vec::new();
        for action in actions {
            match action {
                MmpAction::LogSession { dest } => {
                    // Resolve the display name exactly as the pre-refactor loop
                    // did (alias, else short_npub from the session's remote key).
                    let session_name = self.peer_aliases.get(&dest).cloned().unwrap_or_else(|| {
                        self.sessions
                            .get(&dest)
                            .and_then(SessionEntry::peer_key)
                            .map(|xonly| crate::PeerIdentity::from_pubkey(xonly).short_npub())
                            .unwrap_or_default()
                    });
                    if let Some(mmp) = self.sessions.get_mut(&dest).and_then(|e| e.mmp_mut()) {
                        Self::log_session_mmp_metrics(&session_name, mmp);
                        mmp.mark_logged(now_ms);
                    }
                }
                MmpAction::SendSessionReport { dest, kind } => {
                    let built = self
                        .sessions
                        .get_mut(&dest)
                        .and_then(|entry| entry.mmp_mut())
                        .and_then(|mmp| match kind {
                            SessionReportKind::Sender => {
                                mmp.sender.build_report(now_ms).map(|sr| {
                                    (
                                        SessionMessageType::SenderReport.to_byte(),
                                        SessionSenderReport::from(&sr).encode(),
                                    )
                                })
                            }
                            SessionReportKind::Receiver => {
                                mmp.receiver.build_report(now_ms).map(|rr| {
                                    (
                                        SessionMessageType::ReceiverReport.to_byte(),
                                        SessionReceiverReport::from(&rr).encode(),
                                    )
                                })
                            }
                            SessionReportKind::PathMtu => {
                                mmp.path_mtu.build_notification(now_ms).map(|mtu_value| {
                                    (
                                        SessionMessageType::PathMtuNotification.to_byte(),
                                        PathMtuNotification::new(mtu_value).encode(),
                                    )
                                })
                            }
                        });

                    let Some((msg_type, body)) = built else {
                        continue;
                    };

                    match self.send_session_msg(&dest, msg_type, &body).await {
                        Ok(()) => send_results.push(SendResult { dest, ok: true }),
                        Err(e) => {
                            // Peek at current failure count for log suppression
                            // (unchanged by the backoff apply, which runs later).
                            let failures = self
                                .sessions
                                .get(&dest)
                                .and_then(|entry| entry.mmp())
                                .map(|mmp| mmp.sender.consecutive_send_failures())
                                .unwrap_or(0);

                            if failures < 3 {
                                debug!(
                                    dest = %self.peer_display_name(&dest),
                                    msg_type,
                                    error = %e,
                                    "Failed to send session MMP report"
                                );
                            } else if failures == 3 {
                                debug!(
                                    dest = %self.peer_display_name(&dest),
                                    "Suppressing further session MMP send failure logs"
                                );
                            }
                            // failures > 3: silently suppressed

                            send_results.push(SendResult { dest, ok: false });
                        }
                    }
                }
                MmpAction::ReapPeer { .. }
                | MmpAction::Heartbeat { .. }
                | MmpAction::SendLinkReport { .. }
                | MmpAction::LogLink { .. } => {}
            }
        }

        // Deduplicate send results per destination (any-ok -> success, all-fail
        // -> failure) and apply the backoff state transition for each dest.
        for update in self.mmp.plan_backoff(&send_results) {
            match update {
                BackoffUpdate::Success { dest } => {
                    if let Some(mmp) = self.sessions.get_mut(&dest).and_then(|e| e.mmp_mut()) {
                        let prev = mmp.sender.record_send_success();
                        if prev > 3 {
                            debug!(
                                dest = %self.peer_display_name(&dest),
                                consecutive_failures = prev,
                                "Resumed session MMP reporting"
                            );
                        }
                    }
                }
                BackoffUpdate::Failure { dest } => {
                    if let Some(mmp) = self.sessions.get_mut(&dest).and_then(|e| e.mmp_mut()) {
                        mmp.sender.record_send_failure();
                    }
                }
            }
        }
    }

    /// Emit periodic session MMP metrics.
    fn log_session_mmp_metrics(session_name: &str, mmp: &MmpSessionState) {
        let m = &mmp.metrics;

        let rtt_str = if m.rtt_trend.initialized() {
            format!("{:.1}ms", m.rtt_trend.long() / 1000.0)
        } else {
            "n/a".to_string()
        };
        let loss_str = if m.loss_trend.initialized() {
            format!("{:.1}%", m.loss_trend.long() * 100.0)
        } else {
            "n/a".to_string()
        };
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        debug!(
            session = %session_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            goodput = %format_throughput(m.goodput_bps()),
            mtu = mmp.path_mtu.last_observed_mtu(),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            "MMP session metrics"
        );
    }

    /// Emit a teardown log summarizing lifetime session MMP metrics.
    pub(in crate::node) fn log_session_mmp_teardown(session_name: &str, mmp: &MmpSessionState) {
        let m = &mmp.metrics;
        let jitter_ms = mmp.receiver.jitter_us() as f64 / 1000.0;

        let rtt_str = match m.srtt_ms() {
            Some(rtt) => format!("{:.1}ms", rtt),
            None => "n/a".to_string(),
        };
        let loss_str = format!("{:.1}%", m.loss_rate() * 100.0);

        debug!(
            session = %session_name,
            rtt = %rtt_str,
            loss = %loss_str,
            jitter = format_args!("{:.1}ms", jitter_ms),
            etx = format_args!("{:.2}", m.etx),
            goodput = %format_throughput(m.goodput_bps()),
            send_mtu = mmp.path_mtu.current_mtu(),
            observed_mtu = mmp.path_mtu.last_observed_mtu(),
            tx_pkts = mmp.sender.cumulative_packets_sent(),
            tx_bytes = mmp.sender.cumulative_bytes_sent(),
            rx_pkts = mmp.receiver.cumulative_packets_recv(),
            rx_bytes = mmp.receiver.cumulative_bytes_recv(),
            "MMP session teardown"
        );
    }

    /// Handle an incoming session-layer SenderReport (msg_type 0x11).
    ///
    /// Informational only — the peer is telling us about what they sent.
    /// Logged but not used for metrics (same pattern as link-layer).
    fn handle_session_sender_report(&mut self, src_addr: &NodeAddr, body: &[u8]) {
        let sr = match SessionSenderReport::decode(body) {
            Ok(sr) => sr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionSenderReport");
                return;
            }
        };

        trace!(
            src = %self.peer_display_name(src_addr),
            cum_pkts = sr.cumulative_packets_sent,
            interval_bytes = sr.interval_bytes_sent,
            "Received SessionSenderReport"
        );
    }

    /// Handle an incoming session-layer ReceiverReport (msg_type 0x12),
    /// authenticated under the epoch `tag`.
    ///
    /// The peer is telling us about what they received from us. We feed
    /// this to our metrics to compute RTT, loss rate, and trend indicators.
    /// A report sealed under the epoch a cutover retired describes this
    /// node's frames of that epoch, and is dropped rather than judged
    /// against the new epoch's metrics.
    fn handle_session_receiver_report(&mut self, src_addr: &NodeAddr, tag: EpochTag, body: &[u8]) {
        let session_rr = match SessionReceiverReport::decode(body) {
            Ok(rr) => rr,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed SessionReceiverReport");
                return;
            }
        };

        // Convert to link-layer ReceiverReport for MmpMetrics processing
        let rr: ReceiverReport = ReceiverReport::from(&session_rr);

        let now = Self::session_now();
        let peer_name = self.peer_display_name(src_addr);
        let entry = match self.sessions.get_mut(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %peer_name, "SessionReceiverReport for unknown session");
                self.stats_mut()
                    .record_reject(RejectReason::Session(SessionReject::UnknownSession));
                return;
            }
        };

        let our_timestamp_ms = entry.session_timestamp(now);

        let Some(mmp) = entry.epoch_mmp(tag) else {
            trace!(src = %peer_name, "SessionReceiverReport under a retired epoch, dropped");
            return;
        };

        let (_first_rtt, rr_log) =
            mmp.metrics
                .process_receiver_report(&rr, our_timestamp_ms, crate::time::mono_ms());
        // Re-emit the operator trace the core used to log mid-decision.
        super::mmp::log_rr_outcome(&rr, our_timestamp_ms, rr_log);

        // Feed SRTT back to sender/receiver report interval tuning (session-layer bounds)
        if let Some(srtt_ms) = mmp.metrics.srtt_ms() {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.receiver.update_report_interval_with_bounds(
                srtt_us,
                MIN_SESSION_REPORT_INTERVAL_MS,
                MAX_SESSION_REPORT_INTERVAL_MS,
            );
            // Also update PathMtu notification interval from SRTT
            mmp.path_mtu.update_interval_from_srtt(srtt_ms);
        }

        // Update reverse delivery ratio from our own receiver state, using per-interval deltas.
        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);

        trace!(
            src = %peer_name,
            rtt_ms = ?mmp.metrics.srtt_ms(),
            loss = format_args!("{:.1}%", mmp.metrics.loss_rate() * 100.0),
            "Processed SessionReceiverReport"
        );
    }

    /// Handle an incoming PathMtuNotification (msg_type 0x13).
    ///
    /// The destination is telling us the path MTU has changed.
    /// Apply source-side rules (decrease immediate, increase validated).
    pub(in crate::node) fn handle_session_path_mtu_notification(
        &mut self,
        src_addr: &NodeAddr,
        body: &[u8],
    ) {
        let notif = match PathMtuNotification::decode(body) {
            Ok(n) => n,
            Err(e) => {
                debug!(src = %self.peer_display_name(src_addr), error = %e, "Malformed PathMtuNotification");
                return;
            }
        };

        let peer_name = self.peer_display_name(src_addr);
        let entry = match self.sessions.get_mut(src_addr) {
            Some(e) => e,
            None => {
                debug!(src = %peer_name, "PathMtuNotification for unknown session");
                self.stats_mut()
                    .record_reject(RejectReason::Session(SessionReject::UnknownSession));
                return;
            }
        };

        let Some(mmp) = entry.mmp_mut() else {
            return;
        };

        // `apply_notification` refuses a sub-floor value, but it returns the
        // same `false` it returns for the ordinary "no change" case, which is
        // the common one. Test the floor here so the refusal is visible: this
        // arrives on the decrypted service-payload path, so a value this low
        // means an authenticated peer we hold a session with is sending
        // something unusable.
        if notif.path_mtu < crate::proto::mmp::MIN_ACTIONABLE_PATH_MTU {
            warn!(
                src = %peer_name,
                reported_mtu = notif.path_mtu,
                floor = crate::proto::mmp::MIN_ACTIONABLE_PATH_MTU,
                "PathMtuNotification reports a path MTU below the actionable floor; ignoring"
            );
            self.metrics.errors.path_mtu_notif_below_floor.inc();
            return;
        }

        let old_mtu = mmp.path_mtu.current_mtu();
        let changed = mmp
            .path_mtu
            .apply_notification(notif.path_mtu, crate::time::mono_ms());
        let new_mtu = mmp.path_mtu.current_mtu();

        if !changed {
            return;
        }

        debug!(
            src = %peer_name,
            old_mtu,
            new_mtu,
            "Path MTU changed via notification"
        );

        // Mirror the new effective MTU into the Ipv6Address-keyed lookup used
        // by the TUN reader/writer at TCP MSS clamp time. Without this, new
        // TCP flows opened on a path the proactive end-to-end echo has
        // already tightened keep getting clamped by the staler discovery-
        // time value until a reactive MtuExceeded happens to fire. Keep the
        // tighter of existing-or-new — never loosen the clamp.
        let fips_addr = crate::Ipv6Address::from_node_addr(src_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => {
                // Read existing, decide, and apply the write under one guard so
                // the keep-tighter update stays atomic.
                let prior = map.get(&fips_addr).copied();
                let actions =
                    self.fsp
                        .plan_path_mtu_tighten(fips_addr, prior.map(|e| e.mtu), new_mtu);
                if actions.is_empty() {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        new_mtu,
                        existing = prior.map(|e| e.mtu).unwrap_or(new_mtu),
                        "PathMtuNotification: keeping tighter existing path_mtu_lookup value"
                    );
                }
                for action in actions {
                    if let FspAction::TightenPathMtuLookup { fips_addr, mtu } = action {
                        // Held, not expiring. This value arrives inside a
                        // session, and a session's teardown or a PathBroken
                        // naming it already releases the entry. A deadline here
                        // would instead recreate the gap this mirror exists to
                        // close: a peer repeating an identical value on a stable
                        // path takes the unchanged early-return above and never
                        // rewrites the entry, so an expiring one would vanish
                        // and stay gone.
                        map.insert(fips_addr, crate::node::path_mtu::PathMtuEntry::held(mtu));
                        debug!(
                            dest = %peer_name,
                            fips_addr = %fips_addr,
                            new_mtu,
                            prior = ?prior,
                            map_len = map.len(),
                            "PathMtuNotification: tightened path_mtu_lookup"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    new_mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; PathMtuNotification not reflected"
                );
            }
        }
    }

    /// Whether a routing signal naming `dest`, arriving in a datagram
    /// claiming source `src`, may be acted on, and if not, which kind of
    /// refusal it is.
    ///
    /// `src` is the SessionDatagram's `src_addr`: a plain wire field,
    /// authenticated only hop-by-hop by FMP Noise and never end to end. It
    /// is therefore logged, not trusted. What is enforced here is that this
    /// node has bound `dest` itself, either by initiating toward it or by
    /// completing Noise XK, which binds the address to the peer's static
    /// key (see the address-mismatch check in `handle_session_msg3`). A
    /// responder entry that is still awaiting msg3 does NOT qualify: it is
    /// keyed on an address the sender merely claimed, so admitting it would
    /// let one forged SessionSetup unlock a signal about any address.
    ///
    /// The first two clauses reject nothing legitimate, and so return
    /// `Forged` rather than `Unbound`. A datagram whose destination is this
    /// node takes the deliver-local branch before any forwarding, so no node
    /// ever emits a signal naming us as `dest`; and the emitter is by
    /// construction a transit node for the datagram it is reporting on, so
    /// it is never itself that datagram's destination.
    ///
    /// This narrows who can be targeted; it does not authenticate the
    /// sender, which nothing short of a wire format change can do.
    fn signal_verdict(&self, src: &NodeAddr, dest: &NodeAddr) -> SignalVerdict {
        if dest == self.node_addr() || src == dest {
            return SignalVerdict::Forged;
        }
        if self
            .sessions
            .get(dest)
            .is_some_and(|e| e.is_established() || e.is_initiator())
        {
            SignalVerdict::Admit
        } else {
            SignalVerdict::Unbound
        }
    }

    /// Handle a CoordsRequired error signal from a transit router.
    ///
    /// The router couldn't route our packet because it lacks cached
    /// coordinates for the destination. Send a standalone CoordsWarmup
    /// immediately (rate-limited), trigger discovery, and reset the
    /// warmup counter for subsequent data packets.
    ///
    /// `src_addr` is the datagram's claimed source and is not
    /// end-to-end authenticated; see `signal_verdict`.
    pub(in crate::node) async fn handle_coords_required(
        &mut self,
        src_addr: &NodeAddr,
        inner: &[u8],
    ) {
        self.metrics().errors.coords_required.inc();

        let msg = match CoordsRequired::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed CoordsRequired");
                return;
            }
        };

        // The premise: this signal carries no end-to-end authentication, so
        // the body's `dest_addr` is attacker-chosen. Everything below acts on
        // it — warmup send, discovery, warmup-counter reset — so the gate has
        // to run before any of that, and ahead of the rate limiter, whose
        // state would otherwise be keyed on an attacker-chosen address.
        let verdict = self.signal_verdict(src_addr, &msg.dest_addr);
        if verdict != SignalVerdict::Admit {
            debug!(src = %src_addr, dest = %msg.dest_addr, reporter = %msg.reporter,
                signal = "CoordsRequired", verdict = verdict.label(),
                "Routing signal names an address this node has not bound; dropping");
            self.metrics().errors.unbound.coords.inc();
            if verdict == SignalVerdict::Forged {
                self.metrics().errors.unbound.forged.inc();
            }
            self.stats_mut()
                .record_reject(RejectReason::Session(SessionReject::UnknownSession));
            return;
        }

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "CoordsRequired: transit router needs coordinates"
        );

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr, crate::time::mono_ms())
        {
            if let Some(entry) = self.sessions.get(&msg.dest_addr)
                && entry.is_established()
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to CoordsRequired");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "CoordsRequired response rate-limited, skipping standalone CoordsWarmup");
        }

        // Only trigger discovery if we have the target's identity cached —
        // otherwise we can't verify the LookupResponse proof.
        let has_cached_identity = self.has_cached_identity(&msg.dest_addr);
        let actions = self
            .fsp
            .plan_coords_required_lookup(msg.dest_addr, has_cached_identity);
        if actions.is_empty() {
            debug!(dest = %msg.dest_addr,
                "Skipping discovery after CoordsRequired: no cached identity for target");
        }
        for action in actions {
            if let FspAction::InitiateLookup { dest } = action {
                self.maybe_initiate_lookup(&dest).await;
            }
        }

        // Reset coords warmup counter so the next N packets also include
        // COORDS_PRESENT, re-warming transit caches along the path.
        let n = self.config().node.session.coords_warmup_packets;
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
            entry.set_coords_warmup_remaining(n);
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after CoordsRequired"
            );
        }
    }

    /// Handle a PathBroken error signal from a transit router.
    ///
    /// The router has coordinates but still can't route to the destination.
    /// Send a standalone CoordsWarmup immediately (rate-limited), re-validate
    /// the destination's coordinates by lookup, release its path MTU, and
    /// reset the warmup counter.
    ///
    /// Cached coordinates that are only a hint are removed. Coordinates a
    /// lookup verified are kept while the lookup re-validates them, and are
    /// demoted to a hint only once reports arriving over distinct links reach
    /// the quorum: the signal is unauthenticated, and deleting a verified
    /// entry on one report is what let the next forged warm replace it.
    ///
    /// `src_addr` is the datagram's claimed source and is not
    /// end-to-end authenticated; see `signal_verdict`. `link_peer` is the
    /// authenticated peer the datagram arrived over. It is the report's vote
    /// in the quorum, because the body's reporter is whatever the sender
    /// wrote, and it is compared with the forward path to count mismatches;
    /// it never refuses the signal.
    pub(in crate::node) async fn handle_path_broken(
        &mut self,
        src_addr: &NodeAddr,
        link_peer: &NodeAddr,
        inner: &[u8],
    ) {
        self.metrics().errors.path_broken.inc();

        let msg = match PathBroken::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed PathBroken");
                return;
            }
        };

        // The premise: this signal carries no end-to-end authentication, so
        // the body's `dest_addr` is attacker-chosen. The coord-cache action,
        // the lookup and the path-MTU release below all act on whatever
        // address the body names unless the gate refuses it here, in the
        // shell, which is the only layer that knows who sent the datagram.
        let verdict = self.signal_verdict(src_addr, &msg.dest_addr);
        if verdict != SignalVerdict::Admit {
            debug!(src = %src_addr, dest = %msg.dest_addr, reporter = %msg.reporter,
                signal = "PathBroken", verdict = verdict.label(),
                "Routing signal names an address this node has not bound; dropping");
            self.metrics().errors.unbound.broken.inc();
            if verdict == SignalVerdict::Forged {
                self.metrics().errors.unbound.forged.inc();
            }
            self.stats_mut()
                .record_reject(RejectReason::Session(SessionReject::UnknownSession));
            return;
        }

        debug!(
            dest = %msg.dest_addr,
            reporter = %msg.reporter,
            "PathBroken: transit router reports routing failure"
        );
        self.count_path_broken_mismatches(link_peer, &msg);

        // Send standalone CoordsWarmup immediately (rate-limited)
        if self
            .coords_response_rate_limiter
            .should_send(&msg.dest_addr, crate::time::mono_ms())
        {
            if let Some(entry) = self.sessions.get(&msg.dest_addr)
                && entry.is_established()
                && let Err(e) = self.send_coords_warmup(&msg.dest_addr).await
            {
                debug!(dest = %msg.dest_addr, error = %e,
                    "Failed to send CoordsWarmup in response to PathBroken");
            }
        } else {
            trace!(dest = %msg.dest_addr,
                "PathBroken response rate-limited, skipping standalone CoordsWarmup");
        }

        // Only a live verified entry has anything for the quorum to protect,
        // so only a report against one is recorded; that also bounds the
        // quorum's keys by the destinations this node has looked up. The vote
        // is the link the report arrived over, so a sender on one link counts
        // once however many reporters it names.
        let now = Self::now_ms();
        let verified = self
            .coord_cache
            .get_entry(&msg.dest_addr)
            .is_some_and(|e| e.is_verified(now));
        let quorum = if verified {
            self.broken_quorum.record(msg.dest_addr, *link_peer, now)
        } else {
            QuorumVerdict::Below { distinct: 0 }
        };
        let actions = self.fsp.plan_path_broken(msg.dest_addr, verified, quorum);
        for action in actions {
            match action {
                FspAction::InvalidateCoords { addr } => {
                    self.coord_cache.remove(&addr);
                }
                FspAction::DemoteCoords { addr } => {
                    self.coord_cache.demote(&addr);
                    self.metrics().errors.broken_demoted.inc();
                    debug!(dest = %addr,
                        "PathBroken quorum reached; demoted verified coordinates to a hint");
                }
                FspAction::InitiateLookup { dest } => {
                    self.cache_session_identity(&dest);
                    self.maybe_initiate_lookup(&dest).await;
                }
                _ => {}
            }
        }
        if let QuorumVerdict::Below { distinct } = quorum
            && verified
        {
            self.metrics().errors.broken_below_quorum.inc();
            debug!(dest = %msg.dest_addr, distinct,
                "PathBroken below quorum; keeping verified coordinates pending the lookup");
        }

        // The path this destination's stored MTU described is gone, so release
        // it rather than carrying it onto whatever path replaces it. Rate
        // limited per destination on its own budget: PathBroken is
        // unauthenticated, and an unlimited release discards a genuinely
        // learned bottleneck as fast as it is relearned. The budget is not
        // shared with any other signal, so nothing else can spend it.
        //
        // A cache entry kept above still carries the MTU the lookup stored
        // with it, which describes the same path; clear it with the map so
        // the two do not disagree.
        if self
            .path_mtu_release_limiter
            .should_send(&msg.dest_addr, crate::time::mono_ms())
        {
            self.path_mtu_lookup_release(&msg.dest_addr);
            self.coord_cache.clear_path_mtu(&msg.dest_addr);
        } else {
            trace!(dest = %msg.dest_addr,
                "PathBroken path MTU release rate-limited, keeping the stored value");
        }

        // Reset coords warmup counter so the next N packets include
        // COORDS_PRESENT, re-warming transit caches along the new path.
        let n = self.config().node.session.coords_warmup_packets;
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
            entry.set_coords_warmup_remaining(n);
            debug!(
                dest = %msg.dest_addr,
                warmup_packets = n,
                "Reset coords warmup counter after PathBroken"
            );
        }
    }

    /// Cache the identity of `dest` from its session entry if the identity
    /// cache has none.
    ///
    /// A lookup's answer is verified against the target's cached key, so a
    /// lookup for a destination whose identity has been evicted runs to its
    /// timeout and drops the packets queued for it as unreachable. A session
    /// whose handshake completed holds the key it authenticated; one still
    /// being set up has proven no key, and nothing it holds is cached.
    fn cache_session_identity(&mut self, dest: &NodeAddr) {
        if self.has_cached_identity(dest) {
            return;
        }
        if let Some(key) = self.sessions.get(dest).and_then(SessionEntry::peer_key) {
            self.register_identity(*dest, key.public_key(secp256k1::Parity::Even));
        }
    }

    /// Look `dest` up again after a send on its established session found no
    /// next hop.
    ///
    /// An end-to-end session outlives its route. A link change anywhere on
    /// the way (a wifi roam, a BLE drop, a re-plugged cable, the tree
    /// re-parenting) flushes the coordinates this node routes `dest` by,
    /// while both ends keep the session established. Lookups are otherwise
    /// started only for destinations without a session, so every send on it
    /// failed with "no route" until the idle timeout removed the session.
    ///
    /// The lookup is deduplicated, so a stream of failing sends starts one,
    /// and its answer restores the coordinates for the session already in
    /// place. The identity is cached from the session first: the answer is
    /// verified against it, and on a long-lived session it may have been
    /// evicted.
    pub(in crate::node) async fn relookup_lost_route(&mut self, dest: &NodeAddr) {
        if self.find_next_hop(dest).is_some() {
            return;
        }
        self.cache_session_identity(dest);
        self.maybe_initiate_lookup(dest).await;
    }

    /// Count, without acting on, the two ways an admitted PathBroken can
    /// disagree with this node's own view of the path.
    ///
    /// Advisory only: both checks read state an attacker can influence and
    /// both have a non-zero healthy floor, so they size the problem rather
    /// than refuse anything.
    ///
    /// - Link: the signal arrived over a link other than the one this node
    ///   would forward to the destination on. A genuine report can also do
    ///   this when the reverse path differs from the forward one.
    /// - Reporter: the reporter is this node or the destination, or its known
    ///   coordinates are not strictly closer to the destination than this
    ///   node's. Forwarding makes strict progress under each forwarder's own
    ///   view of the destination, and a PathBroken arises exactly where that
    ///   view may differ from this node's, so a genuine report can count here
    ///   too. A reporter's coordinates are rarely known unless it is a direct
    ///   peer, so this mostly reads as unknown and is not counted.
    fn count_path_broken_mismatches(&self, link_peer: &NodeAddr, msg: &PathBroken) {
        let now = Self::now_ms();
        let dest = &msg.dest_addr;
        let reporter = &msg.reporter;

        if let (Some(hop), _) = self.preview_next_hop(dest, now)
            && hop.node_addr != *link_peer
        {
            self.metrics().errors.broken_link_mismatch.inc();
            debug!(dest = %dest, link_peer = %link_peer, next_hop = %hop.node_addr,
                "PathBroken arrived off the forward link");
        }

        let implausible = if reporter == self.node_addr() || reporter == dest {
            true
        } else {
            let dest_coords = self.coord_cache.get(dest, now);
            let reporter_coords = self
                .tree_state
                .peer_coords(reporter)
                .or_else(|| self.coord_cache.get(reporter, now));
            match (dest_coords, reporter_coords) {
                (Some(d), Some(r)) => {
                    r.distance_to(d) >= self.tree_state.my_coords().distance_to(d)
                }
                _ => false,
            }
        };
        if implausible {
            self.metrics().errors.broken_reporter_mismatch.inc();
            debug!(dest = %dest, reporter = %reporter,
                "PathBroken reporter is not closer to the destination than this node");
        }
    }

    /// Handle an MtuExceeded error signal from a transit router.
    ///
    /// A transit router couldn't forward our packet because it exceeded the
    /// next-hop transport MTU. Apply the reported bottleneck MTU to our
    /// PathMtuState for the affected session, causing an immediate decrease.
    ///
    /// `src_addr` is the datagram's claimed source and is not
    /// end-to-end authenticated; see `signal_verdict`.
    pub(in crate::node) async fn handle_mtu_exceeded(&mut self, src_addr: &NodeAddr, inner: &[u8]) {
        self.metrics().errors.mtu_exceeded.inc();

        let msg = match MtuExceeded::decode(inner) {
            Ok(m) => m,
            Err(e) => {
                debug!(error = %e, "Malformed MtuExceeded");
                return;
            }
        };

        // The premise: this signal carries no end-to-end authentication, so
        // the body's `dest_addr` is attacker-chosen, and the `path_mtu_lookup`
        // write further down needs no session, no peer relationship and no
        // prior state to reach. This gate is about WHICH address may be
        // written; the floor guard below is about WHAT value may be written.
        // They are independent refusals — a bound destination can still carry
        // an unusable value — so neither subsumes the other and each keeps its
        // own counter.
        let verdict = self.signal_verdict(src_addr, &msg.dest_addr);
        if verdict != SignalVerdict::Admit {
            debug!(src = %src_addr, dest = %msg.dest_addr, reporter = %msg.reporter,
                signal = "MtuExceeded", verdict = verdict.label(),
                "Routing signal names an address this node has not bound; dropping");
            self.metrics().errors.unbound.mtu.inc();
            if verdict == SignalVerdict::Forged {
                self.metrics().errors.unbound.forged.inc();
            }
            self.stats_mut()
                .record_reject(RejectReason::Session(SessionReject::UnknownSession));
            return;
        }

        let peer_name = self.peer_display_name(&msg.dest_addr);
        debug!(
            dest = %peer_name,
            reporter = %msg.reporter,
            bottleneck_mtu = msg.mtu,
            "MtuExceeded: transit router reports oversized packet"
        );

        // Both effects below — the session's own path MTU and the
        // Ipv6Address-keyed lookup the TUN MSS clamp reads — are refused from
        // here, so one return covers both. The guards sit ahead of the apply
        // rather than between the two effects, which is what makes the floor
        // govern `current_mtu` and not only the lookup table.

        // Refuse a bottleneck too small to describe a usable path; a stored
        // value that low drives the SYN-time MSS clamp into single digits or
        // zero. The reactive carrier is unauthenticated, so it has its own
        // floor constant, currently equal to the actionable one.
        if msg.mtu < crate::proto::mmp::MIN_REACTIVE_PATH_MTU {
            warn!(
                dest = %peer_name,
                reporter = %msg.reporter,
                bottleneck_mtu = msg.mtu,
                floor = crate::proto::mmp::MIN_REACTIVE_PATH_MTU,
                "MtuExceeded reports a path MTU below the actionable floor; ignoring"
            );
            self.metrics().errors.mtu_exceeded_below_floor.inc();
            return;
        }

        // Corroboration. The admission gate narrows which destination may be
        // named; it cannot authenticate the reporter, so a legal value is a
        // legal value from anyone and the floor alone only sets the outcome of
        // a forgery rather than preventing it. An honest report exists only
        // because a frame this node emitted did not fit some hop, so require
        // that this node has actually sent something larger than the value
        // being claimed since the last accepted decrease. Honest path-MTU
        // discovery satisfies this by construction; a forgery has to wait for
        // us to emit a frame bigger than the value it wants to claim, which
        // bounds every accepted claim from below by our own traffic.
        let sent_wire_len = self
            .sessions
            .get(&msg.dest_addr)
            .map(|e| e.max_sent_wire_len())
            .unwrap_or(0);
        if msg.mtu >= sent_wire_len {
            debug!(
                dest = %peer_name,
                reporter = %msg.reporter,
                bottleneck_mtu = msg.mtu,
                max_sent_wire_len = sent_wire_len,
                "MtuExceeded reports a bottleneck no smaller than anything this node has sent; ignoring"
            );
            self.metrics().errors.mtu_exceeded_uncorroborated.inc();
            return;
        }

        // Apply to PathMtuState: immediate decrease via apply_notification()
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            let old_mtu = mmp.path_mtu.current_mtu();
            if mmp
                .path_mtu
                .apply_notification(msg.mtu, crate::time::mono_ms())
            {
                let new_mtu = mmp.path_mtu.current_mtu();
                info!(
                    dest = %peer_name,
                    old_mtu,
                    new_mtu,
                    reporter = %msg.reporter,
                    "Path MTU decreased via reactive MtuExceeded signal"
                );
            }
        }

        // Spent: the evidence vouched for this decrease and does not vouch for
        // the next one. An initiating session has no `mmp` and so reaches this
        // with the apply above skipped; the reset belongs to the acceptance,
        // not to the apply.
        if let Some(entry) = self.sessions.get_mut(&msg.dest_addr) {
            entry.clear_sent_wire_len();
        }

        // Mirror the bottleneck into the Ipv6Address-keyed lookup used by
        // the TUN reader/writer at TCP MSS clamp time. Discovery's reverse-
        // path response can carry a value too generous for the actual
        // forward path; the reactive signal from a forwarder that actually
        // dropped a packet is authoritative for "what fits". Keep the
        // tighter of existing-or-new — never loosen the clamp.
        //
        // The admission gate above, not this block, is what restricts which
        // addresses can be written here.
        let fips_addr = crate::Ipv6Address::from_node_addr(&msg.dest_addr);
        match self.path_mtu_lookup.write() {
            Ok(mut map) => {
                // Read existing, decide, and apply the write under one guard so
                // the keep-tighter update stays atomic.
                let prior = map.get(&fips_addr).copied();
                let actions =
                    self.fsp
                        .plan_path_mtu_tighten(fips_addr, prior.map(|e| e.mtu), msg.mtu);
                if actions.is_empty() {
                    debug!(
                        dest = %peer_name,
                        fips_addr = %fips_addr,
                        bottleneck_mtu = msg.mtu,
                        existing = prior.map(|e| e.mtu).unwrap_or(msg.mtu),
                        "Reactive MtuExceeded: keeping tighter existing path_mtu_lookup value"
                    );
                }
                for action in actions {
                    if let FspAction::TightenPathMtuLookup { fips_addr, mtu } = action {
                        // Held, not expiring. The admission gate above requires
                        // a session for the named destination, and that
                        // session's teardown releases this entry. Nothing
                        // re-sends the signal once traffic is sized to fit, so a
                        // deadline would drop a genuine persistent bottleneck
                        // and start the next flow at the conservative ceiling.
                        map.insert(fips_addr, crate::node::path_mtu::PathMtuEntry::held(mtu));
                        debug!(
                            dest = %peer_name,
                            fips_addr = %fips_addr,
                            bottleneck_mtu = msg.mtu,
                            prior = ?prior,
                            map_len = map.len(),
                            "Reactive MtuExceeded: tightened path_mtu_lookup"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    dest = %peer_name,
                    fips_addr = %fips_addr,
                    bottleneck_mtu = msg.mtu,
                    error = %e,
                    "path_mtu_lookup write lock poisoned; reactive MtuExceeded not reflected"
                );
            }
        }
    }

    // === Session Initiation (Send Path) ===

    /// Whether a session for `addr` may be created, given the table cap.
    ///
    /// Returns true when an entry already exists, since admitting it cannot
    /// grow the table; a candidate joining that entry is checked against the
    /// half-open share by the setup handler, through
    /// `admit_half_open_candidate`. Counts its own refusals, so the two
    /// reasons are distinguishable without turning on debug logging.
    pub(in crate::node) fn admit_new_session(&mut self, addr: &NodeAddr) -> bool {
        let max_sessions = self.config().node.limits.max_sessions;
        if max_sessions == 0 || self.sessions.contains_key(addr) {
            return true;
        }

        if self.sessions.len() >= max_sessions {
            debug!(
                src = %self.peer_display_name(addr),
                sessions = self.sessions.len(),
                max_sessions = max_sessions,
                "Session table full, refusing to create a session"
            );
            self.stats_mut()
                .record_reject(RejectReason::Session(SessionReject::TableFull));
            return false;
        }

        // A new entry opens with one candidate, which counts toward the
        // half-open share.
        self.admit_half_open_candidate(addr)
    }

    /// Whether one more candidate fits the half-open share of the session
    /// table. Candidates of sessions still being set up count individually,
    /// whether they open an entry or join one, so the share bounds their
    /// memory.
    pub(in crate::node) fn admit_half_open_candidate(&mut self, addr: &NodeAddr) -> bool {
        let max_sessions = self.config().node.limits.max_sessions;
        if max_sessions == 0 {
            return true;
        }
        // Half-open candidates are unauthenticated and expire 40 s after
        // their setup, so they are the cheap half of the table to fill.
        // Holding them to a share keeps room for peers that complete. An
        // entry holds at most `MAX_CANDIDATES`, so below that many times the
        // share in entries the scan cannot reach it. At least one, or a table
        // capped at one would admit no inbound session at all rather than
        // one.
        let half_open_share = (max_sessions / HALF_OPEN_SHARE_DIVISOR).max(1);
        if self.sessions.len() * crate::node::session::MAX_CANDIDATES < half_open_share {
            return true;
        }
        let half_open: usize = self
            .sessions
            .values()
            .map(SessionEntry::half_open_count)
            .sum();
        if half_open >= half_open_share {
            debug!(
                src = %self.peer_display_name(addr),
                half_open = half_open,
                half_open_share = half_open_share,
                reason = "half-open-full",
                "Half-open session share exhausted, refusing a candidate"
            );
            self.stats_mut()
                .record_reject(RejectReason::Session(SessionReject::HalfOpenFull));
            return false;
        }
        true
    }

    /// Open an end-to-end session with `dest_addr`, whose static key is
    /// `dest_pubkey`.
    ///
    /// The session's machine starts this node's first attempt at once: a
    /// Noise XK msg1 in a SessionSetup, routed toward the destination and
    /// resent on the machine's ladder. A session the peer's setups opened
    /// gets this node's attempt beside its candidates, so a setup that
    /// arrived first, forged or genuine, never holds this node's own
    /// handshake back. Nothing is done for a session already established or
    /// with this node's attempt in flight. With no route to the destination,
    /// or when the first setup of a new session fails to send, nothing is
    /// kept and the caller is told, so it can ask discovery for a route; a
    /// later send the transport refuses is loss, which the machine's resends
    /// recover.
    pub(in crate::node) async fn initiate_session(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: PublicKey,
    ) -> Result<(), NodeError> {
        if let Some(existing) = self.sessions.get(&dest_addr)
            && (existing.is_established() || existing.is_initiating())
        {
            return Ok(());
        }
        if self.find_next_hop(&dest_addr).is_none() {
            return Err(NodeError::SendFailed {
                node_addr: dest_addr,
                reason: "no route to destination".into(),
            });
        }

        // Register destination identity for TUN → session routing
        self.register_identity(dest_addr, dest_pubkey);

        let now = Self::session_now();
        let local = self.session_node_keys();
        if let Some(entry) = self.sessions.get_mut(&dest_addr) {
            let out = entry.open(&dest_pubkey, now, &local);
            self.run_session_outputs(&dest_addr, out, true).await;
        } else {
            let (entry, out) = SessionEntry::opened(
                dest_addr,
                &dest_pubkey,
                self.session_params(),
                &local,
                *self.node_addr(),
                now,
            );
            self.sessions.insert(dest_addr, entry);
            // A session is kept only if its first setup left: one that never
            // did is not opened, as when no route is known, so the caller
            // can ask discovery and a retransmit tries again.
            for output in out {
                if let Output::Send { msg, kind, .. } = output {
                    if let Some(entry) = self.sessions.get_mut(&dest_addr) {
                        entry.note_setup_sent();
                    }
                    if let Err(e) = self.send_rekey_message(&dest_addr, msg, kind, None).await {
                        self.sessions.remove(&dest_addr);
                        return Err(e);
                    }
                } else {
                    self.run_session_outputs(&dest_addr, vec![output], true)
                        .await;
                }
            }
        }
        debug!(dest = %self.peer_display_name(&dest_addr), "Session initiation started");
        Ok(())
    }

    /// Send application data over an established session.
    ///
    /// Uses the FSP pipeline: builds a 12-byte cleartext header (used as AAD),
    /// prepends the 6-byte inner header to the plaintext, encrypts with AAD,
    /// optionally inserts cleartext coords, and wraps in a SessionDatagram.
    ///
    /// The `src_port` and `dst_port` identify the service. A 4-byte port header
    /// `[src_port:2 LE][dst_port:2 LE]` is prepended to `payload` inside the
    /// AEAD envelope. The receiver dispatches by `dst_port`.
    pub(in crate::node) async fn send_session_data(
        &mut self,
        dest_addr: &NodeAddr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now = Self::session_now();

        // First borrow: read session metadata (NLL releases before coord decision)
        let entry = self
            .sessions
            .get(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        let wants_coords = entry.coords_warmup_remaining() > 0;
        if !entry.is_established() {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "session not established".into(),
            });
        }

        // Build port-prefixed plaintext: [src_port:2 LE][dst_port:2 LE][payload...]
        let mut port_payload = Vec::with_capacity(FSP_PORT_HEADER_SIZE + payload.len());
        port_payload.extend_from_slice(&src_port.to_le_bytes());
        port_payload.extend_from_slice(&dst_port.to_le_bytes());
        port_payload.extend_from_slice(payload);

        let msg_type = SessionMessageType::DataPacket.to_byte(); // 0x10

        // With no coordinates cached for the destination, send without CP
        // and leave the warmup budget unspent: our own coordinates in the
        // destination's slot would be filed under its address by every
        // receiver, and the budget is better spent on the first frames after
        // discovery refills the cache.
        let cached_dst = if wants_coords {
            self.cached_dest_coords(dest_addr)
        } else {
            None
        };
        let warming = cached_dst.is_some();

        // Determine whether coords fit within transport MTU.
        // If not, send standalone CoordsWarmup before the data packet.
        let (include_coords, my_coords, dest_coords) = if let Some(dst) = cached_dst {
            let src = self.tree_state.my_coords().clone();
            let coords_size = coords_wire_size(&src) + coords_wire_size(&dst);
            let total_wire =
                FIPS_OVERHEAD as usize + FSP_PORT_HEADER_SIZE + coords_size + payload.len();
            if total_wire <= self.transport_mtu() as usize {
                (true, Some(src), Some(dst))
            } else {
                // Coords don't fit piggybacked — send standalone CoordsWarmup first
                if let Err(e) = self.send_coords_warmup(dest_addr).await {
                    debug!(dest = %self.peer_display_name(dest_addr), error = %e,
                        "Failed to send standalone CoordsWarmup before data packet");
                }
                (false, None, None)
            }
        } else {
            (false, None, None)
        };

        // Decrement warmup counter if we sent coords (piggybacked or standalone)
        if warming && let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        }

        // FSP flags: CP if coords ride along. The key-epoch bit, like the
        // timestamp and the spin bit, comes from the epoch the frame is
        // sealed under.
        let flags = if include_coords { FSP_FLAG_CP } else { 0 };

        // ── Pipelined FSP+FMP fast path (unix + UDP) ──
        // Both AEAD layers + the sendmmsg syscall run on the encrypt
        // worker. The rx_loop only builds the wire buffer + reserves
        // counters on both sessions. Falls through to the legacy
        // sync FSP encrypt + send_session_datagram path on any
        // prereq miss (non-UDP, no worker, no cipher, …).
        #[cfg(unix)]
        if self
            .try_send_session_data_pipelined(PipelinedSend {
                dest_addr,
                payload,
                now,
                fsp_flags: flags,
                body: &port_payload,
                my_coords: my_coords.as_ref(),
                dest_coords: dest_coords.as_ref(),
            })
            .await?
        {
            return Ok(());
        }

        // Borrow session for counter + encryption (after potential standalone send)
        let local = self.session_node_keys();
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        // Seal under the current epoch, with the 12-byte FSP header built on
        // the reserved counter as the AAD.
        let frame = entry
            .seal_frame(now, flags, msg_type, &port_payload)
            .map_err(|e| seal_error(*dest_addr, e))?;
        entry.data_sent(now, &local);

        // Assemble: header(12) + [coords] + ciphertext
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + frame.ciphertext.len() + 200);
        fsp_payload.extend_from_slice(&frame.header);
        if let (Some(src), Some(dst)) = (&my_coords, &dest_coords) {
            encode_coords(src, &mut fsp_payload);
            encode_coords(dst, &mut fsp_payload);
        }
        fsp_payload.extend_from_slice(&frame.ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config().node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Re-borrow after send (which borrowed &mut self)
        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.record_sent(payload.len());
            if let Some(mmp) = entry.mmp_mut() {
                mmp.sender
                    .record_sent(frame.counter, frame.timestamp, frame.ciphertext.len());
            }
            entry.touch(now);
        }

        Ok(())
    }

    /// Pipelined send: FSP+FMP AEAD + sendmsg on the encrypt worker.
    ///
    /// Returns `Ok(true)` when the worker accepted the job (caller is
    /// done), `Ok(false)` on prereq miss (non-UDP, no worker, no
    /// cipher) so the caller falls back to the legacy synchronous
    /// path. `Err` on routing / state errors that prevent any send.
    ///
    /// Wire layout built directly (no intermediate `inner_plaintext`
    /// or `fsp_payload` Vecs):
    /// ```text
    ///   [16 FMP header][8 link-ts][1 SessionDatagram][1 ttl][2 mtu]
    ///   [16 src_addr][16 dest_addr][12 FSP header][coords?]
    ///   [FSP plaintext]    <- worker seals here, appends FSP tag,
    ///                         then seals the full FMP plaintext and
    ///                         appends the FMP tag.
    /// ```
    #[cfg(unix)]
    async fn try_send_session_data_pipelined(
        &mut self,
        send: PipelinedSend<'_>,
    ) -> Result<bool, NodeError> {
        let dest_addr = send.dest_addr;
        let Some(workers) = self.supervisor.encrypt_workers.as_ref().cloned() else {
            return Ok(false);
        };

        let Some(next_hop_addr) = self.find_next_hop(dest_addr).map(|peer| *peer.node_addr())
        else {
            return Err(NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no route to destination".into(),
            });
        };

        // Read the next hop's transport / link MTU for the
        // SessionDatagram's path_mtu field. Saves a path_mtu round-
        // trip vs the legacy path where we'd seed in
        // send_session_datagram.
        let mut path_mtu = u16::MAX;
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            if let Some(addr) = peer.current_addr() {
                path_mtu = path_mtu.min(transport.link_mtu(addr));
            } else {
                path_mtu = path_mtu.min(transport.mtu());
            }
        }

        // Extract next-hop info + FMP cipher in one peers/sessions borrow scope.
        let (their_index, transport_id, remote_addr, timestamp_ms, fmp_flags, fmp_cipher) = {
            let peer = self
                .peers
                .get_mut(&next_hop_addr)
                .ok_or(NodeError::PeerNotFound(next_hop_addr))?;
            let their_index = peer.their_index().ok_or_else(|| NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: "no their_index".into(),
            })?;
            let transport_id = peer.transport_id().ok_or_else(|| NodeError::SendFailed {
                node_addr: next_hop_addr,
                reason: "no transport_id".into(),
            })?;
            let remote_addr =
                peer.current_addr()
                    .cloned()
                    .ok_or_else(|| NodeError::SendFailed {
                        node_addr: next_hop_addr,
                        reason: "no current_addr".into(),
                    })?;
            let timestamp_ms = peer.session_elapsed_ms();
            let sp_flag = peer.mmp().map(|m| m.spin_bit.tx_bit()).unwrap_or(false);
            let mut fmp_flags = if sp_flag { FLAG_SP } else { 0 };
            if peer.current_k_bit() {
                fmp_flags |= FLAG_KEY_EPOCH;
            }
            let session = peer
                .noise_session_mut()
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: next_hop_addr,
                    reason: "no noise session".into(),
                })?;
            let Some(fmp_cipher) = session.send_cipher_clone() else {
                return Ok(false);
            };
            (
                their_index,
                transport_id,
                remote_addr,
                timestamp_ms,
                fmp_flags,
                fmp_cipher,
            )
        };
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let connected_socket = self
            .peers
            .get(&next_hop_addr)
            .and_then(|peer| peer.connected_udp());

        // Need a UDP transport (this whole path is sendmsg-on-raw-fd).
        let transport = self
            .transports
            .get(&transport_id)
            .ok_or(NodeError::TransportNotFound(transport_id))?;
        let TransportHandle::Udp(udp) = transport else {
            return Ok(false);
        };
        let socket_addr_opt = {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            {
                match connected_socket.as_ref() {
                    Some(s) => Some(s.peer_addr()),
                    None => udp.resolve_for_off_task(&remote_addr).await.ok(),
                }
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                udp.resolve_for_off_task(&remote_addr).await.ok()
            }
        };
        let Some(socket_addr) = socket_addr_opt else {
            return Ok(false);
        };
        let Some(socket) = udp.async_socket() else {
            return Ok(false);
        };
        let stats = udp.stats().clone();

        // The FSP message, counter and cipher, each fixed by the current
        // epoch — a separate session from the next-hop FMP session.
        let local = self.session_node_keys();
        let fsp = {
            let entry = self
                .sessions
                .get_mut(dest_addr)
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "no session".into(),
                })?;
            if let Some(mmp) = entry.mmp_mut() {
                mmp.path_mtu.seed_source_mtu(path_mtu);
            }
            match entry.reserve_send(
                send.now,
                send.fsp_flags,
                SessionMessageType::DataPacket.to_byte(),
                send.body,
            ) {
                Ok(Some(reserved)) => {
                    entry.data_sent(send.now, &local);
                    reserved
                }
                Ok(None) => return Ok(false),
                Err(SealFailure::NotEstablished) => {
                    return Err(NodeError::SendFailed {
                        node_addr: *dest_addr,
                        reason: "session not established".into(),
                    });
                }
                Err(SealFailure::Noise(e)) => {
                    return Err(NodeError::SendFailed {
                        node_addr: *dest_addr,
                        reason: format!("session counter reservation failed: {}", e),
                    });
                }
            }
        };

        let coords_size = match (send.my_coords, send.dest_coords) {
            (Some(src), Some(dst)) => coords_wire_size(src) + coords_wire_size(dst),
            _ => 0,
        };
        // FMP inner = [link-ts u64][SessionDatagram-encoded after msg_type] + [FSP-encrypted blob]
        // SessionDatagram-encoded includes: [0x00 type][ttl][mtu][src][dest][fsp_payload]
        // fsp_payload = [fsp_header][coords][fsp_plaintext][16-byte FSP tag]
        let link_plaintext_len =
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + coords_size + fsp.plaintext.len();
        let fmp_inner_len = 4 + link_plaintext_len + crate::noise::TAG_SIZE;

        // FMP counter + header (the AAD for the outer AEAD seal).
        let fmp_counter = {
            let peer = self
                .peers
                .get_mut(&next_hop_addr)
                .ok_or(NodeError::PeerNotFound(next_hop_addr))?;
            let session = peer
                .noise_session_mut()
                .ok_or_else(|| NodeError::SendFailed {
                    node_addr: next_hop_addr,
                    reason: "no noise session".into(),
                })?;
            session
                .take_send_counter()
                .map_err(|e| NodeError::SendFailed {
                    node_addr: next_hop_addr,
                    reason: format!("counter reservation failed: {}", e),
                })?
        };
        let fmp_header =
            build_established_header(their_index, fmp_counter, fmp_flags, fmp_inner_len as u16);

        // Build the wire buffer once, in place. The two FSP/FMP tags
        // are appended by the worker after the seals — reserve their
        // capacity here so the worker doesn't have to re-grow.
        let wire_capacity = ESTABLISHED_HEADER_SIZE + fmp_inner_len + crate::noise::TAG_SIZE;
        let mut wire_buf = Vec::with_capacity(wire_capacity);
        wire_buf.extend_from_slice(&fmp_header);
        wire_buf.extend_from_slice(&timestamp_ms.to_le_bytes());
        // SessionDatagram-encoded layout (matches `SessionDatagram::encode`):
        wire_buf.push(LinkMessageType::SessionDatagram.to_byte());
        wire_buf.push(self.config().node.session.default_ttl);
        wire_buf.extend_from_slice(&path_mtu.to_le_bytes());
        wire_buf.extend_from_slice(self.node_addr().as_bytes());
        wire_buf.extend_from_slice(dest_addr.as_bytes());
        // FSP layer (worker seals on `inner_plaintext` portion):
        let fsp_aad_offset = wire_buf.len();
        wire_buf.extend_from_slice(&fsp.header);
        if let (Some(src), Some(dst)) = (send.my_coords, send.dest_coords) {
            encode_coords(src, &mut wire_buf);
            encode_coords(dst, &mut wire_buf);
        }
        let fsp_plaintext_offset = wire_buf.len();
        wire_buf.extend_from_slice(&fsp.plaintext);

        // Stats update — predict size exactly (ChaCha20-Poly1305 tag
        // is constant 16 bytes).
        let predicted_bytes = wire_capacity;
        if let Some(peer) = self.peers.get_mut(&next_hop_addr) {
            peer.link_stats_mut().record_sent(predicted_bytes);
            if let Some(mmp) = peer.mmp_mut() {
                mmp.sender
                    .record_sent(fmp_counter, timestamp_ms, predicted_bytes);
            }
        }
        self.metrics()
            .forwarding
            .record_originated(link_plaintext_len + crate::noise::TAG_SIZE);

        if let Some(entry) = self.sessions.get_mut(dest_addr) {
            entry.record_sent(send.payload.len());
            entry.record_sent_wire_len(wire_capacity);
            if let Some(mmp) = entry.mmp_mut() {
                mmp.sender.record_sent(
                    fsp.counter,
                    fsp.timestamp,
                    fsp.plaintext.len() + crate::noise::TAG_SIZE,
                );
            }
            entry.touch(send.now);
        }

        let dispatched = workers.dispatch(crate::node::encrypt_worker::FmpSendJob {
            cipher: fmp_cipher,
            counter: fmp_counter,
            wire_buf,
            fsp_seal: Some(crate::node::encrypt_worker::FspSealJob {
                cipher: fsp.key,
                counter: fsp.counter,
                aad_offset: fsp_aad_offset,
                plaintext_offset: fsp_plaintext_offset,
            }),
            socket,
            dest_addr: socket_addr,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket,
            stats,
            // Bulk endpoint data: drop on UDP backpressure so the
            // worker queue keeps moving instead of stranding under
            // sustained congestion.
            drop_on_backpressure: true,
            queued_at: None,
        });
        if let Err(job) = dispatched {
            self.send_refused_job_inline(*job, transport_id, &remote_addr, next_hop_addr)
                .await;
        }
        Ok(true)
    }

    /// Seal and send a job the encrypt worker for its next hop refused
    /// because that worker has exited, using the FSP and FMP counters the
    /// job already reserved so neither counter is skipped. Stats were
    /// recorded before dispatch and now describe this packet.
    ///
    /// A failure is logged and swallowed, as the worker does with its own:
    /// the caller sees the same result whichever of the two sent the packet.
    #[cfg(unix)]
    async fn send_refused_job_inline(
        &self,
        job: crate::node::encrypt_worker::FmpSendJob,
        transport_id: crate::transport::TransportId,
        remote_addr: &crate::transport::TransportAddr,
        next_hop_addr: NodeAddr,
    ) {
        let wire = match job.seal_inline() {
            Ok(wire) => wire,
            Err(error) => {
                debug!(next_hop = %next_hop_addr, %error, "Inline seal of session data failed");
                return;
            }
        };
        let Some(transport) = self.transports.get(&transport_id) else {
            debug!(next_hop = %next_hop_addr, "Transport gone before inline send of session data");
            return;
        };
        if let Err(error) = transport.send_existing(remote_addr, &wire).await {
            debug!(next_hop = %next_hop_addr, %error, "Inline send of session data failed");
        }
    }

    /// Send an IPv6 packet through the IPv6 shim (port 256) with header compression.
    ///
    /// Compresses the IPv6 header (format 0x00), then sends via `send_session_data`
    /// with `src_port=256, dst_port=256`.
    pub(in crate::node) async fn send_ipv6_packet(
        &mut self,
        dest_addr: &NodeAddr,
        ipv6_packet: &[u8],
    ) -> Result<(), NodeError> {
        let compressed =
            crate::ipv6tun::ipv6_shim::compress_ipv6(ipv6_packet).ok_or_else(|| {
                NodeError::SendFailed {
                    node_addr: *dest_addr,
                    reason: "IPv6 header compression failed".into(),
                }
            })?;
        self.send_session_data(
            dest_addr,
            FSP_PORT_IPV6_SHIM,
            FSP_PORT_IPV6_SHIM,
            &compressed,
        )
        .await
    }

    /// Send a non-data session message (reports, notifications) over an established session.
    ///
    /// Similar to `send_session_data()` but:
    /// - Takes an explicit `msg_type` byte (0x11, 0x12, 0x13, etc.)
    /// - Never includes COORDS_PRESENT (reports are lightweight)
    /// - Takes the key-epoch bit, the timestamp and the spin bit from the
    ///   epoch it is sealed under, as every send path does
    /// - Records the send in MMP sender state
    pub(in crate::node) async fn send_session_msg(
        &mut self,
        dest_addr: &NodeAddr,
        msg_type: u8,
        payload: &[u8],
    ) -> Result<(), NodeError> {
        let now = Self::session_now();

        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;

        // Seal under the current epoch with no CP flag, the 12-byte FSP
        // header built on the reserved counter as the AAD.
        let frame = entry
            .seal_frame(now, 0, msg_type, payload)
            .map_err(|e| seal_error(*dest_addr, e))?;

        // Assemble: header(12) + ciphertext (no coords)
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + frame.ciphertext.len());
        fsp_payload.extend_from_slice(&frame.header);
        fsp_payload.extend_from_slice(&frame.ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config().node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Record in MMP sender state (no touch — MMP reports don't reset idle timer)
        if let Some(entry) = self.sessions.get_mut(dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.sender
                .record_sent(frame.counter, frame.timestamp, frame.ciphertext.len());
        }

        Ok(())
    }

    /// Send a standalone CoordsWarmup message to warm transit node caches.
    ///
    /// Constructs an encrypted FSP message with CP flag set and
    /// msg_type=CoordsWarmup. Transit nodes extract the cleartext
    /// coordinates via `try_warm_coord_cache()` (same as CP-flagged data
    /// packets). The encrypted inner payload is the 6-byte inner header
    /// with no application data.
    pub(in crate::node) async fn send_coords_warmup(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Result<(), NodeError> {
        let now = Self::session_now();

        // A warmup's only content is the two coordinates; with none cached
        // for the destination, ours would stand in for its own.
        let Some(dest_coords) = self.cached_dest_coords(dest_addr) else {
            trace!(
                dest = %self.peer_display_name(dest_addr),
                "No cached coordinates for destination, skipping CoordsWarmup"
            );
            return Ok(());
        };
        let my_coords = self.tree_state.my_coords().clone();

        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or_else(|| NodeError::SendFailed {
                node_addr: *dest_addr,
                reason: "no session".into(),
            })?;
        // FSP inner header only, no body payload, sealed under the current
        // epoch with the CP flag; the key-epoch bit is that epoch's, as on
        // every other message.
        let msg_type = SessionMessageType::CoordsWarmup.to_byte();
        let frame = entry
            .seal_frame(now, FSP_FLAG_CP, msg_type, &[])
            .map_err(|e| seal_error(*dest_addr, e))?;

        // Assemble: header(12) + coords + ciphertext
        let coords_size = coords_wire_size(&my_coords) + coords_wire_size(&dest_coords);
        let mut fsp_payload =
            Vec::with_capacity(FSP_HEADER_SIZE + coords_size + frame.ciphertext.len());
        fsp_payload.extend_from_slice(&frame.header);
        encode_coords(&my_coords, &mut fsp_payload);
        encode_coords(&dest_coords, &mut fsp_payload);
        fsp_payload.extend_from_slice(&frame.ciphertext);

        let my_addr = *self.node_addr();
        let mut datagram = SessionDatagram::new(my_addr, *dest_addr, fsp_payload)
            .with_ttl(self.config().node.session.default_ttl);

        self.send_session_datagram(&mut datagram).await?;

        // Record in MMP (infrastructure traffic — no idle timer touch)
        if let Some(entry) = self.sessions.get_mut(dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.sender
                .record_sent(frame.counter, frame.timestamp, frame.ciphertext.len());
        }

        debug!(dest = %self.peer_display_name(dest_addr), "Sent standalone CoordsWarmup");
        Ok(())
    }

    /// Route and send a SessionDatagram through the mesh.
    ///
    /// Finds the next hop for the destination, seeds path_mtu from the
    /// first-hop transport MTU, and sends as an encrypted link message.
    pub(in crate::node) async fn send_session_datagram(
        &mut self,
        datagram: &mut SessionDatagram,
    ) -> Result<(), NodeError> {
        let next_hop_addr = match self.find_next_hop(&datagram.dest_addr) {
            Some(peer) => *peer.node_addr(),
            None => {
                return Err(NodeError::SendFailed {
                    node_addr: datagram.dest_addr,
                    reason: "no route to destination".into(),
                });
            }
        };

        // Seed path_mtu from the first-hop transport MTU (same as forwarding path)
        if let Some(peer) = self.peers.get(&next_hop_addr)
            && let Some(tid) = peer.transport_id()
            && let Some(transport) = self.transports.get(&tid)
        {
            if let Some(addr) = peer.current_addr() {
                datagram.path_mtu = datagram.path_mtu.min(transport.link_mtu(addr));
            } else {
                datagram.path_mtu = datagram.path_mtu.min(transport.mtu());
            }
        }

        // Source-side: seed our PathMtuState.current_mtu from the outbound
        // transport MTU so it doesn't stay at u16::MAX until the destination
        // sends a PathMtuNotification back.
        if let Some(entry) = self.sessions.get_mut(&datagram.dest_addr)
            && let Some(mmp) = entry.mmp_mut()
        {
            mmp.path_mtu.seed_source_mtu(datagram.path_mtu);
        }

        let encoded = datagram.encode();
        self.send_encrypted_link_message(&next_hop_addr, &encoded)
            .await?;
        self.metrics().forwarding.record_originated(encoded.len());

        // Evidence for the reactive path-MTU carrier. A transit hop
        // re-encapsulates what it forwards, so the frame that overflows a
        // downstream link is the size this frame is here.
        if let Some(entry) = self.sessions.get_mut(&datagram.dest_addr) {
            entry.record_sent_wire_len(link_wire_len(encoded.len()));
        }
        Ok(())
    }

    /// Look up destination coordinates in the coordinate cache, with no
    /// fallback.
    ///
    /// Use this wherever the coordinates go on the wire as the destination's
    /// own: a miss must not be filled with ours, which every receiver would
    /// file under the destination's address.
    pub(in crate::node) fn cached_dest_coords(
        &self,
        dest: &NodeAddr,
    ) -> Option<crate::proto::stp::TreeCoordinate> {
        self.coord_cache.get(dest, Self::now_ms()).cloned()
    }

    /// Current Unix time in milliseconds.
    pub(in crate::node) fn now_ms() -> u64 {
        crate::time::wall_ms()
    }

    /// Now on the session table's clock, [`SessionClock`].
    pub(crate) fn session_now() -> SessionInstant {
        SessionClock::default().now()
    }

    /// The parameters of this node's session rekey machines.
    pub(in crate::node) fn session_params(&self) -> Params {
        session_params(&self.config().node)
    }

    /// This node's static keypair and startup epoch, as the session rekey
    /// machines take them. The copy erases itself when dropped.
    pub(in crate::node) fn session_node_keys(&self) -> NodeKeys {
        NodeKeys::new(self.identity().keypair(), self.startup_epoch())
    }

    /// The time the session-setup limiter is charged at: the host's
    /// monotonic clock, or in tests the clock a test set in `setup_clock`.
    fn setup_now(&self) -> crate::time::HostInstant {
        #[cfg(test)]
        if let Some(clock) = self.setup_clock {
            return clock();
        }
        crate::time::HostClock.now()
    }

    // === TUN Outbound (Data Plane) ===

    /// Handle an outbound IPv6 packet from the TUN reader.
    ///
    /// The host-side checks and ICMPv6 replies are in
    /// [`crate::ipv6tun::outbound::forward`], which reaches back into the
    /// node through its [`Mesh`] impl: the destination prefix is resolved
    /// in the identity cache, and the packet is sent on an established
    /// session or queued while one is set up.
    ///
    /// Also performs MTU checking: if the packet (plus FIPS overhead) exceeds
    /// the transport MTU, an ICMP Packet Too Big message is sent back to the
    /// source and the packet is dropped.
    pub(in crate::node) async fn handle_tun_outbound(&mut self, ipv6_packet: Vec<u8>) {
        crate::ipv6tun::outbound::forward(self, ipv6_packet).await;
    }

    /// Send a TUN packet to a resolved destination, or queue it while the
    /// destination's session is set up.
    ///
    /// Sends through an established session, queues behind one still being
    /// set up, and otherwise initiates a session and queues. When the
    /// initiation fails it starts discovery and queues while a lookup is
    /// running or routing is still converging. Otherwise it hands the packet
    /// back as `Outcome::NoRoute` to be answered, or, when the destination
    /// has a route and only the setup failed, drops it unanswered for a
    /// retransmit to retry. Refuses the packet, handing it back, when a new
    /// session would exceed the session table.
    async fn send_outbound(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: PublicKey,
        ipv6_packet: Vec<u8>,
    ) -> Outcome {
        // Check for established session
        if let Some(entry) = self.sessions.get(&dest_addr) {
            if entry.is_established() {
                if let Err(e) = self.send_ipv6_packet(&dest_addr, &ipv6_packet).await {
                    debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to send TUN packet via session");
                    self.relookup_lost_route(&dest_addr).await;
                }
                return Outcome::Sent;
            }
            // Session exists but not yet established — queue the packet. A
            // refusal from a full table stays a silent drop: the session's own
            // establishment or timeout settles the flow, and a retransmit goes
            // through once it is established.
            //
            // A session holding only the peer's setups was opened by setups
            // nobody has proven, possibly forged, so this node starts its own
            // attempt beside them at once.
            if !entry.is_initiating() {
                self.initiate_behind_candidates(dest_addr, dest_pubkey)
                    .await;
            }
            let _ = self.queue_pending_packet(dest_addr, ipv6_packet);
            return Outcome::Queued;
        }

        // No session, so this one would grow the table. Answer the local
        // application the way an unroutable destination is answered rather
        // than returning an error from `initiate_session`: the caller reads
        // an error as "no route" and responds with a discovery lookup and a
        // queued packet, which is outbound traffic on a node already at its
        // limit.
        if !self.admit_new_session(&dest_addr) {
            return Outcome::TableFull(ipv6_packet);
        }

        // No session: initiate one and queue the packet.
        // If session initiation fails (no route), trigger discovery and
        // queue the packet for retry when discovery completes, unless no
        // lookup is running and routing has had time to converge: then
        // nothing would ever send it, so answer it now. A destination with a
        // route whose setup failed on the link is dropped unanswered instead,
        // for a retransmit to retry.
        if let Err(e) = self.initiate_session(dest_addr, dest_pubkey).await {
            debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to initiate session, trying discovery");
            let kind = self.maybe_initiate_lookup(&dest_addr).await.kind();
            let in_hold = self.routing_hold_active(std::time::Instant::now());
            let routed =
                self.peers.contains_key(&dest_addr) || self.find_next_hop(&dest_addr).is_some();
            match held_fate(kind, in_hold, routed) {
                HeldFate::Answer => {
                    let released = self.release_held_tun(&dest_addr);
                    debug!(
                        dest = %self.peer_display_name(&dest_addr),
                        kind = ?kind,
                        released,
                        reason = "no-lookup",
                        "No lookup pending for destination, answering no route"
                    );
                    return Outcome::NoRoute(ipv6_packet);
                }
                HeldFate::Discard => {
                    debug!(
                        dest = %self.peer_display_name(&dest_addr),
                        kind = ?kind,
                        reason = "setup-failed",
                        "Session setup to a routed destination failed, dropping for a retransmit to retry"
                    );
                }
                HeldFate::Hold => {
                    // A refusal from a full table stays a silent drop: a
                    // lookup is in flight or routing is converging, and a
                    // retransmit is held once a slot frees.
                    let _ = self.queue_pending_packet(dest_addr, ipv6_packet);
                    // Age the destination from the lookup that can settle
                    // it, not from a packet held earlier inside the hold.
                    match kind {
                        LookupOutcomeKind::Sent => {
                            self.restamp_held(&dest_addr, Restamp::LookupSent);
                        }
                        LookupOutcomeKind::Deduplicated => {
                            self.restamp_held(&dest_addr, Restamp::LookupRidden);
                        }
                        _ => {}
                    }
                }
            }
            return Outcome::Queued;
        }
        // A refusal stays a silent drop, as behind a session being set up
        // above: this session's establishment or timeout settles the flow.
        let _ = self.queue_pending_packet(dest_addr, ipv6_packet);
        // The destination may already have been held before this session
        // started; age it from the start.
        self.restamp_held(&dest_addr, Restamp::SessionStarted);
        Outcome::Queued
    }

    /// Start this node's own attempt toward `dest_addr` beside the
    /// candidates a session the peer's setups opened holds, keeping them for
    /// a late msg3.
    ///
    /// With no route to the destination the initiation fails, and discovery
    /// is asked for one, as when no entry exists: otherwise every packet
    /// would retry the initiation and nothing would look for a route until
    /// the entry was reaped. The packets stay held behind the entry, whose
    /// establishment or reap settles them.
    pub(in crate::node) async fn initiate_behind_candidates(
        &mut self,
        dest_addr: NodeAddr,
        dest_pubkey: PublicKey,
    ) {
        debug!(
            dest = %self.peer_display_name(&dest_addr),
            "Session holds only the peer's setups, initiating our own beside them"
        );
        if let Err(e) = self.initiate_session(dest_addr, dest_pubkey).await {
            debug!(dest = %self.peer_display_name(&dest_addr), error = %e, "Failed to initiate a session beside the peer's setups, trying discovery");
            self.maybe_initiate_lookup(&dest_addr).await;
        }
    }

    /// Whether the routing hold applies at `now`, after noting the current
    /// peer table. The caller passes the time so one decision uses one clock
    /// reading.
    pub(in crate::node) fn routing_hold_active(&mut self, now: std::time::Instant) -> bool {
        self.routing_hold.observe(!self.peers.is_empty(), now);
        self.routing_hold.active(now)
    }

    /// Drop every TUN packet held for `dest`, answering each with ICMPv6
    /// Destination Unreachable, the answer a final lookup timeout gives.
    /// Returns how many were released, for the caller's log.
    pub(in crate::node) fn release_held_tun(&mut self, dest: &NodeAddr) -> usize {
        self.pending_tun_since.remove(dest);
        let Some(packets) = self.pending_tun_packets.remove(dest) else {
            return 0;
        };
        self.host_icmp().no_route(&packets);
        packets.len()
    }

    /// Release `dest`'s held TUN packets as [`Self::release_held_tun`] does,
    /// unless a session entry for it exists in any state: that session's
    /// establishment or timeout settles them. Returns how many were released.
    fn release_orphans(&mut self, dest: &NodeAddr) -> usize {
        if self.sessions.contains_key(dest) {
            0
        } else {
            self.release_held_tun(dest)
        }
    }

    /// Restart the age of `dest`'s held packets, if it has any, because
    /// `cause` started work that can settle them (see [`HeldStamp::restart`]).
    /// A destination with no queue gets no stamp, so a refused packet adds
    /// none.
    fn restamp_held(&mut self, dest: &NodeAddr, cause: Restamp) {
        if !self.pending_tun_packets.contains_key(dest) {
            return;
        }
        let now = std::time::Instant::now();
        self.pending_tun_since
            .entry(*dest)
            .or_insert_with(|| HeldStamp::new(now))
            .restart(cause, now);
    }

    /// Borrow the host-facing ICMPv6 sender: the TUN channel, our address
    /// and the Packet Too Big rate limiter.
    pub(in crate::node) fn host_icmp(&mut self) -> IcmpContext<'_> {
        self.supervisor.ipv6tun.icmp()
    }

    /// Queue a packet while waiting for session establishment.
    ///
    /// Refuses, dropping the packet, when the destination is new and
    /// `node.session.pending_max_destinations` destinations already have
    /// packets held.
    fn queue_pending_packet(&mut self, dest_addr: NodeAddr, packet: Vec<u8>) -> Held {
        let max_dests = self.config().node.session.pending_max_destinations;
        let is_new = !self.pending_tun_packets.contains_key(&dest_addr);
        if is_new && self.pending_tun_packets.len() >= max_dests {
            debug!(
                dest = %self.peer_display_name(&dest_addr),
                reason = "held-destination-table-full",
                "Held TUN packet refused"
            );
            self.stats_mut().record_reject(RejectReason::Session(
                SessionReject::PendingDestinationsFull,
            ));
            if self.pending_tun_bound_log.refused(1) {
                warn!(
                    bound = max_dests,
                    "Held-packet destination table full; packets to new destinations are refused"
                );
            }
            return Held::Refused;
        }

        if is_new {
            self.pending_tun_since
                .insert(dest_addr, HeldStamp::new(std::time::Instant::now()));
        }
        let per_dest = self.config().node.session.pending_packets_per_dest;
        let queue = self.pending_tun_packets.entry(dest_addr).or_default();
        crate::proto::fsp::push_bounded_pending(queue, packet, per_dest);
        Held::Queued
    }

    /// Flush pending packets for a destination whose session just reached Established.
    async fn flush_pending_packets(&mut self, dest_addr: &NodeAddr) {
        let packets = match self.pending_tun_packets.remove(dest_addr) {
            Some(q) => q,
            None => return,
        };
        for packet in packets {
            if let Err(e) = self.send_ipv6_packet(dest_addr, &packet).await {
                debug!(dest = %self.peer_display_name(dest_addr), error = %e, "Failed to send queued TUN packet");
                break;
            }
        }
    }

    /// Retry session initiation after discovery provided coordinates.
    ///
    /// Called when a LookupResponse arrives and we have pending TUN packets
    /// or native datagrams for the discovered target. The coord_cache now
    /// has coords, so `find_next_hop()` should succeed and the SessionSetup
    /// can be sent.
    pub(in crate::node) async fn retry_session_after_discovery(&mut self, dest_addr: NodeAddr) {
        // Look up the destination's public key from the identity cache
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&dest_addr.as_bytes()[0..15]);
        // The lookup has ended, so where the retry below starts no session
        // and finds no session entry, nothing is working on the held TUN
        // packets: they are answered now rather than left for the tick.
        let dest_pubkey = match self.lookup_by_fips_prefix(&prefix) {
            Some((_, pk)) => pk,
            None => {
                // A session entry can exist without a cached identity.
                let released = self.release_orphans(&dest_addr);
                debug!(
                    dest = %self.peer_display_name(&dest_addr),
                    released,
                    reason = "no-identity",
                    "Discovery complete but no identity for session retry"
                );
                return;
            }
        };

        // Skip if a session already exists or this node is already
        // initiating one; its establishment or timeout settles the held
        // packets. The peer's setups alone do not count, as in
        // `initiate_session`.
        if let Some(existing) = self.sessions.get(&dest_addr)
            && (existing.is_established() || existing.is_initiating())
        {
            return;
        }

        if !self.admit_new_session(&dest_addr) {
            let released = self.release_held_tun(&dest_addr);
            debug!(
                dest = %self.peer_display_name(&dest_addr),
                released,
                reason = "admission-refused",
                "Session retry after discovery not admitted"
            );
            return;
        }

        match self.initiate_session(dest_addr, dest_pubkey).await {
            Ok(()) => {
                self.restamp_held(&dest_addr, Restamp::SessionStarted);
                debug!(dest = %self.peer_display_name(&dest_addr), "Session initiated after discovery");
            }
            Err(e) => {
                // A responder handshake survives a failed initiation.
                let released = self.release_orphans(&dest_addr);
                debug!(
                    dest = %self.peer_display_name(&dest_addr),
                    error = %e,
                    released,
                    reason = "initiate-failed",
                    "Session retry after discovery failed"
                );
            }
        }
    }
}

/// The mesh side of TUN outbound forwarding.
impl Mesh for Node {
    type Dest = (NodeAddr, PublicKey);

    fn ipv6_mtu(&self) -> u16 {
        self.effective_ipv6_mtu()
    }

    fn resolve(&mut self, prefix: &[u8; 15]) -> Option<Route<Self::Dest>> {
        // Look up in identity cache
        let (dest_addr, dest_pubkey) = self.lookup_by_fips_prefix(prefix)?;
        let path_mtu = self
            .sessions
            .get(&dest_addr)
            .filter(|entry| entry.is_established())
            .and_then(|entry| entry.mmp())
            .map(|mmp| mmp.path_mtu.current_mtu());
        Some(Route {
            dest: (dest_addr, dest_pubkey),
            path_mtu,
        })
    }

    fn send(&mut self, dest: Self::Dest, packet: Vec<u8>) -> impl Future<Output = Outcome> + Send {
        let (dest_addr, dest_pubkey) = dest;
        self.send_outbound(dest_addr, dest_pubkey, packet)
    }

    fn icmp(&mut self) -> IcmpContext<'_> {
        self.host_icmp()
    }
}

/// The send failure a refused session seal is reported as, worded as the
/// session's own encrypt refusals have always been.
fn seal_error(node_addr: NodeAddr, failure: SealFailure) -> NodeError {
    let reason = match failure {
        SealFailure::NotEstablished => "session not established".into(),
        SealFailure::Noise(e) => format!("session encrypt failed: {}", e),
    };
    NodeError::SendFailed { node_addr, reason }
}
