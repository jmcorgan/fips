//! Sans-IO FMP connection-lifecycle decision core.
//!
//! Pure, runtime-agnostic maintain/teardown decisions for the FMP peer
//! connection lifecycle: handshake-connection timeout/teardown and outbound
//! msg1 resend scheduling. The async I/O adapters in `node::handlers::timeout`
//! build a [`LifecycleView`] over live node state (pre-computing every clock
//! read into plain `u64`/`bool` snapshot fields), call the `poll_*` decisions,
//! and drive the returned [`ConnAction`]s — the actual sends, registry
//! mutations, metrics, and logging. No I/O, no clock, no metrics, no logging
//! here.
//!
//! The establish leaf's Noise wire construction and `promote_connection`
//! effects stay shell-side; handshake message bytes are carried as opaque blobs
//! only. The **inbound classification** decision, however, is modelled here:
//! [`Fmp::establish_inbound`] maps an [`EstablishSnapshot`] + [`WireOutcome`]
//! onto an [`InboundDecision`] the shell dispatches (E3). The outbound
//! (`handle_msg2`) classification and the born-on-next `handle_msg3` leaf remain
//! shell-side.

use super::silent::{ActiveBackoff, epochs_differ};
use super::state::Fmp;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{NodeAddr, PeerIdentity};
use std::collections::VecDeque;

/// Determine winner of cross-connection tie-breaker.
///
/// Rule: The node with the smaller node_addr prefers its OUTBOUND connection.
/// This is deterministic and symmetric: both nodes will reach the same conclusion.
///
/// # Arguments
/// * `our_node_addr` - Our node's ID
/// * `their_node_addr` - The peer's node ID
/// * `this_is_outbound` - Whether the connection being evaluated is our outbound
///
/// # Returns
/// `true` if this connection should win (survive), `false` if it should close.
pub fn cross_connection_winner(
    our_node_addr: &NodeAddr,
    their_node_addr: &NodeAddr,
    this_is_outbound: bool,
) -> bool {
    let we_are_smaller = our_node_addr < their_node_addr;

    // Smaller node's outbound wins
    // If we're smaller: our outbound wins, our inbound loses
    // If they're smaller: our outbound loses, our inbound wins
    if we_are_smaller {
        this_is_outbound
    } else {
        !this_is_outbound
    }
}

/// Result of attempting to promote a connection to active peer.
///
/// When a handshake completes, we may discover that we already have a
/// connection to this peer (cross-connection). The tie-breaker rule
/// determines which connection survives.
///
/// Note: Returns NodeAddr instead of ActivePeer because ActivePeer cannot
/// be cloned (it contains NoiseSession which has cryptographic state).
/// Callers can look up the peer from the peers map using the NodeAddr.
#[derive(Debug, Clone, Copy)]
pub enum PromotionResult {
    /// New peer created successfully.
    Promoted(NodeAddr),

    /// Cross-connection detected. This connection lost the tie-breaker
    /// and should be closed.
    CrossConnectionLost {
        /// The link that won (existing connection).
        winner_link_id: LinkId,
    },

    /// Cross-connection detected. This connection won the tie-breaker.
    /// The existing connection was replaced.
    CrossConnectionWon {
        /// The link that lost (previous connection, now closed).
        loser_link_id: LinkId,
        /// The node ID of the peer.
        node_addr: NodeAddr,
    },
}

impl PromotionResult {
    /// Get the node ID if promotion succeeded.
    pub fn node_addr(&self) -> Option<NodeAddr> {
        match self {
            PromotionResult::Promoted(node_addr) => Some(*node_addr),
            PromotionResult::CrossConnectionWon { node_addr, .. } => Some(*node_addr),
            PromotionResult::CrossConnectionLost { .. } => None,
        }
    }

    /// Check if this connection should be closed.
    pub fn should_close_this_connection(&self) -> bool {
        matches!(self, PromotionResult::CrossConnectionLost { .. })
    }

    /// Get the link that should be closed, if any.
    pub fn link_to_close(&self) -> Option<LinkId> {
        match self {
            PromotionResult::CrossConnectionLost { .. } => None, // Caller's link
            PromotionResult::CrossConnectionWon { loser_link_id, .. } => Some(*loser_link_id),
            PromotionResult::Promoted(_) => None,
        }
    }
}

/// A snapshot of one handshake connection's lifecycle-relevant state, taken by
/// the shell so the core decides without touching live `Node` state or reading
/// a clock.
///
/// Produced by the [`LifecycleView`] read-seam. Each `poll_*` decision only
/// reads the subset of fields relevant to it; the producing view method leaves
/// the rest at their defaults.
pub(crate) struct ConnSnapshot {
    /// The connection's link identifier (teardown/resend target).
    pub link: LinkId,
    /// Teardown path: is this an outbound connection? Drives retry scheduling
    /// (only outbound auto-connect peers are retried).
    pub is_outbound: bool,
    /// Teardown path: the retry target learned from the connection's expected
    /// identity, if any. `None` when no identity is known.
    pub retry_addr: Option<NodeAddr>,
    /// Resend path: prior msg1 resend count. Drives the backoff exponent.
    pub resend_count: u32,
    /// Resend path: the stored outbound handshake msg1 wire bytes (an opaque
    /// blob — the core never parses or constructs a Noise message). Empty on
    /// the teardown path, which never reads it.
    pub msg1: Vec<u8>,
}

/// Which side of a link rekey handshake produced a pending session.
///
/// Only the side that initiated may commit to the new keys on its own
/// schedule: it holds proof that the peer derived them. The responder
/// learns that only when a frame sealed on the new epoch authenticates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RekeyRole {
    /// This node sent the rekey msg1 and read the peer's msg2.
    Initiator,
    /// This node answered the peer's rekey msg1 with a msg2.
    Responder,
}

/// A digest of one link handshake msg1 exactly as it arrived, header included.
///
/// The initiator's resend ladder retransmits its stored msg1 bytes unchanged,
/// so a resend digests equal to the original and any other msg1 does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Msg1Digest([u8; 32]);

impl Msg1Digest {
    /// Digest the wire bytes of one msg1.
    pub(crate) fn of(wire_msg1: &[u8]) -> Self {
        use sha2::{Digest, Sha256};
        Self(Sha256::digest(wire_msg1).into())
    }

    /// The first four bytes of the digest, the part the log lines carry.
    pub(crate) fn prefix(&self) -> [u8; 4] {
        [self.0[0], self.0[1], self.0[2], self.0[3]]
    }
}

/// What this node sent when it answered a peer's rekey msg1 as the responder:
/// the msg1 it answered, by digest, and the framed msg2 it sent back.
///
/// Kept with the pending session that answer armed, so a resend of that msg1
/// draws the same msg2 again rather than a refusal while the pending is held.
#[derive(Clone, Debug)]
pub(crate) struct RekeyAnswer {
    /// The msg1 that armed the pending session.
    pub msg1: Msg1Digest,
    /// The framed msg2 sent in answer, opaque to the core.
    pub msg2: Vec<u8>,
}

/// How many msg1s of ended cycles one peer's [`AnsweredMsg1s`] remembers.
///
/// A msg1 is answered as a rekey only once [`REKEY_MIN_CUTOVER_AGE_SECS`]
/// have passed since the last cutover, so answered cycles are at least 10 s
/// apart and this covers at least 43 minutes of the peer's cycles. Only a
/// peer whose message-count trigger fires every 10 s, on a busy link, cycles
/// that fast; at the default 120 s interval it covers eight and a half hours.
/// 32 bytes each, so 8 KiB per peer at most.
pub(crate) const ENDED_MSG1_RECORD: usize = 256;

/// The rekey msg1s this node answered as the link-rekey responder for one
/// peer, by digest.
///
/// A link msg1 carries nothing that ties it to one cycle, so a copy taken off
/// the wire still authenticates as the peer, in the peer's current epoch,
/// after the cycle it started has ended. This record is how a copy is told
/// from a fresh msg1. The answer that armed the pending session this node
/// holds is kept whole, so a resend of that msg1 draws the same msg2. When
/// the pending leaves (adopted, retired or abandoned) its digest moves to the
/// ended list, and a msg1 matching an ended cycle is refused instead of arming
/// a new pending.
///
/// The ended list also holds the link-setup msg1 the peering was promoted
/// from. A copy of it is no more a rekey than a copy of an ended cycle's
/// msg1, and once the session is old enough to rekey it would otherwise arm
/// a pending.
///
/// Retention is bounded: the ended list keeps the last
/// [`ENDED_MSG1_RECORD`] digests, so a msg1 from an older cycle of the same
/// epoch is not recognized. The record lives with the peer, so it starts empty
/// whenever the peering is established again while the peer's epoch stays the
/// same, as after this node restarts or the link is torn down and re-formed.
#[derive(Debug, Default)]
pub(crate) struct AnsweredMsg1s {
    held: Option<RekeyAnswer>,
    ended: VecDeque<Msg1Digest>,
}

impl AnsweredMsg1s {
    /// Record the answer that armed a new responder pending.
    pub(crate) fn arm(&mut self, answer: RekeyAnswer) {
        self.end();
        self.held = Some(answer);
    }

    /// The pending the held answer armed has left: keep only its digest.
    pub(crate) fn end(&mut self) {
        if let Some(answer) = self.held.take() {
            self.push_ended(answer.msg1);
        }
    }

    /// Record the link-setup msg1 the peering was promoted from as ended.
    pub(crate) fn end_setup(&mut self, msg1: Msg1Digest) {
        self.push_ended(msg1);
    }

    /// Append `msg1` to the ended list, dropping the oldest at the bound.
    fn push_ended(&mut self, msg1: Msg1Digest) {
        if self.ended.len() == ENDED_MSG1_RECORD {
            self.ended.pop_front();
        }
        self.ended.push_back(msg1);
    }

    /// The answer that armed the pending this node holds, if it holds one it
    /// answered.
    pub(crate) fn held(&self) -> Option<&RekeyAnswer> {
        self.held.as_ref()
    }

    /// Whether `msg1` armed a cycle that has since ended.
    pub(crate) fn ended(&self, msg1: &Msg1Digest) -> bool {
        self.ended.contains(msg1)
    }
}

/// A snapshot of one active peer's rekey-relevant state, taken by the shell.
///
/// Every clock read is resolved shell-side into a plain `u64`/`bool` before the
/// snapshot reaches the core: `elapsed_secs` is the monotonic session age, and
/// `drain_expired`/`is_dampened` are the pre-evaluated timer predicates. The
/// core applies the rekey thresholds and jitter with **no** clock read — the
/// deliberate master-side asymmetry with discovery (monotonic ages, not an
/// absolute `now_ms`), so the rekey timing stays behavior-identical under a
/// clock step.
pub(crate) struct PeerSnapshot {
    /// The peer's node address (cutover/drain/rekey target).
    pub addr: NodeAddr,
    /// A pending post-rekey session is held (cut over by the initiator,
    /// promoted on the peer's first new-epoch frame by the responder).
    pub has_pending: bool,
    /// Which role installed the pending session; `Some` exactly when
    /// `has_pending`.
    pub pending_role: Option<RekeyRole>,
    /// The pending session has been held past the responder hold
    /// (pre-evaluated shell-side against the hold, as `drain_expired` is).
    pub pending_expired: bool,
    /// A rekey handshake is currently in flight.
    pub rekey_in_progress: bool,
    /// The peer is in its post-cutover drain window.
    pub is_draining: bool,
    /// The drain window has expired (pre-evaluated against the drain timer).
    pub drain_expired: bool,
    /// Local rekey initiation is dampened after a recently received peer rekey
    /// msg1 (pre-evaluated against the dampening timer).
    pub is_dampened: bool,
    /// Monotonic session age in seconds (`session_established_at().elapsed()`).
    pub elapsed_secs: u64,
    /// Current Noise send counter (0 when there is no session).
    pub counter: u64,
    /// Per-session symmetric rekey jitter, added to the time threshold.
    pub jitter_secs: i64,
}

/// A snapshot of one peer with a rekey handshake in flight, taken by the shell
/// for the rekey-msg1 retransmission decision.
pub(crate) struct RekeyResendSnapshot {
    /// The peer's node address (abandon/resend target).
    pub peer: NodeAddr,
    /// How many rekey-msg1 retransmissions have already happened. Drives both
    /// the abandon-vs-resend classification and the backoff exponent.
    pub resend_count: u32,
    /// The stored rekey msg1 is due for retransmission as of the shell's
    /// `now_ms` (pre-evaluated against the resend timer).
    pub needs_resend: bool,
    /// The stored rekey msg1 wire bytes (an opaque blob).
    pub msg1: Vec<u8>,
}

/// The rekey trigger thresholds, read shell-side from node config.
pub(crate) struct RekeyCfg {
    /// Rekey after this many seconds of session age (before jitter).
    pub after_secs: u64,
    /// Rekey after this many sent messages.
    pub after_messages: u64,
}

/// The result of the shell-side Noise wire step (Phase B) for one inbound
/// handshake msg1, handed to the establish decision core.
///
/// The Noise step (`receive_handshake_init`) runs on the control machine: it
/// reads **no** `Node` registry state — the essential invariant of this
/// decomposition — and yields the learned peer identity, the
/// remote startup epoch, the sender's session index, and the opaque msg2 noise
/// payload to frame and send. The core never parses or builds Noise bytes; the
/// payload is an opaque blob.
pub(crate) struct WireOutcome {
    /// Peer identity learned from the handshake (msg1 static key).
    pub peer_identity: PeerIdentity,
    /// The peer's startup epoch captured from msg1, if present.
    pub remote_epoch: Option<[u8; 8]>,
    /// The sender's session index from the msg1 header (becomes our
    /// `receiver_idx`/`their_index` in the msg2 response and the promotion).
    pub their_index: SessionIndex,
    /// The opaque Noise msg2 payload the responder produced (empty only if no
    /// msg2 is to be sent).
    pub msg2_payload: Vec<u8>,
    /// Digest of the msg1 as it arrived, matched against the msg1 that armed
    /// a held responder pending.
    pub msg1_digest: Msg1Digest,
}

/// A snapshot of the `Node` registry state the inbound establish decision reads
/// about the peer identified in a just-processed msg1, taken by the shell so the
/// core decides without touching live `Node` state or reading a clock.
///
/// Produced by the [`EstablishView`] read-seam. Every clock read
/// (`existing_session_age_secs`, `existing_link_age_secs`) is resolved
/// shell-side into a plain `u64`, the same monotonic-ages asymmetry the rekey
/// snapshot uses.
pub(crate) struct EstablishSnapshot {
    /// The peer is already an active peer in the registry.
    pub has_existing_peer: bool,
    /// The existing active peer's captured remote startup epoch, if any.
    pub existing_peer_epoch: Option<[u8; 8]>,
    /// Monotonic age in seconds of the existing peer's session
    /// (`session_established_at().elapsed()`), resolved shell-side: the time
    /// since the last rekey cutover or adoption, or since promotion when
    /// there has been none. `0` when there is no existing peer.
    pub existing_session_age_secs: u64,
    /// Monotonic age in seconds of the existing peer's link
    /// (`link_established_at().elapsed()`), resolved shell-side: the time
    /// since promotion, or since a peer restart our rekey revealed. A rekey
    /// cutover does not reset it. `0` when there is no existing peer.
    pub existing_link_age_secs: u64,
    /// The existing peer has an established Noise session.
    pub has_session: bool,
    /// The existing peer already holds a pending post-rekey session awaiting
    /// K-bit cutover.
    pub pending_new_session: bool,
    /// The existing peer has a rekey handshake in flight.
    pub rekey_in_progress: bool,
    /// When the pending session is one this node answered as the rekey
    /// responder, the answer that armed it. `None` with no pending, or with a
    /// pending this node initiated.
    pub held_answer: Option<RekeyAnswer>,
    /// This msg1 armed a responder cycle of this peer's that has since ended,
    /// or is the link-setup msg1 the peering was promoted from (pre-evaluated
    /// shell-side against the peer's [`AnsweredMsg1s`]).
    pub msg1_answered_before: bool,
    /// The msg1 arrived on the existing peer's established link: its
    /// transport and current address, or an address mapped to its link.
    pub msg1_on_link: bool,
    /// The existing peer's established link can still carry an answer: a
    /// connectionless transport, or its connection still pooled.
    pub link_reachable: bool,
    /// This msg1 is the link-setup msg1 the peering was promoted from, the
    /// one `existing_msg2` answers (pre-evaluated shell-side against the
    /// digest stored beside that msg2).
    pub setup_match: bool,
    /// The existing peer's stored msg2 wire bytes (an opaque blob), resent on a
    /// resend of the link-setup msg1. `None` when there is no existing peer or
    /// it has no stored msg2.
    pub existing_msg2: Option<Vec<u8>>,
    /// Admitting this peer as a net-new identity would exceed `max_peers`
    /// (pre-evaluated `max_peers > 0 && peers.len() >= max_peers`).
    pub at_max_peers: bool,
    /// A pending outbound connection to this same peer identity already exists
    /// (a cross-connection in progress); bypasses the max-peers cap.
    pub has_pending_outbound_to_peer: bool,
    /// Whether the local rekey trigger is enabled in config (gates treating a
    /// same-epoch msg1 from an established peer as a rekey rather than a
    /// duplicate).
    pub rekey_enabled: bool,
    /// This node's own address, for the dual-initiation tie-break.
    pub our_node_addr: NodeAddr,
    /// The refusal in force for this identity after its sessions ended
    /// without an authenticated frame, read shell-side from its
    /// [`SilentSessions`](super::SilentSessions) record. `None` when none is.
    pub silent_backoff: Option<ActiveBackoff>,
}

/// Where an inbound msg1 arrived, and the shell's answer to whether the
/// sending peer's established link can still carry a reply.
///
/// Reachability is resolved before the snapshot is taken because the
/// transport pools sit behind async locks, which the snapshot cannot await.
pub(crate) struct Msg1Arrival<'a> {
    /// The transport the msg1 arrived on.
    pub transport_id: TransportId,
    /// The address the msg1 arrived from.
    pub remote_addr: &'a TransportAddr,
    /// The established link of the peer the msg1 claims to be from can
    /// still carry a reply. False when there is no such peer or link.
    pub link_reachable: bool,
}

/// A snapshot of the registry state the *outbound* establish decision reads
/// about the peer whose msg2 just completed our handshake, taken by the shell.
///
/// Both fields are pre-evaluated shell-side (the tie-break is a pure function of
/// the two node addresses, resolved into a plain `bool` here) so the core never
/// touches live `Node` state or the `crate::peer` tie-break helper.
pub(crate) struct OutboundSnapshot {
    /// The peer identity is already a promoted active peer — i.e. this outbound
    /// completion is a cross-connection (we also processed their msg1).
    pub has_existing_peer: bool,
    /// Pre-evaluated cross-connection tie-break: our *outbound* connection wins
    /// (we are the smaller NodeAddr). Only meaningful when `has_existing_peer`.
    pub our_outbound_wins: bool,
}

/// A registry/transport effect the async shell performs on the core's behalf.
///
/// The maintain/teardown subset (`Teardown`..`ResendRekeyMsg1`) covers the
/// tick-poll half of the lifecycle. The establish-machine subset
/// (`PromoteToActive`..) is the master-side IK handshake decision; the shell
/// executes each, resolving the ambient identity/time/wire payload it needs.
pub(crate) enum ConnAction {
    /// Tear down and free the handshake connection on `link`
    /// (`cleanup_stale_connection`): frees the session index, removes the
    /// `pending_outbound` entry, and cleans up the link + address mapping.
    Teardown { link: LinkId },
    /// Schedule an auto-connect retry toward `peer` (`schedule_retry`) before
    /// its failed/stale outbound connection is torn down.
    ScheduleRetry { peer: NodeAddr },
    /// Resend the stored handshake msg1 `bytes` on `link`, then (on a
    /// successful send) record the resend and reschedule the next one at
    /// `next_resend_at_ms`. The shell resolves the transport + remote address
    /// from the live connection and performs the send; `bytes` is an opaque
    /// blob the core neither parses nor builds.
    ResendMsg1 {
        link: LinkId,
        bytes: Vec<u8>,
        next_resend_at_ms: u64,
    },
    /// Perform the initiator-side K-bit cutover to `peer`'s pending session
    /// (`cutover_to_new_session` + decrypt-worker re-registration).
    Cutover { peer: NodeAddr },
    /// Complete `peer`'s drain window: erase the previous session, free its
    /// index, and unregister its decrypt-worker entry.
    Drain { peer: NodeAddr },
    /// Retire `peer`'s pending session that this node did not initiate and the
    /// initiator never adopted: drop it, unregister its index from
    /// `peers_by_index`, and free the index.
    RetirePending { peer: NodeAddr },
    /// Initiate a fresh outbound rekey to `peer` (`initiate_rekey`: allocates a
    /// new index, builds and sends msg1, inserts `pending_outbound`). The msg1
    /// construction is the establish leaf and stays shell-side; the action
    /// carries only the target.
    InitiateRekey { peer: NodeAddr },
    /// Abandon `peer`'s in-flight rekey cycle (`abandon_rekey`): its msg1 went
    /// unconfirmed past the retransmission budget.
    AbandonRekey { peer: NodeAddr },
    /// Retransmit `peer`'s stored rekey msg1 `bytes`, then (on a successful
    /// send) record the retransmission and reschedule the next at
    /// `next_resend_at_ms`. The shell resolves the transport + remote address;
    /// `bytes` is an opaque blob.
    ResendRekeyMsg1 {
        peer: NodeAddr,
        bytes: Vec<u8>,
        next_resend_at_ms: u64,
    },
}

/// Read-only view of FMP connection/peer state the lifecycle core needs.
///
/// The core defines this interface; the async shell (`node`) implements it over
/// the live `peer_machines`/`peers` maps — handshake-phase state is read off
/// the machines still carrying a pending handshake, active-peer state off
/// `peers`. It is a **snapshot-iterator** seam: each method returns owned
/// snapshot vectors with all clock reads already resolved shell-side, so the
/// pure decisions never borrow `Node` and never
/// read a clock. Keeping it a trait keeps `proto` free of a `node` dependency
/// and lets the decisions be unit-tested against hand-built snapshots.
pub(crate) trait LifecycleView {
    /// Snapshot every handshake connection that is stale (idle past
    /// `timeout_ms`) or failed, as of `now_ms`. The shell resolves the
    /// timeout/failed predicate; the core decides retry-then-teardown.
    fn stale_connections(&self, now_ms: u64, timeout_ms: u64) -> Vec<ConnSnapshot>;

    /// Snapshot every active peer with a session, pre-computing
    /// its rekey-relevant ages and timer predicates (see [`PeerSnapshot`]). The
    /// shell resolves every clock read here; the core applies the thresholds.
    fn rekey_peers(&self) -> Vec<PeerSnapshot>;

    /// Snapshot every peer with a rekey handshake in flight (and a stored
    /// msg1), pre-evaluating the resend-due predicate against `now_ms`. The
    /// core classifies abandon-vs-resend and computes the backoff.
    fn rekey_resend_candidates(&self, now_ms: u64) -> Vec<RekeyResendSnapshot>;
}

/// The classification outcome for one inbound handshake msg1, decided purely
/// from the [`EstablishSnapshot`] and [`WireOutcome`]. The shell matches on this
/// and drives the effects; the core consumes nothing and touches no live state.
///
/// The variants map one-to-one onto the pre-refactor inline branches of
/// `handle_msg1`'s post-crypto classification. There is deliberately **no**
/// inbound cross-connection won/lost variant: an existing same-identity peer is
/// always intercepted here first (restart / rekey / duplicate), and a net-new
/// [`Promote`](InboundDecision::Promote) reaches `promote_connection` with no
/// existing peer — so on the inbound path the tie-break never fires. The real
/// cross-connection resolution lives in `handle_msg2` (outbound completion).
#[derive(Debug)]
pub(crate) enum InboundDecision {
    /// No existing peer for this identity: authorize, allocate our index, send
    /// msg2, and promote. Everything the shell needs (verified identity, their
    /// index, opaque msg2 payload) is in the `WireOutcome` it still holds, so
    /// the variant carries nothing.
    Promote,
    /// Same-epoch msg1 on a session that cannot rekey, that is not a resend of
    /// the peering's link-setup msg1 and not a copy of an answered one: a
    /// fresh attempt by a peer that has lost its side of the link. The shell
    /// tears the existing peer down and promotes this msg1 exactly as for
    /// [`RestartThenPromote`](InboundDecision::RestartThenPromote), under the
    /// same liveness and interval conditions, and drops it otherwise.
    ReplaceThenPromote { peer: NodeAddr },
    /// Existing peer at a *different* startup epoch — a peer restart. The shell
    /// tears down the stale peer and schedules its reconnect, then runs the same
    /// authorize → … → promote sequence as [`Promote`](InboundDecision::Promote).
    /// `peer` is the teardown / reconnect target.
    RestartThenPromote { peer: NodeAddr },
    /// Same-epoch rekey msg1 on an aged link, past the drain window of the last
    /// cutover: respond as the rekey responder. The shell extracts the fresh
    /// Noise session from the live connection, allocates a new index, sends the
    /// rekey msg2, and stores the session as the peer's pending (post-rekey)
    /// session. `abandon_first` is set only on the dual-initiation *loser*
    /// path, where we first abandon our own in-flight rekey. `peer` is the
    /// rekey target.
    RekeyRespond { peer: NodeAddr, abandon_first: bool },
    /// A resend of the rekey msg1 that armed the responder pending this node
    /// holds: send `msg2`, the answer already given, again. The shell sends it
    /// only on the peer's established link and never to the msg1's source
    /// address, since a captured msg1 replayed from anywhere authenticates
    /// the same as a resend. Nothing else changes; the pending stays held.
    ResendRekeyMsg2 { peer: NodeAddr, msg2: Vec<u8> },
    /// A resend of the msg1 the peering was promoted from, on a session that
    /// cannot rekey: resend the stored msg2 that answered it. `msg2` is the
    /// opaque stored bytes, always present when the setup digest matched,
    /// since the two are stored and cleared together.
    ResendMsg2 { msg2: Option<Vec<u8>> },
    /// Drop this msg1 with a handshake reject and no promotion. Every reject
    /// but [`InboundReject::SilentBackoff`] records `HandshakeReject::BadState`;
    /// that one records its own reason. `reason` otherwise selects only the
    /// diagnostic log line, and every reject completes the rate-limiter
    /// identically.
    Reject { reason: InboundReject },
}

/// Why an inbound msg1 was rejected. Every variant rejects identically
/// (rate-limiter complete, the local not-yet-registered connection dropped)
/// and records `HandshakeReject::BadState`, except
/// [`SilentBackoff`](InboundReject::SilentBackoff), which records its own
/// reason.
#[derive(Debug)]
pub(crate) enum InboundReject {
    /// At `max_peers` and this is a net-new identity with no pending outbound to
    /// bypass the cap: silent-drop before any msg2 build/send.
    AtMaxPeers,
    /// The peer already holds a pending post-rekey session awaiting K-bit
    /// cutover, and this msg1 is not the one that armed it; a second rekey
    /// msg1 must not overwrite it.
    PendingSession,
    /// Dual rekey initiation and we are the tie-break *winner* (smaller
    /// NodeAddr): drop the peer's msg1 and keep driving our own rekey.
    DualRekeyWon,
    /// The msg1 armed a rekey cycle with this peer that has already ended: a
    /// copy, not a fresh request, and it must not arm a pending. Also refused
    /// on a link or session too young to rekey, where it would otherwise
    /// replace the session.
    AnsweredBefore,
    /// A same-epoch msg1 on a link and session old enough to rekey arrived off
    /// the peer's established link while that link works: a second path, not
    /// a rekey of this link.
    OffLink,
    /// The identity's last sessions at this msg1's epoch, at least
    /// [`SILENT_SESSION_LIMIT`](super::silent::SILENT_SESSION_LIMIT) in a
    /// row, ended without one authenticated frame, and the back-off they
    /// started is still running. Checked only where the msg1 would promote a
    /// new session.
    SilentBackoff,
}

/// The classification outcome for one outbound `handle_msg2` completion, decided
/// purely from the [`OutboundSnapshot`]. The shell matches on this and drives
/// the effects; the core consumes nothing and touches no live state.
///
/// Only the case where the peer is *not* yet a promoted active peer is a plain
/// promotion; when it is, this msg2 completes the outbound half of a
/// cross-connection and the tie-break decides whether we swap our session to the
/// (winning) outbound one or keep our existing inbound session. The rekey-msg2
/// completion path is handled by a separate shell driver (it mutates
/// `ActivePeer`, not a pending handshake) and never reaches this decision.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum OutboundDecision {
    /// No existing peer for this identity: promote the completed outbound
    /// connection to an active peer via the normal promotion path.
    Promote,
    /// Cross-connection and our outbound wins (smaller NodeAddr): swap the peer
    /// to the outbound session + indices, freeing the old inbound index.
    CrossConnectionSwap,
    /// Cross-connection and our outbound loses (larger NodeAddr): keep the
    /// existing inbound session and original `their_index`, freeing the unused
    /// outbound index.
    CrossConnectionKeep,
}

/// Minimum link age (seconds) before a same-epoch msg1 from an established
/// peer is treated as a rekey rather than a duplicate. Guards against
/// misreading a simultaneous cross-connection msg1 as a rekey (both sides
/// promote within a tick, so a genuine rekey cannot fire that fast). The age
/// is the link's, from promotion or from a peer restart our rekey revealed;
/// a rekey cutover does not restart it, since a crossing dial follows a
/// promotion, not a rekey. The age separates only that simultaneous case; a
/// second path the peer opens later is told by where its msg1 arrived.
const REKEY_MIN_LINK_AGE_SECS: u64 = 30;

/// Minimum time (seconds) since the last rekey cutover or adoption before a
/// same-epoch msg1 from an established peer is treated as a rekey. A new
/// cycle is not answered while the session that cutover replaced may still
/// be draining: adopting it would overwrite the previous slot that session
/// holds. Equal to the drain window, so the responder completing a drain as
/// it arms a pending never retires a previous session early.
pub(crate) const REKEY_MIN_CUTOVER_AGE_SECS: u64 = crate::proto::fsp::limits::DRAIN_WINDOW_SECS;

/// Read-only view of the `Node` registry state the inbound establish decision
/// needs about a peer whose msg1 has just been processed.
///
/// The core defines this interface; the async shell (`node`) implements it over
/// the live `peers` map, resolving every clock read into a plain `u64` before
/// the [`EstablishSnapshot`] reaches the core. Keeping it a trait
/// keeps `proto` free of a `node` dependency and lets the establish decision be
/// unit-tested against hand-built snapshots.
pub(crate) trait EstablishView {
    /// Snapshot the registry state relevant to classifying an inbound msg1 from
    /// `peer_addr`: the existing peer's epoch/session/rekey state (with the
    /// session and link ages resolved shell-side), the max-peers cap, and this
    /// node's own address for the tie-break.
    /// `msg1` is the digest of the msg1 being classified, checked against the
    /// peer's record of answered msg1s. `arrival` is where it arrived and
    /// whether the peer's established link is reachable, from which the
    /// snapshot tells a msg1 on that link from one off it.
    fn establish_snapshot(
        &self,
        peer_addr: &NodeAddr,
        msg1: &Msg1Digest,
        arrival: &Msg1Arrival<'_>,
    ) -> EstablishSnapshot;

    /// Snapshot the registry state relevant to classifying an outbound msg2
    /// completion for `peer_addr`: whether the identity is already an active
    /// peer, and the pre-evaluated cross-connection tie-break.
    fn outbound_snapshot(&self, peer_addr: &NodeAddr) -> OutboundSnapshot;
}

impl Fmp {
    /// Decide the teardown choreography for the stale/failed connections the
    /// shell snapshotted. For each connection, an outbound one with a known
    /// identity first gets an auto-connect retry scheduled, then every
    /// connection is torn down. Pure over the snapshots.
    ///
    /// Preserves the pre-refactor per-connection order (retry before teardown).
    pub(crate) fn poll_timeouts(&self, stale: Vec<ConnSnapshot>) -> Vec<ConnAction> {
        let mut actions = Vec::new();
        for snap in stale {
            if snap.is_outbound
                && let Some(peer) = snap.retry_addr
            {
                actions.push(ConnAction::ScheduleRetry { peer });
            }
            actions.push(ConnAction::Teardown { link: snap.link });
        }
        actions
    }

    /// Decide the msg1 resend schedule for the outbound handshake connections
    /// the shell snapshotted as due. Each candidate yields one
    /// [`ConnAction::ResendMsg1`] carrying the opaque msg1 bytes and the
    /// next-resend deadline computed from the exponential backoff
    /// (`interval_ms * backoff^(count+1)`). Pure over the snapshots.
    ///
    /// The shell performs the send and only commits the resend (count++ and
    /// reschedule) when it succeeds, preserving the pre-refactor behavior where
    /// a failed send neither advances the count nor reschedules.
    pub(crate) fn poll_resends(
        &self,
        candidates: Vec<ConnSnapshot>,
        now_ms: u64,
        interval_ms: u64,
        backoff: f64,
    ) -> Vec<ConnAction> {
        candidates
            .into_iter()
            .map(|snap| ConnAction::ResendMsg1 {
                link: snap.link,
                next_resend_at_ms: next_resend_at_ms(
                    now_ms,
                    interval_ms,
                    backoff,
                    snap.resend_count,
                ),
                bytes: snap.msg1,
            })
            .collect()
    }

    /// Decide the per-tick rekey choreography for the peers the shell
    /// snapshotted, in this priority:
    ///
    /// - **Cutover** takes precedence: a peer with a pending session this node
    ///   initiated and no in-flight rekey cuts over and is considered for
    ///   nothing else.
    /// - A pending session this node answered is held, never cut over by the
    ///   tick: the peer's first frame on the new epoch promotes it. Once its
    ///   hold has passed it is retired.
    /// - An expired drain window is completed, and — independently — the rekey
    ///   trigger fires when the peer is neither mid-rekey, dampened, nor
    ///   holding a pending session, and its jittered time threshold or send
    ///   counter is reached. A draining peer can thus both drain and
    ///   re-trigger in the same tick.
    ///
    /// Actions are returned phase-grouped (all cutovers, then all drains, then
    /// all retirements, then all rekey initiations) to preserve the global
    /// execution order across peers, which the shared `index_allocator`
    /// observes: retirements free an index, so they run before initiations
    /// allocate.
    pub(crate) fn poll_rekey(&self, peers: Vec<PeerSnapshot>, cfg: &RekeyCfg) -> Vec<ConnAction> {
        let mut cutovers = Vec::new();
        let mut drains = Vec::new();
        let mut retires = Vec::new();
        let mut rekeys = Vec::new();
        for p in peers {
            let initiated = p.pending_role == Some(RekeyRole::Initiator);
            // 1. Initiator-side cutover. A pending this node answered is promoted
            //    by the peer's first frame on the new epoch, never by this tick.
            if p.has_pending && !p.rekey_in_progress && initiated {
                cutovers.push(ConnAction::Cutover { peer: p.addr });
                continue;
            }
            // 1b. A pending the initiator never adopted is retired at its hold.
            if p.has_pending && !initiated && p.pending_expired {
                retires.push(ConnAction::RetirePending { peer: p.addr });
            }
            // 2. Drain window expiry (does not preclude a trigger below).
            if p.is_draining && p.drain_expired {
                drains.push(ConnAction::Drain { peer: p.addr });
            }
            // 3. Rekey trigger. A held pending vetoes it: a new cycle's msg2 would
            //    overwrite the held slot.
            if p.rekey_in_progress || p.is_dampened || p.has_pending {
                continue;
            }
            let effective_after = cfg.after_secs.saturating_add_signed(p.jitter_secs);
            if p.elapsed_secs >= effective_after || p.counter >= cfg.after_messages {
                rekeys.push(ConnAction::InitiateRekey { peer: p.addr });
            }
        }
        cutovers.extend(drains);
        cutovers.extend(retires);
        cutovers.extend(rekeys);
        cutovers
    }

    /// Decide the rekey-msg1 retransmission choreography for the peers the
    /// shell snapshotted as having a rekey in flight. A peer whose
    /// retransmission count has reached `max_resends` has its cycle abandoned;
    /// otherwise, if its msg1 is due, it is retransmitted with the next
    /// deadline computed from the shared backoff. Pure over the snapshots.
    ///
    /// Actions are returned abandons-first (matching the pre-refactor
    /// two-pass order), and the shell commits a retransmission's count++ and
    /// reschedule only on a successful send.
    pub(crate) fn poll_rekey_resends(
        &self,
        candidates: Vec<RekeyResendSnapshot>,
        now_ms: u64,
        interval_ms: u64,
        backoff: f64,
        max_resends: u32,
    ) -> Vec<ConnAction> {
        let mut abandons = Vec::new();
        let mut resends = Vec::new();
        for c in candidates {
            if c.resend_count >= max_resends {
                abandons.push(ConnAction::AbandonRekey { peer: c.peer });
                continue;
            }
            if c.needs_resend {
                resends.push(ConnAction::ResendRekeyMsg1 {
                    peer: c.peer,
                    next_resend_at_ms: next_resend_at_ms(
                        now_ms,
                        interval_ms,
                        backoff,
                        c.resend_count,
                    ),
                    bytes: c.msg1,
                });
            }
        }
        abandons.extend(resends);
        abandons
    }

    /// Classify one inbound handshake msg1 from the establish snapshot and the
    /// Noise wire outcome. Pure: reads only `snap` and `wire`, mutates nothing,
    /// consumes nothing. The returned [`InboundDecision`] tells the shell which
    /// effect sequence to drive.
    ///
    /// Mirrors the pre-refactor `handle_msg1` post-crypto branch order exactly:
    /// the early max-peers cap gate, then — for an existing same-identity peer —
    /// the epoch-restart / rekey / duplicate classification, else a net-new
    /// promote. The pre-refactor `possible_restart` flag is folded away: it was
    /// forced true whenever `has_existing_peer` held, so gating the block on
    /// `has_existing_peer` alone is behavior-identical.
    pub(crate) fn establish_inbound(
        &self,
        snap: &EstablishSnapshot,
        wire: &WireOutcome,
    ) -> InboundDecision {
        // Early cap gate: at capacity and a net-new identity (no existing peer,
        // no pending outbound to bypass) → silent-drop before any msg2.
        if snap.at_max_peers && !snap.has_existing_peer && !snap.has_pending_outbound_to_peer {
            return InboundDecision::Reject {
                reason: InboundReject::AtMaxPeers,
            };
        }

        if snap.has_existing_peer {
            let peer_addr = *wire.peer_identity.node_addr();
            // Which transport the msg1 arrived on plays no part here: a
            // handshake never creates path state. A peer dialling us over
            // a second transport gets the same answer as one dialling over
            // the first — a rekey or a duplicate — and the transport becomes
            // a path only through the authenticated, replay-checked probe
            // exchange. Both ends then resolve on the same information; a
            // rule that read this end's view of its own liveness split them.
            match (snap.existing_peer_epoch, wire.remote_epoch) {
                (Some(existing), Some(new)) if existing != new => {
                    // Epoch mismatch → peer restart.
                    InboundDecision::RestartThenPromote { peer: peer_addr }
                }
                _ => {
                    // Same epoch (or no epoch captured on either side).
                    let is_rekey = snap.rekey_enabled
                        && snap.has_session
                        && snap.existing_link_age_secs >= REKEY_MIN_LINK_AGE_SECS
                        && snap.existing_session_age_secs >= REKEY_MIN_CUTOVER_AGE_SECS;
                    if !is_rekey {
                        // The stored msg2 names the setup msg1's sender index
                        // and completes no other handshake, so it answers only
                        // a resend of that msg1. The setup msg1 is also in the
                        // answered record, so it is matched first or its
                        // resend would be refused. A copy of an answered rekey
                        // msg1 is refused here as on an older session; any
                        // other msg1 is a fresh dial from a peer that lost its
                        // side of the link.
                        if snap.setup_match {
                            return InboundDecision::ResendMsg2 {
                                msg2: snap.existing_msg2.clone(),
                            };
                        }
                        if snap.msg1_answered_before {
                            return InboundDecision::Reject {
                                reason: InboundReject::AnsweredBefore,
                            };
                        }
                        if silent_refusal(snap, wire) {
                            return InboundDecision::Reject {
                                reason: InboundReject::SilentBackoff,
                            };
                        }
                        return InboundDecision::ReplaceThenPromote { peer: peer_addr };
                    }
                    if !snap.msg1_on_link && snap.link_reachable {
                        // A peer that is already linked and dials a second
                        // path sends a link-setup msg1 there. Answered as a
                        // rekey, it arms a pending the dialer never adopts,
                        // which then refuses the peer's genuine rekeys and
                        // vetoes ours for the whole hold. Decided before the
                        // held answer and the tie-break, so it neither
                        // resends that answer nor abandons our own rekey.
                        // With the established connection gone the msg1 is a
                        // redial, and keeps the rekey path.
                        return InboundDecision::Reject {
                            reason: InboundReject::OffLink,
                        };
                    }
                    if snap.pending_new_session {
                        // A completed rekey is already pending cutover. A
                        // resend of the msg1 this node answered to arm it
                        // means the answer was lost: give it again. Any other
                        // msg1 is refused.
                        if let Some(answer) = &snap.held_answer
                            && answer.msg1 == wire.msg1_digest
                        {
                            return InboundDecision::ResendRekeyMsg2 {
                                peer: peer_addr,
                                msg2: answer.msg2.clone(),
                            };
                        }
                        return InboundDecision::Reject {
                            reason: InboundReject::PendingSession,
                        };
                    }
                    if snap.msg1_answered_before {
                        // A copy of a msg1 whose cycle has ended: refuse it
                        // before it can arm a pending, or, on a tie-break we
                        // lose, abandon our own rekey.
                        return InboundDecision::Reject {
                            reason: InboundReject::AnsweredBefore,
                        };
                    }
                    if snap.rekey_in_progress {
                        // Dual initiation — smaller NodeAddr wins as initiator.
                        // Our own rekey is the outbound/initiator side, so reuse
                        // the shared tie-break with `this_is_outbound = true`.
                        if cross_connection_winner(&snap.our_node_addr, &peer_addr, true) {
                            return InboundDecision::Reject {
                                reason: InboundReject::DualRekeyWon,
                            };
                        }
                        // We lose → abandon ours, then respond as responder.
                        return InboundDecision::RekeyRespond {
                            peer: peer_addr,
                            abandon_first: true,
                        };
                    }
                    InboundDecision::RekeyRespond {
                        peer: peer_addr,
                        abandon_first: false,
                    }
                }
            }
        } else if silent_refusal(snap, wire) {
            InboundDecision::Reject {
                reason: InboundReject::SilentBackoff,
            }
        } else {
            // No existing peer for this identity → net-new promote.
            InboundDecision::Promote
        }
    }

    /// Classify one outbound `handle_msg2` completion from the outbound snapshot.
    /// Pure: reads only `snap`, mutates nothing.
    ///
    /// Mirrors the pre-refactor branch exactly: an existing same-identity peer
    /// makes this a cross-connection resolved by the (pre-evaluated) tie-break —
    /// swap on a win, keep on a loss — otherwise a net-new promote.
    pub(crate) fn establish_outbound(&self, snap: &OutboundSnapshot) -> OutboundDecision {
        if !snap.has_existing_peer {
            return OutboundDecision::Promote;
        }
        if snap.our_outbound_wins {
            OutboundDecision::CrossConnectionSwap
        } else {
            OutboundDecision::CrossConnectionKeep
        }
    }
}

/// Exponential-backoff schedule for the next handshake/rekey msg1 resend:
/// `now_ms + interval_ms * backoff^(prior_count + 1)`. Matches the pre-refactor
/// arithmetic (the exponent is the resend count *after* this attempt).
fn next_resend_at_ms(now_ms: u64, interval_ms: u64, backoff: f64, prior_count: u32) -> u64 {
    let count = prior_count + 1;
    now_ms + (interval_ms as f64 * crate::proto::math::powi(backoff, count)) as u64
}

/// Whether a refusal for silent sessions covers this msg1: one is in force
/// for the identity and the msg1 is at the epoch it counted. A msg1 at another
/// epoch is a restart and is left to the restart guard.
fn silent_refusal(snap: &EstablishSnapshot, wire: &WireOutcome) -> bool {
    snap.silent_backoff
        .as_ref()
        .is_some_and(|b| !epochs_differ(b.epoch, wire.remote_epoch))
}
