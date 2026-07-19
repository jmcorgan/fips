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

use super::state::Fmp;
use crate::transport::LinkId;
use crate::utils::index::SessionIndex;
use crate::{NodeAddr, PeerIdentity};

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
    /// A pending post-rekey session is ready to cut over to.
    pub has_pending: bool,
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
}

/// A snapshot of the `Node` registry state the inbound establish decision reads
/// about the peer identified in a just-processed msg1, taken by the shell so the
/// core decides without touching live `Node` state or reading a clock.
///
/// Produced by the [`EstablishView`] read-seam. Every clock read
/// (`existing_session_age_secs`) is resolved shell-side into a plain `u64`, the
/// same monotonic-ages asymmetry the rekey snapshot uses.
pub(crate) struct EstablishSnapshot {
    /// The peer is already an active peer in the registry.
    pub has_existing_peer: bool,
    /// The existing active peer's captured remote startup epoch, if any.
    pub existing_peer_epoch: Option<[u8; 8]>,
    /// Monotonic age in seconds of the existing peer's session
    /// (`session_established_at().elapsed()`), resolved shell-side. `0` when
    /// there is no existing peer.
    pub existing_session_age_secs: u64,
    /// The existing peer has an established Noise session.
    pub has_session: bool,
    /// The existing peer's session is healthy.
    pub is_healthy: bool,
    /// The existing peer already holds a pending post-rekey session awaiting
    /// K-bit cutover.
    pub pending_new_session: bool,
    /// The existing peer has a rekey handshake in flight.
    pub rekey_in_progress: bool,
    /// The existing peer's stored msg2 wire bytes (an opaque blob), resent on a
    /// same-epoch duplicate msg1. `None` when there is no existing peer or it
    /// has no stored msg2.
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

    /// Snapshot every active peer with a session that is healthy, pre-computing
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
    /// Existing peer at a *different* startup epoch — a peer restart. The shell
    /// tears down the stale peer and schedules its reconnect, then runs the same
    /// authorize → … → promote sequence as [`Promote`](InboundDecision::Promote).
    /// `peer` is the teardown / reconnect target.
    RestartThenPromote { peer: NodeAddr },
    /// Same-epoch rekey msg1 on an aged, healthy session: respond as the rekey
    /// responder. The shell extracts the fresh Noise session from the live
    /// connection, allocates a new index, sends the rekey msg2, and stores the
    /// session as the peer's pending (post-rekey) session. `abandon_first` is set
    /// only on the dual-initiation *loser* path, where we first abandon our own
    /// in-flight rekey. `peer` is the rekey target.
    RekeyRespond { peer: NodeAddr, abandon_first: bool },
    /// Same-epoch duplicate msg1 (not a rekey): resend the existing peer's stored
    /// msg2. `msg2` is the opaque stored bytes (`None` → nothing to resend, the
    /// silent no-op preserved from the pre-refactor path).
    ResendMsg2 { msg2: Option<Vec<u8>> },
    /// Drop this msg1 with a handshake reject (`HandshakeReject::BadState`) and
    /// no promotion. `reason` selects only the diagnostic log line — every reject
    /// records the same stat and completes the rate-limiter identically.
    Reject { reason: InboundReject },
}

/// Why an inbound msg1 was rejected. Distinguishes only the diagnostic log
/// message; all three reject identically (BadState stat, rate-limiter complete,
/// the local not-yet-registered connection dropped).
#[derive(Debug)]
pub(crate) enum InboundReject {
    /// At `max_peers` and this is a net-new identity with no pending outbound to
    /// bypass the cap: silent-drop before any msg2 build/send.
    AtMaxPeers,
    /// The peer already holds a pending post-rekey session awaiting K-bit
    /// cutover; a second rekey msg1 must not overwrite it.
    PendingSession,
    /// Dual rekey initiation and we are the tie-break *winner* (smaller
    /// NodeAddr): drop the peer's msg1 and keep driving our own rekey.
    DualRekeyWon,
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

/// Minimum session age (seconds) before a same-epoch msg1 from an established
/// peer is treated as a rekey rather than a duplicate. Guards against
/// misreading a simultaneous cross-connection msg1 as a rekey (both sides
/// promote within a tick, so a genuine rekey cannot fire that fast). Unchanged
/// from the pre-refactor literal.
const REKEY_MIN_SESSION_AGE_SECS: u64 = 30;

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
    /// session age resolved shell-side), the max-peers cap, and this node's own
    /// address for the tie-break.
    fn establish_snapshot(&self, peer_addr: &NodeAddr) -> EstablishSnapshot;

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

    /// Decide the per-tick rekey choreography for the healthy peers the shell
    /// snapshotted. Reproduces the pre-refactor priority and phase grouping
    /// exactly:
    ///
    /// - **Cutover** takes precedence: a peer with a pending session and no
    ///   in-flight rekey cuts over and is considered for nothing else.
    /// - Otherwise an expired drain window is completed, and — independently —
    ///   the rekey trigger fires when the peer is neither mid-rekey nor
    ///   dampened and its jittered time threshold or send counter is reached.
    ///   A draining peer can thus both drain and re-trigger in the same tick,
    ///   as before.
    ///
    /// Actions are returned phase-grouped (all cutovers, then all drains, then
    /// all rekey initiations) to preserve the pre-refactor global execution
    /// order across peers, which the shared `index_allocator` observes.
    pub(crate) fn poll_rekey(&self, peers: Vec<PeerSnapshot>, cfg: &RekeyCfg) -> Vec<ConnAction> {
        let mut cutovers = Vec::new();
        let mut drains = Vec::new();
        let mut rekeys = Vec::new();
        for p in peers {
            // 1. Initiator-side cutover.
            if p.has_pending && !p.rekey_in_progress {
                cutovers.push(ConnAction::Cutover { peer: p.addr });
                continue;
            }
            // 2. Drain window expiry (does not preclude a trigger below).
            if p.is_draining && p.drain_expired {
                drains.push(ConnAction::Drain { peer: p.addr });
            }
            // 3. Rekey trigger.
            if p.rekey_in_progress || p.is_dampened {
                continue;
            }
            let effective_after = cfg.after_secs.saturating_add_signed(p.jitter_secs);
            if p.elapsed_secs >= effective_after || p.counter >= cfg.after_messages {
                rekeys.push(ConnAction::InitiateRekey { peer: p.addr });
            }
        }
        cutovers.extend(drains);
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
            match (snap.existing_peer_epoch, wire.remote_epoch) {
                (Some(existing), Some(new)) if existing != new => {
                    // Epoch mismatch → peer restart.
                    InboundDecision::RestartThenPromote { peer: peer_addr }
                }
                _ => {
                    // Same epoch (or no epoch captured on either side).
                    let is_rekey = snap.rekey_enabled
                        && snap.has_session
                        && snap.is_healthy
                        && snap.existing_session_age_secs >= REKEY_MIN_SESSION_AGE_SECS;
                    if !is_rekey {
                        // Duplicate msg1 — resend the stored msg2.
                        return InboundDecision::ResendMsg2 {
                            msg2: snap.existing_msg2.clone(),
                        };
                    }
                    if snap.pending_new_session {
                        // A completed rekey is already pending cutover.
                        return InboundDecision::Reject {
                            reason: InboundReject::PendingSession,
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
