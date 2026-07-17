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
//! only. The XX **inbound classification** decision, however, is modelled here:
//! [`Fmp::establish_inbound`] maps an [`EstablishSnapshot`] + [`WireOutcome`]
//! onto an [`InboundDecision`] the shell dispatches for `handle_msg3`. The
//! born-on-next Noise leaf (`handle_msg{1,2,3}` crypto) remains shell-side.

use super::state::Fmp;
use super::wire::{
    FMP_FEAT_PROFILE_MASK, FMP_FEAT_PROVIDES_RR, FMP_FEAT_PROVIDES_SR, FMP_FEAT_WANTS_RR,
    FMP_FEAT_WANTS_SR, NegotiationPayload, NodeProfile,
};
use crate::NodeAddr;
use crate::proto::Error;
use crate::transport::LinkId;

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
    /// The initiator already cut over on its own timer but is still
    /// retransmitting this cycle's rekey msg3 to a responder not yet confirmed
    /// on the new epoch. Suppresses starting a fresh rekey (which would
    /// overwrite the retained payload) until the msg3 is delivered or its
    /// budget is exhausted. Mirrors FSP `check_session_rekey`.
    pub rekey_msg3_pending: bool,
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

/// The wire-learned facts about one inbound XX `msg3`, handed to the establish
/// decision core.
///
/// On XX the responder learns the initiator's identity and startup epoch only
/// once `msg3` completes the Noise handshake (unlike IK, which learns them at
/// `msg1`). The shell-side Noise step (`complete_handshake_msg3`) yields these;
/// the core reads them to classify. The Noise bytes themselves never reach the
/// core — the fresh session extraction stays a shell effect. Only the two facts
/// the classification depends on travel here: the peer's node address (for the
/// smaller-NodeAddr tie-breaks) and the peer's captured startup epoch (for
/// restart detection).
pub(crate) struct WireOutcome {
    /// The initiator's node address, learned from the `msg3` static key. Drives
    /// both the cross-connection and the dual-init tie-breaks.
    pub peer_node_addr: NodeAddr,
    /// The initiator's startup epoch captured from the handshake, if present.
    /// `None` when no epoch was carried (treated as same-epoch, never a
    /// restart).
    pub remote_epoch: Option<[u8; 8]>,
}

/// A snapshot of the `Node` registry state the inbound XX establish decision
/// reads about the peer whose `msg3` just completed, taken by the shell so the
/// core decides without touching live `Node` state or reading a clock.
///
/// Every clock read (`existing_session_age_secs`) and every config-derived
/// threshold (`rekey_age_floor_secs`) is resolved shell-side into a plain
/// `u64`, the same monotonic-ages asymmetry the rekey snapshot uses, so the
/// timing stays behavior-identical under a clock step.
pub(crate) struct EstablishSnapshot {
    /// The peer identity is already an active peer in the registry. `false` here
    /// is the net-new path (or the post-restart re-promote) — a plain promote.
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
    /// K-bit cutover. On XX this is one of the two dual-init tie-break states
    /// (the widened window IK never reached) — NOT an unconditional reject.
    pub pending_new_session: bool,
    /// The existing peer has a rekey handshake in flight (the other dual-init
    /// tie-break state).
    pub rekey_in_progress: bool,
    /// The existing peer's stored `msg2` wire bytes (an opaque blob), resent on
    /// a same-epoch duplicate `msg3`. `None` when there is no existing peer or
    /// it has no stored `msg2`.
    pub existing_msg2: Option<Vec<u8>>,
    /// The `msg3` arrived on a *different* link than the existing peer's active
    /// link (`existing_peer.link_id() != link_id`). Required for the inline
    /// cross-connection branch: a `msg3` on the same link is never a
    /// cross-connection.
    pub different_link: bool,
    /// The local rekey trigger is enabled in config (gates treating an aged
    /// same-epoch `msg3` as a rekey rather than a duplicate).
    pub rekey_enabled: bool,
    /// The config-derived minimum session age (seconds) that partitions an aged
    /// rekey from a fresh cross-connection: `< floor` → initial
    /// cross-connection, `>= floor` → rekey responder. Derived shell-side from
    /// `rekey.after_secs` and the rekey jitter so it tracks the real minimum
    /// rekey spacing.
    pub rekey_age_floor_secs: u64,
    /// This node's own address, for both tie-breaks (the smaller NodeAddr wins).
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
/// The scaffold subset covers the maintain/teardown half of the lifecycle. The
/// establish-leaf variants (`SendMsg2`, `PromoteToActive`) are deferred to the
/// born-on-next handshake component and are intentionally absent.
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
/// the live `connections`/`peers` maps. It is a **snapshot-iterator** seam:
/// each method returns owned snapshot vectors with all clock reads already
/// resolved shell-side, so the pure decisions never borrow `Node` and never
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

/// The classification outcome for one inbound XX `msg3`, decided purely from the
/// [`EstablishSnapshot`] and [`WireOutcome`]. The shell matches on this and
/// drives the effects; the core consumes nothing and touches no live state.
///
/// This is a **superset** of the IK inbound decision. Because XX learns the
/// initiator's identity only at `msg3`, the same-epoch cross-connection
/// tie-break resolves *here* (on `msg3`) rather than on the outbound `msg2`
/// completion — hence the [`CrossConnect`](InboundDecision::CrossConnect)
/// variant that the IK inbound decision deliberately lacked. The dual-init
/// tie-break is also widened: it covers both the `rekey_in_progress` and the
/// `pending_new_session` states (see [`EstablishSnapshot::pending_new_session`]),
/// where IK only caught the former.
#[derive(Debug)]
pub(crate) enum InboundDecision {
    /// No existing peer for this identity: promote the completed connection via
    /// `promote_connection` (whose late max-peers cap and cross-connection
    /// won/lost handling stay shell-side). Everything the shell needs is in the
    /// live connection it still holds, so the variant carries nothing.
    Promote,
    /// Existing peer at a *different* startup epoch — a peer restart. The shell
    /// removes the stale active peer and schedules its reconnect, then runs the
    /// same promote sequence as [`Promote`](InboundDecision::Promote). `peer` is
    /// the teardown / reconnect target.
    RestartThenPromote { peer: NodeAddr },
    /// Same-epoch cross-connection resolved inline on `msg3`: a still-fresh
    /// session (age `< rekey_age_floor_secs`) received a concurrent `msg3` on a
    /// different link. `our_inbound_wins` (the larger-NodeAddr side) selects
    /// swap-to-inbound vs keep-outbound; the shell frees the loser index and
    /// tears down the temporary link either way. `peer` is the tie-break target.
    CrossConnect {
        peer: NodeAddr,
        our_inbound_wins: bool,
    },
    /// Same-epoch aged rekey `msg3` on a healthy session: respond as the rekey
    /// responder. The shell extracts the fresh Noise session from the live
    /// connection, allocates a new index, and stores it as the peer's pending
    /// (post-rekey) session awaiting K-bit cutover. `abandon_first` is set only
    /// on the dual-initiation *loser* path (larger NodeAddr), where we first
    /// abandon our own in-flight rekey/pending state. `peer` is the rekey target.
    RekeyRespond { peer: NodeAddr, abandon_first: bool },
    /// Same-epoch duplicate `msg3` (not a cross-connection, not a rekey): resend
    /// the existing peer's stored `msg2`. `msg2` is the opaque stored bytes
    /// (`None` → nothing to resend, the silent no-op preserved from the
    /// pre-refactor path). The active peer is left untouched.
    ResendMsg2 { msg2: Option<Vec<u8>> },
    /// Drop this `msg3` with a handshake reject (`HandshakeReject::BadState`) and
    /// no promotion. `reason` selects only the diagnostic log line.
    Reject { reason: InboundReject },
}

/// Why an inbound XX `msg3` was dropped by the core classification. XX reaches
/// the core with a single reject cause; the negotiation reject and the late ACL
/// reject are shell steps that run *before* the decision, and the max-peers cap
/// is a late gate inside `promote_connection` — none of them reach here.
#[derive(Debug)]
pub(crate) enum InboundReject {
    /// Dual rekey initiation and we are the tie-break *winner* (smaller
    /// NodeAddr): drop the peer's `msg3` and keep driving our own rekey.
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
/// `ActivePeer`, not a `PeerConnection`) and never reaches this decision.
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
            if p.rekey_in_progress || p.is_dampened || p.rekey_msg3_pending {
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

    /// Classify one inbound XX `msg3` from the establish snapshot and the Noise
    /// wire outcome. Pure: reads only `snap` and `wire`, mutates nothing,
    /// consumes nothing. The returned [`InboundDecision`] tells the shell which
    /// effect sequence to drive.
    ///
    /// Mirrors the pre-refactor inline `handle_msg3` classification order
    /// exactly:
    ///
    /// 1. No existing peer → net-new [`Promote`](InboundDecision::Promote).
    /// 2. Existing peer, different epoch → [`RestartThenPromote`].
    /// 3. Same epoch, different link, session younger than the rekey floor →
    ///    inline [`CrossConnect`] (the XX widening: IK resolves this on `msg2`).
    ///    `our_inbound_wins` is the larger-NodeAddr side, matching
    ///    `cross_connection_winner(our, peer, /*outbound=*/ false)`.
    /// 4. Same epoch, rekey enabled + healthy session + age at/above the floor →
    ///    [`RekeyRespond`]. The widened dual-init tie-break fires when the peer
    ///    is in *either* the `rekey_in_progress` or the `pending_new_session`
    ///    state: the smaller NodeAddr wins ([`Reject`] the peer's `msg3`), the
    ///    larger loses (`abandon_first`, then respond).
    /// 5. Otherwise same epoch → duplicate [`ResendMsg2`].
    ///
    /// [`CrossConnect`]: InboundDecision::CrossConnect
    /// [`RestartThenPromote`]: InboundDecision::RestartThenPromote
    /// [`RekeyRespond`]: InboundDecision::RekeyRespond
    /// [`Reject`]: InboundDecision::Reject
    /// [`ResendMsg2`]: InboundDecision::ResendMsg2
    pub(crate) fn establish_inbound(
        &self,
        snap: &EstablishSnapshot,
        wire: &WireOutcome,
    ) -> InboundDecision {
        if !snap.has_existing_peer {
            // No existing peer for this identity → net-new promote.
            return InboundDecision::Promote;
        }

        let peer = wire.peer_node_addr;
        match (snap.existing_peer_epoch, wire.remote_epoch) {
            (Some(existing), Some(new)) if existing != new => {
                // Epoch mismatch → peer restart.
                InboundDecision::RestartThenPromote { peer }
            }
            _ => {
                // Same epoch (or no epoch captured on either side).

                // Inline cross-connection (msg2-then-msg3 ordering): a
                // still-fresh session receiving a concurrent msg3 on a different
                // link. The upper age bound sits below the rekey floor so any
                // rekey-aged msg3 falls through to the rekey responder path.
                if snap.different_link && snap.existing_session_age_secs < snap.rekey_age_floor_secs
                {
                    // `cross_connection_winner(our, peer, this_is_outbound=false)`:
                    // the smaller node prefers its outbound, so our *inbound*
                    // wins iff we are the larger node (the exact negation of the
                    // smaller-NodeAddr `<` test the dual-init tie-break uses).
                    let our_inbound_wins = snap.our_node_addr >= peer;
                    return InboundDecision::CrossConnect {
                        peer,
                        our_inbound_wins,
                    };
                }

                // Rekey responder gate: aged, healthy session with rekey enabled.
                if snap.rekey_enabled
                    && snap.has_session
                    && snap.is_healthy
                    && snap.existing_session_age_secs >= snap.rekey_age_floor_secs
                {
                    // Widened dual-init tie-break: both the still-in-progress and
                    // the already-pending states resolve by the smaller NodeAddr.
                    if snap.rekey_in_progress || snap.pending_new_session {
                        if snap.our_node_addr < peer {
                            // We win — keep our session, drop their msg3.
                            return InboundDecision::Reject {
                                reason: InboundReject::DualRekeyWon,
                            };
                        }
                        // We lose — abandon ours, then respond as responder.
                        return InboundDecision::RekeyRespond {
                            peer,
                            abandon_first: true,
                        };
                    }
                    return InboundDecision::RekeyRespond {
                        peer,
                        abandon_first: false,
                    };
                }

                // Not a cross-connection, not a rekey → duplicate handshake.
                InboundDecision::ResendMsg2 {
                    msg2: snap.existing_msg2.clone(),
                }
            }
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

// ============================================================================
// FMP negotiation decision logic
// ============================================================================
//
// The version-agreement, profile-extraction, and profile-pairing decisions
// relocated from `protocol::negotiation` (the payload *codec* stays in
// `wire.rs`). These are pure decisions over an already-decoded
// `NegotiationPayload`, so they belong beside the other FMP core decisions.

impl NegotiationPayload {
    /// Agree on a protocol version with a peer's negotiation payload.
    ///
    /// Returns `min(our_max, their_max)`, rejecting if the agreed version
    /// is below either side's minimum.
    pub fn agree_version(&self, other: &Self) -> Result<u8, Error> {
        let agreed = self.version_max.min(other.version_max);
        if agreed < self.version_min || agreed < other.version_min {
            return Err(Error::Malformed("version mismatch"));
        }
        Ok(agreed)
    }

    /// Build an FMP negotiation payload for the given node profile.
    ///
    /// Sets the profile bits and MMP wants/provides defaults for the profile.
    pub fn fmp(version_min: u8, version_max: u8, profile: NodeProfile) -> Self {
        let (provides_sr, provides_rr, wants_sr, wants_rr) = match profile {
            NodeProfile::Full => (true, true, true, true),
            NodeProfile::NonRouting => (true, true, false, true),
            NodeProfile::Leaf => (false, true, false, false),
        };

        let mut features = (profile as u8 as u64) & FMP_FEAT_PROFILE_MASK;
        if provides_sr {
            features |= FMP_FEAT_PROVIDES_SR;
        }
        if provides_rr {
            features |= FMP_FEAT_PROVIDES_RR;
        }
        if wants_sr {
            features |= FMP_FEAT_WANTS_SR;
        }
        if wants_rr {
            features |= FMP_FEAT_WANTS_RR;
        }

        Self::new(version_min, version_max, features)
    }

    /// Extract the node profile from the FMP feature bitfield.
    pub fn node_profile(&self) -> Result<NodeProfile, Error> {
        let raw = (self.features & FMP_FEAT_PROFILE_MASK) as u8;
        NodeProfile::try_from(raw)
    }

    /// Whether this peer can provide MMP sender reports.
    pub fn provides_sr(&self) -> bool {
        self.features & FMP_FEAT_PROVIDES_SR != 0
    }

    /// Whether this peer can provide MMP receiver reports.
    pub fn provides_rr(&self) -> bool {
        self.features & FMP_FEAT_PROVIDES_RR != 0
    }

    /// Whether this peer wants MMP sender reports.
    pub fn wants_sr(&self) -> bool {
        self.features & FMP_FEAT_WANTS_SR != 0
    }

    /// Whether this peer wants MMP receiver reports.
    pub fn wants_rr(&self) -> bool {
        self.features & FMP_FEAT_WANTS_RR != 0
    }

    /// Validate that two profiles form a valid link pairing.
    ///
    /// At least one side must be `Full` or the link is rejected.
    pub fn validate_profiles(ours: NodeProfile, theirs: NodeProfile) -> Result<(), Error> {
        if ours != NodeProfile::Full && theirs != NodeProfile::Full {
            return Err(Error::Malformed(
                "invalid profile pairing (at least one must be full)",
            ));
        }
        Ok(())
    }
}

/// Decode, validate, and extract the peer's node profile from an FMP
/// negotiation payload.
///
/// The pure decode -> validate -> profile decision lifted out of the async
/// `process_fmp_negotiation` shell adapter. The shell applies the returned
/// profile to the connection (`set_negotiation_results`) and logs.
pub(crate) fn decide_fmp_negotiation(
    our_profile: NodeProfile,
    neg_bytes: &[u8],
) -> Result<NodeProfile, Error> {
    let their_payload = NegotiationPayload::decode(neg_bytes)?;
    let their_profile = their_payload.node_profile()?;
    NegotiationPayload::validate_profiles(our_profile, their_profile)?;
    Ok(their_profile)
}
