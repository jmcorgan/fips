//! Per-peer FMP control FSM (sans-IO reducer) — XX re-derivation.
//!
//! The unified per-peer lifecycle state machine, ported onto next's XX cores
//! from the IK-lineage template. It provides the FSM types, the machine struct
//! (control-tier state only), and the pure `step` reducer, plus its unit
//! tests. `step` is driven in production by the handshake handlers (msg2 on
//! the dial-persisted machine; msg3 through a throwaway decision machine), the
//! rekey-cadence and liveness-reap routers, and the dial/lifecycle paths, with
//! the executor in `crate::node::dataplane::peer_actions` performing the
//! returned actions. Still dormant: `PeerEvent::Timeout` and
//! `PeerEvent::InboundMsg1` are never dispatched — timer FIRING decisions stay
//! with the shell drivers, and `handle_msg1` sends msg2 inline.
//!
//! ## Shape
//!
//! `step(event, now, index_allocator) -> Vec<PeerAction>` is a **pure reducer**:
//! every lifecycle *decision* is delegated to the existing sans-IO cores in
//! [`crate::proto::fmp`] ([`Fmp::establish_inbound`],
//! [`Fmp::poll_timeouts`]/[`poll_resends`]/[`poll_rekey`]/[`poll_rekey_resends`])
//! — this module writes **no new decision core**. The machine only (a) builds
//! the plain-data snapshots those cores consume from its control-tier state, (b)
//! maps the returned [`ConnAction`]/[`InboundDecision`]/[`PromotionResult`] into
//! the [`PeerAction`] vocabulary the driver executes, and (c) advances its own
//! control state.
//!
//! ## XX asymmetries (vs the IK template)
//!
//! Two structural inversions distinguish XX from IK, and shape the inbound path:
//!
//! - **Identity crystallizes at msg3, not msg1.** On XX the responder learns the
//!   initiator's node address only once `msg3` completes the Noise handshake, so
//!   the inbound classification ([`Fmp::establish_inbound`]) runs at msg3. The
//!   single IK `InboundMsg1` event is therefore split into an
//!   [`InboundMsg1`](PeerEvent::InboundMsg1) index-alloc/defer step and an
//!   [`InboundMsg3`](PeerEvent::InboundMsg3) classify step.
//! - **Our session index is allocated at msg1, before identity/ACL.** Every
//!   admitted inbound handshake allocates at the msg1 event (mirroring the shell
//!   `handle_msg1`); the IK two-phase authorize (`Authorized`/`Rejected` events,
//!   a Phase-2 deferred allocation) has no XX analog and is gone. The late ACL is
//!   a shell gate at msg3 *before* the classify — not a machine event.
//!
//! ## Session-carrying establish effects stay shell-side
//!
//! The XX cross-connection swap ([`CrossConnect`](InboundDecision::CrossConnect))
//! and rekey-responder ([`RekeyRespond`](InboundDecision::RekeyRespond)) arms both
//! move a `NoiseSession` between a `PeerConnection` and an `ActivePeer`
//! (`take_session`/`replace_session`/`set_pending_session`) — effects that cannot
//! ride in a plain-data [`PeerAction`]. The machine owns only the *classification
//! dispatch* + the index-plane facts; it emits a plain-data trigger
//! ([`SwapToInboundSession`](PeerAction::SwapToInboundSession) /
//! [`RekeyRespondTrigger`](PeerAction::RekeyRespondTrigger)) carrying indices +
//! the tie-break flag, and the executor performs the session/registry surgery
//! shell-side, matching the former inline `handle_msg3` bodies verbatim. Both
//! triggers are live: `handle_msg3` steps the decision machine and the
//! executor performs its verdict.
//!
//! Likewise the outbound completion is NOT routed through the machine: next has
//! no `establish_outbound` core — `handle_msg2` learns the identity from
//! `conn.expected_identity()` and drives `promote_connection` inline. The
//! machine's outbound role is `Dial`→`OpenTransport`, `start_outbound_handshake`,
//! and the resend/timeout timers; the shell drives promote and feeds the outcome
//! back via [`PromotionResolved`](PeerEvent::PromotionResolved).
//!
//! ## Realizability notes
//!
//! - `SendHandshake`/`SendRekey`/`SendLinkMessage` carry **opaque bytes**
//!   (`Vec<u8>`); the driver applies outer wire framing / encryption. A fresh
//!   outbound msg1 and a fresh inbound msg2 have no bytes the control machine can
//!   build (the Noise step / `build_msg2` are shell-side), so they are emitted
//!   with an empty payload and threaded at wiring time. Not exercised by the
//!   tests (which assert on action *kinds* / index-plane facts).
//! - `PeerSnapshot::rekey_msg3_pending` is sourced from a control field defaulting
//!   `false`; the real wiring to `peer.rekey_msg3_payload().is_some()` and the
//!   [`RekeyMsg3Resend`](TimerKind::RekeyMsg3Resend) driver land when the rekey
//!   path is wired.
//! - `PeerSnapshot::counter` (the Noise send counter) is a send-state fact the
//!   control machine cannot see; passed as `0`. Irrelevant to every test.

#![allow(dead_code)]

use crate::proto::fmp::{
    ConnAction, ConnSnapshot, ConnectionState, EstablishSnapshot, Fmp, InboundDecision,
    InboundReject, PeerSnapshot, PromotionResult, RekeyCfg, RekeyResendSnapshot, WireOutcome,
};
use crate::proto::link::LinkMessageType;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::{IndexAllocator, SessionIndex};
use crate::{NodeAddr, PeerIdentity};

// ============================================================================
// Timing placeholders
//
// The `poll_*` cores already take the interval/backoff as arguments, so these
// are only used to compute `SetTimer{at_ms}` deadlines and the
// `Closed{backoff_deadline_ms}` park time. The handshake timers are armed
// live at dial time from these constants: the retransmit driver fires on the
// machine-armed deadline, while the timeout reaper keys on the timer's
// presence with its threshold read from `NodeConfig`, which also governs the
// reschedule cadence shell-side. The unit tests assert on timer *kinds*, not
// exact deadlines.
// ============================================================================

const HANDSHAKE_RETRANSMIT_INTERVAL_MS: u64 = 1_000;
const HANDSHAKE_TIMEOUT_MS: u64 = 30_000;
const HANDSHAKE_MAX_RESENDS: u32 = 5;
const RESEND_BACKOFF: f64 = 2.0;
const REKEY_CADENCE_INTERVAL_MS: u64 = 60_000;
const REKEY_RESEND_INTERVAL_MS: u64 = 1_000;
const REKEY_MAX_RESENDS: u32 = 5;
const REKEY_AFTER_SECS: u64 = 3_600;
const REKEY_AFTER_MESSAGES: u64 = 1_000_000;
const DRAIN_WINDOW_MS: u64 = 5_000;
const LIVENESS_INTERVAL_MS: u64 = 15_000;
const REKEY_DAMPEN_MS: u64 = 30_000;
const CLOSED_BACKOFF_MS: u64 = 5_000;

// ============================================================================
// FSM types
// ============================================================================

/// The unified per-peer lifecycle state (subsumes today's `HandshakeState`,
/// `ConnectivityState`, and the rekey flags). Keyed by `LinkId` until
/// `Established` crystallizes the peer to its `NodeAddr`. **Terminal at
/// `Closed`** — re-dial is the reconciler's, not a self-transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PeerState {
    /// Reconciler intent recorded; no transport work started yet.
    Discovered,
    /// Outbound transport connect in flight (connection-oriented transports).
    Connecting { link: LinkId },
    /// Handshake phase; identity not yet crystallized.
    Handshaking { link: LinkId, phase: HandshakePhase },
    /// Handshake complete; identity crystallized; send-state published.
    Established { addr: NodeAddr },
    /// Steady state.
    Active { addr: NodeAddr },
    /// A maintenance sub-machine is running (rekey / liveness / mtu).
    Maintaining { addr: NodeAddr, kind: MaintainKind },
    /// Graceful teardown in flight.
    Closing { addr: NodeAddr, reason: CloseReason },
    /// Terminal failure; carries the diagnostic reason.
    Failed { reason: FailReason },
    /// Terminal; parked at the reconciler-computed backoff deadline.
    Closed { backoff_deadline_ms: u64 },
}

/// Handshake phase. On XX the inbound leg parks at `SentMsg2` after replying to
/// msg1, awaiting the initiator's msg3 (where identity crystallizes).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandshakePhase {
    Initial,
    /// Outbound: our msg1 is sent, awaiting the responder's msg2.
    SentMsg1,
    /// Inbound: our index is allocated and msg2 is sent, awaiting msg3.
    SentMsg2,
}

/// Which maintenance sub-machine `Maintaining` is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintainKind {
    Rekey(RekeyPhase),
    Liveness(LivenessPhase),
    Mtu,
}

/// Rekey negotiation / cutover phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RekeyPhase {
    /// Rekey msg1 sent (initiator) or responder pending-session stored;
    /// negotiation / cutover-wait in flight.
    Msg1Sent,
    /// A pending post-rekey session is ready; awaiting the K-bit cutover.
    PendingCutover,
    /// Post-cutover drain window open.
    Draining,
}

/// Liveness sub-phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LivenessPhase {
    Stale,
    Reconnecting,
}

/// Why a graceful close was requested.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CloseReason {
    /// Operator/protocol requested — no loss report.
    Requested,
    /// Post-rekey drain-driven close.
    Draining,
}

/// Terminal-failure reason (diagnostic only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailReason {
    TransportFailed,
    HandshakeTimeout,
    HandshakeFailed,
    AclRejected,
    Rejected,
    LinkDead,
}

/// A timer the machine schedules on the driver's quantized tick.
///
/// `Hash` lets it key the driver's per-peer timer store; `Ord` lets the driver
/// collect due kinds deterministically. Note the driver must fire
/// `HandshakeTimeout` before `HandshakeRetransmit` on a same-tick coincidence
/// (a reaped leg must not be resent), which is the reverse of this declaration
/// order — the driver orders explicitly rather than relying on the derived
/// ascending `Ord`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum TimerKind {
    HandshakeRetransmit,
    HandshakeTimeout,
    RekeyCadence,
    RekeyResend,
    /// XX-only: retransmit the retained rekey msg3 to a responder not yet
    /// confirmed on the new epoch. Its driving arm lands at the rekey step.
    RekeyMsg3Resend,
    DrainExpiry,
    Liveness,
}

/// Outcome of an outbound cross-connection resolution, observed by the control
/// machine after the shell has already applied the effect inline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CrossConnOutcome {
    /// The outbound session replaced the existing inbound one: the control
    /// shadow adopts the new local and remote session indices.
    Swap {
        our_index: SessionIndex,
        their_index: SessionIndex,
    },
    /// The existing inbound session was kept: the control shadow is unchanged.
    Keep,
}

/// An input to the machine. Cross-registry facts ride in the payload as
/// plain-data snapshots ([`WireOutcome`]/[`EstablishSnapshot`]) built shell-side;
/// `now` is the `step` parameter, never duplicated here.
///
/// Not `Debug`/`PartialEq`: the reused core snapshot payloads derive neither.
pub(crate) enum PeerEvent {
    /// Reconciler dial intent. `connection_oriented` selects the outbound
    /// path: connection-oriented transports open the transport first
    /// (`OpenTransport` → `Connecting`); connectionless ones send msg1
    /// immediately (`start_outbound_handshake` → `Handshaking`).
    Dial {
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer_identity: PeerIdentity,
        connection_oriented: bool,
    },
    /// Connection-oriented transport connected.
    TransportConnected,
    /// Transport connect failed.
    TransportFailed,
    /// Inbound handshake msg1 processed shell-side: allocate our index and reply
    /// with msg2, deferring identity/classification to msg3. Carries no identity
    /// or wire outcome — on XX neither is known at msg1.
    InboundMsg1 { link: LinkId },
    /// Inbound handshake msg3 completed (Noise finalized, identity crystallized
    /// shell-side, ACL already gated). Drives the establish classification. Used
    /// for both a fresh inbound establish and a rekey msg3 on an established peer.
    /// `our_index` is the index allocated for this leg at msg1; it is carried on
    /// the event so a fresh classification machine can be seeded with it before
    /// dispatch (the cross-connection and rekey-responder decisions read it back
    /// to build their session-swap trigger, and would otherwise emit nothing).
    InboundMsg3 {
        wire: WireOutcome,
        est: EstablishSnapshot,
        our_index: SessionIndex,
    },
    /// Outbound handshake msg2 completed (Noise finalized, identity crystallized
    /// shell-side from the connection's expected identity, ACL already gated,
    /// msg3 sent). The net-new-vs-cross-connection decision is the shell's
    /// peer-map membership test; this event is emitted only on the net-new path,
    /// so it maps directly to a promote. `their_index` carries the peer's session
    /// index for shape parity with the inbound path.
    OutboundMsg2 { their_index: SessionIndex },
    /// `promote_connection` resolved the [`PromoteToActive`](PeerAction::PromoteToActive)
    /// action shell-side; the machine consumes the outcome (it does not
    /// re-decide the tie-break).
    PromotionResolved { result: PromotionResult },
    /// Inbound rekey msg2 (completes our initiated rekey).
    RekeyMsg2 { their_index: SessionIndex },
    /// A cadence-decided rekey `ConnAction` to CONSUME. The shell ran the batch
    /// `poll_rekey` across the whole peer set (phase-grouped, index-order
    /// preserving) and routes each decided action here; the machine applies the
    /// control-tier transition + emits the send-state write
    /// (`SwapSendState`/`CompleteDrain`) WITHOUT re-polling. Carries only
    /// `Cutover`/`Drain`; `InitiateRekey` stays inline shell-side with a
    /// [`RekeyInitiated`](PeerEvent::RekeyInitiated) observation.
    RekeyConsume { action: ConnAction },
    /// OBSERVATION: the shell initiated an outbound rekey inline (the Noise msg1
    /// leaf + index allocation are shell-side). Advances the control state to
    /// `Maintaining{Rekey(Msg1Sent)}` so the next tick's `Cutover`/`Drain` consume
    /// transitions from a coherent phase. Emits no action.
    RekeyInitiated,
    /// OBSERVATION: the shell resolved an outbound cross-connection inline (a
    /// session swap or keep, with the registry and index surgery already
    /// applied). Reconciles the control shadow's session indices with reality
    /// on a swap; leaves them untouched on a keep. Emits no action.
    CrossConnResolved { outcome: CrossConnOutcome },
    /// Data plane observed the responder K-bit flip inline.
    PeerKbitFlip { epoch: [u8; 8] },
    /// A filter announce is due for this peer.
    FilterAnnounce,
    /// A tree announce is due for this peer.
    TreeAnnounceDue,
    /// MMP saw a packet from the peer.
    PeerHeard,
    /// A keepalive heartbeat is due.
    HeartbeatDue,
    /// MMP declared the link dead.
    LinkDeadSuspected,
    /// A machine timer fired on the tick.
    Timeout { kind: TimerKind },
    /// Graceful disconnect requested.
    Disconnect { reason: CloseReason },
    /// The periodic quantized tick.
    Tick,
}

/// Why a peer was reported lost. Selects the reconciler reflex the executor
/// routes the `ReportLost` token to: an un-promoted handshake attempt that
/// failed (`HandshakeTimeout`, connected-guarded like the old `schedule_retry`)
/// versus an established peer whose link died (`LinkDead`, unconditional like
/// the old `schedule_reconnect`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LostKind {
    /// An outbound handshake attempt timed out or its dial failed before the
    /// peer promoted — routes to the connected-guarded reflex.
    HandshakeTimeout,
    /// An established peer's link went dead or is being replaced — routes to
    /// the unconditional reconnect reflex.
    LinkDead,
}

/// An effect the driver executes on the machine's behalf. Runtime-agnostic
/// plain data — no tokio handles, time only as `at_ms` fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PeerAction {
    /// Open a connection-oriented transport to the target.
    OpenTransport {
        transport_id: TransportId,
        remote_addr: TransportAddr,
    },
    /// Transmit handshake bytes (driver applies outer framing; see module note).
    SendHandshake { bytes: Vec<u8> },
    /// Transmit rekey handshake bytes.
    SendRekey { bytes: Vec<u8> },
    /// Transmit an (encrypted) plaintext link-control frame. Opaque `Vec<u8>`
    /// pending a unifying `LinkMessage` type.
    SendLinkMessage { msg: Vec<u8> },
    /// Crystallize identity, re-home the map key, publish send-state
    /// (`promote_connection`). Resolves to a [`PromotionResolved`](PeerEvent::PromotionResolved).
    PromoteToActive { link: LinkId },
    /// Initiator-side rekey cutover: swap the published send-state to the pending
    /// epoch.
    SwapSendState { epoch: [u8; 8] },
    /// Complete an initiator-side rekey drain: retire the previous session slot
    /// (drop its `peers_by_index`/decrypt-worker entry, free its index). The
    /// executor reads the REAL previous index from `ActivePeer::complete_drain`
    /// (not a machine-shadow index, which can drift).
    CompleteDrain { peer: NodeAddr },
    /// Invalidate the published send-state (close/loss).
    InvalidateSendState,
    /// Register a decrypt-worker entry for `index`.
    RegisterDecryptSession { index: SessionIndex },
    /// Unregister the decrypt-worker entry for `index`.
    UnregisterDecryptSession { index: SessionIndex },
    /// Free `index` back to the shared allocator.
    FreeIndex { index: SessionIndex },
    /// XX inbound cross-connection resolved at msg3 (a plain-data TRIGGER — the
    /// session swap is a shell effect). The executor reproduces
    /// `handle_msg3`'s `CrossConnect` body verbatim: `our_inbound_wins` (larger
    /// NodeAddr) swaps to the inbound session (`take_session`/`replace_session`,
    /// `peers_by_index` surgery, free the peer's OLD index); otherwise it frees
    /// `our_index` (the msg1-allocated leg index) and keeps the outbound session.
    /// Either way the temporary inbound link is torn down.
    SwapToInboundSession {
        peer: NodeAddr,
        our_index: SessionIndex,
        our_inbound_wins: bool,
    },
    /// XX rekey-responder resolved at msg3 (a plain-data TRIGGER — the session
    /// move is a shell effect). The executor reproduces `handle_msg3`'s
    /// `RekeyRespond` body verbatim: on `abandon_first`, `peer.abandon_rekey()`
    /// then free the abandoned index + remove its `peers_by_index`/
    /// `pending_outbound` entries; then `take_session` +
    /// `peer.set_pending_session(session, our_index, their_index)` +
    /// `record_peer_rekey` + `peers_by_index.insert`. `our_index` is the
    /// msg1-allocated leg index that becomes the pending session's index. On XX
    /// there is NO responder-side msg2 send here (it went out at msg1).
    RekeyRespondTrigger {
        peer: NodeAddr,
        our_index: SessionIndex,
        abandon_first: bool,
    },
    /// Activate the per-peer connected-UDP plane.
    ActivateConnectedUdp,
    /// Tear down the per-peer connected-UDP plane.
    TeardownConnectedUdp,
    /// Schedule `kind` to fire at `at_ms` on the tick.
    SetTimer { kind: TimerKind, at_ms: u64 },
    /// Cancel a scheduled timer.
    CancelTimer { kind: TimerKind },
    /// Report the peer lost to the reconciler (the single loss token — there is
    /// deliberately no `ScheduleRetry` machine action). `kind` selects the
    /// reflex (handshake-timeout vs link-dead) the executor routes to.
    ReportLost { peer: NodeAddr, kind: LostKind },
}

// ============================================================================
// The machine (control tier)
// ============================================================================

/// Per-peer control FSM. Holds control-tier lifecycle state only; the
/// send-critical state is published as `PeerSendState` and mutated via the
/// emitted [`PeerAction`]s.
pub(crate) struct PeerMachine {
    state: PeerState,
    link: LinkId,
    identity: Option<PeerIdentity>,
    /// The crystallized peer node address. Known up front for outbound (from the
    /// dial identity); learned at msg3 for inbound (from [`WireOutcome`]).
    node_addr: Option<NodeAddr>,
    /// Pure handshake-phase bookkeeping (link/direction/indices/transport/
    /// stored handshake bytes/epoch). Reused verbatim from the FMP state core.
    conn: ConnectionState,
    /// Remote startup epoch (establish-path-only; NOT in send-state).
    remote_epoch: Option<[u8; 8]>,

    // --- rekey negotiation sub-state (control tier; NOT the pending send slot) ---
    rekey_in_progress: bool,
    /// The index we allocated for our in-flight/negotiated rekey session.
    rekey_our_index: Option<SessionIndex>,
    /// Stored rekey msg1 wire bytes (for retransmit).
    rekey_msg1: Option<Vec<u8>>,
    rekey_resend_count: u32,
    /// When we last processed a peer rekey msg3 (dampening).
    last_peer_rekey_ms: u64,
    /// XX-only: the initiator cut over but is still retransmitting this cycle's
    /// rekey msg3 to an unconfirmed responder. Suppresses starting a fresh rekey.
    /// Sourced from a control field here (default `false`); the real wiring to
    /// `peer.rekey_msg3_payload().is_some()` lands at the rekey step.
    rekey_msg3_pending: bool,

    // --- timing (control tier) ---
    session_established_at_ms: u64,
    authenticated_at_ms: u64,
    rekey_jitter_secs: i64,
    last_heartbeat_sent_ms: u64,

    // --- decrypt-registration shadow ---
    /// The currently-registered decrypt index (post-establish).
    our_index: Option<SessionIndex>,
    /// The previous index held open during a post-cutover drain window.
    draining_index: Option<SessionIndex>,
}

impl PeerMachine {
    /// New outbound machine (we dial). Starts at `Discovered`; the reconciler's
    /// `Dial` event drives the first transition.
    pub(crate) fn new_outbound(link: LinkId, identity: PeerIdentity, now: u64) -> Self {
        Self {
            state: PeerState::Discovered,
            link,
            identity: Some(identity),
            node_addr: Some(*identity.node_addr()),
            conn: ConnectionState::outbound(link, identity, now),
            remote_epoch: None,
            rekey_in_progress: false,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_resend_count: 0,
            last_peer_rekey_ms: 0,
            rekey_msg3_pending: false,
            session_established_at_ms: 0,
            authenticated_at_ms: 0,
            rekey_jitter_secs: 0,
            last_heartbeat_sent_ms: 0,
            our_index: None,
            draining_index: None,
        }
    }

    /// New inbound machine (they dialed us). Starts at `Handshaking{Initial}`.
    pub(crate) fn new_inbound(link: LinkId, now: u64) -> Self {
        Self {
            state: PeerState::Handshaking {
                link,
                phase: HandshakePhase::Initial,
            },
            link,
            identity: None,
            node_addr: None,
            conn: ConnectionState::inbound(link, now),
            remote_epoch: None,
            rekey_in_progress: false,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_resend_count: 0,
            last_peer_rekey_ms: 0,
            rekey_msg3_pending: false,
            session_established_at_ms: 0,
            authenticated_at_ms: 0,
            rekey_jitter_secs: 0,
            last_heartbeat_sent_ms: 0,
            our_index: None,
            draining_index: None,
        }
    }

    /// New inbound machine for a leg whose msg1 was already processed
    /// shell-side: the index is allocated and msg2 has been built and sent, so
    /// the machine is born parked at `Handshaking{SentMsg2}` awaiting msg3
    /// (where identity crystallizes). This is the birth ctor for the
    /// msg1-inline path (`handle_msg1` runs the crypto and the msg2 send
    /// itself, so no `InboundMsg1` event is dispatched); it seeds exactly the
    /// state that event's handler would have left behind, minus the timers —
    /// no timer is armed on inbound legs (the stale-connection reaper owns
    /// their timeout).
    pub(crate) fn inbound_msg2_sent(link: LinkId, our_index: SessionIndex, now: u64) -> Self {
        let mut machine = Self::new_inbound(link, now);
        machine.conn.set_our_index(our_index);
        machine.our_index = Some(our_index);
        machine.state = PeerState::Handshaking {
            link,
            phase: HandshakePhase::SentMsg2,
        };
        machine
    }

    /// New machine for an ALREADY-established peer: the post-handshake state a
    /// promoted peer occupies before any rekey. The driver inserts one of these
    /// into `Node.peer_machines` at each `promote_connection` establishment site
    /// so every established peer has exactly one machine keyed by its `LinkId`.
    /// The machine is **inert** — nothing drives it yet — and is
    /// parked at [`PeerState::Established`] so a later reap sees
    /// [`is_established_context`](Self::is_established_context) true and a later
    /// rekey finds it. `our_index` is the peer's msg1-allocated session
    /// index; `remote_epoch` is the crystallized peer's startup epoch.
    pub(crate) fn established(
        link: LinkId,
        identity: PeerIdentity,
        our_index: SessionIndex,
        is_outbound: bool,
        remote_epoch: Option<[u8; 8]>,
        now: u64,
    ) -> Self {
        let addr = *identity.node_addr();
        let mut conn = if is_outbound {
            ConnectionState::outbound(link, identity, now)
        } else {
            ConnectionState::inbound(link, now)
        };
        conn.set_our_index(our_index);
        conn.set_remote_epoch(remote_epoch);
        Self {
            state: PeerState::Established { addr },
            link,
            identity: Some(identity),
            node_addr: Some(addr),
            conn,
            remote_epoch,
            rekey_in_progress: false,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_resend_count: 0,
            last_peer_rekey_ms: 0,
            rekey_msg3_pending: false,
            session_established_at_ms: now,
            authenticated_at_ms: now,
            rekey_jitter_secs: 0,
            last_heartbeat_sent_ms: 0,
            our_index: Some(our_index),
            draining_index: None,
        }
    }

    /// Current lifecycle state.
    pub(crate) fn state(&self) -> PeerState {
        self.state
    }

    /// The index we allocated for this peer's inbound session at msg1. `None`
    /// before allocation. The inbound cross-connection / rekey-respond triggers
    /// and the executor read this to perform the shell registry surgery with the
    /// machine-owned index.
    pub(crate) fn our_index(&self) -> Option<SessionIndex> {
        self.our_index
    }

    /// The msg1 resend count for this outbound handshake leg. The per-peer
    /// machine is the home for this counter — the timer driver advances it via
    /// [`record_resend`](Self::record_resend) on each successful resend, and the
    /// control-socket connection snapshot reads it here so the operator-visible
    /// count follows the machine rather than the (now inert) shell connection.
    pub(crate) fn resend_count(&self) -> u32 {
        self.conn.resend_count()
    }

    /// Record a successful msg1 resend: advance the count and store the next
    /// backoff deadline. The driver calls this only after the resend actually
    /// went out (record-on-success — a failed send neither advances the count
    /// nor reschedules), matching the pre-fold shell semantics.
    pub(crate) fn record_resend(&mut self, next_resend_at_ms: u64) {
        self.conn.record_resend(next_resend_at_ms);
    }

    /// Whether this is an outbound leg parked at `SentMsg1` — the only state in
    /// which a msg1 resend is due. Mirrors `on_handshake_retransmit`'s guard so
    /// the shell timer driver can gate without reaching into machine state.
    pub(crate) fn is_handshaking_sent_msg1(&self) -> bool {
        matches!(
            self.state,
            PeerState::Handshaking {
                phase: HandshakePhase::SentMsg1,
                ..
            }
        )
    }

    /// The crystallized node address, if identity is known.
    fn addr(&self) -> Option<NodeAddr> {
        self.node_addr
    }

    // ------------------------------------------------------------------
    // The reducer.
    // ------------------------------------------------------------------

    /// Advance the machine one event. Pure reducer: delegates every decision to
    /// the sans-IO cores, maps their results into [`PeerAction`]s, and updates
    /// control state. `index_allocator` is a synchronous capability (the
    /// handshake/rekey need an index mid-transition), never moved in, never an
    /// action.
    pub(crate) fn step(
        &mut self,
        event: PeerEvent,
        now: u64,
        index_allocator: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        match event {
            PeerEvent::Dial {
                transport_id,
                remote_addr,
                connection_oriented,
                ..
            } => self.on_dial(transport_id, remote_addr, connection_oriented, now),
            PeerEvent::TransportConnected => self.on_transport_connected(now),
            PeerEvent::TransportFailed => self.on_transport_failed(now),
            PeerEvent::InboundMsg1 { link } => self.on_inbound_msg1(link, now, index_allocator),
            PeerEvent::InboundMsg3 {
                wire,
                est,
                our_index,
            } => self.on_inbound_msg3(wire, est, our_index, now, index_allocator),
            PeerEvent::OutboundMsg2 { their_index } => self.on_outbound_msg2(their_index, now),
            PeerEvent::PromotionResolved { result } => self.on_promotion_resolved(result, now),
            PeerEvent::RekeyMsg2 { their_index } => self.on_rekey_msg2(their_index),
            PeerEvent::RekeyConsume { action } => self.map_rekey_action(action, now),
            PeerEvent::RekeyInitiated => self.on_rekey_initiated(),
            PeerEvent::CrossConnResolved { outcome } => self.on_cross_conn_resolved(outcome),
            PeerEvent::PeerKbitFlip { .. } => {
                // Responder cutover is data-plane-owned: the machine only
                // schedules the drain-window unregister. NO slot mutation.
                vec![PeerAction::SetTimer {
                    kind: TimerKind::DrainExpiry,
                    at_ms: now + DRAIN_WINDOW_MS,
                }]
            }
            PeerEvent::FilterAnnounce => vec![PeerAction::SendLinkMessage {
                // Filter-announce payload is data-plane-owned; threaded in at
                // wiring time.
                msg: Vec::new(),
            }],
            PeerEvent::TreeAnnounceDue => vec![PeerAction::SendLinkMessage {
                // Tree-announce payload is data-plane-owned.
                msg: Vec::new(),
            }],
            PeerEvent::PeerHeard => self.on_peer_heard(now),
            PeerEvent::HeartbeatDue => self.on_heartbeat_due(now),
            PeerEvent::LinkDeadSuspected => self.on_link_dead(now),
            PeerEvent::Timeout { kind } => self.on_timeout(kind, now),
            PeerEvent::Disconnect { reason } => self.on_disconnect(reason, now),
            PeerEvent::Tick => self.on_tick(now),
        }
    }

    // ------------------------------------------------------------------
    // Outbound establish
    // ------------------------------------------------------------------

    fn on_dial(
        &mut self,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        connection_oriented: bool,
        now: u64,
    ) -> Vec<PeerAction> {
        if !matches!(self.state, PeerState::Discovered) {
            return Vec::new();
        }
        self.conn.set_transport_id(transport_id);
        if connection_oriented {
            // Connection-oriented transports open the transport first; the
            // executor's `OpenTransport` arm connects, then feeds
            // `TransportConnected` → `start_outbound_handshake`.
            self.state = PeerState::Connecting { link: self.link };
            vec![PeerAction::OpenTransport {
                transport_id,
                remote_addr,
            }]
        } else {
            // Connectionless transports have no connect step — send msg1
            // immediately (the executor's `SendHandshake` msg1 branch performs
            // the Noise leaf, framing, index alloc, and send).
            self.start_outbound_handshake(now)
        }
    }

    fn on_transport_connected(&mut self, now: u64) -> Vec<PeerAction> {
        if !matches!(self.state, PeerState::Connecting { .. }) {
            return Vec::new();
        }
        self.start_outbound_handshake(now)
    }

    fn on_transport_failed(&mut self, now: u64) -> Vec<PeerAction> {
        if !matches!(self.state, PeerState::Connecting { .. }) {
            return Vec::new();
        }
        let mut actions = Vec::new();
        if let Some(peer) = self.addr() {
            // Dial failure on an un-promoted leg routes like a handshake timeout
            // (the connected-guarded reflex). Dormant today — no `TransportFailed`
            // event is dispatched until the connection-oriented cutover (C5).
            actions.push(PeerAction::ReportLost {
                peer,
                kind: LostKind::HandshakeTimeout,
            });
        }
        self.state = PeerState::Closed {
            backoff_deadline_ms: now + CLOSED_BACKOFF_MS,
        };
        actions
    }

    /// Emit msg1 and arm the retransmit/timeout timers. The Noise msg1
    /// construction and its index allocation are shell-side effects performed by
    /// the driver when it executes this action; an empty payload is emitted (see
    /// module note). This path is not exercised by the tests.
    fn start_outbound_handshake(&mut self, now: u64) -> Vec<PeerAction> {
        let bytes = Vec::new();
        self.state = PeerState::Handshaking {
            link: self.link,
            phase: HandshakePhase::SentMsg1,
        };
        vec![
            PeerAction::SendHandshake { bytes },
            PeerAction::SetTimer {
                kind: TimerKind::HandshakeRetransmit,
                at_ms: now + HANDSHAKE_RETRANSMIT_INTERVAL_MS,
            },
            PeerAction::SetTimer {
                kind: TimerKind::HandshakeTimeout,
                at_ms: now + HANDSHAKE_TIMEOUT_MS,
            },
        ]
    }

    // ------------------------------------------------------------------
    // Inbound establish (XX: index at msg1, identity + classify at msg3)
    // ------------------------------------------------------------------

    /// Inbound **msg1**: allocate our session index (mirroring `handle_msg1`'s
    /// allocation before identity/ACL), reply with msg2, and park at `SentMsg2`
    /// awaiting msg3. On XX every admitted handshake allocates here — there is no
    /// IK-style Phase-2 deferred allocation. The msg2 Noise bytes are shell-built
    /// (`build_msg2`); the driver fills them when it executes `SendHandshake`
    /// (empty here, unwired). Identity is unknown at msg1.
    fn on_inbound_msg1(
        &mut self,
        link: LinkId,
        now: u64,
        alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        let our_index = match alloc.allocate() {
            Ok(idx) => idx,
            Err(_) => {
                // Allocation exhausted: mirrors `handle_msg1`'s allocate-failure
                // path (records reject, drops the leg). No index, no msg2.
                self.state = PeerState::Failed {
                    reason: FailReason::Rejected,
                };
                return Vec::new();
            }
        };
        self.conn.set_our_index(our_index);
        self.our_index = Some(our_index);
        self.state = PeerState::Handshaking {
            link,
            phase: HandshakePhase::SentMsg2,
        };
        vec![
            PeerAction::SendHandshake { bytes: Vec::new() },
            PeerAction::SetTimer {
                kind: TimerKind::HandshakeTimeout,
                at_ms: now + HANDSHAKE_TIMEOUT_MS,
            },
        ]
    }

    /// Inbound **msg3**: identity crystallizes here; classify via
    /// `establish_inbound` and dispatch the 6-arm decision. The ACL gate and the
    /// Noise finalize already ran shell-side before this event. Our index was
    /// allocated at msg1 (`self.our_index`).
    fn on_inbound_msg3(
        &mut self,
        wire: WireOutcome,
        est: EstablishSnapshot,
        our_index: SessionIndex,
        now: u64,
        _alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        // Identity crystallizes at msg3 on XX (WireOutcome carries only the node
        // address + epoch; the full static key stays shell-side).
        self.node_addr = Some(wire.peer_node_addr);
        self.remote_epoch = wire.remote_epoch;
        // Seed the leg's index from the event. On a fresh classification machine
        // the index was allocated at msg1 shell-side and is not otherwise known
        // here; the cross-connection and rekey-responder decisions read it back to
        // build their session-swap trigger, and the tie-break/duplicate arms use
        // it to return the index. Without this seed those arms would emit nothing
        // and leak the index.
        self.conn.set_our_index(our_index);
        self.our_index = Some(our_index);

        match Fmp::new().establish_inbound(&est, &wire) {
            InboundDecision::Reject {
                reason: InboundReject::DualRekeyWon,
            } => {
                // Dual-init rekey tie-break: we win (smaller NodeAddr), drop the
                // peer's msg3 and keep driving our own rekey. The existing peer
                // (a separate machine/registry entry) is untouched; this temporary
                // leg is discarded, returning the msg1-allocated index rather than
                // orphaning it, then terminating this leg.
                let actions = vec![PeerAction::FreeIndex { index: our_index }];
                let _ = self.fail(FailReason::Rejected);
                actions
            }
            InboundDecision::ResendMsg2 { msg2 } => {
                // Same-epoch duplicate: resend the existing peer's stored msg2 (if
                // any), leaving the active peer untouched, return the msg1-allocated
                // index, then terminate this leg so a later timeout on a persistent
                // machine cannot fire against the healthy established peer.
                let mut actions = Vec::new();
                if let Some(bytes) = msg2 {
                    actions.push(PeerAction::SendHandshake { bytes });
                }
                actions.push(PeerAction::FreeIndex { index: our_index });
                let _ = self.fail(FailReason::Rejected);
                actions
            }
            InboundDecision::CrossConnect {
                peer,
                our_inbound_wins,
            } => self.on_cross_connect(peer, our_inbound_wins),
            InboundDecision::RekeyRespond {
                peer,
                abandon_first,
            } => self.rekey_respond(peer, abandon_first, now),
            InboundDecision::RestartThenPromote { peer } => {
                // Epoch mismatch — peer restarted. `InvalidateSendState` maps to
                // the shell's `remove_active_peer(&peer)` and `ReportLost` to
                // `note_link_dead(peer)`; then fall through to promote the fresh
                // connection in the stale peer's place.
                vec![
                    PeerAction::InvalidateSendState,
                    PeerAction::ReportLost {
                        peer,
                        kind: LostKind::LinkDead,
                    },
                    PeerAction::PromoteToActive { link: self.link },
                ]
            }
            InboundDecision::Promote => {
                // Net-new inbound (or the post-restart re-promote): the shell's
                // `promote_connection` late max-peers cap + cross-connection
                // won/lost handling resolve via the `PromotionResolved` feedback.
                vec![PeerAction::PromoteToActive { link: self.link }]
            }
        }
    }

    /// Net-new outbound promote after msg2 completes the initiator handshake.
    ///
    /// The net-new-vs-cross-connection decision is made shell-side (via the peer
    /// map), so this handler is reached only on the net-new path and maps
    /// directly to an unconditional promote — there is no sub-decision to run
    /// here. The persistent `Established` machine is created inside
    /// `promote_connection`; this machine is a transient decision vehicle that is
    /// discarded after the step, so the `set_their_index` and state write below
    /// are behaviorally inert (kept to make the transient's intent explicit and
    /// to match the established lifecycle shape).
    fn on_outbound_msg2(&mut self, their_index: SessionIndex, _now: u64) -> Vec<PeerAction> {
        self.conn.set_their_index(their_index);
        let addr = self.addr().unwrap_or_else(zero_addr);
        self.state = PeerState::Established { addr };
        // The machine survives promotion (it becomes the active peer's control
        // machine), so cancel the outbound handshake timers here or they would
        // linger in the driver's store. A late fire would no-op against the
        // non-`Handshaking` state, but leaving them armed is a timer leak.
        vec![
            PeerAction::CancelTimer {
                kind: TimerKind::HandshakeRetransmit,
            },
            PeerAction::CancelTimer {
                kind: TimerKind::HandshakeTimeout,
            },
            PeerAction::PromoteToActive { link: self.link },
        ]
    }

    /// XX inbound cross-connection at msg3. The Noise session swap and the
    /// `peers_by_index`/index surgery are shell effects; the machine emits a
    /// single plain-data trigger carrying the msg1-allocated index and the
    /// tie-break flag, and the executor reproduces `handle_msg3`'s `CrossConnect`
    /// body (register/free) verbatim. `our_inbound_wins` (larger-NodeAddr side)
    /// is already decided by the core; the machine does NOT re-run the tie-break.
    fn on_cross_connect(&mut self, peer: NodeAddr, our_inbound_wins: bool) -> Vec<PeerAction> {
        match self.conn.our_index() {
            Some(our_index) => vec![PeerAction::SwapToInboundSession {
                peer,
                our_index,
                our_inbound_wins,
            }],
            None => Vec::new(),
        }
    }

    /// XX rekey responder at msg3. The abandon-first cleanup and the
    /// `take_session`/`set_pending_session` surgery are shell effects; the machine
    /// emits a single plain-data trigger and records the dampening timestamp. On
    /// XX there is NO responder-side msg2 send here (msg2 went out at msg1), and
    /// no fresh index allocation — the msg1-allocated index becomes the pending
    /// session's index. Parks at `Maintaining{Rekey(Msg1Sent)}` awaiting the K-bit
    /// cutover (the exact responder phase/pending semantics are refined at the
    /// rekey wiring step).
    fn rekey_respond(&mut self, peer: NodeAddr, abandon_first: bool, now: u64) -> Vec<PeerAction> {
        let our_index = self.conn.our_index();
        self.rekey_our_index = our_index;
        self.last_peer_rekey_ms = now;
        let addr = self.addr().unwrap_or_else(zero_addr);
        self.state = PeerState::Maintaining {
            addr,
            kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent),
        };
        match our_index {
            Some(idx) => vec![PeerAction::RekeyRespondTrigger {
                peer,
                our_index: idx,
                abandon_first,
            }],
            None => Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // Promotion feedback
    // ------------------------------------------------------------------

    fn on_promotion_resolved(&mut self, result: PromotionResult, now: u64) -> Vec<PeerAction> {
        match result {
            PromotionResult::Promoted(addr) => {
                self.node_addr = Some(addr);
                self.crystallize(now);
                self.register_current_index()
            }
            PromotionResult::CrossConnectionWon { node_addr, .. } => {
                self.node_addr = Some(node_addr);
                self.crystallize(now);
                let mut actions = Vec::new();
                // Free + unregister the old (losing) index, register ours.
                if let Some(idx) = self.draining_index.take() {
                    actions.push(PeerAction::UnregisterDecryptSession { index: idx });
                    actions.push(PeerAction::FreeIndex { index: idx });
                }
                actions.extend(self.register_current_index());
                actions
            }
            PromotionResult::CrossConnectionLost { .. } => {
                let mut actions = Vec::new();
                if let Some(idx) = self.our_index.take() {
                    actions.push(PeerAction::FreeIndex { index: idx });
                }
                self.state = PeerState::Failed {
                    reason: FailReason::HandshakeFailed,
                };
                actions
            }
        }
    }

    fn register_current_index(&self) -> Vec<PeerAction> {
        match self.our_index {
            Some(idx) => vec![PeerAction::RegisterDecryptSession { index: idx }],
            None => Vec::new(),
        }
    }

    // ------------------------------------------------------------------
    // Rekey (initiator) + cutover
    // ------------------------------------------------------------------

    fn on_rekey_msg2(&mut self, their_index: SessionIndex) -> Vec<PeerAction> {
        // Completes our initiated rekey: a pending session is ready to cut over.
        self.conn.set_their_index(their_index);
        self.rekey_in_progress = false;
        if let PeerState::Maintaining { addr, .. } = self.state {
            self.state = PeerState::Maintaining {
                addr,
                kind: MaintainKind::Rekey(RekeyPhase::PendingCutover),
            };
        }
        // The pending peers_by_index registration is driver-side; no action here.
        Vec::new()
    }

    /// OBS: the shell ran `initiate_rekey` inline — the Noise msg1 leaf, the
    /// index allocation, the wire send, and the rekey-state set all happened
    /// shell-side. Pure observation that advances the control state to
    /// `Maintaining{Rekey(Msg1Sent)}` so the subsequent cadence `Cutover`/`Drain`
    /// consume transitions from a coherent phase. Emits NO action. No-op unless
    /// the peer is established-like.
    fn on_rekey_initiated(&mut self) -> Vec<PeerAction> {
        let addr = match self.addr() {
            Some(a) => a,
            None => return Vec::new(),
        };
        if !self.is_established_context() {
            return Vec::new();
        }
        self.rekey_in_progress = true;
        self.rekey_resend_count = 0;
        self.state = PeerState::Maintaining {
            addr,
            kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent),
        };
        Vec::new()
    }

    /// Observation: the shell resolved an outbound cross-connection inline. On a
    /// session swap it adopts the new local and remote session indices into the
    /// control shadow, mirroring the shell's in-place session replacement; on a
    /// keep it leaves the shadow untouched. Emits NO action — the crypto effect
    /// already ran shell-side.
    fn on_cross_conn_resolved(&mut self, outcome: CrossConnOutcome) -> Vec<PeerAction> {
        if let CrossConnOutcome::Swap {
            our_index,
            their_index,
        } = outcome
        {
            self.conn.set_our_index(our_index);
            self.conn.set_their_index(their_index);
        }
        Vec::new()
    }

    /// Rekey cadence: run `poll_rekey` over this one peer's snapshot and map the
    /// phase-grouped `ConnAction`s.
    fn on_rekey_cadence(&mut self, now: u64) -> Vec<PeerAction> {
        let addr = match self.addr() {
            Some(a) => a,
            None => return Vec::new(),
        };
        let cfg = RekeyCfg {
            after_secs: REKEY_AFTER_SECS,
            after_messages: REKEY_AFTER_MESSAGES,
        };
        let snap = self.peer_snapshot(addr, now);
        let mut actions = Vec::new();
        for act in Fmp::new().poll_rekey(vec![snap], &cfg) {
            actions.extend(self.map_rekey_action(act, now));
        }
        actions
    }

    fn map_rekey_action(&mut self, act: ConnAction, now: u64) -> Vec<PeerAction> {
        match act {
            ConnAction::Cutover { peer } => {
                // Initiator cutover: swap to the pending epoch, register the new
                // index, open the drain window.
                self.draining_index = self.our_index;
                self.our_index = self.rekey_our_index.take();
                self.rekey_in_progress = false;
                self.state = PeerState::Maintaining {
                    addr: peer,
                    kind: MaintainKind::Rekey(RekeyPhase::Draining),
                };
                let mut actions = vec![PeerAction::SwapSendState {
                    epoch: self.remote_epoch.unwrap_or_default(),
                }];
                if let Some(idx) = self.our_index {
                    actions.push(PeerAction::RegisterDecryptSession { index: idx });
                }
                actions.push(PeerAction::SetTimer {
                    kind: TimerKind::DrainExpiry,
                    at_ms: now + DRAIN_WINDOW_MS,
                });
                actions
            }
            ConnAction::Drain { peer } => {
                // The executor reads the real previous_our_index from
                // `ActivePeer::complete_drain` and does the peers_by_index /
                // decrypt-worker / index-free cleanup. Clear the shadow
                // `draining_index` so a leftover `Some(stale)` cannot double-free.
                self.draining_index = None;
                self.state = PeerState::Active { addr: peer };
                vec![PeerAction::CompleteDrain { peer }]
            }
            ConnAction::InitiateRekey { peer } => {
                // Fresh outbound rekey: the Noise leaf + index allocation are
                // shell-side (empty payload here), arm the resend timer.
                self.rekey_in_progress = true;
                self.rekey_resend_count = 0;
                self.rekey_msg1 = Some(Vec::new());
                self.state = PeerState::Maintaining {
                    addr: peer,
                    kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent),
                };
                vec![
                    PeerAction::SendRekey { bytes: Vec::new() },
                    PeerAction::SetTimer {
                        kind: TimerKind::RekeyResend,
                        at_ms: now + REKEY_RESEND_INTERVAL_MS,
                    },
                ]
            }
            // poll_rekey never emits the maintain/teardown-only variants.
            _ => Vec::new(),
        }
    }

    fn on_rekey_resend(&mut self, now: u64) -> Vec<PeerAction> {
        let peer = match self.addr() {
            Some(a) => a,
            None => return Vec::new(),
        };
        let snap = RekeyResendSnapshot {
            peer,
            resend_count: self.rekey_resend_count,
            needs_resend: true,
            msg1: self.rekey_msg1.clone().unwrap_or_default(),
        };
        let mut actions = Vec::new();
        for act in Fmp::new().poll_rekey_resends(
            vec![snap],
            now,
            REKEY_RESEND_INTERVAL_MS,
            RESEND_BACKOFF,
            REKEY_MAX_RESENDS,
        ) {
            match act {
                ConnAction::AbandonRekey { .. } => {
                    if let Some(idx) = self.rekey_our_index.take() {
                        actions.push(PeerAction::FreeIndex { index: idx });
                    }
                    self.rekey_in_progress = false;
                    self.rekey_msg1 = None;
                    actions.push(PeerAction::CancelTimer {
                        kind: TimerKind::RekeyResend,
                    });
                }
                ConnAction::ResendRekeyMsg1 {
                    bytes,
                    next_resend_at_ms,
                    ..
                } => {
                    self.rekey_resend_count += 1;
                    actions.push(PeerAction::SendRekey { bytes });
                    actions.push(PeerAction::SetTimer {
                        kind: TimerKind::RekeyResend,
                        at_ms: next_resend_at_ms,
                    });
                }
                _ => {}
            }
        }
        actions
    }

    // ------------------------------------------------------------------
    // Liveness
    // ------------------------------------------------------------------

    fn on_heartbeat_due(&mut self, now: u64) -> Vec<PeerAction> {
        if !self.is_active_like() {
            return Vec::new();
        }
        self.last_heartbeat_sent_ms = now;
        vec![
            PeerAction::SendLinkMessage {
                msg: vec![LinkMessageType::Heartbeat.to_byte()],
            },
            PeerAction::SetTimer {
                kind: TimerKind::Liveness,
                at_ms: now + LIVENESS_INTERVAL_MS,
            },
        ]
    }

    fn on_peer_heard(&mut self, now: u64) -> Vec<PeerAction> {
        if !self.is_active_like() {
            return Vec::new();
        }
        vec![
            PeerAction::CancelTimer {
                kind: TimerKind::Liveness,
            },
            PeerAction::SetTimer {
                kind: TimerKind::Liveness,
                at_ms: now + LIVENESS_INTERVAL_MS,
            },
        ]
    }

    fn on_link_dead(&mut self, now: u64) -> Vec<PeerAction> {
        // Guard the full established set (Established | Active | Maintaining): a
        // peer that never rekeyed stays parked in `Established`, yet the reap
        // tears down EVERY dead established peer. `InvalidateSendState` maps to
        // the shell's `remove_active_peer` (unregisters the decrypt worker by the
        // REAL current index); `ReportLost` drives `note_link_dead`. This mirrors
        // both the mmp reap and the RestartThenPromote teardown pair.
        if !self.is_established_context() {
            return Vec::new();
        }
        let mut actions = vec![
            PeerAction::InvalidateSendState,
            PeerAction::TeardownConnectedUdp,
        ];
        if let Some(peer) = self.addr() {
            // An established peer whose link died — the unconditional reconnect
            // reflex (the live liveness-reap producer).
            actions.push(PeerAction::ReportLost {
                peer,
                kind: LostKind::LinkDead,
            });
        }
        self.state = PeerState::Closed {
            backoff_deadline_ms: now + CLOSED_BACKOFF_MS,
        };
        actions
    }

    // ------------------------------------------------------------------
    // Timeout / teardown / close
    // ------------------------------------------------------------------

    fn on_timeout(&mut self, kind: TimerKind, now: u64) -> Vec<PeerAction> {
        match kind {
            TimerKind::HandshakeRetransmit => self.on_handshake_retransmit(now),
            TimerKind::HandshakeTimeout => self.on_handshake_timeout(now),
            TimerKind::RekeyCadence => self.on_rekey_cadence(now),
            TimerKind::RekeyResend => self.on_rekey_resend(now),
            // XX-only rekey msg3 retransmission; its driving arm lands at the
            // rekey step.
            TimerKind::RekeyMsg3Resend => Vec::new(),
            TimerKind::DrainExpiry => self.on_rekey_cadence(now),
            TimerKind::Liveness => Vec::new(),
        }
    }

    fn on_handshake_retransmit(&mut self, now: u64) -> Vec<PeerAction> {
        if !matches!(
            self.state,
            PeerState::Handshaking {
                phase: HandshakePhase::SentMsg1,
                ..
            }
        ) {
            return Vec::new();
        }
        let snap = self.conn_snapshot();
        let mut actions = Vec::new();
        for act in Fmp::new().poll_resends(
            vec![snap],
            now,
            HANDSHAKE_RETRANSMIT_INTERVAL_MS,
            RESEND_BACKOFF,
        ) {
            if let ConnAction::ResendMsg1 {
                bytes,
                next_resend_at_ms,
                ..
            } = act
            {
                self.conn.record_resend(next_resend_at_ms);
                actions.push(PeerAction::SendHandshake { bytes });
                actions.push(PeerAction::SetTimer {
                    kind: TimerKind::HandshakeRetransmit,
                    at_ms: next_resend_at_ms,
                });
            }
        }
        actions
    }

    fn on_handshake_timeout(&mut self, now: u64) -> Vec<PeerAction> {
        if !matches!(self.state, PeerState::Handshaking { .. }) {
            return Vec::new();
        }
        let snap = self.conn_snapshot();
        // poll_timeouts emits [ScheduleRetry?, Teardown]; the machine REMAPS
        // ScheduleRetry -> ReportLost (single loss token) and Teardown ->
        // FreeIndex{our_index}, emitting FreeIndex before ReportLost.
        let mut free = Vec::new();
        let mut lost = Vec::new();
        for act in Fmp::new().poll_timeouts(vec![snap]) {
            match act {
                ConnAction::ScheduleRetry { peer } => {
                    // Handshake timeout on an un-promoted leg — the connected-
                    // guarded reflex. Dormant today (no `Timeout` event is
                    // dispatched until the timeout fold in C5).
                    lost.push(PeerAction::ReportLost {
                        peer,
                        kind: LostKind::HandshakeTimeout,
                    });
                }
                ConnAction::Teardown { .. } => {
                    if let Some(idx) = self.conn.our_index() {
                        free.push(PeerAction::FreeIndex { index: idx });
                    }
                }
                _ => {}
            }
        }
        self.state = PeerState::Closed {
            backoff_deadline_ms: now + CLOSED_BACKOFF_MS,
        };
        free.extend(lost);
        free
    }

    fn on_disconnect(&mut self, reason: CloseReason, now: u64) -> Vec<PeerAction> {
        if !self.is_active_like() && !matches!(self.state, PeerState::Established { .. }) {
            return Vec::new();
        }
        let addr = self.addr();
        self.state = PeerState::Closing {
            addr: addr.unwrap_or_else(zero_addr),
            reason,
        };
        let mut actions = vec![PeerAction::SendLinkMessage {
            msg: disconnect_frame(reason),
        }];
        actions.push(PeerAction::InvalidateSendState);
        if let Some(idx) = self.our_index.take() {
            actions.push(PeerAction::UnregisterDecryptSession { index: idx });
        }
        actions.push(PeerAction::TeardownConnectedUdp);
        // No ReportLost on operator Requested.
        self.state = PeerState::Closed {
            backoff_deadline_ms: now + CLOSED_BACKOFF_MS,
        };
        actions
    }

    fn on_tick(&mut self, now: u64) -> Vec<PeerAction> {
        // Dormant no-op: `PeerEvent::Tick` is not dispatched in production.
        // The shell drivers evaluate due timer deadlines themselves, so there
        // is no machine-side bookkeeping to advance here.
        let _ = now;
        Vec::new()
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    fn crystallize(&mut self, now: u64) {
        let addr = self.addr().unwrap_or_else(zero_addr);
        self.session_established_at_ms = now;
        self.authenticated_at_ms = now;
        self.state = PeerState::Established { addr };
    }

    fn fail(&mut self, reason: FailReason) -> Vec<PeerAction> {
        self.state = PeerState::Failed { reason };
        Vec::new()
    }

    fn is_active_like(&self) -> bool {
        matches!(
            self.state,
            PeerState::Active { .. } | PeerState::Maintaining { .. }
        )
    }

    fn is_established_context(&self) -> bool {
        matches!(
            self.state,
            PeerState::Established { .. }
                | PeerState::Active { .. }
                | PeerState::Maintaining { .. }
        )
    }

    fn conn_snapshot(&self) -> ConnSnapshot {
        ConnSnapshot {
            link: self.conn.link_id(),
            is_outbound: self.conn.is_outbound(),
            retry_addr: self.conn.expected_identity().map(|id| *id.node_addr()),
            resend_count: self.conn.resend_count(),
            msg1: self
                .conn
                .handshake_msg1()
                .map(|b| b.to_vec())
                .unwrap_or_default(),
        }
    }

    /// Build this peer's rekey snapshot from control-tier state. `counter` is a
    /// send-state fact; passed as 0 here (see module note). `rekey_msg3_pending`
    /// is sourced from the control field (default `false`; real wiring when the
    /// rekey path is wired).
    fn peer_snapshot(&self, addr: NodeAddr, now: u64) -> PeerSnapshot {
        let phase = match self.state {
            PeerState::Maintaining {
                kind: MaintainKind::Rekey(p),
                ..
            } => Some(p),
            _ => None,
        };
        let elapsed_secs = now.saturating_sub(self.session_established_at_ms) / 1000;
        PeerSnapshot {
            addr,
            has_pending: phase == Some(RekeyPhase::PendingCutover),
            rekey_in_progress: phase == Some(RekeyPhase::Msg1Sent) || self.rekey_in_progress,
            is_draining: phase == Some(RekeyPhase::Draining),
            drain_expired: phase == Some(RekeyPhase::Draining),
            is_dampened: now.saturating_sub(self.last_peer_rekey_ms) < REKEY_DAMPEN_MS
                && self.last_peer_rekey_ms != 0,
            rekey_msg3_pending: self.rekey_msg3_pending,
            elapsed_secs,
            counter: 0,
            jitter_secs: self.rekey_jitter_secs,
        }
    }
}

fn zero_addr() -> NodeAddr {
    NodeAddr::from_bytes([0u8; 16])
}

/// Build the plaintext disconnect frame the driver encrypts + sends.
fn disconnect_frame(reason: CloseReason) -> Vec<u8> {
    use crate::proto::fmp::{Disconnect, DisconnectReason};
    let wire_reason = match reason {
        CloseReason::Requested => DisconnectReason::Shutdown,
        CloseReason::Draining => DisconnectReason::Restart,
    };
    Disconnect::new(wire_reason).encode().to_vec()
}

// ============================================================================
// Unit tests — assert on ACTION SEQUENCES + STATE transitions using hand-built
// synthetic snapshots (no real crypto sessions).
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::fmp::PromotionResult;
    use crate::{Identity, PeerIdentity};

    fn peer_identity() -> PeerIdentity {
        PeerIdentity::from_pubkey(Identity::generate().pubkey())
    }

    /// Two identities with a known NodeAddr ordering: `.0` < `.1`.
    fn ordered_identities() -> (PeerIdentity, PeerIdentity) {
        loop {
            let a = peer_identity();
            let b = peer_identity();
            if a.node_addr() < b.node_addr() {
                return (a, b);
            }
            if b.node_addr() < a.node_addr() {
                return (b, a);
            }
        }
    }

    /// XX `WireOutcome`: node address + epoch only (identity crystallizes at msg3).
    fn wire_outcome(peer: NodeAddr, epoch: Option<[u8; 8]>) -> WireOutcome {
        WireOutcome {
            peer_node_addr: peer,
            remote_epoch: epoch,
        }
    }

    /// XX `EstablishSnapshot` for a net-new inbound (no existing peer). The
    /// dual-init / cross-connection tests flip the existing-peer fields.
    fn est_new_peer(our: NodeAddr) -> EstablishSnapshot {
        EstablishSnapshot {
            has_existing_peer: false,
            existing_peer_epoch: None,
            existing_session_age_secs: 0,
            has_session: false,
            is_healthy: false,
            pending_new_session: false,
            rekey_in_progress: false,
            existing_msg2: None,
            different_link: false,
            rekey_enabled: true,
            rekey_age_floor_secs: 60,
            our_node_addr: our,
        }
    }

    // ---- Test 0: established constructor --------------
    #[test]
    fn established_constructor_yields_established_context() {
        let id = peer_identity();
        let addr = *id.node_addr();
        let idx = SessionIndex::new(0x4242);
        let m = PeerMachine::established(
            LinkId::new(7),
            id,
            idx,
            /* is_outbound */ true,
            None,
            1_234,
        );

        // Parked at Established with the crystallized address + index visible,
        // so a later reap's `is_established_context` and a later rekey both
        // find it.
        assert_eq!(m.state(), PeerState::Established { addr });
        assert!(m.is_established_context());
        assert_eq!(m.addr(), Some(addr));
        assert_eq!(m.our_index(), Some(idx));
    }

    // ---- Test: net-new outbound promote at msg2 ---------------------------
    #[test]
    fn outbound_msg2_promotes_net_new() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let link = LinkId::new(3);
        let mut m = PeerMachine::new_outbound(link, id, 0);
        let their_index = SessionIndex::new(0x77);

        let actions = m.step(PeerEvent::OutboundMsg2 { their_index }, 0, &mut alloc);

        assert_eq!(
            actions,
            vec![
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeRetransmit
                },
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeTimeout
                },
                PeerAction::PromoteToActive { link },
            ]
        );
        assert_eq!(m.state(), PeerState::Established { addr });
    }

    // ---- Test: outbound promote at msg2 cancels handshake timers -----------
    // The promoted machine survives as the active peer's control machine, so
    // its outbound handshake retransmit + timeout timers must be cancelled at
    // promotion or they linger in the driver's store. The promote must emit the
    // two CancelTimer actions ahead of PromoteToActive, in that exact order.
    #[test]
    fn outbound_msg2_promote_cancels_handshake_timers() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let link = LinkId::new(4);
        let mut m = PeerMachine::new_outbound(link, id, 0);
        let their_index = SessionIndex::new(0x88);

        let actions = m.step(PeerEvent::OutboundMsg2 { their_index }, 0, &mut alloc);

        assert_eq!(
            actions,
            vec![
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeRetransmit
                },
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeTimeout
                },
                PeerAction::PromoteToActive { link },
            ]
        );
    }

    // ---- Contract: actions are runtime-agnostic data ----------------------
    //
    // The machine's emitted actions are the message contract between the sync
    // decision core and the async driver. This proves the contract carries no
    // runtime handles: the action type is Send + Sync + 'static (so it can move
    // across a task boundary), and every variant round-trips unchanged through
    // an async channel. Were a variant to embed a runtime handle (a task handle,
    // a raw socket, an Arc<Runtime>), it would stop being plain owned data and
    // this construction + equality round-trip would no longer hold.

    /// Compile-time proof that the action contract crosses task boundaries as
    /// owned, runtime-agnostic data. Fails to compile if any variant field is
    /// not `Send + Sync + 'static`.
    fn assert_contract_bound<T: Send + Sync + 'static>() {}

    /// One value of every [`PeerAction`] variant. The wildcard-free match makes
    /// a newly-added variant a compile error, forcing it through this contract.
    fn all_actions() -> Vec<PeerAction> {
        let peer = *peer_identity().node_addr();
        let sample = vec![
            PeerAction::OpenTransport {
                transport_id: TransportId::new(1),
                remote_addr: TransportAddr::from_string("127.0.0.1:9999"),
            },
            PeerAction::SendHandshake {
                bytes: vec![1, 2, 3],
            },
            PeerAction::SendRekey {
                bytes: vec![4, 5, 6],
            },
            PeerAction::SendLinkMessage { msg: vec![7, 8, 9] },
            PeerAction::PromoteToActive {
                link: LinkId::new(7),
            },
            PeerAction::SwapSendState { epoch: [1u8; 8] },
            PeerAction::CompleteDrain { peer },
            PeerAction::InvalidateSendState,
            PeerAction::RegisterDecryptSession {
                index: SessionIndex::new(5),
            },
            PeerAction::UnregisterDecryptSession {
                index: SessionIndex::new(6),
            },
            PeerAction::FreeIndex {
                index: SessionIndex::new(7),
            },
            PeerAction::ActivateConnectedUdp,
            PeerAction::TeardownConnectedUdp,
            PeerAction::SetTimer {
                kind: TimerKind::RekeyCadence,
                at_ms: 1234,
            },
            PeerAction::CancelTimer {
                kind: TimerKind::Liveness,
            },
            PeerAction::ReportLost {
                peer,
                kind: LostKind::LinkDead,
            },
            PeerAction::SwapToInboundSession {
                peer,
                our_index: SessionIndex::new(8),
                our_inbound_wins: true,
            },
            PeerAction::RekeyRespondTrigger {
                peer,
                our_index: SessionIndex::new(9),
                abandon_first: false,
            },
        ];
        for a in &sample {
            // Exhaustiveness guard: no `_` wildcard, so adding a variant without
            // extending `sample` above breaks the build here.
            match a {
                PeerAction::OpenTransport { .. }
                | PeerAction::SendHandshake { .. }
                | PeerAction::SendRekey { .. }
                | PeerAction::SendLinkMessage { .. }
                | PeerAction::PromoteToActive { .. }
                | PeerAction::SwapSendState { .. }
                | PeerAction::CompleteDrain { .. }
                | PeerAction::InvalidateSendState
                | PeerAction::RegisterDecryptSession { .. }
                | PeerAction::UnregisterDecryptSession { .. }
                | PeerAction::FreeIndex { .. }
                | PeerAction::ActivateConnectedUdp
                | PeerAction::TeardownConnectedUdp
                | PeerAction::SetTimer { .. }
                | PeerAction::CancelTimer { .. }
                | PeerAction::ReportLost { .. }
                | PeerAction::SwapToInboundSession { .. }
                | PeerAction::RekeyRespondTrigger { .. } => {}
            }
        }
        sample
    }

    /// Route every action through a single-threaded async channel and assert it
    /// arrives unchanged. `#[tokio::test]` runs on a current-thread runtime, so
    /// sender and receiver share one thread — mirroring the eventual control
    /// task boundary where actions cross to the driver over a channel.
    #[tokio::test]
    async fn peer_actions_round_trip_through_async_channel() {
        assert_contract_bound::<PeerAction>();

        let sent = all_actions();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PeerAction>();
        for action in sent.iter().cloned() {
            tx.send(action).expect("channel send");
        }
        drop(tx);

        let mut received = Vec::new();
        while let Some(action) = rx.recv().await {
            received.push(action);
        }
        assert_eq!(received, sent, "every action must round-trip unchanged");
    }

    // ---- Test 1: rekey initiator cutover ----------------------------------
    #[test]
    fn rekey_initiator_cutover() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), id, 0);
        // Arrange: a completed rekey pending cutover.
        m.state = PeerState::Maintaining {
            addr,
            kind: MaintainKind::Rekey(RekeyPhase::PendingCutover),
        };
        m.rekey_our_index = Some(SessionIndex::new(0x2222));
        m.our_index = Some(SessionIndex::new(0x1111));
        m.remote_epoch = Some([9u8; 8]);
        m.session_established_at_ms = 0;

        let actions = m.step(
            PeerEvent::Timeout {
                kind: TimerKind::RekeyCadence,
            },
            10_000,
            &mut alloc,
        );

        assert_eq!(
            actions,
            vec![
                PeerAction::SwapSendState { epoch: [9u8; 8] },
                PeerAction::RegisterDecryptSession {
                    index: SessionIndex::new(0x2222)
                },
                PeerAction::SetTimer {
                    kind: TimerKind::DrainExpiry,
                    at_ms: 10_000 + DRAIN_WINDOW_MS
                },
            ]
        );
        assert_eq!(
            m.state(),
            PeerState::Maintaining {
                addr,
                kind: MaintainKind::Rekey(RekeyPhase::Draining)
            }
        );

        // A second cadence tick from the (expired) drain window completes the
        // drain: a single `CompleteDrain` send-state write.
        let drain_actions = m.step(
            PeerEvent::Timeout {
                kind: TimerKind::RekeyCadence,
            },
            20_000,
            &mut alloc,
        );
        assert_eq!(
            drain_actions,
            vec![PeerAction::CompleteDrain { peer: addr }]
        );
        assert_eq!(m.state(), PeerState::Active { addr });
    }

    // ---- Test 2: responder cutover (data-plane owned) ---------------------
    #[test]
    fn responder_cutover_only_sets_drain_timer() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), id, 0);
        m.state = PeerState::Active { addr };

        let actions = m.step(
            PeerEvent::PeerKbitFlip { epoch: [7u8; 8] },
            5_000,
            &mut alloc,
        );

        // ONLY the drain timer — no SwapSendState, no slot mutation.
        assert_eq!(
            actions,
            vec![PeerAction::SetTimer {
                kind: TimerKind::DrainExpiry,
                at_ms: 5_000 + DRAIN_WINDOW_MS
            }]
        );
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, PeerAction::SwapSendState { .. }))
        );
        assert_eq!(m.state(), PeerState::Active { addr });
    }

    // ---- Test 3: dual-init tie-break at msg3, swapped addrs ---------------
    #[test]
    fn dual_init_tiebreak_swapped_addrs() {
        let (smaller, larger) = ordered_identities();

        // Case A: WE are smaller -> we win -> Reject{DualRekeyWon} -> drop, keep.
        {
            let mut alloc = IndexAllocator::new();
            let our = *smaller.node_addr();
            let peer = larger;
            let mut m = PeerMachine::new_outbound(LinkId::new(1), peer, 0);
            let peer_addr = *peer.node_addr();
            m.state = PeerState::Maintaining {
                addr: peer_addr,
                kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent),
            };
            m.rekey_in_progress = true;
            m.conn.set_our_index(SessionIndex::new(0x55));
            m.our_index = Some(SessionIndex::new(0x55));
            let mut est = est_new_peer(our);
            est.has_existing_peer = true;
            est.existing_peer_epoch = Some([1u8; 8]);
            est.has_session = true;
            est.is_healthy = true;
            est.existing_session_age_secs = 120; // >= floor -> rekey path
            est.rekey_in_progress = true;
            let wire = wire_outcome(peer_addr, Some([1u8; 8]));

            let actions = m.step(
                PeerEvent::InboundMsg3 {
                    wire,
                    est,
                    our_index: SessionIndex::new(0x55),
                },
                1_000,
                &mut alloc,
            );
            // We win the tie-break: drop the peer's msg3 and return the
            // msg1-allocated index, then terminate this leg.
            assert_eq!(
                actions,
                vec![PeerAction::FreeIndex {
                    index: SessionIndex::new(0x55)
                }]
            );
            assert_eq!(
                m.state(),
                PeerState::Failed {
                    reason: FailReason::Rejected
                }
            );
        }

        // Case B: PEER is smaller -> we lose -> RekeyRespond{abandon_first:true}.
        {
            let mut alloc = IndexAllocator::new();
            let our = *larger.node_addr();
            let peer = smaller;
            let mut m = PeerMachine::new_outbound(LinkId::new(2), peer, 0);
            let peer_addr = *peer.node_addr();
            m.state = PeerState::Maintaining {
                addr: peer_addr,
                kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent),
            };
            m.rekey_in_progress = true;
            m.conn.set_our_index(SessionIndex::new(0x55));
            m.our_index = Some(SessionIndex::new(0x55));
            let mut est = est_new_peer(our);
            est.has_existing_peer = true;
            est.existing_peer_epoch = Some([1u8; 8]);
            est.has_session = true;
            est.is_healthy = true;
            est.existing_session_age_secs = 120;
            est.rekey_in_progress = true;
            let wire = wire_outcome(peer_addr, Some([1u8; 8]));

            let actions = m.step(
                PeerEvent::InboundMsg3 {
                    wire,
                    est,
                    our_index: SessionIndex::new(0x55),
                },
                1_000,
                &mut alloc,
            );
            // We lose: emit the rekey-respond trigger with abandon_first=true and
            // the msg1-allocated index. The session/registry surgery is the
            // executor's; the machine emits ONLY the plain-data trigger (no
            // SendRekey on XX).
            assert_eq!(
                actions,
                vec![PeerAction::RekeyRespondTrigger {
                    peer: peer_addr,
                    our_index: SessionIndex::new(0x55),
                    abandon_first: true,
                }]
            );
        }
    }

    // ---- Test 4: restart-override (epoch mismatch at msg3) ----------------
    #[test]
    fn restart_override() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let mut m = PeerMachine::new_inbound(LinkId::new(1), 0);

        // msg1: allocate our index, send msg2, park at SentMsg2.
        let msg1 = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
            },
            1_000,
            &mut alloc,
        );
        assert!(
            msg1.iter()
                .any(|a| matches!(a, PeerAction::SendHandshake { .. }))
        );
        assert_eq!(alloc.count(), 1);
        assert!(matches!(
            m.state(),
            PeerState::Handshaking {
                phase: HandshakePhase::SentMsg2,
                ..
            }
        ));

        // msg3: existing peer at a different epoch -> restart-then-promote.
        let our = *peer_identity().node_addr();
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([1u8; 8]); // old
        let wire = wire_outcome(peer_addr, Some([2u8; 8])); // new epoch

        let our_index = m.our_index().unwrap();
        let actions = m.step(
            PeerEvent::InboundMsg3 {
                wire,
                est,
                our_index,
            },
            1_000,
            &mut alloc,
        );
        assert_eq!(
            actions,
            vec![
                PeerAction::InvalidateSendState,
                PeerAction::ReportLost {
                    peer: peer_addr,
                    kind: LostKind::LinkDead,
                },
                PeerAction::PromoteToActive {
                    link: LinkId::new(1)
                },
            ]
        );

        // Promotion feedback -> Established + register the msg1-allocated index.
        let follow = m.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::Promoted(peer_addr),
            },
            1_000,
            &mut alloc,
        );
        assert!(
            follow
                .iter()
                .any(|a| matches!(a, PeerAction::RegisterDecryptSession { .. }))
        );
        assert_eq!(m.state(), PeerState::Established { addr: peer_addr });
    }

    // ---- Test 5: N:1 crystallization --------------------------------------
    #[test]
    fn n_to_one_crystallization() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let our = *peer_identity().node_addr();

        // Winner leg (link 1): net-new inbound promote -> Established.
        let mut winner = PeerMachine::new_inbound(LinkId::new(1), 0);
        let _ = winner.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
            },
            100,
            &mut alloc,
        );
        let winner_index = winner.our_index().unwrap();
        let wp = winner.step(
            PeerEvent::InboundMsg3 {
                wire: wire_outcome(peer_addr, Some([3u8; 8])),
                est: est_new_peer(our),
                our_index: winner_index,
            },
            100,
            &mut alloc,
        );
        assert_eq!(
            wp,
            vec![PeerAction::PromoteToActive {
                link: LinkId::new(1)
            }]
        );
        let wf = winner.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::Promoted(peer_addr),
            },
            100,
            &mut alloc,
        );
        assert!(
            wf.iter()
                .any(|a| matches!(a, PeerAction::RegisterDecryptSession { .. }))
        );
        assert_eq!(winner.state(), PeerState::Established { addr: peer_addr });

        // Loser leg (link 2): same identity, loses cross-connection at
        // promote_connection -> Failed + FreeIndex.
        let mut loser = PeerMachine::new_inbound(LinkId::new(2), 0);
        let _ = loser.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(2),
            },
            100,
            &mut alloc,
        );
        let loser_index_seed = loser.our_index().unwrap();
        let lp = loser.step(
            PeerEvent::InboundMsg3 {
                wire: wire_outcome(peer_addr, Some([3u8; 8])),
                est: est_new_peer(our),
                our_index: loser_index_seed,
            },
            100,
            &mut alloc,
        );
        assert_eq!(
            lp,
            vec![PeerAction::PromoteToActive {
                link: LinkId::new(2)
            }]
        );
        let loser_index = loser.our_index();
        let lf = loser.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::CrossConnectionLost {
                    winner_link_id: LinkId::new(1),
                },
            },
            100,
            &mut alloc,
        );
        assert_eq!(
            lf,
            vec![PeerAction::FreeIndex {
                index: loser_index.unwrap()
            }]
        );
        assert_eq!(
            loser.state(),
            PeerState::Failed {
                reason: FailReason::HandshakeFailed
            }
        );
    }

    // ---- Test 6: inbound establish (msg1 alloc -> msg3 classify) ----------
    #[test]
    fn inbound_establish() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let mut m = PeerMachine::new_inbound(LinkId::new(1), 0);
        assert_eq!(
            m.state(),
            PeerState::Handshaking {
                link: LinkId::new(1),
                phase: HandshakePhase::Initial
            }
        );

        // msg1: allocate our index + send msg2, park at SentMsg2.
        let msg1 = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
            },
            200,
            &mut alloc,
        );
        assert!(matches!(msg1[0], PeerAction::SendHandshake { .. }));
        assert_eq!(
            m.state(),
            PeerState::Handshaking {
                link: LinkId::new(1),
                phase: HandshakePhase::SentMsg2
            }
        );
        assert!(m.our_index().is_some());
        assert_eq!(alloc.count(), 1); // exactly one index allocated at msg1

        // msg3: net-new promote.
        let our = *peer_identity().node_addr();
        let our_index = m.our_index().unwrap();
        let msg3 = m.step(
            PeerEvent::InboundMsg3 {
                wire: wire_outcome(peer_addr, Some([4u8; 8])),
                est: est_new_peer(our),
                our_index,
            },
            200,
            &mut alloc,
        );
        assert_eq!(
            msg3,
            vec![PeerAction::PromoteToActive {
                link: LinkId::new(1)
            }]
        );

        // PromotionResolved{Promoted}: register + Established.
        let follow = m.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::Promoted(peer_addr),
            },
            200,
            &mut alloc,
        );
        assert!(matches!(
            follow[0],
            PeerAction::RegisterDecryptSession { .. }
        ));
        assert_eq!(m.state(), PeerState::Established { addr: peer_addr });
    }

    // ---- Test 6b: inbound msg1 allocate-failure -> no promote -------------
    #[test]
    fn inbound_msg1_alloc_failure() {
        // Force allocation failure: zero attempts -> `allocate` returns
        // `Err(Exhausted)` immediately (the allocator is a random-index pool, not
        // a small bounded range, so it cannot be drained by repeated calls).
        let mut alloc = IndexAllocator::with_max_attempts(0);

        let mut m = PeerMachine::new_inbound(LinkId::new(1), 0);
        let actions = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
            },
            200,
            &mut alloc,
        );
        assert!(actions.is_empty());
        assert_eq!(
            m.state(),
            PeerState::Failed {
                reason: FailReason::Rejected
            }
        );
        assert_eq!(m.our_index(), None);
        assert_eq!(alloc.count(), 0); // no allocation happened
    }

    // ---- Test 7: inbound cross-connection at msg3 (XX-only arm) -----------
    #[test]
    fn cross_connect_at_msg3() {
        // We are the LARGER node -> our inbound wins (our_node_addr >= peer).
        let (smaller, larger) = ordered_identities();
        let our = *larger.node_addr();
        let peer_addr = *smaller.node_addr();

        let mut alloc = IndexAllocator::new();
        let mut m = PeerMachine::new_inbound(LinkId::new(2), 0);
        let _ = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(2),
            },
            100,
            &mut alloc,
        );
        let our_index = m.our_index().unwrap();

        // Existing peer, same epoch, different link, session younger than the
        // rekey floor -> CrossConnect.
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([5u8; 8]);
        est.has_session = true;
        est.is_healthy = true;
        est.different_link = true;
        est.existing_session_age_secs = 10; // < floor(60) -> cross-connection
        let wire = wire_outcome(peer_addr, Some([5u8; 8]));

        let actions = m.step(
            PeerEvent::InboundMsg3 {
                wire,
                est,
                our_index,
            },
            200,
            &mut alloc,
        );
        assert_eq!(
            actions,
            vec![PeerAction::SwapToInboundSession {
                peer: peer_addr,
                our_index,
                our_inbound_wins: true,
            }]
        );
    }

    // ---- Test 7a: cross-connection index seeded ONLY from the event -------
    // A fresh classification machine (no msg1 step, so `conn.our_index()` is
    // None) must still emit a NON-EMPTY `SwapToInboundSession` carrying the index
    // carried on the event. Without the event-seed the cross-connection arm reads
    // a None index and emits nothing — a silent session-swap no-op that leaks the
    // index. This guards that the seed closes that hole.
    #[test]
    fn cross_connect_index_seeded_from_event() {
        let (smaller, larger) = ordered_identities();
        let our = *larger.node_addr();
        let peer_addr = *smaller.node_addr();

        let mut alloc = IndexAllocator::new();
        // Fresh machine, deliberately NOT stepped through msg1 — the only index
        // provenance is the event field.
        let mut m = PeerMachine::new_inbound(LinkId::new(3), 0);
        assert_eq!(m.our_index(), None);
        let seed = SessionIndex::new(0xAB);

        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([5u8; 8]);
        est.has_session = true;
        est.is_healthy = true;
        est.different_link = true;
        est.existing_session_age_secs = 10; // < floor(60) -> cross-connection
        let wire = wire_outcome(peer_addr, Some([5u8; 8]));

        let actions = m.step(
            PeerEvent::InboundMsg3 {
                wire,
                est,
                our_index: seed,
            },
            200,
            &mut alloc,
        );
        assert_eq!(
            actions,
            vec![PeerAction::SwapToInboundSession {
                peer: peer_addr,
                our_index: seed,
                our_inbound_wins: true,
            }]
        );
    }

    // ---- Test 7d: rekey-responder index seeded ONLY from the event -------
    // The rekey-responder counterpart of Test 7a: a fresh machine seeded only via
    // the event emits a NON-EMPTY `RekeyRespondTrigger` carrying that index (the
    // pending session's index), rather than the empty no-op an unseeded index
    // would produce.
    #[test]
    fn rekey_respond_index_seeded_from_event() {
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let our = *peer_identity().node_addr();

        let mut alloc = IndexAllocator::new();
        let mut m = PeerMachine::new_inbound(LinkId::new(4), 0);
        assert_eq!(m.our_index(), None);
        let seed = SessionIndex::new(0xCD);

        // Aged, healthy session, same epoch, same link, no rekey in progress ->
        // plain rekey responder (abandon_first: false).
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([7u8; 8]);
        est.has_session = true;
        est.is_healthy = true;
        est.existing_session_age_secs = 120; // >= floor -> rekey path
        let wire = wire_outcome(peer_addr, Some([7u8; 8]));

        let actions = m.step(
            PeerEvent::InboundMsg3 {
                wire,
                est,
                our_index: seed,
            },
            200,
            &mut alloc,
        );
        assert_eq!(
            actions,
            vec![PeerAction::RekeyRespondTrigger {
                peer: peer_addr,
                our_index: seed,
                abandon_first: false,
            }]
        );
    }

    // ---- Test 7e: same-epoch duplicate frees the index and terminates -----
    // A same-epoch duplicate handshake (no cross-connection, no rekey) resends the
    // stored msg2, returns the msg1-allocated index, and terminates the leg. The
    // terminal transition matters: a persistent machine parked here would keep its
    // handshake-timeout armed and later free the index + report loss against the
    // healthy established peer.
    #[test]
    fn resend_msg2_frees_index_and_terminates() {
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let our = *peer_identity().node_addr();

        let mut alloc = IndexAllocator::new();
        let mut m = PeerMachine::new_inbound(LinkId::new(5), 0);
        let seed = SessionIndex::new(0xEF);
        let stored_msg2 = vec![1u8, 2, 3, 4];

        // Same epoch, same link, rekey disabled -> duplicate handshake.
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([9u8; 8]);
        est.rekey_enabled = false;
        est.existing_msg2 = Some(stored_msg2.clone());
        let wire = wire_outcome(peer_addr, Some([9u8; 8]));

        let actions = m.step(
            PeerEvent::InboundMsg3 {
                wire,
                est,
                our_index: seed,
            },
            200,
            &mut alloc,
        );
        assert_eq!(
            actions,
            vec![
                PeerAction::SendHandshake { bytes: stored_msg2 },
                PeerAction::FreeIndex { index: seed },
            ]
        );
        assert_eq!(
            m.state(),
            PeerState::Failed {
                reason: FailReason::Rejected
            }
        );
    }

    // ---- Test 7b: dial-persisted outbound promote leaves our_index unset ---
    // An outbound machine persisted at DIAL (`new_outbound`, `Discovered`, with
    // `conn.our_index` UNSET — the shell owns the index on its own
    // `PeerConnection`, never on the machine) must, on promote via msg2, end with
    // `our_index == None`, exactly as the pre-persistence transient did. The
    // guard: a subsequent inbound restart then emits NO
    // `UnregisterDecryptSession` (contrast `restart_override`, whose machine has
    // `our_index == Some`). A leaked `Some(dial_index)` here would wrongly
    // unregister — on index reuse, ANOTHER peer's — worker session; keeping the
    // field `None` is the Model-B dial-persistence neutrality property.
    #[test]
    fn dial_persisted_outbound_promote_no_restart_unregister() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let our = *peer_identity().node_addr();

        // Persisted at dial: Discovered, conn.our_index deliberately NOT set.
        let mut m = PeerMachine::new_outbound(LinkId::new(1), peer, 0);
        assert_eq!(m.our_index(), None);

        // Promote via msg2 from Discovered (the production path — the former
        // transient was likewise stepped from `new_outbound` without a state set).
        let promote = m.step(
            PeerEvent::OutboundMsg2 {
                their_index: SessionIndex::new(0x77),
            },
            300,
            &mut alloc,
        );
        assert_eq!(
            promote,
            vec![
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeRetransmit
                },
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeTimeout
                },
                PeerAction::PromoteToActive {
                    link: LinkId::new(1)
                }
            ]
        );
        assert_eq!(
            m.our_index(),
            None,
            "outbound promote must leave our_index unset"
        );

        // Drive promotion to Established (from Discovered, as in production).
        let _ = m.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::Promoted(peer_addr),
            },
            300,
            &mut alloc,
        );
        assert_eq!(m.state(), PeerState::Established { addr: peer_addr });
        assert_eq!(m.our_index(), None);

        // A subsequent inbound restart (peer restart, new epoch) must NOT emit a
        // separate UnregisterDecryptSession: the restart teardown is the full
        // InvalidateSendState (remove_active_peer), which owns the index cleanup.
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([1u8; 8]);
        let wire = wire_outcome(peer_addr, Some([2u8; 8]));
        let restart = m.step(
            PeerEvent::InboundMsg3 {
                wire,
                est,
                our_index: SessionIndex::new(0x99),
            },
            1_000,
            &mut alloc,
        );
        assert!(
            !restart
                .iter()
                .any(|a| matches!(a, PeerAction::UnregisterDecryptSession { .. })),
            "no UnregisterDecryptSession when the promoted outbound machine's our_index is None"
        );
        assert!(
            restart.iter().any(|a| matches!(
                a,
                PeerAction::ReportLost {
                    kind: LostKind::LinkDead,
                    ..
                }
            )),
            "restart still reports the loss via the link-dead reconnect reflex"
        );
    }

    // ---- Test 7c: connectionless dial reaches Handshaking, Msg2 neutral ----
    // The connectionless cutover drives the outbound machine
    // Discovered -> (Dial, connection_oriented=false) -> Handshaking{SentMsg1}
    // BEFORE msg2, whereas the pre-cutover path stepped Msg2 while still in
    // Discovered. `on_msg2` is state-independent, so both must yield the
    // identical `[PromoteToActive]` and leave `our_index == None`.
    #[test]
    fn connectionless_dial_then_msg2_promotes_from_handshaking() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();

        let mut m = PeerMachine::new_outbound(LinkId::new(1), peer, 0);
        // Connectionless dial: no OpenTransport, straight to Handshaking{SentMsg1}.
        let dial = m.step(
            PeerEvent::Dial {
                transport_id: TransportId::new(1),
                remote_addr: TransportAddr::from_string("127.0.0.1:9999"),
                peer_identity: peer,
                connection_oriented: false,
            },
            100,
            &mut alloc,
        );
        assert!(matches!(
            m.state(),
            PeerState::Handshaking {
                phase: HandshakePhase::SentMsg1,
                ..
            }
        ));
        assert!(
            dial.iter()
                .any(|a| matches!(a, PeerAction::SendHandshake { .. }))
        );
        assert!(
            !dial
                .iter()
                .any(|a| matches!(a, PeerAction::OpenTransport { .. })),
            "connectionless dial emits no OpenTransport"
        );

        // Step Msg2 from Handshaking — identical promote to the Discovered path.
        let promote = m.step(
            PeerEvent::OutboundMsg2 {
                their_index: SessionIndex::new(0x77),
            },
            200,
            &mut alloc,
        );
        assert_eq!(
            promote,
            vec![
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeRetransmit
                },
                PeerAction::CancelTimer {
                    kind: TimerKind::HandshakeTimeout
                },
                PeerAction::PromoteToActive {
                    link: LinkId::new(1)
                }
            ]
        );
        assert_eq!(m.our_index(), None);
    }

    // ---- Test 7d: connection-oriented dial opens transport first ----------
    // The connection-oriented cutover drives the outbound machine
    // Discovered -> (Dial, connection_oriented=true) -> Connecting
    // (emitting ONLY OpenTransport, no msg1 yet), then TransportConnected ->
    // Handshaking{SentMsg1} with the same SendHandshake + two SetTimer that
    // `start_outbound_handshake` emits. Covers the oriented reach into
    // `start_outbound_handshake` via `on_transport_connected` (the connectionless
    // reach via `on_dial` is already covered by the test above).
    #[test]
    fn connection_oriented_dial_opens_transport_then_connected_handshakes() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();

        let mut m = PeerMachine::new_outbound(LinkId::new(1), peer, 0);
        // Connection-oriented dial: open the transport first, no msg1 yet.
        let dial = m.step(
            PeerEvent::Dial {
                transport_id: TransportId::new(1),
                remote_addr: TransportAddr::from_string("127.0.0.1:9999"),
                peer_identity: peer,
                connection_oriented: true,
            },
            100,
            &mut alloc,
        );
        assert_eq!(
            m.state(),
            PeerState::Connecting {
                link: LinkId::new(1)
            }
        );
        assert_eq!(
            dial,
            vec![PeerAction::OpenTransport {
                transport_id: TransportId::new(1),
                remote_addr: TransportAddr::from_string("127.0.0.1:9999"),
            }],
            "connection-oriented dial emits exactly one OpenTransport and no msg1"
        );

        // Transport connected: now send msg1 and arm the handshake timers.
        let connected = m.step(PeerEvent::TransportConnected, 200, &mut alloc);
        assert!(matches!(
            m.state(),
            PeerState::Handshaking {
                phase: HandshakePhase::SentMsg1,
                ..
            }
        ));
        assert_eq!(
            connected,
            vec![
                PeerAction::SendHandshake { bytes: Vec::new() },
                PeerAction::SetTimer {
                    kind: TimerKind::HandshakeRetransmit,
                    at_ms: 200 + HANDSHAKE_RETRANSMIT_INTERVAL_MS,
                },
                PeerAction::SetTimer {
                    kind: TimerKind::HandshakeTimeout,
                    at_ms: 200 + HANDSHAKE_TIMEOUT_MS,
                },
            ]
        );
    }

    // ---- Test 8: liveness -> LinkDeadSuspected -> ReportLost --------------
    #[test]
    fn liveness_to_link_dead() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), id, 0);
        m.state = PeerState::Active { addr };
        m.our_index = Some(SessionIndex::new(0x4242));

        let hb = m.step(PeerEvent::HeartbeatDue, 1_000, &mut alloc);
        assert_eq!(
            hb,
            vec![
                PeerAction::SendLinkMessage {
                    msg: vec![LinkMessageType::Heartbeat.to_byte()]
                },
                PeerAction::SetTimer {
                    kind: TimerKind::Liveness,
                    at_ms: 1_000 + LIVENESS_INTERVAL_MS
                },
            ]
        );

        let dead = m.step(PeerEvent::LinkDeadSuspected, 2_000, &mut alloc);
        assert_eq!(
            dead,
            vec![
                PeerAction::InvalidateSendState,
                PeerAction::TeardownConnectedUdp,
                PeerAction::ReportLost {
                    peer: addr,
                    kind: LostKind::LinkDead,
                },
            ]
        );
        assert!(matches!(m.state(), PeerState::Closed { .. }));
        // The exact action-sequence equality above is the "no ScheduleRetry"
        // guarantee: loss is reported only via ReportLost, and no retry-schedule
        // action exists in the PeerAction vocabulary at all (reconciler-owned).
    }

    // ---- Test 9: cadence CONSUME -----------------------------------------
    // The shell polls the batch `poll_rekey` and routes each decided ConnAction
    // as `RekeyConsume` — the machine maps it WITHOUT re-polling.
    #[test]
    fn rekey_consume_cutover_then_drain() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), id, 0);
        m.state = PeerState::Maintaining {
            addr,
            kind: MaintainKind::Rekey(RekeyPhase::PendingCutover),
        };
        m.rekey_our_index = Some(SessionIndex::new(0x2222));
        m.our_index = Some(SessionIndex::new(0x1111));
        m.remote_epoch = Some([9u8; 8]);

        // Consume the shell-decided Cutover.
        let cut = m.step(
            PeerEvent::RekeyConsume {
                action: ConnAction::Cutover { peer: addr },
            },
            10_000,
            &mut alloc,
        );
        assert_eq!(
            cut,
            vec![
                PeerAction::SwapSendState { epoch: [9u8; 8] },
                PeerAction::RegisterDecryptSession {
                    index: SessionIndex::new(0x2222)
                },
                PeerAction::SetTimer {
                    kind: TimerKind::DrainExpiry,
                    at_ms: 10_000 + DRAIN_WINDOW_MS
                },
            ]
        );
        assert_eq!(
            m.state(),
            PeerState::Maintaining {
                addr,
                kind: MaintainKind::Rekey(RekeyPhase::Draining)
            }
        );
        assert_eq!(m.draining_index, Some(SessionIndex::new(0x1111)));

        // Consume the shell-decided Drain: single CompleteDrain, Active, shadow
        // drain index cleared (double-free guard).
        let drain = m.step(
            PeerEvent::RekeyConsume {
                action: ConnAction::Drain { peer: addr },
            },
            20_000,
            &mut alloc,
        );
        assert_eq!(drain, vec![PeerAction::CompleteDrain { peer: addr }]);
        assert_eq!(m.state(), PeerState::Active { addr });
        assert_eq!(m.draining_index, None);
    }

    // ---- Test 10: RekeyInitiated observation ------------------------------
    #[test]
    fn rekey_initiated_observation() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), id, 0);
        m.state = PeerState::Established { addr };

        let acts = m.step(PeerEvent::RekeyInitiated, 5_000, &mut alloc);
        assert!(acts.is_empty());
        assert_eq!(
            m.state(),
            PeerState::Maintaining {
                addr,
                kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent)
            }
        );
        assert!(m.rekey_in_progress);
        // No index allocation happened in the machine (shell-side leaf).
        assert_eq!(alloc.count(), 0);
    }

    // ---- Test 11: RekeyMsg2 observation -----------------------------------
    // The shell completed the initiated rekey inline; the obs records the peer's
    // new index, clears the in-progress flag, advances to PendingCutover, and
    // emits nothing.
    #[test]
    fn rekey_msg2_observation() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), id, 0);
        m.state = PeerState::Maintaining {
            addr,
            kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent),
        };
        m.rekey_in_progress = true;

        let their = SessionIndex::new(0x4444);
        let acts = m.step(
            PeerEvent::RekeyMsg2 { their_index: their },
            6_000,
            &mut alloc,
        );
        assert!(acts.is_empty());
        assert_eq!(m.conn.their_index(), Some(their));
        assert!(!m.rekey_in_progress);
        assert_eq!(
            m.state(),
            PeerState::Maintaining {
                addr,
                kind: MaintainKind::Rekey(RekeyPhase::PendingCutover)
            }
        );
        assert_eq!(alloc.count(), 0);
    }

    // ---- Test 12: CrossConnResolved observation ---------------------------
    // A swap adopts the new local and remote indices into the control shadow and
    // emits nothing; a keep leaves the shadow untouched and emits nothing.
    #[test]
    fn cross_conn_resolved_swap_updates_shadow() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), id, 0);
        m.state = PeerState::Active { addr };
        m.conn.set_our_index(SessionIndex::new(0x1111));
        m.conn.set_their_index(SessionIndex::new(0x2222));

        let our = SessionIndex::new(0xAAAA);
        let their = SessionIndex::new(0xBBBB);
        let acts = m.step(
            PeerEvent::CrossConnResolved {
                outcome: CrossConnOutcome::Swap {
                    our_index: our,
                    their_index: their,
                },
            },
            7_000,
            &mut alloc,
        );
        assert!(acts.is_empty());
        assert_eq!(m.conn.our_index(), Some(our));
        assert_eq!(m.conn.their_index(), Some(their));
        assert_eq!(m.state(), PeerState::Active { addr });
        assert_eq!(alloc.count(), 0);
    }

    #[test]
    fn cross_conn_resolved_keep_is_noop() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), id, 0);
        m.state = PeerState::Active { addr };
        m.conn.set_our_index(SessionIndex::new(0x1111));
        m.conn.set_their_index(SessionIndex::new(0x2222));

        let acts = m.step(
            PeerEvent::CrossConnResolved {
                outcome: CrossConnOutcome::Keep,
            },
            7_000,
            &mut alloc,
        );
        assert!(acts.is_empty());
        assert_eq!(m.conn.our_index(), Some(SessionIndex::new(0x1111)));
        assert_eq!(m.conn.their_index(), Some(SessionIndex::new(0x2222)));
        assert_eq!(m.state(), PeerState::Active { addr });
        assert_eq!(alloc.count(), 0);
    }
}
