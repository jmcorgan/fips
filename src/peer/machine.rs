//! Per-peer FMP control FSM (sans-IO reducer) — XX re-derivation.
//!
//! The unified per-peer lifecycle state machine, ported onto next's XX cores
//! from the IK-lineage template. This is the **M1** increment: the FSM types,
//! the machine struct (control-tier state only), and the pure `step` reducer,
//! plus its unit tests. It is **unwired** — nothing in the codebase calls it
//! yet; the action executor and the msg3/rekey/reap wiring land in later steps.
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
//! shell-side, matching next's inline `handle_msg3` verbatim. These trigger
//! variants are **provisional** (the wiring step may refine them) and unwired.
//!
//! Likewise the outbound completion is NOT routed through the machine: next has
//! no `establish_outbound` core — `handle_msg2` learns the identity from
//! `conn.expected_identity()` and drives `promote_connection` inline. The
//! machine's outbound role is `Dial`→`OpenTransport`, `start_outbound_handshake`,
//! and the resend/timeout timers; the shell drives promote and feeds the outcome
//! back via [`PromotionResolved`](PeerEvent::PromotionResolved).
//!
//! ## M1 realizability notes
//!
//! - `SendHandshake`/`SendRekey`/`SendLinkMessage` carry **opaque bytes**
//!   (`Vec<u8>`); the driver applies outer wire framing / encryption. A fresh
//!   outbound msg1 and a fresh inbound msg2 have no bytes the control machine can
//!   build (the Noise step / `build_msg2` are shell-side), so they are emitted
//!   with an empty payload and threaded at wiring time. Not exercised by the M1
//!   tests (which assert on action *kinds* / index-plane facts).
//! - `PeerSnapshot::rekey_msg3_pending` is sourced from a control field defaulting
//!   `false`; the real wiring to `peer.rekey_msg3_payload().is_some()` and the
//!   [`RekeyMsg3Resend`](TimerKind::RekeyMsg3Resend) driver land at the rekey step.
//! - `PeerSnapshot::counter` (the Noise send counter) is a send-state fact the
//!   control machine cannot see; passed as `0`. Irrelevant to every M1 test.

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
// M1 is unwired; the real intervals come from `NodeConfig` when the driver is
// wired. The `poll_*` cores already take the interval/backoff as arguments, so
// these are only used to compute `SetTimer{at_ms}` deadlines and the
// `Closed{backoff_deadline_ms}` park time. The unit tests assert on timer
// *kinds*, not exact deadlines.
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// An input to the machine. Cross-registry facts ride in the payload as
/// plain-data snapshots ([`WireOutcome`]/[`EstablishSnapshot`]) built shell-side;
/// `now` is the `step` parameter, never duplicated here.
///
/// Not `Debug`/`PartialEq`: the reused core snapshot payloads derive neither.
pub(crate) enum PeerEvent {
    /// Reconciler dial intent.
    Dial {
        transport_id: TransportId,
        remote_addr: TransportAddr,
        peer_identity: PeerIdentity,
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
    InboundMsg3 {
        wire: WireOutcome,
        est: EstablishSnapshot,
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
    /// Either way the temporary inbound link is torn down. Provisional / unwired.
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
    /// Provisional / unwired.
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
    /// deliberately no `ScheduleRetry` machine action).
    ReportLost { peer: NodeAddr },
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

    /// New machine for an ALREADY-established peer: the post-handshake state a
    /// promoted peer occupies before any rekey. M3 inserts one of these into
    /// `Node.peer_machines` at each `promote_connection` establishment site so
    /// every established peer has exactly one machine keyed by its `LinkId`
    /// (Finding A). The machine is **inert** — nothing drives it yet — and is
    /// parked at [`PeerState::Established`] so a later reap sees
    /// [`is_established_context`](Self::is_established_context) true and a later
    /// rekey step finds it. `our_index` is the peer's msg1-allocated session
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

    /// The crystallized node address, if known.
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
                ..
            } => self.on_dial(transport_id, remote_addr, now),
            PeerEvent::TransportConnected => self.on_transport_connected(now),
            PeerEvent::TransportFailed => self.on_transport_failed(now),
            PeerEvent::InboundMsg1 { link } => self.on_inbound_msg1(link, now, index_allocator),
            PeerEvent::InboundMsg3 { wire, est } => {
                self.on_inbound_msg3(wire, est, now, index_allocator)
            }
            PeerEvent::OutboundMsg2 { their_index } => self.on_outbound_msg2(their_index, now),
            PeerEvent::PromotionResolved { result } => self.on_promotion_resolved(result, now),
            PeerEvent::RekeyMsg2 { their_index } => self.on_rekey_msg2(their_index),
            PeerEvent::RekeyConsume { action } => self.map_rekey_action(action, now),
            PeerEvent::RekeyInitiated => self.on_rekey_initiated(),
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
        _now: u64,
    ) -> Vec<PeerAction> {
        if !matches!(self.state, PeerState::Discovered) {
            return Vec::new();
        }
        self.conn.set_transport_id(transport_id);
        // Connection-oriented transports open the transport first; connectionless
        // ones send msg1 immediately. M1 models the connection-oriented arm.
        self.state = PeerState::Connecting { link: self.link };
        vec![PeerAction::OpenTransport {
            transport_id,
            remote_addr,
        }]
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
            actions.push(PeerAction::ReportLost { peer });
        }
        self.state = PeerState::Closed {
            backoff_deadline_ms: now + CLOSED_BACKOFF_MS,
        };
        actions
    }

    /// Emit msg1 and arm the retransmit/timeout timers. The Noise msg1
    /// construction and its index allocation are shell-side effects performed by
    /// the driver when it executes this action; M1 emits an empty payload (see
    /// module note). This path is not exercised by the M1 tests.
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
        now: u64,
        _alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        // Identity crystallizes at msg3 on XX (WireOutcome carries only the node
        // address + epoch; the full static key stays shell-side).
        self.node_addr = Some(wire.peer_node_addr);
        self.remote_epoch = wire.remote_epoch;

        match Fmp::new().establish_inbound(&est, &wire) {
            InboundDecision::Reject {
                reason: InboundReject::DualRekeyWon,
            } => {
                // Dual-init rekey tie-break: we win (smaller NodeAddr), drop the
                // peer's msg3 and keep driving our own rekey. The existing peer
                // (a separate machine/registry entry) is untouched; this temporary
                // leg is discarded. NOTE: next's `handle_msg3` Reject arm removes
                // conn+link but does NOT free the msg1-allocated index — so no
                // FreeIndex is emitted here, matching ground truth.
                self.fail(FailReason::Rejected)
            }
            InboundDecision::ResendMsg2 { msg2 } => {
                // Same-epoch duplicate: resend the existing peer's stored msg2,
                // leaving the active peer untouched. NOTE: next's `handle_msg3`
                // ResendMsg2 arm likewise does NOT free the msg1-allocated index.
                match msg2 {
                    Some(bytes) => vec![PeerAction::SendHandshake { bytes }],
                    None => Vec::new(),
                }
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
                    PeerAction::ReportLost { peer },
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
        vec![PeerAction::PromoteToActive { link: self.link }]
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
                // shell-side (empty payload in M1), arm the resend timer.
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
            actions.push(PeerAction::ReportLost { peer });
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
                    lost.push(PeerAction::ReportLost { peer });
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
        // The driver evaluates due machine timers on the quantized tick and
        // re-enters the Timeout{kind} handlers. M1 is unwired; the deadline
        // bookkeeping is threaded from the driver at wiring time, so Tick is a
        // no-op here.
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
    /// is sourced from the control field (default `false`; real wiring at the
    /// rekey step).
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

    // ---- Test 0: established constructor (Finding A populate) --------------
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

        assert_eq!(actions, vec![PeerAction::PromoteToActive { link }]);
        assert_eq!(m.state(), PeerState::Established { addr });
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

            let actions = m.step(PeerEvent::InboundMsg3 { wire, est }, 1_000, &mut alloc);
            // We win the tie-break: drop the peer's msg3, no response, no free.
            assert!(actions.is_empty());
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

            let actions = m.step(PeerEvent::InboundMsg3 { wire, est }, 1_000, &mut alloc);
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

        let actions = m.step(PeerEvent::InboundMsg3 { wire, est }, 1_000, &mut alloc);
        assert_eq!(
            actions,
            vec![
                PeerAction::InvalidateSendState,
                PeerAction::ReportLost { peer: peer_addr },
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
        let wp = winner.step(
            PeerEvent::InboundMsg3 {
                wire: wire_outcome(peer_addr, Some([3u8; 8])),
                est: est_new_peer(our),
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
        let lp = loser.step(
            PeerEvent::InboundMsg3 {
                wire: wire_outcome(peer_addr, Some([3u8; 8])),
                est: est_new_peer(our),
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
        let msg3 = m.step(
            PeerEvent::InboundMsg3 {
                wire: wire_outcome(peer_addr, Some([4u8; 8])),
                est: est_new_peer(our),
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

        let actions = m.step(PeerEvent::InboundMsg3 { wire, est }, 200, &mut alloc);
        assert_eq!(
            actions,
            vec![PeerAction::SwapToInboundSession {
                peer: peer_addr,
                our_index,
                our_inbound_wins: true,
            }]
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
                PeerAction::ReportLost { peer: addr },
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
}
