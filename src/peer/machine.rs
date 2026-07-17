//! Per-peer FMP control FSM (sans-IO reducer).
//!
//! The unified per-peer lifecycle state machine that folds the scattered
//! `connections`/`peers`/rekey state carriers into one place. It provides the
//! FSM types, the machine struct (control-tier state only), and the pure `step`
//! reducer, plus its unit tests. `step` is driven in production by the
//! handshake handlers, the rekey-cadence and liveness-reap routers, and the
//! dial/lifecycle paths, with the executor in
//! `crate::node::dataplane::peer_actions` performing the returned actions.
//! Still dormant: `PeerEvent::Timeout` is never dispatched — timer FIRING
//! decisions stay with the shell drivers.
//!
//! ## Shape
//!
//! `step(event, now, index_allocator) -> Vec<PeerAction>` is a **pure reducer**:
//! every lifecycle *decision* is delegated to the existing sans-IO cores in
//! [`crate::proto::fmp`] ([`Fmp::establish_inbound`]/[`establish_outbound`],
//! [`Fmp::poll_timeouts`]/[`poll_resends`]/[`poll_rekey`]/[`poll_rekey_resends`],
//! and `cross_connection_winner`) — this module writes **no new decision
//! core**. The machine only (a) builds the plain-data snapshots those cores
//! consume from its control-tier state, (b) maps the returned
//! [`ConnAction`]/[`InboundDecision`]/[`OutboundDecision`]/[`PromotionResult`]
//! into the [`PeerAction`] vocabulary the driver executes, and (c) advances its
//! own control state. Shell-side effects (the Noise wire step, `promote_connection`
//! registry surgery, late ACL `authorize_peer`, decrypt-worker register/unregister)
//! are **emitted as actions**, never performed here.
//!
//! ## Control / send-state split
//!
//! The machine holds **control-tier** state only. The hot send-critical state
//! (the three epoch slots, transport target, connected-UDP handle, hot counters)
//! becomes `PeerSendState` and is *not* built here; the machine emits
//! actions (`PromoteToActive`, `SwapSendState`, `RegisterDecryptSession`, …) that
//! the driver applies to the published send-state. `remote_epoch` is
//! establish-path-only, hence control-tier, and lives here.
//!
//! ## Realizability notes
//!
//! - `SendHandshake`/`SendRekey`/`SendLinkMessage` carry **opaque bytes**
//!   (`Vec<u8>`) — the driver applies outer wire framing / encryption. On the
//!   resend paths the bytes are the stored wire frame; on a fresh inbound msg2 /
//!   rekey msg2 they are the Noise payload the shell already produced
//!   ([`WireOutcome::msg2_payload`]). A fresh outbound msg1 has no bytes the
//!   control machine can build (the Noise step is shell-side), so it is emitted
//!   with an empty payload and a note that the driver fills it in — that path is
//!   not exercised by the tests.
//! - `SendLinkMessage { msg }` is opaque plaintext (there is **no** unifying
//!   `LinkMessage` type in the tree today — heartbeat is a bare `[0x51]` byte,
//!   while filter/tree/disconnect are distinct concrete types). The machine
//!   builds the real heartbeat and disconnect frames; filter/tree announce
//!   payloads are data-plane-owned and threaded in by the driver (empty here).
//! - `PeerSnapshot::counter` (the Noise send counter) is a send-state fact the
//!   control machine cannot see; it is passed as `0` (the message-count rekey
//!   trigger is threaded from `PeerSendState`). Irrelevant to every
//!   test (cutover/drain ignore it).

#![allow(dead_code)]

use crate::peer::PeerConnection;
use crate::proto::fmp::{
    ConnAction, ConnSnapshot, ConnectionState, EstablishSnapshot, Fmp, InboundDecision,
    OutboundDecision, OutboundSnapshot, PeerSnapshot, PromotionResult, RekeyCfg,
    RekeyResendSnapshot, WireOutcome,
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

/// Handshake phase (mirrors `proto::fmp::HandshakeState`'s in-progress arms).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HandshakePhase {
    Initial,
    SentMsg1,
    ReceivedMsg1,
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
    /// Rekey msg1 sent (initiator) or msg2 sent (responder); negotiation in flight.
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
/// plain-data snapshots ([`WireOutcome`]/[`EstablishSnapshot`]/[`OutboundSnapshot`])
/// built shell-side; `now` is the `step` parameter, never duplicated here.
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
    /// The transport accepted the dial but sending a stored handshake
    /// initiation failed. The machine marks the embedded leg failed so the
    /// stale-connection sweep reclaims it, WITHOUT leaving the handshaking
    /// state — the retransmit driver may still resend in the window before
    /// the sweep.
    HandshakeSendFailed,
    /// Inbound handshake msg1 processed shell-side (Noise + snapshot).
    InboundMsg1 {
        link: LinkId,
        wire: WireOutcome,
        est: EstablishSnapshot,
    },
    /// Outbound handshake completed (their msg2 received + Noise finalized).
    Msg2 {
        their_index: SessionIndex,
        out: OutboundSnapshot,
    },
    /// Late-ACL authorization succeeded (benign confirmation).
    Authorized,
    /// Late-ACL authorization rejected.
    Rejected,
    /// `promote_connection` resolved the [`PromoteToActive`](PeerAction::PromoteToActive)
    /// action shell-side; the machine consumes the outcome (it does not
    /// re-decide the tie-break).
    PromotionResolved { result: PromotionResult },
    /// Inbound rekey msg1 (a msg1 on an established peer).
    RekeyMsg1 {
        wire: WireOutcome,
        est: EstablishSnapshot,
    },
    /// Inbound rekey msg2 (completes our initiated rekey).
    RekeyMsg2 { their_index: SessionIndex },
    /// A cadence-decided rekey `ConnAction` to CONSUME. The shell ran the
    /// batch `poll_rekey` across the whole peer set (phase-grouped, index-order
    /// preserving) and routes each decided action here; the machine
    /// applies the control-tier transition + emits the send-state write
    /// (`SwapSendState`/`CompleteDrain`) WITHOUT re-polling. Carries only
    /// `Cutover`/`Drain` (`InitiateRekey` stays inline shell-side
    /// with a [`RekeyInitiated`](PeerEvent::RekeyInitiated) observation).
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
    /// pending a unifying `LinkMessage` type; a future revision could type against
    /// `proto::bloom::FilterAnnounce` / `proto::stp::TreeAnnounce` /
    /// `proto::fmp::Disconnect` / a heartbeat marker.
    SendLinkMessage { msg: Vec<u8> },
    /// Crystallize identity, re-home the map key, publish send-state
    /// (`promote_connection`). Resolves to a [`PromotionResolved`](PeerEvent::PromotionResolved).
    PromoteToActive { link: LinkId },
    /// A DECISION conveyed to the driver, not an effect: emitted by the
    /// outbound-msg2 arm when the establish decision is a cross-connection
    /// resolution. The shell intercepts it and runs the inline swap/keep
    /// resolution; it must never reach the action executor.
    ResolveCrossConnection { swap: bool },
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
    /// The pending handshake connection this machine owns while the leg is in
    /// the handshake window. `None` before the connection is built (the dial
    /// window) and after promotion consumes it (the machine survives as the
    /// active peer's control machine). Pure storage — the machine never reads
    /// or drives it; the shell reaches it through the accessors below.
    leg: Option<PeerConnection>,
    /// Pure handshake-phase bookkeeping (link/direction/indices/transport/
    /// stored handshake bytes/epoch). Reused verbatim from the FMP state core.
    conn: ConnectionState,
    /// Remote startup epoch (establish-path-only; NOT in send-state).
    remote_epoch: Option<[u8; 8]>,
    /// Inbound two-phase authorize: the opaque Noise msg2
    /// payload stashed in Phase 1 (`InboundMsg1`) and emitted in Phase 2
    /// (`on_authorized`), so a rejected/unauthorized msg1 allocates no index.
    pending_msg2_payload: Option<Vec<u8>>,

    // --- rekey negotiation sub-state (control tier; NOT the pending send slot) ---
    rekey_in_progress: bool,
    /// The index we allocated for our in-flight/negotiated rekey session.
    rekey_our_index: Option<SessionIndex>,
    /// Stored rekey msg1 wire bytes (for retransmit).
    rekey_msg1: Option<Vec<u8>>,
    rekey_resend_count: u32,
    /// When we last processed a peer rekey msg1 (dampening).
    last_peer_rekey_ms: u64,

    // --- timing (control tier) ---
    session_established_at_ms: u64,
    authenticated_at_ms: u64,
    rekey_jitter_secs: i64,
    last_heartbeat_sent_ms: u64,

    // --- decrypt-registration shadow ---
    // The machine owns decrypt-worker register/unregister via actions, so it
    // tracks which index it registered (to later unregister/free). This is
    // control knowledge of the registration lifecycle, distinct from the hot
    // send-state slots.
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
            leg: None,
            conn: ConnectionState::outbound(link, identity, now),
            remote_epoch: None,
            pending_msg2_payload: None,
            rekey_in_progress: false,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_resend_count: 0,
            last_peer_rekey_ms: 0,
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
            leg: None,
            conn: ConnectionState::inbound(link, now),
            remote_epoch: None,
            pending_msg2_payload: None,
            rekey_in_progress: false,
            rekey_our_index: None,
            rekey_msg1: None,
            rekey_resend_count: 0,
            last_peer_rekey_ms: 0,
            session_established_at_ms: 0,
            authenticated_at_ms: 0,
            rekey_jitter_secs: 0,
            last_heartbeat_sent_ms: 0,
            our_index: None,
            draining_index: None,
        }
    }

    /// Current lifecycle state.
    pub(crate) fn state(&self) -> PeerState {
        self.state
    }

    /// The pending handshake connection, if this leg is still in the
    /// handshake window.
    pub(crate) fn leg(&self) -> Option<&PeerConnection> {
        self.leg.as_ref()
    }

    /// Mutable access to the pending handshake connection.
    pub(crate) fn leg_mut(&mut self) -> Option<&mut PeerConnection> {
        self.leg.as_mut()
    }

    /// Take the pending handshake connection off the machine (promotion and
    /// teardown consume it by value).
    pub(crate) fn take_leg(&mut self) -> Option<PeerConnection> {
        self.leg.take()
    }

    /// Embed a pending handshake connection on the machine.
    pub(crate) fn set_leg(&mut self, leg: PeerConnection) {
        self.leg = Some(leg);
    }

    /// The index we allocated for this peer's inbound session, once Phase 2
    /// (`on_authorized`) has run. `None` before allocation (and after a
    /// rejected/unauthorized msg1). The inbound cutover reads this to perform
    /// the shell registry surgery with the machine-owned index.
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
        self.identity.map(|id| *id.node_addr())
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
            PeerEvent::HandshakeSendFailed => self.on_handshake_send_failed(),
            PeerEvent::InboundMsg1 { link, wire, est } => {
                let (_decision, actions) = self.inbound_msg1(link, &wire, est, now);
                actions
            }
            PeerEvent::Msg2 { their_index, out } => {
                self.on_msg2(their_index, out, now, index_allocator)
            }
            PeerEvent::Authorized => self.on_authorized(now, index_allocator),
            PeerEvent::Rejected => self.fail(FailReason::AclRejected),
            PeerEvent::PromotionResolved { result } => self.on_promotion_resolved(result, now),
            PeerEvent::RekeyMsg1 { wire, est } => {
                // A rekey msg1 is a msg1 on an established peer — same core.
                let (_decision, actions) = self.inbound_msg1(self.link, &wire, est, now);
                actions
            }
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
                // Filter-announce payload is data-plane-owned; threaded in
                // at wiring time.
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

    /// A stored handshake initiation failed to send: mark the embedded leg
    /// failed so the stale-connection sweep (which reads the leg's
    /// `is_failed`) reclaims it. NO state flip — the machine stays in
    /// `Handshaking{SentMsg1}` so retransmit eligibility
    /// (`is_handshaking_sent_msg1`) survives until the sweep, and no timer
    /// actions are emitted.
    fn on_handshake_send_failed(&mut self) -> Vec<PeerAction> {
        if let Some(leg) = self.leg.as_mut() {
            leg.mark_failed();
        }
        Vec::new()
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

    /// Outbound completion: compute the establish decision from the snapshot
    /// via `establish_outbound`. `Promote` drives promotion via actions; the
    /// Swap/Keep outcomes are conveyed as a
    /// [`ResolveCrossConnection`](PeerAction::ResolveCrossConnection) decision
    /// for the shell's inline resolution, which owns all effects (index
    /// frees, session replacement) permanently.
    fn on_msg2(
        &mut self,
        their_index: SessionIndex,
        out: OutboundSnapshot,
        _now: u64,
        _alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        self.conn.set_their_index(their_index);
        match Fmp::new().establish_outbound(&out) {
            OutboundDecision::Promote => {
                // Net-new: our outbound index (allocated at dial) is the one we
                // register once promotion resolves.
                self.our_index = self.conn.our_index();
                // The machine survives promotion (it becomes the active peer's
                // control machine), so cancel the outbound handshake timers here
                // or they would linger in the driver's store. A late fire would
                // no-op against the non-`Handshaking` state, but leaving them
                // armed is a timer leak.
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
            OutboundDecision::CrossConnectionSwap => {
                // Our outbound wins: convey the decision only. The shell's
                // inline resolution swaps the peer to the outbound session and
                // owns the index frees and session replacement.
                vec![PeerAction::ResolveCrossConnection { swap: true }]
            }
            OutboundDecision::CrossConnectionKeep => {
                // Our outbound loses: convey the decision only. The shell's
                // inline resolution keeps the existing inbound session and
                // frees the unused outbound index.
                vec![PeerAction::ResolveCrossConnection { swap: false }]
            }
        }
    }

    // ------------------------------------------------------------------
    // Inbound establish
    // ------------------------------------------------------------------

    /// Inbound msg1 (fresh or rekey): compute the establish decision for the
    /// driver, alongside any machine-phase actions. The single
    /// `establish_inbound` evaluation happens here; the driver routes on the
    /// returned [`InboundDecision`] and owns the effect-bearing arm bodies
    /// (the rekey-respond abandon/alloc/send/store, the duplicate resend, the
    /// reject bookkeeping). Only the `Promote`/`RestartThenPromote` phase-1
    /// actions (and the fresh-context reject state flip) are machine-side.
    pub(crate) fn inbound_msg1(
        &mut self,
        link: LinkId,
        wire: &WireOutcome,
        est: EstablishSnapshot,
        _now: u64,
    ) -> (InboundDecision, Vec<PeerAction>) {
        let decision = Fmp::new().establish_inbound(&est, wire);
        let actions = match &decision {
            InboundDecision::Reject { .. } => {
                // In an establish-leg context this fails the leg; on an
                // established peer (rekey context) the msg1 is dropped and the
                // peer keeps running (DualRekeyWon/PendingSession keep our rekey).
                if self.is_established_context() {
                    Vec::new()
                } else {
                    self.fail(FailReason::Rejected)
                }
            }
            // The decision carries the stored msg2 bytes; the driver's inline
            // resend owns the send. No machine state is touched.
            InboundDecision::ResendMsg2 { .. } => Vec::new(),
            // Decision-only: the driver's inline body owns the abandon, the
            // index allocation, the framed msg2 send, the pending-session
            // store, and the dampening stamp. The machine mutates nothing.
            InboundDecision::RekeyRespond { .. } => Vec::new(),
            InboundDecision::RestartThenPromote { peer } => {
                let peer = *peer;
                let mut actions = vec![PeerAction::InvalidateSendState];
                if let Some(idx) = self.our_index.take() {
                    actions.push(PeerAction::UnregisterDecryptSession { index: idx });
                }
                // An established peer being replaced by a fresh inbound leg — the
                // unconditional reconnect reflex (a live, cut-over producer).
                actions.push(PeerAction::ReportLost {
                    peer,
                    kind: LostKind::LinkDead,
                });
                actions.extend(self.inbound_classify(link, wire));
                actions
            }
            InboundDecision::Promote => self.inbound_classify(link, wire),
        };
        (decision, actions)
    }

    /// Inbound **Phase 1**: classify the fresh leg *without*
    /// allocating an index. Records identity/epoch/their-index and stashes the
    /// opaque msg2 payload, parking at `Handshaking{ReceivedMsg1}` — the
    /// "awaiting Authorized" marker. The index allocation and the msg2/promote
    /// emission happen in Phase 2 ([`Self::on_authorized`]) only after the
    /// shell's late-ACL gate passes, so a rejected/unauthorized msg1 allocates
    /// nothing (preserving the pre-refactor global index-allocation sequence).
    fn inbound_classify(&mut self, link: LinkId, wire: &WireOutcome) -> Vec<PeerAction> {
        self.identity = Some(wire.peer_identity);
        self.remote_epoch = wire.remote_epoch;
        self.conn.set_their_index(wire.their_index);
        self.pending_msg2_payload = Some(wire.msg2_payload.clone());
        self.state = PeerState::Handshaking {
            link,
            phase: HandshakePhase::ReceivedMsg1,
        };
        Vec::new()
    }

    /// Inbound **Phase 2**: the late-ACL gate passed shell-side.
    /// Allocate our index NOW — the single inbound allocation point — record it
    /// on `conn`, and emit the msg2 send + promotion. `RegisterDecryptSession`
    /// follows on the `PromotionResolved{Promoted}` feedback. Guarded to
    /// the inbound `ReceivedMsg1` phase so the benign outbound `Authorized`
    /// confirmation stays a no-op (state `Handshaking{SentMsg1}` and every other
    /// state fall through to `Vec::new()`).
    fn on_authorized(&mut self, _now: u64, alloc: &mut IndexAllocator) -> Vec<PeerAction> {
        if !matches!(
            self.state,
            PeerState::Handshaking {
                phase: HandshakePhase::ReceivedMsg1,
                ..
            }
        ) {
            return Vec::new();
        }
        let our_index = match alloc.allocate() {
            Ok(idx) => idx,
            Err(_) => {
                // Allocation exhausted: no index, no msg2, no promote. The shell
                // records the reject + completes the rate-limiter bracket
                // (mirrors the pre-refactor `handle_msg1` allocate-failure path).
                self.state = PeerState::Failed {
                    reason: FailReason::Rejected,
                };
                return Vec::new();
            }
        };
        self.conn.set_our_index(our_index);
        self.our_index = Some(our_index);
        let bytes = self.pending_msg2_payload.take().unwrap_or_default();
        let link = self.link;
        vec![
            PeerAction::SendHandshake { bytes },
            PeerAction::PromoteToActive { link },
        ]
    }

    // ------------------------------------------------------------------
    // Promotion feedback
    // ------------------------------------------------------------------

    fn on_promotion_resolved(&mut self, result: PromotionResult, now: u64) -> Vec<PeerAction> {
        match result {
            PromotionResult::Promoted(addr) => {
                self.identity_addr_set(addr);
                self.crystallize(now);
                self.register_current_index()
            }
            PromotionResult::CrossConnectionWon { node_addr, .. } => {
                self.identity_addr_set(node_addr);
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

    /// Observation: the shell ran `initiate_rekey` inline — the Noise msg1 leaf,
    /// the index allocation, the wire send, and the `set_rekey_state` on the
    /// `ActivePeer` all happened shell-side. This is a pure observation that
    /// advances the machine's control state to `Maintaining{Rekey(Msg1Sent)}` so
    /// the subsequent cadence `Cutover`/`Drain` consume transitions from a
    /// coherent phase. Emits NO action (nothing left to do). No-op unless the peer
    /// is in an established-like state (defensive; the shell only initiates on
    /// healthy established peers).
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
                // index, open the drain window. Slot-rotation mechanics stay in
                // active.rs; the machine emits the action sequence.
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
                // decrypt-worker / index-free cleanup, replacing the old
                // shadow-index emission (which could drift from the real index).
                //
                // Clear the shadow `draining_index` set by the Cutover arm: the
                // real previous index is now retired by `CompleteDrain`, so a
                // leftover `Some(stale)` would double-free if a later
                // `CrossConnectionWon` consumed it in `on_promotion_resolved`.
                // Post-rekey cross-connection promotion is
                // not a live path, but clearing here removes the hazard outright.
                self.draining_index = None;
                self.state = PeerState::Active { addr: peer };
                vec![PeerAction::CompleteDrain { peer }]
            }
            ConnAction::InitiateRekey { peer } => {
                // Fresh outbound rekey: allocate our new index, send msg1 (Noise
                // leaf is shell-side → empty payload here), arm the resend timer.
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
        // Guard the full established set (Established | Active | Maintaining), not
        // just `is_active_like()`: a peer that never rekeyed stays parked in
        // `Established` (the machine reaches `Active` only via a rekey `Drain`),
        // yet the pre-refactor liveness reap tore down EVERY dead established peer.
        // A too-narrow `is_active_like()` guard here would silently skip the common
        // (never-rekeyed) reap target. Mirrors `on_disconnect`'s guard.
        if !self.is_established_context() {
            return Vec::new();
        }
        // `InvalidateSendState` maps to the executor's `remove_active_peer`, which
        // unregisters the decrypt worker by the REAL current index. The machine's
        // shadow `our_index` is deliberately NOT used to unregister here: it
        // can drift to a reused index and wrongly unregister ANOTHER peer's worker
        // session. `TeardownConnectedUdp` is inert (the old reap had no
        // connected-UDP teardown, so inert is neutral); `ReportLost` drives the
        // loss reflex (`note_link_dead`).
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

    fn identity_addr_set(&mut self, _addr: NodeAddr) {
        // Identity is already crystallized from the wire outcome during the
        // establish step; the PromotionResult's addr confirms it.
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
    /// send-state fact; passed as 0 here (see module note).
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
// Unit tests — assert on ACTION SEQUENCES + STATE transitions using
// hand-built synthetic snapshots (no real crypto sessions).
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

    fn wire_outcome(peer: PeerIdentity, epoch: Option<[u8; 8]>, their: u32) -> WireOutcome {
        WireOutcome {
            peer_identity: peer,
            remote_epoch: epoch,
            their_index: SessionIndex::new(their),
            msg2_payload: vec![0xAB; 8],
        }
    }

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
            at_max_peers: false,
            has_pending_outbound_to_peer: false,
            rekey_enabled: true,
            our_node_addr: our,
        }
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
            PeerAction::ResolveCrossConnection { swap: true },
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
                | PeerAction::ResolveCrossConnection { .. }
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
                | PeerAction::ReportLost { .. } => {}
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
        // drain: the machine now emits the single `CompleteDrain` send-state
        // write (executor reads the real previous index) instead of the old
        // shadow-index `[UnregisterDecryptSession, FreeIndex]` pair.
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

    // ---- Test 3: dual-init tie-break, swapped addrs -----------------------
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
            m.rekey_our_index = Some(SessionIndex::new(0x55));
            let mut est = est_new_peer(our);
            est.has_existing_peer = true;
            est.existing_peer_epoch = Some([1u8; 8]);
            est.has_session = true;
            est.is_healthy = true;
            est.existing_session_age_secs = 120;
            est.rekey_in_progress = true;
            let wire = wire_outcome(peer, Some([1u8; 8]), 0x77);

            let actions = m.step(PeerEvent::RekeyMsg1 { wire, est }, 1_000, &mut alloc);
            // We win the tie-break: drop the peer's msg1, no rekey response,
            // established-context state untouched (the peer keeps running).
            assert!(actions.is_empty());
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, PeerAction::SendRekey { .. }))
            );
            assert_eq!(
                m.state(),
                PeerState::Maintaining {
                    addr: peer_addr,
                    kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent)
                }
            );
        }

        // Case B: PEER is smaller -> we lose -> RekeyRespond{abandon_first:true}.
        {
            let our = *larger.node_addr();
            let peer = smaller;
            let mut m = PeerMachine::new_outbound(LinkId::new(2), peer, 0);
            let peer_addr = *peer.node_addr();
            m.state = PeerState::Maintaining {
                addr: peer_addr,
                kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent),
            };
            m.rekey_in_progress = true;
            m.rekey_our_index = Some(SessionIndex::new(0x55));
            let mut est = est_new_peer(our);
            est.has_existing_peer = true;
            est.existing_peer_epoch = Some([1u8; 8]);
            est.has_session = true;
            est.is_healthy = true;
            est.existing_session_age_secs = 120;
            est.rekey_in_progress = true;
            let wire = wire_outcome(peer, Some([1u8; 8]), 0x77);

            let (decision, actions) = m.inbound_msg1(LinkId::new(2), &wire, est, 1_000);
            // We lose the tie-break: the decision names the responder path with
            // the abandon flag; the machine emits nothing and mutates nothing
            // (the driver's inline body owns the abandon/alloc/send/store).
            assert!(matches!(
                decision,
                InboundDecision::RekeyRespond {
                    abandon_first: true,
                    ..
                }
            ));
            assert!(actions.is_empty());
            assert_eq!(
                m.state(),
                PeerState::Maintaining {
                    addr: peer_addr,
                    kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent)
                }
            );
            assert_eq!(m.rekey_our_index, Some(SessionIndex::new(0x55)));
            assert!(m.rekey_in_progress);
        }
    }

    // ---- Test 3b: duplicate msg1 -> resend decision only ------------------
    #[test]
    fn inbound_resend_msg2_decision_only() {
        let peer = peer_identity();
        let mut m = PeerMachine::new_inbound(LinkId::new(1), 0);
        let our = *peer_identity().node_addr();
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([1u8; 8]);
        est.has_session = true;
        est.is_healthy = true;
        est.existing_session_age_secs = 5; // young session -> duplicate, not rekey
        est.existing_msg2 = Some(vec![0xC4; 16]);
        let wire = wire_outcome(peer, Some([1u8; 8]), 0x77);

        let (decision, actions) = m.inbound_msg1(LinkId::new(1), &wire, est, 1_000);
        // The decision carries the stored msg2 bytes; no SendHandshake action,
        // no state change (the driver's inline resend owns the send).
        assert!(matches!(
            &decision,
            InboundDecision::ResendMsg2 { msg2: Some(bytes) } if bytes.as_slice() == [0xC4; 16]
        ));
        assert!(actions.is_empty());
        assert_eq!(
            m.state(),
            PeerState::Handshaking {
                link: LinkId::new(1),
                phase: HandshakePhase::Initial
            }
        );
    }

    // ---- Test 4: restart-override -----------------------------------------
    #[test]
    fn restart_override() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let mut m = PeerMachine::new_inbound(LinkId::new(1), 0);
        // Existing peer at a different epoch -> restart.
        m.our_index = Some(SessionIndex::new(0xDEAD));
        let our = *peer_identity().node_addr();
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([1u8; 8]); // old
        let wire = wire_outcome(peer, Some([2u8; 8]), 0x77); // new epoch

        let actions = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
                wire,
                est,
            },
            1_000,
            &mut alloc,
        );

        // Phase 1: restart tail only (invalidate, unregister old, report lost),
        // then park at ReceivedMsg1 — no index allocated yet.
        assert_eq!(
            actions,
            vec![
                PeerAction::InvalidateSendState,
                PeerAction::UnregisterDecryptSession {
                    index: SessionIndex::new(0xDEAD)
                },
                PeerAction::ReportLost {
                    peer: peer_addr,
                    kind: LostKind::LinkDead,
                },
            ]
        );
        assert!(matches!(
            m.state(),
            PeerState::Handshaking {
                phase: HandshakePhase::ReceivedMsg1,
                ..
            }
        ));
        assert_eq!(m.our_index(), None);
        assert_eq!(alloc.count(), 0);

        // Phase 2: late-ACL gate passed -> allocate + Promote tail.
        let promote = m.step(PeerEvent::Authorized, 1_000, &mut alloc);
        assert!(
            promote
                .iter()
                .any(|a| matches!(a, PeerAction::SendHandshake { .. }))
        );
        assert!(
            promote
                .iter()
                .any(|a| matches!(a, PeerAction::PromoteToActive { .. }))
        );

        // Promotion feedback -> Established.
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

        // Winner leg (link 1): net-new inbound promote -> Established.
        let mut winner = PeerMachine::new_inbound(LinkId::new(1), 0);
        let our = *peer_identity().node_addr();
        let est_w = est_new_peer(our);
        let wire_w = wire_outcome(peer, Some([3u8; 8]), 0x77);
        let wp1 = winner.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
                wire: wire_w,
                est: est_w,
            },
            100,
            &mut alloc,
        );
        assert!(wp1.is_empty()); // Phase 1 classifies without emitting.
        let wa = winner.step(PeerEvent::Authorized, 100, &mut alloc);
        assert!(
            wa.iter().any(
                |a| matches!(a, PeerAction::PromoteToActive { link } if *link == LinkId::new(1))
            )
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
        // promote_connection -> Failed + FreeIndex, link terminates.
        let mut loser = PeerMachine::new_inbound(LinkId::new(2), 0);
        let est_l = est_new_peer(our);
        let wire_l = wire_outcome(peer, Some([3u8; 8]), 0x88);
        let lp1 = loser.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(2),
                wire: wire_l,
                est: est_l,
            },
            100,
            &mut alloc,
        );
        assert!(lp1.is_empty()); // Phase 1 classifies without emitting.
        let la = loser.step(PeerEvent::Authorized, 100, &mut alloc);
        assert!(
            la.iter()
                .any(|a| matches!(a, PeerAction::PromoteToActive { .. }))
        );
        let loser_index = loser.our_index;
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

        // One crystallized NodeAddr (the winner); loser never crystallizes.
        assert_eq!(winner.addr(), Some(peer_addr));
    }

    // ---- Test 6: inbound establish ----------------------------------------
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
        let our = *peer_identity().node_addr();
        let est = est_new_peer(our);
        let wire = wire_outcome(peer, Some([4u8; 8]), 0x77);

        // Phase 1 (InboundMsg1): classify only — no actions, no allocation,
        // parked at ReceivedMsg1.
        let phase1 = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
                wire,
                est,
            },
            200,
            &mut alloc,
        );
        assert!(phase1.is_empty());
        assert_eq!(
            m.state(),
            PeerState::Handshaking {
                link: LinkId::new(1),
                phase: HandshakePhase::ReceivedMsg1
            }
        );
        assert_eq!(m.our_index(), None);
        assert_eq!(alloc.count(), 0); // allocator untouched pre-authorize

        // Phase 2 (Authorized): allocate + [SendHandshake, PromoteToActive].
        let phase2 = m.step(PeerEvent::Authorized, 200, &mut alloc);
        assert!(matches!(phase2[0], PeerAction::SendHandshake { .. }));
        assert_eq!(
            phase2[1],
            PeerAction::PromoteToActive {
                link: LinkId::new(1)
            }
        );
        assert!(m.our_index().is_some());
        assert_eq!(alloc.count(), 1); // exactly one index allocated

        // Phase 3 (PromotionResolved{Promoted}): register + Established.
        let phase3 = m.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::Promoted(peer_addr),
            },
            200,
            &mut alloc,
        );
        assert!(matches!(
            phase3[0],
            PeerAction::RegisterDecryptSession { .. }
        ));
        assert_eq!(m.state(), PeerState::Established { addr: peer_addr });
    }

    // ---- Test 6b: inbound late-ACL rejected -> no allocation --------------
    #[test]
    fn inbound_authorize_rejected_no_alloc() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let mut m = PeerMachine::new_inbound(LinkId::new(1), 0);
        let our = *peer_identity().node_addr();
        let est = est_new_peer(our);
        let wire = wire_outcome(peer, Some([4u8; 8]), 0x77);

        // Phase 1 classifies (no alloc).
        let phase1 = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
                wire,
                est,
            },
            200,
            &mut alloc,
        );
        assert!(phase1.is_empty());
        assert_eq!(alloc.count(), 0);

        // Late-ACL rejects -> Failed{AclRejected}, still no allocation.
        let rej = m.step(PeerEvent::Rejected, 200, &mut alloc);
        assert!(rej.is_empty());
        assert_eq!(
            m.state(),
            PeerState::Failed {
                reason: FailReason::AclRejected
            }
        );
        assert_eq!(alloc.count(), 0);
        assert_eq!(m.our_index(), None);
    }

    // ---- Test 6c: inbound reject at max_peers -> no allocation ------------
    #[test]
    fn inbound_at_max_peers_reject_no_alloc() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let mut m = PeerMachine::new_inbound(LinkId::new(1), 0);
        let our = *peer_identity().node_addr();
        let mut est = est_new_peer(our);
        est.at_max_peers = true;
        let wire = wire_outcome(peer, Some([4u8; 8]), 0x77);

        let actions = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
                wire,
                est,
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
        assert_eq!(alloc.count(), 0);
        assert_eq!(m.our_index(), None);
    }

    // ---- Test 7: outbound establish (+ cross-connection) ------------------
    #[test]
    fn outbound_establish() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();

        // Net-new promote.
        let mut m = PeerMachine::new_outbound(LinkId::new(1), peer, 0);
        m.state = PeerState::Handshaking {
            link: LinkId::new(1),
            phase: HandshakePhase::SentMsg1,
        };
        m.conn.set_our_index(SessionIndex::new(0xABCD));
        let out = OutboundSnapshot {
            has_existing_peer: false,
            our_outbound_wins: false,
        };
        let mut actions = m.step(
            PeerEvent::Msg2 {
                their_index: SessionIndex::new(0x77),
                out,
            },
            300,
            &mut alloc,
        );
        assert_eq!(
            actions,
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
        actions = m.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::Promoted(peer_addr),
            },
            300,
            &mut alloc,
        );
        assert_eq!(
            actions,
            vec![PeerAction::RegisterDecryptSession {
                index: SessionIndex::new(0xABCD)
            }]
        );
        assert_eq!(m.state(), PeerState::Established { addr: peer_addr });

        // Cross-connection SWAP: our outbound wins -> decision only; the
        // shell's inline resolution owns the index frees and session
        // replacement.
        let mut m2 = PeerMachine::new_outbound(LinkId::new(2), peer, 0);
        m2.state = PeerState::Handshaking {
            link: LinkId::new(2),
            phase: HandshakePhase::SentMsg1,
        };
        m2.conn.set_our_index(SessionIndex::new(0x2222)); // outbound index
        m2.our_index = Some(SessionIndex::new(0x1111)); // old inbound index
        let out_swap = OutboundSnapshot {
            has_existing_peer: true,
            our_outbound_wins: true,
        };
        let swap = m2.step(
            PeerEvent::Msg2 {
                their_index: SessionIndex::new(0x99),
                out: out_swap,
            },
            400,
            &mut alloc,
        );
        assert_eq!(
            swap,
            vec![PeerAction::ResolveCrossConnection { swap: true }]
        );
        assert!(!swap.iter().any(|a| matches!(
            a,
            PeerAction::FreeIndex { .. } | PeerAction::RegisterDecryptSession { .. }
        )));
        // The decision arm leaves the machine untouched: still Handshaking,
        // our_index unchanged.
        assert_eq!(
            m2.state(),
            PeerState::Handshaking {
                link: LinkId::new(2),
                phase: HandshakePhase::SentMsg1,
            }
        );
        assert_eq!(m2.our_index(), Some(SessionIndex::new(0x1111)));

        // Cross-connection KEEP: our outbound loses -> decision only; the
        // shell's inline resolution frees the unused outbound index.
        let mut m3 = PeerMachine::new_outbound(LinkId::new(3), peer, 0);
        m3.state = PeerState::Handshaking {
            link: LinkId::new(3),
            phase: HandshakePhase::SentMsg1,
        };
        m3.conn.set_our_index(SessionIndex::new(0x3333));
        let out_keep = OutboundSnapshot {
            has_existing_peer: true,
            our_outbound_wins: false,
        };
        let keep = m3.step(
            PeerEvent::Msg2 {
                their_index: SessionIndex::new(0x9A),
                out: out_keep,
            },
            500,
            &mut alloc,
        );
        assert_eq!(
            keep,
            vec![PeerAction::ResolveCrossConnection { swap: false }]
        );
        assert!(!keep.iter().any(|a| matches!(
            a,
            PeerAction::FreeIndex { .. } | PeerAction::RegisterDecryptSession { .. }
        )));
        assert_eq!(
            m3.state(),
            PeerState::Handshaking {
                link: LinkId::new(3),
                phase: HandshakePhase::SentMsg1,
            }
        );
        assert_eq!(m3.our_index(), None);
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
        let out = OutboundSnapshot {
            has_existing_peer: false,
            our_outbound_wins: false,
        };
        let promote = m.step(
            PeerEvent::Msg2 {
                their_index: SessionIndex::new(0x77),
                out,
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

        // A subsequent inbound restart (peer restart, new epoch) must NOT emit
        // UnregisterDecryptSession, because our_index is None.
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([1u8; 8]);
        let wire = wire_outcome(peer, Some([2u8; 8]), 0x88);
        let restart = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
                wire,
                est,
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
        let out = OutboundSnapshot {
            has_existing_peer: false,
            our_outbound_wins: false,
        };
        let promote = m.step(
            PeerEvent::Msg2 {
                their_index: SessionIndex::new(0x77),
                out,
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

    // ---- Test 7e: HandshakeSendFailed marks the leg, keeps the state ------
    // A stored-msg1 send failure marks the embedded leg failed (the
    // stale-connection sweep reads the leg's `is_failed`) WITHOUT leaving
    // `Handshaking{SentMsg1}` — retransmit eligibility
    // (`is_handshaking_sent_msg1`) must survive until the sweep — and emits
    // no actions. On a machine with no leg it is a defensive no-op.
    #[test]
    fn handshake_send_failed_marks_leg_without_leaving_handshaking() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();

        // Dial-persisted outbound machine carrying a prepared leg, driven to
        // Handshaking{SentMsg1} via the connectionless dial.
        let mut m = PeerMachine::new_outbound(LinkId::new(1), peer, 0);
        let _ = m.step(
            PeerEvent::Dial {
                transport_id: TransportId::new(1),
                remote_addr: TransportAddr::from_string("127.0.0.1:9999"),
                peer_identity: peer,
                connection_oriented: false,
            },
            100,
            &mut alloc,
        );
        m.set_leg(PeerConnection::outbound(LinkId::new(1), peer, 100));
        assert!(m.is_handshaking_sent_msg1());
        assert!(!m.leg().expect("leg embedded").is_failed());

        let actions = m.step(PeerEvent::HandshakeSendFailed, 200, &mut alloc);
        assert_eq!(actions, Vec::new(), "HandshakeSendFailed emits no actions");
        assert!(
            m.is_handshaking_sent_msg1(),
            "retransmit eligibility survives a send failure"
        );
        assert!(
            m.leg().expect("leg retained").is_failed(),
            "the leg carries the failed mark the sweep reads"
        );

        // With no leg (e.g. after take_leg) the event is a defensive no-op.
        let _ = m.take_leg();
        let actions = m.step(PeerEvent::HandshakeSendFailed, 300, &mut alloc);
        assert_eq!(actions, Vec::new());
        assert!(m.is_handshaking_sent_msg1());
        assert!(m.leg().is_none());
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

    // ---- Test 9: cadence CONSUME ------------------------------------------
    // The shell polls the batch `poll_rekey` and routes each decided ConnAction
    // as `RekeyConsume` — the machine maps it WITHOUT re-polling, yielding the
    // same action sequence + transition as the machine-driven cadence (Test 1),
    // and the Drain consume clears the shadow `draining_index`.
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

        // Consume the shell-decided Cutover: identical sequence to Test 1.
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
        // Cutover stashed the old index in the drain shadow.
        assert_eq!(m.draining_index, Some(SessionIndex::new(0x1111)));

        // Consume the shell-decided Drain: single CompleteDrain, Active, and the
        // shadow drain index is CLEARED (double-free guard).
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
    // The shell ran `initiate_rekey` inline; the obs advances control state to
    // Msg1Sent and emits nothing.
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
