//! Per-peer FMP control FSM (sans-IO reducer).
//!
//! The unified per-peer lifecycle state machine that Step 2 of the node-runtime
//! decomposition folds the scattered `connections`/`peers`/rekey state carriers
//! into. This module is the **C1** increment: the FSM types, the machine struct
//! (control-tier state only), and the pure `step` reducer, plus its unit tests.
//! It is **unwired** — nothing in the codebase calls it yet; the driver wiring
//! (C3b) and the send-state boundary (C2) land in later commits.
//!
//! ## Shape
//!
//! `step(event, now, index_allocator) -> Vec<PeerAction>` is a **pure reducer**:
//! every lifecycle *decision* is delegated to the existing sans-IO cores in
//! [`crate::proto::fmp`] ([`Fmp::establish_inbound`]/[`establish_outbound`],
//! [`Fmp::poll_timeouts`]/[`poll_resends`]/[`poll_rekey`]/[`poll_rekey_resends`],
//! and `cross_connection_winner`) — this module writes **no new decision
//! core** (R4). The machine only (a) builds the plain-data snapshots those cores
//! consume from its control-tier state, (b) maps the returned
//! [`ConnAction`]/[`InboundDecision`]/[`OutboundDecision`]/[`PromotionResult`]
//! into the [`PeerAction`] vocabulary the driver executes, and (c) advances its
//! own control state. Shell-side effects (the Noise wire step, `promote_connection`
//! registry surgery, late ACL `authorize_peer`, decrypt-worker register/unregister)
//! are **emitted as actions**, never performed here.
//!
//! ## Control / send-state split (§6 Core 3)
//!
//! The machine holds **control-tier** state only. The hot send-critical state
//! (the three epoch slots, transport target, connected-UDP handle, hot counters)
//! becomes `PeerSendState` in **C2** and is *not* built here; the machine emits
//! actions (`PromoteToActive`, `SwapSendState`, `RegisterDecryptSession`, …) that
//! the driver applies to the published send-state. `remote_epoch` is
//! establish-path-only, hence control-tier, and lives here.
//!
//! ## C1 realizability notes (see `design/step2-machine-spec.md` caveats)
//!
//! - `SendHandshake`/`SendRekey`/`SendLinkMessage` carry **opaque bytes**
//!   (`Vec<u8>`) — the driver applies outer wire framing / encryption. On the
//!   resend paths the bytes are the stored wire frame; on a fresh inbound msg2 /
//!   rekey msg2 they are the Noise payload the shell already produced
//!   ([`WireOutcome::msg2_payload`]). A fresh outbound msg1 has no bytes the
//!   control machine can build (the Noise step is shell-side), so it is emitted
//!   with an empty payload and a `C3b` note — that path is not exercised by the
//!   C1 tests.
//! - `SendLinkMessage { msg }` is opaque plaintext (there is **no** unifying
//!   `LinkMessage` type in the tree today — heartbeat is a bare `[0x51]` byte,
//!   while filter/tree/disconnect are distinct concrete types). The machine
//!   builds the real heartbeat and disconnect frames; filter/tree announce
//!   payloads are data-plane-owned and threaded in at C3b (empty here).
//! - `PeerSnapshot::counter` (the Noise send counter) is a send-state fact the
//!   control machine cannot see; it is passed as `0` (the message-count rekey
//!   trigger is threaded from `PeerSendState` at C4). Irrelevant to every C1
//!   test (cutover/drain ignore it).

#![allow(dead_code)]

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
// C1 is unwired; the real intervals come from `NodeConfig` when the driver is
// wired (C3b/C5). The `poll_*` cores already take the interval/backoff as
// arguments, so these are only used to compute `SetTimer{at_ms}` deadlines and
// the `Closed{backoff_deadline_ms}` park time. The unit tests assert on timer
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
// FSM types (spec §1)
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TimerKind {
    HandshakeRetransmit,
    HandshakeTimeout,
    RekeyCadence,
    RekeyResend,
    DrainExpiry,
    Liveness,
}

/// An input to the machine. Cross-registry facts ride in the payload as
/// plain-data snapshots ([`WireOutcome`]/[`EstablishSnapshot`]/[`OutboundSnapshot`])
/// built shell-side; `now` is the `step` parameter, never duplicated here.
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
    /// Data plane observed the responder K-bit flip inline (§3.7).
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
    /// pending a unifying `LinkMessage` type — C3b: type against
    /// `proto::bloom::FilterAnnounce` / `proto::stp::TreeAnnounce` /
    /// `proto::fmp::Disconnect` / a heartbeat marker.
    SendLinkMessage { msg: Vec<u8> },
    /// Crystallize identity, re-home the map key, publish send-state
    /// (`promote_connection`). Resolves to a [`PromotionResolved`](PeerEvent::PromotionResolved).
    PromoteToActive { link: LinkId },
    /// Initiator-side rekey cutover: swap the published send-state to the pending
    /// epoch.
    SwapSendState { epoch: [u8; 8] },
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
    /// deliberately no `ScheduleRetry` machine action).
    ReportLost { peer: NodeAddr },
}

// ============================================================================
// The machine (control tier — spec §2)
// ============================================================================

/// Per-peer control FSM. Holds control-tier lifecycle state only; the
/// send-critical state is published as `PeerSendState` (C2) and mutated via the
/// emitted [`PeerAction`]s.
pub(crate) struct PeerMachine {
    state: PeerState,
    link: LinkId,
    identity: Option<PeerIdentity>,
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
    // send-state slots (C2).
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
            conn: ConnectionState::outbound(link, identity, now),
            remote_epoch: None,
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
            conn: ConnectionState::inbound(link, now),
            remote_epoch: None,
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
                ..
            } => self.on_dial(transport_id, remote_addr, now),
            PeerEvent::TransportConnected => self.on_transport_connected(now),
            PeerEvent::TransportFailed => self.on_transport_failed(now),
            PeerEvent::InboundMsg1 { link, wire, est } => {
                self.on_inbound_msg1(link, wire, est, now, index_allocator)
            }
            PeerEvent::Msg2 { their_index, out } => {
                self.on_msg2(their_index, out, now, index_allocator)
            }
            PeerEvent::Authorized => Vec::new(),
            PeerEvent::Rejected => self.fail(FailReason::AclRejected),
            PeerEvent::PromotionResolved { result } => self.on_promotion_resolved(result, now),
            PeerEvent::RekeyMsg1 { wire, est } => {
                // A rekey msg1 is a msg1 on an established peer — same core.
                self.on_inbound_msg1(self.link, wire, est, now, index_allocator)
            }
            PeerEvent::RekeyMsg2 { their_index } => self.on_rekey_msg2(their_index),
            PeerEvent::PeerKbitFlip { .. } => {
                // Responder cutover is data-plane-owned (§3.7): the machine only
                // schedules the drain-window unregister. NO slot mutation.
                vec![PeerAction::SetTimer {
                    kind: TimerKind::DrainExpiry,
                    at_ms: now + DRAIN_WINDOW_MS,
                }]
            }
            PeerEvent::FilterAnnounce => vec![PeerAction::SendLinkMessage {
                // C3b: filter-announce payload is data-plane-owned; threaded in
                // at wiring time.
                msg: Vec::new(),
            }],
            PeerEvent::TreeAnnounceDue => vec![PeerAction::SendLinkMessage {
                // C3b: tree-announce payload is data-plane-owned.
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
    // Outbound establish (§3.1)
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
        // ones send msg1 immediately. C1 models the connection-oriented arm
        // (OpenTransport) — the reconciler's candidate carries the transport
        // kind at wiring time; connectionless dial reuses `start_handshake`.
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
    /// the driver when it executes this action; C1 emits an empty payload (see
    /// module note). This path is not exercised by the C1 tests.
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

    /// Outbound completion: classify via `establish_outbound` and drive the
    /// promote / cross-connection resolution.
    fn on_msg2(
        &mut self,
        their_index: SessionIndex,
        out: OutboundSnapshot,
        now: u64,
        _alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        self.conn.set_their_index(their_index);
        match Fmp::new().establish_outbound(&out) {
            OutboundDecision::Promote => {
                // Net-new: our outbound index (allocated at dial) is the one we
                // register once promotion resolves.
                self.our_index = self.conn.our_index();
                vec![PeerAction::PromoteToActive { link: self.link }]
            }
            OutboundDecision::CrossConnectionSwap => {
                // Our outbound wins: swap the peer to the outbound session,
                // freeing the old inbound index. Resolved in-step (peer exists).
                let outbound_index = self.conn.our_index();
                let old_inbound_index = self.our_index;
                self.crystallize(now);
                let mut actions = Vec::new();
                if let Some(idx) = old_inbound_index {
                    actions.push(PeerAction::FreeIndex { index: idx });
                }
                if let Some(idx) = outbound_index {
                    self.our_index = Some(idx);
                    actions.push(PeerAction::RegisterDecryptSession { index: idx });
                }
                actions
            }
            OutboundDecision::CrossConnectionKeep => {
                // Our outbound loses: keep the existing inbound session, free the
                // unused outbound index.
                let outbound_index = self.conn.our_index();
                self.crystallize(now);
                let mut actions = Vec::new();
                if let Some(idx) = outbound_index {
                    actions.push(PeerAction::FreeIndex { index: idx });
                }
                actions
            }
        }
    }

    // ------------------------------------------------------------------
    // Inbound establish (§3.2)
    // ------------------------------------------------------------------

    fn on_inbound_msg1(
        &mut self,
        link: LinkId,
        wire: WireOutcome,
        est: EstablishSnapshot,
        now: u64,
        alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        match Fmp::new().establish_inbound(&est, &wire) {
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
            InboundDecision::ResendMsg2 { msg2 } => match msg2 {
                Some(bytes) => vec![PeerAction::SendHandshake { bytes }],
                None => Vec::new(),
            },
            InboundDecision::RekeyRespond {
                peer,
                abandon_first,
            } => self.rekey_respond(peer, abandon_first, &wire, now, alloc),
            InboundDecision::RestartThenPromote { peer } => {
                let mut actions = vec![PeerAction::InvalidateSendState];
                if let Some(idx) = self.our_index.take() {
                    actions.push(PeerAction::UnregisterDecryptSession { index: idx });
                }
                actions.push(PeerAction::ReportLost { peer });
                actions.extend(self.inbound_promote(link, &wire, now, alloc));
                actions
            }
            InboundDecision::Promote => self.inbound_promote(link, &wire, now, alloc),
        }
    }

    /// The inbound Promote tail: allocate our index, record indices/epoch/msg2,
    /// emit msg2 + drive promotion. `RegisterDecryptSession` follows on the
    /// `PromotionResolved{Promoted}` feedback (§3.2 "then on PromotionResult").
    fn inbound_promote(
        &mut self,
        link: LinkId,
        wire: &WireOutcome,
        _now: u64,
        alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        self.identity = Some(wire.peer_identity);
        self.remote_epoch = wire.remote_epoch;
        self.conn.set_their_index(wire.their_index);
        let our_index = alloc.allocate().ok();
        if let Some(idx) = our_index {
            self.conn.set_our_index(idx);
            self.our_index = Some(idx);
        }
        self.conn.set_handshake_msg2(wire.msg2_payload.clone());
        self.state = PeerState::Handshaking {
            link,
            phase: HandshakePhase::ReceivedMsg1,
        };
        vec![
            PeerAction::SendHandshake {
                bytes: wire.msg2_payload.clone(),
            },
            PeerAction::PromoteToActive { link },
        ]
    }

    /// Rekey responder: (optionally) abandon our in-flight rekey, allocate a new
    /// index, send the rekey msg2, record the peer rekey (dampening).
    fn rekey_respond(
        &mut self,
        _peer: NodeAddr,
        abandon_first: bool,
        wire: &WireOutcome,
        now: u64,
        alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        let mut actions = Vec::new();
        if abandon_first {
            if let Some(idx) = self.rekey_our_index.take() {
                actions.push(PeerAction::FreeIndex { index: idx });
            }
            self.rekey_in_progress = false;
            self.rekey_msg1 = None;
        }
        let new_index = alloc.allocate().ok();
        if let Some(idx) = new_index {
            self.rekey_our_index = Some(idx);
        }
        actions.push(PeerAction::SendRekey {
            bytes: wire.msg2_payload.clone(),
        });
        self.last_peer_rekey_ms = now;
        let addr = self
            .addr()
            .unwrap_or_else(|| *wire.peer_identity.node_addr());
        self.state = PeerState::Maintaining {
            addr,
            kind: MaintainKind::Rekey(RekeyPhase::Msg1Sent),
        };
        actions
    }

    // ------------------------------------------------------------------
    // Promotion feedback (§3.3)
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
    // Rekey (initiator) + cutover (§3.4)
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
                self.state = PeerState::Active { addr: peer };
                let mut actions = Vec::new();
                if let Some(idx) = self.draining_index.take() {
                    actions.push(PeerAction::UnregisterDecryptSession { index: idx });
                    actions.push(PeerAction::FreeIndex { index: idx });
                }
                actions
            }
            ConnAction::InitiateRekey { peer } => {
                // Fresh outbound rekey: allocate our new index, send msg1 (Noise
                // leaf is shell-side → empty payload in C1), arm the resend timer.
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
    // Liveness (§3.5)
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
        if !self.is_active_like() {
            return Vec::new();
        }
        let mut actions = vec![PeerAction::InvalidateSendState];
        if let Some(idx) = self.our_index.take() {
            actions.push(PeerAction::UnregisterDecryptSession { index: idx });
        }
        actions.push(PeerAction::TeardownConnectedUdp);
        if let Some(peer) = self.addr() {
            actions.push(PeerAction::ReportLost { peer });
        }
        self.state = PeerState::Closed {
            backoff_deadline_ms: now + CLOSED_BACKOFF_MS,
        };
        actions
    }

    // ------------------------------------------------------------------
    // Timeout / teardown / close (§3.6)
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
        // FreeIndex{our_index}, emitting FreeIndex before ReportLost (§3.6).
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
        // re-enters the Timeout{kind} handlers. C1 is unwired; the deadline
        // bookkeeping is threaded from the driver at C5, so Tick is a no-op here.
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
    /// send-state fact (C4); passed as 0 here (see module note).
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
// Unit tests (spec §5) — assert on ACTION SEQUENCES + STATE transitions using
// hand-built synthetic snapshots (caveat #4: no real crypto sessions).
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
            // We win the tie-break: drop the peer's msg1, no rekey response.
            assert!(actions.is_empty());
            assert!(
                !actions
                    .iter()
                    .any(|a| matches!(a, PeerAction::SendRekey { .. }))
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
            // abandon_first -> FreeIndex(old rekey index) then SendRekey(msg2).
            assert_eq!(
                actions[0],
                PeerAction::FreeIndex {
                    index: SessionIndex::new(0x55)
                }
            );
            assert!(matches!(actions[1], PeerAction::SendRekey { .. }));
        }
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

        // Restart tail: invalidate, unregister old, report lost, then Promote.
        assert_eq!(actions[0], PeerAction::InvalidateSendState);
        assert_eq!(
            actions[1],
            PeerAction::UnregisterDecryptSession {
                index: SessionIndex::new(0xDEAD)
            }
        );
        assert_eq!(actions[2], PeerAction::ReportLost { peer: peer_addr });
        assert!(
            actions
                .iter()
                .any(|a| matches!(a, PeerAction::SendHandshake { .. }))
        );
        assert!(
            actions
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
        let wa = winner.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
                wire: wire_w,
                est: est_w,
            },
            100,
            &mut alloc,
        );
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
        let la = loser.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(2),
                wire: wire_l,
                est: est_l,
            },
            100,
            &mut alloc,
        );
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

        let mut actions = m.step(
            PeerEvent::InboundMsg1 {
                link: LinkId::new(1),
                wire,
                est,
            },
            200,
            &mut alloc,
        );
        actions.extend(m.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::Promoted(peer_addr),
            },
            200,
            &mut alloc,
        ));

        // Combined promote sequence (§3.2 "then on PromotionResult ...").
        assert!(matches!(actions[0], PeerAction::SendHandshake { .. }));
        assert_eq!(
            actions[1],
            PeerAction::PromoteToActive {
                link: LinkId::new(1)
            }
        );
        assert!(matches!(
            actions[2],
            PeerAction::RegisterDecryptSession { .. }
        ));
        assert_eq!(m.state(), PeerState::Established { addr: peer_addr });
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
            vec![PeerAction::PromoteToActive {
                link: LinkId::new(1)
            }]
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

        // Cross-connection SWAP: our outbound wins -> free old inbound, register outbound.
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
            vec![
                PeerAction::FreeIndex {
                    index: SessionIndex::new(0x1111)
                },
                PeerAction::RegisterDecryptSession {
                    index: SessionIndex::new(0x2222)
                },
            ]
        );
        assert_eq!(m2.state(), PeerState::Established { addr: peer_addr });

        // Cross-connection KEEP: our outbound loses -> free unused outbound index.
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
            vec![PeerAction::FreeIndex {
                index: SessionIndex::new(0x3333)
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
                PeerAction::UnregisterDecryptSession {
                    index: SessionIndex::new(0x4242)
                },
                PeerAction::TeardownConnectedUdp,
                PeerAction::ReportLost { peer: addr },
            ]
        );
        assert!(matches!(m.state(), PeerState::Closed { .. }));
        // The exact action-sequence equality above is the "no ScheduleRetry"
        // guarantee: loss is reported only via ReportLost, and no retry-schedule
        // action exists in the PeerAction vocabulary at all (reconciler-owned).
    }
}
