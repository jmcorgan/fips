//! Per-peer FMP control FSM (sans-IO reducer) — XX re-derivation.
//!
//! The unified per-peer lifecycle state machine, ported onto next's XX cores
//! from the IK-lineage template. It provides the FSM types, the machine struct
//! (control-tier state only), and the pure `step` reducer, plus its unit
//! tests. `step` is driven in production by the handshake handlers (msg2 on
//! the dial-persisted machine; msg3 on the leg's machine born at msg1), the
//! liveness-reap router, and the dial/lifecycle paths, with
//! the executor in `crate::node::dataplane::peer_actions` performing the
//! returned actions. Still dormant: `PeerEvent::Timeout` and
//! `PeerEvent::InboundMsg1` are never dispatched — timer FIRING decisions stay
//! with the shell drivers, and `handle_msg1` sends msg2 inline.
//!
//! ## Shape
//!
//! `step(event, now, index_allocator) -> Vec<PeerAction>` is a **pure reducer**:
//! every lifecycle *decision* is delegated to the existing sans-IO cores in
//! [`crate::proto::fmp`] ([`Fmp::establish_inbound`], `establish_outbound`,
//! `poll_timeouts` and `poll_resends`) — this module writes **no new decision
//! core**. A link's rekeys are not modelled here: the active peer's link rekey
//! machine holds them. The machine only (a) builds
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
//! moves a `NoiseSession` and its index lease from a handshake carrier to an
//! `ActivePeer` (`take_session`/`move_session`) — effects that cannot ride in
//! a plain-data [`PeerAction`]. The machine owns only the *classification
//! dispatch* + the index-plane facts; it emits a plain-data trigger
//! ([`ResolveInboundCrossConnection`](PeerAction::ResolveInboundCrossConnection)) carrying the
//! leg's index + the tie-break flag, and the executor performs the
//! session/registry move shell-side. A msg3 declaring a rekey of the peer's
//! link ([`PeerRekey`](InboundDecision::PeerRekey)) leaves the leg's read
//! completion, with the lease on its index, on the leg for the shell to hand to
//! the peer's link rekey machine.
//!
//! The outbound completion is routed through the machine the same way:
//! `handle_msg2` crystallizes the learned identity, builds an
//! [`OutboundSnapshot`], and steps the persistent machine once; the machine
//! computes the establish decision via `establish_outbound`. A net-new
//! completion promotes through [`PromoteToActive`](PeerAction::PromoteToActive)
//! (the executor feeds the outcome back via
//! [`PromotionResolved`](PeerEvent::PromotionResolved)), while a
//! cross-connection resolves as a
//! [`ResolveCrossConnection`](PeerAction::ResolveCrossConnection) decision the
//! shell intercepts — its inline Swap/Keep bodies mutate the already-promoted
//! peer, for which no `PeerAction` exists.
//!
//! ## Realizability notes
//!
//! - `SendHandshake`/`SendLinkMessage` carry **opaque bytes**
//!   (`Vec<u8>`); the driver applies outer wire framing / encryption. A fresh
//!   outbound msg1 and a fresh inbound msg2 have no bytes the control machine can
//!   build (the Noise step / `build_msg2` are shell-side), so they are emitted
//!   with an empty payload and threaded at wiring time. Not exercised by the
//!   tests (which assert on action *kinds* / index-plane facts).

#![allow(dead_code)]

use crate::identity::ErasingKeypair;
use crate::identity::OsEntropy;
use crate::noise::{self, NoiseError, NoiseSession};
use crate::proto::fmp::{
    ConnAction, ConnSnapshot, ConnectionState, DialMsg2Decision, DialMsg2Reject, EstablishSnapshot,
    Fmp, InboundDecision, NodeProfile, OutboundDecision, OutboundSnapshot, PromotionResult,
    WireOutcome,
};
use crate::proto::link::LinkMessageType;
use crate::transport::{LinkDirection, LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::{IndexAllocator, SessionIndex};
use crate::{NodeAddr, PeerIdentity};
use fips_core::proto::fmp::rekey::{Unread, read_final};
use fips_core::proto::rekey::{IndexLease, allocate};
use secp256k1::Keypair;

/// A peer's msg3 as an inbound leg read it: the session it completed, the
/// initiator's identity, startup epoch and negotiation payload, and the lease
/// on the leg's index.
pub(crate) type LinkFinal = fips_core::proto::fmp::rekey::Final<OsEntropy>;

/// Why [`PeerMachine::read_final`] did not complete the leg.
#[derive(Debug, thiserror::Error)]
pub(crate) enum Msg3Error {
    /// The msg3 or its negotiation payload did not authenticate. The leg is
    /// unchanged: the read ran on a fork, and its handshake and the lease on
    /// its index are kept for the genuine msg3.
    #[error("unreadable msg3")]
    Unreadable,
    /// The leg had no handshake to read with, or a step after a successful
    /// read failed. The leg's handshake is consumed.
    #[error(transparent)]
    Failed(#[from] NoiseError),
}

/// How an initiator's initial msg2 ended, when the dial attempt can continue.
///
/// Only [`Completed`](Self::Completed) consumes the leg's handshake. The other
/// two leave the leg exactly as it was before the msg2 was read, so the
/// genuine msg2 can still complete the attempt.
#[derive(Debug)]
pub(crate) enum DialMsg2Step {
    /// The dial-identity decision accepted the msg2: msg3 is written, the
    /// handshake has become the leg's session, and the learned identity and
    /// epoch are on the carrier. Carries the msg3 bytes and the decrypted
    /// negotiation payload from msg2, if it had one.
    Completed(Vec<u8>, Option<Vec<u8>>),
    /// The msg2 read, and the dial-identity decision rejected the static it
    /// carries. `learned_peer` is the address that static derives to.
    Rejected {
        reason: DialMsg2Reject,
        learned_peer: NodeAddr,
    },
    /// The msg2 did not read or its negotiation payload did not decrypt.
    Unreadable(NoiseError),
}

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
// `LIVENESS_INTERVAL_MS` below is a placeholder pinned to today's
// `NodeConfig` default. It is not a wiring to the config: nothing here reads
// a config value, so an operator override is not tracked. The tie to the
// default is asserted by
// `liveness_interval_matches_the_heartbeat_config_default` rather than stated
// in this declaration, because `Default for NodeConfig` is an ordinary impl
// and cannot be called from a `const` initializer.
const LIVENESS_INTERVAL_MS: u64 = 10_000;
const CLOSED_BACKOFF_MS: u64 = 5_000;

// ============================================================================
// FSM types
// ============================================================================

/// The unified per-peer lifecycle state (subsumes today's `HandshakeState`
/// and `ConnectivityState`). Keyed by `LinkId` until
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
    /// A maintenance sub-machine is running (liveness / mtu).
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

/// Map a lifecycle state to the operator-visible pending-connection handshake
/// string. Total over `PeerState`; byte-identical to the strings the deleted
/// leg `HandshakeState` `Display` produced for every (leg, machine) pairing that
/// rests in the pending-connection view. On XX three arms are
/// production-reachable in that view (verified against the pre-collapse leg
/// display):
/// - `Handshaking{SentMsg1}` → `"sent_msg1"` (outbound identified leg).
/// - `Handshaking{SentMsg2}` → `"received_msg1"` (the inbound responder leg,
///   which parks at `SentMsg2` after replying to msg1 while the deleted leg
///   phase displayed `received_msg1` — a direction-aware synthesis with no leg
///   twin).
/// - `Discovered` → `"sent_msg1"` (GAP A: the anonymous-outbound leg rests with
///   its machine parked at `Discovered` while its leg is already at `SentMsg1`;
///   the anon path sends msg1 inline and dispatches no handshake-start event, so
///   advancing the machine to `Handshaking{SentMsg1}` here would arm a retransmit
///   timer the anon leg does not have — the overload is the neutral choice).
///
/// The `send_failed` → `"failed"` override is applied by the caller
/// ([`displayed_handshake_state`](PeerMachine::displayed_handshake_state)). The
/// remaining arms are kept total for a complete mapping and are not reachable in
/// the view.
fn handshake_state_str(state: PeerState) -> &'static str {
    match state {
        PeerState::Handshaking {
            phase: HandshakePhase::Initial,
            ..
        } => "initial",
        PeerState::Handshaking {
            phase: HandshakePhase::SentMsg1,
            ..
        } => "sent_msg1",
        PeerState::Handshaking {
            phase: HandshakePhase::SentMsg2,
            ..
        } => "received_msg1",
        // GAP A: the anonymous-outbound leg rests in the view with its machine
        // parked at `Discovered` while the leg itself is at `SentMsg1`, so it
        // displayed `"sent_msg1"` before the collapse. The only in-view
        // `Discovered`-with-leg case is this anon leg (identified dials leave
        // `Discovered` atomically within their handler before any tick), so the
        // overload preserves display parity byte-for-byte.
        PeerState::Discovered => "sent_msg1",
        PeerState::Established { .. }
        | PeerState::Active { .. }
        | PeerState::Maintaining { .. }
        | PeerState::Closing { .. } => "complete",
        PeerState::Failed { .. } => "failed",
        PeerState::Connecting { .. } | PeerState::Closed { .. } => "initial",
    }
}

/// Which maintenance sub-machine `Maintaining` is running.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MaintainKind {
    Liveness(LivenessPhase),
    Mtu,
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
///
/// An event is built for one `step` and consumed by it, never stored, so the
/// inbound msg1's snapshot payload is carried inline rather than boxed. The
/// enum is the size it was when a second variant (the established peer's
/// msg1, now the link rekey machine's) carried the same payload.
#[allow(clippy::large_enum_variant)]
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
    /// Inbound handshake msg1 processed shell-side: allocate our index and reply
    /// with msg2, deferring identity/classification to msg3. Carries no identity
    /// or wire outcome — on XX neither is known at msg1.
    InboundMsg1 { link: LinkId },
    /// Inbound handshake msg3 completed (Noise finalized, identity crystallized
    /// shell-side, ACL already gated). Drives the establish classification. Used
    /// for both a fresh inbound establish and a rekey msg3 on an established peer.
    /// The leg's index is the lease this machine took at msg1.
    InboundMsg3 {
        wire: WireOutcome,
        est: EstablishSnapshot,
    },
    /// Outbound handshake msg2 completed (Noise finalized, identity crystallized
    /// onto the machine shell-side, ACL already gated, msg3 sent). Carries the
    /// shell-built [`OutboundSnapshot`]; the machine computes the establish
    /// decision from it — a net-new promote, or a cross-connection swap/keep
    /// conveyed as [`ResolveCrossConnection`](PeerAction::ResolveCrossConnection).
    /// `their_index` carries the peer's session index for shape parity with the
    /// inbound path.
    OutboundMsg2 {
        their_index: SessionIndex,
        out: OutboundSnapshot,
    },
    /// `promote_connection` resolved the [`PromoteToActive`](PeerAction::PromoteToActive)
    /// action shell-side; the machine consumes the outcome (it does not
    /// re-decide the tie-break).
    PromotionResolved { result: PromotionResult },
    /// OBSERVATION: the shell resolved an outbound cross-connection inline (a
    /// session swap or keep, with the registry and index surgery already
    /// applied). Reconciles the control shadow's peer index with reality on a
    /// swap; leaves it untouched on a keep. Emits no action.
    CrossConnResolved { outcome: CrossConnOutcome },
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
    /// Transmit an (encrypted) plaintext link-control frame. Opaque `Vec<u8>`
    /// pending a unifying `LinkMessage` type.
    SendLinkMessage { msg: Vec<u8> },
    /// Crystallize identity, re-home the map key, publish send-state
    /// (`promote_connection`). Resolves to a [`PromotionResolved`](PeerEvent::PromotionResolved).
    PromoteToActive { link: LinkId },
    /// A DECISION conveyed to the driver, not an effect: emitted by the
    /// outbound-msg2 arm when the establish decision is a cross-connection
    /// resolution. The shell intercepts it and runs the inline swap/keep
    /// resolution; it must never reach the action executor.
    ResolveCrossConnection { swap: bool },
    /// Invalidate the published send-state (close/loss).
    InvalidateSendState,
    /// Register a decrypt-worker entry for `index`.
    RegisterDecryptSession { index: SessionIndex },
    /// Unregister the decrypt-worker entry for `index`.
    UnregisterDecryptSession { index: SessionIndex },
    /// Free `index` back to the shared allocator.
    FreeIndex { index: SessionIndex },
    /// XX inbound cross-connection resolved at msg3 (a plain-data TRIGGER — the
    /// session move is a shell effect). When `our_inbound_wins` (larger
    /// NodeAddr) the executor moves the peer onto the leg's session and the
    /// lease on its index `our_index`, which closes the peer's link machine
    /// and releases what it held; otherwise it releases the leg's lease and
    /// keeps the outbound session. Either way the temporary inbound link is
    /// torn down.
    ResolveInboundCrossConnection {
        peer: NodeAddr,
        our_index: SessionIndex,
        our_inbound_wins: bool,
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

/// The handshake operations are only reachable while a pending connection is
/// attached; every path that drives the crypto attaches it first.
fn no_pending_connection() -> NoiseError {
    NoiseError::WrongState {
        expected: "attached connection".to_string(),
        got: "no connection".to_string(),
    }
}

/// The handshake-phase Noise crypto, owned by the control machine.
///
/// PRESENCE OF THIS STRUCT (`PeerMachine::leg().is_some()`) IS THE
/// HANDSHAKE-PHASE CARRIER SIGNAL — it is what `Node::connections()`,
/// `connection_count()`, the stale-connection sweep, the transport-in-use
/// check, and the peering budget all key on. It is attached and detached at
/// exactly the points the pending connection was, and its presence is NOT a
/// function of whether either handle is populated.
///
/// A present-but-empty value is legal and load-bearing: `mark_failed` drops
/// the initiation handle while deliberately retaining the carrier so the
/// sweep can reclaim it, and `take_session` empties the other. Deriving
/// presence from handle presence would make every failed handshake invisible
/// to the sweep — a permanent leak. See the presence tests in this module.
pub(crate) struct HandshakeCrypto {
    /// Noise handshake state (consumed on completion).
    pub(crate) noise_handshake: Option<noise::HandshakeState>,
    /// Completed Noise session (available once the handshake completes).
    pub(crate) noise_session: Option<NoiseSession>,
    /// An inbound leg's msg3 read, held until the establish decision says
    /// whether it is a link setup (its session and lease settle onto the
    /// leg) or a rekey of a peer's link (it goes to that peer's machine).
    pub(crate) fin: Option<LinkFinal>,
}

impl HandshakeCrypto {
    /// A fresh carrier holding neither handle, as every handshake begins.
    pub(crate) fn new() -> Self {
        Self {
            noise_handshake: None,
            noise_session: None,
            fin: None,
        }
    }
}

impl std::fmt::Debug for HandshakeCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandshakeCrypto")
            .field("has_noise_handshake", &self.noise_handshake.is_some())
            .field("has_noise_session", &self.noise_session.is_some())
            .field("has_fin", &self.fin.is_some())
            .finish()
    }
}

/// Where an outbound dial's expectation of its peer came from.
///
/// A transport neighbour's key claim (a BLE or Ethernet beacon naming a key)
/// is unproven until the handshake completes, and anyone in radio or link
/// range can make one. The per-node gates count a claim leg only against
/// other claims, so claims cannot hold back the node's configured address,
/// LAN advert or redial. Set at the dial site and carried by the machine for
/// the whole dial, across the pending-connect to handshake-leg hand-off.
///
/// On this line no transport beacon names a key: every transport neighbour
/// is dialled anonymously and is marked `NeighbourClaim` for where it came
/// from, though it claims no identity until its msg2.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) enum DialOrigin {
    /// The address was held for the peer: configuration, a LAN or overlay
    /// advert, a retry, a traversal handoff. Also every inbound machine.
    #[default]
    Addressed,
    /// A transport neighbour claimed the peer's key.
    NeighbourClaim,
}

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
    /// The handshake-phase Noise crypto this machine owns while it is in the
    /// handshake window. `None` before the handshake begins (the dial window)
    /// and after promotion consumes it (the machine survives as the active
    /// peer's control machine). Its presence — not the state of the handles
    /// inside it — is what marks this machine as carrying a pending
    /// handshake; see [`HandshakeCrypto`].
    leg: Option<HandshakeCrypto>,
    /// Pure handshake-phase bookkeeping (link/direction/indices/transport/
    /// stored handshake bytes/epoch). Reused verbatim from the FMP state core.
    conn: ConnectionState,
    /// A stored-handshake send failure was observed on this leg. The failure is
    /// carried as a flag (not a `PeerState::Failed` transition) so retransmit
    /// eligibility (`is_handshaking_sent_msg1`) survives until the
    /// stale-connection sweep reclaims the leg. It drives both `is_failed`
    /// (reaping) and the displayed handshake state (`"failed"`), reproducing the
    /// pre-collapse leg `is_failed`/display signal byte-for-byte.
    send_failed: bool,

    // --- timing (control tier) ---
    last_heartbeat_sent_ms: u64,

    /// Where this machine's dial came from; see [`DialOrigin`].
    origin: DialOrigin,
}

impl PeerMachine {
    /// New outbound machine (we dial). Starts at `Discovered`; the reconciler's
    /// `Dial` event drives the first transition. `identity` is `None` for an
    /// anonymous-discovery leg (a shared-media beacon carries no identity): the
    /// machine is born identity-less and [`crystallize_identity`]
    /// (Self::crystallize_identity) fills it in when the XX msg2 reveals who
    /// answered.
    pub(crate) fn new_outbound(link: LinkId, identity: Option<PeerIdentity>, now: u64) -> Self {
        Self {
            state: PeerState::Discovered,
            link,
            identity,
            node_addr: identity.map(|id| *id.node_addr()),
            leg: None,
            conn: match identity {
                Some(id) => ConnectionState::outbound(link, id, now),
                None => ConnectionState::outbound_anonymous(link, now),
            },
            send_failed: false,
            last_heartbeat_sent_ms: 0,
            origin: DialOrigin::Addressed,
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
            leg: None,
            conn: ConnectionState::inbound(link, now),
            send_failed: false,
            last_heartbeat_sent_ms: 0,
            origin: DialOrigin::Addressed,
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
    pub(crate) fn inbound_msg2_sent(link: LinkId, our_index: IndexLease, now: u64) -> Self {
        let mut machine = Self::new_inbound(link, now);
        machine.park_inbound_msg2_sent(our_index);
        machine
    }

    /// Park an inbound machine at `Handshaking{SentMsg2}`, holding the lease
    /// on the index it allocated. The msg1-inline path builds its machine
    /// above the crypto (the Noise step runs on the machine) and so cannot use
    /// the birth ctor, which needs an index that does not exist until after
    /// the crypto; this applies the same transition to the machine already in
    /// hand. A lease already held is released into nothing: an inbound leg is
    /// parked once, before it holds one.
    pub(crate) fn park_inbound_msg2_sent(&mut self, our_index: IndexLease) {
        let held = self.conn.set_our_index(our_index);
        debug_assert!(held.is_none(), "an inbound leg is parked once");
        self.state = PeerState::Handshaking {
            link: self.link,
            phase: HandshakePhase::SentMsg2,
        };
    }

    /// Current lifecycle state.
    pub(crate) fn state(&self) -> PeerState {
        self.state
    }

    /// The handshake crypto carrier, if this machine is still in the
    /// handshake window. Presence answers "is there a pending handshake
    /// here", independently of whether either handle is populated.
    pub(crate) fn leg(&self) -> Option<&HandshakeCrypto> {
        self.leg.as_ref()
    }

    /// Take the handshake crypto carrier off the machine (promotion and
    /// teardown consume it by value).
    pub(crate) fn take_leg(&mut self) -> Option<HandshakeCrypto> {
        // On promotion the machine lives on as the peer's control machine, so
        // the slot is cleared as the leg leaves, or it would keep the session's
        // traffic keys. Callers unwrap the result at once, which `take_cleared`
        // warns may leave a second stack copy; clearing here still covers every
        // caller's heap slot, and a stack copy is a move like any other.
        noise::take_cleared(&mut self.leg)
    }

    /// Attach a handshake crypto carrier to the machine.
    pub(crate) fn set_leg(&mut self, leg: HandshakeCrypto) {
        self.leg = Some(leg);
    }

    // === Noise handshake operations ===
    //
    // Mechanism, not decision: these are called by the shell, are never
    // reached from `step()`, and no event triggers them. Each drives the
    // Noise crypto on the pending connection and records the results on both
    // that connection and the surviving carrier, so a reader of either sees
    // the same value at the same point.

    /// Start the handshake as initiator and generate message 1.
    ///
    /// For outbound connections only. Returns the Noise XX msg1 bytes.
    /// XX msg1 is ephemeral-only (33 bytes) — no identity or epoch.
    pub(crate) fn start_handshake(
        &mut self,
        mut our_keypair: Keypair,
        epoch: [u8; 8],
        current_time_ms: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        // The parameter is this frame's own copy of the node's long-term
        // private key, and the state checks below return before it is used.
        // The guard clears it in place on every exit path, and makes no copy
        // of its own for an early return to leave behind.
        let our_keypair = ErasingKeypair::new(&mut our_keypair);

        let msg1 = {
            let direction = self.conn.direction();
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;

            if direction != LinkDirection::Outbound {
                return Err(NoiseError::WrongState {
                    expected: "outbound connection".to_string(),
                    got: "inbound connection".to_string(),
                });
            }

            // XX initiator: no remote static needed upfront, so an anonymous
            // dial (no expected identity) is a first-class case rather than an
            // error. The old `!= Initial` phase guard is dropped — this method
            // creates the Noise handshake handle, so there is no
            // `take().expect()` to protect, and its Err path was unreachable in
            // production (one call per fresh outbound handshake).
            let mut kp = *our_keypair.get();
            let mut hs = noise::HandshakeState::new_initiator(kp);
            kp.non_secure_erase();
            hs.set_local_epoch(epoch);
            let msg1 = hs.write_message_1()?;

            leg.noise_handshake = Some(hs);

            msg1
        };
        self.conn.touch(current_time_ms);

        Ok(msg1)
    }

    /// Initialize responder and process incoming message 1.
    ///
    /// For inbound connections only. Returns the Noise XX msg2 bytes.
    /// XX: identity is NOT learned from msg1 (only ephemeral exchange).
    /// The responder learns the initiator's identity from msg3.
    ///
    /// If `negotiation_payload` is provided, it is encrypted and appended
    /// to the returned msg2 bytes.
    pub(crate) fn receive_handshake_init(
        &mut self,
        mut our_keypair: Keypair,
        epoch: [u8; 8],
        message: &[u8],
        negotiation_payload: Option<&[u8]>,
        current_time_ms: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        // Same as `start_handshake`: the parameter copy outlives two early
        // returns, so the guard clears it in place rather than an erase per
        // exit path.
        let our_keypair = ErasingKeypair::new(&mut our_keypair);

        let msg2 = {
            let direction = self.conn.direction();
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;

            if direction != LinkDirection::Inbound {
                return Err(NoiseError::WrongState {
                    expected: "inbound connection".to_string(),
                    got: "outbound connection".to_string(),
                });
            }

            let mut kp = *our_keypair.get();
            let mut hs = noise::HandshakeState::new_responder(kp);
            kp.non_secure_erase();
            hs.set_local_epoch(epoch);

            // Process XX message 1 (ephemeral only — no identity learned)
            hs.read_message_1(message)?;

            // Generate XX message 2 (sends our static + epoch)
            let mut msg2 = hs.write_message_2()?;

            // Append encrypted negotiation payload if provided
            if let Some(payload) = negotiation_payload {
                let encrypted = hs.encrypt_payload(payload)?;
                msg2.extend_from_slice(&encrypted);
            }

            // XX: handshake NOT complete yet — need msg3. Keep the Noise
            // handshake handle for `complete_handshake_msg3()`; the phase
            // (formerly `ReceivedMsg1`) lives on this machine, so no phase is
            // set here. The handle's presence is the crypto-local
            // `ReceivedMsg1` signal.
            leg.noise_handshake = Some(hs);

            msg2
        };
        self.conn.touch(current_time_ms);

        Ok(msg2)
    }

    /// Complete the handshake by processing message 2 and generating message 3.
    ///
    /// For outbound connections only (initiator). Reads the responder's msg2
    /// (learning their identity and epoch), decrypts its negotiation payload if
    /// present, and asks `decide` whether the identity that answered may
    /// complete this dial. Only on [`Accept`](DialMsg2Decision::Accept) is the
    /// handshake taken: msg3 is written (with `negotiation_payload` encrypted
    /// and appended, if given), the handshake becomes the leg's session, and
    /// the learned identity and epoch land on the carrier.
    ///
    /// Nothing authenticates a msg2 before this read, and the index it names
    /// travels in cleartext in our msg1, so the message may be a forgery.
    /// Under XX it may also read correctly and still not be from the peer we
    /// dialed: any keyed node that saw the msg1 can answer it under its own
    /// static. A msg2 that does not read, whose payload does not decrypt, or
    /// whose static `decide` rejects puts the handshake back in its pre-read
    /// state and returns [`Unreadable`](DialMsg2Step::Unreadable) or
    /// [`Rejected`](DialMsg2Step::Rejected). The carrier is not touched: its
    /// expected identity stays the dialed one, and neither the epoch nor the
    /// last activity moves, so the attempt keeps its resend schedule and its
    /// deadline. `Err` means the leg cannot continue: it had no handshake to
    /// read with, or completing an accepted msg2 failed after the handshake
    /// was taken.
    ///
    /// The machine does not decide whether the identity that answered may be
    /// admitted as the one dialed; the caller supplies that decision, taken
    /// against the FMP core, and this runs it before anything is consumed. On
    /// an anonymous leg the decision accepts any answer, and the learned
    /// identity written here is the only way the carrier gets one. The dial
    /// intent sits untouched in `conn_dialed_identity`.
    pub(crate) fn complete_handshake(
        &mut self,
        message: &[u8],
        negotiation_payload: Option<&[u8]>,
        current_time_ms: u64,
        decide: impl FnOnce(NodeAddr) -> DialMsg2Decision,
    ) -> Result<DialMsg2Step, NoiseError> {
        let (msg3, received_negotiation, learned_identity, remote_epoch) = {
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;

            // The connection is at `SentMsg1` iff its Noise handshake handle is
            // present (set by `start_handshake`, taken here on completion).
            let Some(hs) = leg.noise_handshake.as_ref() else {
                return Err(NoiseError::WrongState {
                    expected: "sent_msg1 state".to_string(),
                    got: "no active handshake".to_string(),
                });
            };

            // Read XX msg2 (learning the responder's identity and epoch) and
            // any negotiation payload after it on a fork. A read that fails,
            // and an answer `decide` refuses, drop the fork and leave the
            // handshake as it was for the genuine msg2.
            let (fork, received_negotiation) = match hs.fork_msg2(message) {
                Ok(read) => read,
                Err(e) => return Ok(DialMsg2Step::Unreadable(e)),
            };

            // Learn responder identity from msg2
            let Some(remote_static) = fork.remote_static().copied() else {
                return Ok(DialMsg2Step::Unreadable(NoiseError::WrongState {
                    expected: "remote static learned from msg2".to_string(),
                    got: "no remote static".to_string(),
                }));
            };
            let learned_identity = PeerIdentity::from_pubkey_full(remote_static);
            let learned_peer = *learned_identity.node_addr();

            if let DialMsg2Decision::Reject { reason } = decide(learned_peer) {
                return Ok(DialMsg2Step::Rejected {
                    reason,
                    learned_peer,
                });
            }

            // Capture remote epoch from msg2
            let remote_epoch = fork.remote_epoch();

            // Commit to the fork. The slot is heap memory that outlives this
            // call; clearing it once the handshake has left keeps both private
            // keys from staying there.
            drop(leg.noise_handshake.take());
            noise::clear_slot(&mut leg.noise_handshake);
            let mut hs = fork;

            // Generate XX msg3
            let mut msg3 = hs.write_message_3()?;

            // Append encrypted negotiation payload if provided
            if let Some(payload) = negotiation_payload {
                let encrypted = hs.encrypt_payload(payload)?;
                msg3.extend_from_slice(&encrypted);
            }

            // Handshake complete for initiator
            let session = hs.into_session()?;
            leg.noise_session = Some(session);

            (msg3, received_negotiation, learned_identity, remote_epoch)
        };
        self.conn.set_expected_identity(learned_identity);
        self.conn.set_remote_epoch(remote_epoch);
        self.conn.touch(current_time_ms);

        Ok(DialMsg2Step::Completed(msg3, received_negotiation))
    }

    /// [`complete_handshake`](Self::complete_handshake) with a decision that
    /// accepts whoever answered, for tests that drive a genuine handshake by
    /// hand. `Completed` maps to `Ok`; a msg2 that does not complete the
    /// handshake maps to `Err`.
    #[cfg(test)]
    pub(crate) fn complete_handshake_accepting(
        &mut self,
        message: &[u8],
        negotiation_payload: Option<&[u8]>,
        current_time_ms: u64,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), NoiseError> {
        match self.complete_handshake(message, negotiation_payload, current_time_ms, |_| {
            DialMsg2Decision::Accept
        })? {
            DialMsg2Step::Completed(msg3, negotiation) => Ok((msg3, negotiation)),
            DialMsg2Step::Unreadable(e) => Err(e),
            DialMsg2Step::Rejected { learned_peer, .. } => Err(NoiseError::WrongState {
                expected: "an accepted msg2".to_string(),
                got: format!("a msg2 from {learned_peer} rejected"),
            }),
        }
    }

    /// Read the initiator's framed `msg3` on this inbound leg.
    ///
    /// The read runs on a fork of the leg's responder handshake
    /// (`fmp::rekey::read_final`), so a msg3 that does not authenticate, or
    /// whose negotiation payload does not decrypt, returns
    /// [`Msg3Error::Unreadable`] and leaves the leg exactly as it was: its
    /// handshake and the lease on its index are kept for the genuine msg3,
    /// and its carrier is not touched, so a spray cannot push out its reap
    /// deadline. Nothing ties a msg3 to the leg before the read except the
    /// receiver index, which travels in cleartext in msg2's header.
    ///
    /// On success the handshake is consumed and the read, holding the
    /// session, the initiator's identity, epoch and payload and the leg's
    /// lease, stays on the leg ([`final_read`](Self::final_read)) until the
    /// establish decision settles it; the learned identity and epoch land on
    /// the carrier.
    pub(crate) fn read_final(
        &mut self,
        msg3: &[u8],
        current_time_ms: u64,
    ) -> Result<(), Msg3Error> {
        let (learned_identity, remote_epoch) = {
            let leg = self.leg.as_mut().ok_or_else(no_pending_connection)?;
            // The responder holds its handshake from msg1 until msg3.
            let Some(hs) = leg.noise_handshake.as_ref() else {
                return Err(NoiseError::WrongState {
                    expected: "received_msg1 state".to_string(),
                    got: "no active handshake".to_string(),
                }
                .into());
            };
            let lease = self.conn.take_our_index();
            let fin = match read_final(hs, msg3, lease) {
                Ok(fin) => fin,
                Err(Unread(lease)) => {
                    if let Some(lease) = lease {
                        let _ = self.conn.set_our_index(lease);
                    }
                    return Err(Msg3Error::Unreadable);
                }
            };
            // Cleared as on the initiator's msg2 path: under XX the responder
            // holds its handshake in this heap slot until msg3.
            drop(leg.noise_handshake.take());
            noise::clear_slot(&mut leg.noise_handshake);
            let learned_identity = PeerIdentity::from_pubkey_full(*fin.remote());
            let remote_epoch = fin.epoch();
            leg.fin = Some(fin);
            (learned_identity, remote_epoch)
        };
        self.conn.set_expected_identity(learned_identity);
        self.conn.set_remote_epoch(Some(remote_epoch));
        self.conn.touch(current_time_ms);
        Ok(())
    }

    /// The leg's msg3 read, while the establish decision has not settled it.
    pub(crate) fn final_read(&self) -> Option<&LinkFinal> {
        self.leg.as_ref()?.fin.as_ref()
    }

    /// Take the leg's msg3 read off it, for a rekey of a peer's link: the
    /// read and the lease it carries go to that peer's link rekey machine.
    pub(crate) fn take_final(&mut self) -> Option<LinkFinal> {
        self.leg.as_mut()?.fin.take()
    }

    /// Settle the leg's msg3 read as a link setup: its session becomes the
    /// leg's completed session and its lease the carrier's index, as the
    /// promotion and the cross-connection move read them. A no-op without a
    /// read.
    pub(crate) fn settle_setup(&mut self) {
        let Some(fin) = self.leg.as_mut().and_then(|leg| leg.fin.take()) else {
            return;
        };
        let (session, lease) = fin.into_setup();
        if let Some(leg) = self.leg.as_mut() {
            leg.noise_session = Some(session);
        }
        if let Some(lease) = lease {
            let held = self.conn.set_our_index(lease);
            debug_assert!(
                held.is_none(),
                "a leg's lease is on its read or its carrier"
            );
        }
    }

    /// Complete the responder handshake by reading the bare Noise `msg3`
    /// (no link header) and settling it as a link setup, returning the
    /// decrypted negotiation payload. For tests that drive a genuine
    /// handshake by hand: the msg3 is framed with zero indices and read as
    /// [`read_final`](Self::read_final) reads a framed one.
    #[cfg(test)]
    pub(crate) fn complete_handshake_msg3(
        &mut self,
        message: &[u8],
        current_time_ms: u64,
    ) -> Result<Option<Vec<u8>>, Msg3Error> {
        let zero = SessionIndex::new(0);
        let framed = crate::proto::fmp::wire::build_msg3(zero, zero, message);
        self.read_final(&framed, current_time_ms)?;
        let payload = self
            .final_read()
            .and_then(|fin| fin.payload().map(<[u8]>::to_vec));
        self.settle_setup();
        Ok(payload)
    }

    /// Take the completed Noise session.
    ///
    /// Returns the NoiseSession for use in ActivePeer. Can only be called
    /// once after the handshake completes.
    pub(crate) fn take_session(&mut self) -> Option<NoiseSession> {
        // The session exists iff the handshake reached `Complete`, so taking it
        // unconditionally is byte-equivalent to the old `== Complete` gate.
        // The slot is cleared as the session leaves, so its two traffic keys
        // do not stay behind in the machine.
        self.leg
            .as_mut()
            .and_then(|leg| noise::take_cleared(&mut leg.noise_session))
    }

    /// Check if we have a completed session ready to take.
    pub(crate) fn has_session(&self) -> bool {
        self.leg
            .as_ref()
            .is_some_and(|leg| leg.noise_session.is_some())
    }

    /// Drop the crypto handshake handle. The failure *state* lives on this
    /// machine; this only releases the Noise handle at the identical point it
    /// was released before, so a subsequent `complete_handshake` still reports
    /// `WrongState`.
    pub(crate) fn mark_failed(&mut self) {
        if let Some(leg) = self.leg.as_mut() {
            leg.noise_handshake = None;
        }
    }

    /// The session index we allocated for this peer, read from the surviving
    /// carrier. Populated once the index is allocated on either establish path
    /// (inbound at msg1, outbound at msg1 preparation). `None` before
    /// allocation (and after a rejected/unauthorized msg1). The inbound cutover
    /// reads this to perform the shell registry surgery.
    pub(crate) fn our_index(&self) -> Option<SessionIndex> {
        self.conn.our_index()
    }

    /// The peer identity this machine was born with (outbound identified dial)
    /// or crystallized onto it (anonymous discovery at msg2, inbound at msg3
    /// promote). `None` while the peer is still anonymous.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> Option<&PeerIdentity> {
        self.identity.as_ref()
    }

    /// Crystallize a learned identity onto an anonymous machine: XX msg2 is
    /// where an anonymous-discovery leg first learns who answered its dial.
    /// Sets the identity, the node address, and the conn's expected identity —
    /// control-tier fields only; no action is emitted and no state transition
    /// runs. A no-op when the identity is already known (identified dials fix
    /// it at birth), so callers on shared paths need not distinguish the two.
    pub(crate) fn crystallize_identity(&mut self, identity: PeerIdentity) {
        if self.identity.is_some() {
            return;
        }
        self.identity = Some(identity);
        self.node_addr = Some(*identity.node_addr());
        self.conn.set_expected_identity(identity);
    }

    /// Take the lease holding our session index off the surviving carrier:
    /// the promotion hands it to the active peer's link rekey machine, a
    /// cross-connection hands it to the promoted peer's, and the
    /// stale-connection reaper frees it. A leg whose msg3 read is still
    /// unsettled gives up the read with the lease it holds.
    pub(crate) fn take_our_index(&mut self) -> Option<IndexLease> {
        let held = self.conn.take_our_index();
        let read = self
            .leg
            .as_mut()
            .and_then(|leg| leg.fin.take())
            .and_then(LinkFinal::into_lease);
        debug_assert!(
            held.is_none() || read.is_none(),
            "a leg's lease is on its read or its carrier"
        );
        held.or(read)
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

    /// Connection-start timestamp of the surviving carrier — the home for the
    /// operator-visible `started_at_ms` now that the leg no longer projects it.
    pub(crate) fn conn_started_at(&self) -> u64 {
        self.conn.started_at()
    }

    /// Last-activity timestamp of the surviving carrier — the home for the
    /// operator-visible `last_activity_ms`/`idle_ms` and the idle-timeout check.
    pub(crate) fn conn_last_activity(&self) -> u64 {
        self.conn.last_activity()
    }

    /// Whether the carrier has been idle past `timeout_ms`.
    pub(crate) fn conn_is_timed_out(&self, now_ms: u64, timeout_ms: u64) -> bool {
        self.conn.is_timed_out(now_ms, timeout_ms)
    }

    /// Expected peer identity of the surviving carrier — the home for the
    /// operator-visible `expected_peer` now that the leg no longer projects it.
    /// Outbound carries the dial identity from construction; inbound records
    /// the identity discovered in msg1, written here by `receive_handshake_init`
    /// at the same point it reaches the pending connection. Everything that
    /// names a peer mid-handshake reads this, including the stale-connection
    /// sweep's retry address.
    pub(crate) fn conn_expected_identity(&self) -> Option<&PeerIdentity> {
        self.conn.expected_identity()
    }

    /// The identity this leg was *dialed at*, as opposed to the one that
    /// answered. `Some` only on an identified outbound dial; `None` on an
    /// anonymous shared-media dial and on every inbound leg. Fixed when the
    /// carrier is built and untouched by the handshake, so `handle_msg2` can
    /// hold the msg2-learned identity up against the dial intent instead of
    /// finding the intent already overwritten by it.
    pub(crate) fn conn_dialed_identity(&self) -> Option<&PeerIdentity> {
        self.conn.dialed_identity()
    }

    /// Where this machine's dial came from.
    pub(crate) fn dial_origin(&self) -> DialOrigin {
        self.origin
    }

    /// Record where this machine's dial came from. Called once, at the dial
    /// site, before the machine is first driven.
    pub(crate) fn set_dial_origin(&mut self, origin: DialOrigin) {
        self.origin = origin;
    }

    /// Remote startup epoch of the surviving carrier, recorded by the
    /// handshake operations at the message that reveals it (msg1 inbound,
    /// msg2 outbound). Promotion reads it to seed the active peer and to
    /// detect a peer restart across a reconnect.
    pub(crate) fn conn_remote_epoch(&self) -> Option<[u8; 8]> {
        self.conn.remote_epoch()
    }

    /// Stored wire-format msg1 of the surviving carrier — the resend source for
    /// the outbound handshake retransmit, now that the leg no longer carries it.
    /// On an inbound leg, the msg1 the leg answered.
    pub(crate) fn conn_handshake_msg1(&self) -> Option<&[u8]> {
        self.conn.handshake_msg1()
    }

    /// Stored wire-format msg2 of the surviving carrier — the resend source for a
    /// duplicate msg1 while the inbound handshake is still pending.
    pub(crate) fn conn_handshake_msg2(&self) -> Option<&[u8]> {
        self.conn.handshake_msg2()
    }

    /// Store the wire-format msg1 for resend on the surviving carrier and record
    /// the first resend deadline, mirroring the leg's start-of-handshake write.
    /// An inbound leg stores the msg1 it answered here; it never resends it.
    pub(crate) fn set_conn_handshake_msg1(&mut self, msg1: Vec<u8>, first_resend_at_ms: u64) {
        self.conn.set_handshake_msg1(msg1, first_resend_at_ms);
    }

    /// Store the wire-format msg2 for duplicate-msg1 resend on the surviving
    /// carrier, mirroring the leg's responder write.
    pub(crate) fn set_conn_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.conn.set_handshake_msg2(msg2);
    }

    /// The link this machine controls.
    pub(crate) fn link_id(&self) -> LinkId {
        self.link
    }

    /// Which side opened this connection, read from the surviving carrier.
    /// Seeded at construction: an outbound machine carries an outbound
    /// connection state and an inbound machine an inbound one.
    pub(crate) fn conn_direction(&self) -> LinkDirection {
        self.conn.direction()
    }

    /// Whether we opened this connection.
    pub(crate) fn conn_is_outbound(&self) -> bool {
        self.conn.is_outbound()
    }

    /// Whether the peer opened this connection.
    pub(crate) fn conn_is_inbound(&self) -> bool {
        self.conn.is_inbound()
    }

    /// The peer's address on this link, read from the surviving carrier.
    /// Written at the same three points the connection's own copy was: the
    /// inbound seed, the outbound dial, and message-2 completion.
    pub(crate) fn conn_source_addr(&self) -> Option<&TransportAddr> {
        self.conn.source_addr()
    }

    pub(crate) fn set_conn_source_addr(&mut self, addr: TransportAddr) {
        self.conn.set_source_addr(addr);
    }

    /// Peer session index of the surviving carrier — the source for the
    /// promotion hand-off now that the leg no longer projects it.
    pub(crate) fn conn_their_index(&self) -> Option<SessionIndex> {
        self.conn.their_index()
    }

    /// Transport ID of the surviving carrier — the source for the promotion
    /// hand-off, the stale-connection cleanup, and the msg1 resend send.
    pub(crate) fn conn_transport_id(&self) -> Option<TransportId> {
        self.conn.transport_id()
    }

    /// Link statistics of the surviving carrier — the seed copied into the
    /// active peer at promotion.
    pub(crate) fn conn_link_stats(&self) -> &LinkStats {
        self.conn.link_stats()
    }

    /// Negotiated peer profile of the surviving carrier — the source for the
    /// promotion hand-off now that the leg no longer projects it.
    pub(crate) fn conn_peer_profile(&self) -> Option<NodeProfile> {
        self.conn.peer_profile()
    }

    /// Record the negotiated peer profile on the surviving carrier.
    pub(crate) fn set_conn_peer_profile(&mut self, profile: NodeProfile) {
        self.conn.set_negotiation_results(profile);
    }

    /// Record the peer session index on the surviving carrier, so the
    /// promotion hand-off reads it from the machine.
    pub(crate) fn set_conn_their_index(&mut self, index: SessionIndex) {
        self.conn.set_their_index(index);
    }

    /// Record the transport ID on the surviving carrier. Written on the
    /// inbound establish path at msg1 and on the outbound dial.
    pub(crate) fn set_conn_transport_id(&mut self, id: TransportId) {
        self.conn.set_transport_id(id);
    }

    /// Record our session index on the surviving carrier, as the lease that
    /// holds it. The outbound establish path takes the lease shell-side and
    /// writes it here, the single index home once the leg dissolves (the
    /// inbound path writes the carrier directly at authorize). A lease the
    /// carrier already held is handed back, for the caller to release.
    pub(crate) fn set_conn_our_index(&mut self, index: IndexLease) -> Option<IndexLease> {
        self.conn.set_our_index(index)
    }

    /// Adopt an explicit connection-start timestamp on the carrier, so the
    /// surviving state keeps the leg's start provenance rather than the
    /// dial-time construction default.
    pub(crate) fn set_conn_started_at(&mut self, started_at_ms: u64) {
        self.conn.set_started_at(started_at_ms);
    }

    /// Advance the carrier's last-activity timestamp — the machine-tier paired
    /// write for the leg's handshake `touch`.
    pub(crate) fn touch_conn(&mut self, now_ms: u64) {
        self.conn.touch(now_ms);
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

    /// Whether this peer's handshake has failed. The sole failure carrier now
    /// that the leg's phase enum is gone: a terminal `PeerState::Failed`
    /// (hard crypto/transport/ACL failures) OR the `send_failed` flag (a stored
    /// handshake-initiation send failure that deliberately keeps the machine at
    /// `Handshaking{SentMsg1}`). The stale-connection sweep reads this to reclaim
    /// the leg, exactly as it read the leg's `is_failed` before.
    pub(crate) fn is_failed(&self) -> bool {
        matches!(self.state, PeerState::Failed { .. }) || self.send_failed
    }

    /// The operator-visible handshake-state string for the pending-connection
    /// view, derived from the machine phase. Byte-identical to the strings the
    /// leg's `HandshakeState` `Display` produced before the phase collapsed onto
    /// the machine. A `send_failed` leg renders `"failed"` while its phase stays
    /// `SentMsg1`, matching the pre-collapse leg display.
    pub(crate) fn displayed_handshake_state(&self) -> &'static str {
        if self.send_failed {
            return "failed";
        }
        handshake_state_str(self.state)
    }

    /// Record a handshake failure that the shell observed on the leg (e.g. a
    /// `complete_handshake` that rejected msg2), WITHOUT leaving the current
    /// handshake phase. Mirrors the `HandshakeSendFailed` carve-out: the failure
    /// is carried as `send_failed`, so the machine PHASE is unchanged (matching
    /// the pre-collapse behavior, where the shell marked only the leg failed and
    /// left the machine in place) while `is_failed`/display report the failure.
    /// The stale-connection sweep reclaims the leg via
    /// [`is_failed`](Self::is_failed) at the next tick, before any projection or
    /// resend.
    pub(crate) fn mark_send_failed(&mut self) {
        self.send_failed = true;
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
            PeerEvent::HandshakeSendFailed => self.on_handshake_send_failed(),
            PeerEvent::InboundMsg1 { link } => self.on_inbound_msg1(link, now, index_allocator),
            PeerEvent::InboundMsg3 { wire, est } => {
                let (_decision, actions) = self.inbound_msg3(wire, est, now, index_allocator);
                actions
            }
            PeerEvent::OutboundMsg2 { their_index, out } => {
                self.on_outbound_msg2(their_index, out, now)
            }
            PeerEvent::PromotionResolved { result } => self.on_promotion_resolved(result, now),
            PeerEvent::CrossConnResolved { outcome } => self.on_cross_conn_resolved(outcome),
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

    /// A stored handshake initiation failed to send: mark the embedded leg
    /// failed so the stale-connection sweep (which reads the leg's
    /// `is_failed`) reclaims it. NO state flip — the machine stays in
    /// `Handshaking{SentMsg1}` so retransmit eligibility
    /// (`is_handshaking_sent_msg1`) survives until the sweep, and no timer
    /// actions are emitted.
    fn on_handshake_send_failed(&mut self) -> Vec<PeerAction> {
        // Drop the Noise handshake handle at the identical point as before;
        // the failure *state* is recorded on the machine.
        self.mark_failed();
        self.send_failed = true;
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
        _now: u64,
        alloc: &mut IndexAllocator,
    ) -> Vec<PeerAction> {
        let Some(our_index) = allocate(alloc) else {
            // Allocation exhausted: mirrors `handle_msg1`'s allocate-failure
            // path (records reject, drops the leg). No index, no msg2.
            self.state = PeerState::Failed {
                reason: FailReason::Rejected,
            };
            return Vec::new();
        };
        let held = self.conn.set_our_index(our_index);
        debug_assert!(held.is_none(), "an inbound leg draws its index once");
        self.state = PeerState::Handshaking {
            link,
            phase: HandshakePhase::SentMsg2,
        };
        // No timer is armed on inbound legs — the stale-connection reaper owns
        // their timeout (see `inbound_msg2_sent`).
        vec![PeerAction::SendHandshake { bytes: Vec::new() }]
    }

    /// Inbound **msg3**: identity crystallizes here. Compute the establish
    /// decision for the driver, alongside the machine-phase actions. The single
    /// `establish_inbound` evaluation happens here; the driver routes on the
    /// returned [`InboundDecision`], while the terminal arms' effect actions —
    /// the reject/duplicate `FreeIndex` and the `fail` flip — are legitimate
    /// carrier effects on this map-resident machine. The duplicate-resend send
    /// stays a driver mechanism (the stored msg2 bytes are replayed as-is), so
    /// this method emits no `SendHandshake`. The ACL gate and the Noise read
    /// already ran shell-side before this event; our index was drawn at msg1,
    /// and its lease rides the leg's msg3 read, or the carrier.
    ///
    /// A link setup settles the read onto the leg before its actions run; a
    /// rekey of the peer's link leaves it on the leg for the shell to take
    /// ([`take_final`](Self::take_final)) and hand to the peer's machine.
    pub(crate) fn inbound_msg3(
        &mut self,
        wire: WireOutcome,
        est: EstablishSnapshot,
        _now: u64,
        _alloc: &mut IndexAllocator,
    ) -> (InboundDecision, Vec<PeerAction>) {
        // Identity crystallizes at msg3 on XX (WireOutcome carries only the node
        // address + epoch; the full static key stays shell-side).
        self.node_addr = Some(wire.peer_node_addr);

        let decision = Fmp::new().establish_inbound(&est, &wire);
        let actions = match &decision {
            // The epoch-mismatch teardown was refused: the peering this msg3
            // would destroy is still carrying authenticated traffic, or this
            // identity already changed epoch inside the dampening interval.
            // The identity's recent sessions carried no frame and its back-off
            // is running. A same-epoch duplicate, whose stored msg2 the driver
            // resends inline (the bytes ride the decision, not an action). In
            // every case the established peer, if any, is untouched, and this
            // temporary leg is discarded, its lease released, so a later
            // timeout on a persistent machine cannot fire against a healthy
            // peer.
            InboundDecision::Reject { .. } | InboundDecision::RepeatMsg2 { .. } => {
                let actions = self.release_leg_index();
                let _ = self.fail(FailReason::Rejected);
                actions
            }
            // A declared rekey of the peer's link: the read and its lease stay
            // on the leg for the peer's link rekey machine, and the leg is
            // done. A leg holding no read has nothing to hand over, and its
            // lease is released.
            InboundDecision::PeerRekey { .. } => {
                let actions = if self.final_read().is_some() {
                    Vec::new()
                } else {
                    self.release_leg_index()
                };
                let _ = self.fail(FailReason::Rejected);
                actions
            }
            InboundDecision::CrossConnect {
                peer,
                our_inbound_wins,
            } => {
                self.settle_setup();
                self.on_cross_connect(*peer, *our_inbound_wins)
            }
            InboundDecision::RestartThenPromote { peer } => {
                // Epoch mismatch — peer restarted. `InvalidateSendState` maps to
                // the shell's `remove_active_peer(&peer)` and `ReportLost` to
                // `note_link_dead(peer)`; then fall through to promote the fresh
                // connection in the stale peer's place.
                self.settle_setup();
                vec![
                    PeerAction::InvalidateSendState,
                    PeerAction::ReportLost {
                        peer: *peer,
                        kind: LostKind::LinkDead,
                    },
                    PeerAction::PromoteToActive { link: self.link },
                ]
            }
            InboundDecision::Promote => {
                // Net-new inbound (or the post-restart re-promote): the shell's
                // `promote_connection` late max-peers cap + cross-connection
                // won/lost handling resolve via the `PromotionResolved` feedback.
                self.settle_setup();
                vec![PeerAction::PromoteToActive { link: self.link }]
            }
        };
        (decision, actions)
    }

    /// Release the lease on the index this leg drew at msg1, as the
    /// `FreeIndex` the driver carries out. Empty when the leg holds none.
    fn release_leg_index(&mut self) -> Vec<PeerAction> {
        self.take_our_index()
            .map(|lease| PeerAction::FreeIndex {
                index: SessionIndex::new(lease.release()),
            })
            .into_iter()
            .collect()
    }

    /// Outbound completion after msg2 completes the initiator handshake:
    /// compute the establish decision from the snapshot via
    /// `establish_outbound`. `Promote` drives promotion via actions; the
    /// Swap/Keep outcomes are conveyed as a
    /// [`ResolveCrossConnection`](PeerAction::ResolveCrossConnection) decision
    /// for the shell's inline resolution, which owns all effects (index frees,
    /// session replacement) permanently. No state guard: anonymous-discovery
    /// legs reach msg2 parked in `Discovered` (identified dials in
    /// `Handshaking{SentMsg1}`), and the decision reads only the snapshot.
    ///
    /// On `Promote` the persistent machine survives as the active peer's
    /// control machine, and `Established` is written here, ahead of the
    /// `PromotionResolved` feedback (which re-crystallizes it). The shell
    /// crystallizes the learned identity onto the machine before the step, so
    /// the `addr()` read is `Some` for anonymous legs too. On Swap/Keep the
    /// `set_their_index` write lands on the machine's shadow connection and
    /// the shell discards the machine right after the step, so it is
    /// unobservable.
    fn on_outbound_msg2(
        &mut self,
        their_index: SessionIndex,
        out: OutboundSnapshot,
        _now: u64,
    ) -> Vec<PeerAction> {
        self.conn.set_their_index(their_index);
        match Fmp::new().establish_outbound(&out, self.conn.remote_epoch()) {
            OutboundDecision::Promote => self.outbound_promote(),
            OutboundDecision::RestartThenPromote => {
                // The peer restarted: the stale peer goes first, with its
                // sessions and indices, and is reported lost, as an inbound
                // restart does; then this dial promotes as a net-new peer.
                let mut actions = vec![PeerAction::InvalidateSendState];
                if let Some(id) = self.conn.expected_identity() {
                    actions.push(PeerAction::ReportLost {
                        peer: *id.node_addr(),
                        kind: LostKind::LinkDead,
                    });
                }
                actions.extend(self.outbound_promote());
                actions
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

    /// The promotion of a completed outbound connection as a net-new peer.
    ///
    /// The machine survives promotion (it becomes the active peer's control
    /// machine), so the outbound handshake timers are cancelled here or they
    /// would linger in the driver's store. A late fire would no-op against the
    /// non-`Handshaking` state, but leaving them armed is a timer leak.
    fn outbound_promote(&mut self) -> Vec<PeerAction> {
        let addr = self.addr().unwrap_or_else(zero_addr);
        self.state = PeerState::Established { addr };
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

    /// XX inbound cross-connection at msg3. The Noise session move and the
    /// index bindings are shell effects; the machine emits a single plain-data
    /// trigger carrying the msg1-allocated index and the tie-break flag, and
    /// the executor takes the leg's session and lease from this machine.
    /// `our_inbound_wins` (larger-NodeAddr side) is already decided by the
    /// core; the machine does NOT re-run the tie-break.
    fn on_cross_connect(&mut self, peer: NodeAddr, our_inbound_wins: bool) -> Vec<PeerAction> {
        match self.conn.our_index() {
            Some(our_index) => vec![PeerAction::ResolveInboundCrossConnection {
                peer,
                our_index,
                our_inbound_wins,
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
                self.register_current_index()
            }
            PromotionResult::CrossConnectionLost { .. } => {
                let mut actions = Vec::new();
                if let Some(lease) = self.conn.take_our_index() {
                    actions.push(PeerAction::FreeIndex {
                        index: SessionIndex::new(lease.release()),
                    });
                }
                self.state = PeerState::Failed {
                    reason: FailReason::HandshakeFailed,
                };
                actions
            }
        }
    }

    fn register_current_index(&self) -> Vec<PeerAction> {
        match self.conn.our_index() {
            Some(idx) => vec![PeerAction::RegisterDecryptSession { index: idx }],
            None => Vec::new(),
        }
    }

    /// Observation: the shell resolved an outbound cross-connection inline. On a
    /// session swap it adopts the new remote session index into the control
    /// shadow, mirroring the shell's in-place session replacement; on a keep it
    /// leaves the shadow untouched. Our new index is the active peer's link
    /// rekey machine's, which holds its lease. Emits NO action — the crypto
    /// effect already ran shell-side.
    fn on_cross_conn_resolved(&mut self, outcome: CrossConnOutcome) -> Vec<PeerAction> {
        if let CrossConnOutcome::Swap { their_index, .. } = outcome {
            self.conn.set_their_index(their_index);
        }
        Vec::new()
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
                    if let Some(lease) = self.conn.take_our_index() {
                        free.push(PeerAction::FreeIndex {
                            index: SessionIndex::new(lease.release()),
                        });
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
        if let Some(lease) = self.conn.take_our_index() {
            actions.push(PeerAction::UnregisterDecryptSession {
                index: SessionIndex::new(lease.index()),
            });
            // The index is the active peer's to free: the removal the
            // previous action runs releases it with the peer's sessions.
            let _ = lease.release();
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
        let _ = now;
        let addr = self.addr().unwrap_or_else(zero_addr);
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
#[path = "tests/machine.rs"]
mod msg2_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::fmp::{PromotionResult, RekeyClaim};
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
    /// restart, cross-connection, rekey and duplicate tests flip the
    /// existing-peer fields.
    fn est_new_peer(our: NodeAddr) -> EstablishSnapshot {
        EstablishSnapshot {
            has_existing_peer: false,
            existing_peer_epoch: None,
            has_session: false,
            stored_msg2: None,
            different_link: false,
            rekey_claim: RekeyClaim::None,
            peering_idle_ms: u64::MAX,
            epoch_restart_dampened: false,
            our_node_addr: our,
            silent_backoff: None,
        }
    }

    // ---- Test: net-new outbound promote at msg2 ---------------------------
    #[test]
    fn outbound_msg2_promotes_net_new() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let link = LinkId::new(3);
        let mut m = PeerMachine::new_outbound(link, Some(id), 0);
        let their_index = SessionIndex::new(0x77);

        let actions = m.step(
            PeerEvent::OutboundMsg2 {
                their_index,
                out: OutboundSnapshot {
                    has_existing_peer: false,
                    our_outbound_wins: false,
                    existing_peer_epoch: None,
                },
            },
            0,
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
        let mut m = PeerMachine::new_outbound(link, Some(id), 0);
        let their_index = SessionIndex::new(0x88);

        let actions = m.step(
            PeerEvent::OutboundMsg2 {
                their_index,
                out: OutboundSnapshot {
                    has_existing_peer: false,
                    our_outbound_wins: false,
                    existing_peer_epoch: None,
                },
            },
            0,
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
                PeerAction::PromoteToActive { link },
            ]
        );
    }

    // ---- Test: outbound msg2 cross-connection decision arms ---------------
    // Swap/Keep are decision-only: a single `ResolveCrossConnection { swap }`
    // action, no index actions, no state change — the shell's inline
    // resolution owns all effects and discards the machine after the step.
    #[test]
    fn outbound_msg2_cross_connection_decisions() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();

        // Cross-connection SWAP: our outbound wins -> decision only; the
        // shell's inline resolution owns the index frees and session
        // replacement.
        let mut m2 = PeerMachine::new_outbound(LinkId::new(2), Some(peer), 0);
        m2.state = PeerState::Handshaking {
            link: LinkId::new(2),
            phase: HandshakePhase::SentMsg1,
        };
        let _ = m2.conn.set_our_index(IndexLease::for_test(0x2222)); // outbound index
        let swap = m2.step(
            PeerEvent::OutboundMsg2 {
                their_index: SessionIndex::new(0x99),
                out: OutboundSnapshot {
                    has_existing_peer: true,
                    our_outbound_wins: true,
                    existing_peer_epoch: None,
                },
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
        // the carrier's outbound index unchanged.
        assert_eq!(
            m2.state(),
            PeerState::Handshaking {
                link: LinkId::new(2),
                phase: HandshakePhase::SentMsg1,
            }
        );
        assert_eq!(m2.our_index(), Some(SessionIndex::new(0x2222)));

        // Cross-connection KEEP: our outbound loses -> decision only; the
        // shell's inline resolution frees the unused outbound index.
        let mut m3 = PeerMachine::new_outbound(LinkId::new(3), Some(peer), 0);
        m3.state = PeerState::Handshaking {
            link: LinkId::new(3),
            phase: HandshakePhase::SentMsg1,
        };
        let _ = m3.conn.set_our_index(IndexLease::for_test(0x3333));
        let keep = m3.step(
            PeerEvent::OutboundMsg2 {
                their_index: SessionIndex::new(0x9A),
                out: OutboundSnapshot {
                    has_existing_peer: true,
                    our_outbound_wins: false,
                    existing_peer_epoch: None,
                },
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
        assert_eq!(m3.our_index(), Some(SessionIndex::new(0x3333)));
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
            PeerAction::SendLinkMessage { msg: vec![7, 8, 9] },
            PeerAction::PromoteToActive {
                link: LinkId::new(7),
            },
            PeerAction::ResolveCrossConnection { swap: true },
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
                kind: TimerKind::HandshakeRetransmit,
                at_ms: 1234,
            },
            PeerAction::CancelTimer {
                kind: TimerKind::Liveness,
            },
            PeerAction::ReportLost {
                peer,
                kind: LostKind::LinkDead,
            },
            PeerAction::ResolveInboundCrossConnection {
                peer,
                our_index: SessionIndex::new(8),
                our_inbound_wins: true,
            },
        ];
        for a in &sample {
            // Exhaustiveness guard: no `_` wildcard, so adding a variant without
            // extending `sample` above breaks the build here.
            match a {
                PeerAction::OpenTransport { .. }
                | PeerAction::SendHandshake { .. }
                | PeerAction::SendLinkMessage { .. }
                | PeerAction::PromoteToActive { .. }
                | PeerAction::ResolveCrossConnection { .. }
                | PeerAction::InvalidateSendState
                | PeerAction::RegisterDecryptSession { .. }
                | PeerAction::UnregisterDecryptSession { .. }
                | PeerAction::FreeIndex { .. }
                | PeerAction::ActivateConnectedUdp
                | PeerAction::TeardownConnectedUdp
                | PeerAction::SetTimer { .. }
                | PeerAction::CancelTimer { .. }
                | PeerAction::ReportLost { .. }
                | PeerAction::ResolveInboundCrossConnection { .. } => {}
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

    // ---- Test 4: restart-override -----------------------------------------
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

        // Existing peer, same epoch, different link, no rekey declared ->
        // CrossConnect.
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([5u8; 8]);
        est.has_session = true;
        est.different_link = true;
        est.rekey_claim = RekeyClaim::None; // no rekey declared -> cross-connection
        let wire = wire_outcome(peer_addr, Some([5u8; 8]));

        let actions = m.step(PeerEvent::InboundMsg3 { wire, est }, 200, &mut alloc);
        assert_eq!(
            actions,
            vec![PeerAction::ResolveInboundCrossConnection {
                peer: peer_addr,
                our_index,
                our_inbound_wins: true,
            }]
        );
    }

    // ---- Test 7d: a declared link rekey at msg3 ends the leg -------------
    // A msg3 declaring a rekey of the session the node holds with the peer
    // goes to the peer's link rekey machine with the leg's msg3 read, which
    // holds the lease on the leg's index; the leg terminates. A leg that holds
    // no read, as here, where the lease is on the carrier, has nothing to hand
    // over, and the lease is released. The hand-over itself, with a real read,
    // is driven end to end in the node's tests.
    #[test]
    fn a_declared_link_rekey_at_msg3_ends_the_leg_and_releases_a_lease_no_read_holds() {
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let our = *peer_identity().node_addr();

        let mut alloc = IndexAllocator::new();
        let mut m = PeerMachine::new_inbound(LinkId::new(4), 0);
        let seed = SessionIndex::new(0xCD);
        let _ = m.conn.set_our_index(IndexLease::for_test(seed.as_u32()));

        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([7u8; 8]);
        est.has_session = true;
        est.rekey_claim = RekeyClaim::Matches; // declared rekey of our session
        let wire = wire_outcome(peer_addr, Some([7u8; 8]));

        let (decision, actions) = m.inbound_msg3(wire, est, 200, &mut alloc);
        assert!(matches!(decision, InboundDecision::PeerRekey { peer } if peer == peer_addr));
        assert_eq!(actions, vec![PeerAction::FreeIndex { index: seed }]);
        assert_eq!(m.our_index(), None, "the leg's lease is released");
        assert_eq!(
            m.state(),
            PeerState::Failed {
                reason: FailReason::Rejected
            }
        );
    }

    // ---- Test 7e: same-epoch duplicate frees the index and terminates -----
    // A same-epoch duplicate handshake (no cross-connection, no rekey) returns the
    // msg1-allocated index and terminates the leg. The stored-msg2 resend is a
    // driver mechanism (the bytes ride the decision, replayed as-is), so the
    // machine emits `FreeIndex` only — no `SendHandshake`. The terminal transition
    // matters: a persistent machine parked here would keep its handshake-timeout
    // armed and later free the index + report loss against the healthy established
    // peer.
    #[test]
    fn repeat_msg2_frees_index_and_terminates() {
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let our = *peer_identity().node_addr();

        let mut alloc = IndexAllocator::new();
        let mut m = PeerMachine::new_inbound(LinkId::new(5), 0);
        let seed = SessionIndex::new(0xEF);
        let _ = m.conn.set_our_index(IndexLease::for_test(seed.as_u32()));
        let stored_msg2 = vec![1u8, 2, 3, 4];

        // Same epoch, same link, no rekey declared -> duplicate handshake. The
        // `est_new_peer` default of `RekeyClaim::None` plus `different_link =
        // false` is what pins this arm: an undeclared msg3 on the peer's own
        // link is neither a rekey nor a crossing dial.
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([9u8; 8]);
        est.stored_msg2 = Some(stored_msg2.clone());
        let wire = wire_outcome(peer_addr, Some([9u8; 8]));

        let actions = m.step(PeerEvent::InboundMsg3 { wire, est }, 200, &mut alloc);
        assert_eq!(actions, vec![PeerAction::FreeIndex { index: seed }]);
        assert_eq!(
            m.state(),
            PeerState::Failed {
                reason: FailReason::Rejected
            }
        );
    }

    // ---- Test 7b: dial-persisted outbound promote keeps the carrier index ---
    // An outbound machine persisted at DIAL carries the allocated index on its
    // surviving carrier (the shell writes it at msg1 preparation). On promote via
    // msg2 the machine keeps that index, so `our_index()` reads `Some(dial_index)`
    // through Established. A subsequent inbound restart (peer restart, new epoch)
    // still emits NO separate `UnregisterDecryptSession`: the restart teardown is
    // the full `InvalidateSendState` (remove_active_peer), which owns the index
    // cleanup, and the msg3 restart arm never reads the carrier index.
    #[test]
    fn dial_persisted_outbound_promote_keeps_carrier_index() {
        let mut alloc = IndexAllocator::new();
        let peer = peer_identity();
        let peer_addr = *peer.node_addr();
        let our = *peer_identity().node_addr();
        let dial_index = SessionIndex::new(0x55AA);

        // Persisted at dial: Discovered, with the carrier index written by the
        // shell at msg1 preparation.
        let mut m = PeerMachine::new_outbound(LinkId::new(1), Some(peer), 0);
        let _ = m
            .conn
            .set_our_index(IndexLease::for_test(dial_index.as_u32()));
        assert_eq!(m.our_index(), Some(dial_index));

        // Promote via msg2 from Discovered.
        let promote = m.step(
            PeerEvent::OutboundMsg2 {
                their_index: SessionIndex::new(0x77),
                out: OutboundSnapshot {
                    has_existing_peer: false,
                    our_outbound_wins: false,
                    existing_peer_epoch: None,
                },
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
        assert_eq!(m.our_index(), Some(dial_index));

        // Drive promotion to Established.
        let _ = m.step(
            PeerEvent::PromotionResolved {
                result: PromotionResult::Promoted(peer_addr),
            },
            300,
            &mut alloc,
        );
        assert_eq!(m.state(), PeerState::Established { addr: peer_addr });
        assert_eq!(m.our_index(), Some(dial_index));

        // A subsequent inbound restart (peer restart, new epoch) must NOT emit a
        // separate UnregisterDecryptSession: the restart teardown is the full
        // InvalidateSendState (remove_active_peer), which owns the index cleanup.
        let mut est = est_new_peer(our);
        est.has_existing_peer = true;
        est.existing_peer_epoch = Some([1u8; 8]);
        let wire = wire_outcome(peer_addr, Some([2u8; 8]));
        let restart = m.step(PeerEvent::InboundMsg3 { wire, est }, 1_000, &mut alloc);
        assert!(
            !restart
                .iter()
                .any(|a| matches!(a, PeerAction::UnregisterDecryptSession { .. })),
            "no separate UnregisterDecryptSession: the msg3 restart teardown is InvalidateSendState"
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

        let mut m = PeerMachine::new_outbound(LinkId::new(1), Some(peer), 0);
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
                out: OutboundSnapshot {
                    has_existing_peer: false,
                    our_outbound_wins: false,
                    existing_peer_epoch: None,
                },
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

        let mut m = PeerMachine::new_outbound(LinkId::new(1), Some(peer), 0);
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
        let mut m = PeerMachine::new_outbound(LinkId::new(1), Some(peer), 0);
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
        m.set_leg(HandshakeCrypto::new());
        assert!(m.is_handshaking_sent_msg1());
        assert!(!m.is_failed());
        assert_eq!(m.displayed_handshake_state(), "sent_msg1");

        let actions = m.step(PeerEvent::HandshakeSendFailed, 200, &mut alloc);
        assert_eq!(actions, Vec::new(), "HandshakeSendFailed emits no actions");
        assert!(
            m.is_handshaking_sent_msg1(),
            "retransmit eligibility survives a send failure"
        );
        assert!(
            m.is_failed(),
            "the machine carries the failed mark the sweep reads"
        );
        assert_eq!(
            m.displayed_handshake_state(),
            "failed",
            "the send-failed leg still displays as failed"
        );

        // With no leg (e.g. after take_leg) the event stays a defensive no-op
        // for the leg handle and keeps the state retransmit-eligible.
        let _ = m.take_leg();
        let actions = m.step(PeerEvent::HandshakeSendFailed, 300, &mut alloc);
        assert_eq!(actions, Vec::new());
        assert!(m.is_handshaking_sent_msg1());
        assert!(m.leg().is_none());
    }

    // ---- Test 7f: handshake_state_str is a total, byte-identical mapping ---
    // Pins the displayed-string derivation for every `PeerState` arm against the
    // strings the deleted leg `HandshakeState` `Display` produced.
    #[test]
    fn handshake_state_str_total_mapping() {
        let link = LinkId::new(1);
        let addr = *peer_identity().node_addr();

        assert_eq!(
            handshake_state_str(PeerState::Handshaking {
                link,
                phase: HandshakePhase::Initial,
            }),
            "initial"
        );
        assert_eq!(
            handshake_state_str(PeerState::Handshaking {
                link,
                phase: HandshakePhase::SentMsg1,
            }),
            "sent_msg1"
        );
        assert_eq!(
            handshake_state_str(PeerState::Handshaking {
                link,
                phase: HandshakePhase::SentMsg2,
            }),
            "received_msg1"
        );

        assert_eq!(
            handshake_state_str(PeerState::Established { addr }),
            "complete"
        );
        assert_eq!(handshake_state_str(PeerState::Active { addr }), "complete");
        assert_eq!(
            handshake_state_str(PeerState::Maintaining {
                addr,
                kind: MaintainKind::Mtu,
            }),
            "complete"
        );
        assert_eq!(
            handshake_state_str(PeerState::Closing {
                addr,
                reason: CloseReason::Requested,
            }),
            "complete"
        );

        assert_eq!(
            handshake_state_str(PeerState::Failed {
                reason: FailReason::HandshakeFailed,
            }),
            "failed"
        );

        // GAP A: the anonymous-outbound leg rests at `Discovered` while its leg
        // is at `SentMsg1`, so the pending-connection view displayed "sent_msg1".
        assert_eq!(handshake_state_str(PeerState::Discovered), "sent_msg1");
        assert_eq!(
            handshake_state_str(PeerState::Connecting { link }),
            "initial"
        );
        assert_eq!(
            handshake_state_str(PeerState::Closed {
                backoff_deadline_ms: 0,
            }),
            "initial"
        );
    }

    // ---- Test 8: liveness -> LinkDeadSuspected -> ReportLost --------------
    #[test]
    fn liveness_to_link_dead() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), Some(id), 0);
        m.state = PeerState::Active { addr };
        let _ = m.conn.set_our_index(IndexLease::for_test(0x4242));

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

    // ---- Test 12: CrossConnResolved observation ---------------------------
    // A swap adopts the new remote index into the control shadow and
    // emits nothing; a keep leaves the shadow untouched and emits nothing.
    #[test]
    fn cross_conn_resolved_swap_updates_shadow() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), Some(id), 0);
        m.state = PeerState::Active { addr };
        let _ = m.conn.set_our_index(IndexLease::for_test(0x1111));
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
        // Our new index is held by the promoted peer's link rekey machine,
        // so the carrier's own is left as it was.
        assert_eq!(m.conn.our_index(), Some(SessionIndex::new(0x1111)));
        assert_eq!(m.conn.their_index(), Some(their));
        assert_eq!(m.state(), PeerState::Active { addr });
        assert_eq!(alloc.count(), 0);
    }

    #[test]
    fn cross_conn_resolved_keep_is_noop() {
        let mut alloc = IndexAllocator::new();
        let id = peer_identity();
        let addr = *id.node_addr();
        let mut m = PeerMachine::new_outbound(LinkId::new(1), Some(id), 0);
        m.state = PeerState::Active { addr };
        let _ = m.conn.set_our_index(IndexLease::for_test(0x1111));
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

    // ---- Moved from the handshake leg's own test module --------------------
    // These exercise the Noise handshake operations, which now live on the
    // control machine. Constructed as a machine with a leg attached; the
    // assertions are unchanged.

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    fn make_keypair() -> Keypair {
        let identity = Identity::generate();
        identity.keypair()
    }

    fn make_epoch() -> [u8; 8] {
        let mut epoch = [0u8; 8];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut epoch);
        epoch
    }

    fn outbound_leg(
        link_id: LinkId,
        expected_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> PeerMachine {
        let mut machine =
            PeerMachine::new_outbound(link_id, Some(expected_identity), current_time_ms);
        machine.set_leg(HandshakeCrypto::new());
        machine
    }

    fn inbound_leg(link_id: LinkId, current_time_ms: u64) -> PeerMachine {
        let mut machine = PeerMachine::new_inbound(link_id, current_time_ms);
        machine.set_leg(HandshakeCrypto::new());
        machine
    }

    #[test]
    fn test_outbound_connection() {
        let identity = make_peer_identity();
        let conn = outbound_leg(LinkId::new(1), identity, 1000);

        assert!(conn.conn_is_outbound());
        assert!(!conn.conn_is_inbound());
        assert!(!conn.has_session());
        assert!(conn.conn_expected_identity().is_some());
        assert_eq!(conn.conn_started_at(), 1000);
    }

    #[test]
    fn test_inbound_connection() {
        let conn = inbound_leg(LinkId::new(2), 2000);

        assert!(conn.conn_is_inbound());
        assert!(!conn.conn_is_outbound());
        assert!(!conn.has_session());
        assert!(conn.conn_expected_identity().is_none());
        assert_eq!(conn.conn_started_at(), 2000);
    }

    #[test]
    fn test_full_handshake_flow() {
        // Create identities
        let initiator_identity = Identity::generate();
        let responder_identity = Identity::generate();

        let initiator_keypair = initiator_identity.keypair();
        let responder_keypair = responder_identity.keypair();
        let initiator_epoch = make_epoch();
        let responder_epoch = make_epoch();

        // Use from_pubkey_full to preserve parity for ECDH
        let responder_peer_id = PeerIdentity::from_pubkey_full(responder_identity.pubkey_full());

        // Create connections
        let mut initiator_conn = outbound_leg(LinkId::new(1), responder_peer_id, 1000);
        let mut responder_conn = inbound_leg(LinkId::new(2), 1000);

        // Initiator starts XX handshake
        let msg1 = initiator_conn
            .start_handshake(initiator_keypair, initiator_epoch, 1100)
            .unwrap();
        // Post-msg1 the initiator holds an in-flight handshake, not yet a session.
        assert!(!initiator_conn.has_session());

        // Responder processes msg1 and sends msg2 (XX: does NOT complete yet)
        let msg2 = responder_conn
            .receive_handshake_init(responder_keypair, responder_epoch, &msg1, None, 1200)
            .unwrap();
        // XX: the responder parks awaiting msg3 — it holds an in-flight
        // handshake, not yet a session (the deleted phase was `ReceivedMsg1`).
        assert!(!responder_conn.has_session());
        // Responder does NOT know initiator's identity yet (XX property)
        assert!(responder_conn.conn_expected_identity().is_none());

        // Initiator processes msg2 and generates msg3
        let (msg3, _neg) = initiator_conn
            .complete_handshake_accepting(&msg2, None, 1300)
            .unwrap();
        // The initiator completes at msg3 generation: it now holds a session.
        assert!(initiator_conn.has_session());

        // Initiator learned responder's identity from msg2
        let discovered = initiator_conn.conn_expected_identity().unwrap();
        assert_eq!(discovered.pubkey(), responder_identity.pubkey());
        assert_eq!(initiator_conn.conn_remote_epoch(), Some(responder_epoch));

        // Responder processes msg3 (completes handshake): it now holds a session.
        let _neg = responder_conn.complete_handshake_msg3(&msg3, 1400).unwrap();
        assert!(responder_conn.has_session());

        // Responder learned initiator's identity from msg3
        let discovered = responder_conn.conn_expected_identity().unwrap();
        assert_eq!(discovered.pubkey(), initiator_identity.pubkey());
        assert_eq!(responder_conn.conn_remote_epoch(), Some(initiator_epoch));

        // Both have sessions
        assert!(initiator_conn.has_session());
        assert!(responder_conn.has_session());

        // Take and verify sessions work
        let mut init_session = initiator_conn.take_session().unwrap();
        let mut resp_session = responder_conn.take_session().unwrap();

        // Encrypt/decrypt test
        let plaintext = b"test message";
        let ciphertext = init_session.encrypt(plaintext).unwrap();
        let decrypted = resp_session.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Non-zero bytes left in a leg slot, read in place.
    #[cfg(not(debug_assertions))]
    fn leg_slot_nonzero_bytes(slot: &Option<HandshakeCrypto>) -> usize {
        let base = (slot as *const Option<HandshakeCrypto>).cast::<u8>();
        (0..std::mem::size_of::<Option<HandshakeCrypto>>())
            // SAFETY: `base` comes from a live reference, so every byte of the
            // slot is in bounds; volatile so the read is of memory as it is.
            .filter(|&i| unsafe { std::ptr::read_volatile(base.add(i)) } != 0)
            .count()
    }

    /// Release only: in a debug build `Option::take` leaves stack garbage in
    /// the payload of the `None` it writes, so the count means nothing there.
    #[cfg(not(debug_assertions))]
    #[test]
    fn take_leg_leaves_no_session_keys_in_the_slot_it_empties() {
        let initiator = Identity::generate();
        let responder = Identity::generate();
        let responder_id = PeerIdentity::from_pubkey_full(responder.pubkey_full());
        let mut ini = outbound_leg(LinkId::new(1), responder_id, 1000);
        let mut res = Box::new(inbound_leg(LinkId::new(2), 1000));
        let msg1 = ini
            .start_handshake(initiator.keypair(), make_epoch(), 1100)
            .unwrap();
        let msg2 = res
            .receive_handshake_init(responder.keypair(), make_epoch(), &msg1, None, 1200)
            .unwrap();
        let (msg3, _) = ini.complete_handshake_accepting(&msg2, None, 1300).unwrap();
        res.complete_handshake_msg3(&msg3, 1400).unwrap();
        assert!(res.has_session(), "the responder's leg holds the session");
        assert!(leg_slot_nonzero_bytes(&res.leg) > 64);

        let leg = res.take_leg().expect("the leg was attached");
        assert!(leg.noise_session.is_some(), "the session left with the leg");
        let left = leg_slot_nonzero_bytes(&res.leg);
        assert!(
            left <= 8,
            "{left} non-zero bytes of the session stayed in the emptied leg slot"
        );
    }

    #[test]
    fn test_connection_failure() {
        // `mark_failed` releases the leg's Noise handshake handle. The failure
        // *state* now lives on the control machine, but the leg-local effect is
        // still observable: a completion attempt afterward reports `WrongState`
        // (the handle-presence gate) and no session is produced.
        let identity = make_peer_identity();
        let keypair = make_keypair();
        let mut conn = outbound_leg(LinkId::new(1), identity, 1000);
        conn.start_handshake(keypair, make_epoch(), 1100).unwrap();

        conn.mark_failed();

        assert!(!conn.has_session());
        assert!(
            conn.complete_handshake_accepting(&[0u8; 96], None, 1200)
                .is_err()
        );
    }

    #[test]
    fn test_wrong_direction_errors() {
        let identity = make_peer_identity();
        let keypair = make_keypair();

        // Outbound can't receive_handshake_init
        let mut outbound = outbound_leg(LinkId::new(1), identity, 1000);
        assert!(
            outbound
                .receive_handshake_init(keypair, make_epoch(), &[0u8; 33], None, 1100)
                .is_err()
        );

        // Inbound can't start_handshake
        let mut inbound = inbound_leg(LinkId::new(2), 1000);
        assert!(
            inbound
                .start_handshake(keypair, make_epoch(), 1100)
                .is_err()
        );
    }

    /// `LIVENESS_INTERVAL_MS` stays pinned to `NodeConfig`'s heartbeat default.
    ///
    /// The expectation is read from the default rather than repeated as a
    /// literal, so raising or lowering `heartbeat_interval_secs` without
    /// re-pinning the constant reds here instead of drifting unnoticed.
    #[test]
    fn liveness_interval_matches_the_heartbeat_config_default() {
        assert_eq!(
            LIVENESS_INTERVAL_MS,
            crate::config::NodeConfig::default().heartbeat_interval_secs * 1_000
        );
    }
}

/// T-SANSIO: the action vocabulary must stay plain, comparable data.
///
/// `PeerAction` is the sans-IO boundary between the pure reducer and its
/// driver. Requiring `Clone + Eq` is a compile-time statement that no variant
/// may carry a runtime handle (a socket, a `JoinHandle`, a channel sender),
/// since none of those are `Clone + Eq`. If a future variant smuggles one in,
/// this bound stops compiling.
#[cfg(test)]
mod action_contract {
    use super::PeerAction;

    fn assert_clone_eq<T: Clone + Eq>() {}

    #[test]
    fn peer_action_is_plain_comparable_data() {
        assert_clone_eq::<PeerAction>();
    }
}
