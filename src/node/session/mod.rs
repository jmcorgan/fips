//! End-to-end session state.
//!
//! Tracks Noise XK sessions between this node and remote endpoints.
//! Sessions are established via a three-message XK handshake
//! (SessionSetup/SessionAck/SessionMsg3) carried inside SessionDatagram
//! envelopes through the mesh.

use crate::NodeAddr;
use crate::config::SessionMmpConfig;
use crate::node::REKEY_JITTER_SECS;
use crate::noise::{HandshakeState, NoiseSession};
use crate::proto::mmp::MmpSessionState;
use crate::time::WallStamp;
use fips_core::time::{Clock, Instant};
use rand::RngExt;
use secp256k1::PublicKey;
use std::time::Duration;

/// The clock the session table measures its timers on: the host's monotonic
/// clock, so a step of the system clock neither fires nor holds a session
/// timer. Times the control API reports are converted to Unix milliseconds at
/// the edge, through `WallStamp`.
pub(crate) type SessionClock = crate::time::HostClock;

/// An instant on [`SessionClock`].
pub(crate) type SessionInstant = <SessionClock as Clock>::Instant;

/// The session clock's instant `ms` milliseconds after its test epoch.
#[cfg(test)]
pub(crate) fn session_at(ms: u64) -> SessionInstant {
    crate::time::at::<SessionClock>(ms)
}

/// `ms` milliseconds after `t`, for tests that name an instant relative to
/// another.
#[cfg(test)]
pub(crate) fn session_after(t: SessionInstant, ms: u64) -> SessionInstant {
    t.checked_add(Duration::from_millis(ms))
        .expect("a test instant fits the clock's range")
}

/// `ms` milliseconds before `t`, for tests that backdate a stamp.
#[cfg(test)]
pub(crate) fn session_before(t: SessionInstant, ms: u64) -> SessionInstant {
    t.checked_sub(Duration::from_millis(ms))
        .expect("a test instant fits the clock's range")
}

/// Time from `earlier` to `now` in whole milliseconds, zero when `earlier`
/// is the later one.
pub(crate) fn age_ms(now: SessionInstant, earlier: SessionInstant) -> u64 {
    now.saturating_duration_since(earlier).as_millis() as u64
}

/// Draw a fresh per-session rekey jitter from `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`.
fn draw_rekey_jitter() -> i64 {
    rand::rng().random_range(-REKEY_JITTER_SECS..=REKEY_JITTER_SECS)
}

/// State machine for an end-to-end session.
///
/// `Established` is intentionally larger than the handshake variants:
/// `NoiseSession` carries ring's `LessSafeKey` (×2, send + recv), each of
/// which embeds the precomputed Poly1305 key + per-implementation AEAD
/// state. That precomputation is exactly the win — it lets the per-packet
/// AEAD skip key derivation and dispatch straight to NEON / AVX. Boxing
/// the variant would add an allocation per session and double-indirection
/// on every encrypt/decrypt, working against that win.
#[allow(clippy::large_enum_variant)]
pub(crate) enum EndToEndState {
    /// We initiated: sent SessionSetup with Noise XK msg1, awaiting SessionAck.
    /// The entry may also hold responder candidates beside this leg.
    Initiating(HandshakeState),
    /// XK responder: processed msg1, sent msg2, awaiting msg3.
    ///
    /// The form a responder handshake is handed to `SessionEntry::new` in,
    /// which tests use to install a half-open entry directly. The entry
    /// keeps the handshake as a responder candidate and records its state
    /// as `Responding`.
    #[cfg_attr(not(test), allow(dead_code))]
    AwaitingMsg3(HandshakeState),
    /// Responder candidates only, held in the entry's candidate list, each
    /// awaiting its msg3. Transitions to Established when one completes.
    Responding,
    /// Handshake complete, NoiseSession available for encrypt/decrypt.
    Established(NoiseSession),
}

/// Most responder candidates one session entry holds.
///
/// A SessionSetup is unauthenticated: its msg1 is a bare ephemeral and the
/// source address is an envelope field, so anyone can open a half-open
/// handshake under another node's address. Holding one candidate per
/// distinct msg1 lets the address's owner be answered beside a forger. An
/// honest address needs one (two in a simultaneous initiation with a lost
/// first ack). To keep the owner's setups refused a forger has to keep every
/// slot younger than `HALF_OPEN_MIN_AGE`, about this many forged setups per
/// minimum age per address. Candidates count individually toward the
/// half-open share of the session table, which bounds their memory. No
/// measured basis.
pub(crate) const MAX_HALF_OPEN_RESPONDERS: usize = 4;

/// How long a responder candidate is protected from eviction, and how long
/// an entry holding only responder candidates holds this node's own traffic
/// before this node initiates itself.
///
/// Sized above the initiator's first msg3 resend (`handshake_resend_interval_ms`
/// 1 s with backoff 2.0 at the defaults), so a genuine msg3 or its first resend
/// lands inside it, and well above one honest round trip, so an honest
/// simultaneous initiation completes inside it. A forger holds this node's
/// own traffic to an address for this long per hold it opens there, and a
/// hold lasts at least a handshake timeout from its first setup; to keep the
/// owner's own setups refused it must refresh every candidate slot within
/// this age. No measured basis.
pub(crate) const HALF_OPEN_MIN_AGE: Duration = Duration::from_secs(5);

/// One responder handshake held for a SessionSetup naming the entry's
/// address, awaiting the msg3 that would prove who sent it.
pub(crate) struct ResponderCandidate {
    /// The responder handshake, having read the setup's msg1.
    handshake: HandshakeState,
    /// The setup's msg1 (the initiator's ephemeral), so an identical resent
    /// setup draws this candidate's own ack. Empty when unknown.
    msg1: Vec<u8>,
    /// The encoded SessionAck this candidate answered with.
    ack: Option<Vec<u8>>,
    /// The link peer the setup arrived over, if known.
    link_peer: Option<NodeAddr>,
    /// When the setup was admitted.
    received_at: SessionInstant,
}

impl ResponderCandidate {
    /// A candidate for a setup admitted at `received_at` over `link_peer`.
    pub(crate) fn new(
        handshake: HandshakeState,
        msg1: Vec<u8>,
        ack: Vec<u8>,
        link_peer: NodeAddr,
        received_at: SessionInstant,
    ) -> Self {
        Self {
            handshake,
            msg1,
            ack: Some(ack),
            link_peer: Some(link_peer),
            received_at,
        }
    }

    /// The responder handshake, to try a msg3 against.
    pub(crate) fn handshake_mut(&mut self) -> &mut HandshakeState {
        &mut self.handshake
    }

    /// Give up the handshake, for a completed msg3.
    pub(crate) fn into_handshake(self) -> HandshakeState {
        self.handshake
    }
}

/// Where a new responder candidate goes in an entry's candidate list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateAdmission {
    /// Below the bound: added beside the others.
    Room,
    /// At the bound: replaces the candidate at this index, the oldest one at
    /// least `HALF_OPEN_MIN_AGE` old, preferring one from the newcomer's own
    /// link peer.
    Evict(usize),
    /// At the bound with every candidate younger than the minimum age.
    Refuse,
}

/// Decide where a candidate arriving over `link_peer` at `now` goes.
pub(crate) fn admit_candidate(
    candidates: &[ResponderCandidate],
    link_peer: &NodeAddr,
    now: SessionInstant,
) -> CandidateAdmission {
    if candidates.len() < MAX_HALF_OPEN_RESPONDERS {
        return CandidateAdmission::Room;
    }
    let aged =
        |c: &&ResponderCandidate| now.saturating_duration_since(c.received_at) >= HALF_OPEN_MIN_AGE;
    let oldest = |same_link: bool| {
        candidates
            .iter()
            .enumerate()
            .filter(|(_, c)| aged(c))
            .filter(|(_, c)| !same_link || c.link_peer.as_ref() == Some(link_peer))
            .min_by_key(|(i, c)| (c.received_at, *i))
            .map(|(i, _)| i)
    };
    match oldest(true).or_else(|| oldest(false)) {
        Some(i) => CandidateAdmission::Evict(i),
        None => CandidateAdmission::Refuse,
    }
}

/// Which key epoch a frame decrypted against in the trial-decrypt
/// cascade. Reported by [`SessionEntry::fsp_trial_decrypt`] so the
/// receive path can react to a non-`Current` epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EpochSlot {
    /// The current (active) session — steady-state traffic.
    Current,
    /// The pending (new, not yet promoted) session — the peer cut over
    /// before this endpoint did.
    Pending,
    /// The previous (draining) session — old-epoch stragglers.
    Previous,
}

impl EndToEndState {
    /// Check if the session is established and ready for data.
    pub(crate) fn is_established(&self) -> bool {
        matches!(self, EndToEndState::Established(_))
    }

    /// Check if we are the initiator (waiting for ack).
    pub(crate) fn is_initiating(&self) -> bool {
        matches!(self, EndToEndState::Initiating(_))
    }

    /// Check if we are an XK responder awaiting msg3, with no initiator leg.
    pub(crate) fn is_awaiting_msg3(&self) -> bool {
        matches!(
            self,
            EndToEndState::AwaitingMsg3(_) | EndToEndState::Responding
        )
    }
}

/// A single end-to-end session with a remote node.
///
/// The state is wrapped in `Option` to allow taking ownership of the
/// handshake state during transitions without placeholder values.
/// The state is `None` only transiently during handler processing.
pub(crate) struct SessionEntry {
    /// Remote node's address (session table key).
    #[allow(dead_code)]
    remote_addr: NodeAddr,
    /// Remote node's static public key.
    remote_pubkey: PublicKey,
    /// Current session state. `None` only during state transitions.
    state: Option<EndToEndState>,
    /// Responder candidates, one per distinct setup naming this address, each
    /// awaiting its msg3. Held beside an initiator leg too, so neither blocks
    /// the other: the first leg to complete establishes the session. On a
    /// node that lost the initiation tie-break they are also kept beside the
    /// session its own leg established, and one completing replaces it.
    candidates: Vec<ResponderCandidate>,
    /// When this entry first held a responder candidate. Never
    /// refreshed by later candidates, so a forger cannot hold this node's own
    /// initiation back by forging again. Kept when a msg3 drops the last
    /// candidate, so the hold outlives the candidates a forger can remove at
    /// will; cleared once no candidate is left and it is a handshake timeout
    /// old, or when a leg completes.
    opened_at: Option<SessionInstant>,
    /// This node's initiator leg lost a simultaneous-initiation tie-break and
    /// its setup resends are paused: the winner dropped our setup, and a
    /// resend reaching it after it established would arm a spurious rekey.
    initiator_paused: bool,
    /// When the session was created.
    #[cfg_attr(not(test), allow(dead_code))]
    created_at: SessionInstant,
    /// Last application data activity timestamp.
    /// Only updated for DataPacket send/receive and session establishment.
    /// MMP reports do not update this field. Used for idle session timeout.
    last_activity: SessionInstant,
    /// When the session transitioned to Established.
    /// Used to compute session-relative timestamps for the FSP inner header.
    /// `None` until the session is established.
    session_start: Option<SessionInstant>,
    /// Remaining data packets that should include COORDS_PRESENT.
    /// Initialized from config when session becomes Established;
    /// reset on CoordsRequired receipt.
    coords_warmup_remaining: u8,
    /// Whether this node initiated the Noise handshake.
    /// Used for spin bit role assignment in session-layer MMP.
    is_initiator: bool,
    /// Largest on-the-wire frame this node has sent toward the remote since
    /// the last accepted path-MTU decrease or release, in bytes.
    ///
    /// Corroborates a reactive `MtuExceeded`, which is unauthenticated: an
    /// honest report exists only because a frame this node emitted did not
    /// fit some hop, so an honest report always names a value below this.
    /// Reset on each accepted decrease and on release so one historical
    /// large send cannot vouch for a session's whole lifetime.
    max_sent_wire_len: u16,
    /// Session-layer MMP state. Initialized on Established transition.
    mmp: Option<MmpSessionState>,

    // === Traffic Counters ===
    /// Total data packets sent on this session.
    packets_sent: u64,
    /// Total data packets received on this session.
    packets_recv: u64,
    /// Total data bytes sent on this session (FSP payload).
    bytes_sent: u64,
    /// Total data bytes received on this session (FSP payload).
    bytes_recv: u64,

    // === Handshake Resend ===
    /// The last initial-handshake message this side sent and has no proof the
    /// peer received: SessionSetup while initiating, and on an established
    /// initiator its SessionMsg3 until an inbound frame authenticates on the
    /// session or the resend budget is spent. The state says which one it is,
    /// and which sweep resends it. A responder candidate keeps its own
    /// SessionAck, which is resent only in answer to a resent setup.
    handshake_payload: Option<Vec<u8>>,
    /// Number of resends performed.
    resend_count: u32,
    /// When the next resend should fire. `None` = no resend scheduled.
    next_resend_at: Option<SessionInstant>,

    // === Rekey (Key Rotation) ===
    /// Current K-bit epoch value (alternates each rekey).
    current_k_bit: bool,
    /// Previous NoiseSession during drain window after cutover.
    previous_noise_session: Option<NoiseSession>,
    /// When drain window started. `None` = no drain.
    drain_started: Option<SessionInstant>,
    /// Last time an inbound frame authenticated against the `previous`
    /// slot. `None` = the `previous` slot has not been used since the
    /// drain began.
    ///
    /// Drives peer-progress-aware retirement of the old epoch: the drain
    /// window does not expire until `DRAIN_WINDOW_SECS` have elapsed
    /// since the LATER of the cutover and the last `previous`-slot
    /// decrypt. The old epoch therefore lives as long as the peer is
    /// still transmitting on it — closing the rep-003 gap where the
    /// initiator erased the `previous` slot on a fixed wall-clock timer
    /// while the peer (having never received msg3) was still sealing
    /// every frame in the old epoch, leaving the trial-decrypt cascade
    /// with no slot that could decrypt them.
    previous_last_used: Option<SessionInstant>,
    /// In-progress rekey state (runs alongside Established session).
    rekey_state: Option<HandshakeState>,
    /// Pending completed session awaiting K-bit cutover.
    pending_new_session: Option<NoiseSession>,
    /// Whether we initiated the current rekey.
    rekey_initiator: bool,
    /// Dampening: last time peer sent us a rekey msg1.
    last_peer_rekey: Option<SessionInstant>,
    /// When this node armed its current rekey handshake as initiator, which
    /// bounds how long that handshake waits for a SessionAck.
    ///
    /// Written only by `begin_rekey`, so putting the handshake back after
    /// an unreadable SessionAck does not move it. Read only while a
    /// handshake is armed and `rekey_initiator` is set, which is why it is
    /// never cleared.
    initiated: Option<SessionInstant>,
    /// When this side's FSP rekey handshake completed and produced the
    /// `pending` session: the initiator sending msg3, or the
    /// responder accepting it. Cleared on cutover.
    ///
    /// On the initiator it drives the liveness-bound cutover timer, which
    /// is no longer safety-critical: overlapping-epoch trial-decrypt covers
    /// any cutover skew, so it only bounds how long the initiator
    /// advertises the old K-bit. On the responder it dates the wait for the
    /// peer's cut-over (`pending_stale`) and never expires the keys.
    rekey_completed: Option<SessionInstant>,
    /// Encoded SessionMsg3 payload retained for retransmission (initiator).
    /// Set when the rekey initiator sends msg3; cleared once the responder
    /// is confirmed on the new epoch (an authenticated peer frame against
    /// `pending` or new `current`) or the rekey cycle is abandoned.
    /// Retransmission lifetime is tied to responder reception of msg3,
    /// decoupled from the initiator's own cutover.
    rekey_msg3_payload: Option<Vec<u8>>,
    /// When the next rekey msg3 retransmission should fire.
    /// `None` = no retransmission scheduled.
    rekey_msg3_next_resend: Option<SessionInstant>,
    /// Number of rekey msg3 retransmissions performed so far.
    rekey_msg3_resend_count: u32,
    /// Whether the rekey peer has been observed on the new epoch — set
    /// when an inbound frame authenticates against `pending` or against
    /// the post-cutover `current`. Stops msg3 retransmission.
    peer_new_epoch_confirmed: bool,
    /// Per-session symmetric jitter applied to the rekey timer trigger.
    /// Drawn once at construction (and at each cutover) uniformly from
    /// `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`. Desynchronizes
    /// dual-initiation in symmetric-start meshes; mean interval is
    /// preserved.
    rekey_jitter_secs: i64,
}

impl SessionEntry {
    /// Create a new session entry.
    pub(crate) fn new(
        remote_addr: NodeAddr,
        remote_pubkey: PublicKey,
        state: EndToEndState,
        now: SessionInstant,
        is_initiator: bool,
    ) -> Self {
        let (state, candidates, opened_at) = match state {
            EndToEndState::AwaitingMsg3(handshake) => (
                EndToEndState::Responding,
                vec![ResponderCandidate {
                    handshake,
                    msg1: Vec::new(),
                    ack: None,
                    link_peer: None,
                    received_at: now,
                }],
                Some(now),
            ),
            other => (other, Vec::new(), None),
        };
        Self {
            remote_addr,
            remote_pubkey,
            state: Some(state),
            candidates,
            opened_at,
            initiator_paused: false,
            created_at: now,
            last_activity: now,
            session_start: None,
            coords_warmup_remaining: 0,
            is_initiator,
            max_sent_wire_len: 0,
            mmp: None,
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            handshake_payload: None,
            resend_count: 0,
            next_resend_at: None,
            current_k_bit: false,
            previous_noise_session: None,
            drain_started: None,
            previous_last_used: None,
            rekey_state: None,
            pending_new_session: None,
            rekey_initiator: false,
            last_peer_rekey: None,
            initiated: None,
            rekey_completed: None,
            rekey_msg3_payload: None,
            rekey_msg3_next_resend: None,
            rekey_msg3_resend_count: 0,
            peer_new_epoch_confirmed: false,
            rekey_jitter_secs: draw_rekey_jitter(),
        }
    }

    /// Get the remote node's public key.
    pub(crate) fn remote_pubkey(&self) -> &PublicKey {
        &self.remote_pubkey
    }

    /// Get the current session state.
    #[cfg(test)]
    pub(crate) fn state(&self) -> &EndToEndState {
        self.state
            .as_ref()
            .expect("session state taken but not restored")
    }

    /// Get mutable access to the session state.
    pub(crate) fn state_mut(&mut self) -> &mut EndToEndState {
        self.state
            .as_mut()
            .expect("session state taken but not restored")
    }

    /// Replace the session state. Establishing drops every responder
    /// candidate: the session is decided. A tie-break loser whose own leg
    /// completes takes its candidates out first and puts them back after.
    pub(crate) fn set_state(&mut self, state: EndToEndState) {
        if state.is_established() {
            self.candidates.clear();
            self.opened_at = None;
            self.initiator_paused = false;
        }
        self.state = Some(state);
    }

    /// Take the state out, leaving `None`.
    ///
    /// The caller must call `set_state()` to restore a valid state,
    /// or discard the entry entirely.
    pub(crate) fn take_state(&mut self) -> Option<EndToEndState> {
        self.state.take()
    }

    /// Update the last application data activity timestamp.
    ///
    /// Only call for DataPacket send/receive and session establishment,
    /// not for MMP reports. Used by the idle session timeout.
    pub(crate) fn touch(&mut self, now: SessionInstant) {
        self.last_activity = now;
    }

    /// Check if the session is established.
    pub(crate) fn is_established(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_established())
    }

    /// Check if we are the initiator (waiting for ack). For display; the
    /// protocol paths use `has_initiator_leg`.
    pub(crate) fn is_initiating(&self) -> bool {
        self.has_initiator_leg()
    }

    /// Check if we are an XK responder awaiting msg3 with no initiator leg.
    /// For display; the protocol paths use `has_candidates`.
    pub(crate) fn is_awaiting_msg3(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_awaiting_msg3())
    }

    // === Handshake legs ===

    /// Whether this node's own initiator handshake is in flight here.
    pub(crate) fn has_initiator_leg(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_initiating())
    }

    /// Whether any responder candidate awaits its msg3 here.
    pub(crate) fn has_candidates(&self) -> bool {
        !self.candidates.is_empty()
    }

    /// How many responder candidates await their msg3 here.
    #[cfg(test)]
    pub(crate) fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Whether a received setup opened a hold on this entry at least
    /// `HALF_OPEN_MIN_AGE` ago, by `opened_at`, with no leg completed. The
    /// hold's age counts whether or not its candidates are still here: a
    /// forger can drop its own candidate with a msg3 whenever it likes.
    pub(crate) fn responder_hold_aged(&self, now: SessionInstant) -> bool {
        self.opened_at
            .is_some_and(|t| now.saturating_duration_since(t) >= HALF_OPEN_MIN_AGE)
    }

    /// Whether a received setup opened a hold on this entry less than
    /// `timeout` ago. Such an entry is kept even with no leg left in it,
    /// so the next setup for the address joins the same hold instead of
    /// opening a fresh one.
    pub(crate) fn responder_hold_open(&self, now: SessionInstant, timeout: Duration) -> bool {
        self.opened_at
            .is_some_and(|t| now.saturating_duration_since(t) <= timeout)
    }

    /// How much of the half-open share this entry takes: one per responder
    /// candidate, and one for an open hold whose candidates are gone, since
    /// that entry is kept on the strength of unproven setups too.
    pub(crate) fn half_open_count(&self) -> usize {
        self.candidates
            .len()
            .max(usize::from(self.opened_at.is_some()))
    }

    /// Whether the entry has no initiator leg and a hold at least
    /// `HALF_OPEN_MIN_AGE` old, so this node should stop waiting for the
    /// responder candidates and initiate itself.
    pub(crate) fn responder_hold_expired(&self, now: SessionInstant) -> bool {
        !self.has_initiator_leg() && self.responder_hold_aged(now)
    }

    /// The stored ack of the candidate whose setup carried `msg1`, if any.
    pub(crate) fn candidate_ack(&self, msg1: &[u8]) -> Option<&[u8]> {
        self.candidates
            .iter()
            .find(|c| !c.msg1.is_empty() && c.msg1 == msg1)
            .and_then(|c| c.ack.as_deref())
    }

    /// Where a candidate arriving over `link_peer` at `now` would go.
    pub(crate) fn candidate_admission(
        &self,
        link_peer: &NodeAddr,
        now: SessionInstant,
    ) -> CandidateAdmission {
        admit_candidate(&self.candidates, link_peer, now)
    }

    /// Hold `candidate`, placed as `admission` decided. The entry's
    /// `opened_at` is set by its first candidate only.
    pub(crate) fn add_candidate(
        &mut self,
        candidate: ResponderCandidate,
        admission: CandidateAdmission,
    ) {
        self.opened_at.get_or_insert(candidate.received_at);
        match admission {
            CandidateAdmission::Room => self.candidates.push(candidate),
            CandidateAdmission::Evict(i) => self.candidates[i] = candidate,
            CandidateAdmission::Refuse => {}
        }
        if self.state.is_none() {
            self.state = Some(EndToEndState::Responding);
        }
    }

    /// Take every candidate out, to try a msg3 against each.
    pub(crate) fn take_candidates(&mut self) -> Vec<ResponderCandidate> {
        std::mem::take(&mut self.candidates)
    }

    /// Put candidates back after a msg3 was tried against them.
    pub(crate) fn restore_candidates(&mut self, candidates: Vec<ResponderCandidate>) {
        self.candidates = candidates;
    }

    /// Drop candidates whose setup was admitted more than `timeout`
    /// before `now`. Returns how many went.
    pub(crate) fn expire_candidates(&mut self, now: SessionInstant, timeout: Duration) -> usize {
        let before = self.candidates.len();
        self.candidates
            .retain(|c| now.saturating_duration_since(c.received_at) <= timeout);
        self.settle_opened(now, timeout);
        before - self.candidates.len()
    }

    /// Forget `opened_at` once no candidate is left and the hold is a
    /// handshake timeout old, so a setup arriving later opens the hold
    /// afresh. Otherwise it would inherit the age of candidates that no
    /// longer exist, and a leg it paused would resume at once. Only time
    /// clears it: a forger cannot hasten that, while dropping its own
    /// candidate with a msg3 is something it can do as often as it likes,
    /// and must not restart the hold.
    fn settle_opened(&mut self, now: SessionInstant, timeout: Duration) {
        if self.candidates.is_empty() && !self.responder_hold_open(now, timeout) {
            self.opened_at = None;
        }
    }

    /// Attach this node's own initiator leg to an entry that holds only
    /// responder candidates, keeping them for a late msg3.
    ///
    /// The entry now names the key this node was given, counts as initiated
    /// by this node, and dates from now, as an entry `initiate_session`
    /// inserts would.
    pub(crate) fn attach_initiator(
        &mut self,
        handshake: HandshakeState,
        remote_pubkey: PublicKey,
        setup_payload: Vec<u8>,
        now: SessionInstant,
        next_resend_at: SessionInstant,
    ) {
        self.state = Some(EndToEndState::Initiating(handshake));
        self.remote_pubkey = remote_pubkey;
        self.is_initiator = true;
        self.created_at = now;
        self.last_activity = now;
        self.initiator_paused = false;
        self.set_handshake_payload(setup_payload, next_resend_at);
    }

    /// Pause this node's own setup resends: it lost the simultaneous
    /// initiation tie-break and is answering the peer's setup instead.
    pub(crate) fn pause_initiator(&mut self) {
        self.initiator_paused = true;
    }

    /// Whether this node's own setup resends are paused.
    pub(crate) fn initiator_paused(&self) -> bool {
        self.initiator_paused
    }

    /// Resume this node's own setup resends, due at `next_resend_at`.
    pub(crate) fn resume_initiator(&mut self, next_resend_at: SessionInstant) {
        self.initiator_paused = false;
        self.next_resend_at = Some(next_resend_at);
    }

    /// Drop this node's initiator leg (including one already taken out of
    /// the state), leaving the responder candidates: the entry is again one
    /// a received setup opened.
    pub(crate) fn drop_initiator_leg(&mut self) {
        self.state = Some(EndToEndState::Responding);
        self.is_initiator = false;
        self.initiator_paused = false;
        self.clear_handshake_payload();
    }

    /// Move every timestamp the handshake legs are aged by `by_ms` into the
    /// past. Test-only: stands for that much time passing.
    #[cfg(test)]
    pub(crate) fn backdate_handshake(&mut self, by_ms: u64) {
        use crate::time::TestEpoch;
        let back = |t: SessionInstant| {
            t.checked_sub(Duration::from_millis(by_ms))
                .unwrap_or_else(SessionClock::epoch)
        };
        for c in &mut self.candidates {
            c.received_at = back(c.received_at);
        }
        if let Some(t) = self.opened_at.as_mut() {
            *t = back(*t);
        }
        self.created_at = back(self.created_at);
        self.last_activity = back(self.last_activity);
    }

    /// Get creation time. Used as the probe's session-identity check: an
    /// entry with a different creation stamp is a replacement, not ours.
    pub(crate) fn created_at(&self) -> SessionInstant {
        self.created_at
    }

    /// Get last activity time.
    pub(crate) fn last_activity(&self) -> SessionInstant {
        self.last_activity
    }

    /// Remaining DataPackets that should include COORDS_PRESENT.
    pub(crate) fn coords_warmup_remaining(&self) -> u8 {
        self.coords_warmup_remaining
    }

    /// Set the coords warmup counter (used on Established transition
    /// and CoordsRequired reset).
    pub(crate) fn set_coords_warmup_remaining(&mut self, value: u8) {
        self.coords_warmup_remaining = value;
    }

    /// Largest wire frame sent toward the remote since the last accepted
    /// path-MTU decrease or release.
    pub(crate) fn max_sent_wire_len(&self) -> u16 {
        self.max_sent_wire_len
    }

    /// Note a frame of `wire_len` bytes sent toward the remote, keeping the
    /// largest. Frames beyond `u16::MAX` saturate, which only ever makes the
    /// corroboration more permissive and cannot exceed what a path MTU can
    /// name.
    pub(crate) fn record_sent_wire_len(&mut self, wire_len: usize) {
        let wire_len = u16::try_from(wire_len).unwrap_or(u16::MAX);
        self.max_sent_wire_len = self.max_sent_wire_len.max(wire_len);
    }

    /// Forget what has been sent, so the next reactive report needs fresh
    /// evidence of its own.
    pub(crate) fn clear_sent_wire_len(&mut self) {
        self.max_sent_wire_len = 0;
    }

    /// Mark the session as started (transition to Established).
    ///
    /// Records the current time as the session start for computing
    /// session-relative timestamps in the FSP inner header.
    pub(crate) fn mark_established(&mut self, now: SessionInstant) {
        self.session_start = Some(now);
    }

    /// Compute a session-relative timestamp for the FSP inner header.
    ///
    /// Returns the milliseconds from the session start to `now` truncated
    /// to u32, or 0 when `now` reads before the session start. Wraps
    /// naturally at ~49.7 days, which is fine for relative timing. Before
    /// the session is established it is `now`'s Unix milliseconds truncated
    /// the same way, as when an unset start read as zero.
    pub(crate) fn session_timestamp(&self, now: SessionInstant) -> u32 {
        match self.session_start {
            Some(start) => age_ms(now, start) as u32,
            None => now.wall_ms() as u32,
        }
    }

    /// Whether this node initiated the Noise handshake.
    pub(crate) fn is_initiator(&self) -> bool {
        self.is_initiator
    }

    /// Get a reference to the session-layer MMP state, if initialized.
    pub(crate) fn mmp(&self) -> Option<&MmpSessionState> {
        self.mmp.as_ref()
    }

    /// Get a mutable reference to the session-layer MMP state, if initialized.
    pub(crate) fn mmp_mut(&mut self) -> Option<&mut MmpSessionState> {
        self.mmp.as_mut()
    }

    /// Initialize session-layer MMP state (called on Established transition).
    pub(crate) fn init_mmp(&mut self, config: &SessionMmpConfig) {
        self.mmp = Some(MmpSessionState::new(
            config.mode,
            config.log_interval_secs,
            config.owd_window_size,
            self.is_initiator,
        ));
    }

    // === Traffic Counters ===

    /// Record a sent data packet.
    pub(crate) fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record a received data packet.
    pub(crate) fn record_recv(&mut self, bytes: usize) {
        self.packets_recv += 1;
        self.bytes_recv += bytes as u64;
    }

    /// Get traffic counters: (packets_sent, packets_recv, bytes_sent, bytes_recv).
    pub(crate) fn traffic_counters(&self) -> (u64, u64, u64, u64) {
        (
            self.packets_sent,
            self.packets_recv,
            self.bytes_sent,
            self.bytes_recv,
        )
    }

    // === Handshake Resend ===

    /// Store the encoded session-layer payload for potential resend.
    ///
    /// For initiators, this is the SessionSetup payload bytes.
    /// For an initiator that has just become established, this is its
    /// SessionMsg3 payload bytes, held until the responder is heard from.
    /// The payload is re-wrapped in a fresh SessionDatagram on each resend
    /// so routing can adapt to topology changes.
    pub(crate) fn set_handshake_payload(
        &mut self,
        payload: Vec<u8>,
        next_resend_at: SessionInstant,
    ) {
        self.handshake_payload = Some(payload);
        self.resend_count = 0;
        self.next_resend_at = Some(next_resend_at);
    }

    /// Get the stored handshake payload for resend.
    pub(crate) fn handshake_payload(&self) -> Option<&[u8]> {
        self.handshake_payload.as_deref()
    }

    /// Clear the stored handshake payload (an inbound frame authenticated on
    /// the session, or the msg3 resend budget is spent).
    pub(crate) fn clear_handshake_payload(&mut self) {
        self.handshake_payload = None;
        self.next_resend_at = None;
    }

    /// Number of resends performed so far.
    pub(crate) fn resend_count(&self) -> u32 {
        self.resend_count
    }

    /// When the next resend should fire. `None` = no resend scheduled.
    pub(crate) fn next_resend_at(&self) -> Option<SessionInstant> {
        self.next_resend_at
    }

    /// Record a resend and schedule the next one.
    pub(crate) fn record_resend(&mut self, next_resend_at: SessionInstant) {
        self.resend_count += 1;
        self.next_resend_at = Some(next_resend_at);
    }

    // === Rekey (Key Rotation) ===

    /// Current K-bit epoch value.
    pub(crate) fn current_k_bit(&self) -> bool {
        self.current_k_bit
    }

    /// Whether a rekey is currently in progress.
    pub(crate) fn has_rekey_in_progress(&self) -> bool {
        self.rekey_state.is_some()
    }

    /// Get the pending new session (completed rekey, not yet cut over).
    pub(crate) fn pending_new_session(&self) -> Option<&NoiseSession> {
        self.pending_new_session.as_ref()
    }

    /// Whether we initiated the current rekey.
    pub(crate) fn is_rekey_initiator(&self) -> bool {
        self.rekey_initiator
    }

    /// Check if rekey initiation is dampened.
    pub(crate) fn is_rekey_dampened(&self, now: SessionInstant, dampening: Duration) -> bool {
        let Some(last) = self.last_peer_rekey else {
            return false;
        };
        now.saturating_duration_since(last) < dampening
    }

    /// When the peer last initiated a rekey, or `None` if it never has.
    ///
    /// Bounds the age of any rekey state armed by the peer's setup message,
    /// including a pending session derived from it.
    pub(crate) fn last_peer_rekey(&self) -> Option<SessionInstant> {
        self.last_peer_rekey
    }

    /// When this node armed its current rekey handshake as initiator, or
    /// `None` if it never has.
    ///
    /// Bounds the age of a handshake this node armed, independently of any
    /// rekey the peer started.
    pub(crate) fn initiated(&self) -> Option<SessionInstant> {
        self.initiated
    }

    /// Record that the peer initiated a rekey (for dampening).
    pub(crate) fn record_peer_rekey(&mut self, now: SessionInstant) {
        self.last_peer_rekey = Some(now);
    }

    /// When the session transitioned to Established (for rekey timer), or
    /// `None` before it has.
    pub(crate) fn session_start(&self) -> Option<SessionInstant> {
        self.session_start
    }

    /// Get the current send counter from the established NoiseSession.
    pub(crate) fn send_counter(&self) -> u64 {
        match self.state.as_ref() {
            Some(EndToEndState::Established(s)) => s.current_send_counter(),
            _ => 0,
        }
    }

    /// When this side's FSP rekey handshake completed: the initiator
    /// sending msg3, or the responder accepting it.
    pub(crate) fn rekey_completed(&self) -> Option<SessionInstant> {
        self.rekey_completed
    }

    /// Per-session symmetric rekey-timer jitter offset (seconds).
    ///
    /// Drawn at session construction and at each rekey cutover; uniform
    /// over `[-REKEY_JITTER_SECS, +REKEY_JITTER_SECS]`. Callers add this
    /// to the configured `node.rekey.after_secs` to obtain the effective
    /// trigger interval for this session.
    pub(crate) fn rekey_jitter_secs(&self) -> i64 {
        self.rekey_jitter_secs
    }

    /// Record when this side's FSP rekey handshake completed and the
    /// `pending` session appeared.
    pub(crate) fn set_rekey_completed(&mut self, at: SessionInstant) {
        self.rekey_completed = Some(at);
    }

    // === Rekey msg3 Retransmission (Initiator, liveness-only) ===

    /// Retain the encoded SessionMsg3 payload for retransmission and
    /// schedule the first resend. Called by the rekey initiator after
    /// sending msg3.
    ///
    /// Retransmission is a liveness mechanism: the responder must
    /// eventually receive msg3 to derive the new session. It runs until
    /// the peer is confirmed on the new epoch, independent of the
    /// initiator's own cutover.
    pub(crate) fn set_rekey_msg3_payload(
        &mut self,
        payload: Vec<u8>,
        next_resend_at: SessionInstant,
    ) {
        self.rekey_msg3_payload = Some(payload);
        self.rekey_msg3_next_resend = Some(next_resend_at);
        self.rekey_msg3_resend_count = 0;
        self.peer_new_epoch_confirmed = false;
    }

    /// Get the retained rekey msg3 payload for retransmission.
    pub(crate) fn rekey_msg3_payload(&self) -> Option<&[u8]> {
        self.rekey_msg3_payload.as_deref()
    }

    /// When the next rekey msg3 retransmission should fire, or `None` if
    /// none is scheduled.
    pub(crate) fn rekey_msg3_next_resend(&self) -> Option<SessionInstant> {
        self.rekey_msg3_next_resend
    }

    /// Number of rekey msg3 retransmissions performed so far.
    pub(crate) fn rekey_msg3_resend_count(&self) -> u32 {
        self.rekey_msg3_resend_count
    }

    /// Record a rekey msg3 retransmission and schedule the next one.
    pub(crate) fn record_rekey_msg3_resend(&mut self, next_resend_at: SessionInstant) {
        self.rekey_msg3_resend_count += 1;
        self.rekey_msg3_next_resend = Some(next_resend_at);
    }

    /// Clear the retained rekey msg3 payload (responder confirmed on the
    /// new epoch, or the cycle abandoned).
    pub(crate) fn clear_rekey_msg3_payload(&mut self) {
        self.rekey_msg3_payload = None;
        self.rekey_msg3_next_resend = None;
        self.rekey_msg3_resend_count = 0;
    }

    /// Whether the rekey peer has been observed on the new epoch.
    #[cfg(test)]
    pub(crate) fn peer_new_epoch_confirmed(&self) -> bool {
        self.peer_new_epoch_confirmed
    }

    /// Mark the rekey peer as confirmed on the new epoch and stop msg3
    /// retransmission. Called when an inbound frame authenticates against
    /// the `pending` or post-cutover `current` session.
    pub(crate) fn confirm_peer_new_epoch(&mut self) {
        self.peer_new_epoch_confirmed = true;
        self.clear_rekey_msg3_payload();
    }

    // === Overlapping-epoch trial-decrypt slots ===

    /// Mutable access to the current (active) `NoiseSession`, if established.
    pub(crate) fn current_noise_session_mut(&mut self) -> Option<&mut NoiseSession> {
        match self.state.as_mut() {
            Some(EndToEndState::Established(s)) => Some(s),
            _ => None,
        }
    }

    /// Trial-decrypt an encrypted FSP frame against every live key epoch.
    ///
    /// During a rekey window an endpoint may legitimately receive frames
    /// sealed in up to three epochs: `current` (steady state), `pending`
    /// (the peer cut over before this endpoint did), and `previous`
    /// (drain-window stragglers sealed in the old epoch). This cascade
    /// makes the receive path able to decrypt any of them, so no cutover
    /// ordering and no packet reordering can cause a decrypt failure.
    ///
    /// The received K-bit is an ordering hint only — it selects which
    /// slot to try first to save one cheap `check()` rejection on the
    /// common cut-over-in-progress packet. Correctness never depends on
    /// it.
    ///
    /// Continues the cascade on **any** error, including
    /// `ReplayDetected`: a replay rejection from a non-matching slot is
    /// just "wrong key, try the next one." This is replay-safe by
    /// construction — `decrypt_with_replay_check_and_aad` only mutates a
    /// slot's `ReplayWindow` after a successful decrypt, so a failed
    /// trial against the wrong slot leaves that slot untouched. Only the
    /// slot that authenticates the packet advances its window.
    ///
    /// A successful decrypt against the `previous` slot refreshes the
    /// drain deadline (`refresh_previous_use`): the old epoch must stay
    /// retained as long as the peer is still sealing frames in it. See
    /// [`SessionEntry::drain_expired`] for why.
    ///
    /// Returns the plaintext plus the slot it decrypted against, or
    /// `None` if every live slot failed (a genuine drop).
    pub(crate) fn fsp_trial_decrypt(
        &mut self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
        received_k_bit: bool,
        now: SessionInstant,
    ) -> Option<(Vec<u8>, EpochSlot)> {
        // Hint: if the received K-bit differs from our current epoch and
        // we hold a pending session, the peer has likely cut over — try
        // `pending` first. Pure optimisation; the cascade still tries
        // every slot regardless.
        let pending_first =
            received_k_bit != self.current_k_bit && self.pending_new_session.is_some();

        let order: [EpochSlot; 3] = if pending_first {
            [EpochSlot::Pending, EpochSlot::Current, EpochSlot::Previous]
        } else {
            [EpochSlot::Current, EpochSlot::Pending, EpochSlot::Previous]
        };

        for slot in order {
            let session = match slot {
                EpochSlot::Current => self.current_noise_session_mut(),
                EpochSlot::Pending => self.pending_new_session.as_mut(),
                EpochSlot::Previous => self.previous_noise_session.as_mut(),
            };
            if let Some(session) = session
                && let Ok(pt) = session.decrypt_with_replay_check_and_aad(ciphertext, counter, aad)
            {
                // The peer is still transmitting on the old epoch:
                // push the drain deadline out so the `previous` slot
                // is not retired out from under a peer still using it.
                if slot == EpochSlot::Previous {
                    self.refresh_previous_use(now);
                }
                return Some((pt, slot));
            }
        }
        None
    }

    /// Store a completed rekey session.
    pub(crate) fn set_pending_session(&mut self, session: NoiseSession) {
        self.pending_new_session = Some(session);
        self.rekey_state = None;
    }

    /// Set the rekey handshake state (in-progress XK handshake).
    pub(crate) fn set_rekey_state(&mut self, state: HandshakeState, is_initiator: bool) {
        self.rekey_state = Some(state);
        self.rekey_initiator = is_initiator;
    }

    /// Arm a rekey handshake this node initiated, and stamp its deadline.
    ///
    /// The only writer of `initiated`. The restore after an unreadable
    /// SessionAck goes through `set_rekey_state` instead and must stay
    /// there: a restamping restore would let a stream of forged acks hold
    /// the rekey open for good.
    pub(crate) fn begin_rekey(&mut self, state: HandshakeState, now: SessionInstant) {
        self.rekey_state = Some(state);
        self.rekey_initiator = true;
        self.initiated = Some(now);
    }

    /// Take the rekey state for processing.
    pub(crate) fn take_rekey_state(&mut self) -> Option<HandshakeState> {
        self.rekey_state.take()
    }

    /// Promote the pending session to current (the cutover).
    ///
    /// Moves the current session to `previous` (for drain), promotes
    /// `pending` to `current`, flips the K-bit, stamps the drain window.
    /// Shared by both cutover triggers: the initiator's liveness timer
    /// (`cutover_to_new_session`) and a successful `pending` trial-decrypt
    /// (`handle_peer_kbit_flip`).
    fn promote_pending(&mut self, now: SessionInstant) -> bool {
        let new_session = match self.pending_new_session.take() {
            Some(s) => s,
            None => return false,
        };

        // Demote current to previous for drain
        if let Some(EndToEndState::Established(old)) = self.state.take() {
            self.previous_noise_session = Some(old);
        }
        self.drain_started = Some(now);
        // Fresh drain: no `previous`-slot use observed yet. The drain
        // deadline starts from the cutover and is pushed out by any
        // subsequent `previous`-slot decrypt.
        self.previous_last_used = None;

        // Promote pending to current
        self.state = Some(EndToEndState::Established(new_session));
        self.current_k_bit = !self.current_k_bit;
        self.session_start = Some(now);
        self.rekey_state = None;
        self.rekey_initiator = false;
        self.rekey_completed = None;
        self.rekey_jitter_secs = draw_rekey_jitter();

        // Reset MMP counters to avoid metric discontinuity
        let now_ms = crate::time::mono_ms();
        if let Some(mmp) = &mut self.mmp {
            mmp.reset_for_rekey(now_ms);
        }
        true
    }

    /// Cut over to the pending new session on the initiator's liveness
    /// timer.
    ///
    /// This is the unconditional timer-driven cutover (option A). It is
    /// safe on any schedule: overlapping-epoch trial-decrypt covers the
    /// skew between the two endpoints' cutovers. It does NOT confirm the
    /// peer is on the new epoch — the responder may still be awaiting
    /// msg3 — so msg3 retransmission must continue past this cutover.
    pub(crate) fn cutover_to_new_session(&mut self, now: SessionInstant) -> bool {
        self.promote_pending(now)
    }

    /// Promote the pending session because a peer frame authenticated
    /// against it.
    ///
    /// A frame that decrypts against `pending` is itself the cutover
    /// signal — proof the peer derived the new session and moved to it.
    /// This unifies the trigger: the header K-bit is only a hint, the
    /// authenticated decrypt is the actual proof. Used by the
    /// trial-decrypt cascade on a successful `pending` decrypt.
    pub(crate) fn handle_peer_kbit_flip(&mut self, now: SessionInstant) -> bool {
        self.promote_pending(now)
    }

    /// Check if the drain window has expired.
    ///
    /// Peer-progress-aware: the deadline is `drain` after the LATER
    /// of the cutover (`drain_started`) and the last inbound frame
    /// that authenticated against the `previous` slot
    /// (`previous_last_used`). The old epoch is therefore retired
    /// only once the peer has been silent on it for a full drain
    /// window — never while the peer is still transmitting on it.
    ///
    /// This closes the rep-003 gap: a fixed wall-clock drain timer,
    /// started unilaterally at the initiator's Option-A cutover, would
    /// erase the `previous` slot 10 s later even if the peer (having
    /// lost msg3) was still sealing every frame in the old epoch — the
    /// trial-decrypt cascade then had no slot to decrypt them, a
    /// permanent silent decrypt failure. A peer that never catches up
    /// is instead handled by the FSP session liveness path (fresh
    /// handshake / teardown of a genuinely dead link).
    ///
    /// `max_drain` is an absolute ceiling measured from the cutover
    /// alone, so the sliding deadline delays erasure by a bounded amount
    /// rather than preventing it: the only party that can push the
    /// deadline out is the authenticated peer holding the old key, and
    /// without a ceiling it holds that key for as long as it keeps using
    /// it. What the ceiling costs is that a peer which has still not
    /// recovered by then is cut off deliberately, and its frames are
    /// undecryptable until its own rekey retry re-converges the epochs.
    /// It must therefore stay above the worst-case legitimate recovery;
    /// see `DRAIN_MAX_RETENTION_SECS`.
    pub(crate) fn drain_expired(
        &self,
        now: SessionInstant,
        drain: Duration,
        max_drain: Duration,
    ) -> bool {
        let Some(started) = self.drain_started else {
            return false;
        };
        if now.saturating_duration_since(started) >= max_drain {
            return true;
        }
        let deadline_anchor = self
            .previous_last_used
            .map_or(started, |used| used.max(started));
        now.saturating_duration_since(deadline_anchor) >= drain
    }

    /// Whether a drain is in progress.
    pub(crate) fn is_draining(&self) -> bool {
        self.drain_started.is_some()
    }

    /// Refresh the drain deadline because an inbound frame authenticated
    /// against the `previous` slot — the peer is still using the old
    /// epoch, so it must stay retained. No-op if no drain is in
    /// progress (a `previous` slot installed only for test purposes).
    pub(crate) fn refresh_previous_use(&mut self, now: SessionInstant) {
        if self.drain_started.is_some() {
            self.previous_last_used = Some(now);
        }
    }

    /// Complete the drain: drop previous session.
    pub(crate) fn complete_drain(&mut self) {
        self.previous_noise_session = None;
        self.drain_started = None;
        self.previous_last_used = None;
    }

    /// Whether a completed rekey session has waited longer than `stale`
    /// for the cut-over that would consume it.
    ///
    /// This is a staleness question about the *wait*, never a licence to
    /// drop the keys: the peer may be on this epoch and simply silent, so
    /// the pending slot is retained regardless. It answers only whether a
    /// fresh setup message from that peer still has to yield to the
    /// cut-over that has not arrived.
    ///
    /// False when no pending session is held, and false while the entry
    /// carries no completion stamp, so an unstamped pending is treated as
    /// freshly completed.
    pub(crate) fn pending_stale(&self, now: SessionInstant, stale: Duration) -> bool {
        self.pending_new_session.is_some()
            && self
                .rekey_completed
                .is_some_and(|done| now.saturating_duration_since(done) > stale)
    }

    /// Abandon an in-progress rekey handshake, keeping any completed
    /// session already waiting for cut-over.
    ///
    /// Used when an armed handshake times out: one the peer armed without
    /// its msg3, or one this node armed without a SessionAck. The handshake
    /// holds no key material either endpoint can be using, so dropping it
    /// costs nothing; a `pending` session alongside it is the epoch the
    /// peer may already have moved to and must survive.
    ///
    /// `rekey_initiator` is deliberately left alone: it describes whichever
    /// rekey artefact the entry still holds, and every reader gates on a
    /// live handshake or a pending session first.
    pub(crate) fn abandon_handshake(&mut self) {
        self.rekey_state = None;
    }

    /// Abandon an in-progress rekey.
    ///
    /// Drops the in-flight handshake state, the pending session, and any
    /// retained msg3 retransmission payload, returning the entry to a
    /// clean `Established` state. Safe under overlapping-epoch decrypt:
    /// an abandoned cycle never leaves a divergent unsafe state — the
    /// endpoints simply stay on `current` until a later cycle completes.
    pub(crate) fn abandon_rekey(&mut self) {
        self.rekey_state = None;
        self.pending_new_session = None;
        self.rekey_initiator = false;
        self.rekey_completed = None;
        self.clear_rekey_msg3_payload();
        self.peer_new_epoch_confirmed = false;
    }

    // === Test-only helpers ===

    /// Install a session directly in the `previous` (draining) slot.
    #[cfg(test)]
    pub(crate) fn set_previous_session_for_test(
        &mut self,
        session: NoiseSession,
        now: SessionInstant,
    ) {
        self.previous_noise_session = Some(session);
        self.drain_started = Some(now);
    }

    /// Read the highest received counter of the `previous` slot, if any.
    #[cfg(test)]
    pub(crate) fn previous_highest_counter(&self) -> Option<u64> {
        self.previous_noise_session
            .as_ref()
            .map(|s| s.highest_received_counter())
    }

    /// Read the highest received counter of the `pending` slot, if any.
    #[cfg(test)]
    pub(crate) fn pending_highest_counter(&self) -> Option<u64> {
        self.pending_new_session
            .as_ref()
            .map(|s| s.highest_received_counter())
    }

    /// Read the highest received counter of the `current` slot, if
    /// established.
    #[cfg(test)]
    pub(crate) fn current_highest_counter(&self) -> Option<u64> {
        match self.state.as_ref() {
            Some(EndToEndState::Established(s)) => Some(s.highest_received_counter()),
            _ => None,
        }
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod overlapping_epoch_tests;
