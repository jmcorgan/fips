//! End-to-end session state.
//!
//! Tracks Noise XX sessions between this node and remote endpoints.
//! Sessions are established via a three-message XX handshake
//! (SessionSetup/SessionAck/SessionMsg3) carried inside SessionDatagram
//! envelopes through the mesh.

use crate::NodeAddr;
use crate::config::SessionMmpConfig;
use crate::node::REKEY_JITTER_SECS;
use crate::noise::{HandshakeState, NoiseSession};
use crate::proto::mmp::MmpSessionState;
use rand::RngExt;
use secp256k1::PublicKey;

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
    /// We initiated: sent SessionSetup with Noise XX msg1, awaiting SessionAck.
    Initiating(HandshakeState),
    /// XX responder: processed msg1, sent msg2, awaiting msg3.
    /// Transitions to Established when msg3 arrives.
    AwaitingMsg3(HandshakeState),
    /// Handshake complete, NoiseSession available for encrypt/decrypt.
    Established(NoiseSession),
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

    /// Check if we are an XX responder awaiting msg3.
    pub(crate) fn is_awaiting_msg3(&self) -> bool {
        matches!(self, EndToEndState::AwaitingMsg3(_))
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
    /// When the session was created (Unix milliseconds).
    #[cfg_attr(not(test), allow(dead_code))]
    created_at: u64,
    /// Last application data activity timestamp (Unix milliseconds).
    /// Only updated for DataPacket send/receive and session establishment.
    /// MMP reports do not update this field. Used for idle session timeout.
    last_activity: u64,
    /// When the session transitioned to Established (Unix milliseconds).
    /// Used to compute session-relative timestamps for the FSP inner header.
    /// Set to 0 until the session is established.
    session_start_ms: u64,
    /// Remaining data packets that should include COORDS_PRESENT.
    /// Initialized from config when session becomes Established;
    /// reset on CoordsRequired receipt.
    coords_warmup_remaining: u8,
    /// Whether this node initiated the Noise handshake.
    /// Surfaced through the `is_initiator()` accessor.
    is_initiator: bool,
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
    /// Encoded session-layer payload for resend (SessionSetup or SessionAck).
    /// Cleared on Established transition.
    handshake_payload: Option<Vec<u8>>,
    /// Number of resends performed.
    resend_count: u32,
    /// When the next resend should fire (Unix ms). 0 = no resend scheduled.
    next_resend_at_ms: u64,

    // === Rekey (Key Rotation) ===
    /// Current K-bit epoch value (alternates each rekey).
    current_k_bit: bool,
    /// Previous NoiseSession during drain window after cutover.
    previous_noise_session: Option<NoiseSession>,
    /// When drain window started (Unix ms). 0 = no drain.
    drain_started_ms: u64,
    /// Last time an inbound frame authenticated against the `previous`
    /// slot (Unix ms). 0 = the `previous` slot has not been used since
    /// the drain began.
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
    previous_last_used_ms: u64,
    /// In-progress rekey state (runs alongside Established session).
    rekey_state: Option<HandshakeState>,
    /// Pending completed session awaiting K-bit cutover.
    pending_new_session: Option<NoiseSession>,
    /// Whether we initiated the current rekey.
    rekey_initiator: bool,
    /// Dampening: last time peer sent us a rekey msg1 (Unix ms).
    last_peer_rekey_ms: u64,
    /// When the FSP rekey handshake completed (initiator sent msg3, Unix ms).
    /// Drives the initiator's liveness-bound cutover timer. Cleared on
    /// cutover. The timer is no longer safety-critical: overlapping-epoch
    /// trial-decrypt covers any cutover skew. It only bounds how long the
    /// initiator advertises the old K-bit.
    rekey_completed_ms: u64,
    /// Encoded SessionMsg3 payload retained for retransmission (initiator).
    /// Set when the rekey initiator sends msg3; cleared once the responder
    /// is confirmed on the new epoch (an authenticated peer frame against
    /// `pending` or new `current`) or the rekey cycle is abandoned.
    /// Retransmission lifetime is tied to responder reception of msg3,
    /// decoupled from the initiator's own cutover.
    rekey_msg3_payload: Option<Vec<u8>>,
    /// When the next rekey msg3 retransmission should fire (Unix ms).
    /// 0 = no retransmission scheduled.
    rekey_msg3_next_resend_ms: u64,
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
        now_ms: u64,
        is_initiator: bool,
    ) -> Self {
        Self {
            remote_addr,
            remote_pubkey,
            state: Some(state),
            created_at: now_ms,
            last_activity: now_ms,
            session_start_ms: 0,
            coords_warmup_remaining: 0,
            is_initiator,
            mmp: None,
            packets_sent: 0,
            packets_recv: 0,
            bytes_sent: 0,
            bytes_recv: 0,
            handshake_payload: None,
            resend_count: 0,
            next_resend_at_ms: 0,
            current_k_bit: false,
            previous_noise_session: None,
            drain_started_ms: 0,
            previous_last_used_ms: 0,
            rekey_state: None,
            pending_new_session: None,
            rekey_initiator: false,
            last_peer_rekey_ms: 0,
            rekey_completed_ms: 0,
            rekey_msg3_payload: None,
            rekey_msg3_next_resend_ms: 0,
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

    /// Replace the session state.
    pub(crate) fn set_state(&mut self, state: EndToEndState) {
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
    pub(crate) fn touch(&mut self, now_ms: u64) {
        self.last_activity = now_ms;
    }

    /// Check if the session is established.
    pub(crate) fn is_established(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_established())
    }

    /// Check if we are the initiator (waiting for ack).
    pub(crate) fn is_initiating(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_initiating())
    }

    /// Check if we are an XX responder awaiting msg3.
    pub(crate) fn is_awaiting_msg3(&self) -> bool {
        self.state.as_ref().is_some_and(|s| s.is_awaiting_msg3())
    }

    /// Get creation time.
    #[cfg(test)]
    pub(crate) fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Get last activity time.
    pub(crate) fn last_activity(&self) -> u64 {
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

    /// Mark the session as started (transition to Established).
    ///
    /// Records the current time as the session start for computing
    /// session-relative timestamps in the FSP inner header.
    pub(crate) fn mark_established(&mut self, now_ms: u64) {
        self.session_start_ms = now_ms;
    }

    /// Compute a session-relative timestamp for the FSP inner header.
    ///
    /// Returns `(now_ms - session_start_ms)` truncated to u32.
    /// Wraps naturally at ~49.7 days, which is fine for relative timing.
    pub(crate) fn session_timestamp(&self, now_ms: u64) -> u32 {
        now_ms.wrapping_sub(self.session_start_ms) as u32
    }

    /// Whether this node initiated the Noise handshake.
    #[cfg_attr(not(test), allow(dead_code))]
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
    /// For responders, this is the SessionAck payload bytes.
    /// The payload is re-wrapped in a fresh SessionDatagram on each resend
    /// so routing can adapt to topology changes.
    pub(crate) fn set_handshake_payload(&mut self, payload: Vec<u8>, next_resend_at_ms: u64) {
        self.handshake_payload = Some(payload);
        self.resend_count = 0;
        self.next_resend_at_ms = next_resend_at_ms;
    }

    /// Get the stored handshake payload for resend.
    pub(crate) fn handshake_payload(&self) -> Option<&[u8]> {
        self.handshake_payload.as_deref()
    }

    /// Clear the stored handshake payload (called on Established transition).
    pub(crate) fn clear_handshake_payload(&mut self) {
        self.handshake_payload = None;
        self.next_resend_at_ms = 0;
    }

    /// Number of resends performed so far.
    pub(crate) fn resend_count(&self) -> u32 {
        self.resend_count
    }

    /// When the next resend should fire (Unix ms). 0 = no resend scheduled.
    pub(crate) fn next_resend_at_ms(&self) -> u64 {
        self.next_resend_at_ms
    }

    /// Record a resend and schedule the next one.
    pub(crate) fn record_resend(&mut self, next_resend_at_ms: u64) {
        self.resend_count += 1;
        self.next_resend_at_ms = next_resend_at_ms;
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
    pub(crate) fn is_rekey_dampened(&self, now_ms: u64, dampening_ms: u64) -> bool {
        if self.last_peer_rekey_ms == 0 {
            return false;
        }
        now_ms.saturating_sub(self.last_peer_rekey_ms) < dampening_ms
    }

    /// Record that the peer initiated a rekey (for dampening).
    pub(crate) fn record_peer_rekey(&mut self, now_ms: u64) {
        self.last_peer_rekey_ms = now_ms;
    }

    /// When the session transitioned to Established (for rekey timer).
    pub(crate) fn session_start_ms(&self) -> u64 {
        self.session_start_ms
    }

    /// Get the current send counter from the established NoiseSession.
    pub(crate) fn send_counter(&self) -> u64 {
        match self.state.as_ref() {
            Some(EndToEndState::Established(s)) => s.current_send_counter(),
            _ => 0,
        }
    }

    /// When the FSP rekey handshake completed (initiator sent msg3).
    pub(crate) fn rekey_completed_ms(&self) -> u64 {
        self.rekey_completed_ms
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

    /// Record when the FSP rekey handshake completed (initiator side).
    pub(crate) fn set_rekey_completed_ms(&mut self, ms: u64) {
        self.rekey_completed_ms = ms;
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
    pub(crate) fn set_rekey_msg3_payload(&mut self, payload: Vec<u8>, next_resend_at_ms: u64) {
        self.rekey_msg3_payload = Some(payload);
        self.rekey_msg3_next_resend_ms = next_resend_at_ms;
        self.rekey_msg3_resend_count = 0;
        self.peer_new_epoch_confirmed = false;
    }

    /// Get the retained rekey msg3 payload for retransmission.
    pub(crate) fn rekey_msg3_payload(&self) -> Option<&[u8]> {
        self.rekey_msg3_payload.as_deref()
    }

    /// When the next rekey msg3 retransmission should fire (Unix ms).
    pub(crate) fn rekey_msg3_next_resend_ms(&self) -> u64 {
        self.rekey_msg3_next_resend_ms
    }

    /// Number of rekey msg3 retransmissions performed so far.
    pub(crate) fn rekey_msg3_resend_count(&self) -> u32 {
        self.rekey_msg3_resend_count
    }

    /// Record a rekey msg3 retransmission and schedule the next one.
    pub(crate) fn record_rekey_msg3_resend(&mut self, next_resend_at_ms: u64) {
        self.rekey_msg3_resend_count += 1;
        self.rekey_msg3_next_resend_ms = next_resend_at_ms;
    }

    /// Clear the retained rekey msg3 payload (responder confirmed on the
    /// new epoch, or the cycle abandoned).
    pub(crate) fn clear_rekey_msg3_payload(&mut self) {
        self.rekey_msg3_payload = None;
        self.rekey_msg3_next_resend_ms = 0;
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
        now_ms: u64,
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
                    self.refresh_previous_use(now_ms);
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

    /// Set the rekey handshake state (in-progress XX handshake).
    pub(crate) fn set_rekey_state(&mut self, state: HandshakeState, is_initiator: bool) {
        self.rekey_state = Some(state);
        self.rekey_initiator = is_initiator;
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
    fn promote_pending(&mut self, now_ms: u64) -> bool {
        let new_session = match self.pending_new_session.take() {
            Some(s) => s,
            None => return false,
        };

        // Demote current to previous for drain
        if let Some(EndToEndState::Established(old)) = self.state.take() {
            self.previous_noise_session = Some(old);
        }
        self.drain_started_ms = now_ms;
        // Fresh drain: no `previous`-slot use observed yet. The drain
        // deadline starts from the cutover and is pushed out by any
        // subsequent `previous`-slot decrypt.
        self.previous_last_used_ms = 0;

        // Promote pending to current
        self.state = Some(EndToEndState::Established(new_session));
        self.current_k_bit = !self.current_k_bit;
        self.session_start_ms = now_ms;
        self.rekey_state = None;
        self.rekey_initiator = false;
        self.rekey_completed_ms = 0;
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
    pub(crate) fn cutover_to_new_session(&mut self, now_ms: u64) -> bool {
        self.promote_pending(now_ms)
    }

    /// Promote the pending session because a peer frame authenticated
    /// against it.
    ///
    /// A frame that decrypts against `pending` is itself the cutover
    /// signal — proof the peer derived the new session and moved to it.
    /// This unifies the trigger: the header K-bit is only a hint, the
    /// authenticated decrypt is the actual proof. Used by the
    /// trial-decrypt cascade on a successful `pending` decrypt.
    pub(crate) fn handle_peer_kbit_flip(&mut self, now_ms: u64) -> bool {
        self.promote_pending(now_ms)
    }

    /// Check if the drain window has expired.
    ///
    /// Peer-progress-aware: the deadline is `drain_ms` after the LATER
    /// of the cutover (`drain_started_ms`) and the last inbound frame
    /// that authenticated against the `previous` slot
    /// (`previous_last_used_ms`). The old epoch is therefore retired
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
    pub(crate) fn drain_expired(&self, now_ms: u64, drain_ms: u64) -> bool {
        if self.drain_started_ms == 0 {
            return false;
        }
        let deadline_anchor = self.drain_started_ms.max(self.previous_last_used_ms);
        now_ms.saturating_sub(deadline_anchor) >= drain_ms
    }

    /// Whether a drain is in progress.
    pub(crate) fn is_draining(&self) -> bool {
        self.drain_started_ms > 0
    }

    /// Refresh the drain deadline because an inbound frame authenticated
    /// against the `previous` slot — the peer is still using the old
    /// epoch, so it must stay retained. No-op if no drain is in
    /// progress (a `previous` slot installed only for test purposes).
    pub(crate) fn refresh_previous_use(&mut self, now_ms: u64) {
        if self.drain_started_ms > 0 {
            self.previous_last_used_ms = now_ms;
        }
    }

    /// Complete the drain: drop previous session.
    pub(crate) fn complete_drain(&mut self) {
        self.previous_noise_session = None;
        self.drain_started_ms = 0;
        self.previous_last_used_ms = 0;
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
        self.rekey_completed_ms = 0;
        self.clear_rekey_msg3_payload();
        self.peer_new_epoch_confirmed = false;
    }

    // === Test-only helpers ===

    /// Install a session directly in the `previous` (draining) slot.
    #[cfg(test)]
    pub(crate) fn set_previous_session_for_test(&mut self, session: NoiseSession, now_ms: u64) {
        self.previous_noise_session = Some(session);
        self.drain_started_ms = now_ms;
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
mod overlapping_epoch_tests {
    use super::*;
    use crate::noise::HandshakeState;
    use crate::proto::fsp::wire::{FSP_FLAG_K, build_fsp_header};
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    /// Deterministic keypair from a single seed byte.
    fn keypair(seed: u8) -> Keypair {
        let secp = Secp256k1::new();
        let mut bytes = [1u8; 32];
        bytes[0] = seed;
        let sk = SecretKey::from_slice(&bytes).expect("valid secret key");
        Keypair::from_secret_key(&secp, &sk)
    }

    /// Run a full XX handshake and return `(initiator_session,
    /// responder_session)` — a paired sender/receiver.
    fn xk_pair(init_seed: u8, resp_seed: u8) -> (NoiseSession, NoiseSession) {
        let init_kp = keypair(init_seed);
        let resp_kp = keypair(resp_seed);
        let mut initiator = HandshakeState::new_initiator(init_kp);
        initiator.set_local_epoch([0xA1, 0xB2, 0xC3, 0xD4, 0x11, 0x22, 0x33, 0x44]);
        let mut responder = HandshakeState::new_responder(resp_kp);
        responder.set_local_epoch([0xD4, 0xC3, 0xB2, 0xA1, 0x44, 0x33, 0x22, 0x11]);

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();
        let msg3 = initiator.write_message_3().unwrap();
        responder.read_message_3(&msg3).unwrap();

        (
            initiator.into_session().unwrap(),
            responder.into_session().unwrap(),
        )
    }

    /// Seal an FSP frame: returns `(ciphertext, counter, header_bytes,
    /// k_bit)` exactly as the send path produces them.
    fn seal(sender: &mut NoiseSession, plaintext: &[u8], k_bit: bool) -> (Vec<u8>, u64, [u8; 12]) {
        let counter = sender.current_send_counter();
        let flags = if k_bit { FSP_FLAG_K } else { 0 };
        let header = build_fsp_header(counter, flags, plaintext.len() as u16);
        let ciphertext = sender.encrypt_with_aad(plaintext, &header).unwrap();
        (ciphertext, counter, header)
    }

    /// Build a `SessionEntry` whose `current` slot is `session`.
    fn entry_with_current(session: NoiseSession) -> SessionEntry {
        let addr = NodeAddr::from_bytes([7u8; 16]);
        let pubkey = keypair(99).public_key();
        let mut entry = SessionEntry::new(
            addr,
            pubkey,
            EndToEndState::Established(session),
            1_000,
            true,
        );
        entry.mark_established(1_000);
        entry
    }

    // 1. A frame sealed in `current` decrypts against `current`; the
    //    `pending` and `previous` windows are left untouched.
    #[test]
    fn trial_decrypt_picks_current() {
        let (mut cur_send, cur_recv) = xk_pair(1, 2);
        let (_p_send, p_recv) = xk_pair(3, 4);
        let (_o_send, o_recv) = xk_pair(5, 6);

        let mut entry = entry_with_current(cur_recv);
        entry.set_pending_session(p_recv);
        entry.set_previous_session_for_test(o_recv, 1_000);

        let (ct, counter, hdr) = seal(&mut cur_send, b"steady-state", false);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, false, 2_000)
            .expect("current frame must decrypt");

        assert_eq!(pt, b"steady-state");
        assert_eq!(slot, EpochSlot::Current);
        assert_eq!(entry.pending_highest_counter(), Some(0));
        assert_eq!(entry.previous_highest_counter(), Some(0));
    }

    // 2. A frame sealed in `pending` decrypts via the cascade and the
    //    entry promotes pending -> current, current -> previous, K-bit
    //    flips.
    #[test]
    fn trial_decrypt_picks_pending_and_promotes() {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);

        // Peer sealed in the new epoch with the flipped K-bit.
        let (ct, counter, hdr) = seal(&mut p_send, b"new-epoch", !k_before);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, !k_before, 2_000)
            .expect("pending frame must decrypt");
        assert_eq!(pt, b"new-epoch");
        assert_eq!(slot, EpochSlot::Pending);

        // Receive path promotes on a pending hit.
        entry.handle_peer_kbit_flip(2_000);
        assert!(entry.pending_new_session().is_none());
        assert!(entry.previous_highest_counter().is_some());
        assert_ne!(entry.current_k_bit(), k_before);
    }

    // 3. After cutover, an old-epoch frame decrypts against `previous`
    //    with no state change.
    #[test]
    fn trial_decrypt_picks_previous_during_drain() {
        let (mut old_send, old_recv) = xk_pair(1, 2);
        let (_new_send, new_recv) = xk_pair(3, 4);

        // Start with the old session, install the new as pending, cut over.
        let mut entry = entry_with_current(new_recv);
        entry.set_previous_session_for_test(old_recv, 1_500);
        let k_after = entry.current_k_bit();

        // Old-epoch straggler still in flight after our cutover.
        let (ct, counter, hdr) = seal(&mut old_send, b"old-straggler", !k_after);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, !k_after, 3_000)
            .expect("previous frame must decrypt");

        assert_eq!(pt, b"old-straggler");
        assert_eq!(slot, EpochSlot::Previous);
        // No promotion, no K-bit change.
        assert_eq!(entry.current_k_bit(), k_after);
        assert!(entry.is_draining());
    }

    // 4. After a pending-driven promotion, an old-epoch straggler still
    //    decrypts (against the now-`previous` slot) — the reordering
    //    case that broke attempt 1.
    #[test]
    fn trial_decrypt_reordered_old_after_cutover() {
        let (mut cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);

        // New-epoch frame promotes the entry.
        let (ct_new, c_new, hdr_new) = seal(&mut p_send, b"after-cutover", !k_before);
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct_new, c_new, &hdr_new, !k_before, 2_000)
            .unwrap();
        assert_eq!(slot, EpochSlot::Pending);
        entry.handle_peer_kbit_flip(2_000);

        // Now an OLD-epoch straggler arrives reordered after cutover.
        let (ct_old, c_old, hdr_old) = seal(&mut cur_send, b"reordered-old", k_before);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct_old, c_old, &hdr_old, k_before, 2_500)
            .expect("reordered old-epoch frame must still decrypt");
        assert_eq!(pt, b"reordered-old");
        assert_eq!(slot, EpochSlot::Previous);
    }

    // 5. A genuine replay of a `current`-epoch counter is rejected (all
    //    slots fail) and does not corrupt the other windows; a `current`
    //    replay while `pending` holds the real key still authenticates
    //    against `pending`.
    #[test]
    fn trial_decrypt_replay_is_per_slot() {
        let (mut cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);

        // First delivery on `current`.
        let (ct, counter, hdr) = seal(&mut cur_send, b"first", k_before);
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, k_before, 2_000)
            .unwrap();
        assert_eq!(slot, EpochSlot::Current);

        // Replaying the exact same `current` frame: all slots fail.
        assert!(
            entry
                .fsp_trial_decrypt(&ct, counter, &hdr, k_before, 2_100)
                .is_none(),
            "a genuine replay must be rejected by every slot"
        );
        // The pending window must not have been corrupted by the failed
        // trials.
        assert_eq!(entry.pending_highest_counter(), Some(0));

        // A pending-epoch frame sharing counter 0 with `current` (whose
        // counter 0 is already consumed) still authenticates against
        // `pending`.
        let (ct_p, c_p, hdr_p) = seal(&mut p_send, b"pending-c0", !k_before);
        assert_eq!(c_p, 0);
        let (pt, slot) = entry
            .fsp_trial_decrypt(&ct_p, c_p, &hdr_p, !k_before, 2_200)
            .expect("pending frame must decrypt despite current replay overlap");
        assert_eq!(pt, b"pending-c0");
        assert_eq!(slot, EpochSlot::Pending);
    }

    // 6. A failed trial against a non-winning slot leaves that slot's
    //    ReplayWindow::highest() unchanged (the section-4 invariant).
    #[test]
    fn trial_decrypt_failed_slot_leaves_replay_window_intact() {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);
        let (_o_send, o_recv) = xk_pair(5, 6);

        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);
        entry.set_previous_session_for_test(o_recv, 1_000);

        // Advance the pending sender so its frame carries a non-zero
        // counter — the cascade will still try (and fail) `current` and
        // `previous` first.
        for _ in 0..4 {
            let _ = seal(&mut p_send, b"warmup", !k_before);
        }
        let (ct, counter, hdr) = seal(&mut p_send, b"pending-hit", !k_before);
        assert_eq!(counter, 4);

        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, false, 2_000) // hint says "current first"
            .expect("pending frame must decrypt");
        assert_eq!(slot, EpochSlot::Pending);

        // current and previous were tried and failed: their windows must
        // be untouched (highest still 0).
        assert_eq!(entry.current_highest_counter(), Some(0));
        assert_eq!(entry.previous_highest_counter(), Some(0));
        // Only the winning slot advanced.
        assert_eq!(entry.pending_highest_counter(), Some(4));
    }

    // 7. The retained msg3 payload is cleared once a peer frame
    //    authenticates against `pending`/new-`current`, not at the
    //    initiator's own cutover.
    #[test]
    fn msg3_retransmit_stops_on_peer_new_epoch_confirmed() {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (mut p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        entry.set_pending_session(p_recv);
        entry.set_rekey_completed_ms(1_000);
        entry.set_rekey_msg3_payload(vec![0xAB; 73], 1_500);

        // The initiator's own liveness-timer cutover must NOT clear the
        // retained msg3 payload — the responder may not have it yet.
        assert!(entry.cutover_to_new_session(2_000));
        assert!(
            entry.rekey_msg3_payload().is_some(),
            "cutover alone must not stop msg3 retransmission"
        );
        assert!(!entry.peer_new_epoch_confirmed());

        // A peer frame authenticated against the post-cutover `current`
        // (new epoch) confirms the responder and clears the payload.
        let (ct, counter, hdr) = seal(&mut p_send, b"peer-on-new-epoch", entry.current_k_bit());
        let k_now = entry.current_k_bit();
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, k_now, 2_500)
            .unwrap();
        assert_eq!(slot, EpochSlot::Current);
        // Receive-path logic: current hit + retained payload + no pending
        // => responder confirmed.
        assert!(entry.rekey_msg3_payload().is_some() && entry.pending_new_session().is_none());
        entry.confirm_peer_new_epoch();
        assert!(entry.peer_new_epoch_confirmed());
        assert!(entry.rekey_msg3_payload().is_none());
    }

    // 8. After exhausting the retransmission budget, abandon_rekey runs
    //    and the entry is a clean Established with no pending.
    #[test]
    fn msg3_retransmit_budget_exhaustion_abandons_cleanly() {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (_p_send, p_recv) = xk_pair(3, 4);

        let mut entry = entry_with_current(cur_recv);
        entry.set_pending_session(p_recv);
        entry.set_rekey_completed_ms(1_000);
        entry.set_rekey_msg3_payload(vec![0xCD; 73], 1_500);

        // Simulate the resend driver exhausting its budget.
        let max_resends = 8;
        for i in 0..max_resends {
            entry.record_rekey_msg3_resend(2_000 + i as u64 * 100);
        }
        assert_eq!(entry.rekey_msg3_resend_count(), max_resends);

        // Budget exhausted -> abandon.
        entry.abandon_rekey();
        assert!(entry.rekey_msg3_payload().is_none());
        assert!(entry.pending_new_session().is_none());
        assert!(!entry.has_rekey_in_progress());
        assert!(entry.is_established());
        assert!(!entry.peer_new_epoch_confirmed());
    }

    // 9. The initiator cuts over on its timer while the responder has
    //    not; both directions still decrypt (overlapping epochs).
    //
    // Naming: in each `xk_pair` the `.0` session is node A's view and
    // `.1` is node B's view; they seal frames the other one decrypts. A
    // is the rekey initiator, B the responder.
    #[test]
    fn initiator_cutover_safe_before_responder() {
        // Pre-rekey ("old") epoch and post-rekey ("new") epoch pairs.
        let (old_a, old_b) = xk_pair(1, 2);
        let (new_a, mut new_b) = xk_pair(3, 4);

        // Node A (initiator): current = old_a, pending = new_a, retains a
        // msg3 payload, then cuts over on its own liveness timer before
        // the responder has received msg3.
        let mut a = entry_with_current(old_a);
        a.set_rekey_completed_ms(1_000);
        a.set_rekey_msg3_payload(vec![0xEE; 73], 1_500);
        a.set_pending_session(new_a);
        assert!(a.cutover_to_new_session(2_000));
        // A now: current = new_a, previous = old_a, K-bit flipped, msg3
        // payload still retained (responder not yet confirmed).
        assert!(a.rekey_msg3_payload().is_some());

        // Node B (responder): still entirely on the old epoch — no
        // pending, msg3 not yet received. B's `current` slot is `old_b`.
        let mut b = entry_with_current(old_b);

        // A -> B sealed in the NEW epoch (B has no pending slot yet).
        // This is the one residual liveness-bounded drop, closed by msg3
        // retransmission. Confirm it is a clean drop, not a panic.
        let (ct_new, c_new, hdr_new) = seal(&mut new_b, b"new-from-a", true);
        assert!(
            b.fsp_trial_decrypt(&ct_new, c_new, &hdr_new, true, 2_100)
                .is_none(),
            "responder without msg3 drops the new-epoch frame cleanly"
        );

        // B -> A still sealed in the OLD epoch (B seals from its own
        // `current` slot). A kept the old session as `previous`, so it
        // decrypts fine despite the cutover skew.
        let (ct_old, c_old, hdr_old) = {
            let b_old = b.current_noise_session_mut().unwrap();
            seal(b_old, b"old-from-b", false)
        };
        let (pt, slot) = a
            .fsp_trial_decrypt(&ct_old, c_old, &hdr_old, false, 2_200)
            .expect("initiator must still decrypt the responder's old-epoch frame");
        assert_eq!(pt, b"old-from-b");
        assert_eq!(slot, EpochSlot::Previous);

        // Once B receives msg3 it derives the new session as pending; A's
        // new-epoch frames then decrypt and drive B's promotion.
        let (new_a2, mut new_b2) = xk_pair(3, 4);
        b.set_pending_session(new_a2);
        let (ct_new2, c_new2, hdr_new2) = seal(&mut new_b2, b"new-from-a-2", true);
        let (pt, slot) = b
            .fsp_trial_decrypt(&ct_new2, c_new2, &hdr_new2, true, 2_300)
            .expect("responder must decrypt new-epoch frame once pending is installed");
        assert_eq!(pt, b"new-from-a-2");
        assert_eq!(slot, EpochSlot::Pending);
    }

    // 10. Drain-window expiry is peer-progress-aware (the rep-003
    //     scenario). After the initiator cuts over, a responder that
    //     never received msg3 keeps transmitting on the OLD epoch. The
    //     `previous` slot must NOT be retired while those old-epoch
    //     frames keep decrypting — even well past the 10 s fixed
    //     window — and must be retired once the peer finally goes
    //     silent on the old epoch.
    #[test]
    fn drain_expiry_is_peer_progress_aware() {
        const DRAIN_MS: u64 = 10_000;
        let cutover_ms = 1_000;

        // Build the post-cutover state via the production cutover path:
        // start with the old session as `current`, the new session as
        // `pending`, then cut over so `current` = new epoch, `previous`
        // = old epoch, and the drain clock is stamped at the cutover.
        let (mut old_send, old_recv) = xk_pair(1, 2);
        let (_new_send, new_recv) = xk_pair(3, 4);
        let mut entry = entry_with_current(old_recv);
        entry.set_pending_session(new_recv);
        assert!(entry.cutover_to_new_session(cutover_ms));
        assert!(entry.is_draining());

        // The peer (responder) is still on the OLD epoch — it never
        // received msg3. Each old-epoch frame must decrypt against
        // `previous` and push the drain deadline out. Deliver frames at
        // t = 5s, 15s, 25s — the latter two are well past the fixed
        // 10 s window measured from the cutover at t=1s.
        let k_old = !entry.current_k_bit();
        for &t in &[5_000u64, 15_000, 25_000] {
            let (ct, counter, hdr) = seal(&mut old_send, b"still-old-epoch", k_old);
            let (_pt, slot) = entry
                .fsp_trial_decrypt(&ct, counter, &hdr, k_old, t)
                .expect("old-epoch frame must still decrypt while peer uses it");
            assert_eq!(slot, EpochSlot::Previous);
            // Even though `now - drain_started_ms` exceeds DRAIN_MS, the
            // window is NOT expired: the peer just used `previous`.
            assert!(
                !entry.drain_expired(t, DRAIN_MS),
                "previous slot must not be retired while peer keeps using it (t={t})"
            );
            assert!(
                entry.previous_highest_counter().is_some(),
                "previous slot must remain live (t={t})"
            );
        }

        // The peer cuts over (or dies): no more old-epoch frames. The
        // last `previous`-slot use was at t=25_000; the window now
        // elapses DRAIN_MS after that, NOT DRAIN_MS after the cutover.
        assert!(
            !entry.drain_expired(34_999, DRAIN_MS),
            "window must not expire before DRAIN_MS past the last previous use"
        );
        assert!(
            entry.drain_expired(35_000, DRAIN_MS),
            "window must expire DRAIN_MS after the last previous-slot decrypt"
        );

        // Once expired, complete_drain retires the previous slot.
        entry.complete_drain();
        assert!(entry.previous_highest_counter().is_none());
        assert!(!entry.is_draining());
    }

    // 11. Absent any peer traffic on the old epoch, drain expiry still
    //     fires on the plain wall-clock window measured from the
    //     cutover — the peer-progress refinement must not delay
    //     retirement when the peer cut over cleanly (no `previous`-slot
    //     use at all).
    #[test]
    fn drain_expiry_unaffected_when_peer_off_old_epoch() {
        const DRAIN_MS: u64 = 10_000;
        let cutover_ms = 1_000;

        let (_old_send, old_recv) = xk_pair(1, 2);
        let (_new_send, new_recv) = xk_pair(3, 4);
        let mut entry = entry_with_current(old_recv);
        entry.set_pending_session(new_recv);
        assert!(entry.cutover_to_new_session(cutover_ms));

        // No old-epoch frames ever arrive: `previous_last_used_ms` stays
        // 0, the deadline anchor is the cutover time.
        assert!(
            !entry.drain_expired(cutover_ms + DRAIN_MS - 1, DRAIN_MS),
            "window must not expire early"
        );
        assert!(
            entry.drain_expired(cutover_ms + DRAIN_MS, DRAIN_MS),
            "window must expire on the plain wall-clock timer when peer is off the old epoch"
        );
    }

    // ========================================================================
    // Rekey-policy characterization (pins `check_session_rekey`'s decision
    // boundaries before the `Fsp::poll_rekey` hoist — these thresholds have no
    // other test module; see plan §10).
    // ========================================================================

    /// The initiator liveness-cutover delay used by `check_session_rekey`
    /// (`FSP_CUTOVER_DELAY_MS`). Mirrored here as the characterization anchor.
    const CUTOVER_DELAY_MS: u64 = 2000;

    /// Build an established entry that has completed a rekey as initiator and
    /// holds a pending session awaiting the K-bit cutover.
    fn entry_pending_cutover(rekey_completed_ms: u64) -> SessionEntry {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let (_new_send, new_recv) = xk_pair(3, 4);
        let mut entry = entry_with_current(cur_recv);
        // Mark ourselves the rekey initiator, then land the completed session
        // as pending (clears rekey_state, so has_rekey_in_progress() == false).
        entry.set_rekey_state(HandshakeState::new_responder(keypair(7)), true);
        entry.set_pending_session(new_recv);
        entry.set_rekey_completed_ms(rekey_completed_ms);
        entry
    }

    // The initiator-side cutover predicate: pending session present, no rekey
    // in progress, we are the initiator, and the liveness timer has elapsed.
    #[test]
    fn rekey_cutover_predicate_boundary() {
        let completed = 1_000u64;
        let entry = entry_pending_cutover(completed);

        assert!(entry.pending_new_session().is_some());
        assert!(!entry.has_rekey_in_progress());
        assert!(entry.is_rekey_initiator());

        // Not yet eligible one ms before the delay elapses.
        let just_before = completed + CUTOVER_DELAY_MS - 1;
        assert!(
            just_before.saturating_sub(entry.rekey_completed_ms()) < CUTOVER_DELAY_MS,
            "cutover must not fire before the liveness delay"
        );
        // Eligible exactly at the delay.
        let at = completed + CUTOVER_DELAY_MS;
        assert!(
            at.saturating_sub(entry.rekey_completed_ms()) >= CUTOVER_DELAY_MS,
            "cutover fires once the liveness delay has elapsed"
        );
    }

    // Rekey-trigger threshold: elapsed time (with symmetric jitter applied)
    // OR the send counter crossing its configured bound.
    #[test]
    fn rekey_trigger_threshold_arithmetic() {
        let after_secs = 100u64;
        let after_messages = 1_000u64;

        // Jitter is always within [-REKEY_JITTER_SECS, +REKEY_JITTER_SECS].
        let (_s, recv) = xk_pair(1, 2);
        let entry = entry_with_current(recv);
        let jitter = entry.rekey_jitter_secs();
        assert!(
            jitter.abs() <= REKEY_JITTER_SECS,
            "jitter within configured bound"
        );

        // Effective time threshold applies the symmetric jitter.
        let effective_after = after_secs.saturating_add_signed(jitter);

        // Reproduce the policy's OR predicate directly.
        let triggers =
            |elapsed: u64, counter: u64| elapsed >= effective_after || counter >= after_messages;

        // Time arm: fires at/after the effective threshold, not below it.
        assert!(!triggers(effective_after - 1, 0), "below time threshold");
        assert!(triggers(effective_after, 0), "at time threshold");
        // Counter arm: fires independently of elapsed time.
        assert!(!triggers(0, after_messages - 1), "below counter threshold");
        assert!(triggers(0, after_messages), "at counter threshold");
    }

    // Dampening boundary: within `dampening_ms` of the peer's rekey msg1, local
    // initiation is suppressed; at/after the window it is not.
    #[test]
    fn rekey_dampening_boundary() {
        let (_s, recv) = xk_pair(1, 2);
        let mut entry = entry_with_current(recv);
        const DAMP_MS: u64 = 30_000;

        // No peer rekey recorded → never dampened.
        assert!(!entry.is_rekey_dampened(50_000, DAMP_MS));

        entry.record_peer_rekey(10_000);
        assert!(
            entry.is_rekey_dampened(10_000 + DAMP_MS - 1, DAMP_MS),
            "dampened within the window"
        );
        assert!(
            !entry.is_rekey_dampened(10_000 + DAMP_MS, DAMP_MS),
            "not dampened once the window has elapsed"
        );
    }

    // Epoch-reaction: a frame authenticating against `pending` while a msg3
    // retransmission is retained confirms the peer on the new epoch (clears the
    // msg3 payload) and then promotes.
    #[test]
    fn epoch_reaction_pending_confirms_then_promotes() {
        let (mut p_send, p_recv) = xk_pair(3, 4);
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let mut entry = entry_with_current(cur_recv);
        let k_before = entry.current_k_bit();
        entry.set_pending_session(p_recv);
        entry.set_rekey_msg3_payload(vec![0xAB; 8], 5_000);
        assert!(entry.rekey_msg3_payload().is_some());

        let (ct, counter, hdr) = seal(&mut p_send, b"new-epoch", !k_before);
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, !k_before, 2_000)
            .expect("pending frame decrypts");
        assert_eq!(slot, EpochSlot::Pending);

        // Reaction order: confirm (while pending still held) then promote.
        entry.confirm_peer_new_epoch();
        assert!(entry.rekey_msg3_payload().is_none());
        entry.handle_peer_kbit_flip(2_000);
        assert!(entry.pending_new_session().is_none());
        assert_ne!(entry.current_k_bit(), k_before);
    }

    // Epoch-reaction: as the initiator that already cut over on its own timer
    // (msg3 retained, no pending), a frame authenticating against `current`
    // confirms the responder reached the new epoch.
    #[test]
    fn epoch_reaction_current_confirms_responder() {
        let (mut cur_send, cur_recv) = xk_pair(1, 2);
        let mut entry = entry_with_current(cur_recv);
        entry.set_rekey_msg3_payload(vec![0xCD; 8], 5_000);
        assert!(entry.pending_new_session().is_none());
        assert!(entry.rekey_msg3_payload().is_some());

        let (ct, counter, hdr) = seal(&mut cur_send, b"steady", false);
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, false, 2_000)
            .expect("current frame decrypts");
        assert_eq!(slot, EpochSlot::Current);

        // The Current-with-retained-msg3-and-no-pending arm confirms.
        entry.confirm_peer_new_epoch();
        assert!(entry.rekey_msg3_payload().is_none());
    }
}
