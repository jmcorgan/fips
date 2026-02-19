//! End-to-end session state.
//!
//! Tracks Noise IK sessions between this node and remote endpoints.
//! Sessions are established via SessionSetup/SessionAck handshake
//! messages carried inside SessionDatagram envelopes through the mesh.

use crate::config::SessionMmpConfig;
use crate::mmp::MmpSessionState;
use crate::noise::{HandshakeState, NoiseSession};
use crate::NodeAddr;
use secp256k1::PublicKey;

/// State machine for an end-to-end session.
pub(crate) enum EndToEndState {
    /// We initiated: sent SessionSetup with Noise IK msg1, awaiting SessionAck.
    Initiating(HandshakeState),
    /// We are responding: received msg1, sent SessionAck with msg2.
    Responding(HandshakeState),
    /// Handshake complete, NoiseSession available for encrypt/decrypt.
    Established(NoiseSession),
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

    /// Check if we are the responder (sent ack, waiting for data).
    pub(crate) fn is_responding(&self) -> bool {
        matches!(self, EndToEndState::Responding(_))
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
    /// Remote node's static public key (for Noise IK).
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
    /// Whether this node initiated the Noise IK handshake.
    /// Used for spin bit role assignment in session-layer MMP.
    is_initiator: bool,
    /// Session-layer MMP state. Initialized on Established transition.
    mmp: Option<MmpSessionState>,

    // === Handshake Resend ===
    /// Encoded session-layer payload for resend (SessionSetup or SessionAck).
    /// Cleared on Established transition.
    handshake_payload: Option<Vec<u8>>,
    /// Number of resends performed.
    resend_count: u32,
    /// When the next resend should fire (Unix ms). 0 = no resend scheduled.
    next_resend_at_ms: u64,
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
            handshake_payload: None,
            resend_count: 0,
            next_resend_at_ms: 0,
        }
    }

    /// Get the remote node's public key.
    pub(crate) fn remote_pubkey(&self) -> &PublicKey {
        &self.remote_pubkey
    }

    /// Get the current session state.
    pub(crate) fn state(&self) -> &EndToEndState {
        self.state.as_ref().expect("session state taken but not restored")
    }

    /// Get mutable access to the session state.
    pub(crate) fn state_mut(&mut self) -> &mut EndToEndState {
        self.state.as_mut().expect("session state taken but not restored")
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

    /// Whether this node initiated the Noise IK handshake.
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
        self.mmp = Some(MmpSessionState::new(config, self.is_initiator));
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
}
