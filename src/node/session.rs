//! End-to-end session state.
//!
//! Tracks Noise IK sessions between this node and remote endpoints.
//! Sessions are established via SessionSetup/SessionAck handshake
//! messages carried inside SessionDatagram envelopes through the mesh.

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
    #[allow(dead_code)]
    remote_pubkey: PublicKey,
    /// Current session state. `None` only during state transitions.
    state: Option<EndToEndState>,
    /// When the session was created (Unix milliseconds).
    #[cfg_attr(not(test), allow(dead_code))]
    created_at: u64,
    /// Last activity timestamp (Unix milliseconds).
    last_activity: u64,
}

impl SessionEntry {
    /// Create a new session entry.
    pub(crate) fn new(
        remote_addr: NodeAddr,
        remote_pubkey: PublicKey,
        state: EndToEndState,
        now_ms: u64,
    ) -> Self {
        Self {
            remote_addr,
            remote_pubkey,
            state: Some(state),
            created_at: now_ms,
            last_activity: now_ms,
        }
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

    /// Update the last activity timestamp.
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
    #[cfg(test)]
    pub(crate) fn last_activity(&self) -> u64 {
        self.last_activity
    }
}
