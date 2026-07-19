//! Peer Connection (Handshake Phase)
//!
//! Represents an in-progress connection before authentication completes.
//! PeerConnection tracks the Noise IK handshake and transitions to
//! ActivePeer upon successful authentication. Neither the handshake *phase*
//! (initial / sent_msg1 / complete / failed) nor the handshake operations are
//! tracked here — both live on the per-peer control machine, which drives the
//! Noise handles held below.

use crate::PeerIdentity;
use crate::noise::{self, NoiseSession};
use crate::proto::fmp::ConnectionState;
use crate::transport::{LinkId, TransportAddr, TransportId};
use std::fmt;

/// A connection in the handshake phase, before authentication completes.
///
/// For outbound connections, we know the expected peer identity from config.
/// For inbound connections, we learn the identity during the Noise handshake.
///
/// This is the shell holder for the FMP crypto/state split: the pure
/// connection bookkeeping lives in [`ConnectionState`] (`proto::fmp::state`),
/// and the two Noise crypto handles stay here beside it. Pure public methods
/// delegate to `self.state`; the control machine drives the handles and
/// records each result here and on its own carrier.
pub struct PeerConnection {
    /// Pure, runtime-agnostic connection bookkeeping.
    state: ConnectionState,

    /// Noise handshake state (consumes on completion).
    ///
    /// Driven by the control machine, which owns the handshake operations.
    pub(crate) noise_handshake: Option<noise::HandshakeState>,

    /// Completed Noise session (available after handshake complete).
    ///
    /// Driven by the control machine, which owns the handshake operations.
    pub(crate) noise_session: Option<NoiseSession>,
}

impl PeerConnection {
    /// Create a new outbound connection (we are initiating).
    ///
    /// For outbound, we know who we're trying to reach from configuration.
    /// The Noise handshake will be initialized when `start_handshake` is called.
    pub fn outbound(
        link_id: LinkId,
        expected_identity: PeerIdentity,
        current_time_ms: u64,
    ) -> Self {
        Self {
            state: ConnectionState::outbound(link_id, expected_identity, current_time_ms),
            noise_handshake: None,
            noise_session: None,
        }
    }

    /// Create a new inbound connection (they are initiating).
    ///
    /// For inbound, we don't know who they are until we decrypt their
    /// identity from Noise message 1.
    pub fn inbound(link_id: LinkId, current_time_ms: u64) -> Self {
        Self {
            state: ConnectionState::inbound(link_id, current_time_ms),
            noise_handshake: None,
            noise_session: None,
        }
    }

    /// Create a new inbound connection with transport information.
    ///
    /// Used when processing msg1 where we know the transport and source address.
    pub fn inbound_with_transport(
        link_id: LinkId,
        transport_id: TransportId,
        source_addr: TransportAddr,
        current_time_ms: u64,
    ) -> Self {
        Self {
            state: ConnectionState::inbound_with_transport(
                link_id,
                transport_id,
                source_addr,
                current_time_ms,
            ),
            noise_handshake: None,
            noise_session: None,
        }
    }

    // === Epoch Accessors ===

    /// Get the remote peer's startup epoch (available after handshake).
    pub fn remote_epoch(&self) -> Option<[u8; 8]> {
        self.state.remote_epoch()
    }

    // === Crypto handle plumbing (the control machine drives the handshake) ===

    /// Mutable access to the pure bookkeeping, so the control machine's
    /// handshake operations can record their results here as well as on the
    /// surviving carrier.
    pub(crate) fn state(&self) -> &ConnectionState {
        &self.state
    }

    pub(crate) fn state_mut(&mut self) -> &mut ConnectionState {
        &mut self.state
    }
}

impl fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerConnection")
            .field("link_id", &self.state.link_id())
            .field("direction", &self.state.direction())
            .field("expected_identity", &self.state.expected_identity())
            .field("has_noise_handshake", &self.noise_handshake.is_some())
            .field("has_noise_session", &self.noise_session.is_some())
            .field("our_index", &self.state.our_index())
            .field("their_index", &self.state.their_index())
            .field("transport_id", &self.state.transport_id())
            .field("started_at", &self.state.started_at())
            .field("last_activity", &self.state.last_activity())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    fn make_peer_identity() -> PeerIdentity {
        let identity = Identity::generate();
        PeerIdentity::from_pubkey(identity.pubkey())
    }

    #[test]
    fn test_connection_timing() {
        let identity = make_peer_identity();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        assert_eq!(conn.state().duration(1500), 500);
        assert_eq!(conn.state().idle_time(1500), 500);
        assert!(!conn.state().is_timed_out(1500, 1000));
        assert!(conn.state().is_timed_out(2500, 1000));
    }
}
