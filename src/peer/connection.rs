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
use crate::transport::{LinkDirection, LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
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

    // === Accessors (delegated to the pure ConnectionState) ===

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.state.link_id()
    }

    /// Get the connection direction.
    pub fn direction(&self) -> LinkDirection {
        self.state.direction()
    }

    /// Get the expected/learned peer identity, if known.
    pub fn expected_identity(&self) -> Option<&PeerIdentity> {
        self.state.expected_identity()
    }

    /// Check if this is an outbound connection.
    pub fn is_outbound(&self) -> bool {
        self.state.is_outbound()
    }

    /// Check if this is an inbound connection.
    pub fn is_inbound(&self) -> bool {
        self.state.is_inbound()
    }

    /// When the connection started. Retained only to seed a control machine's
    /// carrier from a pre-built leg (`Node::add_connection`); the operator-facing
    /// `started_at_ms`/`last_activity_ms` telemetry now reads the machine carrier,
    /// not the leg.
    pub fn started_at(&self) -> u64 {
        self.state.started_at()
    }

    /// Connection duration so far.
    pub fn duration(&self, current_time_ms: u64) -> u64 {
        self.state.duration(current_time_ms)
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        self.state.idle_time(current_time_ms)
    }

    // === Index Accessors ===

    /// Get our session index (if set).
    pub fn our_index(&self) -> Option<SessionIndex> {
        self.state.our_index()
    }

    /// Set our session index.
    pub fn set_our_index(&mut self, index: SessionIndex) {
        self.state.set_our_index(index);
    }

    /// Get their session index (if known).
    pub fn their_index(&self) -> Option<SessionIndex> {
        self.state.their_index()
    }

    /// Set their session index.
    pub fn set_their_index(&mut self, index: SessionIndex) {
        self.state.set_their_index(index);
    }

    /// Get the transport ID (if set).
    pub fn transport_id(&self) -> Option<TransportId> {
        self.state.transport_id()
    }

    /// Set the transport ID.
    pub fn set_transport_id(&mut self, id: TransportId) {
        self.state.set_transport_id(id);
    }

    /// Get the source address (if known).
    pub fn source_addr(&self) -> Option<&TransportAddr> {
        self.state.source_addr()
    }

    /// Set the source address.
    pub fn set_source_addr(&mut self, addr: TransportAddr) {
        self.state.set_source_addr(addr);
    }

    // === Epoch Accessors ===

    /// Get the remote peer's startup epoch (available after handshake).
    pub fn remote_epoch(&self) -> Option<[u8; 8]> {
        self.state.remote_epoch()
    }

    // === Handshake Resend ===

    /// Store the wire-format msg1 bytes for resend and schedule the first resend.
    pub fn set_handshake_msg1(&mut self, msg1: Vec<u8>, first_resend_at_ms: u64) {
        self.state.set_handshake_msg1(msg1, first_resend_at_ms);
    }

    /// Store the wire-format msg2 bytes for resend on duplicate msg1.
    pub fn set_handshake_msg2(&mut self, msg2: Vec<u8>) {
        self.state.set_handshake_msg2(msg2);
    }

    /// Get the stored msg1 bytes (if any).
    pub fn handshake_msg1(&self) -> Option<&[u8]> {
        self.state.handshake_msg1()
    }

    /// Get the stored msg2 bytes (if any).
    pub fn handshake_msg2(&self) -> Option<&[u8]> {
        self.state.handshake_msg2()
    }

    // === Crypto handle plumbing (the control machine drives the handshake) ===

    /// Mutable access to the pure bookkeeping, so the control machine's
    /// handshake operations can record their results here as well as on the
    /// surviving carrier.
    pub(crate) fn state_mut(&mut self) -> &mut ConnectionState {
        &mut self.state
    }

    // === Validation ===

    /// Check if the connection has timed out.
    pub fn is_timed_out(&self, current_time_ms: u64, timeout_ms: u64) -> bool {
        self.state.is_timed_out(current_time_ms, timeout_ms)
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

        assert_eq!(conn.duration(1500), 500);
        assert_eq!(conn.idle_time(1500), 500);
        assert!(!conn.is_timed_out(1500, 1000));
        assert!(conn.is_timed_out(2500, 1000));
    }
}
