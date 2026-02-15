//! Peer Connection (Handshake Phase)
//!
//! Represents an in-progress connection before authentication completes.
//! PeerConnection tracks the Noise IK handshake state and transitions to
//! ActivePeer upon successful authentication.

use crate::utils::index::SessionIndex;
use crate::noise::{self, NoiseError, NoiseSession};
use crate::transport::{LinkDirection, LinkId, LinkStats, TransportAddr, TransportId};
use crate::PeerIdentity;
use secp256k1::Keypair;
use std::fmt;

/// Handshake protocol state machine.
///
/// For Noise IK pattern:
/// - Initiator: Initial → SentMsg1 → Complete
/// - Responder: Initial → ReceivedMsg1 → Complete
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeState {
    /// Initial state, ready to start handshake.
    Initial,
    /// Initiator: Sent message 1, awaiting message 2.
    SentMsg1,
    /// Responder: Received message 1, ready to send message 2.
    ReceivedMsg1,
    /// Handshake completed successfully.
    Complete,
    /// Handshake failed.
    Failed,
}

impl HandshakeState {
    /// Check if handshake is still in progress.
    pub fn is_in_progress(&self) -> bool {
        matches!(
            self,
            HandshakeState::Initial | HandshakeState::SentMsg1 | HandshakeState::ReceivedMsg1
        )
    }

    /// Check if handshake completed successfully.
    pub fn is_complete(&self) -> bool {
        matches!(self, HandshakeState::Complete)
    }

    /// Check if handshake failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, HandshakeState::Failed)
    }
}

impl fmt::Display for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            HandshakeState::Initial => "initial",
            HandshakeState::SentMsg1 => "sent_msg1",
            HandshakeState::ReceivedMsg1 => "received_msg1",
            HandshakeState::Complete => "complete",
            HandshakeState::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

/// A connection in the handshake phase, before authentication completes.
///
/// For outbound connections, we know the expected peer identity from config.
/// For inbound connections, we learn the identity during the Noise handshake.
pub struct PeerConnection {
    // === Link Reference ===
    /// The link carrying this connection.
    link_id: LinkId,

    /// Connection direction (we initiated or they initiated).
    direction: LinkDirection,

    // === Handshake State ===
    /// Current handshake state.
    handshake_state: HandshakeState,

    /// Expected peer identity (known for outbound, learned for inbound).
    /// Updated after receiving their static key in the handshake.
    expected_identity: Option<PeerIdentity>,

    /// Noise handshake state (consumes on completion).
    noise_handshake: Option<noise::HandshakeState>,

    /// Completed Noise session (available after handshake complete).
    noise_session: Option<NoiseSession>,

    // === Timing ===
    /// When the connection attempt started (Unix milliseconds).
    started_at: u64,

    /// When the last handshake message was sent/received.
    last_activity: u64,

    // === Statistics ===
    /// Link statistics during handshake.
    link_stats: LinkStats,

    // === Wire Protocol Index Tracking ===
    /// Our sender_idx for this handshake (chosen by us).
    /// For outbound: included in msg1, used as receiver_idx in msg2 echo.
    /// For inbound: chosen after processing msg1, included in msg2.
    our_index: Option<SessionIndex>,

    /// Their sender_idx (learned from their messages).
    /// For outbound: learned from msg2.
    /// For inbound: learned from msg1.
    their_index: Option<SessionIndex>,

    /// Transport ID (for index namespace).
    transport_id: Option<TransportId>,

    /// Current source address (updated on packet receipt).
    source_addr: Option<TransportAddr>,
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
            link_id,
            direction: LinkDirection::Outbound,
            handshake_state: HandshakeState::Initial,
            expected_identity: Some(expected_identity),
            noise_handshake: None,
            noise_session: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,

            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: None,
            source_addr: None,
        }
    }

    /// Create a new inbound connection (they are initiating).
    ///
    /// For inbound, we don't know who they are until we decrypt their
    /// identity from Noise message 1.
    pub fn inbound(link_id: LinkId, current_time_ms: u64) -> Self {
        Self {
            link_id,
            direction: LinkDirection::Inbound,
            handshake_state: HandshakeState::Initial,
            expected_identity: None,
            noise_handshake: None,
            noise_session: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,

            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: None,
            source_addr: None,
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
            link_id,
            direction: LinkDirection::Inbound,
            handshake_state: HandshakeState::Initial,
            expected_identity: None,
            noise_handshake: None,
            noise_session: None,
            started_at: current_time_ms,
            last_activity: current_time_ms,

            link_stats: LinkStats::new(),
            our_index: None,
            their_index: None,
            transport_id: Some(transport_id),
            source_addr: Some(source_addr),
        }
    }

    // === Accessors ===

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    /// Get the connection direction.
    pub fn direction(&self) -> LinkDirection {
        self.direction
    }

    /// Get the handshake state.
    pub fn handshake_state(&self) -> HandshakeState {
        self.handshake_state
    }

    /// Get the expected/learned peer identity, if known.
    pub fn expected_identity(&self) -> Option<&PeerIdentity> {
        self.expected_identity.as_ref()
    }

    /// Check if this is an outbound connection.
    pub fn is_outbound(&self) -> bool {
        self.direction == LinkDirection::Outbound
    }

    /// Check if this is an inbound connection.
    pub fn is_inbound(&self) -> bool {
        self.direction == LinkDirection::Inbound
    }

    /// Check if handshake is in progress.
    pub fn is_in_progress(&self) -> bool {
        self.handshake_state.is_in_progress()
    }

    /// Check if handshake completed.
    pub fn is_complete(&self) -> bool {
        self.handshake_state.is_complete()
    }

    /// Check if handshake failed.
    pub fn is_failed(&self) -> bool {
        self.handshake_state.is_failed()
    }

    /// When the connection started.
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// When the last activity occurred.
    pub fn last_activity(&self) -> u64 {
        self.last_activity
    }

    /// Connection duration so far.
    pub fn duration(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.started_at)
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        current_time_ms.saturating_sub(self.last_activity)
    }

    /// Get link statistics.
    pub fn link_stats(&self) -> &LinkStats {
        &self.link_stats
    }

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        &mut self.link_stats
    }

    // === Index Accessors ===

    /// Get our session index (if set).
    pub fn our_index(&self) -> Option<SessionIndex> {
        self.our_index
    }

    /// Set our session index.
    pub fn set_our_index(&mut self, index: SessionIndex) {
        self.our_index = Some(index);
    }

    /// Get their session index (if known).
    pub fn their_index(&self) -> Option<SessionIndex> {
        self.their_index
    }

    /// Set their session index.
    pub fn set_their_index(&mut self, index: SessionIndex) {
        self.their_index = Some(index);
    }

    /// Get the transport ID (if set).
    pub fn transport_id(&self) -> Option<TransportId> {
        self.transport_id
    }

    /// Set the transport ID.
    pub fn set_transport_id(&mut self, id: TransportId) {
        self.transport_id = Some(id);
    }

    /// Get the source address (if known).
    pub fn source_addr(&self) -> Option<&TransportAddr> {
        self.source_addr.as_ref()
    }

    /// Set the source address.
    pub fn set_source_addr(&mut self, addr: TransportAddr) {
        self.source_addr = Some(addr);
    }

    // === Noise Handshake Operations ===

    /// Start the handshake as initiator and generate message 1.
    ///
    /// For outbound connections only. Returns the handshake message to send.
    pub fn start_handshake(
        &mut self,
        our_keypair: Keypair,
        current_time_ms: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        if self.direction != LinkDirection::Outbound {
            return Err(NoiseError::WrongState {
                expected: "outbound connection".to_string(),
                got: "inbound connection".to_string(),
            });
        }

        if self.handshake_state != HandshakeState::Initial {
            return Err(NoiseError::WrongState {
                expected: "initial state".to_string(),
                got: self.handshake_state.to_string(),
            });
        }

        let remote_static = self
            .expected_identity
            .as_ref()
            .expect("outbound must have expected identity")
            .pubkey_full();

        let mut hs = noise::HandshakeState::new_initiator(our_keypair, remote_static);
        let msg1 = hs.write_message_1()?;

        self.noise_handshake = Some(hs);
        self.handshake_state = HandshakeState::SentMsg1;
        self.last_activity = current_time_ms;

        Ok(msg1)
    }

    /// Initialize responder and process incoming message 1.
    ///
    /// For inbound connections only. Returns the handshake message 2 to send.
    pub fn receive_handshake_init(
        &mut self,
        our_keypair: Keypair,
        message: &[u8],
        current_time_ms: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        if self.direction != LinkDirection::Inbound {
            return Err(NoiseError::WrongState {
                expected: "inbound connection".to_string(),
                got: "outbound connection".to_string(),
            });
        }

        if self.handshake_state != HandshakeState::Initial {
            return Err(NoiseError::WrongState {
                expected: "initial state".to_string(),
                got: self.handshake_state.to_string(),
            });
        }

        let mut hs = noise::HandshakeState::new_responder(our_keypair);

        // Process message 1 (this reveals the initiator's identity)
        hs.read_message_1(message)?;

        // Extract the discovered identity
        let remote_static = *hs
            .remote_static()
            .expect("remote static available after msg1");
        self.expected_identity = Some(PeerIdentity::from_pubkey_full(remote_static));

        // Generate message 2
        let msg2 = hs.write_message_2()?;

        // Handshake is complete for responder
        let session = hs.into_session()?;
        self.noise_session = Some(session);
        self.handshake_state = HandshakeState::Complete;
        self.last_activity = current_time_ms;

        Ok(msg2)
    }

    /// Complete the handshake by processing message 2.
    ///
    /// For outbound connections only (initiator completing handshake).
    pub fn complete_handshake(
        &mut self,
        message: &[u8],
        current_time_ms: u64,
    ) -> Result<(), NoiseError> {
        if self.handshake_state != HandshakeState::SentMsg1 {
            return Err(NoiseError::WrongState {
                expected: "sent_msg1 state".to_string(),
                got: self.handshake_state.to_string(),
            });
        }

        let mut hs = self
            .noise_handshake
            .take()
            .expect("noise handshake must exist in SentMsg1 state");

        hs.read_message_2(message)?;

        let session = hs.into_session()?;
        self.noise_session = Some(session);
        self.handshake_state = HandshakeState::Complete;
        self.last_activity = current_time_ms;

        Ok(())
    }

    /// Take the completed Noise session.
    ///
    /// Returns the NoiseSession for use in ActivePeer. Can only be called
    /// once after handshake completes.
    pub fn take_session(&mut self) -> Option<NoiseSession> {
        if self.handshake_state == HandshakeState::Complete {
            self.noise_session.take()
        } else {
            None
        }
    }

    /// Check if we have a completed session ready to take.
    pub fn has_session(&self) -> bool {
        self.handshake_state == HandshakeState::Complete && self.noise_session.is_some()
    }

    // === State Transitions (for manual control if needed) ===

    /// Mark handshake as failed.
    pub fn mark_failed(&mut self) {
        self.handshake_state = HandshakeState::Failed;
        self.noise_handshake = None;
    }

    /// Update last activity timestamp.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.last_activity = current_time_ms;
    }

    // === Validation ===

    /// Check if the connection has timed out.
    pub fn is_timed_out(&self, current_time_ms: u64, timeout_ms: u64) -> bool {
        self.idle_time(current_time_ms) > timeout_ms
    }

}

impl fmt::Debug for PeerConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerConnection")
            .field("link_id", &self.link_id)
            .field("direction", &self.direction)
            .field("handshake_state", &self.handshake_state)
            .field("expected_identity", &self.expected_identity)
            .field("has_noise_handshake", &self.noise_handshake.is_some())
            .field("has_noise_session", &self.noise_session.is_some())
            .field("our_index", &self.our_index)
            .field("their_index", &self.their_index)
            .field("transport_id", &self.transport_id)
            .field("started_at", &self.started_at)
            .field("last_activity", &self.last_activity)
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

    fn make_keypair() -> Keypair {
        let identity = Identity::generate();
        identity.keypair()
    }

    #[test]
    fn test_handshake_state_properties() {
        assert!(HandshakeState::Initial.is_in_progress());
        assert!(HandshakeState::SentMsg1.is_in_progress());
        assert!(HandshakeState::ReceivedMsg1.is_in_progress());
        assert!(!HandshakeState::Complete.is_in_progress());
        assert!(!HandshakeState::Failed.is_in_progress());

        assert!(HandshakeState::Complete.is_complete());
        assert!(HandshakeState::Failed.is_failed());
    }

    #[test]
    fn test_outbound_connection() {
        let identity = make_peer_identity();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        assert!(conn.is_outbound());
        assert!(!conn.is_inbound());
        assert_eq!(conn.handshake_state(), HandshakeState::Initial);
        assert!(conn.expected_identity().is_some());
        assert_eq!(conn.started_at(), 1000);
    }

    #[test]
    fn test_inbound_connection() {
        let conn = PeerConnection::inbound(LinkId::new(2), 2000);

        assert!(conn.is_inbound());
        assert!(!conn.is_outbound());
        assert_eq!(conn.handshake_state(), HandshakeState::Initial);
        assert!(conn.expected_identity().is_none());
        assert_eq!(conn.started_at(), 2000);
    }

    #[test]
    fn test_full_handshake_flow() {
        // Create identities
        let initiator_identity = Identity::generate();
        let responder_identity = Identity::generate();

        let initiator_keypair = initiator_identity.keypair();
        let responder_keypair = responder_identity.keypair();

        // Use from_pubkey_full to preserve parity for ECDH
        let responder_peer_id = PeerIdentity::from_pubkey_full(responder_identity.pubkey_full());

        // Create connections
        let mut initiator_conn =
            PeerConnection::outbound(LinkId::new(1), responder_peer_id, 1000);
        let mut responder_conn = PeerConnection::inbound(LinkId::new(2), 1000);

        // Initiator starts handshake
        let msg1 = initiator_conn.start_handshake(initiator_keypair, 1100).unwrap();
        assert_eq!(initiator_conn.handshake_state(), HandshakeState::SentMsg1);

        // Responder processes msg1 and sends msg2
        let msg2 = responder_conn
            .receive_handshake_init(responder_keypair, &msg1, 1200)
            .unwrap();
        assert_eq!(responder_conn.handshake_state(), HandshakeState::Complete);

        // Responder learned initiator's identity
        let discovered = responder_conn.expected_identity().unwrap();
        assert_eq!(discovered.pubkey(), initiator_identity.pubkey());

        // Initiator completes handshake
        initiator_conn.complete_handshake(&msg2, 1300).unwrap();
        assert_eq!(initiator_conn.handshake_state(), HandshakeState::Complete);

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

    #[test]
    fn test_connection_timing() {
        let identity = make_peer_identity();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        assert_eq!(conn.duration(1500), 500);
        assert_eq!(conn.idle_time(1500), 500);
        assert!(!conn.is_timed_out(1500, 1000));
        assert!(conn.is_timed_out(2500, 1000));
    }

    #[test]
    fn test_connection_failure() {
        let identity = make_peer_identity();
        let mut conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        conn.mark_failed();
        assert!(conn.is_failed());
        assert!(!conn.is_in_progress());
        assert!(!conn.is_complete());
    }

    #[test]
    fn test_wrong_direction_errors() {
        let identity = make_peer_identity();
        let keypair = make_keypair();

        // Outbound can't receive_handshake_init
        let mut outbound = PeerConnection::outbound(LinkId::new(1), identity, 1000);
        assert!(outbound
            .receive_handshake_init(keypair, &[0u8; 82], 1100)
            .is_err());

        // Inbound can't start_handshake
        let mut inbound = PeerConnection::inbound(LinkId::new(2), 1000);
        assert!(inbound.start_handshake(keypair, 1100).is_err());
    }
}
