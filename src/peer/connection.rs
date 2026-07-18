//! Peer Connection (Handshake Phase)
//!
//! Represents an in-progress connection before authentication completes.
//! PeerConnection tracks the Noise IK handshake and transitions to
//! ActivePeer upon successful authentication. The handshake *phase* (initial /
//! sent_msg1 / complete / failed) is no longer tracked here — it lives on the
//! per-peer control machine; the leg's crypto methods gate on the presence of
//! their Noise handles (`noise_handshake` / `noise_session`) directly.

use crate::PeerIdentity;
use crate::noise::{self, NoiseError, NoiseSession};
use crate::proto::fmp::{ConnectionState, NodeProfile};
use crate::transport::{LinkDirection, LinkId, LinkStats, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use secp256k1::Keypair;
use std::fmt;

/// A connection in the handshake phase, before authentication completes.
///
/// For outbound connections, we know the expected peer identity from config.
/// For inbound connections, we learn the identity during the Noise handshake.
///
/// This is the shell holder for the FMP crypto/state split: the pure
/// connection bookkeeping lives in [`ConnectionState`] (`proto::fmp::state`),
/// and the two Noise crypto handles stay here beside it. Pure public methods
/// delegate to `self.state`; the XX transition methods drive the crypto and
/// write results back through `self.state`'s setters.
pub struct PeerConnection {
    /// Pure, runtime-agnostic connection bookkeeping.
    state: ConnectionState,

    /// Noise handshake state (consumes on completion).
    noise_handshake: Option<noise::HandshakeState>,

    /// Completed Noise session (available after handshake complete).
    noise_session: Option<NoiseSession>,
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

    /// Create a new outbound connection without a pre-known identity.
    ///
    /// Used for anonymous discovery on shared-media transports (Ethernet,
    /// BLE) where the beacon doesn't carry identity. The peer's identity is
    /// learned from XX msg2 during the handshake.
    pub fn outbound_anonymous(link_id: LinkId, current_time_ms: u64) -> Self {
        Self {
            state: ConnectionState::outbound_anonymous(link_id, current_time_ms),
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

    /// When the connection started.
    pub fn started_at(&self) -> u64 {
        self.state.started_at()
    }

    /// When the last activity occurred.
    pub fn last_activity(&self) -> u64 {
        self.state.last_activity()
    }

    /// Connection duration so far.
    pub fn duration(&self, current_time_ms: u64) -> u64 {
        self.state.duration(current_time_ms)
    }

    /// Time since last activity.
    pub fn idle_time(&self, current_time_ms: u64) -> u64 {
        self.state.idle_time(current_time_ms)
    }

    /// Get link statistics.
    pub fn link_stats(&self) -> &LinkStats {
        self.state.link_stats()
    }

    /// Get mutable link statistics.
    pub fn link_stats_mut(&mut self) -> &mut LinkStats {
        self.state.link_stats_mut()
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

    // === Negotiation Results ===

    /// Get the peer's negotiated node profile, if learned.
    pub fn peer_profile(&self) -> Option<NodeProfile> {
        self.state.peer_profile()
    }

    /// Record the peer's node profile learned during FMP negotiation.
    pub fn set_negotiation_results(&mut self, peer_profile: NodeProfile) {
        self.state.set_negotiation_results(peer_profile);
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

    // === Noise Handshake Operations ===

    /// Start the handshake as initiator and generate message 1.
    ///
    /// For outbound connections only. Returns the Noise XX msg1 bytes.
    /// XX msg1 is ephemeral-only (33 bytes) — no identity or epoch.
    pub fn start_handshake(
        &mut self,
        our_keypair: Keypair,
        epoch: [u8; 8],
        current_time_ms: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        if self.state.direction() != LinkDirection::Outbound {
            return Err(NoiseError::WrongState {
                expected: "outbound connection".to_string(),
                got: "inbound connection".to_string(),
            });
        }

        // XX initiator: no remote static needed upfront. The old `!= Initial`
        // phase guard is dropped — this method creates the Noise handshake
        // handle, so there is no `take().expect()` to protect, and its Err path
        // was unreachable in production (one call per fresh outbound leg).
        let mut hs = noise::HandshakeState::new_initiator(our_keypair);
        hs.set_local_epoch(epoch);
        let msg1 = hs.write_message_1()?;

        self.noise_handshake = Some(hs);
        self.state.touch(current_time_ms);

        Ok(msg1)
    }

    /// Initialize responder and process incoming message 1.
    ///
    /// For inbound connections only. Returns the Noise XX msg2 bytes.
    /// XX: identity is NOT learned from msg1 (only ephemeral exchange).
    /// The responder learns the initiator's identity from msg3.
    /// The handshake remains in ReceivedMsg1 state (not Complete).
    ///
    /// If `negotiation_payload` is provided, it is encrypted and appended
    /// to the returned msg2 bytes.
    pub fn receive_handshake_init(
        &mut self,
        our_keypair: Keypair,
        epoch: [u8; 8],
        message: &[u8],
        negotiation_payload: Option<&[u8]>,
        current_time_ms: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        if self.state.direction() != LinkDirection::Inbound {
            return Err(NoiseError::WrongState {
                expected: "inbound connection".to_string(),
                got: "outbound connection".to_string(),
            });
        }

        let mut hs = noise::HandshakeState::new_responder(our_keypair);
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

        // XX: handshake NOT complete yet — need msg3. Keep the Noise handshake
        // handle for complete_handshake_msg3(); the phase (formerly
        // `ReceivedMsg1`) now lives on the control machine, so no phase is set
        // here. The handle's presence is the leg-local `ReceivedMsg1` signal.
        self.noise_handshake = Some(hs);
        self.state.touch(current_time_ms);

        Ok(msg2)
    }

    /// Complete the handshake by processing message 2 and generating message 3.
    ///
    /// For outbound connections only (initiator). Processes the responder's
    /// msg2 (learning their identity and epoch), then generates msg3.
    /// Returns the Noise XX msg3 bytes to send.
    ///
    /// If `negotiation_payload` is provided, it is encrypted and appended
    /// to the returned msg3 bytes. If the received msg2 contains a negotiation
    /// payload (bytes beyond the base XX msg2), it is decrypted and returned.
    pub fn complete_handshake(
        &mut self,
        message: &[u8],
        negotiation_payload: Option<&[u8]>,
        current_time_ms: u64,
    ) -> Result<(Vec<u8>, Option<Vec<u8>>), NoiseError> {
        // The leg is at `SentMsg1` iff its Noise handshake handle is present
        // (set by `start_handshake`, taken here on completion). Gate on the
        // handle directly now that the phase enum is gone — byte-equivalent to
        // the old `!= SentMsg1` guard for every reachable transition.
        if self.noise_handshake.is_none() {
            return Err(NoiseError::WrongState {
                expected: "sent_msg1 state".to_string(),
                got: "no active handshake".to_string(),
            });
        }

        let mut hs = self
            .noise_handshake
            .take()
            .expect("noise handshake must exist in SentMsg1 state");

        // Split msg2 into base XX part and optional negotiation
        let base_size = noise::HANDSHAKE_MSG2_SIZE;
        let (base_msg2, extra) = if message.len() > base_size {
            (&message[..base_size], Some(&message[base_size..]))
        } else {
            (message, None)
        };

        // Process XX msg2 (learns responder identity + epoch)
        hs.read_message_2(base_msg2)?;

        // Decrypt negotiation payload from msg2 if present
        let received_negotiation = if let Some(encrypted) = extra {
            Some(hs.decrypt_payload(encrypted)?)
        } else {
            None
        };

        // Learn responder identity from msg2
        let remote_static = *hs
            .remote_static()
            .expect("remote static available after XX msg2");
        self.state
            .set_expected_identity(PeerIdentity::from_pubkey_full(remote_static));

        // Capture remote epoch from msg2
        self.state.set_remote_epoch(hs.remote_epoch());

        // Generate XX msg3
        let mut msg3 = hs.write_message_3()?;

        // Append encrypted negotiation payload if provided
        if let Some(payload) = negotiation_payload {
            let encrypted = hs.encrypt_payload(payload)?;
            msg3.extend_from_slice(&encrypted);
        }

        // Handshake complete for initiator
        let session = hs.into_session()?;
        self.noise_session = Some(session);
        self.state.touch(current_time_ms);

        Ok((msg3, received_negotiation))
    }

    /// Complete the responder handshake by processing message 3.
    ///
    /// For inbound connections only (responder). Processes the initiator's
    /// msg3, learning their identity and epoch.
    ///
    /// If the msg3 contains a negotiation payload (bytes beyond base XX msg3),
    /// it is decrypted and returned.
    pub fn complete_handshake_msg3(
        &mut self,
        message: &[u8],
        current_time_ms: u64,
    ) -> Result<Option<Vec<u8>>, NoiseError> {
        // The responder leg is at `ReceivedMsg1` iff its Noise handshake handle
        // is present (set by `receive_handshake_init`, taken here on msg3). Gate
        // on the handle directly now that the phase enum is gone — byte-equivalent
        // to the old `!= ReceivedMsg1` guard for every reachable transition, and
        // it protects the `take().expect()` below.
        if self.noise_handshake.is_none() {
            return Err(NoiseError::WrongState {
                expected: "received_msg1 state".to_string(),
                got: "no active handshake".to_string(),
            });
        }

        let mut hs = self
            .noise_handshake
            .take()
            .expect("noise handshake must exist in ReceivedMsg1 state");

        // Split msg3 into base XX part and optional negotiation
        let base_size = noise::HANDSHAKE_MSG3_SIZE;
        let (base_msg3, extra) = if message.len() > base_size {
            (&message[..base_size], Some(&message[base_size..]))
        } else {
            (message, None)
        };

        // Process XX msg3 (learns initiator identity + epoch)
        hs.read_message_3(base_msg3)?;

        // Decrypt negotiation payload from msg3 if present
        let received_negotiation = if let Some(encrypted) = extra {
            Some(hs.decrypt_payload(encrypted)?)
        } else {
            None
        };

        // Learn initiator identity from msg3
        let remote_static = *hs
            .remote_static()
            .expect("remote static available after XX msg3");
        self.state
            .set_expected_identity(PeerIdentity::from_pubkey_full(remote_static));

        // Capture remote epoch from msg3
        self.state.set_remote_epoch(hs.remote_epoch());

        // Handshake complete for responder. The completion signal is now the
        // Noise session's presence (the phase enum is gone); no phase is set.
        let session = hs.into_session()?;
        self.noise_session = Some(session);
        self.state.touch(current_time_ms);

        Ok(received_negotiation)
    }

    /// Take the completed Noise session.
    ///
    /// Returns the NoiseSession for use in ActivePeer. Can only be called
    /// once after handshake completes.
    pub fn take_session(&mut self) -> Option<NoiseSession> {
        // The session exists iff the handshake reached `Complete`, so taking it
        // unconditionally is byte-equivalent to the old `== Complete` gate.
        self.noise_session.take()
    }

    /// Check if we have a completed session ready to take.
    pub fn has_session(&self) -> bool {
        self.noise_session.is_some()
    }

    // === State Transitions (for manual control if needed) ===

    /// Drop the shell-owned crypto handshake handle. The failure *state* now
    /// lives on the control machine (`PeerMachine`); this only releases the
    /// leg's Noise handle at the identical point it was released before, so a
    /// subsequent `complete_handshake` on this leg still reports `WrongState`.
    pub fn mark_failed(&mut self) {
        self.noise_handshake = None;
    }

    /// Update last activity timestamp.
    pub fn touch(&mut self, current_time_ms: u64) {
        self.state.touch(current_time_ms);
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
    use rand::Rng;

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
        rand::rng().fill_bytes(&mut epoch);
        epoch
    }

    #[test]
    fn test_outbound_connection() {
        let identity = make_peer_identity();
        let conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);

        assert!(conn.is_outbound());
        assert!(!conn.is_inbound());
        assert!(!conn.has_session());
        assert!(conn.expected_identity().is_some());
        assert_eq!(conn.started_at(), 1000);
    }

    #[test]
    fn test_inbound_connection() {
        let conn = PeerConnection::inbound(LinkId::new(2), 2000);

        assert!(conn.is_inbound());
        assert!(!conn.is_outbound());
        assert!(!conn.has_session());
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
        let initiator_epoch = make_epoch();
        let responder_epoch = make_epoch();

        // Use from_pubkey_full to preserve parity for ECDH
        let responder_peer_id = PeerIdentity::from_pubkey_full(responder_identity.pubkey_full());

        // Create connections
        let mut initiator_conn = PeerConnection::outbound(LinkId::new(1), responder_peer_id, 1000);
        let mut responder_conn = PeerConnection::inbound(LinkId::new(2), 1000);

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
        assert!(responder_conn.expected_identity().is_none());

        // Initiator processes msg2 and generates msg3
        let (msg3, _neg) = initiator_conn
            .complete_handshake(&msg2, None, 1300)
            .unwrap();
        // The initiator completes at msg3 generation: it now holds a session.
        assert!(initiator_conn.has_session());

        // Initiator learned responder's identity from msg2
        let discovered = initiator_conn.expected_identity().unwrap();
        assert_eq!(discovered.pubkey(), responder_identity.pubkey());
        assert_eq!(initiator_conn.remote_epoch(), Some(responder_epoch));

        // Responder processes msg3 (completes handshake): it now holds a session.
        let _neg = responder_conn.complete_handshake_msg3(&msg3, 1400).unwrap();
        assert!(responder_conn.has_session());

        // Responder learned initiator's identity from msg3
        let discovered = responder_conn.expected_identity().unwrap();
        assert_eq!(discovered.pubkey(), initiator_identity.pubkey());
        assert_eq!(responder_conn.remote_epoch(), Some(initiator_epoch));

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
        // `mark_failed` releases the leg's Noise handshake handle. The failure
        // *state* now lives on the control machine, but the leg-local effect is
        // still observable: a completion attempt afterward reports `WrongState`
        // (the handle-presence gate) and no session is produced.
        let identity = make_peer_identity();
        let keypair = make_keypair();
        let mut conn = PeerConnection::outbound(LinkId::new(1), identity, 1000);
        conn.start_handshake(keypair, make_epoch(), 1100).unwrap();

        conn.mark_failed();

        assert!(!conn.has_session());
        assert!(conn.complete_handshake(&[0u8; 96], None, 1200).is_err());
    }

    #[test]
    fn test_wrong_direction_errors() {
        let identity = make_peer_identity();
        let keypair = make_keypair();

        // Outbound can't receive_handshake_init
        let mut outbound = PeerConnection::outbound(LinkId::new(1), identity, 1000);
        assert!(
            outbound
                .receive_handshake_init(keypair, make_epoch(), &[0u8; 33], None, 1100)
                .is_err()
        );

        // Inbound can't start_handshake
        let mut inbound = PeerConnection::inbound(LinkId::new(2), 1000);
        assert!(
            inbound
                .start_handshake(keypair, make_epoch(), 1100)
                .is_err()
        );
    }
}
