use super::{CipherState, HandshakeRole, NoiseError, ReplayWindow};
use secp256k1::{PublicKey, XOnlyPublicKey};
use std::fmt;

/// Completed Noise session for transport encryption.
///
/// Provides bidirectional authenticated encryption with replay protection.
/// The send counter is monotonically incremented; received counters are
/// validated against a sliding window to prevent replay attacks.
pub struct NoiseSession {
    /// Our role in the original handshake.
    role: HandshakeRole,
    /// Cipher for sending.
    send_cipher: CipherState,
    /// Cipher for receiving.
    recv_cipher: CipherState,
    /// Handshake hash for channel binding.
    handshake_hash: [u8; 32],
    /// Remote peer's static public key.
    remote_static: PublicKey,
    /// Replay window for received packets.
    replay_window: ReplayWindow,
}

impl NoiseSession {
    /// Create a new session from completed handshake data.
    pub(super) fn from_handshake(
        role: HandshakeRole,
        send_cipher: CipherState,
        recv_cipher: CipherState,
        handshake_hash: [u8; 32],
        remote_static: PublicKey,
    ) -> Self {
        Self {
            role,
            send_cipher,
            recv_cipher,
            handshake_hash,
            remote_static,
            replay_window: ReplayWindow::new(),
        }
    }

    /// Encrypt a message for sending (using internal counter).
    ///
    /// Returns the ciphertext. The current send counter should be included
    /// in the wire format before calling this method.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.send_cipher.encrypt(plaintext)
    }

    /// Get the current send counter (before incrementing).
    ///
    /// Use this to get the counter to include in the wire format.
    /// The counter will be incremented when `encrypt` is called.
    pub fn current_send_counter(&self) -> u64 {
        self.send_cipher.nonce
    }

    /// Decrypt a received message (using internal counter).
    ///
    /// This is for handshake-phase decryption. For transport phase with
    /// explicit counters, use `decrypt_with_replay_check` instead.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        self.recv_cipher.decrypt(ciphertext)
    }

    /// Check if a counter passes the replay window.
    ///
    /// Returns Ok(()) if the counter is acceptable, Err if it should be rejected.
    /// Call this before attempting decryption to avoid wasting CPU on replay attacks.
    pub fn check_replay(&self, counter: u64) -> Result<(), NoiseError> {
        if self.replay_window.check(counter) {
            Ok(())
        } else {
            Err(NoiseError::ReplayDetected(counter))
        }
    }

    /// Decrypt with explicit counter and replay protection.
    ///
    /// This is the primary decryption method for transport phase.
    /// The counter comes from the wire format and is validated against
    /// the replay window before and after decryption.
    ///
    /// On success, the counter is accepted into the replay window.
    pub fn decrypt_with_replay_check(
        &mut self,
        ciphertext: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        // Check replay window first (cheap)
        if !self.replay_window.check(counter) {
            return Err(NoiseError::ReplayDetected(counter));
        }

        // Attempt decryption (expensive)
        let plaintext = self.recv_cipher.decrypt_with_counter(ciphertext, counter)?;

        // Only accept into window after successful decryption
        // This prevents DoS attacks that exhaust the window
        self.replay_window.accept(counter);

        Ok(plaintext)
    }

    /// Encrypt a message with Additional Authenticated Data (AAD).
    ///
    /// Returns the ciphertext. The current send counter should be included
    /// in the wire format before calling this method.
    pub fn encrypt_with_aad(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        self.send_cipher.encrypt_with_aad(plaintext, aad)
    }

    /// Decrypt with explicit counter, replay protection, and AAD.
    ///
    /// This is the primary decryption method for the FMP transport phase
    /// with AAD binding. The AAD (typically the 16-byte outer header) must
    /// match what was used during encryption.
    pub fn decrypt_with_replay_check_and_aad(
        &mut self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        // Check replay window first (cheap)
        if !self.replay_window.check(counter) {
            return Err(NoiseError::ReplayDetected(counter));
        }

        // Attempt decryption with AAD (expensive)
        let plaintext = self.recv_cipher.decrypt_with_counter_and_aad(ciphertext, counter, aad)?;

        // Only accept into window after successful decryption
        self.replay_window.accept(counter);

        Ok(plaintext)
    }

    /// Get the highest received counter.
    pub fn highest_received_counter(&self) -> u64 {
        self.replay_window.highest()
    }

    /// Reset the replay window (use when rekeying).
    pub fn reset_replay_window(&mut self) {
        self.replay_window.reset();
    }

    /// Get the handshake hash for channel binding.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// Get the remote peer's static public key.
    pub fn remote_static(&self) -> &PublicKey {
        &self.remote_static
    }

    /// Get the remote peer's x-only public key.
    pub fn remote_static_xonly(&self) -> XOnlyPublicKey {
        self.remote_static.x_only_public_key().0
    }

    /// Get our role in the handshake.
    pub fn role(&self) -> HandshakeRole {
        self.role
    }

    /// Get the send nonce (for debugging).
    pub fn send_nonce(&self) -> u64 {
        self.send_cipher.nonce()
    }

    /// Get the receive nonce (for debugging).
    pub fn recv_nonce(&self) -> u64 {
        self.recv_cipher.nonce()
    }
}

impl fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NoiseSession")
            .field("role", &self.role)
            .field("send_nonce", &self.send_cipher.nonce())
            .field("recv_nonce", &self.recv_cipher.nonce())
            .field("handshake_hash", &hex::encode(&self.handshake_hash[..8]))
            .finish()
    }
}
