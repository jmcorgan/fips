//! Noise IK Protocol for Peer Authentication
//!
//! Implements the Noise Protocol Framework IK pattern using secp256k1
//! for link-local peer authentication. This establishes encrypted
//! channels between direct peers over a transport.
//!
//! The IK pattern assumes the initiator knows the responder's static
//! public key before the handshake. The responder learns the initiator's
//! identity from the encrypted payload in message 1.
//!
//! ## Handshake Pattern
//!
//! Pre-message (key known before handshake):
//! ```text
//!   <- s  (responder's static known to initiator)
//! ```
//!
//! Messages:
//! ```text
//!   -> e, es, s, ss    (initiator sends ephemeral + encrypted static)
//!   <- e, ee, se       (responder sends ephemeral)
//! ```
//!
//! After handshake, both parties derive symmetric keys for bidirectional
//! encrypted communication over the peer link.
//!
//! ## Separation of Concerns
//!
//! This module handles **peer authentication** only - securing the direct
//! link between neighboring nodes. End-to-end FIPS session encryption
//! between arbitrary network addresses is a separate concern handled by
//! the session layer.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use secp256k1::{ecdh::shared_secret_point, Keypair, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;
use thiserror::Error;

/// Protocol name for Noise IK with secp256k1.
/// Format: Noise_IK_secp256k1_ChaChaPoly_SHA256
const PROTOCOL_NAME: &[u8] = b"Noise_IK_secp256k1_ChaChaPoly_SHA256";

/// Maximum message size for noise transport messages.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of the AEAD tag.
pub const TAG_SIZE: usize = 16;

/// Size of a public key (compressed secp256k1).
pub const PUBKEY_SIZE: usize = 33;

/// Size of handshake message 1: ephemeral (33) + encrypted static (33 + 16 tag).
pub const HANDSHAKE_MSG1_SIZE: usize = PUBKEY_SIZE + PUBKEY_SIZE + TAG_SIZE;

/// Size of handshake message 2: ephemeral only.
pub const HANDSHAKE_MSG2_SIZE: usize = PUBKEY_SIZE;

/// Replay window size in packets (matching WireGuard).
pub const REPLAY_WINDOW_SIZE: usize = 2048;

// ============================================================================
// Replay Window
// ============================================================================

/// Sliding window for replay protection.
///
/// Tracks which packet counters have been received within a window of
/// REPLAY_WINDOW_SIZE. Packets with counters below the window or already
/// seen within the window are rejected.
///
/// Based on WireGuard's anti-replay mechanism (RFC 6479 style).
#[derive(Clone)]
pub struct ReplayWindow {
    /// Highest counter value seen.
    highest: u64,
    /// Bitmap tracking which counters in the window have been seen.
    /// Bit i corresponds to counter (highest - i).
    bitmap: [u64; REPLAY_WINDOW_SIZE / 64],
}

impl ReplayWindow {
    /// Create a new replay window.
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; REPLAY_WINDOW_SIZE / 64],
        }
    }

    /// Check if a counter is valid (not replayed, not too old).
    ///
    /// Returns true if the counter is acceptable, false if it should be rejected.
    /// Does NOT update the window - call `accept` after successful decryption.
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.highest {
            // New highest - always acceptable
            return true;
        }

        // Counter is <= highest, check if it's within the window
        let diff = self.highest - counter;
        if diff as usize >= REPLAY_WINDOW_SIZE {
            // Too old (outside window)
            return false;
        }

        // Check bitmap - bit is set if counter was already seen
        let word_idx = (diff as usize) / 64;
        let bit_idx = (diff as usize) % 64;
        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }

    /// Accept a counter into the window.
    ///
    /// Call this only after successful decryption to prevent
    /// DoS attacks that exhaust the window.
    pub fn accept(&mut self, counter: u64) {
        if counter > self.highest {
            // Shift the window
            let shift = counter - self.highest;
            if shift as usize >= REPLAY_WINDOW_SIZE {
                // Complete reset
                self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            } else {
                // Shift bitmap
                self.shift_bitmap(shift as usize);
            }
            self.highest = counter;
            // Mark counter 0 (which is now the highest) as seen
            self.bitmap[0] |= 1;
        } else {
            // Mark the counter as seen
            let diff = self.highest - counter;
            let word_idx = (diff as usize) / 64;
            let bit_idx = (diff as usize) % 64;
            self.bitmap[word_idx] |= 1u64 << bit_idx;
        }
    }

    /// Shift the bitmap by the given number of positions.
    ///
    /// This moves old counters to higher bit positions to make room for the
    /// new highest counter at position 0.
    fn shift_bitmap(&mut self, shift: usize) {
        if shift >= REPLAY_WINDOW_SIZE {
            self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            return;
        }

        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        // Shift entire words first (from high to low to avoid overwriting)
        if word_shift > 0 {
            for i in (word_shift..self.bitmap.len()).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
            for i in 0..word_shift {
                self.bitmap[i] = 0;
            }
        }

        // Shift bits within words (from low to high so carry propagates correctly)
        if bit_shift > 0 {
            let mut carry = 0u64;
            for i in 0..self.bitmap.len() {
                let new_carry = self.bitmap[i] >> (64 - bit_shift);
                self.bitmap[i] = (self.bitmap[i] << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }

    /// Get the highest counter seen.
    pub fn highest(&self) -> u64 {
        self.highest
    }

    /// Reset the window (use when rekeying).
    pub fn reset(&mut self) {
        self.highest = 0;
        self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ReplayWindow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReplayWindow")
            .field("highest", &self.highest)
            .field("window_size", &REPLAY_WINDOW_SIZE)
            .finish()
    }
}

/// Errors from Noise protocol operations.
#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("handshake not complete")]
    HandshakeNotComplete,

    #[error("handshake already complete")]
    HandshakeAlreadyComplete,

    #[error("wrong handshake state: expected {expected}, got {got}")]
    WrongState { expected: String, got: String },

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("decryption failed")]
    DecryptionFailed,

    #[error("encryption failed")]
    EncryptionFailed,

    #[error("message too large: {size} > {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("message too short: expected at least {expected}, got {got}")]
    MessageTooShort { expected: usize, got: usize },

    #[error("nonce overflow")]
    NonceOverflow,

    #[error("replay detected: counter {0} already seen or too old")]
    ReplayDetected(u64),

    #[error("secp256k1 error: {0}")]
    Secp256k1(#[from] secp256k1::Error),
}

/// Role in the handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeRole {
    /// We initiated the connection.
    Initiator,
    /// They initiated the connection.
    Responder,
}

impl fmt::Display for HandshakeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeRole::Initiator => write!(f, "initiator"),
            HandshakeRole::Responder => write!(f, "responder"),
        }
    }
}

/// Handshake state machine states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeProgress {
    /// Initial state, ready to send/receive message 1.
    Initial,
    /// Message 1 sent/received, ready for message 2.
    Message1Done,
    /// Handshake complete, ready for transport.
    Complete,
}

impl fmt::Display for HandshakeProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeProgress::Initial => write!(f, "initial"),
            HandshakeProgress::Message1Done => write!(f, "message1_done"),
            HandshakeProgress::Complete => write!(f, "complete"),
        }
    }
}

/// Symmetric cipher state for post-handshake encryption.
#[derive(Clone)]
pub struct CipherState {
    /// Encryption key (32 bytes).
    key: [u8; 32],
    /// Nonce counter (8 bytes used, 4 bytes zero prefix).
    nonce: u64,
    /// Whether this cipher has a valid key.
    has_key: bool,
}

impl CipherState {
    /// Create a new cipher state with the given key.
    fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            nonce: 0,
            has_key: true,
        }
    }

    /// Create an empty cipher state (no key yet).
    fn empty() -> Self {
        Self {
            key: [0u8; 32],
            nonce: 0,
            has_key: false,
        }
    }

    /// Initialize with a key.
    fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = key;
        self.nonce = 0;
        self.has_key = true;
    }

    /// Encrypt plaintext, returning ciphertext with appended tag.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            // No key means no encryption (shouldn't happen in transport phase)
            return Ok(plaintext.to_vec());
        }

        if plaintext.len() > MAX_MESSAGE_SIZE - TAG_SIZE {
            return Err(NoiseError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_MESSAGE_SIZE - TAG_SIZE,
            });
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| NoiseError::EncryptionFailed)?;

        let nonce = self.next_nonce()?;
        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| NoiseError::EncryptionFailed)?;

        Ok(ciphertext)
    }

    /// Decrypt ciphertext (with appended tag), returning plaintext.
    ///
    /// Uses the internal nonce counter. For transport phase with explicit
    /// counters from the wire format, use `decrypt_with_counter` instead.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            // No key means no encryption
            return Ok(ciphertext.to_vec());
        }

        if ciphertext.len() < TAG_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: TAG_SIZE,
                got: ciphertext.len(),
            });
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| NoiseError::DecryptionFailed)?;

        let nonce = self.next_nonce()?;
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| NoiseError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Decrypt with an explicit counter value (for transport phase).
    ///
    /// This is used when the counter comes from the wire format rather than
    /// an internal counter. The counter must be validated by a replay window
    /// before calling this method.
    pub fn decrypt_with_counter(
        &self,
        ciphertext: &[u8],
        counter: u64,
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            return Ok(ciphertext.to_vec());
        }

        if ciphertext.len() < TAG_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: TAG_SIZE,
                got: ciphertext.len(),
            });
        }

        let cipher = ChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| NoiseError::DecryptionFailed)?;

        let nonce = Self::counter_to_nonce(counter);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| NoiseError::DecryptionFailed)?;

        Ok(plaintext)
    }

    /// Convert a counter value to a nonce.
    fn counter_to_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    /// Get the next nonce, incrementing the counter.
    fn next_nonce(&mut self) -> Result<Nonce, NoiseError> {
        if self.nonce == u64::MAX {
            return Err(NoiseError::NonceOverflow);
        }

        let n = self.nonce;
        self.nonce += 1;

        // Noise uses 8-byte counter with 4-byte zero prefix
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&n.to_le_bytes());

        Ok(*Nonce::from_slice(&nonce_bytes))
    }

    /// Get the current nonce value (for debugging/testing).
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Check if cipher has a key.
    pub fn has_key(&self) -> bool {
        self.has_key
    }
}

impl fmt::Debug for CipherState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipherState")
            .field("nonce", &self.nonce)
            .field("has_key", &self.has_key)
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Symmetric state during handshake.
///
/// Maintains the chaining key (ck), handshake hash (h), and current cipher.
struct SymmetricState {
    /// Chaining key for key derivation.
    ck: [u8; 32],
    /// Handshake hash for transcript binding.
    h: [u8; 32],
    /// Current cipher state for encrypting handshake payloads.
    cipher: CipherState,
}

impl SymmetricState {
    /// Initialize with protocol name.
    fn initialize() -> Self {
        // If protocol name <= 32 bytes, pad with zeros
        // If > 32 bytes, hash it
        let h = if PROTOCOL_NAME.len() <= 32 {
            let mut h = [0u8; 32];
            h[..PROTOCOL_NAME.len()].copy_from_slice(PROTOCOL_NAME);
            h
        } else {
            let mut hasher = Sha256::new();
            hasher.update(PROTOCOL_NAME);
            hasher.finalize().into()
        };

        Self {
            ck: h,
            h,
            cipher: CipherState::empty(),
        }
    }

    /// Mix data into the handshake hash.
    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(&self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// Mix key material into the chaining key.
    fn mix_key(&mut self, input_key_material: &[u8]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), input_key_material);
        let mut output = [0u8; 64];
        hk.expand(&[], &mut output)
            .expect("64 bytes is valid output length");

        self.ck.copy_from_slice(&output[..32]);

        // Initialize cipher with derived key for handshake encryption
        let mut key = [0u8; 32];
        key.copy_from_slice(&output[32..64]);
        self.cipher.initialize_key(key);
    }

    /// Encrypt and mix into hash.
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let ciphertext = self.cipher.encrypt(plaintext)?;
        self.mix_hash(&ciphertext);
        Ok(ciphertext)
    }

    /// Decrypt and mix ciphertext into hash.
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, NoiseError> {
        let plaintext = self.cipher.decrypt(ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(plaintext)
    }

    /// Split into two cipher states for transport.
    fn split(&self) -> (CipherState, CipherState) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut output = [0u8; 64];
        hk.expand(&[], &mut output)
            .expect("64 bytes is valid output length");

        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&output[..32]);
        k2.copy_from_slice(&output[32..64]);

        (CipherState::new(k1), CipherState::new(k2))
    }

    /// Get the handshake hash (for channel binding).
    fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }
}

/// Handshake state for Noise IK.
pub struct HandshakeState {
    /// Our role in the handshake.
    role: HandshakeRole,
    /// Current progress.
    progress: HandshakeProgress,
    /// Symmetric state.
    symmetric: SymmetricState,
    /// Our static keypair.
    static_keypair: Keypair,
    /// Our ephemeral keypair (generated at handshake start).
    ephemeral_keypair: Option<Keypair>,
    /// Remote static public key.
    /// For initiator: known before handshake (from config).
    /// For responder: learned from message 1.
    remote_static: Option<PublicKey>,
    /// Remote ephemeral public key (learned during handshake).
    remote_ephemeral: Option<PublicKey>,
    /// Secp256k1 context.
    secp: Secp256k1<secp256k1::All>,
}

impl HandshakeState {
    /// Normalize a compressed public key to even parity for pre-message hashing.
    ///
    /// Nostr npubs encode x-only keys (no parity). The Noise IK pre-message
    /// mixes the responder's static key into the hash before any messages.
    /// Both sides must mix identical bytes. Since the initiator may only have
    /// the x-only key (from an npub), we normalize to even parity (0x02 prefix)
    /// so the hash chain matches regardless of the key's actual parity.
    ///
    /// This does NOT affect ECDH operations (which use x-coordinate-only output)
    /// or the keys sent in handshake messages (which use actual parity).
    fn normalize_for_premessage(pubkey: &PublicKey) -> [u8; PUBKEY_SIZE] {
        let mut bytes = pubkey.serialize();
        bytes[0] = 0x02; // Force even parity
        bytes
    }

    /// Create a new handshake as initiator.
    ///
    /// The initiator knows the responder's static key and will send first.
    pub fn new_initiator(static_keypair: Keypair, remote_static: PublicKey) -> Self {
        let secp = Secp256k1::new();
        let mut state = Self {
            role: HandshakeRole::Initiator,
            progress: HandshakeProgress::Initial,
            symmetric: SymmetricState::initialize(),
            static_keypair,
            ephemeral_keypair: None,
            remote_static: Some(remote_static),
            remote_ephemeral: None,
            secp,
        };

        // Mix in pre-message: <- s (responder's static is known)
        // Normalize to even parity so initiator and responder hash chains match
        // even when the initiator only has the x-only key (from npub).
        let normalized = Self::normalize_for_premessage(&remote_static);
        state.symmetric.mix_hash(&normalized);

        state
    }

    /// Create a new handshake as responder.
    ///
    /// The responder does NOT know the initiator's static key - it will be
    /// learned from message 1.
    pub fn new_responder(static_keypair: Keypair) -> Self {
        let secp = Secp256k1::new();
        let mut state = Self {
            role: HandshakeRole::Responder,
            progress: HandshakeProgress::Initial,
            symmetric: SymmetricState::initialize(),
            static_keypair,
            ephemeral_keypair: None,
            remote_static: None, // Will learn from message 1
            remote_ephemeral: None,
            secp,
        };

        // Mix in pre-message: <- s (our static, since we're responder)
        // Normalize to even parity to match initiator's hash chain.
        let normalized = Self::normalize_for_premessage(&state.static_keypair.public_key());
        state.symmetric.mix_hash(&normalized);

        state
    }

    /// Get our role.
    pub fn role(&self) -> HandshakeRole {
        self.role
    }

    /// Get current progress.
    pub fn progress(&self) -> HandshakeProgress {
        self.progress
    }

    /// Check if handshake is complete.
    pub fn is_complete(&self) -> bool {
        self.progress == HandshakeProgress::Complete
    }

    /// Get the remote static key (available after message 1 for responder).
    pub fn remote_static(&self) -> Option<&PublicKey> {
        self.remote_static.as_ref()
    }

    /// Generate ephemeral keypair.
    fn generate_ephemeral(&mut self) {
        let mut rng = rand::thread_rng();
        let mut secret_bytes = [0u8; 32];
        rng.fill_bytes(&mut secret_bytes);

        let secret_key =
            SecretKey::from_slice(&secret_bytes).expect("32 random bytes is valid secret key");
        self.ephemeral_keypair = Some(Keypair::from_secret_key(&self.secp, &secret_key));
    }

    /// Perform ECDH between our secret and their public key.
    ///
    /// Uses x-only hashing (SHA-256 of just the x-coordinate) to produce
    /// a parity-independent shared secret. This is necessary because Nostr
    /// npubs encode x-only keys without parity information, so the initiator
    /// may have the wrong parity for the responder's static key. Since P and
    /// -P produce ECDH result points with the same x-coordinate, hashing
    /// only x ensures both sides derive the same shared secret.
    fn ecdh(&self, our_secret: &SecretKey, their_public: &PublicKey) -> [u8; 32] {
        // Get raw (x, y) coordinates (64 bytes) without any hashing
        let point = shared_secret_point(their_public, our_secret);
        // Hash only the x-coordinate (first 32 bytes), ignoring y/parity
        let mut hasher = Sha256::new();
        hasher.update(&point[..32]);
        let hash = hasher.finalize();
        let mut result = [0u8; 32];
        result.copy_from_slice(&hash);
        result
    }

    /// Write message 1 (initiator only).
    ///
    /// Message 1 contains:
    /// - e: ephemeral public key (33 bytes)
    /// - encrypted s: our static public key encrypted (33 + 16 = 49 bytes)
    ///
    /// Total: 82 bytes
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.role != HandshakeRole::Initiator {
            return Err(NoiseError::WrongState {
                expected: "initiator".to_string(),
                got: "responder".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Initial {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Initial.to_string(),
                got: self.progress.to_string(),
            });
        }

        let remote_static = self.remote_static.expect("initiator must have remote static");

        // Generate ephemeral keypair
        self.generate_ephemeral();
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let e_pub = ephemeral.public_key().serialize();

        let mut message = Vec::with_capacity(HANDSHAKE_MSG1_SIZE);

        // -> e: send ephemeral, mix into hash
        message.extend_from_slice(&e_pub);
        self.symmetric.mix_hash(&e_pub);

        // -> es: DH(e, rs), mix into key
        let es = self.ecdh(&ephemeral.secret_key(), &remote_static);
        self.symmetric.mix_key(&es);

        // -> s: encrypt our static and send
        let our_static = self.static_keypair.public_key().serialize();
        let encrypted_static = self.symmetric.encrypt_and_hash(&our_static)?;
        message.extend_from_slice(&encrypted_static);

        // -> ss: DH(s, rs), mix into key
        let ss = self.ecdh(&self.static_keypair.secret_key(), &remote_static);
        self.symmetric.mix_key(&ss);

        self.progress = HandshakeProgress::Message1Done;

        Ok(message)
    }

    /// Read message 1 (responder only).
    ///
    /// Processes the initiator's first message and learns their identity.
    pub fn read_message_1(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        if self.role != HandshakeRole::Responder {
            return Err(NoiseError::WrongState {
                expected: "responder".to_string(),
                got: "initiator".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Initial {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Initial.to_string(),
                got: self.progress.to_string(),
            });
        }
        if message.len() != HANDSHAKE_MSG1_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: HANDSHAKE_MSG1_SIZE,
                got: message.len(),
            });
        }

        // -> e: parse remote ephemeral, mix into hash
        let re = PublicKey::from_slice(&message[..PUBKEY_SIZE])
            .map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_ephemeral = Some(re);
        self.symmetric.mix_hash(&message[..PUBKEY_SIZE]);

        // -> es: DH(s, re), mix into key
        // (responder uses their static with initiator's ephemeral)
        let es = self.ecdh(&self.static_keypair.secret_key(), &re);
        self.symmetric.mix_key(&es);

        // -> s: decrypt initiator's static
        let encrypted_static = &message[PUBKEY_SIZE..];
        let decrypted_static = self.symmetric.decrypt_and_hash(encrypted_static)?;
        let rs =
            PublicKey::from_slice(&decrypted_static).map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_static = Some(rs);

        // -> ss: DH(s, rs), mix into key
        let ss = self.ecdh(&self.static_keypair.secret_key(), &rs);
        self.symmetric.mix_key(&ss);

        self.progress = HandshakeProgress::Message1Done;

        Ok(())
    }

    /// Write message 2 (responder only).
    ///
    /// Message 2 contains:
    /// - e: ephemeral public key (33 bytes)
    ///
    /// Total: 33 bytes
    pub fn write_message_2(&mut self) -> Result<Vec<u8>, NoiseError> {
        if self.role != HandshakeRole::Responder {
            return Err(NoiseError::WrongState {
                expected: "responder".to_string(),
                got: "initiator".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Message1Done {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Message1Done.to_string(),
                got: self.progress.to_string(),
            });
        }

        let re = self.remote_ephemeral.expect("should have remote ephemeral");

        // Generate ephemeral keypair
        self.generate_ephemeral();
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let e_pub = ephemeral.public_key().serialize();

        // <- e: send ephemeral, mix into hash
        self.symmetric.mix_hash(&e_pub);

        // <- ee: DH(e, re), mix into key
        let ee = self.ecdh(&ephemeral.secret_key(), &re);
        self.symmetric.mix_key(&ee);

        // <- se: DH(s, re), mix into key
        let se = self.ecdh(&self.static_keypair.secret_key(), &re);
        self.symmetric.mix_key(&se);

        self.progress = HandshakeProgress::Complete;

        Ok(e_pub.to_vec())
    }

    /// Read message 2 (initiator only).
    ///
    /// Processes the responder's message and completes the handshake.
    pub fn read_message_2(&mut self, message: &[u8]) -> Result<(), NoiseError> {
        if self.role != HandshakeRole::Initiator {
            return Err(NoiseError::WrongState {
                expected: "initiator".to_string(),
                got: "responder".to_string(),
            });
        }
        if self.progress != HandshakeProgress::Message1Done {
            return Err(NoiseError::WrongState {
                expected: HandshakeProgress::Message1Done.to_string(),
                got: self.progress.to_string(),
            });
        }
        if message.len() != HANDSHAKE_MSG2_SIZE {
            return Err(NoiseError::MessageTooShort {
                expected: HANDSHAKE_MSG2_SIZE,
                got: message.len(),
            });
        }

        // <- e: parse remote ephemeral, mix into hash
        let re = PublicKey::from_slice(message).map_err(|_| NoiseError::InvalidPublicKey)?;
        self.remote_ephemeral = Some(re);
        self.symmetric.mix_hash(message);

        // <- ee: DH(e, re), mix into key
        let ephemeral = self.ephemeral_keypair.as_ref().unwrap();
        let ee = self.ecdh(&ephemeral.secret_key(), &re);
        self.symmetric.mix_key(&ee);

        // <- se: DH(e, rs), mix into key
        // (initiator uses their ephemeral with responder's static)
        let rs = self.remote_static.expect("initiator has remote static");
        let se = self.ecdh(&ephemeral.secret_key(), &rs);
        self.symmetric.mix_key(&se);

        self.progress = HandshakeProgress::Complete;

        Ok(())
    }

    /// Complete the handshake and return a NoiseSession.
    ///
    /// Must be called after the handshake is complete.
    pub fn into_session(self) -> Result<NoiseSession, NoiseError> {
        if !self.is_complete() {
            return Err(NoiseError::HandshakeNotComplete);
        }

        let (c1, c2) = self.symmetric.split();
        let handshake_hash = self.symmetric.handshake_hash();
        let remote_static = self
            .remote_static
            .expect("remote static must be known after handshake");

        // Initiator sends with c1, receives with c2
        // Responder sends with c2, receives with c1
        let (send_cipher, recv_cipher) = match self.role {
            HandshakeRole::Initiator => (c1, c2),
            HandshakeRole::Responder => (c2, c1),
        };

        Ok(NoiseSession {
            role: self.role,
            send_cipher,
            recv_cipher,
            handshake_hash,
            remote_static,
            replay_window: ReplayWindow::new(),
        })
    }

    /// Get the handshake hash (for channel binding, available after complete).
    pub fn handshake_hash(&self) -> [u8; 32] {
        self.symmetric.handshake_hash()
    }
}

impl fmt::Debug for HandshakeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HandshakeState")
            .field("role", &self.role)
            .field("progress", &self.progress)
            .field("has_ephemeral", &self.ephemeral_keypair.is_some())
            .field("has_remote_static", &self.remote_static.is_some())
            .field("has_remote_ephemeral", &self.remote_ephemeral.is_some())
            .finish()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::Parity;

    fn generate_keypair() -> Keypair {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (secret_key, _) = secp.generate_keypair(&mut rng);
        Keypair::from_secret_key(&secp, &secret_key)
    }

    #[test]
    fn test_full_handshake() {
        let initiator_keypair = generate_keypair();
        let responder_keypair = generate_keypair();

        let responder_pub = responder_keypair.public_key();

        // Initiator knows responder's static key
        // Responder does NOT know initiator's static key (IK pattern)
        let mut initiator = HandshakeState::new_initiator(initiator_keypair.clone(), responder_pub);
        let mut responder = HandshakeState::new_responder(responder_keypair);

        assert_eq!(initiator.role(), HandshakeRole::Initiator);
        assert_eq!(responder.role(), HandshakeRole::Responder);

        // Initially, responder doesn't know initiator's identity
        assert!(responder.remote_static().is_none());

        // Message 1: Initiator -> Responder
        let msg1 = initiator.write_message_1().unwrap();
        assert_eq!(msg1.len(), HANDSHAKE_MSG1_SIZE);

        responder.read_message_1(&msg1).unwrap();

        // Now responder knows initiator's identity!
        assert!(responder.remote_static().is_some());
        assert_eq!(
            responder.remote_static().unwrap(),
            &initiator_keypair.public_key()
        );

        // Message 2: Responder -> Initiator
        let msg2 = responder.write_message_2().unwrap();
        assert_eq!(msg2.len(), HANDSHAKE_MSG2_SIZE);

        initiator.read_message_2(&msg2).unwrap();

        // Both should be complete
        assert!(initiator.is_complete());
        assert!(responder.is_complete());

        // Handshake hashes should match
        assert_eq!(initiator.handshake_hash(), responder.handshake_hash());

        // Convert to sessions
        let mut initiator_session = initiator.into_session().unwrap();
        let mut responder_session = responder.into_session().unwrap();

        // Test encryption/decryption
        let plaintext = b"Hello, secure world!";

        let ciphertext = initiator_session.encrypt(plaintext).unwrap();
        let decrypted = responder_session.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);

        // Test reverse direction
        let plaintext2 = b"Hello back!";
        let ciphertext2 = responder_session.encrypt(plaintext2).unwrap();
        let decrypted2 = initiator_session.decrypt(&ciphertext2).unwrap();
        assert_eq!(decrypted2, plaintext2);
    }

    #[test]
    fn test_multiple_messages() {
        let initiator_keypair = generate_keypair();
        let responder_keypair = generate_keypair();

        let mut initiator =
            HandshakeState::new_initiator(initiator_keypair, responder_keypair.public_key());
        let mut responder = HandshakeState::new_responder(responder_keypair);

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();
        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();

        let mut initiator_session = initiator.into_session().unwrap();
        let mut responder_session = responder.into_session().unwrap();

        // Send many messages to test nonce increment
        for i in 0..100 {
            let msg = format!("Message {}", i);
            let ct = initiator_session.encrypt(msg.as_bytes()).unwrap();
            let pt = responder_session.decrypt(&ct).unwrap();
            assert_eq!(pt, msg.as_bytes());
        }

        assert_eq!(initiator_session.send_nonce(), 100);
        assert_eq!(responder_session.recv_nonce(), 100);
    }

    #[test]
    fn test_wrong_role_errors() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        let mut initiator = HandshakeState::new_initiator(keypair1, keypair2.public_key());

        // Initiator can't read message 1
        assert!(initiator
            .read_message_1(&[0u8; HANDSHAKE_MSG1_SIZE])
            .is_err());

        // Initiator can't write message 2 before message 1
        assert!(initiator.write_message_2().is_err());
    }

    #[test]
    fn test_invalid_pubkey_in_msg1() {
        let keypair = generate_keypair();
        let mut responder = HandshakeState::new_responder(keypair);

        // Invalid pubkey bytes (first 33 bytes are zero)
        let invalid_msg = [0u8; HANDSHAKE_MSG1_SIZE];
        assert!(responder.read_message_1(&invalid_msg).is_err());
    }

    #[test]
    fn test_decryption_failure_wrong_key() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();
        let keypair3 = generate_keypair();

        // Session between 1 and 2
        let mut init1 = HandshakeState::new_initiator(keypair1.clone(), keypair2.public_key());
        let mut resp1 = HandshakeState::new_responder(keypair2.clone());

        let msg1 = init1.write_message_1().unwrap();
        resp1.read_message_1(&msg1).unwrap();
        let msg2 = resp1.write_message_2().unwrap();
        init1.read_message_2(&msg2).unwrap();

        let mut session1 = init1.into_session().unwrap();

        // Session between 1 and 3
        let mut init2 = HandshakeState::new_initiator(keypair1.clone(), keypair3.public_key());
        let mut resp2 = HandshakeState::new_responder(keypair3);

        let msg1 = init2.write_message_1().unwrap();
        resp2.read_message_1(&msg1).unwrap();
        let msg2 = resp2.write_message_2().unwrap();
        init2.read_message_2(&msg2).unwrap();

        let mut session2 = resp2.into_session().unwrap();

        // Encrypt with session 1, try to decrypt with session 2
        let ciphertext = session1.encrypt(b"test").unwrap();
        assert!(session2.decrypt(&ciphertext).is_err());
    }

    #[test]
    fn test_cipher_state_nonce_sequence() {
        let key = [0u8; 32];
        let mut cipher = CipherState::new(key);

        assert_eq!(cipher.nonce(), 0);

        let _ = cipher.encrypt(b"test").unwrap();
        assert_eq!(cipher.nonce(), 1);

        let _ = cipher.encrypt(b"test").unwrap();
        assert_eq!(cipher.nonce(), 2);
    }

    #[test]
    fn test_session_remote_static() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        let mut init = HandshakeState::new_initiator(keypair1.clone(), keypair2.public_key());
        let mut resp = HandshakeState::new_responder(keypair2.clone());

        let msg1 = init.write_message_1().unwrap();
        resp.read_message_1(&msg1).unwrap();
        let msg2 = resp.write_message_2().unwrap();
        init.read_message_2(&msg2).unwrap();

        let session1 = init.into_session().unwrap();
        let session2 = resp.into_session().unwrap();

        // Each session should know the other's static key
        assert_eq!(session1.remote_static(), &keypair2.public_key());
        assert_eq!(session2.remote_static(), &keypair1.public_key());
    }

    #[test]
    fn test_message_sizes() {
        // Verify our size constants are correct
        assert_eq!(HANDSHAKE_MSG1_SIZE, 33 + 33 + 16); // e + encrypted_s
        assert_eq!(HANDSHAKE_MSG2_SIZE, 33); // e only
    }

    #[test]
    fn test_responder_identity_discovery() {
        // This test verifies the key IK property: responder learns initiator's identity
        let initiator_keypair = generate_keypair();
        let responder_keypair = generate_keypair();

        let mut responder = HandshakeState::new_responder(responder_keypair);

        // Before message 1: responder has no idea who's connecting
        assert!(responder.remote_static().is_none());

        let mut initiator =
            HandshakeState::new_initiator(initiator_keypair.clone(), responder.static_keypair.public_key());
        let msg1 = initiator.write_message_1().unwrap();

        // After processing message 1: responder knows initiator's identity
        responder.read_message_1(&msg1).unwrap();
        let discovered_initiator = responder.remote_static().unwrap();
        assert_eq!(discovered_initiator, &initiator_keypair.public_key());

        // The discovered key can be used to look up peer config, verify against allow-list, etc.
    }

    // ===== ReplayWindow Tests =====

    #[test]
    fn test_replay_window_basic() {
        let mut window = ReplayWindow::new();

        // First packet is always acceptable
        assert!(window.check(0));
        window.accept(0);
        assert_eq!(window.highest(), 0);

        // Replay of 0 should fail
        assert!(!window.check(0));

        // New higher counter is acceptable
        assert!(window.check(1));
        window.accept(1);
        assert_eq!(window.highest(), 1);

        // Out-of-order within window is acceptable
        // (after accepting 10, 2 is still in window)
        window.accept(10);
        assert!(window.check(5));
        window.accept(5);

        // Replay of 5 should now fail
        assert!(!window.check(5));
    }

    #[test]
    fn test_replay_window_large_jump() {
        let mut window = ReplayWindow::new();

        // Accept counter 0
        window.accept(0);

        // Jump to a large counter
        window.accept(REPLAY_WINDOW_SIZE as u64 + 100);

        // Old counter should be outside window
        assert!(!window.check(0));
        assert!(!window.check(50));

        // Counters within window should work
        assert!(window.check(REPLAY_WINDOW_SIZE as u64 + 99));
        assert!(window.check(REPLAY_WINDOW_SIZE as u64 + 50));
    }

    #[test]
    fn test_replay_window_boundary() {
        let mut window = ReplayWindow::new();

        // Accept at boundary
        window.accept(REPLAY_WINDOW_SIZE as u64 - 1);

        // Counter 0 should be exactly at the edge of the window
        assert!(window.check(0));
        window.accept(0);

        // Move window forward by 1
        window.accept(REPLAY_WINDOW_SIZE as u64);

        // Counter 0 is now outside the window
        assert!(!window.check(0));

        // Counter 1 is still in the window
        assert!(window.check(1));
    }

    #[test]
    fn test_replay_window_sequential() {
        let mut window = ReplayWindow::new();

        // Accept counters 0-999 in order
        for i in 0..1000 {
            assert!(window.check(i), "Counter {} should be acceptable", i);
            window.accept(i);
        }

        // All should be marked as seen
        for i in 0..1000 {
            assert!(!window.check(i), "Counter {} should be rejected as replay", i);
        }

        assert_eq!(window.highest(), 999);
    }

    #[test]
    fn test_replay_window_reset() {
        let mut window = ReplayWindow::new();

        window.accept(100);
        assert_eq!(window.highest(), 100);
        assert!(!window.check(100));

        window.reset();

        assert_eq!(window.highest(), 0);
        assert!(window.check(100));
    }

    #[test]
    fn test_session_replay_protection() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        let mut init = HandshakeState::new_initiator(keypair1, keypair2.public_key());
        let mut resp = HandshakeState::new_responder(keypair2);

        let msg1 = init.write_message_1().unwrap();
        resp.read_message_1(&msg1).unwrap();
        let msg2 = resp.write_message_2().unwrap();
        init.read_message_2(&msg2).unwrap();

        let mut sender = init.into_session().unwrap();
        let mut receiver = resp.into_session().unwrap();

        // Encrypt a message
        let counter = sender.current_send_counter();
        let ciphertext = sender.encrypt(b"test message").unwrap();

        // First decryption should succeed
        let plaintext = receiver
            .decrypt_with_replay_check(&ciphertext, counter)
            .unwrap();
        assert_eq!(plaintext, b"test message");

        // Replay should fail
        let result = receiver.decrypt_with_replay_check(&ciphertext, counter);
        assert!(matches!(result, Err(NoiseError::ReplayDetected(_))));

        // Check method alone also detects replay
        assert!(receiver.check_replay(counter).is_err());
    }

    #[test]
    fn test_handshake_with_odd_parity_responder() {
        // Node B's secret key produces an odd-parity public key (0x03 prefix).
        // When the initiator only has the npub (x-only), PeerIdentity::pubkey_full()
        // returns even parity (0x02). The pre-message mix_hash must normalize
        // parity so both sides produce matching hash chains.
        let secp = Secp256k1::new();

        // Node B (responder) - odd parity key
        let sk_b = SecretKey::from_slice(
            &hex::decode("b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0")
                .unwrap(),
        )
        .unwrap();
        let kp_b = Keypair::from_secret_key(&secp, &sk_b);
        let (xonly_b, parity_b) = kp_b.public_key().x_only_public_key();
        assert_eq!(parity_b, Parity::Odd, "Test requires odd-parity responder key");

        // Node A (initiator) - even parity key
        let sk_a = SecretKey::from_slice(
            &hex::decode("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .unwrap(),
        )
        .unwrap();
        let kp_a = Keypair::from_secret_key(&secp, &sk_a);

        // Simulate the production path: initiator gets responder's key via npub
        // (x-only → assumed even parity)
        let assumed_even_b = xonly_b.public_key(Parity::Even);
        assert_ne!(
            assumed_even_b, kp_b.public_key(),
            "Even assumption should differ from actual odd key"
        );

        // Handshake using assumed-even key (as production code does)
        let mut initiator = HandshakeState::new_initiator(kp_a, assumed_even_b);
        let mut responder = HandshakeState::new_responder(kp_b);

        let msg1 = initiator.write_message_1().unwrap();
        responder.read_message_1(&msg1).unwrap();

        let msg2 = responder.write_message_2().unwrap();
        initiator.read_message_2(&msg2).unwrap();

        assert!(initiator.is_complete());
        assert!(responder.is_complete());

        // Verify sessions can communicate
        let mut sender = initiator.into_session().unwrap();
        let mut receiver = responder.into_session().unwrap();

        let counter = sender.current_send_counter();
        let ciphertext = sender.encrypt(b"parity test").unwrap();
        let plaintext = receiver
            .decrypt_with_replay_check(&ciphertext, counter)
            .unwrap();
        assert_eq!(plaintext, b"parity test");
    }
}
