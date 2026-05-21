//! Noise Protocol Implementation for FIPS
//!
//! Implements the Noise XX pattern using secp256k1 for both link-layer and
//! session-layer encryption. Neither side knows the other's static key before
//! the handshake. Both identities are revealed during the handshake: responder
//! in msg2, initiator in msg3. Three-message handshake.
//!
//! ## XX Handshake Pattern
//!
//! ```text
//!   -> e                    (msg1: ephemeral only, no DH)
//!   <- e, ee, s, es         (msg2: ephemeral + encrypted static)
//!   -> s, se                (msg3: encrypted static)
//! ```
//!
//! The XX pattern handles both **link-layer peer authentication** (securing the
//! direct link between neighboring nodes) and **session-layer end-to-end
//! encryption** between arbitrary network addresses.
//!
//! ## Identity Timing
//!
//! Unlike IK (where the initiator's identity was in msg1), XX defers all
//! identity disclosure:
//!
//! - **msg1**: Ephemeral only. No identity, no DH with static keys.
//! - **msg2**: Responder reveals its static key to the initiator.
//! - **msg3**: Initiator reveals its static key to the responder.
//!
//! Consequence: all identity-based checks that previously ran during msg1
//! processing (restart detection, rekey detection, allow/deny lists,
//! cross-connection resolution) are now deferred:
//!
//! - **Initiator** performs identity checks in `handle_msg2` after
//!   decrypting the responder's static key.
//! - **Responder** performs identity checks in `handle_msg3` after
//!   decrypting the initiator's static key.
//! - **msg1 handler** can only do address-based duplicate detection (same
//!   transport + address). Identity-dependent decisions happen later.

mod handshake;
mod replay;
mod session;

use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
use std::fmt;
use thiserror::Error;

pub use handshake::HandshakeState;
pub use replay::ReplayWindow;
pub use session::NoiseSession;

/// Protocol name for Noise XX with secp256k1.
/// Format: Noise_XX_secp256k1_ChaChaPoly_SHA256
pub(crate) const PROTOCOL_NAME_XX: &[u8] = b"Noise_XX_secp256k1_ChaChaPoly_SHA256";

/// Maximum message size for noise transport messages.
pub const MAX_MESSAGE_SIZE: usize = 65535;

/// Size of the AEAD tag.
pub const TAG_SIZE: usize = 16;

/// Size of a public key (compressed secp256k1).
pub const PUBKEY_SIZE: usize = 33;

/// Size of the startup epoch (random bytes for restart detection).
pub const EPOCH_SIZE: usize = 8;

/// Size of encrypted epoch (epoch + AEAD tag).
pub const EPOCH_ENCRYPTED_SIZE: usize = EPOCH_SIZE + TAG_SIZE;

/// Handshake msg1: ephemeral only (33 bytes). No DH, no encryption.
pub const HANDSHAKE_MSG1_SIZE: usize = PUBKEY_SIZE;

/// Handshake msg2: ephemeral (33) + encrypted static (33 + 16 tag) + encrypted epoch (8 + 16 tag) = 106 bytes.
pub const HANDSHAKE_MSG2_SIZE: usize = PUBKEY_SIZE + PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE;

/// Handshake msg3: encrypted static (33 + 16 tag) + encrypted epoch (8 + 16 tag) = 73 bytes.
pub const HANDSHAKE_MSG3_SIZE: usize = PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE;

/// Replay window size in packets (matching WireGuard).
pub const REPLAY_WINDOW_SIZE: usize = 2048;

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

/// Which Noise pattern is being used for this handshake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoisePattern {
    /// Noise XX: three-message handshake, no prior key knowledge.
    Xx,
}

/// Handshake state machine states.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandshakeProgress {
    /// Initial state, ready to send/receive message 1.
    Initial,
    /// Message 1 sent/received, ready for message 2.
    Message1Done,
    /// Message 2 sent/received, ready for message 3.
    Message2Done,
    /// Handshake complete, ready for transport.
    Complete,
}

impl fmt::Display for HandshakeProgress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HandshakeProgress::Initial => write!(f, "initial"),
            HandshakeProgress::Message1Done => write!(f, "message1_done"),
            HandshakeProgress::Message2Done => write!(f, "message2_done"),
            HandshakeProgress::Complete => write!(f, "complete"),
        }
    }
}

/// Symmetric cipher state for post-handshake encryption.
///
/// AEAD is `ring`'s ChaCha20-Poly1305 (BoringSSL backend), which dispatches
/// to NEON on aarch64 and AVX2/AVX-512 on x86_64. The 32-byte key is
/// retained alongside a cached `LessSafeKey` so the per-packet AEAD skips
/// the keyed-cipher construction (key copy + Poly1305 key derivation).
/// `LessSafeKey` itself doesn't implement `Clone` (deliberate, for safety),
/// so `CipherState`'s manual `Clone` impl rebuilds the keyed AEAD from the
/// retained key bytes — cheap for ChaCha20-Poly1305 since the construction
/// is essentially a key copy plus a constant-time check.
pub struct CipherState {
    /// Encryption key (32 bytes). Retained so we can rebuild the keyed
    /// AEAD on `Clone` and on `initialize_key` (ring's `UnboundKey` /
    /// `LessSafeKey` do not implement `Clone`).
    key: [u8; 32],
    /// Cached keyed AEAD, valid iff `has_key`. None for an un-keyed state.
    cipher: Option<LessSafeKey>,
    /// Nonce counter (8 bytes used, 4 bytes zero prefix).
    pub(super) nonce: u64,
    /// Whether this cipher has a valid key.
    has_key: bool,
}

impl Clone for CipherState {
    fn clone(&self) -> Self {
        let cipher = if self.has_key {
            Self::build_cipher(&self.key)
        } else {
            None
        };
        Self {
            key: self.key,
            cipher,
            nonce: self.nonce,
            has_key: self.has_key,
        }
    }
}

impl CipherState {
    /// Create a new cipher state with the given key.
    pub(crate) fn new(key: [u8; 32]) -> Self {
        let cipher = Self::build_cipher(&key);
        Self {
            key,
            cipher,
            nonce: 0,
            has_key: true,
        }
    }

    /// Create an empty cipher state (no key yet).
    pub(super) fn empty() -> Self {
        Self {
            key: [0u8; 32],
            cipher: None,
            nonce: 0,
            has_key: false,
        }
    }

    /// Initialize with a key.
    pub(super) fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = key;
        self.cipher = Self::build_cipher(&key);
        self.nonce = 0;
        self.has_key = true;
    }

    /// Build a ring `LessSafeKey` from raw key bytes. Centralized so the
    /// cipher-cache rebuild paths (`new`, `initialize_key`, `Clone`) all
    /// agree on construction.
    fn build_cipher(key: &[u8; 32]) -> Option<LessSafeKey> {
        UnboundKey::new(&CHACHA20_POLY1305, key)
            .ok()
            .map(LessSafeKey::new)
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

        let counter = self.advance_nonce()?;
        seal(self.cipher.as_ref(), counter, &[], plaintext)
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

        let counter = self.advance_nonce()?;
        open(self.cipher.as_ref(), counter, &[], ciphertext)
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

        open(self.cipher.as_ref(), counter, &[], ciphertext)
    }

    /// Encrypt plaintext with Additional Authenticated Data (AAD).
    ///
    /// The AAD is authenticated but not encrypted. Used for the FMP
    /// established frame format where the 16-byte outer header is
    /// bound to the AEAD tag.
    pub fn encrypt_with_aad(
        &mut self,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, NoiseError> {
        if !self.has_key {
            return Ok(plaintext.to_vec());
        }

        if plaintext.len() > MAX_MESSAGE_SIZE - TAG_SIZE {
            return Err(NoiseError::MessageTooLarge {
                size: plaintext.len(),
                max: MAX_MESSAGE_SIZE - TAG_SIZE,
            });
        }

        let counter = self.advance_nonce()?;
        seal(self.cipher.as_ref(), counter, aad, plaintext)
    }

    /// Decrypt with an explicit counter and AAD (for transport phase).
    ///
    /// Combines explicit counter (from wire format) with AAD verification.
    /// The AAD must match exactly what was used during encryption or the
    /// AEAD tag verification will fail.
    pub fn decrypt_with_counter_and_aad(
        &self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
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

        open(self.cipher.as_ref(), counter, aad, ciphertext)
    }

    /// Build a ring `Nonce` from a counter value (8-byte LE counter, with
    /// 4-byte zero prefix to match the Noise/WireGuard wire format).
    fn counter_to_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        Nonce::assume_unique_for_key(nonce_bytes)
    }

    /// Reserve and return the next nonce, advancing the internal counter.
    fn advance_nonce(&mut self) -> Result<u64, NoiseError> {
        if self.nonce == u64::MAX {
            return Err(NoiseError::NonceOverflow);
        }
        let n = self.nonce;
        self.nonce += 1;
        Ok(n)
    }

    /// Get the current nonce value (for debugging/testing).
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// Check if cipher has a key.
    pub fn has_key(&self) -> bool {
        self.has_key
    }

    /// Clone the underlying keyed AEAD, for off-task AEAD workers.
    ///
    /// Returns `None` if no key. The cloned `LessSafeKey` pairs with
    /// `decrypt_with_counter[_and_aad]` / `encrypt_with_counter[_and_aad]`
    /// or with bare `ring::aead::LessSafeKey::seal_in_place_separate_tag` —
    /// the worker holds the cipher and a pre-assigned counter, while the
    /// dispatcher keeps the replay window and counter assignment sequential.
    pub fn cipher_clone(&self) -> Option<LessSafeKey> {
        if self.has_key {
            Self::build_cipher(&self.key)
        } else {
            None
        }
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

/// Encrypt `plaintext` with the given keyed AEAD, counter, and AAD,
/// returning a `Vec<u8>` of `plaintext.len() + TAG_SIZE` bytes. ring's
/// `seal_in_place_append_tag` works on a single buffer; we own it here
/// to keep the public Vec-returning API of `CipherState`.
fn seal(
    cipher: Option<&LessSafeKey>,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    let cipher = cipher.ok_or(NoiseError::EncryptionFailed)?;
    let mut buf = Vec::with_capacity(plaintext.len() + TAG_SIZE);
    buf.extend_from_slice(plaintext);
    let nonce = CipherState::counter_to_nonce(counter);
    cipher
        .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| NoiseError::EncryptionFailed)?;
    Ok(buf)
}

/// Decrypt `ciphertext` (with appended tag) with the given keyed AEAD,
/// counter, and AAD, returning the plaintext as a `Vec<u8>`. Truncates
/// in place to drop the AEAD tag.
pub(crate) fn open(
    cipher: Option<&LessSafeKey>,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    let cipher = cipher.ok_or(NoiseError::DecryptionFailed)?;
    let mut buf = ciphertext.to_vec();
    let nonce = CipherState::counter_to_nonce(counter);
    let plaintext_len = cipher
        .open_in_place(nonce, Aad::from(aad), &mut buf)
        .map_err(|_| NoiseError::DecryptionFailed)?
        .len();
    buf.truncate(plaintext_len);
    Ok(buf)
}

#[cfg(test)]
mod tests;
