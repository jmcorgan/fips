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

use super::aead::{self, Aead, AeadKey};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::TAG_SIZE;

/// Protocol name for Noise XX with secp256k1.
/// Format: Noise_XX_secp256k1_ChaChaPoly_SHA256
pub(crate) const PROTOCOL_NAME_XX: &[u8] = b"Noise_XX_secp256k1_ChaChaPoly_SHA256";

/// Maximum message size for noise transport messages.
pub const MAX_MESSAGE_SIZE: usize = 65535;

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
    Secp256k1(secp256k1::Error),
}

// Written out rather than derived with `#[from]`, which would also make the
// field the error's `source()`: that needs `core::error::Error` on
// `secp256k1::Error`, which the crate implements only with its `std` feature.
// So `source()` returns `None` for this variant; the inner error's text is in
// the `Display` output.
impl From<secp256k1::Error> for NoiseError {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
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
/// AEAD is ChaCha20-Poly1305 through [`AeadKey`], the backend this build
/// chose: `ring`'s (BoringSSL assembly, NEON on aarch64 and AVX2/AVX-512 on
/// x86_64) on hosted builds, RustCrypto's elsewhere. The keyed cipher is
/// built once, when the key is set, and cached, so the per-packet AEAD skips
/// rebuilding it. (It does not skip Poly1305 key derivation, which is
/// nonce-dependent and happens per message inside seal and open.) `Clone`
/// and `cipher_clone`, which hands a key to each off-task AEAD worker, clone
/// the cached cipher; the 32 key bytes are not kept.
///
/// The state holds no key bytes of its own, so the derived `Zeroize` and
/// `ZeroizeOnDrop` skip every field and clear nothing. They are kept so the
/// type's trait impls do not change. The key material is inside `cipher`:
/// RustCrypto's key clears itself on drop, and `ring`'s holds its material
/// behind `ring`'s own API with no route to clear it. Every clone, and every
/// key `cipher_clone` hands out, is a further copy of that material. `nonce`
/// and `has_key` are not secret.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CipherState {
    /// Cached keyed AEAD, valid iff `has_key`. None for an un-keyed state.
    #[zeroize(skip)]
    cipher: Option<AeadKey>,
    /// Nonce counter (8 bytes used, 4 bytes zero prefix).
    #[zeroize(skip)]
    pub(super) nonce: u64,
    /// Whether this cipher has a valid key.
    #[zeroize(skip)]
    has_key: bool,
}

impl CipherState {
    /// Create a new cipher state with the given key.
    ///
    /// The parameter is this frame's own copy of live key material, so it is
    /// cleared before returning. The caller's copy stays the caller's to clear.
    pub(crate) fn new(mut key: [u8; 32]) -> Self {
        let cipher = Self::build_cipher(&key);
        let state = Self {
            cipher,
            nonce: 0,
            has_key: true,
        };
        key.zeroize();
        state
    }

    /// Create an empty cipher state (no key yet).
    pub(super) fn empty() -> Self {
        Self {
            cipher: None,
            nonce: 0,
            has_key: false,
        }
    }

    /// Initialize with a key.
    ///
    /// The parameter is this frame's own copy of live key material, so it is
    /// cleared before returning. The caller's copy stays the caller's to clear.
    pub(super) fn initialize_key(&mut self, mut key: [u8; 32]) {
        self.cipher = Self::build_cipher(&key);
        self.nonce = 0;
        self.has_key = true;
        key.zeroize();
    }

    /// Build the keyed cipher from raw key bytes. Centralized so the two
    /// paths that set a key (`new`, `initialize_key`) agree on construction.
    fn build_cipher(key: &[u8; 32]) -> Option<AeadKey> {
        AeadKey::with_key(key)
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
    /// Returns `None` if no key; otherwise a clone of the cached cipher, not
    /// a rebuild from key bytes. On hosted builds the clone is a
    /// `ring::aead::LessSafeKey`, which the workers seal and open with
    /// directly — the worker holds the cipher and a pre-assigned counter,
    /// while the dispatcher keeps the replay window and counter assignment
    /// sequential.
    pub fn cipher_clone(&self) -> Option<AeadKey> {
        if self.has_key {
            self.cipher.clone()
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
/// returning a `Vec<u8>` of `plaintext.len() + TAG_SIZE` bytes: the
/// ciphertext, sealed in place, then the tag.
///
/// What [`CipherState::encrypt_with_aad`] does once it has taken its
/// counter, for a sender that reserved the counter and cloned the key
/// elsewhere (the session rekey machine's seal).
pub fn seal(
    cipher: Option<&AeadKey>,
    counter: u64,
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    let cipher = cipher.ok_or(NoiseError::EncryptionFailed)?;
    let mut buf = Vec::with_capacity(plaintext.len() + TAG_SIZE);
    buf.extend_from_slice(plaintext);
    let tag = cipher
        .seal(&aead::nonce(counter), aad, &mut buf)
        .map_err(|_| NoiseError::EncryptionFailed)?;
    buf.extend_from_slice(&tag);
    Ok(buf)
}

/// Decrypt `ciphertext` (with appended tag) with the given keyed AEAD,
/// counter, and AAD, returning the plaintext as a `Vec<u8>`. Truncates
/// in place to drop the AEAD tag.
pub fn open(
    cipher: Option<&AeadKey>,
    counter: u64,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, NoiseError> {
    let cipher = cipher.ok_or(NoiseError::DecryptionFailed)?;
    let mut buf = ciphertext.to_vec();
    let plaintext_len = cipher
        .open(&aead::nonce(counter), aad, &mut buf)
        .map_err(|_| NoiseError::DecryptionFailed)?;
    buf.truncate(plaintext_len);
    Ok(buf)
}

/// Move the value out of `slot`, leaving `None`, and clear the bytes the
/// value occupied.
///
/// `Option::take` moves the value out but writes only the `None` marker, so
/// the old value's bytes stay where they were. For a slot holding a
/// handshake or a session that is a full copy of its keys, which nothing
/// will clear because nothing owns it any more. Here, once the value has
/// moved out, the slot is cleared with [`clear_slot`].
///
/// This clears the slot only. The moved value is the caller's to clear, and
/// any copy made on the way out, such as in a register or a stack slot, is
/// out of reach as it is for every other move. A caller that unwraps the
/// result straight away should use `take().expect(..)` followed by
/// [`clear_slot`] instead: unwrapping after the slot has been cleared makes
/// the optimiser keep a second copy of the value on the stack, because it
/// can no longer copy the value straight from the slot to where it ends up.
pub fn take_cleared<T>(slot: &mut Option<T>) -> Option<T> {
    let value = slot.take();
    clear_slot(slot);
    value
}

/// Drop whatever `slot` holds, overwrite every byte of it with zeros, and
/// leave it `None`.
///
/// The zeros are volatile writes, which the optimiser keeps. Meant for a
/// slot whose value has just been moved out, so the bytes the move left
/// behind are cleared.
pub fn clear_slot<T>(slot: &mut Option<T>) {
    *slot = None;
    let raw: *mut Option<T> = slot;
    // SAFETY: `raw` comes from a live `&mut`, so it is valid and aligned for
    // `size_of::<Option<T>>()` bytes. Seen as `MaybeUninit`, those bytes have
    // no drop glue, own nothing and may be all zero, which is what
    // `zeroize_flat_type` asks of its target. The slot holds `None` after the
    // assignment above, so zeroing it discards nothing, and writing `None`
    // (which does not drop the zeroed bytes) leaves the slot valid before
    // anything reads it again.
    unsafe {
        zeroize::zeroize_flat_type(raw.cast::<core::mem::MaybeUninit<Option<T>>>());
        raw.write(None);
    }
}
