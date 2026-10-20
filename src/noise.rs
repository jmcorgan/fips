//! Noise Protocol Implementations for FIPS
//!
//! The handshakes, sessions, replay window, cipher state and AEAD live in
//! `fips-core`. This module re-exports all but the AEAD, with the handshake
//! drawing its ephemeral keys from [`OsEntropy`](crate::identity::OsEntropy);
//! the AEAD key type is reached only as what the sessions' key hand-outs
//! return, and in the compile-time tie below that pins it to `ring`.

pub use fips_core::noise::{
    CipherState, EPOCH_ENCRYPTED_SIZE, EPOCH_SIZE, Fork, HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE,
    HANDSHAKE_MSG3_SIZE, HandshakeProgress, HandshakeRole, MAX_MESSAGE_SIZE, NoiseError,
    NoisePattern, NoiseSession, PUBKEY_SIZE, REPLAY_WINDOW_SIZE, ReplayWindow, TAG_SIZE,
};
pub(crate) use fips_core::noise::{clear_slot, take_cleared};

#[cfg(all(test, unix))]
pub(crate) use fips_core::noise::open;

/// The Noise handshake, drawing its ephemeral keys from
/// [`OsEntropy`](crate::identity::OsEntropy).
pub type HandshakeState = fips_core::noise::HandshakeState<crate::identity::OsEntropy>;

// Hosted builds must seal and open with `ring`: this fails to compile if the
// root's `fips-core` line loses its `ring` feature. On Unix the workers' use of
// the handed-out keys would fail too; on Windows this line is the only check.
const _: fn(fips_core::noise::aead::AeadKey) -> ring::aead::LessSafeKey = |key| key;
