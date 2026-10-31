//! Noise: the handshake, the transport sessions and the AEAD.
//!
//! The XX handshake over secp256k1, which both the link layer (FMP) and the
//! session layer (FSP) run, the sessions it produces, the replay window, and
//! the ChaCha20-Poly1305 AEAD they seal and open with. Below the declarations
//! are the fixed sizes of the AEAD tag, a public key, the startup epoch and the
//! three XX handshake messages, which the link-layer wire codec checks frames
//! against. They are wire format. The root crate re-exports this module's
//! items other than `aead` as `fips::noise`, with `HandshakeState` drawing its
//! ephemeral keys from the host's entropy source.
//!
//! A msg2 or msg3 that nothing has authenticated yet is read on a fork of
//! the handshake ([`Fork`], `HandshakeState::fork_msg2` and `fork_msg3`),
//! never on the handshake itself, so a message that fails partway leaves the
//! handshake able to read the genuine one.

pub mod aead;
mod cipher;
mod fork;
mod handshake;
mod replay;
mod session;

pub(crate) use cipher::PROTOCOL_NAME_XX;
#[cfg(any(test, feature = "test-hooks"))]
pub use cipher::open;
pub use cipher::seal;
pub use cipher::{
    CipherState, HandshakeProgress, HandshakeRole, MAX_MESSAGE_SIZE, NoiseError, NoisePattern,
    REPLAY_WINDOW_SIZE,
};
#[doc(hidden)]
pub use cipher::{clear_slot, take_cleared};
pub use fork::{Fork, ForkRead};
pub use handshake::HandshakeState;
#[cfg(any(test, feature = "test-hooks"))]
#[doc(hidden)]
pub use handshake::dh_ops;
pub use replay::ReplayWindow;
pub use session::NoiseSession;

#[cfg(test)]
mod tests;

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
