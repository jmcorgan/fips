//! Noise: the handshakes, the transport sessions and the AEAD.
//!
//! The IK (link layer) and XK (session layer) handshakes over secp256k1,
//! the sessions they produce, the replay window, and the ChaCha20-Poly1305
//! AEAD they seal and open with. A handshake message is read on a fork
//! (`Fork`), so a message that fails to authenticate leaves the handshake as
//! it was. Below the declarations are the fixed sizes of the AEAD tag, a
//! public key, the startup epoch and the IK handshake messages, which the
//! link-layer wire codec checks frames against. They are wire format. The
//! root crate re-exports this module's items other than `aead` as
//! `fips::noise`, with `HandshakeState` drawing its ephemeral keys from the
//! host's entropy source.

pub mod aead;
mod cipher;
mod fork;
mod handshake;
mod replay;
mod session;

#[cfg(any(test, feature = "test-hooks"))]
pub use cipher::open;
pub use cipher::seal;
pub use cipher::{
    CipherState, HandshakeProgress, HandshakeRole, MAX_MESSAGE_SIZE, NoiseError, NoisePattern,
    REPLAY_WINDOW_SIZE, XK_HANDSHAKE_MSG1_SIZE, XK_HANDSHAKE_MSG2_SIZE, XK_HANDSHAKE_MSG3_SIZE,
};
pub(crate) use cipher::{PROTOCOL_NAME_IK, PROTOCOL_NAME_XK};
#[doc(hidden)]
pub use cipher::{clear_slot, take_cleared};
pub use fork::Fork;
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

/// Size of IK handshake message 1: ephemeral (33) + encrypted static (33 + 16 tag) + encrypted epoch (8 + 16 tag).
pub const HANDSHAKE_MSG1_SIZE: usize = PUBKEY_SIZE + PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE;

/// Size of IK handshake message 2: ephemeral (33) + encrypted epoch (8 + 16 tag).
pub const HANDSHAKE_MSG2_SIZE: usize = PUBKEY_SIZE + EPOCH_ENCRYPTED_SIZE;
