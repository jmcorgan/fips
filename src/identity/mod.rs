//! FIPS Identity System
//!
//! Node identity based on Nostr keypairs (secp256k1). The node_addr is derived
//! from the public key via SHA-256, and the FIPS address uses an IPv6-compatible
//! format with the 0xfd prefix.

mod address;
mod auth;
mod encoding;
mod local;
mod node_addr;
mod peer;

use std::sync::LazyLock;

use secp256k1::{All, Secp256k1};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use address::FipsAddress;
pub use auth::{AuthChallenge, AuthResponse};
pub use encoding::{decode_npub, decode_nsec, decode_secret, encode_npub, encode_nsec};
pub use local::Identity;
pub use node_addr::NodeAddr;
pub use peer::PeerIdentity;

/// Shared secp256k1 context reused across all identity operations.
///
/// `Secp256k1::new()` allocates a `Secp256k1<All>` and runs randomization /
/// blinding table setup; it is designed to be created once and reused rather
/// than rebuilt per sign / verify / key-derive call. This single `All` context
/// serves both signing and verification across the identity module and still
/// performs the standard construction-time blinding.
pub(crate) static SECP: LazyLock<Secp256k1<All>> = LazyLock::new(Secp256k1::new);

/// FIPS address prefix (IPv6 ULA range).
pub const FIPS_ADDRESS_PREFIX: u8 = 0xfd;

/// Errors that can occur in identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(#[from] secp256k1::Error),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid node_addr length: expected 16, got {0}")]
    InvalidNodeAddrLength(usize),

    #[error("invalid address length: expected 16, got {0}")]
    InvalidAddressLength(usize),

    #[error("invalid address prefix: expected 0xfd, got 0x{0:02x}")]
    InvalidAddressPrefix(u8),

    #[error("bech32 encoding error: {0}")]
    Bech32Encode(#[from] bech32::EncodeError),

    #[error("bech32 decoding error: {0}")]
    Bech32Decode(#[from] bech32::DecodeError),

    #[error("invalid npub: expected 'npub' prefix, got '{0}'")]
    InvalidNpubPrefix(String),

    #[error("invalid npub: expected 32 bytes, got {0}")]
    InvalidNpubLength(usize),

    #[error("invalid nsec: expected 'nsec' prefix, got '{0}'")]
    InvalidNsecPrefix(String),

    #[error("invalid nsec: expected 32 bytes, got {0}")]
    InvalidNsecLength(usize),

    #[error("invalid hex encoding: {0}")]
    InvalidHex(#[from] hex::FromHexError),
}

/// Compute SHA-256 hash of data.
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Encode bytes as lowercase hex string.
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests;
