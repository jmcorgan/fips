//! FIPS Identity System
//!
//! Node identity based on Nostr keypairs (secp256k1). The node_addr is derived
//! from the public key via SHA-256, and the node's IPv6 address is the 0xfd
//! prefix followed by the first 15 bytes of the node_addr.

mod address;
mod auth;
mod encoding;
mod key;
mod local;
mod node_addr;
mod peer;
mod prefix;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;

use once_cell::race::OnceBox;
use secp256k1::{All, Secp256k1};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use address::Ipv6Address;
pub use auth::{AuthChallenge, AuthResponse};
pub use encoding::{decode_npub, decode_nsec, decode_secret, encode_npub, encode_nsec};
pub use key::PeerKey;
#[doc(hidden)]
pub use local::ErasingKeypair;
pub use local::Identity;
pub use node_addr::NodeAddr;
pub use peer::PeerIdentity;
pub use prefix::NodePrefix;

/// Shared secp256k1 context reused across all identity operations.
///
/// `Secp256k1::new()` allocates a `Secp256k1<All>`; it is designed to be
/// created once and reused rather than rebuilt per sign / verify /
/// key-derive call. This single `All` context serves both signing and
/// verification across the identity module. It is blinded with the seed
/// passed to [`init_secp`]; see there for what happens without one.
static SECP: OnceBox<Secp256k1<All>> = OnceBox::new();

/// Install the shared secp256k1 context, blinded with `seed`.
///
/// Call this once at start-up, before anything signs, verifies or derives a
/// key, with 32 bytes from the host's cryptographic random source. The seed
/// randomizes the context's internal blinding, which protects secret keys
/// against timing and power side channels; it does not change any signature
/// or key the context produces.
///
/// Returns `true` if this call installed the context, and `false` if one was
/// already installed, by an earlier call or by [`secp`] on first use. The
/// installed context is never replaced, so a `false` return means `seed` was
/// not used.
#[must_use]
pub fn init_secp(seed: &[u8; 32]) -> bool {
    install(&SECP, seed)
}

/// Build a context blinded with `seed` and install it in `cell` if the cell
/// is empty. Split from [`init_secp`] so tests can use a cell of their own.
fn install(cell: &OnceBox<Secp256k1<All>>, seed: &[u8; 32]) -> bool {
    let mut ctx = Secp256k1::new();
    ctx.seeded_randomize(seed);
    cell.set(Box::new(ctx)).is_ok()
}

/// Return the shared secp256k1 context.
///
/// If [`init_secp`] has not run, the first call builds the context with
/// `Secp256k1::new()`. That context is blinded only when the `secp256k1`
/// crate is built with its `rand` and `std` features, which this crate does
/// not enable; in a build that includes the root `fips` crate they are on.
///
/// If two threads race on first use, each may build a context; one is kept
/// and the other dropped, so every caller sees the same context afterwards.
#[doc(hidden)]
pub fn secp() -> &'static Secp256k1<All> {
    SECP.get_or_init(|| Box::new(Secp256k1::new()))
}

/// Prefix byte of every node's IPv6 address (the `fd00::/8` ULA range).
pub const IPV6_ADDRESS_PREFIX: u8 = 0xfd;

/// Errors that can occur in identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(secp256k1::Error),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid node_addr length: expected 16, got {0}")]
    InvalidNodeAddrLength(usize),

    #[error("invalid address length: expected 16, got {0}")]
    InvalidAddressLength(usize),

    #[error("invalid address prefix: expected 0xfd, got 0x{0:02x}")]
    InvalidAddressPrefix(u8),

    #[error("bech32 encoding error: {0}")]
    Bech32Encode(bech32::EncodeError),

    #[error("bech32 decoding error: {0}")]
    Bech32Decode(bech32::DecodeError),

    #[error("invalid npub: expected 'npub' prefix, got '{0}'")]
    InvalidNpubPrefix(String),

    #[error("invalid npub: expected 32 bytes, got {0}")]
    InvalidNpubLength(usize),

    #[error("invalid nsec: expected 'nsec' prefix, got '{0}'")]
    InvalidNsecPrefix(String),

    #[error("invalid nsec: expected 32 bytes, got {0}")]
    InvalidNsecLength(usize),

    #[error("invalid hex encoding: {0}")]
    InvalidHex(hex::FromHexError),
}

// Written out rather than derived with `#[from]`: that also marks the field
// as the error's source, which needs `core::error::Error` on the field type,
// and `secp256k1`, `bech32` and `hex` implement it only with their `std`
// features. So `source()` returns `None` for these four variants; the inner
// error's text is in the `Display` output.
impl From<secp256k1::Error> for IdentityError {
    fn from(e: secp256k1::Error) -> Self {
        Self::InvalidSecretKey(e)
    }
}

impl From<bech32::EncodeError> for IdentityError {
    fn from(e: bech32::EncodeError) -> Self {
        Self::Bech32Encode(e)
    }
}

impl From<bech32::DecodeError> for IdentityError {
    fn from(e: bech32::DecodeError) -> Self {
        Self::Bech32Decode(e)
    }
}

impl From<hex::FromHexError> for IdentityError {
    fn from(e: hex::FromHexError) -> Self {
        Self::InvalidHex(e)
    }
}

/// Compute SHA-256 hash of data.
#[doc(hidden)]
pub fn sha256(data: &[u8]) -> [u8; 32] {
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
