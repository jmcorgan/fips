//! 16-byte node identifier derived from truncated SHA-256(pubkey).

use secp256k1::XOnlyPublicKey;
use sha2::{Digest, Sha256};
use std::fmt;

use super::{hex_encode, IdentityError};

/// 16-byte node identifier derived from truncated SHA-256(pubkey).
///
/// The node_addr is the first 16 bytes of SHA-256(pubkey), providing 128 bits
/// of collision resistance. Hashing the public key prevents grinding attacks
/// that exploit secp256k1's algebraic structure.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeAddr([u8; 16]);

impl NodeAddr {
    /// Create a NodeAddr from a 16-byte array.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Create a NodeAddr from a slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, IdentityError> {
        if slice.len() != 16 {
            return Err(IdentityError::InvalidNodeAddrLength(slice.len()));
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Derive a NodeAddr from an x-only public key (npub).
    ///
    /// Computes SHA-256(pubkey) and takes the first 16 bytes.
    pub fn from_pubkey(pubkey: &XOnlyPublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.serialize());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        Self(bytes)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Return the bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Return a short hex representation: first 4 bytes + "...".
    pub fn short_hex(&self) -> String {
        format!("{}...", hex_encode(&self.0[..4]))
    }
}

impl fmt::Debug for NodeAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeAddr({})", hex_encode(&self.0[..8]))
    }
}

impl fmt::Display for NodeAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_encode(&self.0))
    }
}

impl AsRef<[u8]> for NodeAddr {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
