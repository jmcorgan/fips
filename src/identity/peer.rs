//! Remote peer identity (public key only, no signing capability).

use secp256k1::{Parity, PublicKey, Secp256k1, XOnlyPublicKey};
use std::fmt;

use super::encoding::{decode_npub, encode_npub};
use super::{sha256, FipsAddress, IdentityError, NodeAddr};

/// A known peer's identity (public key only, no signing capability).
///
/// Use this to represent remote peers whose npub you know. For a local
/// identity with signing capability, use [`Identity`] instead.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    pubkey: XOnlyPublicKey,
    /// Full public key if known (includes parity for ECDH operations).
    pubkey_full: Option<PublicKey>,
    node_addr: NodeAddr,
    address: FipsAddress,
}

impl PeerIdentity {
    /// Create a PeerIdentity from an x-only public key.
    ///
    /// Note: When only the x-only key is available, the full public key
    /// will be derived assuming even parity for ECDH operations.
    pub fn from_pubkey(pubkey: XOnlyPublicKey) -> Self {
        let node_addr = NodeAddr::from_pubkey(&pubkey);
        let address = FipsAddress::from_node_addr(&node_addr);
        Self {
            pubkey,
            pubkey_full: None,
            node_addr,
            address,
        }
    }

    /// Create a PeerIdentity from a full public key (includes parity).
    ///
    /// Use this when you have the complete public key (e.g., from a Noise
    /// handshake) to preserve parity information for ECDH operations.
    pub fn from_pubkey_full(pubkey: PublicKey) -> Self {
        let (x_only, _parity) = pubkey.x_only_public_key();
        let node_addr = NodeAddr::from_pubkey(&x_only);
        let address = FipsAddress::from_node_addr(&node_addr);
        Self {
            pubkey: x_only,
            pubkey_full: Some(pubkey),
            node_addr,
            address,
        }
    }

    /// Create a PeerIdentity from a bech32-encoded npub string.
    pub fn from_npub(npub: &str) -> Result<Self, IdentityError> {
        let pubkey = decode_npub(npub)?;
        Ok(Self::from_pubkey(pubkey))
    }

    /// Return the x-only public key.
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.pubkey
    }

    /// Return the full public key for ECDH operations.
    ///
    /// If the full key was provided during construction, it is returned.
    /// Otherwise, the key is derived from the x-only key assuming even parity.
    pub fn pubkey_full(&self) -> PublicKey {
        self.pubkey_full.unwrap_or_else(|| {
            // Derive full key assuming even parity
            self.pubkey.public_key(Parity::Even)
        })
    }

    /// Return the public key as a bech32-encoded npub string (NIP-19).
    pub fn npub(&self) -> String {
        encode_npub(&self.pubkey)
    }

    /// Return a shortened npub for log display (e.g., `npub1abcd...wxyz`).
    pub fn short_npub(&self) -> String {
        let full = self.npub();
        let data = &full[5..]; // strip "npub1"
        format!("npub1{}...{}", &data[..4], &data[data.len() - 4..])
    }

    /// Return the node ID.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node_addr
    }

    /// Return the FIPS address.
    pub fn address(&self) -> &FipsAddress {
        &self.address
    }

    /// Verify a signature from this peer.
    pub fn verify(&self, data: &[u8], signature: &secp256k1::schnorr::Signature) -> bool {
        let secp = Secp256k1::new();
        let digest = sha256(data);
        secp.verify_schnorr(signature, &digest, &self.pubkey).is_ok()
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerIdentity")
            .field("node_addr", &self.node_addr)
            .field("address", &self.address)
            .finish()
    }
}

impl fmt::Display for PeerIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.npub())
    }
}
