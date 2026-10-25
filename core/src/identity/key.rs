//! A node's static key, held as the 32 bytes of its x-only public key.

use core::fmt;

use secp256k1::XOnlyPublicKey;

use super::{Ipv6Address, NodeAddr, sha256};

/// A node's static key, held as the 32 bytes of its x-only public key and
/// compared and hashed as those bytes, so comparing or hashing one, as the
/// node does for every datagram the IPv6 adapter sends, never calls into
/// secp256k1.
///
/// Any 32 bytes make one, since the rekey machine builds them from what a
/// peer sent; [`PeerKey::to_xonly`] is where they are checked.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PeerKey([u8; 32]);

impl PeerKey {
    /// The key whose X coordinate is `x`.
    pub fn new(x: [u8; 32]) -> Self {
        Self(x)
    }

    /// The key of an x-only public key.
    pub fn from_xonly(key: &XOnlyPublicKey) -> Self {
        Self(key.serialize())
    }

    /// The X coordinate.
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The x-only public key, or secp256k1's error when the bytes are not
    /// the X coordinate of a point on the curve. A key made by
    /// [`PeerKey::from_xonly`] always converts.
    pub fn to_xonly(&self) -> Result<XOnlyPublicKey, secp256k1::Error> {
        XOnlyPublicKey::from_byte_array(&self.0)
    }

    /// The node address derived from the key: the first 16 bytes of the
    /// SHA-256 of its X coordinate. This is the one place the derivation is
    /// written; [`NodeAddr::from_pubkey`] derives through it.
    pub fn addr(&self) -> NodeAddr {
        let hash = sha256(&self.0);
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&hash[..16]);
        NodeAddr::from_bytes(bytes)
    }

    /// The key's IPv6 address: the `fd00::/8` form of [`PeerKey::addr`].
    pub fn address(&self) -> Ipv6Address {
        Ipv6Address::from_node_addr(&self.addr())
    }
}

impl fmt::Debug for PeerKey {
    /// The first four bytes, which is enough to tell test keys apart.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PeerKey({:02x}{:02x}{:02x}{:02x})",
            self.0[0], self.0[1], self.0[2], self.0[3]
        )
    }
}
