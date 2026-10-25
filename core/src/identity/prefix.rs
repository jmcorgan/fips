//! The part of a node address that its IPv6 address carries.

/// Bytes 0 to 14 of a node address, which are bytes 1 to 15 of the node's
/// `fd00::/8` IPv6 address: what a host packet names its destination by.
///
/// Not [`IPV6_ADDRESS_PREFIX`](super::IPV6_ADDRESS_PREFIX), the `0xfd` byte
/// before them.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct NodePrefix([u8; 15]);

impl NodePrefix {
    /// The prefix made of `bytes`.
    pub fn from_bytes(bytes: [u8; 15]) -> Self {
        Self(bytes)
    }

    /// The prefix an IPv6 address's `octets` name: bytes 1 to 15. Byte 0 is
    /// not read, so an address outside `fd00::/8` names a prefix too.
    pub fn from_octets(octets: &[u8; 16]) -> Self {
        let mut bytes = [0u8; 15];
        bytes.copy_from_slice(&octets[1..16]);
        Self(bytes)
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; 15] {
        &self.0
    }
}
