//! A node's 128-bit IPv6 address, in the `fd00::/8` ULA range.

use core::fmt;
use core::net::Ipv6Addr;

use super::{IPV6_ADDRESS_PREFIX, IdentityError, NodeAddr, NodePrefix};

/// A node's 128-bit IPv6 address, in the `fd00::/8` ULA range.
///
/// The address uses the IPv6 Unique Local Address (ULA) prefix `fd00::/8`,
/// providing 120 bits for the node_addr hash. This format allows applications
/// designed for IP transports to bind to these addresses via a TUN interface.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Address([u8; 16]);

impl Ipv6Address {
    /// Create an Ipv6Address from a 16-byte array.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, IdentityError> {
        if bytes[0] != IPV6_ADDRESS_PREFIX {
            return Err(IdentityError::InvalidAddressPrefix(bytes[0]));
        }
        Ok(Self(bytes))
    }

    /// Create an Ipv6Address from a slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, IdentityError> {
        if slice.len() != 16 {
            return Err(IdentityError::InvalidAddressLength(slice.len()));
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(slice);
        Self::from_bytes(bytes)
    }

    /// Derive an Ipv6Address from a NodeAddr.
    ///
    /// Takes the node_addr's prefix, its first 15 bytes, and prepends the
    /// 0xfd prefix.
    pub fn from_node_addr(node_addr: &NodeAddr) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0] = IPV6_ADDRESS_PREFIX;
        bytes[1..16].copy_from_slice(node_addr.prefix().as_bytes());
        Self(bytes)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The node prefix the address carries in bytes 1 to 15.
    pub fn prefix(&self) -> NodePrefix {
        NodePrefix::from_octets(&self.0)
    }

    /// Convert to std::net::Ipv6Addr.
    pub fn to_ipv6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.0)
    }
}

impl From<Ipv6Address> for Ipv6Addr {
    fn from(addr: Ipv6Address) -> Self {
        Ipv6Addr::from(addr.0)
    }
}

impl fmt::Debug for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Ipv6Address({})", self.to_ipv6())
    }
}

impl fmt::Display for Ipv6Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ipv6())
    }
}
