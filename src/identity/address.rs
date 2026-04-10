//! 128-bit FIPS address with IPv6-compatible format.

use std::fmt;
use std::net::Ipv6Addr;

use super::{FIPS_ADDRESS_PREFIX, IdentityError, NodeAddr};

/// 128-bit FIPS address with IPv6-compatible format.
///
/// The address uses the IPv6 Unique Local Address (ULA) prefix `fd00::/8`,
/// providing 120 bits for the node_addr hash. This format allows applications
/// designed for IP transports to bind to FIPS addresses via a TUN interface.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FipsAddress([u8; 16]);

impl FipsAddress {
    /// Create a FipsAddress from a 16-byte array.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, IdentityError> {
        if bytes[0] != FIPS_ADDRESS_PREFIX {
            return Err(IdentityError::InvalidAddressPrefix(bytes[0]));
        }
        Ok(Self(bytes))
    }

    /// Create a FipsAddress from a slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, IdentityError> {
        if slice.len() != 16 {
            return Err(IdentityError::InvalidAddressLength(slice.len()));
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(slice);
        Self::from_bytes(bytes)
    }

    /// Derive a FipsAddress from a NodeAddr.
    ///
    /// Takes the first 15 bytes of the node_addr and prepends the 0xfd prefix.
    pub fn from_node_addr(node_addr: &NodeAddr) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0] = FIPS_ADDRESS_PREFIX;
        bytes[1..16].copy_from_slice(&node_addr.as_bytes()[0..15]);
        Self(bytes)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Convert to std::net::Ipv6Addr.
    pub fn to_ipv6(&self) -> Ipv6Addr {
        Ipv6Addr::from(self.0)
    }
}

impl From<FipsAddress> for Ipv6Addr {
    fn from(addr: FipsAddress) -> Self {
        Ipv6Addr::from(addr.0)
    }
}

impl fmt::Debug for FipsAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FipsAddress({})", self.to_ipv6())
    }
}

impl fmt::Display for FipsAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_ipv6())
    }
}
