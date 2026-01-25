//! FIPS Identity System
//!
//! Node identity based on Nostr keypairs (secp256k1). The node_id is derived
//! from the public key via SHA-256, and the FIPS address uses an IPv6-compatible
//! format with the 0xfd prefix.

use rand::Rng;
use secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::Ipv6Addr;
use thiserror::Error;

/// Domain separation string for authentication challenges.
const AUTH_DOMAIN: &[u8] = b"fips-auth-v1";

/// FIPS address prefix (IPv6 ULA range).
const FIPS_ADDRESS_PREFIX: u8 = 0xfd;

/// Errors that can occur in identity operations.
#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("invalid secret key: {0}")]
    InvalidSecretKey(#[from] secp256k1::Error),

    #[error("signature verification failed")]
    SignatureVerificationFailed,

    #[error("invalid node_id length: expected 32, got {0}")]
    InvalidNodeIdLength(usize),

    #[error("invalid address length: expected 16, got {0}")]
    InvalidAddressLength(usize),

    #[error("invalid address prefix: expected 0xfd, got 0x{0:02x}")]
    InvalidAddressPrefix(u8),
}

/// 32-byte node identifier derived from SHA-256(npub).
///
/// The node_id is used in protocol messages and bloom filters. Hashing the
/// public key prevents grinding attacks that exploit secp256k1's algebraic
/// structure.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Create a NodeId from a 32-byte array.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Create a NodeId from a slice.
    pub fn from_slice(slice: &[u8]) -> Result<Self, IdentityError> {
        if slice.len() != 32 {
            return Err(IdentityError::InvalidNodeIdLength(slice.len()));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Derive a NodeId from an x-only public key (npub).
    pub fn from_pubkey(pubkey: &XOnlyPublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(pubkey.serialize());
        let hash = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&hash);
        Self(bytes)
    }

    /// Return the raw bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex_encode(&self.0[..8]))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_encode(&self.0))
    }
}

impl AsRef<[u8]> for NodeId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// 128-bit FIPS address with IPv6-compatible format.
///
/// The address uses the IPv6 Unique Local Address (ULA) prefix `fd00::/8`,
/// providing 120 bits for the node_id hash. This format allows applications
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

    /// Derive a FipsAddress from a NodeId.
    ///
    /// Takes the first 15 bytes of the node_id and prepends the 0xfd prefix.
    pub fn from_node_id(node_id: &NodeId) -> Self {
        let mut bytes = [0u8; 16];
        bytes[0] = FIPS_ADDRESS_PREFIX;
        bytes[1..16].copy_from_slice(&node_id.0[0..15]);
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

/// A FIPS node identity consisting of a keypair and derived identifiers.
///
/// The identity holds the secp256k1 keypair and provides methods for signing
/// and verifying protocol messages.
pub struct Identity {
    keypair: Keypair,
    node_id: NodeId,
    address: FipsAddress,
}

impl Identity {
    /// Create a new random identity.
    pub fn generate() -> Self {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        Self::from_keypair(keypair)
    }

    /// Create an identity from an existing keypair.
    pub fn from_keypair(keypair: Keypair) -> Self {
        let (pubkey, _parity) = keypair.x_only_public_key();
        let node_id = NodeId::from_pubkey(&pubkey);
        let address = FipsAddress::from_node_id(&node_id);
        Self {
            keypair,
            node_id,
            address,
        }
    }

    /// Create an identity from a secret key.
    pub fn from_secret_key(secret_key: SecretKey) -> Self {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &secret_key);
        Self::from_keypair(keypair)
    }

    /// Create an identity from secret key bytes.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        let secret_key = SecretKey::from_slice(bytes)?;
        Ok(Self::from_secret_key(secret_key))
    }

    /// Return the x-only public key (npub).
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }

    /// Return the node ID.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Return the FIPS address.
    pub fn address(&self) -> &FipsAddress {
        &self.address
    }

    /// Sign arbitrary data with this identity's secret key.
    pub fn sign(&self, data: &[u8]) -> secp256k1::schnorr::Signature {
        let secp = Secp256k1::new();
        let digest = sha256(data);
        secp.sign_schnorr(&digest, &self.keypair)
    }

    /// Create an authentication response for a challenge.
    ///
    /// The response signs: SHA256("fips-auth-v1" || challenge || timestamp)
    pub fn sign_challenge(&self, challenge: &[u8; 32], timestamp: u64) -> AuthResponse {
        let digest = auth_challenge_digest(challenge, timestamp);
        let secp = Secp256k1::new();
        let signature = secp.sign_schnorr(&digest, &self.keypair);
        AuthResponse {
            pubkey: self.pubkey(),
            timestamp,
            signature,
        }
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("node_id", &self.node_id)
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

/// A 32-byte random authentication challenge.
#[derive(Clone, Copy, Debug)]
pub struct AuthChallenge([u8; 32]);

impl AuthChallenge {
    /// Generate a new random challenge.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill(&mut bytes);
        Self(bytes)
    }

    /// Create a challenge from bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the challenge bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Verify a response to this challenge.
    pub fn verify(&self, response: &AuthResponse) -> Result<NodeId, IdentityError> {
        let digest = auth_challenge_digest(&self.0, response.timestamp);
        let secp = Secp256k1::new();

        secp.verify_schnorr(&response.signature, &digest, &response.pubkey)
            .map_err(|_| IdentityError::SignatureVerificationFailed)?;

        Ok(NodeId::from_pubkey(&response.pubkey))
    }
}

/// Response to an authentication challenge.
#[derive(Clone, Debug)]
pub struct AuthResponse {
    /// The responder's public key.
    pub pubkey: XOnlyPublicKey,
    /// Timestamp included in the signed message.
    pub timestamp: u64,
    /// Schnorr signature over the challenge digest.
    pub signature: secp256k1::schnorr::Signature,
}

/// Compute the digest for an authentication challenge.
fn auth_challenge_digest(challenge: &[u8; 32], timestamp: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update(challenge);
    hasher.update(timestamp.to_be_bytes());
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
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
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate();

        // NodeId should be 32 bytes
        assert_eq!(identity.node_id().as_bytes().len(), 32);

        // Address should start with 0xfd
        assert_eq!(identity.address().as_bytes()[0], 0xfd);

        // Address bytes 1-15 should match node_id bytes 0-14
        assert_eq!(
            &identity.address().as_bytes()[1..16],
            &identity.node_id().as_bytes()[0..15]
        );
    }

    #[test]
    fn test_node_id_from_pubkey_deterministic() {
        let identity = Identity::generate();
        let pubkey = identity.pubkey();

        let node_id1 = NodeId::from_pubkey(&pubkey);
        let node_id2 = NodeId::from_pubkey(&pubkey);

        assert_eq!(node_id1, node_id2);
    }

    #[test]
    fn test_fips_address_ipv6_format() {
        let identity = Identity::generate();
        let ipv6 = identity.address().to_ipv6();
        let addr_str = ipv6.to_string();

        // Should start with fd (ULA prefix)
        assert!(addr_str.starts_with("fd"));

        // Conversion should be lossless
        let octets = ipv6.octets();
        assert_eq!(&octets, identity.address().as_bytes());
    }

    #[test]
    fn test_auth_challenge_verify_success() {
        let identity = Identity::generate();
        let challenge = AuthChallenge::generate();
        let timestamp = 1234567890u64;

        let response = identity.sign_challenge(challenge.as_bytes(), timestamp);
        let result = challenge.verify(&response);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), *identity.node_id());
    }

    #[test]
    fn test_auth_challenge_verify_wrong_challenge() {
        let identity = Identity::generate();
        let challenge1 = AuthChallenge::generate();
        let challenge2 = AuthChallenge::generate();
        let timestamp = 1234567890u64;

        let response = identity.sign_challenge(challenge1.as_bytes(), timestamp);
        let result = challenge2.verify(&response);

        assert!(matches!(
            result,
            Err(IdentityError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_auth_challenge_verify_wrong_timestamp() {
        let identity = Identity::generate();
        let challenge = AuthChallenge::generate();

        let response = identity.sign_challenge(challenge.as_bytes(), 1234567890);

        // Modify the timestamp in the response
        let bad_response = AuthResponse {
            pubkey: response.pubkey,
            timestamp: 9999999999,
            signature: response.signature,
        };

        let result = challenge.verify(&bad_response);
        assert!(matches!(
            result,
            Err(IdentityError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_node_id_ordering() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        // NodeIds should be comparable for root election
        let _cmp = id1.node_id().cmp(id2.node_id());
    }

    #[test]
    fn test_identity_from_secret_bytes() {
        // A known secret key (32 bytes)
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let identity1 = Identity::from_secret_bytes(&secret_bytes).unwrap();
        let identity2 = Identity::from_secret_bytes(&secret_bytes).unwrap();

        // Same secret key should produce same node_id
        assert_eq!(identity1.node_id(), identity2.node_id());
        assert_eq!(identity1.address(), identity2.address());
    }

    #[test]
    fn test_node_id_from_slice() {
        let bytes = [0u8; 32];
        let node_id = NodeId::from_slice(&bytes).unwrap();
        assert_eq!(node_id.as_bytes(), &bytes);

        // Wrong length should fail
        let short = [0u8; 16];
        assert!(matches!(
            NodeId::from_slice(&short),
            Err(IdentityError::InvalidNodeIdLength(16))
        ));
    }

    #[test]
    fn test_fips_address_validation() {
        // Valid address with fd prefix
        let mut valid = [0u8; 16];
        valid[0] = 0xfd;
        assert!(FipsAddress::from_bytes(valid).is_ok());

        // Invalid prefix
        let mut invalid = [0u8; 16];
        invalid[0] = 0xfe;
        assert!(matches!(
            FipsAddress::from_bytes(invalid),
            Err(IdentityError::InvalidAddressPrefix(0xfe))
        ));
    }

    #[test]
    fn test_identity_sign() {
        let identity = Identity::generate();
        let data = b"test message";

        let sig = identity.sign(data);

        // Verify the signature manually
        let secp = Secp256k1::new();
        let digest = sha256(data);
        assert!(secp
            .verify_schnorr(&sig, &digest, &identity.pubkey())
            .is_ok());
    }
}
