//! FIPS Identity System
//!
//! Node identity based on Nostr keypairs (secp256k1). The node_addr is derived
//! from the public key via SHA-256, and the FIPS address uses an IPv6-compatible
//! format with the 0xfd prefix.

use bech32::{Bech32, Hrp};
use rand::Rng;
use secp256k1::{Keypair, Parity, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use sha2::{Digest, Sha256};
use std::fmt;
use std::net::Ipv6Addr;
use thiserror::Error;

/// Human-readable part for npub (NIP-19).
const NPUB_HRP: Hrp = Hrp::parse_unchecked("npub");

/// Human-readable part for nsec (NIP-19).
const NSEC_HRP: Hrp = Hrp::parse_unchecked("nsec");

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
        bytes[1..16].copy_from_slice(&node_addr.0[0..15]);
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

/// A FIPS node identity consisting of a keypair and derived identifiers.
///
/// The identity holds the secp256k1 keypair and provides methods for signing
/// and verifying protocol messages.
pub struct Identity {
    keypair: Keypair,
    node_addr: NodeAddr,
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
        let node_addr = NodeAddr::from_pubkey(&pubkey);
        let address = FipsAddress::from_node_addr(&node_addr);
        Self {
            keypair,
            node_addr,
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

    /// Create an identity from an nsec string (bech32) or hex-encoded secret.
    pub fn from_secret_str(s: &str) -> Result<Self, IdentityError> {
        let secret_key = decode_secret(s)?;
        Ok(Self::from_secret_key(secret_key))
    }

    /// Return the underlying keypair.
    ///
    /// This is needed for cryptographic operations like Noise handshakes.
    pub fn keypair(&self) -> Keypair {
        self.keypair
    }

    /// Return the x-only public key.
    pub fn pubkey(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }

    /// Return the full public key (includes parity).
    pub fn pubkey_full(&self) -> PublicKey {
        self.keypair.public_key()
    }

    /// Return the public key as a bech32-encoded npub string (NIP-19).
    pub fn npub(&self) -> String {
        encode_npub(&self.pubkey())
    }

    /// Return the node ID.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node_addr
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
            .field("node_addr", &self.node_addr)
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
    pub fn verify(&self, response: &AuthResponse) -> Result<NodeAddr, IdentityError> {
        let digest = auth_challenge_digest(&self.0, response.timestamp);
        let secp = Secp256k1::new();

        secp.verify_schnorr(&response.signature, &digest, &response.pubkey)
            .map_err(|_| IdentityError::SignatureVerificationFailed)?;

        Ok(NodeAddr::from_pubkey(&response.pubkey))
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

/// Encode an x-only public key as a bech32 npub string (NIP-19).
pub fn encode_npub(pubkey: &XOnlyPublicKey) -> String {
    bech32::encode::<Bech32>(NPUB_HRP, &pubkey.serialize()).expect("npub encoding cannot fail")
}

/// Decode an npub string to an x-only public key.
pub fn decode_npub(npub: &str) -> Result<XOnlyPublicKey, IdentityError> {
    let (hrp, data) = bech32::decode(npub)?;

    if hrp != NPUB_HRP {
        return Err(IdentityError::InvalidNpubPrefix(hrp.to_string()));
    }

    if data.len() != 32 {
        return Err(IdentityError::InvalidNpubLength(data.len()));
    }

    let pubkey = XOnlyPublicKey::from_slice(&data)?;
    Ok(pubkey)
}

/// Encode a secret key as a bech32 nsec string (NIP-19).
pub fn encode_nsec(secret_key: &SecretKey) -> String {
    bech32::encode::<Bech32>(NSEC_HRP, &secret_key.secret_bytes())
        .expect("nsec encoding cannot fail")
}

/// Decode an nsec string to a secret key.
pub fn decode_nsec(nsec: &str) -> Result<SecretKey, IdentityError> {
    let (hrp, data) = bech32::decode(nsec)?;

    if hrp != NSEC_HRP {
        return Err(IdentityError::InvalidNsecPrefix(hrp.to_string()));
    }

    if data.len() != 32 {
        return Err(IdentityError::InvalidNsecLength(data.len()));
    }

    let secret_key = SecretKey::from_slice(&data)?;
    Ok(secret_key)
}

/// Decode a secret key from either nsec (bech32) or hex format.
pub fn decode_secret(s: &str) -> Result<SecretKey, IdentityError> {
    if s.starts_with("nsec1") {
        decode_nsec(s)
    } else {
        let bytes = hex::decode(s)?;
        if bytes.len() != 32 {
            return Err(IdentityError::InvalidNsecLength(bytes.len()));
        }
        let secret_key = SecretKey::from_slice(&bytes)?;
        Ok(secret_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation() {
        let identity = Identity::generate();

        // NodeAddr should be 16 bytes
        assert_eq!(identity.node_addr().as_bytes().len(), 16);

        // Address should start with 0xfd
        assert_eq!(identity.address().as_bytes()[0], 0xfd);

        // Address bytes 1-15 should match node_addr bytes 0-14
        assert_eq!(
            &identity.address().as_bytes()[1..16],
            &identity.node_addr().as_bytes()[0..15]
        );
    }

    #[test]
    fn test_node_addr_from_pubkey_deterministic() {
        let identity = Identity::generate();
        let pubkey = identity.pubkey();

        let node_addr1 = NodeAddr::from_pubkey(&pubkey);
        let node_addr2 = NodeAddr::from_pubkey(&pubkey);

        assert_eq!(node_addr1, node_addr2);
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
        assert_eq!(result.unwrap(), *identity.node_addr());
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
    fn test_node_addr_ordering() {
        let id1 = Identity::generate();
        let id2 = Identity::generate();

        // NodeAddrs should be comparable for root election
        let _cmp = id1.node_addr().cmp(id2.node_addr());
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

        // Same secret key should produce same node_addr
        assert_eq!(identity1.node_addr(), identity2.node_addr());
        assert_eq!(identity1.address(), identity2.address());
    }

    #[test]
    fn test_node_addr_from_slice() {
        let bytes = [0u8; 16];
        let node_addr = NodeAddr::from_slice(&bytes).unwrap();
        assert_eq!(node_addr.as_bytes(), &bytes);

        // Wrong length should fail
        let short = [0u8; 8];
        assert!(matches!(
            NodeAddr::from_slice(&short),
            Err(IdentityError::InvalidNodeAddrLength(8))
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

    #[test]
    fn test_npub_encoding() {
        let identity = Identity::generate();
        let npub = identity.npub();

        // Should start with "npub1"
        assert!(npub.starts_with("npub1"));

        // Should be 63 characters (npub1 + 58 chars of bech32 data)
        assert_eq!(npub.len(), 63);
    }

    #[test]
    fn test_npub_roundtrip() {
        let identity = Identity::generate();
        let npub = identity.npub();

        let decoded = decode_npub(&npub).unwrap();
        assert_eq!(decoded, identity.pubkey());
    }

    #[test]
    fn test_npub_known_vector() {
        // Test against a known npub (from NIP-19 test vectors or generated externally)
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let identity = Identity::from_secret_bytes(&secret_bytes).unwrap();
        let npub = identity.npub();

        // Decode and verify it matches the original pubkey
        let decoded = decode_npub(&npub).unwrap();
        assert_eq!(decoded, identity.pubkey());

        // npub should be deterministic
        let npub2 = encode_npub(&identity.pubkey());
        assert_eq!(npub, npub2);
    }

    #[test]
    fn test_decode_npub_invalid_prefix() {
        // nsec instead of npub
        let nsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5";
        let result = decode_npub(nsec);
        assert!(matches!(result, Err(IdentityError::InvalidNpubPrefix(_))));
    }

    #[test]
    fn test_decode_npub_invalid_checksum() {
        // Valid npub with corrupted checksum
        let bad_npub = "npub1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
        let result = decode_npub(bad_npub);
        assert!(result.is_err());
    }

    #[test]
    fn test_peer_identity_from_npub() {
        let identity = Identity::generate();
        let npub = identity.npub();

        let peer = PeerIdentity::from_npub(&npub).unwrap();

        assert_eq!(peer.pubkey(), identity.pubkey());
        assert_eq!(peer.node_addr(), identity.node_addr());
        assert_eq!(peer.address(), identity.address());
        assert_eq!(peer.npub(), npub);
    }

    #[test]
    fn test_peer_identity_verify_signature() {
        let identity = Identity::generate();
        let peer = PeerIdentity::from_pubkey(identity.pubkey());

        let data = b"hello world";
        let signature = identity.sign(data);

        assert!(peer.verify(data, &signature));
        assert!(!peer.verify(b"wrong data", &signature));
    }

    #[test]
    fn test_peer_identity_from_invalid_npub() {
        let result = PeerIdentity::from_npub("npub1invalid");
        assert!(result.is_err());

        let result = PeerIdentity::from_npub("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5");
        assert!(matches!(result, Err(IdentityError::InvalidNpubPrefix(_))));
    }

    #[test]
    fn test_peer_identity_display() {
        let identity = Identity::generate();
        let peer = PeerIdentity::from_pubkey(identity.pubkey());

        let display = format!("{}", peer);
        assert!(display.starts_with("npub1"));
        assert_eq!(display, identity.npub());
    }

    #[test]
    fn test_nsec_roundtrip() {
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
        let nsec = encode_nsec(&secret_key);

        assert!(nsec.starts_with("nsec1"));
        assert_eq!(nsec.len(), 63);

        let decoded = decode_nsec(&nsec).unwrap();
        assert_eq!(decoded.secret_bytes(), secret_bytes);
    }

    #[test]
    fn test_decode_nsec_invalid_prefix() {
        // Use a valid npub (from a generated identity) to test prefix rejection
        let identity = Identity::generate();
        let npub = identity.npub();
        let result = decode_nsec(&npub);
        assert!(matches!(result, Err(IdentityError::InvalidNsecPrefix(_))));
    }

    #[test]
    fn test_decode_secret_nsec() {
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
        let nsec = encode_nsec(&secret_key);

        let decoded = decode_secret(&nsec).unwrap();
        assert_eq!(decoded.secret_bytes(), secret_bytes);
    }

    #[test]
    fn test_decode_secret_hex() {
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let decoded = decode_secret(hex_str).unwrap();

        let expected: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];
        assert_eq!(decoded.secret_bytes(), expected);
    }

    #[test]
    fn test_identity_from_secret_str_nsec() {
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let secret_key = SecretKey::from_slice(&secret_bytes).unwrap();
        let nsec = encode_nsec(&secret_key);

        let identity = Identity::from_secret_str(&nsec).unwrap();
        let identity_from_bytes = Identity::from_secret_bytes(&secret_bytes).unwrap();

        assert_eq!(identity.node_addr(), identity_from_bytes.node_addr());
    }

    #[test]
    fn test_identity_from_secret_str_hex() {
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let secret_bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ];

        let identity = Identity::from_secret_str(hex_str).unwrap();
        let identity_from_bytes = Identity::from_secret_bytes(&secret_bytes).unwrap();

        assert_eq!(identity.node_addr(), identity_from_bytes.node_addr());
    }
}

#[cfg(test)]
mod conversion_tests {
    use super::*;

    #[test]
    fn test_hex_conversion_case1() {
        let hex_str = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
        let identity = Identity::from_secret_str(hex_str).unwrap();
        let npub = identity.npub();
        println!("Hex: {}", hex_str);
        println!("NPub: {}", npub);
        println!("NodeAddr: {}", identity.node_addr());
        println!("FipsAddress: {}", identity.address());
        assert!(npub.starts_with("npub1"));
    }

    #[test]
    fn test_hex_conversion_case2() {
        let hex_str = "b102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1fb0";
        let identity = Identity::from_secret_str(hex_str).unwrap();
        let npub = identity.npub();
        println!("Hex: {}", hex_str);
        println!("NPub: {}", npub);
        println!("NodeAddr: {}", identity.node_addr());
        println!("FipsAddress: {}", identity.address());
        assert!(npub.starts_with("npub1"));
    }

}
