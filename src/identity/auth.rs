//! Authentication challenge-response protocol.

use rand::Rng;
use secp256k1::XOnlyPublicKey;
use sha2::{Digest, Sha256};

use super::{IdentityError, NodeAddr};

/// Domain separation string for authentication challenges.
const AUTH_DOMAIN: &[u8] = b"fips-auth-v1";

/// A 32-byte random authentication challenge.
#[derive(Clone, Copy, Debug)]
pub struct AuthChallenge([u8; 32]);

impl AuthChallenge {
    /// Generate a new random challenge.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
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

        super::SECP
            .verify_schnorr(&response.signature, &digest, &response.pubkey)
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
pub(super) fn auth_challenge_digest(challenge: &[u8; 32], timestamp: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(AUTH_DOMAIN);
    hasher.update(challenge);
    hasher.update(timestamp.to_be_bytes());
    let result = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&result);
    digest
}
