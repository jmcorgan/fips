//! Local node identity with signing capability.

use secp256k1::{Keypair, PublicKey, SecretKey, XOnlyPublicKey};
use std::fmt;
use zeroize::Zeroize;

use super::auth::{AuthResponse, auth_challenge_digest};
use super::encoding::{decode_secret, encode_npub};
use super::{FipsAddress, IdentityError, NodeAddr, sha256};

/// A FIPS node identity consisting of a keypair and derived identifiers.
///
/// The identity holds the secp256k1 keypair and provides methods for signing
/// and verifying protocol messages.
///
/// The keypair is the node's long-term private key. It is erased when the
/// identity is dropped, and every constructor below erases the intermediate
/// secret it built the identity from. All of that clears the copies this
/// crate owns, not every copy that ever existed: `secp256k1` names its erase
/// non-secure because the compiler may duplicate or move the bytes to places
/// no code here can name.
#[derive(Clone)]
pub struct Identity {
    keypair: Keypair,
    node_addr: NodeAddr,
    address: FipsAddress,
}

impl Identity {
    /// Create a new random identity.
    pub fn generate() -> Self {
        let mut secret_bytes = [0u8; 32];
        rand::Rng::fill_bytes(&mut rand::rng(), &mut secret_bytes);
        let mut secret_key =
            SecretKey::from_slice(&secret_bytes).expect("32 random bytes is a valid secret key");
        let identity = Self::from_secret_key(secret_key);
        secret_bytes.zeroize();
        secret_key.non_secure_erase();
        identity
    }

    /// Create an identity from an existing keypair.
    pub fn from_keypair(mut keypair: Keypair) -> Self {
        let (pubkey, _parity) = keypair.x_only_public_key();
        let node_addr = NodeAddr::from_pubkey(&pubkey);
        let address = FipsAddress::from_node_addr(&node_addr);
        let identity = Self {
            keypair,
            node_addr,
            address,
        };
        keypair.non_secure_erase();
        identity
    }

    /// Create an identity from a secret key.
    pub fn from_secret_key(mut secret_key: SecretKey) -> Self {
        let mut keypair = Keypair::from_secret_key(&super::SECP, &secret_key);
        let identity = Self::from_keypair(keypair);
        keypair.non_secure_erase();
        secret_key.non_secure_erase();
        identity
    }

    /// Create an identity from secret key bytes.
    pub fn from_secret_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        let mut secret_key = SecretKey::from_slice(bytes)?;
        let identity = Self::from_secret_key(secret_key);
        secret_key.non_secure_erase();
        Ok(identity)
    }

    /// Create an identity from an nsec string (bech32) or hex-encoded secret.
    pub fn from_secret_str(s: &str) -> Result<Self, IdentityError> {
        let mut secret_key = decode_secret(s)?;
        let identity = Self::from_secret_key(secret_key);
        secret_key.non_secure_erase();
        Ok(identity)
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
        let digest = sha256(data);
        super::SECP.sign_schnorr(&digest, &self.keypair)
    }

    /// Create an authentication response for a challenge.
    ///
    /// The response signs: SHA256("fips-auth-v1" || challenge || timestamp)
    pub fn sign_challenge(&self, challenge: &[u8; 32], timestamp: u64) -> AuthResponse {
        let digest = auth_challenge_digest(challenge, timestamp);
        let signature = super::SECP.sign_schnorr(&digest, &self.keypair);
        AuthResponse {
            pubkey: self.pubkey(),
            timestamp,
            signature,
        }
    }
}

impl Drop for Identity {
    /// Erase the long-term private key this identity owns.
    ///
    /// `Keypair` is `Copy` and so cannot clear itself on drop; `Identity` is
    /// not, so it does it for the copy it holds. See the type's own
    /// documentation for what that does and does not reach.
    fn drop(&mut self) {
        self.keypair.non_secure_erase();
    }
}

/// A `Keypair` copy that is erased when it goes out of scope.
///
/// `Keypair` is `Copy` and so cannot clear itself on drop. A frame that holds
/// a copy of the node's long-term private key across several exit paths —
/// early error returns, `?`, a normal return — would otherwise need an erase
/// written at each one, and a missed path is invisible. Holding the copy here
/// instead makes the clearing structural.
///
/// This clears the copy this guard owns, not every copy that ever existed:
/// `secp256k1` names its erase non-secure because the compiler may duplicate
/// or move the bytes to places no code here can name.
pub(crate) struct ErasingKeypair(Keypair);

impl ErasingKeypair {
    /// Take a copy of `source` into the guard and erase `source` in place, so
    /// the caller's own binding does not outlive the move.
    pub(crate) fn take(source: &mut Keypair) -> Self {
        let guarded = Self(*source);
        source.non_secure_erase();
        guarded
    }

    /// Borrow the guarded keypair.
    pub(crate) fn get(&self) -> &Keypair {
        &self.0
    }
}

impl Drop for ErasingKeypair {
    fn drop(&mut self) {
        self.0.non_secure_erase();
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
