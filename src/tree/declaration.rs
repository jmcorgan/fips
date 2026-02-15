//! Parent declarations for the spanning tree.

use secp256k1::schnorr::Signature;
use secp256k1::XOnlyPublicKey;
use std::fmt;

use super::TreeError;
use crate::{Identity, NodeAddr};

/// A node's declaration of its parent in the spanning tree.
///
/// Each node periodically announces its parent selection. The declaration
/// includes a monotonic sequence number for freshness and a signature
/// for authenticity. When `parent_id == node_addr`, the node declares itself
/// as a root candidate.
#[derive(Clone)]
pub struct ParentDeclaration {
    /// The node making this declaration.
    node_addr: NodeAddr,
    /// The selected parent (equals node_addr if self-declaring as root).
    parent_id: NodeAddr,
    /// Monotonically increasing sequence number.
    sequence: u64,
    /// Timestamp when this declaration was created (Unix seconds).
    timestamp: u64,
    /// Schnorr signature over the declaration fields.
    signature: Option<Signature>,
}

impl ParentDeclaration {
    /// Create a new unsigned parent declaration.
    ///
    /// The declaration must be signed before transmission using `set_signature()`.
    pub fn new(node_addr: NodeAddr, parent_id: NodeAddr, sequence: u64, timestamp: u64) -> Self {
        Self {
            node_addr,
            parent_id,
            sequence,
            timestamp,
            signature: None,
        }
    }

    /// Create a self-declaration (node is root candidate).
    pub fn self_root(node_addr: NodeAddr, sequence: u64, timestamp: u64) -> Self {
        Self::new(node_addr, node_addr, sequence, timestamp)
    }

    /// Create a declaration with a pre-computed signature.
    pub fn with_signature(
        node_addr: NodeAddr,
        parent_id: NodeAddr,
        sequence: u64,
        timestamp: u64,
        signature: Signature,
    ) -> Self {
        Self {
            node_addr,
            parent_id,
            sequence,
            timestamp,
            signature: Some(signature),
        }
    }

    /// Get the declaring node's ID.
    pub fn node_addr(&self) -> &NodeAddr {
        &self.node_addr
    }

    /// Get the parent node's ID.
    pub fn parent_id(&self) -> &NodeAddr {
        &self.parent_id
    }

    /// Get the sequence number.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get the signature, if set.
    pub fn signature(&self) -> Option<&Signature> {
        self.signature.as_ref()
    }

    /// Set the signature after signing.
    pub fn set_signature(&mut self, signature: Signature) {
        self.signature = Some(signature);
    }

    /// Sign this declaration with the given identity.
    ///
    /// The identity's node_addr must match this declaration's node_addr.
    /// Returns an error if the node_addrs don't match.
    pub fn sign(&mut self, identity: &Identity) -> Result<(), TreeError> {
        if identity.node_addr() != &self.node_addr {
            return Err(TreeError::InvalidSignature(self.node_addr));
        }
        let signature = identity.sign(&self.signing_bytes());
        self.signature = Some(signature);
        Ok(())
    }

    /// Check if this is a root declaration (parent == self).
    pub fn is_root(&self) -> bool {
        self.node_addr == self.parent_id
    }

    /// Check if this declaration is signed.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Get the bytes that should be signed.
    ///
    /// Format: node_addr (16) || parent_id (16) || sequence (8) || timestamp (8)
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(48);
        bytes.extend_from_slice(self.node_addr.as_bytes());
        bytes.extend_from_slice(self.parent_id.as_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        bytes
    }

    /// Verify the signature on this declaration.
    ///
    /// Returns Ok(()) if the signature is valid, or an error otherwise.
    pub fn verify(&self, pubkey: &XOnlyPublicKey) -> Result<(), TreeError> {
        let signature = self
            .signature
            .as_ref()
            .ok_or(TreeError::InvalidSignature(self.node_addr))?;

        let secp = secp256k1::Secp256k1::verification_only();
        let hash = self.signing_hash();

        secp.verify_schnorr(signature, &hash, pubkey)
            .map_err(|_| TreeError::InvalidSignature(self.node_addr))
    }

    /// Compute the SHA-256 hash of the signing bytes.
    fn signing_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_bytes());
        hasher.finalize().into()
    }

    /// Check if this declaration is fresher than another.
    pub fn is_fresher_than(&self, other: &ParentDeclaration) -> bool {
        self.sequence > other.sequence
    }
}

impl fmt::Debug for ParentDeclaration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParentDeclaration")
            .field("node_addr", &self.node_addr)
            .field("parent_id", &self.parent_id)
            .field("sequence", &self.sequence)
            .field("is_root", &self.is_root())
            .field("signed", &self.is_signed())
            .finish()
    }
}

impl PartialEq for ParentDeclaration {
    fn eq(&self, other: &Self) -> bool {
        self.node_addr == other.node_addr
            && self.parent_id == other.parent_id
            && self.sequence == other.sequence
            && self.timestamp == other.timestamp
    }
}

impl Eq for ParentDeclaration {}
