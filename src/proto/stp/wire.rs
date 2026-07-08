//! TreeAnnounce message: spanning tree state propagation.

use super::{CoordEntry, ParentDeclaration, TreeCoordinate, TreeError};
use crate::NodeAddr;
use crate::proto::Error;
use crate::proto::codec::{Reader, Writer};
use crate::proto::link::LinkMessageType;
use secp256k1::schnorr::Signature;

/// Spanning tree announcement carrying parent declaration and ancestry.
///
/// Sent to peers to propagate tree state. The declaration proves the
/// sender's parent selection; the ancestry provides path to root for
/// routing decisions.
#[derive(Clone, Debug)]
pub struct TreeAnnounce {
    /// The sender's parent declaration.
    pub declaration: ParentDeclaration,
    /// Full ancestry from sender to root.
    pub ancestry: TreeCoordinate,
}

impl TreeAnnounce {
    /// TreeAnnounce wire format version 1.
    pub const VERSION_1: u8 = 0x01;

    /// Minimum payload size (after msg_type stripped by dispatcher):
    /// version(1) + sequence(8) + timestamp(8) + parent(16) + ancestry_count(2) + signature(64) = 99
    const MIN_PAYLOAD_SIZE: usize = 99;

    /// Create a new TreeAnnounce message.
    pub fn new(declaration: ParentDeclaration, ancestry: TreeCoordinate) -> Self {
        Self {
            declaration,
            ancestry,
        }
    }

    /// Validate that the ancestry is structurally consistent with the signed
    /// declaration.
    ///
    /// Expected properties:
    /// - the first ancestry entry is the declaring node's `node_addr`
    /// - a root declaration has exactly one ancestry entry
    /// - a non-root declaration has at least two ancestry entries
    /// - for a non-root declaration, the second ancestry entry matches `parent_id`
    /// - the final ancestry entry is the advertised root
    /// - the advertised root is the smallest `node_addr` in the ancestry
    pub fn validate_semantics(&self) -> Result<(), TreeError> {
        let entries = self.ancestry.entries();
        let declared_node = *self.declaration.node_addr();
        let declared_parent = *self.declaration.parent_id();

        if entries[0].node_addr != declared_node {
            return Err(TreeError::AncestryNodeMismatch {
                declared: declared_node,
                ancestry: entries[0].node_addr,
            });
        }

        if self.declaration.is_root() {
            if entries.len() != 1 {
                return Err(TreeError::RootDeclarationMismatch);
            }
        } else {
            let ancestry_parent = entries.get(1).ok_or(TreeError::AncestryTooShort)?.node_addr;
            if ancestry_parent != declared_parent {
                return Err(TreeError::AncestryParentMismatch {
                    declared: declared_parent,
                    ancestry: ancestry_parent,
                });
            }
        }

        let advertised_root = *self.ancestry.root_id();
        let minimum = entries
            .iter()
            .map(|entry| entry.node_addr)
            .min()
            .expect("TreeCoordinate is never empty");
        if advertised_root != minimum {
            return Err(TreeError::AncestryRootNotMinimum {
                advertised: advertised_root,
                minimum,
            });
        }

        Ok(())
    }

    /// Encode as link-layer plaintext (includes msg_type byte).
    ///
    /// The declaration must be signed. The encoded format is:
    /// ```text
    /// [0x10][version:1][sequence:8 LE][timestamp:8 LE][parent:16]
    /// [ancestry_count:2 LE][entries:32×n][signature:64]
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let signature = self
            .declaration
            .signature()
            .ok_or(Error::InvalidSignature)?;

        let entries = self.ancestry.entries();
        let ancestry_count = entries.len() as u16;
        let size = 1 + Self::MIN_PAYLOAD_SIZE + entries.len() * CoordEntry::WIRE_SIZE;
        let mut w = Writer::with_capacity(size);

        // msg_type
        w.write_u8(LinkMessageType::TreeAnnounce.to_byte());
        // version
        w.write_u8(Self::VERSION_1);
        // sequence (8 LE)
        w.write_u64_le(self.declaration.sequence());
        // timestamp (8 LE)
        w.write_u64_le(self.declaration.timestamp());
        // parent (16)
        w.write_bytes(self.declaration.parent_id().as_bytes());
        // ancestry_count (2 LE)
        w.write_u16_le(ancestry_count);
        // ancestry entries (32 bytes each)
        for entry in entries {
            w.write_bytes(entry.node_addr.as_bytes()); // 16
            w.write_u64_le(entry.sequence); // 8
            w.write_u64_le(entry.timestamp); // 8
        }
        // outer signature (64)
        w.write_bytes(signature.as_ref());

        Ok(w.into_vec())
    }

    /// Decode from link-layer payload (after msg_type byte stripped by dispatcher).
    ///
    /// The payload starts with the version byte.
    pub fn decode(payload: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader::new(payload);
        reader.require(Self::MIN_PAYLOAD_SIZE)?;

        // version
        let version = reader.read_u8()?;
        if version != Self::VERSION_1 {
            return Err(Error::UnsupportedVersion(version));
        }

        // sequence (8 LE)
        let sequence = reader.read_u64_le()?;

        // timestamp (8 LE)
        let timestamp = reader.read_u64_le()?;

        // parent (16)
        let parent = NodeAddr::from_bytes(reader.read_array::<16>()?);

        // ancestry_count (2 LE)
        let ancestry_count = reader.read_u16_le()? as usize;

        // Validate remaining length: entries + signature
        let expected_remaining = ancestry_count * CoordEntry::WIRE_SIZE + 64;
        reader.require(expected_remaining)?;

        // ancestry entries (32 bytes each)
        let mut entries = Vec::with_capacity(ancestry_count);
        for _ in 0..ancestry_count {
            let node_addr = NodeAddr::from_bytes(reader.read_array::<16>()?);
            let entry_seq = reader.read_u64_le()?;
            let entry_ts = reader.read_u64_le()?;
            entries.push(CoordEntry::new(node_addr, entry_seq, entry_ts));
        }

        // signature (64)
        let sig_bytes: [u8; 64] = reader.read_array::<64>()?;
        // Validate the signature parses as a well-formed schnorr signature (the
        // codec's only crypto touch, §11 w2); store the raw bytes so the in-core
        // declaration carries no `secp256k1` dependency. Actual verification is a
        // shell concern (§6).
        Signature::from_slice(&sig_bytes).map_err(|_| Error::InvalidSignature)?;

        // The first entry's node_addr is the declaring node
        if entries.is_empty() {
            return Err(Error::Malformed("ancestry must have at least one entry"));
        }
        let node_addr = entries[0].node_addr;

        let declaration =
            ParentDeclaration::with_signature(node_addr, parent, sequence, timestamp, sig_bytes);

        let ancestry = TreeCoordinate::new(entries).map_err(Error::BadCoord)?;

        Ok(Self {
            declaration,
            ancestry,
        })
    }
}
