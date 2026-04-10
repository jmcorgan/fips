//! TreeAnnounce message: spanning tree state propagation.

use super::error::ProtocolError;
use super::link::LinkMessageType;
use crate::NodeAddr;
use crate::tree::{CoordEntry, ParentDeclaration, TreeCoordinate};
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

    /// Encode as link-layer plaintext (includes msg_type byte).
    ///
    /// The declaration must be signed. The encoded format is:
    /// ```text
    /// [0x10][version:1][sequence:8 LE][timestamp:8 LE][parent:16]
    /// [ancestry_count:2 LE][entries:32×n][signature:64]
    /// ```
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        let signature = self
            .declaration
            .signature()
            .ok_or(ProtocolError::InvalidSignature)?;

        let entries = self.ancestry.entries();
        let ancestry_count = entries.len() as u16;
        let size = 1 + Self::MIN_PAYLOAD_SIZE + entries.len() * CoordEntry::WIRE_SIZE;
        let mut buf = Vec::with_capacity(size);

        // msg_type
        buf.push(LinkMessageType::TreeAnnounce.to_byte());
        // version
        buf.push(Self::VERSION_1);
        // sequence (8 LE)
        buf.extend_from_slice(&self.declaration.sequence().to_le_bytes());
        // timestamp (8 LE)
        buf.extend_from_slice(&self.declaration.timestamp().to_le_bytes());
        // parent (16)
        buf.extend_from_slice(self.declaration.parent_id().as_bytes());
        // ancestry_count (2 LE)
        buf.extend_from_slice(&ancestry_count.to_le_bytes());
        // ancestry entries (32 bytes each)
        for entry in entries {
            buf.extend_from_slice(entry.node_addr.as_bytes()); // 16
            buf.extend_from_slice(&entry.sequence.to_le_bytes()); // 8
            buf.extend_from_slice(&entry.timestamp.to_le_bytes()); // 8
        }
        // outer signature (64)
        buf.extend_from_slice(signature.as_ref());

        Ok(buf)
    }

    /// Decode from link-layer payload (after msg_type byte stripped by dispatcher).
    ///
    /// The payload starts with the version byte.
    pub fn decode(payload: &[u8]) -> Result<Self, ProtocolError> {
        if payload.len() < Self::MIN_PAYLOAD_SIZE {
            return Err(ProtocolError::MessageTooShort {
                expected: Self::MIN_PAYLOAD_SIZE,
                got: payload.len(),
            });
        }

        let mut pos = 0;

        // version
        let version = payload[pos];
        pos += 1;
        if version != Self::VERSION_1 {
            return Err(ProtocolError::UnsupportedVersion(version));
        }

        // sequence (8 LE)
        let sequence = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad sequence".into()))?,
        );
        pos += 8;

        // timestamp (8 LE)
        let timestamp = u64::from_le_bytes(
            payload[pos..pos + 8]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad timestamp".into()))?,
        );
        pos += 8;

        // parent (16)
        let parent = NodeAddr::from_bytes(
            payload[pos..pos + 16]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad parent".into()))?,
        );
        pos += 16;

        // ancestry_count (2 LE)
        let ancestry_count = u16::from_le_bytes(
            payload[pos..pos + 2]
                .try_into()
                .map_err(|_| ProtocolError::Malformed("bad ancestry count".into()))?,
        ) as usize;
        pos += 2;

        // Validate remaining length: entries + signature
        let expected_remaining = ancestry_count * CoordEntry::WIRE_SIZE + 64;
        if payload.len() - pos < expected_remaining {
            return Err(ProtocolError::MessageTooShort {
                expected: pos + expected_remaining,
                got: payload.len(),
            });
        }

        // ancestry entries (32 bytes each)
        let mut entries = Vec::with_capacity(ancestry_count);
        for _ in 0..ancestry_count {
            let node_addr = NodeAddr::from_bytes(
                payload[pos..pos + 16]
                    .try_into()
                    .map_err(|_| ProtocolError::Malformed("bad entry node_addr".into()))?,
            );
            pos += 16;
            let entry_seq = u64::from_le_bytes(
                payload[pos..pos + 8]
                    .try_into()
                    .map_err(|_| ProtocolError::Malformed("bad entry sequence".into()))?,
            );
            pos += 8;
            let entry_ts = u64::from_le_bytes(
                payload[pos..pos + 8]
                    .try_into()
                    .map_err(|_| ProtocolError::Malformed("bad entry timestamp".into()))?,
            );
            pos += 8;
            entries.push(CoordEntry::new(node_addr, entry_seq, entry_ts));
        }

        // signature (64)
        let sig_bytes: [u8; 64] = payload[pos..pos + 64]
            .try_into()
            .map_err(|_| ProtocolError::Malformed("bad signature".into()))?;
        let signature =
            Signature::from_slice(&sig_bytes).map_err(|_| ProtocolError::InvalidSignature)?;

        // The first entry's node_addr is the declaring node
        if entries.is_empty() {
            return Err(ProtocolError::Malformed(
                "ancestry must have at least one entry".into(),
            ));
        }
        let node_addr = entries[0].node_addr;

        let declaration =
            ParentDeclaration::with_signature(node_addr, parent, sequence, timestamp, signature);

        let ancestry = TreeCoordinate::new(entries)
            .map_err(|e| ProtocolError::Malformed(format!("bad ancestry: {}", e)))?;

        Ok(Self {
            declaration,
            ancestry,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
    }

    #[test]
    fn test_tree_announce() {
        let node = make_node_addr(1);
        let parent = make_node_addr(2);
        let decl = ParentDeclaration::new(node, parent, 1, 1000);
        let ancestry = make_coords(&[1, 2, 0]);

        let announce = TreeAnnounce::new(decl, ancestry);

        assert_eq!(announce.declaration.node_addr(), &node);
        assert_eq!(announce.ancestry.depth(), 2);
    }

    #[test]
    fn test_tree_announce_encode_decode_root() {
        use crate::identity::Identity;

        let identity = Identity::generate();
        let node_addr = *identity.node_addr();

        // Root declaration: parent == self
        let mut decl = ParentDeclaration::new(node_addr, node_addr, 1, 5000);
        decl.sign(&identity).unwrap();

        // Root ancestry: just the root itself
        let ancestry = TreeCoordinate::new(vec![CoordEntry::new(node_addr, 1, 5000)]).unwrap();

        let announce = TreeAnnounce::new(decl, ancestry);
        let encoded = announce.encode().unwrap();

        // msg_type (1) + version (1) + seq (8) + ts (8) + parent (16) + count (2) + 1 entry (32) + sig (64) = 132
        assert_eq!(encoded.len(), 132);
        assert_eq!(encoded[0], 0x10); // LinkMessageType::TreeAnnounce

        // Decode strips msg_type byte (as dispatcher does)
        let decoded = TreeAnnounce::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.declaration.node_addr(), &node_addr);
        assert_eq!(decoded.declaration.parent_id(), &node_addr);
        assert_eq!(decoded.declaration.sequence(), 1);
        assert_eq!(decoded.declaration.timestamp(), 5000);
        assert!(decoded.declaration.is_root());
        assert!(decoded.declaration.is_signed());
        assert_eq!(decoded.ancestry.depth(), 0); // root has depth 0
        assert_eq!(decoded.ancestry.entries().len(), 1);
        assert_eq!(decoded.ancestry.entries()[0].node_addr, node_addr);
        assert_eq!(decoded.ancestry.entries()[0].sequence, 1);
        assert_eq!(decoded.ancestry.entries()[0].timestamp, 5000);
    }

    #[test]
    fn test_tree_announce_encode_decode_depth3() {
        use crate::identity::Identity;

        let identity = Identity::generate();
        let node_addr = *identity.node_addr();
        let parent = make_node_addr(2);
        let grandparent = make_node_addr(3);
        let root = make_node_addr(4);

        let mut decl = ParentDeclaration::new(node_addr, parent, 5, 10000);
        decl.sign(&identity).unwrap();

        let ancestry = TreeCoordinate::new(vec![
            CoordEntry::new(node_addr, 5, 10000),
            CoordEntry::new(parent, 4, 9000),
            CoordEntry::new(grandparent, 3, 8000),
            CoordEntry::new(root, 2, 7000),
        ])
        .unwrap();

        let announce = TreeAnnounce::new(decl, ancestry);
        let encoded = announce.encode().unwrap();

        // 1 + 99 + 4*32 = 228
        assert_eq!(encoded.len(), 228);

        let decoded = TreeAnnounce::decode(&encoded[1..]).unwrap();

        assert_eq!(decoded.declaration.node_addr(), &node_addr);
        assert_eq!(decoded.declaration.parent_id(), &parent);
        assert_eq!(decoded.declaration.sequence(), 5);
        assert_eq!(decoded.declaration.timestamp(), 10000);
        assert!(!decoded.declaration.is_root());
        assert_eq!(decoded.ancestry.depth(), 3);
        assert_eq!(decoded.ancestry.entries().len(), 4);

        // Verify all entries preserved
        let entries = decoded.ancestry.entries();
        assert_eq!(entries[0].node_addr, node_addr);
        assert_eq!(entries[0].sequence, 5);
        assert_eq!(entries[1].node_addr, parent);
        assert_eq!(entries[1].sequence, 4);
        assert_eq!(entries[2].node_addr, grandparent);
        assert_eq!(entries[2].timestamp, 8000);
        assert_eq!(entries[3].node_addr, root);
        assert_eq!(entries[3].timestamp, 7000);

        // Root ID is last entry
        assert_eq!(decoded.ancestry.root_id(), &root);
    }

    #[test]
    fn test_tree_announce_decode_unsupported_version() {
        use crate::identity::Identity;

        let identity = Identity::generate();
        let node_addr = *identity.node_addr();

        let mut decl = ParentDeclaration::new(node_addr, node_addr, 1, 1000);
        decl.sign(&identity).unwrap();

        let ancestry = TreeCoordinate::new(vec![CoordEntry::new(node_addr, 1, 1000)]).unwrap();
        let announce = TreeAnnounce::new(decl, ancestry);
        let mut encoded = announce.encode().unwrap();

        // Corrupt version byte (byte index 1, after msg_type)
        encoded[1] = 0xFF;

        let result = TreeAnnounce::decode(&encoded[1..]);
        assert!(matches!(
            result,
            Err(ProtocolError::UnsupportedVersion(0xFF))
        ));
    }

    #[test]
    fn test_tree_announce_decode_truncated() {
        // Way too short
        let result = TreeAnnounce::decode(&[0x01]);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooShort { expected: 99, .. })
        ));

        // Just under minimum (98 bytes)
        let short = vec![0u8; 98];
        let result = TreeAnnounce::decode(&short);
        assert!(matches!(
            result,
            Err(ProtocolError::MessageTooShort { expected: 99, .. })
        ));
    }

    #[test]
    fn test_tree_announce_decode_ancestry_count_mismatch() {
        use crate::identity::Identity;

        let identity = Identity::generate();
        let node_addr = *identity.node_addr();

        let mut decl = ParentDeclaration::new(node_addr, node_addr, 1, 1000);
        decl.sign(&identity).unwrap();

        let ancestry = TreeCoordinate::new(vec![CoordEntry::new(node_addr, 1, 1000)]).unwrap();
        let announce = TreeAnnounce::new(decl, ancestry);
        let mut encoded = announce.encode().unwrap();

        // The ancestry_count is at offset: 1 (msg_type) + 1 (version) + 8 (seq) + 8 (ts) + 16 (parent) = 34
        // Set ancestry_count to 5 but we only have 1 entry's worth of data
        encoded[34] = 5;
        encoded[35] = 0;

        let result = TreeAnnounce::decode(&encoded[1..]);
        assert!(matches!(result, Err(ProtocolError::MessageTooShort { .. })));
    }

    #[test]
    fn test_tree_announce_encode_unsigned_fails() {
        let node = make_node_addr(1);
        let decl = ParentDeclaration::new(node, node, 1, 1000);
        let ancestry = make_coords(&[1, 0]);

        let announce = TreeAnnounce::new(decl, ancestry);
        let result = announce.encode();
        assert!(matches!(result, Err(ProtocolError::InvalidSignature)));
    }
}
