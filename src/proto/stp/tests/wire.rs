//! TreeAnnounce wire codec unit tests.

use super::util::{make_coords, make_node_addr};
use crate::identity::Identity;
use crate::proto::Error;
use crate::proto::stp::wire::TreeAnnounce;
use crate::proto::stp::{CoordEntry, ParentDeclaration, TreeCoordinate, TreeError};

/// Sign a declaration in place. In production the shell owns the key-crypto
/// (§6); this test-local helper keeps the sign/verify boundary out of the
/// in-core `state.rs` while letting the codec tests build signed messages.
fn sign_decl(decl: &mut ParentDeclaration, identity: &Identity) {
    let sig = identity.sign(&decl.signing_bytes());
    decl.set_signature(sig.to_byte_array());
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
    sign_decl(&mut decl, &identity);

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
    sign_decl(&mut decl, &identity);

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
    sign_decl(&mut decl, &identity);

    let ancestry = TreeCoordinate::new(vec![CoordEntry::new(node_addr, 1, 1000)]).unwrap();
    let announce = TreeAnnounce::new(decl, ancestry);
    let mut encoded = announce.encode().unwrap();

    // Corrupt version byte (byte index 1, after msg_type)
    encoded[1] = 0xFF;

    let result = TreeAnnounce::decode(&encoded[1..]);
    assert!(matches!(result, Err(Error::UnsupportedVersion(0xFF))));
}

#[test]
fn test_tree_announce_decode_truncated() {
    // Way too short
    let result = TreeAnnounce::decode(&[0x01]);
    assert!(matches!(
        result,
        Err(Error::MessageTooShort { expected: 99, .. })
    ));

    // Just under minimum (98 bytes)
    let short = vec![0u8; 98];
    let result = TreeAnnounce::decode(&short);
    assert!(matches!(
        result,
        Err(Error::MessageTooShort { expected: 99, .. })
    ));
}

#[test]
fn test_tree_announce_decode_ancestry_count_mismatch() {
    use crate::identity::Identity;

    let identity = Identity::generate();
    let node_addr = *identity.node_addr();

    let mut decl = ParentDeclaration::new(node_addr, node_addr, 1, 1000);
    sign_decl(&mut decl, &identity);

    let ancestry = TreeCoordinate::new(vec![CoordEntry::new(node_addr, 1, 1000)]).unwrap();
    let announce = TreeAnnounce::new(decl, ancestry);
    let mut encoded = announce.encode().unwrap();

    // The ancestry_count is at offset: 1 (msg_type) + 1 (version) + 8 (seq) + 8 (ts) + 16 (parent) = 34
    // Set ancestry_count to 5 but we only have 1 entry's worth of data
    encoded[34] = 5;
    encoded[35] = 0;

    let result = TreeAnnounce::decode(&encoded[1..]);
    assert!(matches!(result, Err(Error::MessageTooShort { .. })));
}

#[test]
fn test_tree_announce_encode_unsigned_fails() {
    let node = make_node_addr(1);
    let decl = ParentDeclaration::new(node, node, 1, 1000);
    let ancestry = make_coords(&[1, 0]);

    let announce = TreeAnnounce::new(decl, ancestry);
    let result = announce.encode();
    assert!(matches!(result, Err(Error::InvalidSignature)));
}

/// Tests that a well-formed non-root ancestry is accepted.
#[test]
fn test_tree_announce_validate_semantics_accepts_valid_non_root() {
    use crate::identity::Identity;

    // Regenerate until the random identity's node_addr is numerically
    // larger than both fixed parent (02:..) and root (01:..), so the
    // root-minimum invariant holds deterministically.
    let identity = loop {
        let id = Identity::generate();
        if id.node_addr().as_bytes()[0] > 1 {
            break id;
        }
    };
    let node_addr = *identity.node_addr();
    let parent = make_node_addr(2);
    let root = make_node_addr(1);

    let mut decl = ParentDeclaration::new(node_addr, parent, 5, 1000);
    sign_decl(&mut decl, &identity);

    let ancestry = TreeCoordinate::new(vec![
        CoordEntry::new(node_addr, 5, 1000),
        CoordEntry::new(parent, 4, 900),
        CoordEntry::new(root, 3, 800),
    ])
    .unwrap();

    let announce = TreeAnnounce::new(decl, ancestry);
    assert!(announce.validate_semantics().is_ok());
}

/// Tests that an ancestry is rejected if the final node_addr is not the smallest entry in the path.
#[test]
fn test_tree_announce_validate_semantics_rejects_non_minimal_root() {
    use crate::identity::Identity;

    let identity = Identity::generate();
    let node_addr = *identity.node_addr();
    let smaller = make_node_addr(0);
    let advertised_root = make_node_addr(1);

    let mut decl = ParentDeclaration::new(node_addr, smaller, 5, 1000);
    sign_decl(&mut decl, &identity);

    let ancestry = TreeCoordinate::new(vec![
        CoordEntry::new(node_addr, 5, 1000),
        CoordEntry::new(smaller, 4, 900),
        CoordEntry::new(advertised_root, 3, 800),
    ])
    .unwrap();

    let announce = TreeAnnounce::new(decl, ancestry);
    assert!(matches!(
        announce.validate_semantics(),
        Err(TreeError::AncestryRootNotMinimum {
            advertised,
            minimum,
        }) if advertised == advertised_root && minimum == smaller
    ));
}

/// Tests that an ancestry is rejected if the first ancestry hop does not match the signed parent_id.
#[test]
fn test_tree_announce_validate_semantics_rejects_parent_mismatch() {
    use crate::identity::Identity;

    let identity = Identity::generate();
    let node_addr = *identity.node_addr();
    let declared_parent = make_node_addr(2);
    let ancestry_parent = make_node_addr(3);

    let mut decl = ParentDeclaration::new(node_addr, declared_parent, 5, 1000);
    sign_decl(&mut decl, &identity);

    let ancestry = TreeCoordinate::new(vec![
        CoordEntry::new(node_addr, 5, 1000),
        CoordEntry::new(ancestry_parent, 4, 900),
        CoordEntry::new(make_node_addr(1), 3, 800),
    ])
    .unwrap();

    let announce = TreeAnnounce::new(decl, ancestry);
    assert!(matches!(
        announce.validate_semantics(),
        Err(TreeError::AncestryParentMismatch {
            declared,
            ancestry,
        }) if declared == declared_parent && ancestry == ancestry_parent
    ));
}

/// Tests that an ancestry is rejected if the first path entry does not match the signed sender node_addr.
#[test]
fn test_tree_announce_validate_semantics_rejects_sender_mismatch() {
    use crate::identity::Identity;

    let identity = Identity::generate();
    let node_addr = *identity.node_addr();
    let ancestry_sender = make_node_addr(9);
    let parent = make_node_addr(2);

    let mut decl = ParentDeclaration::new(node_addr, parent, 5, 1000);
    sign_decl(&mut decl, &identity);

    let ancestry = TreeCoordinate::new(vec![
        CoordEntry::new(ancestry_sender, 5, 1000),
        CoordEntry::new(parent, 4, 900),
        CoordEntry::new(make_node_addr(1), 3, 800),
    ])
    .unwrap();

    let announce = TreeAnnounce::new(decl, ancestry);
    assert!(matches!(
        announce.validate_semantics(),
        Err(TreeError::AncestryNodeMismatch {
            declared,
            ancestry,
        }) if declared == node_addr && ancestry == ancestry_sender
    ));
}

/// Tests that a self-root declaration is rejected if its ancestry contains extra ancestors.
#[test]
fn test_tree_announce_validate_semantics_rejects_root_with_ancestors() {
    use crate::identity::Identity;

    let identity = Identity::generate();
    let node_addr = *identity.node_addr();

    let mut decl = ParentDeclaration::self_root(node_addr, 5, 1000);
    sign_decl(&mut decl, &identity);

    let ancestry = TreeCoordinate::new(vec![
        CoordEntry::new(node_addr, 5, 1000),
        CoordEntry::new(make_node_addr(0), 4, 900),
    ])
    .unwrap();

    let announce = TreeAnnounce::new(decl, ancestry);
    assert!(matches!(
        announce.validate_semantics(),
        Err(TreeError::RootDeclarationMismatch)
    ));
}
