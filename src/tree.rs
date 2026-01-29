//! Spanning Tree Protocol Entities
//!
//! Tree coordinates and parent declarations for the FIPS spanning tree.
//! The spanning tree provides a routing topology where each node maintains
//! a path to a common root, enabling greedy distance-based routing.

use crate::{IdentityError, NodeId};
use secp256k1::schnorr::Signature;
use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use std::fmt;
use thiserror::Error;

/// Errors related to spanning tree operations.
#[derive(Debug, Error)]
pub enum TreeError {
    #[error("invalid tree coordinate: empty path")]
    EmptyCoordinate,

    #[error("invalid ancestry: does not reach claimed root")]
    AncestryNotToRoot,

    #[error("signature verification failed for node {0:?}")]
    InvalidSignature(NodeId),

    #[error("sequence number regression: got {got}, expected > {expected}")]
    SequenceRegression { got: u64, expected: u64 },

    #[error("parent not in peers: {0:?}")]
    ParentNotPeer(NodeId),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

/// A node's declaration of its parent in the spanning tree.
///
/// Each node periodically announces its parent selection. The declaration
/// includes a monotonic sequence number for freshness and a signature
/// for authenticity. When `parent_id == node_id`, the node declares itself
/// as a root candidate.
#[derive(Clone)]
pub struct ParentDeclaration {
    /// The node making this declaration.
    node_id: NodeId,
    /// The selected parent (equals node_id if self-declaring as root).
    parent_id: NodeId,
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
    pub fn new(node_id: NodeId, parent_id: NodeId, sequence: u64, timestamp: u64) -> Self {
        Self {
            node_id,
            parent_id,
            sequence,
            timestamp,
            signature: None,
        }
    }

    /// Create a self-declaration (node is root candidate).
    pub fn self_root(node_id: NodeId, sequence: u64, timestamp: u64) -> Self {
        Self::new(node_id, node_id, sequence, timestamp)
    }

    /// Create a declaration with a pre-computed signature.
    pub fn with_signature(
        node_id: NodeId,
        parent_id: NodeId,
        sequence: u64,
        timestamp: u64,
        signature: Signature,
    ) -> Self {
        Self {
            node_id,
            parent_id,
            sequence,
            timestamp,
            signature: Some(signature),
        }
    }

    /// Get the declaring node's ID.
    pub fn node_id(&self) -> &NodeId {
        &self.node_id
    }

    /// Get the parent node's ID.
    pub fn parent_id(&self) -> &NodeId {
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

    /// Check if this is a root declaration (parent == self).
    pub fn is_root(&self) -> bool {
        self.node_id == self.parent_id
    }

    /// Check if this declaration is signed.
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Get the bytes that should be signed.
    ///
    /// Format: node_id (32) || parent_id (32) || sequence (8) || timestamp (8)
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        bytes.extend_from_slice(self.node_id.as_bytes());
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
            .ok_or(TreeError::InvalidSignature(self.node_id))?;

        let secp = secp256k1::Secp256k1::verification_only();
        let hash = self.signing_hash();

        secp.verify_schnorr(signature, &hash, pubkey)
            .map_err(|_| TreeError::InvalidSignature(self.node_id))
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
            .field("node_id", &self.node_id)
            .field("parent_id", &self.parent_id)
            .field("sequence", &self.sequence)
            .field("is_root", &self.is_root())
            .field("signed", &self.is_signed())
            .finish()
    }
}

impl PartialEq for ParentDeclaration {
    fn eq(&self, other: &Self) -> bool {
        self.node_id == other.node_id
            && self.parent_id == other.parent_id
            && self.sequence == other.sequence
            && self.timestamp == other.timestamp
    }
}

impl Eq for ParentDeclaration {}

/// A node's coordinates in the spanning tree.
///
/// Coordinates are the path from the node to the root:
/// `[self, parent, grandparent, ..., root]`
///
/// The coordinate enables greedy routing via tree distance calculation.
/// Two nodes can compute the hops between them by finding their lowest
/// common ancestor (LCA) in the tree.
#[derive(Clone, PartialEq, Eq)]
pub struct TreeCoordinate(Vec<NodeId>);

impl TreeCoordinate {
    /// Create a coordinate from a path (self to root).
    ///
    /// The path must be non-empty and ordered from the node to the root.
    pub fn new(path: Vec<NodeId>) -> Result<Self, TreeError> {
        if path.is_empty() {
            return Err(TreeError::EmptyCoordinate);
        }
        Ok(Self(path))
    }

    /// Create a coordinate for a root node.
    pub fn root(node_id: NodeId) -> Self {
        Self(vec![node_id])
    }

    /// The node this coordinate belongs to (first element).
    pub fn node_id(&self) -> &NodeId {
        &self.0[0]
    }

    /// The root of the tree (last element).
    pub fn root_id(&self) -> &NodeId {
        self.0.last().expect("coordinate never empty")
    }

    /// The immediate parent (second element, or self if root).
    pub fn parent_id(&self) -> &NodeId {
        self.0.get(1).unwrap_or(&self.0[0])
    }

    /// Depth in the tree (0 = root).
    pub fn depth(&self) -> usize {
        self.0.len() - 1
    }

    /// The full ancestry path.
    pub fn path(&self) -> &[NodeId] {
        &self.0
    }

    /// Check if this coordinate is a root (length 1).
    pub fn is_root(&self) -> bool {
        self.0.len() == 1
    }

    /// Calculate tree distance to another coordinate.
    ///
    /// Distance is hops through the lowest common ancestor (LCA).
    /// If the coordinates have different roots, returns usize::MAX.
    pub fn distance_to(&self, other: &TreeCoordinate) -> usize {
        // Different trees have infinite distance
        if self.root_id() != other.root_id() {
            return usize::MAX;
        }

        let lca_depth = self.lca_depth(other);
        let self_to_lca = self.depth() - lca_depth;
        let other_to_lca = other.depth() - lca_depth;
        self_to_lca + other_to_lca
    }

    /// Find the depth of the lowest common ancestor.
    ///
    /// Since coordinates are self-to-root, common ancestry is a suffix match.
    /// Returns the depth (from root) of the LCA.
    pub fn lca_depth(&self, other: &TreeCoordinate) -> usize {
        let mut common: usize = 0;
        let self_rev = self.0.iter().rev();
        let other_rev = other.0.iter().rev();

        for (a, b) in self_rev.zip(other_rev) {
            if a == b {
                common += 1;
            } else {
                break;
            }
        }

        // LCA depth is counted from root (depth 0)
        common.saturating_sub(1)
    }

    /// Get the lowest common ancestor node ID.
    pub fn lca(&self, other: &TreeCoordinate) -> Option<&NodeId> {
        let self_rev: Vec<_> = self.0.iter().rev().collect();
        let other_rev: Vec<_> = other.0.iter().rev().collect();

        let mut lca = None;
        for (a, b) in self_rev.iter().zip(other_rev.iter()) {
            if a == b {
                lca = Some(*a);
            } else {
                break;
            }
        }
        lca
    }

    /// Check if `other` is an ancestor (appears in our path after self).
    pub fn has_ancestor(&self, other: &NodeId) -> bool {
        self.0.iter().skip(1).any(|id| id == other)
    }

    /// Check if `other` is in our ancestry (including self).
    pub fn contains(&self, other: &NodeId) -> bool {
        self.0.iter().any(|id| id == other)
    }

    /// Get the ancestor at a specific depth from self.
    ///
    /// `ancestor_at(0)` returns self, `ancestor_at(1)` returns parent, etc.
    pub fn ancestor_at(&self, depth: usize) -> Option<&NodeId> {
        self.0.get(depth)
    }
}

impl fmt::Debug for TreeCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreeCoordinate(depth={}, path=[", self.depth())?;
        for (i, id) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, " → ")?;
            }
            // Show first 4 bytes of each node ID
            write!(f, "{:02x}{:02x}", id.as_bytes()[0], id.as_bytes()[1])?;
        }
        write!(f, "])")
    }
}

impl AsRef<[NodeId]> for TreeCoordinate {
    fn as_ref(&self) -> &[NodeId] {
        &self.0
    }
}

/// Local spanning tree state for a node.
///
/// Contains this node's declaration, coordinates, and view of peers'
/// tree positions. State is bounded by O(P × D) where P is peer count
/// and D is tree depth.
pub struct TreeState {
    /// This node's NodeId.
    my_node_id: NodeId,
    /// This node's current parent declaration.
    my_declaration: ParentDeclaration,
    /// This node's current coordinates (computed from declaration chain).
    my_coords: TreeCoordinate,
    /// The current elected root (smallest reachable node_id).
    root: NodeId,
    /// Each peer's most recent parent declaration.
    peer_declarations: HashMap<NodeId, ParentDeclaration>,
    /// Each peer's full ancestry to root.
    peer_ancestry: HashMap<NodeId, TreeCoordinate>,
}

impl TreeState {
    /// Create initial tree state for a node (as root candidate).
    ///
    /// The node starts as its own root until it learns of a smaller node_id.
    pub fn new(my_node_id: NodeId) -> Self {
        let my_declaration = ParentDeclaration::self_root(my_node_id, 0, 0);
        let my_coords = TreeCoordinate::root(my_node_id);

        Self {
            my_node_id,
            my_declaration,
            my_coords,
            root: my_node_id,
            peer_declarations: HashMap::new(),
            peer_ancestry: HashMap::new(),
        }
    }

    /// Get this node's NodeId.
    pub fn my_node_id(&self) -> &NodeId {
        &self.my_node_id
    }

    /// Get this node's current declaration.
    pub fn my_declaration(&self) -> &ParentDeclaration {
        &self.my_declaration
    }

    /// Get this node's current coordinates.
    pub fn my_coords(&self) -> &TreeCoordinate {
        &self.my_coords
    }

    /// Get the current root.
    pub fn root(&self) -> &NodeId {
        &self.root
    }

    /// Check if this node is currently the root.
    pub fn is_root(&self) -> bool {
        self.root == self.my_node_id
    }

    /// Get coordinates for a peer, if known.
    pub fn peer_coords(&self, peer_id: &NodeId) -> Option<&TreeCoordinate> {
        self.peer_ancestry.get(peer_id)
    }

    /// Get declaration for a peer, if known.
    pub fn peer_declaration(&self, peer_id: &NodeId) -> Option<&ParentDeclaration> {
        self.peer_declarations.get(peer_id)
    }

    /// Number of known peers.
    pub fn peer_count(&self) -> usize {
        self.peer_declarations.len()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeId> {
        self.peer_declarations.keys()
    }

    /// Add or update a peer's tree state.
    ///
    /// Returns true if the state was updated (new or fresher declaration).
    pub fn update_peer(
        &mut self,
        declaration: ParentDeclaration,
        ancestry: TreeCoordinate,
    ) -> bool {
        let peer_id = *declaration.node_id();

        // Check if this is a fresh update
        if let Some(existing) = self.peer_declarations.get(&peer_id)
            && !declaration.is_fresher_than(existing)
        {
            return false;
        }

        self.peer_declarations.insert(peer_id, declaration);
        self.peer_ancestry.insert(peer_id, ancestry);
        true
    }

    /// Remove a peer from the tree state.
    pub fn remove_peer(&mut self, peer_id: &NodeId) {
        self.peer_declarations.remove(peer_id);
        self.peer_ancestry.remove(peer_id);
    }

    /// Update this node's parent selection.
    ///
    /// Call this when switching parents. Updates the declaration and coordinates.
    pub fn set_parent(&mut self, parent_id: NodeId, sequence: u64, timestamp: u64) {
        self.my_declaration = ParentDeclaration::new(self.my_node_id, parent_id, sequence, timestamp);
        // Coordinates will be recomputed when ancestry is available
    }

    /// Update this node's coordinates based on current parent's ancestry.
    pub fn recompute_coords(&mut self) {
        if self.my_declaration.is_root() {
            self.my_coords = TreeCoordinate::root(self.my_node_id);
            self.root = self.my_node_id;
            return;
        }

        let parent_id = self.my_declaration.parent_id();
        if let Some(parent_coords) = self.peer_ancestry.get(parent_id) {
            // Our coords = [self] ++ parent_coords
            let mut path = vec![self.my_node_id];
            path.extend_from_slice(parent_coords.path());
            self.my_coords = TreeCoordinate::new(path).expect("non-empty path");
            self.root = *self.my_coords.root_id();
        }
    }

    /// Calculate tree distance to a peer.
    pub fn distance_to_peer(&self, peer_id: &NodeId) -> Option<usize> {
        self.peer_ancestry
            .get(peer_id)
            .map(|coords| self.my_coords.distance_to(coords))
    }

    /// Find the best next hop toward a destination.
    ///
    /// Returns the peer that minimizes tree distance to the destination.
    /// This is a stub - full implementation requires greedy routing logic.
    pub fn find_next_hop(&self, _dest_coords: &TreeCoordinate) -> Option<NodeId> {
        // Stub: would implement greedy tree routing
        None
    }

    /// Check if a parent switch to `candidate` would be beneficial.
    ///
    /// This is a stub - full implementation requires policy decisions.
    pub fn should_switch_parent(&self, _candidate: &NodeId) -> bool {
        // Stub: would evaluate parent switch criteria
        false
    }
}

impl fmt::Debug for TreeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreeState")
            .field("my_node_id", &self.my_node_id)
            .field("root", &self.root)
            .field("is_root", &self.is_root())
            .field("depth", &self.my_coords.depth())
            .field("peers", &self.peer_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node_id(val: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = val;
        NodeId::from_bytes(bytes)
    }

    // ===== TreeCoordinate Tests =====

    #[test]
    fn test_tree_coordinate_root() {
        let root_id = make_node_id(1);
        let coord = TreeCoordinate::root(root_id);

        assert!(coord.is_root());
        assert_eq!(coord.depth(), 0);
        assert_eq!(coord.node_id(), &root_id);
        assert_eq!(coord.root_id(), &root_id);
        assert_eq!(coord.parent_id(), &root_id);
    }

    #[test]
    fn test_tree_coordinate_path() {
        let node = make_node_id(1);
        let parent = make_node_id(2);
        let root = make_node_id(3);

        let coord = TreeCoordinate::new(vec![node, parent, root]).unwrap();

        assert!(!coord.is_root());
        assert_eq!(coord.depth(), 2);
        assert_eq!(coord.node_id(), &node);
        assert_eq!(coord.parent_id(), &parent);
        assert_eq!(coord.root_id(), &root);
    }

    #[test]
    fn test_tree_coordinate_empty_fails() {
        let result = TreeCoordinate::new(vec![]);
        assert!(matches!(result, Err(TreeError::EmptyCoordinate)));
    }

    #[test]
    fn test_tree_distance_same_node() {
        let node = make_node_id(1);
        let coord = TreeCoordinate::root(node);

        assert_eq!(coord.distance_to(&coord), 0);
    }

    #[test]
    fn test_tree_distance_siblings() {
        let root = make_node_id(0);
        let a = make_node_id(1);
        let b = make_node_id(2);

        let coord_a = TreeCoordinate::new(vec![a, root]).unwrap();
        let coord_b = TreeCoordinate::new(vec![b, root]).unwrap();

        // a -> root -> b = 2 hops
        assert_eq!(coord_a.distance_to(&coord_b), 2);
    }

    #[test]
    fn test_tree_distance_ancestor() {
        let root = make_node_id(0);
        let parent = make_node_id(1);
        let child = make_node_id(2);

        let coord_parent = TreeCoordinate::new(vec![parent, root]).unwrap();
        let coord_child = TreeCoordinate::new(vec![child, parent, root]).unwrap();

        // child -> parent = 1 hop
        assert_eq!(coord_child.distance_to(&coord_parent), 1);
    }

    #[test]
    fn test_tree_distance_cousins() {
        // Tree structure:
        //       root
        //      /    \
        //     a      b
        //    /        \
        //   c          d
        let root = make_node_id(0);
        let a = make_node_id(1);
        let b = make_node_id(2);
        let c = make_node_id(3);
        let d = make_node_id(4);

        let coord_c = TreeCoordinate::new(vec![c, a, root]).unwrap();
        let coord_d = TreeCoordinate::new(vec![d, b, root]).unwrap();

        // c -> a -> root -> b -> d = 4 hops
        assert_eq!(coord_c.distance_to(&coord_d), 4);
    }

    #[test]
    fn test_tree_distance_different_roots() {
        let root1 = make_node_id(1);
        let root2 = make_node_id(2);

        let coord1 = TreeCoordinate::root(root1);
        let coord2 = TreeCoordinate::root(root2);

        assert_eq!(coord1.distance_to(&coord2), usize::MAX);
    }

    #[test]
    fn test_has_ancestor() {
        let root = make_node_id(0);
        let parent = make_node_id(1);
        let child = make_node_id(2);

        let coord = TreeCoordinate::new(vec![child, parent, root]).unwrap();

        assert!(coord.has_ancestor(&parent));
        assert!(coord.has_ancestor(&root));
        assert!(!coord.has_ancestor(&child)); // self is not an ancestor
    }

    #[test]
    fn test_contains() {
        let root = make_node_id(0);
        let parent = make_node_id(1);
        let child = make_node_id(2);
        let other = make_node_id(99);

        let coord = TreeCoordinate::new(vec![child, parent, root]).unwrap();

        assert!(coord.contains(&child));
        assert!(coord.contains(&parent));
        assert!(coord.contains(&root));
        assert!(!coord.contains(&other));
    }

    #[test]
    fn test_ancestor_at() {
        let root = make_node_id(0);
        let parent = make_node_id(1);
        let child = make_node_id(2);

        let coord = TreeCoordinate::new(vec![child, parent, root]).unwrap();

        assert_eq!(coord.ancestor_at(0), Some(&child));
        assert_eq!(coord.ancestor_at(1), Some(&parent));
        assert_eq!(coord.ancestor_at(2), Some(&root));
        assert_eq!(coord.ancestor_at(3), None);
    }

    #[test]
    fn test_lca() {
        let root = make_node_id(0);
        let a = make_node_id(1);
        let b = make_node_id(2);
        let c = make_node_id(3);
        let d = make_node_id(4);

        // c under a, d under b, both under root
        let coord_c = TreeCoordinate::new(vec![c, a, root]).unwrap();
        let coord_d = TreeCoordinate::new(vec![d, b, root]).unwrap();

        assert_eq!(coord_c.lca(&coord_d), Some(&root));

        // c and a share ancestry through a and root
        let coord_a = TreeCoordinate::new(vec![a, root]).unwrap();
        assert_eq!(coord_c.lca(&coord_a), Some(&a));
    }

    // ===== ParentDeclaration Tests =====

    #[test]
    fn test_parent_declaration_new() {
        let node = make_node_id(1);
        let parent = make_node_id(2);

        let decl = ParentDeclaration::new(node, parent, 1, 1000);

        assert_eq!(decl.node_id(), &node);
        assert_eq!(decl.parent_id(), &parent);
        assert_eq!(decl.sequence(), 1);
        assert_eq!(decl.timestamp(), 1000);
        assert!(!decl.is_root());
        assert!(!decl.is_signed());
    }

    #[test]
    fn test_parent_declaration_self_root() {
        let node = make_node_id(1);

        let decl = ParentDeclaration::self_root(node, 5, 2000);

        assert!(decl.is_root());
        assert_eq!(decl.node_id(), decl.parent_id());
    }

    #[test]
    fn test_parent_declaration_freshness() {
        let node = make_node_id(1);
        let parent = make_node_id(2);

        let old_decl = ParentDeclaration::new(node, parent, 1, 1000);
        let new_decl = ParentDeclaration::new(node, parent, 2, 2000);

        assert!(new_decl.is_fresher_than(&old_decl));
        assert!(!old_decl.is_fresher_than(&new_decl));
        assert!(!old_decl.is_fresher_than(&old_decl));
    }

    #[test]
    fn test_parent_declaration_signing_bytes() {
        let node = make_node_id(1);
        let parent = make_node_id(2);

        let decl = ParentDeclaration::new(node, parent, 100, 1234567890);
        let bytes = decl.signing_bytes();

        // Should be 80 bytes: 32 + 32 + 8 + 8
        assert_eq!(bytes.len(), 80);

        // Verify structure
        assert_eq!(&bytes[0..32], node.as_bytes());
        assert_eq!(&bytes[32..64], parent.as_bytes());
        assert_eq!(&bytes[64..72], &100u64.to_le_bytes());
        assert_eq!(&bytes[72..80], &1234567890u64.to_le_bytes());
    }

    #[test]
    fn test_parent_declaration_equality() {
        let node = make_node_id(1);
        let parent = make_node_id(2);

        let decl1 = ParentDeclaration::new(node, parent, 1, 1000);
        let decl2 = ParentDeclaration::new(node, parent, 1, 1000);
        let decl3 = ParentDeclaration::new(node, parent, 2, 1000);

        assert_eq!(decl1, decl2);
        assert_ne!(decl1, decl3);
    }

    // ===== TreeState Tests =====

    #[test]
    fn test_tree_state_new() {
        let node = make_node_id(1);
        let state = TreeState::new(node);

        assert_eq!(state.my_node_id(), &node);
        assert!(state.is_root());
        assert_eq!(state.root(), &node);
        assert_eq!(state.my_coords().depth(), 0);
        assert_eq!(state.peer_count(), 0);
    }

    #[test]
    fn test_tree_state_update_peer() {
        let my_node = make_node_id(0);
        let mut state = TreeState::new(my_node);

        let peer = make_node_id(1);
        let root = make_node_id(2);

        let decl = ParentDeclaration::new(peer, root, 1, 1000);
        let coords = TreeCoordinate::new(vec![peer, root]).unwrap();

        assert!(state.update_peer(decl.clone(), coords.clone()));
        assert_eq!(state.peer_count(), 1);
        assert!(state.peer_coords(&peer).is_some());
        assert!(state.peer_declaration(&peer).is_some());

        // Same sequence should not update
        let decl2 = ParentDeclaration::new(peer, root, 1, 1000);
        assert!(!state.update_peer(decl2, coords.clone()));

        // Higher sequence should update
        let decl3 = ParentDeclaration::new(peer, root, 2, 2000);
        assert!(state.update_peer(decl3, coords));
    }

    #[test]
    fn test_tree_state_remove_peer() {
        let my_node = make_node_id(0);
        let mut state = TreeState::new(my_node);

        let peer = make_node_id(1);
        let root = make_node_id(2);

        let decl = ParentDeclaration::new(peer, root, 1, 1000);
        let coords = TreeCoordinate::new(vec![peer, root]).unwrap();

        state.update_peer(decl, coords);
        assert_eq!(state.peer_count(), 1);

        state.remove_peer(&peer);
        assert_eq!(state.peer_count(), 0);
        assert!(state.peer_coords(&peer).is_none());
    }

    #[test]
    fn test_tree_state_distance_to_peer() {
        let my_node = make_node_id(0);
        let mut state = TreeState::new(my_node);

        let peer = make_node_id(1);

        // Both are roots in their own trees initially - different roots
        let peer_coords = TreeCoordinate::root(peer);
        let decl = ParentDeclaration::self_root(peer, 1, 1000);
        state.update_peer(decl, peer_coords);

        // Different roots = MAX distance
        assert_eq!(state.distance_to_peer(&peer), Some(usize::MAX));

        // If they share a root, distance should be finite
        let shared_root = make_node_id(99);

        // Update my state to have shared root
        state.set_parent(shared_root, 1, 1000);
        let my_new_coords = TreeCoordinate::new(vec![my_node, shared_root]).unwrap();
        // Manually set coords for test (normally done by recompute_coords)
        state.my_coords = my_new_coords;
        state.root = shared_root;

        // Update peer to have same root
        let peer_coords = TreeCoordinate::new(vec![peer, shared_root]).unwrap();
        let decl = ParentDeclaration::new(peer, shared_root, 2, 2000);
        state.update_peer(decl, peer_coords);

        // Now distance should be 2 (me -> root -> peer)
        assert_eq!(state.distance_to_peer(&peer), Some(2));
    }

    #[test]
    fn test_tree_state_peer_ids() {
        let my_node = make_node_id(0);
        let mut state = TreeState::new(my_node);

        let peer1 = make_node_id(1);
        let peer2 = make_node_id(2);

        state.update_peer(
            ParentDeclaration::self_root(peer1, 1, 1000),
            TreeCoordinate::root(peer1),
        );
        state.update_peer(
            ParentDeclaration::self_root(peer2, 1, 1000),
            TreeCoordinate::root(peer2),
        );

        let ids: Vec<_> = state.peer_ids().collect();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&&peer1));
        assert!(ids.contains(&&peer2));
    }
}
