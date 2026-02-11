//! Spanning Tree Protocol Entities
//!
//! Tree coordinates and parent declarations for the FIPS spanning tree.
//! The spanning tree provides a routing topology where each node maintains
//! a path to a common root, enabling greedy distance-based routing.

use crate::{Identity, IdentityError, NodeAddr};
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
    InvalidSignature(NodeAddr),

    #[error("sequence number regression: got {got}, expected > {expected}")]
    SequenceRegression { got: u64, expected: u64 },

    #[error("parent not in peers: {0:?}")]
    ParentNotPeer(NodeAddr),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

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

/// Metadata for a single node in a tree coordinate path.
///
/// Carries the node address and its declaration metadata (sequence number
/// and timestamp). Used in TreeCoordinate entries and TreeAnnounce wire
/// format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordEntry {
    /// The node's routing address.
    pub node_addr: NodeAddr,
    /// The node's declaration sequence number.
    pub sequence: u64,
    /// The node's declaration timestamp (Unix seconds).
    pub timestamp: u64,
}

impl CoordEntry {
    /// Wire size of a serialized entry: node_addr(16) + sequence(8) + timestamp(8).
    pub const WIRE_SIZE: usize = 32;

    /// Create a new coordinate entry.
    pub fn new(node_addr: NodeAddr, sequence: u64, timestamp: u64) -> Self {
        Self {
            node_addr,
            sequence,
            timestamp,
        }
    }

    /// Create an entry with default metadata (sequence=0, timestamp=0).
    ///
    /// Useful for constructing coordinates when only routing (not wire format)
    /// is needed, e.g., in tests or distance calculations.
    pub fn addr_only(node_addr: NodeAddr) -> Self {
        Self {
            node_addr,
            sequence: 0,
            timestamp: 0,
        }
    }
}

/// A node's coordinates in the spanning tree.
///
/// Coordinates are the path from the node to the root:
/// `[self, parent, grandparent, ..., root]`
///
/// Each entry carries the node address plus declaration metadata (sequence
/// and timestamp) for the wire protocol. Routing operations (distance,
/// LCA) use only the node addresses.
///
/// The coordinate enables greedy routing via tree distance calculation.
/// Two nodes can compute the hops between them by finding their lowest
/// common ancestor (LCA) in the tree.
#[derive(Clone, PartialEq, Eq)]
pub struct TreeCoordinate(Vec<CoordEntry>);

impl TreeCoordinate {
    /// Create a coordinate from a path of entries (self to root).
    ///
    /// The path must be non-empty and ordered from the node to the root.
    pub fn new(path: Vec<CoordEntry>) -> Result<Self, TreeError> {
        if path.is_empty() {
            return Err(TreeError::EmptyCoordinate);
        }
        Ok(Self(path))
    }

    /// Create a coordinate from node addresses only (no metadata).
    ///
    /// Convenience constructor for cases where only routing is needed.
    /// Each entry gets sequence=0, timestamp=0.
    pub fn from_addrs(addrs: Vec<NodeAddr>) -> Result<Self, TreeError> {
        if addrs.is_empty() {
            return Err(TreeError::EmptyCoordinate);
        }
        Ok(Self(
            addrs
                .into_iter()
                .map(CoordEntry::addr_only)
                .collect(),
        ))
    }

    /// Create a coordinate for a root node.
    pub fn root(node_addr: NodeAddr) -> Self {
        Self(vec![CoordEntry::addr_only(node_addr)])
    }

    /// Create a root coordinate with metadata.
    pub fn root_with_meta(node_addr: NodeAddr, sequence: u64, timestamp: u64) -> Self {
        Self(vec![CoordEntry::new(node_addr, sequence, timestamp)])
    }

    /// The node this coordinate belongs to (first element).
    pub fn node_addr(&self) -> &NodeAddr {
        &self.0[0].node_addr
    }

    /// The root of the tree (last element).
    pub fn root_id(&self) -> &NodeAddr {
        &self.0.last().expect("coordinate never empty").node_addr
    }

    /// The immediate parent (second element, or self if root).
    pub fn parent_id(&self) -> &NodeAddr {
        self.0
            .get(1)
            .map(|e| &e.node_addr)
            .unwrap_or(&self.0[0].node_addr)
    }

    /// Depth in the tree (0 = root).
    pub fn depth(&self) -> usize {
        self.0.len() - 1
    }

    /// The full path of entries with metadata.
    pub fn entries(&self) -> &[CoordEntry] {
        &self.0
    }

    /// Iterator over node addresses in the path (self to root).
    ///
    /// Use this for routing operations (distance, LCA, ancestor checks)
    /// that only need the address path.
    pub fn node_addrs(&self) -> impl Iterator<Item = &NodeAddr> + DoubleEndedIterator {
        self.0.iter().map(|e| &e.node_addr)
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
        let self_rev = self.node_addrs().rev();
        let other_rev = other.node_addrs().rev();

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
    pub fn lca(&self, other: &TreeCoordinate) -> Option<&NodeAddr> {
        let self_rev: Vec<_> = self.node_addrs().rev().collect();
        let other_rev: Vec<_> = other.node_addrs().rev().collect();

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
    pub fn has_ancestor(&self, other: &NodeAddr) -> bool {
        self.node_addrs().skip(1).any(|id| id == other)
    }

    /// Check if `other` is in our ancestry (including self).
    pub fn contains(&self, other: &NodeAddr) -> bool {
        self.node_addrs().any(|id| id == other)
    }

    /// Get the ancestor at a specific depth from self.
    ///
    /// `ancestor_at(0)` returns self, `ancestor_at(1)` returns parent, etc.
    pub fn ancestor_at(&self, depth: usize) -> Option<&NodeAddr> {
        self.0.get(depth).map(|e| &e.node_addr)
    }
}

impl fmt::Debug for TreeCoordinate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TreeCoordinate(depth={}, path=[", self.depth())?;
        for (i, entry) in self.0.iter().enumerate() {
            if i > 0 {
                write!(f, " → ")?;
            }
            // Show first 4 bytes of each node ID
            write!(
                f,
                "{:02x}{:02x}",
                entry.node_addr.as_bytes()[0],
                entry.node_addr.as_bytes()[1]
            )?;
        }
        write!(f, "])")
    }
}

/// Local spanning tree state for a node.
///
/// Contains this node's declaration, coordinates, and view of peers'
/// tree positions. State is bounded by O(P × D) where P is peer count
/// and D is tree depth.
pub struct TreeState {
    /// This node's NodeAddr.
    my_node_addr: NodeAddr,
    /// This node's current parent declaration.
    my_declaration: ParentDeclaration,
    /// This node's current coordinates (computed from declaration chain).
    my_coords: TreeCoordinate,
    /// The current elected root (smallest reachable node_addr).
    root: NodeAddr,
    /// Each peer's most recent parent declaration.
    peer_declarations: HashMap<NodeAddr, ParentDeclaration>,
    /// Each peer's full ancestry to root.
    peer_ancestry: HashMap<NodeAddr, TreeCoordinate>,
}

impl TreeState {
    /// Create initial tree state for a node (as root candidate).
    ///
    /// The node starts as its own root until it learns of a smaller node_addr.
    /// Initial sequence is 1 per protocol spec; timestamp is current Unix time.
    pub fn new(my_node_addr: NodeAddr) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let my_declaration = ParentDeclaration::self_root(my_node_addr, 1, timestamp);
        let my_coords = TreeCoordinate::root_with_meta(my_node_addr, 1, timestamp);

        Self {
            my_node_addr,
            my_declaration,
            my_coords,
            root: my_node_addr,
            peer_declarations: HashMap::new(),
            peer_ancestry: HashMap::new(),
        }
    }

    /// Get this node's NodeAddr.
    pub fn my_node_addr(&self) -> &NodeAddr {
        &self.my_node_addr
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
    pub fn root(&self) -> &NodeAddr {
        &self.root
    }

    /// Check if this node is currently the root.
    pub fn is_root(&self) -> bool {
        self.root == self.my_node_addr
    }

    /// Get coordinates for a peer, if known.
    pub fn peer_coords(&self, peer_id: &NodeAddr) -> Option<&TreeCoordinate> {
        self.peer_ancestry.get(peer_id)
    }

    /// Get declaration for a peer, if known.
    pub fn peer_declaration(&self, peer_id: &NodeAddr) -> Option<&ParentDeclaration> {
        self.peer_declarations.get(peer_id)
    }

    /// Number of known peers.
    pub fn peer_count(&self) -> usize {
        self.peer_declarations.len()
    }

    /// Iterate over all peer node IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NodeAddr> {
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
        let peer_id = *declaration.node_addr();

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
    pub fn remove_peer(&mut self, peer_id: &NodeAddr) {
        self.peer_declarations.remove(peer_id);
        self.peer_ancestry.remove(peer_id);
    }

    /// Update this node's parent selection.
    ///
    /// Call this when switching parents. Updates the declaration and coordinates.
    pub fn set_parent(&mut self, parent_id: NodeAddr, sequence: u64, timestamp: u64) {
        self.my_declaration = ParentDeclaration::new(self.my_node_addr, parent_id, sequence, timestamp);
        // Coordinates will be recomputed when ancestry is available
    }

    /// Update this node's coordinates based on current parent's ancestry.
    pub fn recompute_coords(&mut self) {
        if self.my_declaration.is_root() {
            self.my_coords = TreeCoordinate::root_with_meta(
                self.my_node_addr,
                self.my_declaration.sequence(),
                self.my_declaration.timestamp(),
            );
            self.root = self.my_node_addr;
            return;
        }

        let parent_id = self.my_declaration.parent_id();
        if let Some(parent_coords) = self.peer_ancestry.get(parent_id) {
            // Our coords = [self_entry] ++ parent_coords entries
            let self_entry = CoordEntry::new(
                self.my_node_addr,
                self.my_declaration.sequence(),
                self.my_declaration.timestamp(),
            );
            let mut entries = vec![self_entry];
            entries.extend_from_slice(parent_coords.entries());
            self.my_coords = TreeCoordinate::new(entries).expect("non-empty path");
            self.root = *self.my_coords.root_id();
        }
    }

    /// Calculate tree distance to a peer.
    pub fn distance_to_peer(&self, peer_id: &NodeAddr) -> Option<usize> {
        self.peer_ancestry
            .get(peer_id)
            .map(|coords| self.my_coords.distance_to(coords))
    }

    /// Find the best next hop toward a destination using greedy tree routing.
    ///
    /// Returns the peer that minimizes tree distance to the destination,
    /// but only if that peer is strictly closer than we are (prevents
    /// routing loops at local minima). Tie-breaks equal distance by
    /// smallest node_addr.
    ///
    /// Returns `None` if:
    /// - No peers have coordinates
    /// - Destination is in a different tree (different root)
    /// - No peer is closer to the destination than we are
    pub fn find_next_hop(&self, dest_coords: &TreeCoordinate) -> Option<NodeAddr> {
        if self.my_coords.root_id() != dest_coords.root_id() {
            return None;
        }

        let my_distance = self.my_coords.distance_to(dest_coords);

        let mut best: Option<(NodeAddr, usize)> = None;

        for (peer_id, peer_coords) in &self.peer_ancestry {
            let distance = peer_coords.distance_to(dest_coords);

            let dominated = match &best {
                None => true,
                Some((best_id, best_dist)) => {
                    distance < *best_dist
                        || (distance == *best_dist && peer_id < best_id)
                }
            };

            if dominated {
                best = Some((*peer_id, distance));
            }
        }

        match best {
            Some((peer_id, distance)) if distance < my_distance => Some(peer_id),
            _ => None,
        }
    }

    /// Minimum depth improvement required to switch parents (same root).
    /// Prevents thrashing on equivalent-depth paths.
    const PARENT_SWITCH_THRESHOLD: usize = 1;

    /// Evaluate whether to switch parents based on current peer tree state.
    ///
    /// v1 algorithm: depth-based, no latency/loss metrics.
    ///
    /// Returns `Some(peer_node_addr)` if a parent switch is recommended,
    /// or `None` if the current parent is adequate.
    pub fn evaluate_parent(&self) -> Option<NodeAddr> {
        if self.peer_ancestry.is_empty() {
            return None;
        }

        // Find the smallest root visible across all peers
        let mut smallest_root: Option<NodeAddr> = None;
        for coords in self.peer_ancestry.values() {
            let peer_root = coords.root_id();
            smallest_root = Some(match smallest_root {
                None => *peer_root,
                Some(current) => {
                    if *peer_root < current {
                        *peer_root
                    } else {
                        current
                    }
                }
            });
        }

        let smallest_root = match smallest_root {
            Some(r) => r,
            None => return None,
        };

        // If we are the smallest node in the network, stay root
        if self.my_node_addr <= smallest_root && self.is_root() {
            return None;
        }

        // Among peers that reach the smallest root, find the shallowest
        let mut best_peer: Option<(NodeAddr, usize)> = None; // (peer_addr, depth)
        for (peer_id, coords) in &self.peer_ancestry {
            if *coords.root_id() != smallest_root {
                continue;
            }
            let depth = coords.depth();
            match &best_peer {
                None => best_peer = Some((*peer_id, depth)),
                Some((_, best_depth)) => {
                    if depth < *best_depth {
                        best_peer = Some((*peer_id, depth));
                    }
                }
            }
        }

        let (best_peer_id, best_depth) = match best_peer {
            Some(bp) => bp,
            None => return None,
        };

        // If already using this peer as parent, no switch needed
        if *self.my_declaration.parent_id() == best_peer_id && !self.is_root() {
            return None;
        }

        // If our current parent is gone from peer_ancestry, our path is broken — always switch
        if !self.is_root() && !self.peer_ancestry.contains_key(self.my_declaration.parent_id()) {
            return Some(best_peer_id);
        }

        // Switching roots (smaller root found) → always switch
        if smallest_root < self.root || (self.is_root() && smallest_root < self.my_node_addr) {
            return Some(best_peer_id);
        }

        // Same root: require depth improvement ≥ threshold
        if self.is_root() {
            // We're root but shouldn't be (peers have a smaller root) — always switch
            return Some(best_peer_id);
        }

        // Compare depth: our current depth vs what we'd get through best_peer
        // Our new depth would be best_depth + 1
        let current_depth = self.my_coords.depth();
        let proposed_depth = best_depth + 1;

        if current_depth >= proposed_depth + Self::PARENT_SWITCH_THRESHOLD {
            return Some(best_peer_id);
        }

        None
    }

    /// Handle loss of current parent.
    ///
    /// Tries to find an alternative parent among remaining peers.
    /// If none available, becomes its own root (increments sequence).
    ///
    /// Returns `true` if the tree state changed (caller should re-announce).
    pub fn handle_parent_lost(&mut self) -> bool {
        // Try to find an alternative parent
        if let Some(new_parent) = self.evaluate_parent() {
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0);
            let new_seq = self.my_declaration.sequence() + 1;
            self.set_parent(new_parent, new_seq, timestamp);
            self.recompute_coords();
            return true;
        }

        // No alternative: become own root
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let new_seq = self.my_declaration.sequence() + 1;
        self.my_declaration =
            ParentDeclaration::self_root(self.my_node_addr, new_seq, timestamp);
        self.recompute_coords();
        true
    }

    /// Sign this node's declaration with the given identity.
    ///
    /// The identity's node_addr must match this TreeState's node_addr.
    pub fn sign_declaration(&mut self, identity: &Identity) -> Result<(), TreeError> {
        self.my_declaration.sign(identity)
    }

    /// Check if this node's declaration is signed.
    pub fn is_declaration_signed(&self) -> bool {
        self.my_declaration.is_signed()
    }
}

impl fmt::Debug for TreeState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreeState")
            .field("my_node_addr", &self.my_node_addr)
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

    fn make_node_addr(val: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = val;
        NodeAddr::from_bytes(bytes)
    }

    fn make_coords(ids: &[u8]) -> TreeCoordinate {
        TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
    }

    // ===== TreeCoordinate Tests =====

    #[test]
    fn test_tree_coordinate_root() {
        let root_id = make_node_addr(1);
        let coord = TreeCoordinate::root(root_id);

        assert!(coord.is_root());
        assert_eq!(coord.depth(), 0);
        assert_eq!(coord.node_addr(), &root_id);
        assert_eq!(coord.root_id(), &root_id);
        assert_eq!(coord.parent_id(), &root_id);
    }

    #[test]
    fn test_tree_coordinate_path() {
        let node = make_node_addr(1);
        let parent = make_node_addr(2);
        let root = make_node_addr(3);

        let coord = make_coords(&[1, 2, 3]);

        assert!(!coord.is_root());
        assert_eq!(coord.depth(), 2);
        assert_eq!(coord.node_addr(), &node);
        assert_eq!(coord.parent_id(), &parent);
        assert_eq!(coord.root_id(), &root);
    }

    #[test]
    fn test_tree_coordinate_empty_fails() {
        let result = TreeCoordinate::from_addrs(vec![]);
        assert!(matches!(result, Err(TreeError::EmptyCoordinate)));
    }

    #[test]
    fn test_tree_coordinate_entries_metadata() {
        let node = make_node_addr(1);
        let root = make_node_addr(0);

        let coord = TreeCoordinate::new(vec![
            CoordEntry::new(node, 5, 1000),
            CoordEntry::new(root, 1, 500),
        ])
        .unwrap();

        assert_eq!(coord.entries()[0].sequence, 5);
        assert_eq!(coord.entries()[0].timestamp, 1000);
        assert_eq!(coord.entries()[1].sequence, 1);
        assert_eq!(coord.entries()[1].timestamp, 500);
    }

    #[test]
    fn test_tree_distance_same_node() {
        let node = make_node_addr(1);
        let coord = TreeCoordinate::root(node);

        assert_eq!(coord.distance_to(&coord), 0);
    }

    #[test]
    fn test_tree_distance_siblings() {
        let coord_a = make_coords(&[1, 0]);
        let coord_b = make_coords(&[2, 0]);

        // a -> root -> b = 2 hops
        assert_eq!(coord_a.distance_to(&coord_b), 2);
    }

    #[test]
    fn test_tree_distance_ancestor() {
        let coord_parent = make_coords(&[1, 0]);
        let coord_child = make_coords(&[2, 1, 0]);

        // child -> parent = 1 hop
        assert_eq!(coord_child.distance_to(&coord_parent), 1);
    }

    #[test]
    fn test_tree_distance_cousins() {
        // Tree structure:
        //       root(0)
        //      /    \
        //     a(1)   b(2)
        //    /        \
        //   c(3)       d(4)
        let coord_c = make_coords(&[3, 1, 0]);
        let coord_d = make_coords(&[4, 2, 0]);

        // c -> a -> root -> b -> d = 4 hops
        assert_eq!(coord_c.distance_to(&coord_d), 4);
    }

    #[test]
    fn test_tree_distance_different_roots() {
        let coord1 = TreeCoordinate::root(make_node_addr(1));
        let coord2 = TreeCoordinate::root(make_node_addr(2));

        assert_eq!(coord1.distance_to(&coord2), usize::MAX);
    }

    #[test]
    fn test_has_ancestor() {
        let root = make_node_addr(0);
        let parent = make_node_addr(1);
        let child = make_node_addr(2);

        let coord = make_coords(&[2, 1, 0]);

        assert!(coord.has_ancestor(&parent));
        assert!(coord.has_ancestor(&root));
        assert!(!coord.has_ancestor(&child)); // self is not an ancestor
    }

    #[test]
    fn test_contains() {
        let root = make_node_addr(0);
        let parent = make_node_addr(1);
        let child = make_node_addr(2);
        let other = make_node_addr(99);

        let coord = make_coords(&[2, 1, 0]);

        assert!(coord.contains(&child));
        assert!(coord.contains(&parent));
        assert!(coord.contains(&root));
        assert!(!coord.contains(&other));
    }

    #[test]
    fn test_ancestor_at() {
        let root = make_node_addr(0);
        let parent = make_node_addr(1);
        let child = make_node_addr(2);

        let coord = make_coords(&[2, 1, 0]);

        assert_eq!(coord.ancestor_at(0), Some(&child));
        assert_eq!(coord.ancestor_at(1), Some(&parent));
        assert_eq!(coord.ancestor_at(2), Some(&root));
        assert_eq!(coord.ancestor_at(3), None);
    }

    #[test]
    fn test_lca() {
        let root = make_node_addr(0);
        let a = make_node_addr(1);

        // c under a, d under b, both under root
        let coord_c = make_coords(&[3, 1, 0]);
        let coord_d = make_coords(&[4, 2, 0]);

        assert_eq!(coord_c.lca(&coord_d), Some(&root));

        // c and a share ancestry through a and root
        let coord_a = make_coords(&[1, 0]);
        assert_eq!(coord_c.lca(&coord_a), Some(&a));
    }

    // ===== ParentDeclaration Tests =====

    #[test]
    fn test_parent_declaration_new() {
        let node = make_node_addr(1);
        let parent = make_node_addr(2);

        let decl = ParentDeclaration::new(node, parent, 1, 1000);

        assert_eq!(decl.node_addr(), &node);
        assert_eq!(decl.parent_id(), &parent);
        assert_eq!(decl.sequence(), 1);
        assert_eq!(decl.timestamp(), 1000);
        assert!(!decl.is_root());
        assert!(!decl.is_signed());
    }

    #[test]
    fn test_parent_declaration_self_root() {
        let node = make_node_addr(1);

        let decl = ParentDeclaration::self_root(node, 5, 2000);

        assert!(decl.is_root());
        assert_eq!(decl.node_addr(), decl.parent_id());
    }

    #[test]
    fn test_parent_declaration_freshness() {
        let node = make_node_addr(1);
        let parent = make_node_addr(2);

        let old_decl = ParentDeclaration::new(node, parent, 1, 1000);
        let new_decl = ParentDeclaration::new(node, parent, 2, 2000);

        assert!(new_decl.is_fresher_than(&old_decl));
        assert!(!old_decl.is_fresher_than(&new_decl));
        assert!(!old_decl.is_fresher_than(&old_decl));
    }

    #[test]
    fn test_parent_declaration_signing_bytes() {
        let node = make_node_addr(1);
        let parent = make_node_addr(2);

        let decl = ParentDeclaration::new(node, parent, 100, 1234567890);
        let bytes = decl.signing_bytes();

        // Should be 48 bytes: 16 + 16 + 8 + 8
        assert_eq!(bytes.len(), 48);

        // Verify structure
        assert_eq!(&bytes[0..16], node.as_bytes());
        assert_eq!(&bytes[16..32], parent.as_bytes());
        assert_eq!(&bytes[32..40], &100u64.to_le_bytes());
        assert_eq!(&bytes[40..48], &1234567890u64.to_le_bytes());
    }

    #[test]
    fn test_parent_declaration_equality() {
        let node = make_node_addr(1);
        let parent = make_node_addr(2);

        let decl1 = ParentDeclaration::new(node, parent, 1, 1000);
        let decl2 = ParentDeclaration::new(node, parent, 1, 1000);
        let decl3 = ParentDeclaration::new(node, parent, 2, 1000);

        assert_eq!(decl1, decl2);
        assert_ne!(decl1, decl3);
    }

    // ===== TreeState Tests =====

    #[test]
    fn test_tree_state_new() {
        let node = make_node_addr(1);
        let state = TreeState::new(node);

        assert_eq!(state.my_node_addr(), &node);
        assert!(state.is_root());
        assert_eq!(state.root(), &node);
        assert_eq!(state.my_coords().depth(), 0);
        assert_eq!(state.peer_count(), 0);
    }

    #[test]
    fn test_tree_state_update_peer() {
        let my_node = make_node_addr(0);
        let mut state = TreeState::new(my_node);

        let peer = make_node_addr(1);
        let root = make_node_addr(2);

        let decl = ParentDeclaration::new(peer, root, 1, 1000);
        let coords = make_coords(&[1, 2]);

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
        let my_node = make_node_addr(0);
        let mut state = TreeState::new(my_node);

        let peer = make_node_addr(1);
        let root = make_node_addr(2);

        let decl = ParentDeclaration::new(peer, root, 1, 1000);
        let coords = make_coords(&[1, 2]);

        state.update_peer(decl, coords);
        assert_eq!(state.peer_count(), 1);

        state.remove_peer(&peer);
        assert_eq!(state.peer_count(), 0);
        assert!(state.peer_coords(&peer).is_none());
    }

    #[test]
    fn test_tree_state_distance_to_peer() {
        let my_node = make_node_addr(0);
        let mut state = TreeState::new(my_node);

        let peer = make_node_addr(1);

        // Both are roots in their own trees initially - different roots
        let peer_coords = TreeCoordinate::root(peer);
        let decl = ParentDeclaration::self_root(peer, 1, 1000);
        state.update_peer(decl, peer_coords);

        // Different roots = MAX distance
        assert_eq!(state.distance_to_peer(&peer), Some(usize::MAX));

        // If they share a root, distance should be finite
        let shared_root = make_node_addr(99);

        // Update my state to have shared root
        state.set_parent(shared_root, 1, 1000);
        let my_new_coords = make_coords(&[0, 99]);
        // Manually set coords for test (normally done by recompute_coords)
        state.my_coords = my_new_coords;
        state.root = shared_root;

        // Update peer to have same root
        let peer_coords = make_coords(&[1, 99]);
        let decl = ParentDeclaration::new(peer, shared_root, 2, 2000);
        state.update_peer(decl, peer_coords);

        // Now distance should be 2 (me -> root -> peer)
        assert_eq!(state.distance_to_peer(&peer), Some(2));
    }

    #[test]
    fn test_tree_state_peer_ids() {
        let my_node = make_node_addr(0);
        let mut state = TreeState::new(my_node);

        let peer1 = make_node_addr(1);
        let peer2 = make_node_addr(2);

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

    // ===== Parent Selection Tests =====

    #[test]
    fn test_evaluate_parent_picks_smallest_root() {
        // Node 5 starts as root. Peers 3 and 7 each claim different roots.
        // Peer 3's path: [3, 1] (root=1)
        // Peer 7's path: [7, 2] (root=2)
        // Should pick peer 3 because root 1 < root 2.
        let my_node = make_node_addr(5);
        let mut state = TreeState::new(my_node);

        let peer3 = make_node_addr(3);
        let peer7 = make_node_addr(7);

        state.update_peer(
            ParentDeclaration::new(peer3, make_node_addr(1), 1, 1000),
            make_coords(&[3, 1]),
        );
        state.update_peer(
            ParentDeclaration::new(peer7, make_node_addr(2), 1, 1000),
            make_coords(&[7, 2]),
        );

        let result = state.evaluate_parent();
        assert_eq!(result, Some(peer3));
    }

    #[test]
    fn test_evaluate_parent_prefers_shallowest_depth() {
        // Node 5, root=0 (shared). Peer 1 at depth 1, peer 2 at depth 3.
        // Both reach root 0. Should pick peer 1 (shallowest).
        let my_node = make_node_addr(5);
        let mut state = TreeState::new(my_node);

        let peer1 = make_node_addr(1);
        let peer2 = make_node_addr(2);
        let root = make_node_addr(0);

        // Peer 1: depth 1 (path = [1, 0])
        state.update_peer(
            ParentDeclaration::new(peer1, root, 1, 1000),
            make_coords(&[1, 0]),
        );
        // Peer 2: depth 3 (path = [2, 3, 4, 0])
        state.update_peer(
            ParentDeclaration::new(peer2, make_node_addr(3), 1, 1000),
            make_coords(&[2, 3, 4, 0]),
        );

        let result = state.evaluate_parent();
        assert_eq!(result, Some(peer1));
    }

    #[test]
    fn test_evaluate_parent_stays_root_when_smallest() {
        // Node 0 (smallest possible) should stay root even if peers exist.
        let my_node = make_node_addr(0);
        let mut state = TreeState::new(my_node);

        let peer1 = make_node_addr(1);
        // Peer 1 has root 0 (us) — shouldn't trigger switch
        state.update_peer(
            ParentDeclaration::new(peer1, my_node, 1, 1000),
            make_coords(&[1, 0]),
        );

        assert_eq!(state.evaluate_parent(), None);
    }

    #[test]
    fn test_evaluate_parent_no_switch_when_already_best() {
        // Node 5, already using peer 1 as parent. No better option.
        let my_node = make_node_addr(5);
        let mut state = TreeState::new(my_node);

        let peer1 = make_node_addr(1);
        let root = make_node_addr(0);

        state.update_peer(
            ParentDeclaration::new(peer1, root, 1, 1000),
            make_coords(&[1, 0]),
        );

        // Switch to peer1 as parent first
        state.set_parent(peer1, 1, 1000);
        state.recompute_coords();

        // Now evaluate — should return None since peer1 is already our parent
        assert_eq!(state.evaluate_parent(), None);
    }

    #[test]
    fn test_evaluate_parent_no_peers() {
        let my_node = make_node_addr(5);
        let state = TreeState::new(my_node);

        assert_eq!(state.evaluate_parent(), None);
    }

    #[test]
    fn test_evaluate_parent_depth_threshold() {
        // Node 5, currently at depth 4 through peer 2.
        // Peer 1 offers depth 3 (improvement of 1, which equals threshold).
        // Peer 3 offers depth 1 (improvement of 3, exceeds threshold).
        // Should switch to peer 3.
        let my_node = make_node_addr(5);
        let mut state = TreeState::new(my_node);

        let peer2 = make_node_addr(2);
        let peer3 = make_node_addr(3);
        let root = make_node_addr(0);

        // Peer 2: depth 3 (we'd be depth 4 through them)
        state.update_peer(
            ParentDeclaration::new(peer2, make_node_addr(6), 1, 1000),
            make_coords(&[2, 6, 7, 0]),
        );

        // Set peer2 as our parent, making us depth 4
        state.set_parent(peer2, 1, 1000);
        state.recompute_coords();
        assert_eq!(state.my_coords().depth(), 4);

        // Peer 3: depth 1 (we'd be depth 2 through them) — improvement of 2
        state.update_peer(
            ParentDeclaration::new(peer3, root, 1, 1000),
            make_coords(&[3, 0]),
        );

        let result = state.evaluate_parent();
        assert_eq!(result, Some(peer3));
    }

    #[test]
    fn test_handle_parent_lost_finds_alternative() {
        let my_node = make_node_addr(5);
        let mut state = TreeState::new(my_node);

        let peer1 = make_node_addr(1);
        let peer2 = make_node_addr(2);
        let root = make_node_addr(0);

        state.update_peer(
            ParentDeclaration::new(peer1, root, 1, 1000),
            make_coords(&[1, 0]),
        );
        state.update_peer(
            ParentDeclaration::new(peer2, root, 1, 1000),
            make_coords(&[2, 0]),
        );

        // Set peer1 as parent
        state.set_parent(peer1, 1, 1000);
        state.recompute_coords();

        // Remove peer1 (parent lost)
        state.remove_peer(&peer1);
        let changed = state.handle_parent_lost();

        assert!(changed);
        // Should have switched to peer2
        assert_eq!(state.my_declaration().parent_id(), &peer2);
        assert!(!state.is_root());
    }

    #[test]
    fn test_handle_parent_lost_becomes_root() {
        let my_node = make_node_addr(5);
        let mut state = TreeState::new(my_node);

        let peer1 = make_node_addr(1);
        let root = make_node_addr(0);

        state.update_peer(
            ParentDeclaration::new(peer1, root, 1, 1000),
            make_coords(&[1, 0]),
        );

        // Set peer1 as parent
        state.set_parent(peer1, 1, 1000);
        state.recompute_coords();
        let seq_before = state.my_declaration().sequence();

        // Remove peer1 (only parent)
        state.remove_peer(&peer1);
        let changed = state.handle_parent_lost();

        assert!(changed);
        assert!(state.is_root());
        assert!(state.my_declaration().sequence() > seq_before);
        assert_eq!(state.root(), &my_node);
    }

    // === find_next_hop tests ===

    /// Build a TreeState with our own coordinates set.
    fn make_tree_state(my_addr: u8, coord_path: &[u8]) -> TreeState {
        let my_node = make_node_addr(my_addr);
        let mut state = TreeState::new(my_node);
        let coords = make_coords(coord_path);
        state.root = *coords.root_id();
        state.my_coords = coords;
        state
    }

    /// Add a peer with given coordinates to the tree state.
    fn add_peer(state: &mut TreeState, peer_addr: u8, coord_path: &[u8]) {
        let peer = make_node_addr(peer_addr);
        let parent = make_node_addr(coord_path[1]);
        state.update_peer(
            ParentDeclaration::new(peer, parent, 1, 1000),
            make_coords(coord_path),
        );
    }

    #[test]
    fn test_find_next_hop_chain() {
        // Chain: 0 (root) <- 5 (us) <- 1 <- 2
        // Both peers 1 and 2 are in our peer_ancestry. Peer 2 IS the
        // destination (distance 0), so it's the best next hop.
        let mut state = make_tree_state(5, &[5, 0]);
        add_peer(&mut state, 1, &[1, 5, 0]);
        add_peer(&mut state, 2, &[2, 1, 5, 0]);

        let dest = make_coords(&[2, 1, 5, 0]);
        assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(2)));
    }

    #[test]
    fn test_find_next_hop_chain_indirect() {
        // Chain: 0 (root) <- 5 (us) <- 1
        // Dest is node 2 at [2, 1, 5, 0] but peer 2 is NOT in our peer
        // list — only peer 1 is. So we route via peer 1 (distance 1).
        let mut state = make_tree_state(5, &[5, 0]);
        add_peer(&mut state, 1, &[1, 5, 0]);

        let dest = make_coords(&[2, 1, 5, 0]);
        assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(1)));
    }

    #[test]
    fn test_find_next_hop_toward_root() {
        // Tree: 0 (root) <- 1 <- 5 (us)
        // Routing toward root should pick node 1 (our parent).
        let mut state = make_tree_state(5, &[5, 1, 0]);
        add_peer(&mut state, 1, &[1, 0]);

        let dest = make_coords(&[0]);
        assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(1)));
    }

    #[test]
    fn test_find_next_hop_sibling() {
        // Tree: 0 (root) <- 5 (us), 0 <- 3
        // Routing to sibling 3: should go through parent 0... but 0 is
        // the root and not in our peer list. Our only peer is 3 itself.
        // But 3 is not a "closer" peer in tree distance — distance from
        // us to 3 is 2 (up to root, down to 3), and distance from 3 to
        // 3 is 0, so 3 IS closer. Should pick 3.
        let mut state = make_tree_state(5, &[5, 0]);
        add_peer(&mut state, 3, &[3, 0]);

        let dest = make_coords(&[3, 0]);
        assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(3)));
    }

    #[test]
    fn test_find_next_hop_tie_breaking() {
        // Tree: 0 (root) <- 5 (us), 0 <- 3, 0 <- 2
        // Both peers are siblings at depth 1, equidistant to a dest
        // at [4, 0]. Should pick node 2 (smaller node_addr).
        let mut state = make_tree_state(5, &[5, 0]);
        add_peer(&mut state, 3, &[3, 0]);
        add_peer(&mut state, 2, &[2, 0]);

        let dest = make_coords(&[4, 0]);
        // Our distance: 2 (up to root, down to 4)
        // Peer 3 distance: 2 (up to root, down to 4)
        // Peer 2 distance: 2 (up to root, down to 4)
        // All equal to our distance — no peer is strictly closer.
        assert_eq!(state.find_next_hop(&dest), None);
    }

    #[test]
    fn test_find_next_hop_different_root() {
        let mut state = make_tree_state(5, &[5, 0]);
        add_peer(&mut state, 1, &[1, 0]);

        // Destination in a different tree (root = 9)
        let dest = make_coords(&[3, 9]);
        assert_eq!(state.find_next_hop(&dest), None);
    }

    #[test]
    fn test_find_next_hop_no_peers() {
        let state = make_tree_state(5, &[5, 0]);
        let dest = make_coords(&[3, 0]);
        assert_eq!(state.find_next_hop(&dest), None);
    }

    #[test]
    fn test_find_next_hop_local_minimum() {
        // Tree: 0 (root) <- 5 (us), 5 <- 8
        // Routing to node 3 at [3, 0]. Our distance = 2.
        // Peer 8's distance = 4 (8→5→0→3 but via coords: [8,5,0] to [3,0] = 3).
        // Actually: lca of [8,5,0] and [3,0] is root 0 at depth 0.
        // dist = (2-0) + (1-0) = 3. Our dist = (1-0) + (1-0) = 2.
        // Peer is farther, so no hop.
        let mut state = make_tree_state(5, &[5, 0]);
        add_peer(&mut state, 8, &[8, 5, 0]);

        let dest = make_coords(&[3, 0]);
        assert_eq!(state.find_next_hop(&dest), None);
    }

    #[test]
    fn test_find_next_hop_best_of_multiple() {
        // Tree: 0 (root) <- 1 <- 5 (us), 1 <- 3 <- 7
        // Dest is node 7 at [7, 3, 1, 0].
        // Peer 1 coords [1, 0]: dist to dest = 0 + 2 = 2
        // Peer 3 coords [3, 1, 0]: dist to dest = 0 + 1 = 1
        // Our coords [5, 1, 0]: dist to dest = 1 + 2 = 3
        // Peer 3 is closest. Should pick 3.
        let mut state = make_tree_state(5, &[5, 1, 0]);
        add_peer(&mut state, 1, &[1, 0]);
        add_peer(&mut state, 3, &[3, 1, 0]);

        let dest = make_coords(&[7, 3, 1, 0]);
        assert_eq!(state.find_next_hop(&dest), Some(make_node_addr(3)));
    }
}
