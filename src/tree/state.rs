//! Local spanning tree state for a node.

use std::collections::HashMap;
use std::fmt;

use super::{CoordEntry, ParentDeclaration, TreeCoordinate, TreeError};
use crate::{Identity, NodeAddr};

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
    pub(super) my_coords: TreeCoordinate,
    /// The current elected root (smallest reachable node_addr).
    pub(super) root: NodeAddr,
    /// Each peer's most recent parent declaration.
    peer_declarations: HashMap<NodeAddr, ParentDeclaration>,
    /// Each peer's full ancestry to root.
    peer_ancestry: HashMap<NodeAddr, TreeCoordinate>,
    /// Minimum depth improvement required to switch parents (same root).
    parent_switch_threshold: usize,
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
            parent_switch_threshold: 1,
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

    /// Set the parent switch threshold.
    pub fn set_parent_switch_threshold(&mut self, threshold: usize) {
        self.parent_switch_threshold = threshold;
    }

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

        let smallest_root = smallest_root?;

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

        let (best_peer_id, best_depth) = best_peer?;

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

        if current_depth >= proposed_depth + self.parent_switch_threshold {
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
