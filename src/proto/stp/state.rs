//! Local spanning tree state for a node.

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt;

use super::core::ParentEval;
use super::limits::FlapDampener;
use super::{CoordEntry, TreeCoordinate};
use crate::NodeAddr;

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
    peer_declarations: BTreeMap<NodeAddr, ParentDeclaration>,
    /// Each peer's full ancestry to root.
    peer_ancestry: BTreeMap<NodeAddr, TreeCoordinate>,
    /// Hysteresis factor for cost-based parent re-selection (0.0-1.0).
    parent_hysteresis: f64,
    /// Flap-dampening / hold-down state machine.
    flap: FlapDampener,
}

impl TreeState {
    /// Create initial tree state for a node (as root candidate).
    ///
    /// The node starts as its own root until it learns of a smaller node_addr.
    /// Initial sequence is 1 per protocol spec; `now_secs` is the injected
    /// wall-clock Unix time in seconds stamped onto the initial declaration.
    pub fn new(my_node_addr: NodeAddr, now_secs: u64) -> Self {
        let timestamp = now_secs;
        let my_declaration = ParentDeclaration::self_root(my_node_addr, 1, timestamp);
        let my_coords = TreeCoordinate::root_with_meta(my_node_addr, 1, timestamp);

        Self {
            my_node_addr,
            my_declaration,
            my_coords,
            root: my_node_addr,
            peer_declarations: BTreeMap::new(),
            peer_ancestry: BTreeMap::new(),
            parent_hysteresis: 0.0,
            flap: FlapDampener::new(),
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

    /// Test-only override of this node's coordinates, bypassing the
    /// parent/declaration state machine. Lets routing tests place the node at
    /// an arbitrary tree position to exercise coordinate-based classification.
    #[cfg(test)]
    pub(crate) fn set_my_coords_for_test(&mut self, coords: TreeCoordinate) {
        self.root = *coords.root_id();
        self.my_coords = coords;
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
    /// Returns true if flap dampening was just engaged due to this switch.
    /// Only records a flap when the parent actually changes.
    ///
    /// `timestamp` is the escaping wall-clock Unix seconds stamped onto the new
    /// declaration; `now_ms` is the monotonic milliseconds driving the
    /// flap-dampening timers (the two clock bases must not be crossed).
    pub fn set_parent(
        &mut self,
        parent_id: NodeAddr,
        sequence: u64,
        timestamp: u64,
        now_ms: u64,
    ) -> bool {
        let parent_changed = self.is_root() || *self.my_declaration.parent_id() != parent_id;
        self.my_declaration =
            ParentDeclaration::new(self.my_node_addr, parent_id, sequence, timestamp);
        self.flap.mark_switch(now_ms);
        // Record switch for flap detection only when parent actually changes;
        // coordinates will be recomputed when ancestry is available
        if parent_changed {
            self.flap.record_parent_switch(now_ms)
        } else {
            false
        }
    }

    /// Update this node's coordinates based on current parent's ancestry.
    ///
    /// Defensive: if extending the parent's ancestry would put `self` at the
    /// minimum (because `self` is smaller than the parent's root), the
    /// declaration is demoted to self-root in place. The caller is responsible
    /// for re-signing the declaration after this call (do `set_parent → recompute_coords → sign_declaration`,
    /// not `set_parent → sign_declaration → recompute_coords`).
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
            let parent_root = *parent_coords.root_id();
            if self.my_node_addr <= parent_root {
                // Prepending self would put a smaller-or-equal node at depth 0,
                // breaking the "advertised root = min path entry" invariant.
                // Demote to self-root rather than emit a path peers will reject.
                let seq = self.my_declaration.sequence();
                let ts = self.my_declaration.timestamp();
                self.my_declaration = ParentDeclaration::self_root(self.my_node_addr, seq, ts);
                self.my_coords = TreeCoordinate::root_with_meta(self.my_node_addr, seq, ts);
                self.root = self.my_node_addr;
                return;
            }
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

    /// Smallest root_id visible across known peers.
    pub fn smallest_visible_root(&self) -> Option<NodeAddr> {
        self.peer_ancestry.values().map(|c| *c.root_id()).min()
    }

    /// Whether this node should be the tree root: either there are no peers,
    /// or our NodeAddr is `<=` every visible root.
    pub fn should_be_root(&self) -> bool {
        match self.smallest_visible_root() {
            Some(sr) => self.my_node_addr <= sr,
            None => true,
        }
    }

    /// Promote self to root with an incremented sequence number.
    ///
    /// `now_secs` is the injected wall-clock Unix time in seconds stamped onto
    /// the new self-root declaration. Caller must `sign_declaration` afterwards
    /// before sending the result.
    pub fn become_root(&mut self, now_secs: u64) {
        let new_seq = self.my_declaration.sequence() + 1;
        let timestamp = now_secs;
        self.my_declaration = ParentDeclaration::self_root(self.my_node_addr, new_seq, timestamp);
        self.recompute_coords();
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
    ///
    /// `skip_peers` contains peers that should not be used as transit
    /// (e.g., non-routing and leaf nodes).
    pub fn find_next_hop(
        &self,
        dest_coords: &TreeCoordinate,
        skip_peers: &BTreeSet<NodeAddr>,
    ) -> Option<NodeAddr> {
        if self.my_coords.root_id() != dest_coords.root_id() {
            return None;
        }

        let my_distance = self.my_coords.distance_to(dest_coords);

        let mut best: Option<(NodeAddr, usize)> = None;

        for (peer_id, peer_coords) in &self.peer_ancestry {
            if skip_peers.contains(peer_id) {
                continue;
            }
            let distance = peer_coords.distance_to(dest_coords);

            let dominated = match &best {
                None => true,
                Some((best_id, best_dist)) => {
                    distance < *best_dist || (distance == *best_dist && peer_id < best_id)
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

    /// Set the parent hysteresis factor (0.0-1.0).
    pub fn set_parent_hysteresis(&mut self, hysteresis: f64) {
        self.parent_hysteresis = hysteresis.clamp(0.0, 1.0);
    }

    /// Set the hold-down duration after parent switches.
    pub fn set_hold_down(&mut self, secs: u64) {
        self.flap.set_hold_down(secs);
    }

    /// Configure flap dampening parameters.
    pub fn set_flap_dampening(&mut self, threshold: u32, window_secs: u64, dampening_secs: u64) {
        self.flap
            .set_flap_dampening(threshold, window_secs, dampening_secs);
    }

    /// Check if flap dampening is currently active. `now_ms` is the injected
    /// monotonic time in milliseconds.
    pub fn is_flap_dampened(&self, now_ms: u64) -> bool {
        self.flap.is_flap_dampened(now_ms)
    }

    /// Whether a *discretionary* parent switch should currently be suppressed by the
    /// flap-dampening / hold-down veto. `now_ms` is the injected monotonic time.
    /// Mandatory switches ignore this. Read at the shell edge; the classify core is
    /// clock-free and takes the resulting bool.
    pub fn is_switch_suppressed(&self, now_ms: u64) -> bool {
        self.flap.is_hold_down_active(now_ms) || self.flap.is_flap_dampened(now_ms)
    }

    /// Evaluate whether to switch parents based on current peer tree state.
    ///
    /// Uses effective_depth (depth + link_cost) for parent comparison.
    /// `peer_costs` maps each peer's NodeAddr to its link cost (from local
    /// MMP measurements). Missing entries default to 1.0 (optimistic).
    ///
    /// Returns a [`ParentEval`] describing whether a parent switch is warranted:
    /// `Mandatory` (path-breaking / root-correcting — always taken), `Discretionary`
    /// (an improvement the caller applies only if its veto is inactive), or `None`.
    ///
    /// This core is clock-free: it no longer applies the flap-dampening / hold-down
    /// veto. The caller reads the clock, computes the veto verdict via
    /// [`is_switch_suppressed`](Self::is_switch_suppressed), and suppresses the
    /// `Discretionary` arm at the edge; `Mandatory` switches bypass the veto.
    ///
    /// `skip_peers` contains peers that should not be considered as parent
    /// candidates (e.g., non-routing and leaf nodes that don't forward transit).
    pub(crate) fn evaluate_parent(
        &self,
        peer_costs: &BTreeMap<NodeAddr, f64>,
        skip_peers: &BTreeSet<NodeAddr>,
    ) -> ParentEval {
        if self.peer_ancestry.is_empty() {
            return ParentEval::None;
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
            None => return ParentEval::None,
        };

        // If our own NodeAddr is smaller than (or equal to) the smallest visible
        // root, we are the network's smallest node and must be root. Returning
        // `None` lets the caller promote us via `become_root` / `should_be_root`.
        // Picking any peer here would produce an invalid path, since prepending
        // `self` to that peer's ancestry would put `self` at depth 0 and the
        // peer's larger root at the tail — violating "advertised root = min path
        // entry" and getting rejected by recipients' `validate_semantics`.
        if self.my_node_addr <= smallest_root {
            return ParentEval::None;
        }

        // Among peers that reach the smallest root, find the lowest effective_depth.
        // effective_depth(peer) = peer.depth + link_cost_to_peer
        let mut best_peer: Option<(NodeAddr, f64)> = None; // (peer_addr, effective_depth)
        for (peer_id, coords) in &self.peer_ancestry {
            if *coords.root_id() != smallest_root {
                continue;
            }
            // Skip non-routing/leaf peers (can't forward transit)
            if skip_peers.contains(peer_id) {
                continue;
            }
            // Reject candidates whose ancestry contains us (would create a loop)
            if coords.contains(&self.my_node_addr) {
                continue;
            }
            // If any peer has MMP cost data, only consider measured peers.
            // This prevents freshly connected peers (no SRTT, default cost 1.0)
            // from appearing artificially cheap. During cold start (no peer has
            // MMP data, peer_costs is empty), fall back to default cost 1.0.
            let cost = match peer_costs.get(peer_id) {
                Some(&c) => c,
                None if peer_costs.is_empty() => 1.0,
                None => continue,
            };
            let eff_depth = coords.depth() as f64 + cost;
            match &best_peer {
                None => best_peer = Some((*peer_id, eff_depth)),
                Some((best_id, best_eff)) => {
                    if eff_depth < *best_eff || (eff_depth == *best_eff && peer_id < best_id) {
                        best_peer = Some((*peer_id, eff_depth));
                    }
                }
            }
        }

        let (best_peer_id, best_eff_depth) = match best_peer {
            Some(b) => b,
            None => return ParentEval::None,
        };

        // If already using this peer as parent, no switch needed
        if *self.my_declaration.parent_id() == best_peer_id && !self.is_root() {
            return ParentEval::None;
        }

        // --- Mandatory switches (bypass the shell's hold-down / flap veto) ---

        // If our current parent is gone from peer_ancestry, our path is broken — always switch
        if !self.is_root()
            && !self
                .peer_ancestry
                .contains_key(self.my_declaration.parent_id())
        {
            return ParentEval::Mandatory(best_peer_id);
        }

        // Switching roots (smaller root found) → always switch
        if smallest_root < self.root || (self.is_root() && smallest_root < self.my_node_addr) {
            return ParentEval::Mandatory(best_peer_id);
        }

        // We're root but shouldn't be (peers have a smaller root) — always switch
        if self.is_root() {
            return ParentEval::Mandatory(best_peer_id);
        }

        // --- Discretionary switches (the caller applies the veto before taking) ---
        //
        // Same root, cost-aware comparison with hysteresis. Everything below is
        // veto-gated at the edge: the shell suppresses these `Discretionary` results
        // while hold-down / flap-dampening is active.

        // Current parent's effective_depth.
        // If peer_costs is non-empty but current parent has no entry,
        // treat as maximally expensive so any measured candidate can win.
        // If peer_costs is empty (cold start), use default cost 1.0.
        let current_parent_cost = peer_costs
            .get(self.my_declaration.parent_id())
            .copied()
            .unwrap_or(if peer_costs.is_empty() {
                1.0
            } else {
                f64::INFINITY
            });
        let current_parent_coords = self.peer_ancestry.get(self.my_declaration.parent_id());
        let current_parent_eff = match current_parent_coords {
            Some(coords) => coords.depth() as f64 + current_parent_cost,
            // Parent has no coords — treat as lost. This sat BELOW the veto, so it
            // is veto-gated: Discretionary, not Mandatory.
            None => return ParentEval::Discretionary(best_peer_id),
        };

        // Apply hysteresis: only switch if candidate is significantly better
        if best_eff_depth < current_parent_eff * (1.0 - self.parent_hysteresis) {
            return ParentEval::Discretionary(best_peer_id);
        }

        ParentEval::None
    }

    /// Handle loss of current parent.
    ///
    /// Tries to find an alternative parent among remaining peers.
    /// If none available, becomes its own root (increments sequence).
    ///
    /// Returns `true` if the tree state changed (caller should re-announce).
    ///
    /// `now_secs` is the injected wall-clock Unix seconds stamped onto the new
    /// declaration; `now_ms` is the monotonic milliseconds driving the parent
    /// re-evaluation's flap timers (the two clock bases must not be crossed).
    pub fn handle_parent_lost(
        &mut self,
        peer_costs: &BTreeMap<NodeAddr, f64>,
        now_secs: u64,
        now_ms: u64,
    ) -> bool {
        // Try to find an alternative parent. The veto is computed at the edge and
        // applied only to a discretionary result; a mandatory switch bypasses it.
        let suppressed = self.is_switch_suppressed(now_ms);
        let alt = match self.evaluate_parent(peer_costs, &BTreeSet::new()) {
            ParentEval::Mandatory(p) => Some(p),
            ParentEval::Discretionary(p) if !suppressed => Some(p),
            ParentEval::Discretionary(_) | ParentEval::None => None,
        };
        if let Some(new_parent) = alt {
            let new_seq = self.my_declaration.sequence() + 1;
            self.set_parent(new_parent, new_seq, now_secs, now_ms);
            self.recompute_coords();
            return true;
        }

        // No alternative: become own root
        let new_seq = self.my_declaration.sequence() + 1;
        self.my_declaration = ParentDeclaration::self_root(self.my_node_addr, new_seq, now_secs);
        self.recompute_coords();
        true
    }

    /// Mutable access to this node's declaration.
    ///
    /// Exposed so the shell can write back a signature after signing: the
    /// declaration data + `signing_bytes()` live in-core, but the key-crypto
    /// (the schnorr sign) is a shell-driven boundary (§6), mirroring discovery.
    pub(crate) fn my_declaration_mut(&mut self) -> &mut ParentDeclaration {
        &mut self.my_declaration
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
    /// Raw 64-byte Schnorr signature over the declaration fields. Stored as
    /// opaque bytes so the in-core type carries no signature-crypto dependency;
    /// the shell computes/verifies it over `signing_bytes()` (§6).
    signature: Option<[u8; 64]>,
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
        signature: [u8; 64],
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

    /// Get the raw 64-byte signature, if set.
    pub fn signature(&self) -> Option<&[u8; 64]> {
        self.signature.as_ref()
    }

    /// Set the raw 64-byte signature after signing.
    pub fn set_signature(&mut self, signature: [u8; 64]) {
        self.signature = Some(signature);
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
