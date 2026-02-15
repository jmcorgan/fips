//! Tree coordinates and distance calculations.

use std::fmt;

use super::TreeError;
use crate::NodeAddr;

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
    pub fn node_addrs(&self) -> impl DoubleEndedIterator<Item = &NodeAddr> {
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
