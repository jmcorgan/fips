//! Spanning Tree Protocol Entities
//!
//! Tree coordinates and parent declarations for the FIPS spanning tree.
//! The spanning tree provides a routing topology where each node maintains
//! a path to a common root, enabling greedy distance-based routing.

mod coordinate;
mod declaration;
mod state;

use thiserror::Error;

use crate::{IdentityError, NodeAddr};

pub use coordinate::{CoordEntry, TreeCoordinate};
pub use declaration::ParentDeclaration;
pub use state::TreeState;

/// Errors related to spanning tree operations.
#[derive(Debug, Error)]
pub enum TreeError {
    #[error("invalid tree coordinate: empty path")]
    EmptyCoordinate,

    #[error("invalid ancestry: does not reach claimed root")]
    AncestryNotToRoot,

    #[error("invalid ancestry: root declaration must contain only the sender")]
    RootDeclarationMismatch,

    #[error("invalid ancestry: non-root declaration must include a parent hop")]
    AncestryTooShort,

    #[error("invalid ancestry: sender {declared} does not match first path entry {ancestry}")]
    AncestryNodeMismatch {
        declared: NodeAddr,
        ancestry: NodeAddr,
    },

    #[error(
        "invalid ancestry: signed parent {declared} does not match first ancestry hop {ancestry}"
    )]
    AncestryParentMismatch {
        declared: NodeAddr,
        ancestry: NodeAddr,
    },

    #[error(
        "invalid ancestry: advertised root {advertised} is not the minimum path entry {minimum}"
    )]
    AncestryRootNotMinimum {
        advertised: NodeAddr,
        minimum: NodeAddr,
    },

    #[error("signature verification failed for node {0:?}")]
    InvalidSignature(NodeAddr),

    #[error("sequence number regression: got {got}, expected > {expected}")]
    SequenceRegression { got: u64, expected: u64 },

    #[error("parent not in peers: {0:?}")]
    ParentNotPeer(NodeAddr),

    #[error("identity error: {0}")]
    Identity(#[from] IdentityError),
}

#[cfg(test)]
mod tests;
