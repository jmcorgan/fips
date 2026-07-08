//! Sans-IO spanning tree protocol (STP) state.
//!
//! The non-async STP surface has been migrated out of the async node shell:
//! `TreeState` ranking/election, `TreeCoordinate` algebra, `ParentDeclaration`
//! data, and the flap-dampening limiter all live here. The async I/O handlers
//! remain in `node::tree`. The STP wire codec lives in `wire.rs` (the
//! `TreeAnnounce` struct + `validate_semantics`), per the
//! wire-migrates-with-subsystem policy. It imports the shared
//! [`crate::proto::Error`] and [`crate::proto::link::LinkMessageType`] downward.
//!
//! - `core.rs` — the pure classify ladder (`Stp::classify_announce` /
//!   `classify_periodic` / `should_echo`) over an in-core `TreeState`.
//! - `state.rs` — `TreeState` + `ParentDeclaration` data + the `&self`
//!   ranking/election methods (`evaluate_parent`, `should_be_root`,
//!   `find_next_hop`).
//! - `TreeCoordinate` / `CoordEntry` now live in the shared
//!   [`crate::proto::coord`] primitive and are re-exported here for continuity.
//! - `limits.rs` — the flap-dampening / hold-down state machine.
//! - `wire.rs` — `TreeAnnounce` + `validate_semantics` (the one std-tethered
//!   file).

mod core;
mod declaration;
mod limits;
mod state;
mod wire;

#[cfg(test)]
mod tests;

use crate::{IdentityError, NodeAddr};

pub use crate::proto::coord::{CoordEntry, CoordError, TreeCoordinate};
pub(crate) use crate::proto::coord::{
    coords_wire_size, decode_coords, decode_optional_coords, encode_coords, encode_empty_coords,
};
pub(crate) use core::{ParentEval, Stp, TreeDecision};
pub use declaration::ParentDeclaration;
pub use state::TreeState;
pub use wire::TreeAnnounce;

/// Errors related to spanning tree operations.
#[derive(Debug)]
pub enum TreeError {
    /// Coordinate path had zero entries.
    EmptyCoordinate,

    /// Ancestry path does not reach the claimed root.
    AncestryNotToRoot,

    /// Root declaration contained hops other than the sender.
    RootDeclarationMismatch,

    /// Non-root declaration was missing its parent hop.
    AncestryTooShort,

    /// Declared sender does not match the first ancestry entry.
    AncestryNodeMismatch {
        /// The declared sender address.
        declared: NodeAddr,
        /// The first ancestry path entry.
        ancestry: NodeAddr,
    },

    /// Signed parent does not match the first ancestry hop.
    AncestryParentMismatch {
        /// The signed parent address.
        declared: NodeAddr,
        /// The first ancestry hop.
        ancestry: NodeAddr,
    },

    /// Advertised root is not the minimum path entry.
    AncestryRootNotMinimum {
        /// The advertised root address.
        advertised: NodeAddr,
        /// The minimum path entry.
        minimum: NodeAddr,
    },

    /// Signature verification failed for the given node.
    InvalidSignature(NodeAddr),

    /// Sequence number regressed below the expected value.
    SequenceRegression {
        /// The received sequence number.
        got: u64,
        /// The value the sequence had to exceed.
        expected: u64,
    },

    /// Declared parent was not among the known peers.
    ParentNotPeer(NodeAddr),

    /// An identity operation failed.
    Identity(IdentityError),
}

impl ::core::fmt::Display for TreeError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
        match self {
            TreeError::EmptyCoordinate => write!(f, "invalid tree coordinate: empty path"),
            TreeError::AncestryNotToRoot => {
                write!(f, "invalid ancestry: does not reach claimed root")
            }
            TreeError::RootDeclarationMismatch => write!(
                f,
                "invalid ancestry: root declaration must contain only the sender"
            ),
            TreeError::AncestryTooShort => write!(
                f,
                "invalid ancestry: non-root declaration must include a parent hop"
            ),
            TreeError::AncestryNodeMismatch { declared, ancestry } => write!(
                f,
                "invalid ancestry: sender {declared} does not match first path entry {ancestry}"
            ),
            TreeError::AncestryParentMismatch { declared, ancestry } => write!(
                f,
                "invalid ancestry: signed parent {declared} does not match first ancestry hop {ancestry}"
            ),
            TreeError::AncestryRootNotMinimum {
                advertised,
                minimum,
            } => write!(
                f,
                "invalid ancestry: advertised root {advertised} is not the minimum path entry {minimum}"
            ),
            TreeError::InvalidSignature(node) => {
                write!(f, "signature verification failed for node {node:?}")
            }
            TreeError::SequenceRegression { got, expected } => {
                write!(
                    f,
                    "sequence number regression: got {got}, expected > {expected}"
                )
            }
            TreeError::ParentNotPeer(node) => write!(f, "parent not in peers: {node:?}"),
            TreeError::Identity(e) => write!(f, "identity error: {e}"),
        }
    }
}

impl ::core::error::Error for TreeError {
    fn source(&self) -> Option<&(dyn ::core::error::Error + 'static)> {
        match self {
            TreeError::Identity(e) => Some(e),
            _ => None,
        }
    }
}

impl From<IdentityError> for TreeError {
    fn from(e: IdentityError) -> Self {
        TreeError::Identity(e)
    }
}
