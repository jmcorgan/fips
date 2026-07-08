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
//! - `coordinate.rs` — `TreeCoordinate` / `CoordEntry`.
//! - `limits.rs` — the flap-dampening / hold-down state machine.
//! - `wire.rs` — `TreeAnnounce` + `validate_semantics` (the one std-tethered
//!   file).

mod coordinate;
mod core;
mod limits;
mod state;
mod wire;

#[cfg(test)]
mod tests;

use thiserror::Error;

use crate::{IdentityError, NodeAddr};

pub use coordinate::{CoordEntry, TreeCoordinate};
pub(crate) use core::{Stp, TreeDecision};
pub use state::{ParentDeclaration, TreeState};
pub use wire::TreeAnnounce;
pub(crate) use wire::{
    coords_wire_size, decode_coords, decode_optional_coords, encode_coords, encode_empty_coords,
};

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
