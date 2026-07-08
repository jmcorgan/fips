//! Sans-IO routing protocol state.
//!
//! Pure, runtime-agnostic routing state and decision core, migrated out of
//! the async node shell. The async I/O handlers remain in
//! `node::handlers::forwarding`.
//!
//! - `core.rs` — the `RoutingView` read-seam trait, the `NextHop` /
//!   `RouteOutcome` types, `Router::route`, the pure transit-forward
//!   decision (TTL, local-vs-forward, path-MTU min-fold, ECN CE), and the
//!   pure candidate assembly + hop-selection / route-classification helpers
//!   (`Candidate`, `RouteClass`, `routing_candidates`, `select_best_candidate`,
//!   `classify_forward`). The assembly reads raw per-peer data through the
//!   `RoutingView` seam; the shell keeps only the seam impl.
//! - `state.rs` — `Router`, the routing-subsystem state owned by `Node`.
//! - `limits.rs` — the routing error-signal rate limiter.
//! - `wire.rs` — the routing error-signal PDUs (`CoordsRequired`,
//!   `PathBroken`, `MtuExceeded`) and the `RoutingSignalType` (`0x20`–`0x2F`)
//!   message-type registry split off from the FSP `SessionMessageType`.

mod core;
mod limits;
mod state;
mod wire;

#[cfg(test)]
mod tests;

pub(crate) use core::{
    DropReason, NextHop, RouteAction, RouteClass, RouteOutcome, RoutingView, classify_forward,
    routing_candidates, select_best_candidate,
};
pub(crate) use limits::RoutingErrorRateLimiter;
pub(crate) use state::Router;
pub use wire::{
    COORDS_REQUIRED_SIZE, CoordsRequired, MTU_EXCEEDED_SIZE, MtuExceeded, PathBroken,
    RoutingSignalType,
};
