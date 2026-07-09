//! Sans-IO mesh lookup protocol state.
//!
//! Pure, runtime-agnostic mesh lookup state and rate limiting, migrated out
//! of the async node shell. The async I/O handlers remain in
//! `node::handlers::lookup`. The mesh lookup wire codec now lives here in
//! `wire.rs` (the `LookupRequest` / `LookupResponse` structs), per the
//! wire-migrates-with-subsystem policy.
//!
//! The sans-IO decision core lives in `core.rs`: it defines the `RoutingView`
//! read-seam trait plus the `plan_forward` / `plan_initiate` LookupRequest
//! planners and their `LookupAction` / `ForwardOutcome` types. The async
//! shell decodes wire
//! bytes, calls the planner, and drives the returned actions.

mod core;
mod limits;
mod state;
mod wire;

#[cfg(test)]
mod tests;

pub(crate) use core::{
    ForwardOutcome, InitiateDecision, LookupAction, RequestOutcome, ResponseRoute,
    ResponseRouteDecision, RoutingView, classify_request, classify_response, initiate_failed,
    initiate_gate, on_response_accepted, plan_forward, plan_initiate, plan_response_route,
    poll_pending,
};
pub(crate) use limits::{LookupBackoff, LookupForwardRateLimiter, MAX_RECENT_LOOKUP_REQUESTS};
#[cfg(test)]
pub(crate) use state::RecentRequest;
pub(crate) use state::{Lookup, PendingLookup};
pub use wire::{LookupRequest, LookupResponse};
