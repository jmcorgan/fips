//! Sans-IO discovery protocol state.
//!
//! Pure, runtime-agnostic discovery state and rate limiting, migrated out
//! of the async node shell. The async I/O handlers remain in
//! `node::handlers::discovery`. The discovery wire codec now lives here in
//! `wire.rs` (the `LookupRequest` / `LookupResponse` structs), per the
//! wire-migrates-with-subsystem policy.
//!
//! The sans-IO decision core lives in `core.rs`: it defines the `RoutingView`
//! read-seam trait plus the `plan_forward` / `plan_initiate` LookupRequest
//! planners and their `DiscoveryAction` / `ForwardOutcome` types. The async
//! shell decodes wire
//! bytes, calls the planner, and drives the returned actions.

mod core;
mod limits;
mod state;
mod wire;

#[cfg(test)]
mod tests;

pub(crate) use core::{
    DiscoveryAction, ForwardOutcome, InitiateDecision, RequestOutcome, ResponseRoute,
    ResponseRouteDecision, RoutingView, classify_request, classify_response, initiate_failed,
    initiate_gate, on_response_accepted, plan_forward, plan_initiate, plan_response_route,
    poll_pending,
};
pub(crate) use limits::{
    DiscoveryBackoff, DiscoveryForwardRateLimiter, MAX_RECENT_DISCOVERY_REQUESTS,
};
#[cfg(test)]
pub(crate) use state::RecentRequest;
pub(crate) use state::{Discovery, PendingLookup};
pub use wire::{LookupRequest, LookupResponse};
