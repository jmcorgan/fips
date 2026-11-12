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
    ForwardOutcome, InitiateDecision, LookupAction, RequestOutcome, ResponseRoute, RoutingView,
    classify_request, classify_response, initiate_failed, initiate_gate, on_response_accepted,
    plan_initiate, plan_transit_forward, poll_pending,
};
// The shell forwards through `plan_transit_forward`; the planner it wraps is
// named directly only by the tests of its peer selection.
#[cfg(test)]
pub(crate) use core::plan_forward;
// The shell reads the refusal reason off `ResponseRoute::Ineligible` without
// naming its type; only the tests name it.
#[cfg(test)]
pub(crate) use core::Ineligibility;
pub(crate) use limits::{
    LookupBackoff, LookupForwardRateLimiter, MAX_BACKOFF_ENTRIES, MAX_FORWARD_ENTRIES,
    MAX_RECENT_LOOKUP_REQUESTS,
};
pub(crate) use state::{Lookup, PendingLookup};
#[cfg(test)]
pub(crate) use state::{MAX_RELAYED_DIGESTS, RecentRequest};
// The eviction policy reads the share floor through `Lookup::peer_share`;
// only the node-level regression tests name the constant itself.
#[cfg(test)]
pub(crate) use state::MIN_RECENT_PER_PEER;
pub use wire::{LookupRequest, LookupResponse};
