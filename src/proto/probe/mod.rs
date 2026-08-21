//! Sans-IO diagnostic-probe state.
//!
//! Pure, runtime-agnostic decisions for the `probe` diagnostic: a four-stage
//! machine (resolve, path, session, rtt) driven one step per rx-loop tick. The
//! async adapter lives in `node::handlers::probe`; the control-socket
//! projection lives in `control::probe`.
//!
//! - `core.rs` — the [`Probe`] stage machine, its [`Observation`] input and
//!   [`ProbeAction`] output, and the pure [`describe_path`] LCA arithmetic.
//! - `state.rs` — the stage/verdict/reason vocabulary and the plain-data
//!   preflight and report snapshots.
//! - `limits.rs` — budget floors, latch counts, and the registry cap.

mod core;
mod limits;
mod state;

#[cfg(test)]
mod tests;

pub(crate) use core::{Budgets, Observation, Probe, ProbeAction, describe_path};
pub(crate) use limits::{MAX_CONCURRENT_PROBES, REAP_MS};
#[cfg(test)]
pub(crate) use state::StageVerdict;
pub(crate) use state::{
    LeftIntact, LookupOutcomeKind, NextHopFacts, NoHopReason, Preflight, ProbeSnapshot,
    RttCounters, StageRecord,
};
