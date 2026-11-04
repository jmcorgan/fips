//! Peer settlement: how two nodes that dial each other, restart or rekey
//! settle on one session on one link.
//!
//! The settlement core is the sans-IO judgement the node shell will call.
//! It is compiled in every build and nothing calls it yet. It holds the
//! link records ([`links`]), the restart gates ([`gates`]) and the
//! handshake legs ([`legs`]), with the intervals they read ([`params`]),
//! and the judgements over them ([`table`]), which take an [`input`] and
//! return [`output`]s. The reference model ([`model`]) beside it
//! is compiled for tests and the `test-hooks` feature alone, with the
//! deterministic world its tests explore both in. No core file refers to
//! the model, and the model refers to no core item.

#![deny(clippy::wildcard_enum_match_arm)]

/// Whether the test-only switch `$f` is on (see `faults.rs`).
#[cfg(test)]
macro_rules! fault {
    ($f:ident) => {
        $crate::proto::settle::faults::on($crate::proto::settle::faults::Fault::$f)
    };
}

/// Outside test builds no guard can be switched off.
#[cfg(not(test))]
macro_rules! fault {
    ($f:ident) => {
        false
    };
}

#[cfg(test)]
mod faults;
pub mod gates;
pub mod input;
pub mod legs;
pub mod links;
#[cfg(any(test, feature = "test-hooks"))]
pub mod model;
pub mod output;
pub mod params;
pub mod table;

#[cfg(test)]
mod tests;
