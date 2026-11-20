//! Real nodes driven by a schedule, and the real-node explorer that runs
//! the core's named starts on them.
//!
//! A `World` holds two or three real `Node`s on one transport, each node's
//! receive channel held by the test. A schedule is a list of `Step`s, as
//! data, and `script::run` applies them one at a time: every dial goes
//! through `initiate_connection`, time moves by `crate::time::advance`, and
//! a packet reaches a node only when a step hands it over.
//! The explorer runs each named start's script, then each single variation
//! of it, a handshake packet dropped, duplicated or swapped.
//! The shared schedules of `fips_core::proto::settle::parity` run here too,
//! each end compared after each step with the committed trace.
//! `src/node/tests/settle/explore/README.md` says what each step does, what
//! the world does not model, and which starts run.

// Without the `explorers` feature only the world's own tests, the map of
// pinned defects and the test of a walk thread's name compile, and most of
// the explorer's machinery (the walk, the reference model, the worker
// pools) has no caller. It is kept compiled so those tests and the walks
// share one copy; the --all-features clippy pass still finds code nothing
// at all uses.
#![cfg_attr(not(feature = "explorers"), allow(dead_code))]

// The explorer's file is named for what the directory is for.
#[allow(clippy::module_inception)]
mod explore;
mod model;
// The walks run only with the `explorers` feature (see the crate's
// Cargo.toml and this directory's README); the world's own tests and the
// map of pinned defects run in every build.
#[cfg(feature = "explorers")]
mod oracle;
#[cfg(feature = "explorers")]
mod parity;
mod script;
mod starts;
mod world;
