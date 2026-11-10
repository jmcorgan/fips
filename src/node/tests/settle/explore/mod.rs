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

// The explorer's file is named for what the directory is for.
#[allow(clippy::module_inception)]
mod explore;
mod model;
mod oracle;
mod parity;
mod script;
mod starts;
mod world;
