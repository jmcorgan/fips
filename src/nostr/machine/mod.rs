//! The Nostr rendezvous machine: the decisions of FRC-1601, with no I/O.
//!
//! The fence: this module is written against `core`, `alloc`, `fips_core`,
//! `serde` and `sha2`, and never names `std`, `tokio`, `tracing`, `nostr_sdk`,
//! `rand` or anything in the root crate outside `crate::nostr::machine`. It
//! reads no clock, draws no randomness and logs nothing: the shell in
//! `src/nostr/` does those and passes what it read in as arguments. Nothing
//! builds the module without `std`, so `testing/check-nostr-machine.py` holds
//! the fence in local CI and GitHub CI. It flags the names it bans, so a crate
//! it does not name passes it; its README lists what it flags.
//!
//! Its pieces arrive from the shell one at a time, each with its tests; the
//! shell keeps the paths its callers already use by re-exporting them.

pub mod types;
