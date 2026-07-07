//! Sans-IO (runtime-agnostic) protocol state machines.
//!
//! A module here has been migrated out of the async node shell; the async
//! I/O adapters remain in `node::handlers`.

pub(crate) mod discovery;
pub(crate) mod fmp;
pub(crate) mod routing;
