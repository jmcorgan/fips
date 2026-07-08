//! Sans-IO (runtime-agnostic) protocol state machines.
//!
//! A module here has been migrated out of the async node shell; the async
//! I/O adapters remain in `node::handlers`.

mod error;
pub use error::Error;

pub(crate) mod bloom;
pub(crate) mod codec;
pub(crate) mod coord;
pub(crate) mod discovery;
pub(crate) mod fmp;
pub(crate) mod fsp;
pub(crate) mod link;
pub(crate) mod mmp;
pub(crate) mod rate_limit;
pub(crate) mod routing;
pub(crate) mod stp;
