//! Utility modules.
//!
//! Shared infrastructure that doesn't belong to a specific protocol layer:
//! session index allocation, Unix socket binding and its permission
//! primitives, the control clients' check of who serves a socket, and other
//! cross-cutting concerns.

pub mod index;
pub mod logfile;
pub mod onlink;
pub mod sockbind;
#[cfg(unix)]
pub mod sockpeer;
#[cfg(unix)]
pub mod sockperm;
