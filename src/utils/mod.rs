//! Utility modules.
//!
//! Shared infrastructure that doesn't belong to a specific protocol layer:
//! session index allocation, Unix socket binding, and other cross-cutting
//! concerns.

pub mod index;
pub mod sockbind;
