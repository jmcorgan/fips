//! A crate that uses every item the root clippy.toml bans: once each in
//! `banned`, and again in `allowed` under a file-level allow.

pub mod allowed;
pub mod banned;
