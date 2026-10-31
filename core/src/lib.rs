//! The `no_std` core of FIPS.
//!
//! Code in this crate builds for any target with an allocator. The rule that
//! keeps it so: no `std`, no async runtime, no OS calls, and no target `cfg`.
//! Anything that needs one of those belongs in the root `fips` crate, which
//! supplies it to the core rather than the core reaching for it.

#![no_std]

extern crate alloc;

// Tests run on the host, where the standard library is available. So do
// the root crate's tests, the only builds that enable `test-hooks`; the
// per-thread DH counter it exposes (`noise::dh_ops`) needs `std`.
#[cfg(any(test, feature = "test-hooks"))]
extern crate std;

pub mod cache;
pub mod entropy;
pub mod identity;
pub mod node;
pub mod noise;
pub mod proto;
pub mod time;
pub mod transport;
pub mod utils;

#[cfg(test)]
mod testutil;
