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

/// Whether the mutation lane's switch `$f` is on (see `faults.rs`). Outside
/// test builds and the `test-hooks` feature it is the literal `false`, so
/// production code has no switch to turn and the branch it guards compiles
/// away. Defined before the modules so every one of them sees it.
#[cfg(any(test, feature = "test-hooks"))]
macro_rules! node_fault {
    ($f:ident) => {
        $crate::faults::on($crate::faults::Fault::$f)
    };
}

/// Outside test builds no break can be switched on.
#[cfg(not(any(test, feature = "test-hooks")))]
macro_rules! node_fault {
    ($f:ident) => {
        false
    };
}

pub mod cache;
pub mod entropy;
#[doc(hidden)]
#[cfg(any(test, feature = "test-hooks"))]
pub mod faults;
pub mod identity;
pub mod node;
pub mod noise;
pub mod proto;
pub mod time;
pub mod transport;
pub mod utils;

#[cfg(test)]
mod testutil;
