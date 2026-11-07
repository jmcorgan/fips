//! A reference model of peer settlement, written from FRC-1201 Sections 5.5
//! to 5.8 and the operator's decisions, without reference to the code that
//! implements them.
//!
//! From an abstract [`history`] of what one node saw of one peer identity,
//! [`judge::Judge`] gives the node's settled handshake and link, each
//! msg1's class, each peer change's transition, and the `(transport,
//! address)` each link still needs. Where the FRC is silent the model
//! follows a named [`judge::LocalRule`]. Tests compare the code with it;
//! when they disagree, the question is whether the model misreads the FRC,
//! the code breaks it, or a local rule decides it.
//!
//! `no_std` with `alloc`, and compiled only for tests and the `test-hooks`
//! feature: every item is `pub`, so the root crate's `test-hooks` build has
//! nothing unused.

pub mod history;
pub mod judge;

#[cfg(test)]
mod tests;
