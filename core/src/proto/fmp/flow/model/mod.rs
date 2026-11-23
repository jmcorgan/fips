//! A reference model of the XX handshake's settlement, written from
//! FRC-2201 Sections 5.2 to 5.7 and 7.2 to 7.4, without reference to the
//! code that implements them.
//!
//! From an abstract [`history`] of what one node saw of one peer identity,
//! [`judge::Judge`] gives the node's settled handshake and link, each
//! completed handshake's class, each check that refused one, and each peer
//! change. Where the FRC is silent, or where a node keeps its own rule in
//! place of an FRC rule, the judge follows a named [`judge::LocalRule`].
//! Tests compare the flow and the transcription of next's rules with it;
//! when they disagree, the question is whether the judge misreads the FRC,
//! the code breaks it, or a local rule decides it.
//!
//! `no_std` with `alloc`, and compiled only for tests.

pub mod history;
pub mod judge;

#[cfg(test)]
mod tests;
