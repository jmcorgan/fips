//! Sans-IO FSP (end-to-end session) protocol.
//!
//! The FSP session **wire** — the message types
//! (`SessionSetup`/`SessionAck`/`SessionMsg3`), the packet flags, the
//! `SessionMessageType` inner-message catalog, and the prefix/header/
//! inner-header codec — migrated out of the async node shell (`protocol::session`
//! + `node::session_wire`) per the wire-migrates-with-subsystem policy.
//!
//! The crypto-owning `SessionEntry` session state machine stays shell-side in
//! `node::session`, so `proto::fsp` carries no `proto -> noise` dependency and
//! no crypto. It imports the shared [`crate::proto::Error`] and the
//! address-only coordinate helpers downward from `crate::proto::stp`.
//!
//! - `core.rs` — the stateless [`Fsp`] anchor + [`FspAction`]: the pure rekey
//!   choreography (`poll_rekey`/`poll_rekey_msg3_resends`), the post-decrypt
//!   `classify_epoch`, the initiation tie-break, and the pure MTU-clamp /
//!   bounded-queue / ECN transforms. No clock/crypto/I/O/tracing.
//! - `limits.rs` — the session-rekey timing constants.
//! - `wire.rs` — the FSP session wire codec and message types. Clock-free,
//!   crypto-free.

pub(crate) mod core;
pub(crate) mod limits;
pub(crate) mod wire;

#[cfg(test)]
mod tests;

pub(crate) use core::{
    DecryptSlot, EpochReaction, Fsp, FspAction, RekeyCfg, RekeyMsg3ResendSnapshot, SessionSnapshot,
    cutover_timer_elapsed, initiation_winner, mark_ipv6_ecn_ce, push_bounded_pending,
};
pub use wire::{
    FspInnerFlags, SessionAck, SessionFlags, SessionMessageType, SessionMsg3, SessionSetup,
};
