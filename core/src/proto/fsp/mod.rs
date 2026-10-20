//! Sans-IO FSP (end-to-end session) protocol.
//!
//! The FSP session **wire** — the message types
//! (`SessionSetup`/`SessionAck`/`SessionMsg3`), the packet flags, the
//! `SessionMessageType` inner-message catalog, and the prefix/header/
//! inner-header codec — migrated out of the async node shell (`protocol::session`
//! + `node::session_wire`) per the wire-migrates-with-subsystem policy.
//!
//! The `SessionEntry` session state machine stays shell-side in
//! `node::session`; the keys it holds live in a rekey machine on this
//! layer's profile in `rekey/`, the one part of this module that names
//! Noise. The rest of `proto::fsp` carries no crypto. It imports the shared
//! [`crate::proto::Error`] and the address-only coordinate helpers downward
//! from `crate::proto::stp`.
//!
//! - `core.rs` — the stateless [`Fsp`] anchor + [`FspAction`]: the
//!   coordinate and path-MTU reactions and the pure MTU-clamp /
//!   bounded-queue / ECN transforms. No clock/crypto/I/O/tracing. The first
//!   handshake and every rekey, cutover and drain belong to the session
//!   rekey machine.
//! - `rekey/` — the session profile of the shared rekey machine (Noise XK),
//!   the one part of this module that holds keys; hidden. The root crate's
//!   session table holds one machine per session, from its first handshake.
//! - `quorum.rs` — the distinct-link quorum that gates demoting verified
//!   coordinates on `PathBroken`. Clock injected.
//! - `wire.rs` — the FSP session wire codec and message types. Clock-free,
//!   crypto-free.

pub mod core;
pub mod quorum;
#[doc(hidden)]
pub mod rekey;
pub mod wire;

#[cfg(test)]
mod tests;

pub use core::{Fsp, FspAction, mark_ipv6_ecn_ce, push_bounded_pending, should_apply_path_mtu};
pub use wire::{
    FspInnerFlags, SessionAck, SessionFlags, SessionMessageType, SessionMsg3, SessionSetup,
};
