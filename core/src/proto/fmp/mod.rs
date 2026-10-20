//! Sans-IO FMP connection-lifecycle state machine.
//!
//! Pure, runtime-agnostic maintain/teardown decisions for the FMP peer
//! connection lifecycle, migrated out of the async node shell. The async I/O
//! adapters remain in `node::handlers::{timeout,rekey}`.
//!
//! This covers the four tick-poll maintain/teardown drivers (handshake
//! timeout/teardown, msg1 resend, rekey cutover/drain/trigger, rekey-msg1
//! resend) plus the inbound-msg1 classification decision
//! ([`Fmp::establish_inbound`]). Handshake message bytes are opaque blobs
//! throughout — the Noise wire construction and `promote_connection` effects,
//! the outbound `handle_msg2` classification, and the born-on-next
//! `handle_msg3` leaf stay in `node/`.
//!
//! - `core.rs` — the [`LifecycleView`] read-seam trait, the [`ConnAction`]
//!   effect vocabulary, the snapshot types, the pure `poll_*` decisions, and
//!   the [`cross_connection_winner`] tie-break helper.
//! - `limits.rs` — the pure connection-retry backoff math.
//! - `rekey/` — the link profile of the shared rekey machine (Noise IK) and
//!   the node-level msg1 read; hidden, with no caller yet.
//! - `silent.rs` — [`SilentSessions`], the per-identity record of link
//!   sessions that ended without an authenticated frame, and the msg1
//!   refusal it drives.
//! - `state.rs` — [`ConnectionState`], the pure handshake-phase connection
//!   bookkeeping (owned by the per-peer control machine beside its Noise
//!   crypto carrier), plus [`Fmp`], the (stateless) lifecycle anchor owned by
//!   `Node`.
//!   The handshake phase itself lives on the per-peer control machine.
//! - `wire.rs` — the FMP link-framing codec: handshake message types,
//!   disconnect reasons, and the orderly disconnect message. Also carries the
//!   FMP link wire framing relocated from `node/wire.rs` — the common prefix,
//!   encrypted/msg1/msg2 headers, and the `build_*`/inner-header codec fns.

mod core;
mod limits;
#[doc(hidden)]
pub mod rekey;
mod silent;
mod state;
pub mod wire;

#[cfg(test)]
mod tests;

pub use core::{
    AnsweredMsg1s, ConnAction, ConnSnapshot, EphemeralDigest, EstablishSnapshot, EstablishView,
    InboundDecision, InboundReject, LifecycleView, Msg1Arrival, Msg1Digest, OutboundDecision,
    OutboundSnapshot, PeerSnapshot, REKEY_MIN_CUTOVER_AGE_SECS, RekeyAnswer, RekeyCfg,
    RekeyResendSnapshot, RekeyRole, WireOutcome,
};
pub use core::{PromotionResult, cross_connection_winner};
pub use limits::backoff_ms;
pub use silent::SilentSessions;
pub use state::{ConnectionState, Fmp};
pub use wire::HandshakeMessageType;
pub use wire::{Disconnect, DisconnectReason};
