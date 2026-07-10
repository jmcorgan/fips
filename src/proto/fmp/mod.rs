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
//! - `state.rs` — [`ConnectionState`], the pure handshake-phase connection
//!   bookkeeping (owned by the shell `PeerConnection` beside its Noise crypto
//!   handles) and its [`HandshakeState`] phase enum, plus [`Fmp`], the
//!   (stateless) lifecycle anchor owned by `Node`.
//! - `wire.rs` — the FMP link-framing codec: handshake message types,
//!   disconnect reasons, and the orderly disconnect message. Also carries the
//!   FMP link wire framing relocated from `node/wire.rs` — the common prefix,
//!   encrypted/msg1/msg2 headers, and the `build_*`/inner-header codec fns.

mod core;
mod limits;
mod state;
pub(crate) mod wire;

#[cfg(test)]
mod tests;

pub use core::cross_connection_winner;
pub(crate) use core::{
    ConnAction, ConnSnapshot, EstablishSnapshot, EstablishView, InboundDecision, InboundReject,
    LifecycleView, OutboundDecision, OutboundSnapshot, PeerSnapshot, RekeyCfg, RekeyResendSnapshot,
    WireOutcome,
};
pub(crate) use limits::backoff_ms;
pub use state::HandshakeState;
pub(crate) use state::{ConnectionState, Fmp};
pub use wire::HandshakeMessageType;
pub(crate) use wire::{Disconnect, DisconnectReason};
