//! Sans-IO FMP connection-lifecycle state machine.
//!
//! Pure, runtime-agnostic maintain/teardown decisions for the FMP peer
//! connection lifecycle, migrated out of the async node shell. The async I/O
//! adapters remain in `node::handlers::{timeout,rekey}`.
//!
//! This covers the four tick-poll maintain/teardown drivers (handshake
//! timeout/teardown, msg1 resend, rekey cutover/drain/trigger, rekey-msg1
//! resend) plus the XX inbound `msg3` establish classification
//! ([`InboundDecision`], decided by [`Fmp::establish_inbound`]). Handshake
//! message bytes are opaque blobs throughout — the establish leaf's Noise wire
//! construction and `promote_connection` effects are born-on-next and stay in
//! `node/`; only the classification decision lives here.
//!
//! - `core.rs` — the [`LifecycleView`] read-seam trait, the [`ConnAction`]
//!   effect vocabulary, the snapshot types, the [`InboundDecision`] establish
//!   classification, the pure `poll_*`/`establish_inbound` decisions, the
//!   [`cross_connection_winner`] tie-break helper, and the FMP negotiation
//!   decision logic (version agreement, profile validation).
//! - `limits.rs` — the pure connection-retry backoff math.
//! - `state.rs` — [`ConnectionState`], the pure handshake-phase connection
//!   bookkeeping (owned by the per-peer control machine beside its Noise
//!   crypto carrier), plus [`Fmp`], the (stateless) lifecycle anchor owned by
//!   `Node`.
//!   The handshake phase itself lives on the per-peer control machine.
//! - `wire.rs` — the FMP wire codec: XX handshake message types, disconnect
//!   reasons, the orderly disconnect message, and the negotiation payload.
//!   Also carries the relocated FMP link wire framing (moved from
//!   `node/wire.rs`): the common prefix, encrypted/established headers, and
//!   the msg1/msg2/msg3 handshake framing.

mod core;
mod limits;
mod state;
pub(crate) mod wire;

#[cfg(test)]
mod tests;

pub(crate) use core::{
    ConnAction, ConnSnapshot, EstablishSnapshot, InboundDecision, InboundReject, LifecycleView,
    OutboundDecision, OutboundSnapshot, PeerSnapshot, RekeyCfg, RekeyResendSnapshot, WireOutcome,
    decide_fmp_negotiation,
};
pub use core::{PromotionResult, cross_connection_winner};
pub(crate) use limits::backoff_ms;
pub(crate) use state::{ConnectionState, Fmp};
pub(crate) use wire::{Disconnect, DisconnectReason};
pub use wire::{HandshakeMessageType, NegotiationPayload, NodeProfile, TlvEntry};
