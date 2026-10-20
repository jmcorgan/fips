//! Sans-IO FMP connection-lifecycle state machine.
//!
//! Pure, runtime-agnostic maintain/teardown decisions for the FMP peer
//! connection lifecycle, migrated out of the async node shell. The async I/O
//! adapters remain in `node::handlers::{timeout,rekey}`.
//!
//! This covers the two tick-poll maintain/teardown drivers (handshake
//! timeout/teardown and msg1 resend) plus the XX inbound `msg3` establish
//! classification ([`InboundDecision`], decided by [`Fmp::establish_inbound`]);
//! link rekeys are decided by each link's rekey machine on the `rekey/`
//! profile, and a declared rekey at `msg3` is handed to that machine. Handshake
//! message bytes are opaque blobs throughout — the establish leaf's Noise wire
//! construction and `promote_connection` effects are born-on-next and stay in
//! `node/`; only the classification decision lives here.
//!
//! - `core.rs` — the [`LifecycleView`] read-seam trait, the [`ConnAction`]
//!   effect vocabulary, the snapshot types, the [`InboundDecision`] establish
//!   classification, the [`DialMsg2Decision`] initiator-side initial `msg2`
//!   dial-identity classification, the pure
//!   `poll_*`/`establish_inbound`/`establish_outbound`/`dial_outbound`
//!   decisions, the [`cross_connection_winner`] tie-break helper, and the FMP
//!   negotiation decision logic (version agreement, profile validation).
//! - `limits.rs` — the pure connection-retry backoff math.
//! - `rekey/` — the link profile of the shared rekey machine (Noise XX) and
//!   the node-level msg3 read of an inbound leg; hidden from the docs.
//! - `silent.rs` — [`SilentSessions`], the per-identity record of link
//!   sessions that ended without an authenticated frame, and the msg1
//!   refusal it drives.
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
#[doc(hidden)]
pub mod rekey;
mod silent;
mod state;
pub mod wire;

#[cfg(test)]
mod tests;

pub use core::{
    ConnAction, ConnSnapshot, DialMsg2Decision, DialMsg2Reject, DialMsg2Snapshot,
    EPOCH_RESTART_MIN_INTERVAL_SECS, EphemeralDigest, EstablishSnapshot, InboundDecision,
    InboundReject, LifecycleView, Msg1Digest, OutboundDecision, OutboundSnapshot, RekeyClaim,
    WireOutcome, decide_fmp_negotiation,
};
pub use core::{PromotionResult, cross_connection_winner};
pub use limits::backoff_ms;
pub use silent::SilentSessions;
pub use state::{ConnectionState, Fmp};
pub use wire::{Disconnect, DisconnectReason};
pub use wire::{HandshakeMessageType, NegotiationPayload, NodeProfile, TlvEntry};
