//! Sans-IO FMP connection-lifecycle state machine.
//!
//! Pure, runtime-agnostic maintain/teardown decisions for the FMP peer
//! connection lifecycle, migrated out of the async node shell. The async I/O
//! adapters remain in `node::handlers::{timeout,rekey}`.
//!
//! This covers the tick-poll maintain/teardown driver (handshake
//! timeout/teardown); each handshake is classified by the settlement core
//! (`proto::settle`), and link rekeys are decided by each link's rekey
//! machine on the `rekey/` profile. Handshake message bytes are opaque blobs
//! throughout — the Noise wire construction and the promotion's effects stay
//! in `node/`.
//!
//! - `core.rs` — the [`LifecycleView`] read-seam trait, the [`ConnAction`]
//!   effect vocabulary, the snapshot types, the pure `poll_*` decisions, and
//!   the [`cross_connection_winner`] tie-break helper.
//! - `limits.rs` — the pure connection-retry backoff math.
//! - `rekey/` — the link profile of the shared rekey machine (Noise IK) and
//!   the node-level msg1 read; hidden from the docs.
//! - `silent.rs` — [`ActiveBackoff`], the refusal in force for an identity
//!   whose link sessions ended without an authenticated frame, as the msg1
//!   refusal's log reads it.
//! - `state.rs` — [`ConnectionState`], the pure handshake-phase connection
//!   bookkeeping (held by the node's entry for the handshake beside its
//!   Noise crypto carrier), its two-clock activity stamp [`LegStamp`], plus
//!   [`Fmp`], the (stateless) lifecycle anchor owned by `Node`.
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
    ConnAction, ConnSnapshot, EphemeralDigest, InboundReject, LifecycleView, Msg1Digest,
    WireOutcome,
};
pub use core::{PromotionResult, cross_connection_winner};
pub use limits::backoff_ms;
pub use silent::ActiveBackoff;
pub use state::{ConnectionState, Fmp, LegStamp};
pub use wire::HandshakeMessageType;
pub use wire::{Disconnect, DisconnectReason};
