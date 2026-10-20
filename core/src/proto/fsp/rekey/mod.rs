//! The session layer's binding of the shared rekey machine
//! (`proto::rekey`).
//!
//! The root crate names only [`FspProfile`] and the pattern-neutral names
//! re-exported here, never the pattern behind them, so the profile can
//! change with the handshake pattern a line speaks without a change to the
//! shell: on this line it is Noise XX ([`xx::FspXx`]), until the session
//! layer's v2 handshake replaces it.

pub mod xx;

/// The session rekey profile this line speaks.
pub type FspProfile<E> = xx::FspXx<E>;

pub use xx::{SessionKeys, SessionLocal};
