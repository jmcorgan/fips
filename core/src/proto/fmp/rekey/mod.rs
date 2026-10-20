//! The link layer's binding of the shared rekey machine (`proto::rekey`).
//!
//! The root crate names only [`FmpProfile`] and the pattern-neutral names
//! re-exported here, never the pattern behind them, so the profile can
//! change with the handshake pattern a line speaks without a change to the
//! shell: on this line it is Noise XX ([`xx::FmpXx`]).

pub mod xx;

/// The link rekey profile this line speaks.
pub type FmpProfile<E> = xx::FmpXx<E>;

pub use xx::{LinkKeys, LinkLocal, Unread, XxFinal as Final, read_final};
