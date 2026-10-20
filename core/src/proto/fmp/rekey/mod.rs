//! The link layer's binding of the shared rekey machine (`proto::rekey`).
//!
//! The root crate names only [`FmpProfile`], never the pattern behind it, so
//! the profile can change with the handshake pattern a line speaks without
//! a change to the shell: on master it is Noise IK ([`ik::FmpIk`]).

pub mod ik;

/// The link rekey profile this line speaks.
pub type FmpProfile<E> = ik::FmpIk<E>;
