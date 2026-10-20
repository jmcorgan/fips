//! The session layer's binding of the shared rekey machine
//! (`proto::rekey`).
//!
//! The root crate names only [`FspProfile`], never the pattern behind it, so
//! the profile can change with the handshake pattern a line speaks without
//! a change to the shell: on master it is Noise XK ([`xk::FspXk`]).

pub mod xk;

/// The session rekey profile this line speaks.
pub type FspProfile<E> = xk::FspXk<E>;
