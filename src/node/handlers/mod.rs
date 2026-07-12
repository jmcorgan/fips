//! Message handlers: per-message-type behavior on `impl Node`.

mod handshake;
pub(crate) mod lookup;
mod mmp;
mod rekey;
pub(in crate::node) mod session;
mod timeout;
