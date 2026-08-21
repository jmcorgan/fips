//! Message handlers: per-message-type behavior on `impl Node`.

mod handshake;
pub(crate) mod lookup;
mod mmp;
mod native;
pub(in crate::node) use native::PendingNative;
pub(crate) mod probe;
mod rekey;
pub(in crate::node) mod session;
mod timeout;
