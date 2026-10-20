//! Message handlers: per-message-type behavior on `impl Node`.

pub(in crate::node) mod handshake;
pub(crate) mod lookup;
mod mmp;
mod native;
pub(in crate::node) use native::PendingNative;
pub(in crate::node) mod netmon;
pub(crate) mod probe;
// Visible to `node`, which builds the link record store and the transports'
// idle timeout from `rekey`. `rx_loop` is not declared here; master moved it
// out of `handlers`.
pub(in crate::node) mod rekey;
pub(in crate::node) mod session;
mod timeout;
