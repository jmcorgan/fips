//! Message handlers: per-message-type behavior on `impl Node`.

pub(in crate::node) mod handshake;
pub(crate) mod lookup;
mod mmp;
mod native;
pub(in crate::node) use native::PendingNative;
pub(in crate::node) mod netmon;
pub(crate) mod probe;
// Widened from private by the rekey drain cap: `node::session` calls
// `rekey::drain_max_retention_ms` to bound how long a superseded epoch is
// retained. `rx_loop` is not declared here; master moved it out of `handlers`.
pub(in crate::node) mod rekey;
pub(in crate::node) mod session;
mod timeout;
