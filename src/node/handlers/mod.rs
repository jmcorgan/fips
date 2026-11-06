//! Message handlers: per-message-type behavior on `impl Node`.

pub(in crate::node) mod handshake;
pub(crate) mod lookup;
mod mmp;
mod native;
pub(in crate::node) use native::PendingNative;
pub(in crate::node) mod netmon;
// The node's side of each link's path machine: facts, parameters, release.
pub(in crate::node) mod path;
// What the node's sources say about where a linked peer may be reachable,
// as the path machines' candidates.
pub(in crate::node) mod path_intake;
// The node's end of the link to the IPv6 adapter.
pub(in crate::node) mod host_link;
pub(crate) mod probe;
// Visible to `node`, which builds the link record store and the transports'
// idle timeout from `rekey`. `rx_loop` is not declared here; master moved it
// out of `handlers`.
pub(in crate::node) mod rekey;
pub(in crate::node) mod session;
mod timeout;
