//! The traversal sub-machines: what the node remembers about traversal
//! attempts and decides from that memory, and the rate limit on inbound
//! traversal signals.

pub mod election;
pub mod failures;
pub mod gate;
