//! The traversal sub-machines: what the node remembers about traversal
//! attempts and decides from that memory, the rate limit on inbound
//! traversal signals, and the pure rules a traversal follows.

pub mod admission;
pub mod election;
pub mod failures;
pub mod gate;
pub mod rules;
pub mod sessions;
