//! The settlement core's parameters as the node's configuration gives them.
//!
//! The core holds its own defaults (`Params::default`), which are the
//! node's configuration defaults and the gate constants. The node overrides
//! only what it lets an operator configure: the handshake timeout, the msg1
//! resend interval, multiplier and count, and the cap on answers in flight.
//! The gate constants stay the core's, so a configuration cannot move them.

use crate::config::NodeConfig;
use crate::proto::settle::params::Params;
use std::time::Duration;

/// The settlement core's parameters for a node configured as `node`.
///
/// Nothing in the node steps the core yet, so outside tests nothing calls
/// this.
#[cfg_attr(not(test), allow(dead_code))]
pub(in crate::node) fn settle_params(node: &NodeConfig) -> Params {
    let rl = &node.rate_limit;
    Params {
        handshake: Duration::from_secs(rl.handshake_timeout_secs),
        resend: Duration::from_millis(rl.handshake_resend_interval_ms),
        backoff: rl.handshake_resend_backoff.to_bits(),
        resends: rl.handshake_max_resends,
        pending: node.limits.max_pending_inbound,
        ..Params::default()
    }
}

#[cfg(test)]
#[path = "tests/params.rs"]
mod tests;
