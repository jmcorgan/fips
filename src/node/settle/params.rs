//! The settlement core's parameters as the node's configuration gives them.
//!
//! The core holds its own defaults (`Params::default`), which are the
//! node's configuration defaults and the gate constants. The node overrides
//! only what it lets an operator configure: the handshake timeout, the msg1
//! resend interval, multiplier and count, the cap on answers in flight and
//! the max-peers cap. The gate constants stay the core's, so a configuration
//! cannot move them. On this line the core's handshake flow is XX's, whose
//! own parameters ([`fips_core::proto::fmp::flow::params`]) replace the
//! gates' unheard floor, replay memory and interval with next's.

use crate::config::NodeConfig;
use crate::proto::settle::params::Params;
use std::time::Duration;

/// The settlement core's parameters for a node configured as `node`.
pub(in crate::node) fn settle_params(node: &NodeConfig) -> Params {
    let rl = &node.rate_limit;
    Params {
        handshake: Duration::from_secs(rl.handshake_timeout_secs),
        resend: Duration::from_millis(rl.handshake_resend_interval_ms),
        backoff: rl.handshake_resend_backoff.to_bits(),
        resends: rl.handshake_max_resends,
        pending: node.limits.max_pending_inbound,
        peers: node.limits.max_peers,
        ..Params::default()
    }
}

/// The parameters of the node's own handshake legs: [`settle_params`],
/// with the handshake deadline one millisecond later. The node reaps a leg
/// once it has been idle longer than the handshake timeout, in whole
/// milliseconds of its interval clock, and the core reaps a leg at its
/// deadline, so a leg stamped at a whole millisecond is reaped by the core
/// at the node's tick exactly when its deadline lies a millisecond past the
/// timeout.
pub(in crate::node) fn leg_params(node: &NodeConfig) -> Params {
    let params = settle_params(node);
    Params {
        handshake: params.handshake.saturating_add(Duration::from_millis(1)),
        ..params
    }
}

/// The parameters of the XX flow's table for a node configured as `node`:
/// [`leg_params`], with the XX flow's gate values. The node's table runs
/// with them.
pub(in crate::node) fn xx_params(node: &NodeConfig) -> Params {
    fips_core::proto::fmp::flow::params(leg_params(node))
}

#[cfg(test)]
#[path = "tests/params.rs"]
mod tests;
