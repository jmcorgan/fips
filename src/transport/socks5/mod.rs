//! Shared SOCKS5 / proxied-transport building blocks.
//!
//! The Tor and Nym transports both dial outbound through a local SOCKS5
//! proxy and share the same connection-pool, receive-loop, and dialing
//! machinery. That shared surface lives here so it is written once rather
//! than copied into each transport.

mod dialer;
mod pool;
mod stats;

pub use dialer::{DialError, Socks5Auth, Socks5Dialer, SocksTarget};
pub(crate) use pool::{
    ConnectingEntry, ConnectingPool, ProxiedConnection, ProxiedPool, ProxiedStats, poll_connecting,
    proxied_receive_loop,
};
pub(crate) use stats::ProxiedStatsBase;

#[cfg(test)]
pub(crate) mod mock;
