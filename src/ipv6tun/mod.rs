//! The IPv6 adapter
//!
//! This module groups the components that bridge between the FIPS routing
//! layer and IPv6 applications: the TUN interface (packet I/O), DNS
//! responder (.fips domain resolution), and ICMPv6 error messages
//! (Destination Unreachable and Packet Too Big).

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsdnet;
pub mod config;
pub(crate) mod core;
pub mod dns;
pub mod firewall_state;
pub mod icmp;
pub mod icmp_rate_limit;
pub(crate) mod inbound;
pub mod ipv6_shim;
pub(crate) mod lifecycle;
pub(crate) mod link;
pub mod listening;
pub(crate) mod mss;
pub(crate) mod mtu;
pub(crate) mod outbound;
pub(crate) mod queue;
pub(crate) mod status;
pub mod tcp_mss;
pub mod tun;
#[cfg(windows)]
mod winnet;

#[cfg(test)]
mod tests;
