//! IPv6 Upper Layer Adaptation
//!
//! This module groups the components that bridge between the FIPS routing
//! layer and IPv6 applications: the TUN interface (packet I/O), DNS
//! responder (.fips domain resolution), and ICMPv6 handling (error
//! signaling and neighbor discovery).

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bsdnet;
pub mod config;
pub(crate) mod core;
pub mod dns;
pub mod icmp;
pub mod icmp_rate_limit;
pub mod ipv6_shim;
pub(crate) mod lifecycle;
pub(crate) mod link;
pub(crate) mod mtu;
pub(crate) mod outbound;
pub mod tcp_mss;
pub mod tun;
#[cfg(windows)]
mod winnet;
