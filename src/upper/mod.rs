//! IPv6 Upper Layer Adaptation
//!
//! This module groups the components that bridge between the FIPS routing
//! layer and IPv6 applications: the TUN interface (packet I/O), DNS
//! responder (.fips domain resolution), and ICMPv6 handling (error
//! signaling and neighbor discovery).

pub mod config;
pub mod dns;
pub mod icmp;
pub mod icmp_rate_limit;
pub mod tcp_mss;
pub mod tun;
