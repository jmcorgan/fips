//! Outbound LAN gateway.
//!
//! Allows unmodified LAN hosts to reach FIPS mesh destinations via
//! DNS-allocated virtual IPs and kernel nftables NAT.

pub mod conntrack;
pub mod control;
pub mod dns;
pub mod nat;
pub mod net;
pub mod pool;
pub mod state;
