//! Upper layer configuration types.
//!
//! Configuration for the IPv6 adaptation layer components: TUN interface
//! and DNS responder.

use serde::{Deserialize, Serialize};

/// Default TUN device name.
const DEFAULT_TUN_NAME: &str = "fips0";

/// Default TUN MTU (IPv6 minimum).
const DEFAULT_TUN_MTU: u16 = 1280;

/// Default DNS responder bind address.
const DEFAULT_DNS_BIND_ADDR: &str = "127.0.0.1";

/// Default DNS responder port.
const DEFAULT_DNS_PORT: u16 = 5354;

/// Default DNS record TTL in seconds (5 minutes).
const DEFAULT_DNS_TTL: u32 = 300;

/// DNS responder configuration (`dns.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Enable DNS responder (`dns.enabled`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,

    /// Bind address (`dns.bind_addr`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// Port (`dns.port`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,

    /// Record TTL in seconds (`dns.ttl`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
}

impl DnsConfig {
    /// Get the bind address (default: 127.0.0.1).
    pub fn bind_addr(&self) -> &str {
        self.bind_addr.as_deref().unwrap_or(DEFAULT_DNS_BIND_ADDR)
    }

    /// Get the port (default: 5354).
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_DNS_PORT)
    }

    /// Get the TTL in seconds (default: 300).
    pub fn ttl(&self) -> u32 {
        self.ttl.unwrap_or(DEFAULT_DNS_TTL)
    }
}

/// TUN interface configuration (`tun.*`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TunConfig {
    /// Enable TUN interface (`tun.enabled`).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub enabled: bool,

    /// Device name (`tun.name`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// MTU (`tun.mtu`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
}

impl TunConfig {
    /// Get the device name (default: "fips0").
    pub fn name(&self) -> &str {
        self.name.as_deref().unwrap_or(DEFAULT_TUN_NAME)
    }

    /// Get the MTU (default: 1280).
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_TUN_MTU)
    }
}
