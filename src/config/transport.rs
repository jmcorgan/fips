//! Transport configuration types.
//!
//! Generic transport instance handling (single vs. named) and
//! transport-specific configuration structs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Default UDP bind address.
const DEFAULT_UDP_BIND_ADDR: &str = "0.0.0.0:2121";

/// Default UDP MTU (IPv6 minimum).
const DEFAULT_UDP_MTU: u16 = 1280;

/// Default UDP receive buffer size (2 MB).
const DEFAULT_UDP_RECV_BUF: usize = 2 * 1024 * 1024;

/// Default UDP send buffer size (2 MB).
const DEFAULT_UDP_SEND_BUF: usize = 2 * 1024 * 1024;

/// UDP transport instance configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpConfig {
    /// Bind address (`bind_addr`). Defaults to "0.0.0.0:2121".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// UDP MTU (`mtu`). Defaults to 1280 (IPv6 minimum).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// UDP receive buffer size in bytes (`recv_buf_size`). Defaults to 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_buf_size: Option<usize>,

    /// UDP send buffer size in bytes (`send_buf_size`). Defaults to 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_buf_size: Option<usize>,
}

impl UdpConfig {
    /// Get the bind address, using default if not configured.
    pub fn bind_addr(&self) -> &str {
        self.bind_addr.as_deref().unwrap_or(DEFAULT_UDP_BIND_ADDR)
    }

    /// Get the UDP MTU, using default if not configured.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_UDP_MTU)
    }

    /// Get the receive buffer size, using default if not configured.
    pub fn recv_buf_size(&self) -> usize {
        self.recv_buf_size.unwrap_or(DEFAULT_UDP_RECV_BUF)
    }

    /// Get the send buffer size, using default if not configured.
    pub fn send_buf_size(&self) -> usize {
        self.send_buf_size.unwrap_or(DEFAULT_UDP_SEND_BUF)
    }
}

/// Transport instances - either a single config or named instances.
///
/// Allows both simple single-instance config:
/// ```yaml
/// transports:
///   udp:
///     bind_addr: "0.0.0.0:2121"
/// ```
///
/// And multiple named instances:
/// ```yaml
/// transports:
///   udp:
///     main:
///       bind_addr: "0.0.0.0:2121"
///     backup:
///       bind_addr: "192.168.1.100:2122"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransportInstances<T> {
    /// Single unnamed instance (config fields directly under transport type).
    Single(T),
    /// Multiple named instances.
    Named(HashMap<String, T>),
}

impl<T> TransportInstances<T> {
    /// Get the number of instances.
    pub fn len(&self) -> usize {
        match self {
            TransportInstances::Single(_) => 1,
            TransportInstances::Named(map) => map.len(),
        }
    }

    /// Check if there are no instances.
    pub fn is_empty(&self) -> bool {
        match self {
            TransportInstances::Single(_) => false,
            TransportInstances::Named(map) => map.is_empty(),
        }
    }

    /// Iterate over all instances as (name, config) pairs.
    ///
    /// Single instances have `None` as the name.
    /// Named instances have `Some(name)`.
    pub fn iter(&self) -> impl Iterator<Item = (Option<&str>, &T)> {
        match self {
            TransportInstances::Single(config) => {
                vec![(None, config)].into_iter()
            }
            TransportInstances::Named(map) => {
                map.iter()
                    .map(|(k, v)| (Some(k.as_str()), v))
                    .collect::<Vec<_>>()
                    .into_iter()
            }
        }
    }
}

impl<T> Default for TransportInstances<T> {
    fn default() -> Self {
        TransportInstances::Named(HashMap::new())
    }
}

/// Default Ethernet EtherType (FIPS default).
const DEFAULT_ETHERNET_ETHERTYPE: u16 = 0x2121;

/// Default Ethernet receive buffer size (2 MB).
const DEFAULT_ETHERNET_RECV_BUF: usize = 2 * 1024 * 1024;

/// Default Ethernet send buffer size (2 MB).
const DEFAULT_ETHERNET_SEND_BUF: usize = 2 * 1024 * 1024;

/// Default beacon announcement interval in seconds.
const DEFAULT_BEACON_INTERVAL_SECS: u64 = 30;

/// Minimum beacon announcement interval in seconds.
const MIN_BEACON_INTERVAL_SECS: u64 = 10;

/// Ethernet transport instance configuration.
///
/// EthernetConfig is always compiled (for config parsing on any platform),
/// but the transport runtime requires Linux (`#[cfg(target_os = "linux")]`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EthernetConfig {
    /// Network interface name (e.g., "eth0", "enp3s0"). Required.
    pub interface: String,

    /// Custom EtherType (default: 0x2121).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ethertype: Option<u16>,

    /// MTU override. Defaults to the interface's MTU minus 1 (for frame type prefix).
    /// Cannot exceed the interface's actual MTU.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Receive buffer size in bytes. Default: 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_buf_size: Option<usize>,

    /// Send buffer size in bytes. Default: 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_buf_size: Option<usize>,

    /// Listen for discovery beacons from other nodes. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discovery: Option<bool>,

    /// Broadcast announcement beacons on the LAN. Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub announce: Option<bool>,

    /// Auto-connect to discovered peers. Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,

    /// Accept incoming connection attempts. Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,

    /// Announcement beacon interval in seconds. Default: 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub beacon_interval_secs: Option<u64>,
}

impl EthernetConfig {
    /// Get the EtherType, using default if not configured.
    pub fn ethertype(&self) -> u16 {
        self.ethertype.unwrap_or(DEFAULT_ETHERNET_ETHERTYPE)
    }

    /// Get the receive buffer size, using default if not configured.
    pub fn recv_buf_size(&self) -> usize {
        self.recv_buf_size.unwrap_or(DEFAULT_ETHERNET_RECV_BUF)
    }

    /// Get the send buffer size, using default if not configured.
    pub fn send_buf_size(&self) -> usize {
        self.send_buf_size.unwrap_or(DEFAULT_ETHERNET_SEND_BUF)
    }

    /// Whether to listen for discovery beacons. Default: true.
    pub fn discovery(&self) -> bool {
        self.discovery.unwrap_or(true)
    }

    /// Whether to broadcast announcement beacons. Default: false.
    pub fn announce(&self) -> bool {
        self.announce.unwrap_or(false)
    }

    /// Whether to auto-connect to discovered peers. Default: false.
    pub fn auto_connect(&self) -> bool {
        self.auto_connect.unwrap_or(false)
    }

    /// Whether to accept incoming connections. Default: false.
    pub fn accept_connections(&self) -> bool {
        self.accept_connections.unwrap_or(false)
    }

    /// Get the beacon interval, clamped to minimum. Default: 30s.
    pub fn beacon_interval_secs(&self) -> u64 {
        self.beacon_interval_secs
            .unwrap_or(DEFAULT_BEACON_INTERVAL_SECS)
            .max(MIN_BEACON_INTERVAL_SECS)
    }
}

// ============================================================================
// TCP Transport Configuration
// ============================================================================

/// Default TCP MTU (conservative, matches typical Ethernet MSS minus overhead).
const DEFAULT_TCP_MTU: u16 = 1400;

/// Default TCP connect timeout in milliseconds.
const DEFAULT_TCP_CONNECT_TIMEOUT_MS: u64 = 5000;

/// Default TCP keepalive interval in seconds.
const DEFAULT_TCP_KEEPALIVE_SECS: u64 = 30;

/// Default TCP receive buffer size (2 MB).
const DEFAULT_TCP_RECV_BUF: usize = 2 * 1024 * 1024;

/// Default TCP send buffer size (2 MB).
const DEFAULT_TCP_SEND_BUF: usize = 2 * 1024 * 1024;

/// Default maximum inbound TCP connections.
const DEFAULT_TCP_MAX_INBOUND: usize = 256;

/// TCP transport instance configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpConfig {
    /// Listen address (e.g., "0.0.0.0:443"). If not set, outbound-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,

    /// Default MTU for TCP connections. Defaults to 1400.
    /// Per-connection MTU is derived from TCP_MAXSEG when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Outbound connect timeout in milliseconds. Defaults to 5000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Enable TCP_NODELAY (disable Nagle). Defaults to true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nodelay: Option<bool>,

    /// TCP keepalive interval in seconds. 0 = disabled. Defaults to 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_secs: Option<u64>,

    /// TCP receive buffer size in bytes. Defaults to 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recv_buf_size: Option<usize>,

    /// TCP send buffer size in bytes. Defaults to 2 MB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub send_buf_size: Option<usize>,

    /// SOCKS5 proxy for outbound connections (placeholder; not yet implemented).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5_proxy: Option<String>,

    /// Maximum simultaneous inbound connections. Defaults to 256.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inbound_connections: Option<usize>,
}

impl TcpConfig {
    /// Get the default MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_TCP_MTU)
    }

    /// Get the connect timeout in milliseconds.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms.unwrap_or(DEFAULT_TCP_CONNECT_TIMEOUT_MS)
    }

    /// Whether TCP_NODELAY is enabled. Default: true.
    pub fn nodelay(&self) -> bool {
        self.nodelay.unwrap_or(true)
    }

    /// Get the keepalive interval in seconds. 0 = disabled. Default: 30.
    pub fn keepalive_secs(&self) -> u64 {
        self.keepalive_secs.unwrap_or(DEFAULT_TCP_KEEPALIVE_SECS)
    }

    /// Get the receive buffer size. Default: 2 MB.
    pub fn recv_buf_size(&self) -> usize {
        self.recv_buf_size.unwrap_or(DEFAULT_TCP_RECV_BUF)
    }

    /// Get the send buffer size. Default: 2 MB.
    pub fn send_buf_size(&self) -> usize {
        self.send_buf_size.unwrap_or(DEFAULT_TCP_SEND_BUF)
    }

    /// Get the maximum number of inbound connections. Default: 256.
    pub fn max_inbound_connections(&self) -> usize {
        self.max_inbound_connections.unwrap_or(DEFAULT_TCP_MAX_INBOUND)
    }
}

// ============================================================================
// TransportsConfig
// ============================================================================

/// Transports configuration section.
///
/// Each transport type can have either a single instance (config directly
/// under the type name) or multiple named instances.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TransportsConfig {
    /// UDP transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub udp: TransportInstances<UdpConfig>,

    /// Ethernet transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub ethernet: TransportInstances<EthernetConfig>,

    /// TCP transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub tcp: TransportInstances<TcpConfig>,
}

/// Helper for skip_serializing_if on TransportInstances.
fn is_transport_empty<T>(instances: &TransportInstances<T>) -> bool {
    instances.is_empty()
}

impl TransportsConfig {
    /// Check if any transports are configured.
    pub fn is_empty(&self) -> bool {
        self.udp.is_empty() && self.ethernet.is_empty() && self.tcp.is_empty()
    }

    /// Merge another TransportsConfig into this one.
    ///
    /// Non-empty transport sections from `other` replace those in `self`.
    pub fn merge(&mut self, other: TransportsConfig) {
        if !other.udp.is_empty() {
            self.udp = other.udp;
        }
        if !other.ethernet.is_empty() {
            self.ethernet = other.ethernet;
        }
        if !other.tcp.is_empty() {
            self.tcp = other.tcp;
        }
    }
}
