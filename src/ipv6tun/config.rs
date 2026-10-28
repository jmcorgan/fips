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
///
/// Loopback by default. The shipped `fips-dns-setup` configures
/// systemd-resolved with a global drop-in pointing at `[::1]:5354`
/// (instead of a per-link `resolvectl dns fips0 [<fips0_addr>]:5354`),
/// which avoids a Linux IPV6_PKTINFO behaviour where self-destined
/// traffic to a TUN address is attributed to the TUN's ifindex —
/// causing the mesh-interface filter to silently drop every query.
///
/// A non-loopback `bind_addr` such as `"::"` answers every host that can
/// reach it, so set one only to serve other hosts (LAN clients, or a
/// gateway reaching the daemon over IPv4). On Linux, macOS and FreeBSD,
/// with the daemon's own TUN, the `is_mesh_interface_query` filter drops
/// queries arriving on the mesh interface, so mesh peers are not served.
/// Where the mesh interface's index is unknown (an application-supplied
/// TUN, Windows, or a name that did not resolve, which the daemon logs as
/// "Mesh interface index unresolved") and a TUN is up, `mesh_query` drops
/// mesh queries by address instead: on unix those addressed to the node's
/// mesh address, on Windows those from a remote `fd00::/8` source, which
/// also leaves Windows LAN clients with ULA addresses unanswered. See
/// `packaging/common/fips-dns-setup` for backend selection.
const DEFAULT_DNS_BIND_ADDR: &str = "::1";

/// Default DNS responder port.
const DEFAULT_DNS_PORT: u16 = 5354;

/// Default DNS record TTL in seconds (5 minutes).
const DEFAULT_DNS_TTL: u32 = 300;

fn default_true() -> bool {
    true
}

/// DNS responder configuration (`dns.*`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Enable DNS responder (`dns.enabled`, default: true).
    #[serde(default = "default_true")]
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

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: None,
            port: None,
            ttl: None,
        }
    }
}

impl DnsConfig {
    /// Get the bind address (default: `::1`, IPv6 loopback only).
    pub fn bind_addr(&self) -> &str {
        self.bind_addr.as_deref().unwrap_or(DEFAULT_DNS_BIND_ADDR)
    }

    /// Get the port (default: 5354).
    pub fn port(&self) -> u16 {
        self.port.unwrap_or(DEFAULT_DNS_PORT)
    }

    /// Get the TTL in seconds (default: 300), at most 2147483647.
    ///
    /// Resolvers read a TTL with the top bit set as zero (RFC 2181 Section
    /// 8), so a larger configured value is used as 2147483647, with one
    /// warning per process.
    pub fn ttl(&self) -> u32 {
        let configured = self.ttl.unwrap_or(DEFAULT_DNS_TTL);
        let used = crate::dnsmsg::clamp_ttl(configured);
        if used != configured {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    configured,
                    used,
                    "dns.ttl is above 2147483647, the largest TTL resolvers honour; using 2147483647"
                );
            });
        }
        used
    }

    /// Merge a later configuration file's `dns` section into this one.
    ///
    /// `enabled` is taken from the later section when `named` says the file
    /// set it, and left as it is otherwise. `bind_addr`, `port` and `ttl` are
    /// taken from the later section when it sets them.
    pub(crate) fn merge(&mut self, other: DnsConfig, named: bool) {
        if named {
            self.enabled = other.enabled;
        }
        if other.bind_addr.is_some() {
            self.bind_addr = other.bind_addr;
        }
        if other.port.is_some() {
            self.port = other.port;
        }
        if other.ttl.is_some() {
            self.ttl = other.ttl;
        }
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

    /// Merge a later configuration file's `tun` section into this one:
    /// `enabled` is taken from it when `named` says the file set it, and its
    /// `name` and `mtu` are taken when it sets them.
    pub(crate) fn merge(&mut self, other: TunConfig, named: bool) {
        if named {
            self.enabled = other.enabled;
        }
        if other.name.is_some() {
            self.name = other.name;
        }
        if other.mtu.is_some() {
            self.mtu = other.mtu;
        }
    }
}

/// A peer alias the `.fips` DNS responder answers for: name and npub, as
/// configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Alias {
    /// The alias, as the peer list gives it.
    pub(crate) name: String,
    /// The npub the alias names, as the peer list gives it.
    pub(crate) npub: String,
}

/// What the IPv6 adapter runs by, handed to it when the node builds it: its
/// two configuration sections, the node settings it reads, and the peer
/// aliases. All of it is owned data, so no node type crosses.
#[derive(Debug, Clone)]
pub(crate) struct Settings {
    /// The TUN section (`tun.*`).
    pub(crate) tun: TunConfig,
    /// The DNS responder section (`dns.*`).
    pub(crate) dns: DnsConfig,
    /// How many packets an embedder that owns the TUN can queue toward the
    /// mesh (`node.buffers.tun_channel`).
    pub(crate) tun_channel: usize,
    /// How many packets toward the host the TUN writer's queue, or an
    /// embedder's, holds (`node.buffers.host_channel`).
    pub(crate) host_channel: usize,
    /// The node's control socket path (`node.control.socket_path`), beside
    /// which the adapter's status socket is bound.
    pub(crate) control: String,
    /// The peer aliases the DNS responder answers for, until the node
    /// replaces them.
    pub(crate) aliases: Vec<Alias>,
}

#[cfg(test)]
impl Settings {
    /// Default sections, both queues 64 packets, no aliases, and the TUN
    /// enabled when `tun`, for tests that build the adapter's handles by
    /// themselves.
    pub(crate) fn with_tun(tun: bool) -> Self {
        Self {
            tun: TunConfig {
                enabled: tun,
                ..Default::default()
            },
            dns: DnsConfig::default(),
            tun_channel: 64,
            host_channel: 64,
            control: String::new(),
            aliases: Vec::new(),
        }
    }
}

/// The `dns.ttl` setting read through its accessor.
#[cfg(test)]
mod ttl_tests {
    use super::*;

    /// A DNS configuration with `ttl` set and every other field default.
    fn with_ttl(ttl: Option<u32>) -> DnsConfig {
        DnsConfig {
            ttl,
            ..DnsConfig::default()
        }
    }

    #[test]
    fn a_dns_ttl_of_u32_max_is_read_as_2147483647() {
        assert_eq!(with_ttl(Some(u32::MAX)).ttl(), 2_147_483_647);
    }

    #[test]
    fn a_dns_ttl_of_2147483647_or_300_or_unset_is_unchanged() {
        assert_eq!(with_ttl(Some(2_147_483_647)).ttl(), 2_147_483_647);
        assert_eq!(with_ttl(Some(300)).ttl(), 300);
        assert_eq!(with_ttl(None).ttl(), 300);
    }
}
