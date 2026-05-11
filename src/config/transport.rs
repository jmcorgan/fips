//! Transport configuration types.
//!
//! Generic transport instance handling (single vs. named) and
//! transport-specific configuration structs.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

/// Parse an `external_addr` config string against a known bind port,
/// producing the absolute `SocketAddr` to advertise on Nostr.
///
/// Accepts either a bare IP (`"198.51.100.1"` or `"[::1]"`) — in which
/// case the bind port is appended — or a full `host:port` form
/// (`"198.51.100.1:443"` or `"[::1]:443"`). Returns `None` on any parse
/// error. IPv6 must use bracket notation when supplying a port.
fn parse_external_advert_addr(raw: &str, bind_port: u16) -> Option<SocketAddr> {
    if let Ok(sa) = raw.parse::<SocketAddr>() {
        return Some(sa);
    }
    let ip: IpAddr = raw.parse().ok()?;
    Some(SocketAddr::new(ip, bind_port))
}

/// Extract the port from a `bind_addr` string. Returns `None` if the
/// string can't be parsed (e.g. a bare hostname without port).
fn parse_bind_port(raw: &str) -> Option<u16> {
    raw.parse::<SocketAddr>().ok().map(|sa| sa.port())
}

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
    ///
    /// When `outbound_only = true`, this field is ignored and the transport
    /// binds to `0.0.0.0:0` (kernel-assigned ephemeral port) regardless.
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

    /// Whether this transport should be advertised on Nostr overlay discovery.
    /// Default: false. Implicitly forced false when `outbound_only = true`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_on_nostr: Option<bool>,

    /// Whether UDP should be advertised as directly reachable (`host:port`) on
    /// Nostr. When false and advertised, UDP is emitted as `addr: "nat"` to
    /// trigger rendezvous traversal.
    ///
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<bool>,
    /// Optional explicit public address to advertise when `public: true`
    /// is set. Takes precedence over both the bound address and any
    /// STUN-derived autodiscovery. Accepts either a bare IP
    /// (`"198.51.100.1"` — the configured `bind_addr` port is appended)
    /// or a full `host:port` (`"198.51.100.1:443"`). Useful when the
    /// public IP isn't on a local interface (e.g. AWS EIP / cloud 1:1
    /// NAT) and the operator wants to skip STUN autodiscovery for a
    /// deterministic value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_addr: Option<String>,
    /// Outbound-only mode. When true, the transport binds to a kernel-
    /// assigned ephemeral port (`0.0.0.0:0`) instead of the configured
    /// `bind_addr`, refuses inbound handshake msg1, and is never
    /// advertised on Nostr regardless of `advertise_on_nostr`. Use this
    /// to participate in the mesh as a pure client — initiate outbound
    /// links without exposing an inbound listener on a known port.
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_only: Option<bool>,

    /// Accept inbound handshake msg1 from new peers. Default: true.
    /// Setting this to false combined with `auto_connect: true` on
    /// peer-side configurations gives a "client" posture: this node
    /// initiates outbound links but refuses inbound handshakes from
    /// unfamiliar addresses. The Node-level gate at
    /// `src/node/handlers/handshake.rs` carves out msg1 from peers
    /// already established on this transport (so rekey continues to
    /// work) — see ISSUE-2026-0004.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,
}

impl UdpConfig {
    /// Get the bind address, using default if not configured.
    ///
    /// When `outbound_only = true`, returns `0.0.0.0:0` so the kernel picks
    /// an ephemeral source port and no listener is exposed on a known port.
    pub fn bind_addr(&self) -> &str {
        if self.outbound_only() {
            "0.0.0.0:0"
        } else {
            self.bind_addr.as_deref().unwrap_or(DEFAULT_UDP_BIND_ADDR)
        }
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

    /// Whether this UDP transport should be advertised on Nostr discovery.
    /// Always false when `outbound_only = true`.
    pub fn advertise_on_nostr(&self) -> bool {
        if self.outbound_only() {
            false
        } else {
            self.advertise_on_nostr.unwrap_or(false)
        }
    }

    /// Whether this UDP transport should be advertised as directly reachable.
    pub fn is_public(&self) -> bool {
        self.public.unwrap_or(false)
    }

    /// Parse `external_addr` against the configured `bind_addr` port,
    /// returning the absolute `SocketAddr` to advertise on Nostr.
    /// Returns `None` if `external_addr` is unset or malformed, or if
    /// the port cannot be inferred.
    pub fn external_advert_addr(&self) -> Option<SocketAddr> {
        let raw = self.external_addr.as_deref()?;
        let bind_port = parse_bind_port(self.bind_addr())?;
        parse_external_advert_addr(raw, bind_port)
    }

    /// Whether this transport runs in outbound-only mode. Default: false.
    pub fn outbound_only(&self) -> bool {
        self.outbound_only.unwrap_or(false)
    }

    /// Whether this transport accepts inbound handshakes. Default: true.
    pub fn accept_connections(&self) -> bool {
        self.accept_connections.unwrap_or(true)
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
            TransportInstances::Single(config) => vec![(None, config)].into_iter(),
            TransportInstances::Named(map) => map
                .iter()
                .map(|(k, v)| (Some(k.as_str()), v))
                .collect::<Vec<_>>()
                .into_iter(),
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

    /// MTU override. Defaults to the interface's MTU minus 3 bytes of frame
    /// header (`[type:1][length:2 LE][payload]`). The 2-byte length field is
    /// required to trim NIC minimum-frame padding before AEAD verification.
    /// Cannot exceed the interface's actual MTU minus 3.
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

    /// Maximum simultaneous inbound connections. Defaults to 256.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inbound_connections: Option<usize>,

    /// Whether this transport should be advertised on Nostr overlay discovery.
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_on_nostr: Option<bool>,

    /// Optional explicit public address to advertise. Required when
    /// `bind_addr` is wildcard (e.g. `"0.0.0.0:443"`) and
    /// `advertise_on_nostr: true`, since TCP has no STUN equivalent
    /// for autodiscovery. Accepts either a bare IP (`"198.51.100.1"`
    /// — the configured `bind_addr` port is appended) or a full
    /// `host:port`. Common pattern on AWS EIP / cloud 1:1 NAT setups
    /// where the public IP isn't bindable on the host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_addr: Option<String>,
}

impl TcpConfig {
    /// Get the default MTU.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_TCP_MTU)
    }

    /// Get the connect timeout in milliseconds.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_TCP_CONNECT_TIMEOUT_MS)
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
        self.max_inbound_connections
            .unwrap_or(DEFAULT_TCP_MAX_INBOUND)
    }

    /// Whether this TCP transport should be advertised on Nostr discovery.
    pub fn advertise_on_nostr(&self) -> bool {
        self.advertise_on_nostr.unwrap_or(false)
    }

    /// Parse `external_addr` against the configured `bind_addr` port,
    /// returning the absolute `SocketAddr` to advertise on Nostr.
    /// Returns `None` if `external_addr` is unset or malformed, or if
    /// `bind_addr` is unset / unparseable so no port can be inferred.
    pub fn external_advert_addr(&self) -> Option<SocketAddr> {
        let raw = self.external_addr.as_deref()?;
        let bind_port = parse_bind_port(self.bind_addr.as_deref()?)?;
        parse_external_advert_addr(raw, bind_port)
    }
}

// ============================================================================
// Tor Transport Configuration
// ============================================================================

/// Default Tor SOCKS5 proxy address.
const DEFAULT_TOR_SOCKS5_ADDR: &str = "127.0.0.1:9050";

/// Default Tor control port address.
const DEFAULT_TOR_CONTROL_ADDR: &str = "/run/tor/control";

/// Default Tor control cookie file path (Debian standard location).
const DEFAULT_TOR_COOKIE_PATH: &str = "/var/run/tor/control.authcookie";

/// Default Tor connect timeout in milliseconds (120s — Tor circuit
/// establishment can take 30-60s on first connect, plus SOCKS5 handshake).
const DEFAULT_TOR_CONNECT_TIMEOUT_MS: u64 = 120_000;

/// Default Tor MTU (same as TCP).
const DEFAULT_TOR_MTU: u16 = 1400;

/// Default max inbound connections via onion service.
const DEFAULT_TOR_MAX_INBOUND: usize = 64;

/// Default HiddenServiceDir hostname file path.
const DEFAULT_HOSTNAME_FILE: &str = "/var/lib/tor/fips_onion_service/hostname";

/// Default directory mode bind address.
const DEFAULT_DIRECTORY_BIND_ADDR: &str = "127.0.0.1:8443";

/// Default advertised onion port for Nostr overlay discovery. Matches the
/// Tor convention of `HiddenServicePort 443 127.0.0.1:<bind_port>` in torrc.
const DEFAULT_TOR_ADVERTISED_PORT: u16 = 443;

/// Tor transport instance configuration.
///
/// Supports three modes:
/// - `socks5`: Outbound-only connections through a Tor SOCKS5 proxy.
/// - `control_port`: Full bidirectional support — outbound via SOCKS5
///   plus inbound via Tor onion service managed through the control port.
/// - `directory`: Full bidirectional support — outbound via SOCKS5,
///   inbound via a Tor-managed `HiddenServiceDir` onion service. No
///   control port needed. Enables Tor `Sandbox 1` mode.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TorConfig {
    /// Tor access mode: "socks5", "control_port", or "directory".
    /// Default: "socks5".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// SOCKS5 proxy address (host:port). Defaults to "127.0.0.1:9050".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5_addr: Option<String>,

    /// Outbound connect timeout in milliseconds. Defaults to 120000 (120s).
    /// Tor circuit establishment can take 30-60s, so this must be generous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Default MTU for Tor connections. Defaults to 1400.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Control port address: a Unix socket path (`/run/tor/control`) or
    /// TCP address (`host:port`). Unix sockets are preferred for security.
    /// Defaults to "/run/tor/control".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_addr: Option<String>,

    /// Control port authentication method:
    /// `"cookie"` (read from default path),
    /// `"cookie:/path/to/cookie"` (read from specified path), or
    /// `"password:secret"` (password auth). Default: `"cookie"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_auth: Option<String>,

    /// Path to the Tor control cookie file. Used when control_auth is "cookie".
    /// Defaults to "/var/run/tor/control.authcookie".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_path: Option<String>,

    /// Maximum number of inbound connections via onion service. Default: 64.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_inbound_connections: Option<usize>,

    /// Directory-mode onion service configuration. Only valid in
    /// "directory" mode. Tor manages the onion service via HiddenServiceDir
    /// in torrc; fips reads the .onion hostname from a file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub directory_service: Option<DirectoryServiceConfig>,

    /// Whether this transport should be advertised on Nostr overlay discovery.
    /// Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise_on_nostr: Option<bool>,

    /// Public-facing onion port published in Nostr overlay adverts. Must
    /// match the virtual port in torrc's `HiddenServicePort <port>
    /// 127.0.0.1:<bind_port>` directive — that is the port other peers
    /// will use to reach this onion. Default: 443.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertised_port: Option<u16>,
}

/// Directory-mode onion service configuration.
///
/// In `directory` mode, Tor manages the onion service via `HiddenServiceDir`
/// in torrc. FIPS reads the `.onion` address from the hostname file and
/// binds a local TCP listener for Tor to forward inbound connections to.
/// This mode requires no control port and enables Tor's `Sandbox 1`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryServiceConfig {
    /// Path to the Tor-managed hostname file containing the .onion address.
    /// Defaults to "/var/lib/tor/fips_onion_service/hostname".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname_file: Option<String>,

    /// Local bind address for the listener that Tor forwards inbound
    /// connections to. Must match the target in torrc's `HiddenServicePort`.
    /// Defaults to "127.0.0.1:8443".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_addr: Option<String>,
}

impl DirectoryServiceConfig {
    /// Path to the hostname file. Default: "/var/lib/tor/fips_onion_service/hostname".
    pub fn hostname_file(&self) -> &str {
        self.hostname_file
            .as_deref()
            .unwrap_or(DEFAULT_HOSTNAME_FILE)
    }

    /// Local bind address for the listener. Default: "127.0.0.1:8443".
    pub fn bind_addr(&self) -> &str {
        self.bind_addr
            .as_deref()
            .unwrap_or(DEFAULT_DIRECTORY_BIND_ADDR)
    }
}

impl TorConfig {
    /// Get the access mode. Default: "socks5".
    pub fn mode(&self) -> &str {
        self.mode.as_deref().unwrap_or("socks5")
    }

    /// Get the SOCKS5 proxy address. Default: "127.0.0.1:9050".
    pub fn socks5_addr(&self) -> &str {
        self.socks5_addr
            .as_deref()
            .unwrap_or(DEFAULT_TOR_SOCKS5_ADDR)
    }

    /// Get the control port address. Default: "/run/tor/control".
    pub fn control_addr(&self) -> &str {
        self.control_addr
            .as_deref()
            .unwrap_or(DEFAULT_TOR_CONTROL_ADDR)
    }

    /// Get the control auth string. Default: "cookie".
    pub fn control_auth(&self) -> &str {
        self.control_auth.as_deref().unwrap_or("cookie")
    }

    /// Get the cookie file path. Default: "/var/run/tor/control.authcookie".
    pub fn cookie_path(&self) -> &str {
        self.cookie_path
            .as_deref()
            .unwrap_or(DEFAULT_TOR_COOKIE_PATH)
    }

    /// Get the connect timeout in milliseconds. Default: 120000.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_TOR_CONNECT_TIMEOUT_MS)
    }

    /// Get the default MTU. Default: 1400.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_TOR_MTU)
    }

    /// Get the max inbound connections. Default: 64.
    pub fn max_inbound_connections(&self) -> usize {
        self.max_inbound_connections
            .unwrap_or(DEFAULT_TOR_MAX_INBOUND)
    }

    /// Whether this Tor transport should be advertised on Nostr discovery.
    pub fn advertise_on_nostr(&self) -> bool {
        self.advertise_on_nostr.unwrap_or(false)
    }

    /// Public-facing onion port published in Nostr overlay adverts.
    /// Default: 443.
    pub fn advertised_port(&self) -> u16 {
        self.advertised_port.unwrap_or(DEFAULT_TOR_ADVERTISED_PORT)
    }
}

// ============================================================================
// BLE Transport Configuration
// ============================================================================

/// Default BLE L2CAP PSM (dynamic range).
const DEFAULT_BLE_PSM: u16 = 0x0085;

/// Default BLE MTU for L2CAP CoC connections.
const DEFAULT_BLE_MTU: u16 = 2048;

/// Default maximum concurrent BLE connections.
const DEFAULT_BLE_MAX_CONNECTIONS: usize = 7;

/// Default BLE connect timeout in milliseconds.
const DEFAULT_BLE_CONNECT_TIMEOUT_MS: u64 = 10_000;

/// Default BLE probe cooldown in seconds. After probing an address
/// (success or failure), wait this long before probing it again.
const DEFAULT_BLE_PROBE_COOLDOWN_SECS: u64 = 30;

/// BLE transport instance configuration.
///
/// BleConfig is always compiled (for config parsing on any platform),
/// but the transport runtime requires Linux and the `ble` feature.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BleConfig {
    /// HCI adapter name (e.g., "hci0"). Required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<String>,

    /// L2CAP PSM for FIPS connections. Default: 0x0085 (133).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub psm: Option<u16>,

    /// Default MTU for BLE connections. Default: 2048.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,

    /// Maximum concurrent BLE connections. Default: 7.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,

    /// Outbound connect timeout in milliseconds. Default: 10000.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_timeout_ms: Option<u64>,

    /// Broadcast BLE advertisements. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub advertise: Option<bool>,

    /// Listen for BLE advertisements. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scan: Option<bool>,

    /// Auto-connect to discovered BLE peers. Default: false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_connect: Option<bool>,

    /// Accept incoming BLE connections. Default: true.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accept_connections: Option<bool>,

    /// Probe cooldown in seconds. After probing a BLE address, wait
    /// this long before probing the same address again. Default: 30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe_cooldown_secs: Option<u64>,
}

impl BleConfig {
    /// Get the adapter name. Default: "hci0".
    pub fn adapter(&self) -> &str {
        self.adapter.as_deref().unwrap_or("hci0")
    }

    /// Get the L2CAP PSM. Default: 0x0085.
    pub fn psm(&self) -> u16 {
        self.psm.unwrap_or(DEFAULT_BLE_PSM)
    }

    /// Get the default MTU. Default: 2048.
    pub fn mtu(&self) -> u16 {
        self.mtu.unwrap_or(DEFAULT_BLE_MTU)
    }

    /// Get the maximum concurrent connections. Default: 7.
    pub fn max_connections(&self) -> usize {
        self.max_connections.unwrap_or(DEFAULT_BLE_MAX_CONNECTIONS)
    }

    /// Get the connect timeout in milliseconds. Default: 10000.
    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
            .unwrap_or(DEFAULT_BLE_CONNECT_TIMEOUT_MS)
    }

    /// Whether to broadcast advertisements. Default: true.
    pub fn advertise(&self) -> bool {
        self.advertise.unwrap_or(true)
    }

    /// Whether to scan for advertisements. Default: true.
    pub fn scan(&self) -> bool {
        self.scan.unwrap_or(true)
    }

    /// Whether to auto-connect to discovered peers. Default: false.
    pub fn auto_connect(&self) -> bool {
        self.auto_connect.unwrap_or(false)
    }

    /// Whether to accept incoming connections. Default: true.
    pub fn accept_connections(&self) -> bool {
        self.accept_connections.unwrap_or(true)
    }

    /// Get the probe cooldown in seconds. Default: 30.
    pub fn probe_cooldown_secs(&self) -> u64 {
        self.probe_cooldown_secs
            .unwrap_or(DEFAULT_BLE_PROBE_COOLDOWN_SECS)
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

    /// Tor transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub tor: TransportInstances<TorConfig>,

    /// BLE transport instances.
    #[serde(default, skip_serializing_if = "is_transport_empty")]
    pub ble: TransportInstances<BleConfig>,
}

/// Helper for skip_serializing_if on TransportInstances.
fn is_transport_empty<T>(instances: &TransportInstances<T>) -> bool {
    instances.is_empty()
}

impl TransportsConfig {
    /// Check if any transports are configured.
    pub fn is_empty(&self) -> bool {
        self.udp.is_empty()
            && self.ethernet.is_empty()
            && self.tcp.is_empty()
            && self.tor.is_empty()
            && self.ble.is_empty()
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
        if !other.tor.is_empty() {
            self.tor = other.tor;
        }
        if !other.ble.is_empty() {
            self.ble = other.ble;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_external_addr_accepts_bare_ipv4_with_appended_bind_port() {
        let sa = parse_external_advert_addr("198.51.100.1", 2121).unwrap();
        assert_eq!(sa.to_string(), "198.51.100.1:2121");
    }

    #[test]
    fn parse_external_addr_accepts_full_ipv4_socket_addr() {
        let sa = parse_external_advert_addr("198.51.100.1:443", 2121).unwrap();
        assert_eq!(sa.to_string(), "198.51.100.1:443");
        // Explicit port wins over the bind port we passed in.
    }

    #[test]
    fn parse_external_addr_accepts_bare_ipv6_with_appended_bind_port() {
        let sa = parse_external_advert_addr("2001:db8::1", 443).unwrap();
        assert_eq!(sa.to_string(), "[2001:db8::1]:443");
    }

    #[test]
    fn parse_external_addr_accepts_bracketed_ipv6_with_explicit_port() {
        let sa = parse_external_advert_addr("[2001:db8::1]:8443", 443).unwrap();
        assert_eq!(sa.to_string(), "[2001:db8::1]:8443");
    }

    #[test]
    fn parse_external_addr_rejects_garbage() {
        assert!(parse_external_advert_addr("not-an-ip", 443).is_none());
        assert!(parse_external_advert_addr("", 443).is_none());
    }

    #[test]
    fn udp_external_advert_addr_combines_with_bind_port_default() {
        let cfg = UdpConfig {
            external_addr: Some("198.51.100.1".to_string()),
            ..UdpConfig::default()
        };
        // bind_addr unset, so default DEFAULT_UDP_BIND_ADDR (0.0.0.0:2121) applies.
        let sa = cfg.external_advert_addr().unwrap();
        assert_eq!(sa.to_string(), "198.51.100.1:2121");
    }

    #[test]
    fn udp_external_advert_addr_with_explicit_full_socket_addr_overrides_bind_port() {
        let cfg = UdpConfig {
            bind_addr: Some("0.0.0.0:2121".to_string()),
            external_addr: Some("198.51.100.1:9999".to_string()),
            ..UdpConfig::default()
        };
        let sa = cfg.external_advert_addr().unwrap();
        assert_eq!(sa.to_string(), "198.51.100.1:9999");
    }

    #[test]
    fn udp_external_advert_addr_returns_none_when_unset() {
        let cfg = UdpConfig::default();
        assert!(cfg.external_advert_addr().is_none());
    }

    #[test]
    fn tcp_external_advert_addr_requires_bind_port() {
        let cfg = TcpConfig {
            external_addr: Some("198.51.100.1".to_string()),
            ..TcpConfig::default()
        };
        // bind_addr unset → no port to combine with → None.
        assert!(cfg.external_advert_addr().is_none());

        let cfg = TcpConfig {
            bind_addr: Some("0.0.0.0:443".to_string()),
            external_addr: Some("198.51.100.1".to_string()),
            ..TcpConfig::default()
        };
        let sa = cfg.external_advert_addr().unwrap();
        assert_eq!(sa.to_string(), "198.51.100.1:443");
    }

    #[test]
    fn tcp_external_advert_addr_with_full_socket_addr_independent_of_bind() {
        let cfg = TcpConfig {
            bind_addr: Some("0.0.0.0:443".to_string()),
            external_addr: Some("198.51.100.1:8443".to_string()),
            ..TcpConfig::default()
        };
        let sa = cfg.external_advert_addr().unwrap();
        assert_eq!(sa.to_string(), "198.51.100.1:8443");
    }

    #[test]
    fn parse_bind_port_extracts_from_socket_addr_strings() {
        assert_eq!(parse_bind_port("0.0.0.0:2121"), Some(2121));
        assert_eq!(parse_bind_port("[::]:443"), Some(443));
        assert_eq!(parse_bind_port("not-a-socket-addr"), None);
    }
}
