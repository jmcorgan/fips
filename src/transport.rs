//! Transport Layer Abstractions
//!
//! Traits and types for FIPS transport drivers. Transports provide the
//! underlying communication mechanisms (UDP, Ethernet, Tor, etc.) over
//! which FIPS links are established.

use secp256k1::XOnlyPublicKey;
use std::fmt;
use std::time::Duration;
use thiserror::Error;

/// Unique identifier for a transport instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TransportId(u32);

impl TransportId {
    /// Create a new transport ID.
    pub fn new(id: u32) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

impl fmt::Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "transport:{}", self.0)
    }
}

/// Unique identifier for a link instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct LinkId(u64);

impl LinkId {
    /// Create a new link ID.
    pub fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::Display for LinkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "link:{}", self.0)
    }
}

/// Errors related to transport operations.
#[derive(Debug, Error)]
pub enum TransportError {
    #[error("transport not started")]
    NotStarted,

    #[error("transport already started")]
    AlreadyStarted,

    #[error("transport failed to start: {0}")]
    StartFailed(String),

    #[error("transport shutdown failed: {0}")]
    ShutdownFailed(String),

    #[error("link failed: {0}")]
    LinkFailed(String),

    #[error("send failed: {0}")]
    SendFailed(String),

    #[error("receive failed: {0}")]
    RecvFailed(String),

    #[error("invalid transport address: {0}")]
    InvalidAddress(String),

    #[error("mtu exceeded: packet {packet_size} > mtu {mtu}")]
    MtuExceeded { packet_size: usize, mtu: u16 },

    #[error("transport timeout")]
    Timeout,

    #[error("connection refused")]
    ConnectionRefused,

    #[error("transport not supported: {0}")]
    NotSupported(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Static metadata about a transport type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportType {
    /// Human-readable name (e.g., "udp", "ethernet", "tor").
    pub name: &'static str,
    /// Whether this transport requires connection establishment.
    pub connection_oriented: bool,
    /// Whether the transport guarantees delivery.
    pub reliable: bool,
}

impl TransportType {
    /// UDP/IP transport.
    pub const UDP: TransportType = TransportType {
        name: "udp",
        connection_oriented: false,
        reliable: false,
    };

    /// TCP/IP transport.
    pub const TCP: TransportType = TransportType {
        name: "tcp",
        connection_oriented: true,
        reliable: true,
    };

    /// Raw Ethernet transport.
    pub const ETHERNET: TransportType = TransportType {
        name: "ethernet",
        connection_oriented: false,
        reliable: false,
    };

    /// WiFi (same characteristics as Ethernet).
    pub const WIFI: TransportType = TransportType {
        name: "wifi",
        connection_oriented: false,
        reliable: false,
    };

    /// Tor onion transport.
    pub const TOR: TransportType = TransportType {
        name: "tor",
        connection_oriented: true,
        reliable: true,
    };

    /// Serial/UART transport.
    pub const SERIAL: TransportType = TransportType {
        name: "serial",
        connection_oriented: false,
        reliable: true, // typically uses framing with checksums
    };

    /// Check if the transport is connectionless.
    pub fn is_connectionless(&self) -> bool {
        !self.connection_oriented
    }
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Transport lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransportState {
    /// Configured but not started.
    Configured,
    /// Initialization in progress.
    Starting,
    /// Ready for links.
    Up,
    /// Was up, now unavailable.
    Down,
    /// Failed to start.
    Failed,
}

impl TransportState {
    /// Check if the transport is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, TransportState::Up)
    }

    /// Check if the transport can be started.
    pub fn can_start(&self) -> bool {
        matches!(
            self,
            TransportState::Configured | TransportState::Down | TransportState::Failed
        )
    }

    /// Check if the transport is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, TransportState::Failed)
    }
}

impl fmt::Display for TransportState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            TransportState::Configured => "configured",
            TransportState::Starting => "starting",
            TransportState::Up => "up",
            TransportState::Down => "down",
            TransportState::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

/// Link lifecycle state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// Connection in progress (connection-oriented only).
    Connecting,
    /// Ready for traffic.
    Connected,
    /// Was connected, now gone.
    Disconnected,
    /// Connection attempt failed.
    Failed,
}

impl LinkState {
    /// Check if the link is operational.
    pub fn is_operational(&self) -> bool {
        matches!(self, LinkState::Connected)
    }

    /// Check if the link is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        matches!(self, LinkState::Disconnected | LinkState::Failed)
    }
}

impl fmt::Display for LinkState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LinkState::Connecting => "connecting",
            LinkState::Connected => "connected",
            LinkState::Disconnected => "disconnected",
            LinkState::Failed => "failed",
        };
        write!(f, "{}", s)
    }
}

/// Direction of link establishment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkDirection {
    /// We initiated the connection.
    Outbound,
    /// They initiated the connection.
    Inbound,
}

impl fmt::Display for LinkDirection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LinkDirection::Outbound => "outbound",
            LinkDirection::Inbound => "inbound",
        };
        write!(f, "{}", s)
    }
}

/// Opaque transport-specific address.
///
/// Each transport type interprets this differently:
/// - UDP: "ip:port"
/// - Ethernet: MAC address (6 bytes)
/// - Tor: ".onion:port"
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TransportAddr(Vec<u8>);

impl TransportAddr {
    /// Create a transport address from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Create a transport address from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(bytes.to_vec())
    }

    /// Create a transport address from a string.
    pub fn from_string(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Try to interpret as a UTF-8 string.
    pub fn as_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Get the length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.as_str() {
            Some(s) => write!(f, "TransportAddr(\"{}\")", s),
            None => write!(f, "TransportAddr({:?})", self.0),
        }
    }
}

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Best-effort display as string if valid UTF-8, else hex
        match self.as_str() {
            Some(s) => write!(f, "{}", s),
            None => {
                for byte in &self.0 {
                    write!(f, "{:02x}", byte)?;
                }
                Ok(())
            }
        }
    }
}

impl From<&str> for TransportAddr {
    fn from(s: &str) -> Self {
        Self::from_string(s)
    }
}

impl From<String> for TransportAddr {
    fn from(s: String) -> Self {
        Self(s.into_bytes())
    }
}

/// Statistics for a link.
#[derive(Clone, Debug, Default)]
pub struct LinkStats {
    /// Total packets sent.
    pub packets_sent: u64,
    /// Total packets received.
    pub packets_recv: u64,
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_recv: u64,
    /// Timestamp of last received packet (Unix milliseconds).
    pub last_recv_ms: u64,
    /// Estimated round-trip time.
    rtt_estimate: Option<Duration>,
    /// Observed packet loss rate (0.0-1.0).
    pub loss_rate: f32,
    /// Estimated throughput in bytes/second.
    pub throughput_estimate: u64,
}

impl LinkStats {
    /// Create new link statistics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a sent packet.
    pub fn record_sent(&mut self, bytes: usize) {
        self.packets_sent += 1;
        self.bytes_sent += bytes as u64;
    }

    /// Record a received packet.
    pub fn record_recv(&mut self, bytes: usize, timestamp_ms: u64) {
        self.packets_recv += 1;
        self.bytes_recv += bytes as u64;
        self.last_recv_ms = timestamp_ms;
    }

    /// Get the RTT estimate, if available.
    pub fn rtt_estimate(&self) -> Option<Duration> {
        self.rtt_estimate
    }

    /// Update RTT estimate from a probe response.
    ///
    /// Uses exponential moving average with alpha=0.2.
    pub fn update_rtt(&mut self, rtt: Duration) {
        match self.rtt_estimate {
            Some(old_rtt) => {
                let alpha = 0.2;
                let new_rtt_nanos = (alpha * rtt.as_nanos() as f64
                    + (1.0 - alpha) * old_rtt.as_nanos() as f64)
                    as u64;
                self.rtt_estimate = Some(Duration::from_nanos(new_rtt_nanos));
            }
            None => {
                self.rtt_estimate = Some(rtt);
            }
        }
    }

    /// Time since last receive (for keepalive/timeout).
    pub fn time_since_recv(&self, current_time_ms: u64) -> u64 {
        if self.last_recv_ms == 0 {
            return u64::MAX;
        }
        current_time_ms.saturating_sub(self.last_recv_ms)
    }

    /// Reset all statistics.
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

/// A link to a remote endpoint over a transport.
#[derive(Clone, Debug)]
pub struct Link {
    /// Unique link identifier.
    link_id: LinkId,
    /// Which transport this link uses.
    transport_id: TransportId,
    /// Transport-specific remote address.
    remote_addr: TransportAddr,
    /// Whether we initiated or they initiated.
    direction: LinkDirection,
    /// Current link state.
    state: LinkState,
    /// Base RTT hint from transport type.
    base_rtt: Duration,
    /// Measured statistics.
    stats: LinkStats,
    /// When this link was created (Unix milliseconds).
    created_at: u64,
}

impl Link {
    /// Create a new link in Connecting state.
    pub fn new(
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        direction: LinkDirection,
        base_rtt: Duration,
    ) -> Self {
        Self {
            link_id,
            transport_id,
            remote_addr,
            direction,
            state: LinkState::Connecting,
            base_rtt,
            stats: LinkStats::new(),
            created_at: 0,
        }
    }

    /// Create a link with a creation timestamp.
    pub fn new_with_timestamp(
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        direction: LinkDirection,
        base_rtt: Duration,
        created_at: u64,
    ) -> Self {
        let mut link = Self::new(link_id, transport_id, remote_addr, direction, base_rtt);
        link.created_at = created_at;
        link
    }

    /// Create a connectionless link (immediately connected).
    ///
    /// For connectionless transports (UDP, Ethernet), links are immediately
    /// in the Connected state.
    pub fn connectionless(
        link_id: LinkId,
        transport_id: TransportId,
        remote_addr: TransportAddr,
        direction: LinkDirection,
        base_rtt: Duration,
    ) -> Self {
        let mut link = Self::new(link_id, transport_id, remote_addr, direction, base_rtt);
        link.state = LinkState::Connected;
        link
    }

    /// Get the link ID.
    pub fn link_id(&self) -> LinkId {
        self.link_id
    }

    /// Get the transport ID.
    pub fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    /// Get the remote address.
    pub fn remote_addr(&self) -> &TransportAddr {
        &self.remote_addr
    }

    /// Get the link direction.
    pub fn direction(&self) -> LinkDirection {
        self.direction
    }

    /// Get the current state.
    pub fn state(&self) -> LinkState {
        self.state
    }

    /// Get the base RTT hint.
    pub fn base_rtt(&self) -> Duration {
        self.base_rtt
    }

    /// Get the link statistics.
    pub fn stats(&self) -> &LinkStats {
        &self.stats
    }

    /// Get mutable access to link statistics.
    pub fn stats_mut(&mut self) -> &mut LinkStats {
        &mut self.stats
    }

    /// Get the creation timestamp.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    /// Set the creation timestamp.
    pub fn set_created_at(&mut self, timestamp: u64) {
        self.created_at = timestamp;
    }

    /// Mark the link as connected.
    pub fn set_connected(&mut self) {
        self.state = LinkState::Connected;
    }

    /// Mark the link as disconnected.
    pub fn set_disconnected(&mut self) {
        self.state = LinkState::Disconnected;
    }

    /// Mark the link as failed.
    pub fn set_failed(&mut self) {
        self.state = LinkState::Failed;
    }

    /// Check if this link is operational.
    pub fn is_operational(&self) -> bool {
        self.state.is_operational()
    }

    /// Check if this link is in a terminal state.
    pub fn is_terminal(&self) -> bool {
        self.state.is_terminal()
    }

    /// Get effective RTT (measured if available, else base hint).
    pub fn effective_rtt(&self) -> Duration {
        self.stats.rtt_estimate().unwrap_or(self.base_rtt)
    }

    /// Age of the link in milliseconds.
    pub fn age(&self, current_time_ms: u64) -> u64 {
        if self.created_at == 0 {
            return 0;
        }
        current_time_ms.saturating_sub(self.created_at)
    }
}

/// A peer discovered via transport-layer discovery.
#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    /// Transport that discovered this peer.
    pub transport_id: TransportId,
    /// Transport address where the peer was found.
    pub addr: TransportAddr,
    /// Optional hint about the peer's identity (if known from discovery).
    pub pubkey_hint: Option<XOnlyPublicKey>,
}

impl DiscoveredPeer {
    /// Create a discovered peer without identity hint.
    pub fn new(transport_id: TransportId, addr: TransportAddr) -> Self {
        Self {
            transport_id,
            addr,
            pubkey_hint: None,
        }
    }

    /// Create a discovered peer with identity hint.
    pub fn with_hint(
        transport_id: TransportId,
        addr: TransportAddr,
        pubkey: XOnlyPublicKey,
    ) -> Self {
        Self {
            transport_id,
            addr,
            pubkey_hint: Some(pubkey),
        }
    }
}

/// Transport trait defining the interface for transport drivers.
///
/// This is a simplified synchronous trait. Actual implementations would
/// be async and use channels for event delivery.
pub trait Transport {
    /// Get the transport identifier.
    fn transport_id(&self) -> TransportId;

    /// Get the transport type metadata.
    fn transport_type(&self) -> &TransportType;

    /// Get the current state.
    fn state(&self) -> TransportState;

    /// Get the MTU for this transport.
    fn mtu(&self) -> u16;

    /// Start the transport.
    fn start(&mut self) -> Result<(), TransportError>;

    /// Stop the transport.
    fn stop(&mut self) -> Result<(), TransportError>;

    /// Send data to a transport address.
    fn send(&self, addr: &TransportAddr, data: &[u8]) -> Result<(), TransportError>;

    /// Discover potential peers (if supported).
    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transport_id() {
        let id = TransportId::new(42);
        assert_eq!(id.as_u32(), 42);
        assert_eq!(format!("{}", id), "transport:42");
    }

    #[test]
    fn test_link_id() {
        let id = LinkId::new(12345);
        assert_eq!(id.as_u64(), 12345);
        assert_eq!(format!("{}", id), "link:12345");
    }

    #[test]
    fn test_transport_state_transitions() {
        assert!(TransportState::Configured.can_start());
        assert!(TransportState::Down.can_start());
        assert!(TransportState::Failed.can_start());
        assert!(!TransportState::Starting.can_start());
        assert!(!TransportState::Up.can_start());

        assert!(TransportState::Up.is_operational());
        assert!(!TransportState::Starting.is_operational());
        assert!(!TransportState::Failed.is_operational());
    }

    #[test]
    fn test_link_state() {
        assert!(LinkState::Connected.is_operational());
        assert!(!LinkState::Connecting.is_operational());
        assert!(!LinkState::Disconnected.is_operational());
        assert!(!LinkState::Failed.is_operational());

        assert!(LinkState::Disconnected.is_terminal());
        assert!(LinkState::Failed.is_terminal());
        assert!(!LinkState::Connected.is_terminal());
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_transport_type_constants() {
        // These assertions verify the constant definitions are correct
        assert!(!TransportType::UDP.connection_oriented);
        assert!(!TransportType::UDP.reliable);
        assert!(TransportType::UDP.is_connectionless());

        assert!(TransportType::TOR.connection_oriented);
        assert!(TransportType::TOR.reliable);
        assert!(!TransportType::TOR.is_connectionless());

        assert_eq!(TransportType::UDP.name, "udp");
        assert_eq!(TransportType::ETHERNET.name, "ethernet");
    }

    #[test]
    fn test_transport_addr_string() {
        let addr = TransportAddr::from_string("192.168.1.1:4000");
        assert_eq!(format!("{}", addr), "192.168.1.1:4000");
        assert_eq!(addr.as_str(), Some("192.168.1.1:4000"));
    }

    #[test]
    fn test_transport_addr_binary() {
        // Binary address with invalid UTF-8 bytes (0xff, 0x80 are invalid UTF-8)
        let binary = TransportAddr::new(vec![0xff, 0x80, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(format!("{}", binary), "ff802b3c4d5e");
        assert!(binary.as_str().is_none());
        assert_eq!(binary.len(), 6);
    }

    #[test]
    fn test_transport_addr_from_string() {
        let addr: TransportAddr = "test:1234".into();
        assert_eq!(addr.as_str(), Some("test:1234"));

        let addr2: TransportAddr = String::from("hello").into();
        assert_eq!(addr2.as_str(), Some("hello"));
    }

    #[test]
    fn test_link_stats_basic() {
        let mut stats = LinkStats::new();

        stats.record_sent(100);
        stats.record_recv(200, 1000);

        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.packets_recv, 1);
        assert_eq!(stats.bytes_recv, 200);
        assert_eq!(stats.last_recv_ms, 1000);
    }

    #[test]
    fn test_link_stats_rtt() {
        let mut stats = LinkStats::new();

        assert!(stats.rtt_estimate().is_none());

        stats.update_rtt(Duration::from_millis(100));
        assert_eq!(stats.rtt_estimate(), Some(Duration::from_millis(100)));

        // Second update uses EMA
        stats.update_rtt(Duration::from_millis(200));
        // EMA: 0.2 * 200 + 0.8 * 100 = 120ms
        let rtt = stats.rtt_estimate().unwrap();
        assert!(rtt.as_millis() >= 110 && rtt.as_millis() <= 130);
    }

    #[test]
    fn test_link_stats_time_since_recv() {
        let mut stats = LinkStats::new();

        // No receive yet
        assert_eq!(stats.time_since_recv(1000), u64::MAX);

        stats.record_recv(100, 500);
        assert_eq!(stats.time_since_recv(1000), 500);
        assert_eq!(stats.time_since_recv(500), 0);
    }

    #[test]
    fn test_link_creation() {
        let link = Link::new(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        assert_eq!(link.state(), LinkState::Connecting);
        assert!(!link.is_operational());
        assert_eq!(link.direction(), LinkDirection::Outbound);
    }

    #[test]
    fn test_link_connectionless() {
        let link = Link::connectionless(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Inbound,
            Duration::from_millis(5),
        );

        assert_eq!(link.state(), LinkState::Connected);
        assert!(link.is_operational());
    }

    #[test]
    fn test_link_state_changes() {
        let mut link = Link::new(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        assert!(!link.is_operational());

        link.set_connected();
        assert!(link.is_operational());
        assert!(!link.is_terminal());

        link.set_disconnected();
        assert!(!link.is_operational());
        assert!(link.is_terminal());
    }

    #[test]
    fn test_link_effective_rtt() {
        let mut link = Link::connectionless(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Inbound,
            Duration::from_millis(50),
        );

        // Before measurement, uses base RTT
        assert_eq!(link.effective_rtt(), Duration::from_millis(50));

        // After measurement, uses measured RTT
        link.stats_mut().update_rtt(Duration::from_millis(100));
        assert_eq!(link.effective_rtt(), Duration::from_millis(100));
    }

    #[test]
    fn test_link_age() {
        let mut link = Link::new(
            LinkId::new(1),
            TransportId::new(1),
            TransportAddr::from_string("test"),
            LinkDirection::Outbound,
            Duration::from_millis(50),
        );

        // No timestamp set
        assert_eq!(link.age(1000), 0);

        link.set_created_at(500);
        assert_eq!(link.age(1000), 500);
        assert_eq!(link.age(500), 0);
    }

    #[test]
    fn test_discovered_peer() {
        let peer = DiscoveredPeer::new(
            TransportId::new(1),
            TransportAddr::from_string("192.168.1.1:4000"),
        );

        assert_eq!(peer.transport_id, TransportId::new(1));
        assert!(peer.pubkey_hint.is_none());
    }

    #[test]
    fn test_link_direction_display() {
        assert_eq!(format!("{}", LinkDirection::Outbound), "outbound");
        assert_eq!(format!("{}", LinkDirection::Inbound), "inbound");
    }

    #[test]
    fn test_transport_state_display() {
        assert_eq!(format!("{}", TransportState::Up), "up");
        assert_eq!(format!("{}", TransportState::Failed), "failed");
    }
}
