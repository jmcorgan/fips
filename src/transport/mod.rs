//! Transport Layer Abstractions
//!
//! Traits and types for FIPS transport drivers. Transports provide the
//! underlying communication mechanisms (UDP, Ethernet, Tor, etc.) over
//! which FIPS links are established.

#[cfg(test)]
pub mod loopback;
pub mod nym;
pub mod socks5;
pub mod tcp;
pub mod tor;
pub mod udp;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod ethernet;

#[cfg(target_os = "linux")]
pub mod ble;

#[cfg(target_os = "linux")]
use ble::DefaultBleTransport;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use ethernet::EthernetTransport;
#[cfg(test)]
use loopback::LoopbackTransport;
use nym::NymTransport;
use secp256k1::XOnlyPublicKey;
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tcp::TcpTransport;
use thiserror::Error;
use tor::TorTransport;
use tor::control::TorMonitoringInfo;
use udp::UdpTransport;

pub(crate) mod framing;

mod stats_common;
pub(crate) use stats_common::PoolCounters;

mod types;
pub use types::*;

// ============================================================================
// Packet Channel Types
// ============================================================================

/// A packet received from a transport.
#[derive(Clone, Debug)]
pub struct ReceivedPacket {
    /// Which transport received this packet.
    pub transport_id: TransportId,
    /// Remote peer address.
    pub remote_addr: TransportAddr,
    /// Packet data.
    pub data: Vec<u8>,
    /// Receipt timestamp (Unix milliseconds).
    pub timestamp_ms: u64,
}

impl ReceivedPacket {
    /// Create a new received packet with current timestamp.
    pub fn new(transport_id: TransportId, remote_addr: TransportAddr, data: Vec<u8>) -> Self {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        Self {
            transport_id,
            remote_addr,
            data,
            timestamp_ms,
        }
    }

    /// Create a received packet with explicit timestamp.
    pub fn with_timestamp(
        transport_id: TransportId,
        remote_addr: TransportAddr,
        data: Vec<u8>,
        timestamp_ms: u64,
    ) -> Self {
        Self {
            transport_id,
            remote_addr,
            data,
            timestamp_ms,
        }
    }
}

/// Channel sender for received packets.
pub type PacketTx = tokio::sync::mpsc::Sender<ReceivedPacket>;

/// Channel receiver for received packets.
pub type PacketRx = tokio::sync::mpsc::Receiver<ReceivedPacket>;

/// Create a packet channel with the given buffer size.
pub fn packet_channel(buffer: usize) -> (PacketTx, PacketRx) {
    tokio::sync::mpsc::channel(buffer)
}

// ============================================================================
// Errors
// ============================================================================

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

// ============================================================================
// Transport Type Metadata
// ============================================================================

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

    /// BLE L2CAP CoC transport.
    pub const BLE: TransportType = TransportType {
        name: "ble",
        connection_oriented: true,
        reliable: true, // L2CAP SeqPacket guarantees delivery
    };

    /// In-process loopback transport (test harness only).
    #[cfg(test)]
    pub const LOOPBACK: TransportType = TransportType {
        name: "loopback",
        connection_oriented: false,
        reliable: true, // in-process channel delivery is lossless
    };

    /// Nym mixnet transport (via SOCKS5).
    pub const NYM: TransportType = TransportType {
        name: "nym",
        connection_oriented: true,
        reliable: true,
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

// ============================================================================
// Transport State
// ============================================================================

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

// ============================================================================
// Link State
// ============================================================================

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

// ============================================================================
// Transport Address (std-bound helper; the plain type lives in `types`)
// ============================================================================

impl TransportAddr {
    /// Create a UDP/TCP transport address directly from a socket address.
    pub fn from_socket_addr(addr: std::net::SocketAddr) -> Self {
        use std::io::Write;
        let mut buf = Vec::with_capacity(56);
        write!(&mut buf, "{addr}").expect("Vec<u8>::write_fmt is infallible");
        Self::new(buf)
    }
}

// ============================================================================
// Link
// ============================================================================

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

// ============================================================================
// Discovered Peer
// ============================================================================

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

// ============================================================================
// Transport Trait
// ============================================================================

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

    /// Get the MTU for a specific link.
    ///
    /// Returns the MTU negotiated for the given transport address, or
    /// falls back to the transport-wide default if the address is unknown
    /// or the transport doesn't support per-link MTU negotiation.
    fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        let _ = addr;
        self.mtu()
    }

    /// Start the transport.
    fn start(&mut self) -> Result<(), TransportError>;

    /// Stop the transport.
    fn stop(&mut self) -> Result<(), TransportError>;

    /// Send data to a transport address.
    fn send(&self, addr: &TransportAddr, data: &[u8]) -> Result<(), TransportError>;

    /// Discover potential peers (if supported).
    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError>;

    /// Whether to auto-connect to peers returned by discover().
    /// Default: false. Concrete transports read from their own config.
    fn auto_connect(&self) -> bool {
        false
    }

    /// Whether to accept inbound handshake initiations on this transport.
    /// Default: true (preserves UDP's current implicit behavior).
    fn accept_connections(&self) -> bool {
        true
    }

    /// Close a specific connection (connection-oriented transports only).
    ///
    /// For connectionless transports (UDP, Ethernet), this is a no-op.
    /// Connection-oriented transports (TCP, Tor) remove the connection
    /// from their pool and drop the underlying stream.
    fn close_connection(&self, _addr: &TransportAddr) {
        // Default no-op for connectionless transports
    }
}

// ============================================================================
// Connection State (for non-blocking connect)
// ============================================================================

/// State of a transport-level connection attempt.
///
/// Used by connection-oriented transports (TCP, Tor) to report the progress
/// of a background connection attempt initiated by `connect()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    /// No connection attempt in progress for this address.
    None,
    /// Connection attempt is in progress (background task running).
    Connecting,
    /// Connection is established and ready for send().
    Connected,
    /// Connection attempt failed with the given error message.
    Failed(String),
}

// ============================================================================
// Transport Congestion
// ============================================================================

/// Transport-local congestion indicators.
///
/// All fields are optional — transports report what they can.
/// Consumers compute deltas from cumulative counters.
#[derive(Clone, Debug, Default)]
pub struct TransportCongestion {
    /// Cumulative packets dropped by kernel/OS before reaching the application.
    /// Monotonically increasing since transport start.
    pub recv_drops: Option<u64>,
}

// ============================================================================
// Transport Handle
// ============================================================================

/// Wrapper enum for concrete transport implementations.
///
/// This enables polymorphic transport handling without trait objects,
/// supporting async methods that the sync Transport trait cannot express.
pub enum TransportHandle {
    /// UDP/IP transport.
    Udp(UdpTransport),
    /// Raw Ethernet transport.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Ethernet(EthernetTransport),
    /// TCP/IP transport.
    Tcp(TcpTransport),
    /// Tor transport (via SOCKS5).
    Tor(TorTransport),
    /// Nym mixnet transport (via SOCKS5).
    Nym(NymTransport),
    /// BLE L2CAP transport.
    #[cfg(target_os = "linux")]
    Ble(DefaultBleTransport),
    /// In-process loopback transport (test harness only).
    #[cfg(test)]
    Loopback(LoopbackTransport),
}

impl TransportHandle {
    /// Start the transport asynchronously.
    pub async fn start(&mut self) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(t) => t.start_async().await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.start_async().await,
            TransportHandle::Tcp(t) => t.start_async().await,
            TransportHandle::Tor(t) => t.start_async().await,
            TransportHandle::Nym(t) => t.start_async().await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.start_async().await,
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.start_async().await,
        }
    }

    /// Stop the transport asynchronously.
    pub async fn stop(&mut self) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(t) => t.stop_async().await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.stop_async().await,
            TransportHandle::Tcp(t) => t.stop_async().await,
            TransportHandle::Tor(t) => t.stop_async().await,
            TransportHandle::Nym(t) => t.stop_async().await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.stop_async().await,
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.stop_async().await,
        }
    }

    /// Send data to a remote address asynchronously.
    pub async fn send(&self, addr: &TransportAddr, data: &[u8]) -> Result<usize, TransportError> {
        match self {
            TransportHandle::Udp(t) => t.send_async(addr, data).await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.send_async(addr, data).await,
            TransportHandle::Tcp(t) => t.send_async(addr, data).await,
            TransportHandle::Tor(t) => t.send_async(addr, data).await,
            TransportHandle::Nym(t) => t.send_async(addr, data).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.send_async(addr, data).await,
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.send_async(addr, data).await,
        }
    }

    /// Get the transport ID.
    pub fn transport_id(&self) -> TransportId {
        match self {
            TransportHandle::Udp(t) => t.transport_id(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.transport_id(),
            TransportHandle::Tcp(t) => t.transport_id(),
            TransportHandle::Tor(t) => t.transport_id(),
            TransportHandle::Nym(t) => t.transport_id(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.transport_id(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.transport_id(),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        match self {
            TransportHandle::Udp(t) => t.name(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.name(),
            TransportHandle::Tcp(t) => t.name(),
            TransportHandle::Tor(t) => t.name(),
            TransportHandle::Nym(t) => t.name(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.name(),
            #[cfg(test)]
            TransportHandle::Loopback(_) => None,
        }
    }

    /// Get the transport type metadata.
    pub fn transport_type(&self) -> &TransportType {
        match self {
            TransportHandle::Udp(t) => t.transport_type(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.transport_type(),
            TransportHandle::Tcp(t) => t.transport_type(),
            TransportHandle::Tor(t) => t.transport_type(),
            TransportHandle::Nym(t) => t.transport_type(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.transport_type(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.transport_type(),
        }
    }

    /// Get current transport state.
    pub fn state(&self) -> TransportState {
        match self {
            TransportHandle::Udp(t) => t.state(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.state(),
            TransportHandle::Tcp(t) => t.state(),
            TransportHandle::Tor(t) => t.state(),
            TransportHandle::Nym(t) => t.state(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.state(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.state(),
        }
    }

    /// Get the transport MTU.
    pub fn mtu(&self) -> u16 {
        match self {
            TransportHandle::Udp(t) => t.mtu(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.mtu(),
            TransportHandle::Tcp(t) => t.mtu(),
            TransportHandle::Tor(t) => t.mtu(),
            TransportHandle::Nym(t) => t.mtu(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.mtu(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.mtu(),
        }
    }

    /// Get the MTU for a specific link address.
    ///
    /// Falls back to transport-wide MTU if the transport doesn't
    /// support per-link MTU or the address is unknown.
    pub fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        match self {
            TransportHandle::Udp(t) => t.link_mtu(addr),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.link_mtu(addr),
            TransportHandle::Tcp(t) => t.link_mtu(addr),
            TransportHandle::Tor(t) => t.link_mtu(addr),
            TransportHandle::Nym(t) => t.link_mtu(addr),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.link_mtu(addr),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.link_mtu(addr),
        }
    }

    /// Get the local bound address (UDP/TCP only, returns None for other transports).
    pub fn local_addr(&self) -> Option<std::net::SocketAddr> {
        match self {
            TransportHandle::Udp(t) => t.local_addr(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => None,
            TransportHandle::Tcp(t) => t.local_addr(),
            TransportHandle::Tor(_) => None,
            TransportHandle::Nym(_) => None,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => None,
            #[cfg(test)]
            TransportHandle::Loopback(_) => None,
        }
    }

    /// Get the interface name (Ethernet only, returns None for other transports).
    pub fn interface_name(&self) -> Option<&str> {
        match self {
            TransportHandle::Udp(_) => None,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => Some(t.interface_name()),
            TransportHandle::Tcp(_) => None,
            TransportHandle::Tor(_) => None,
            TransportHandle::Nym(_) => None,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => None,
            #[cfg(test)]
            TransportHandle::Loopback(_) => None,
        }
    }

    /// Get the onion service address (Tor only, returns None for other transports).
    pub fn onion_address(&self) -> Option<&str> {
        match self {
            TransportHandle::Tor(t) => t.onion_address(),
            _ => None,
        }
    }

    /// Get cached Tor daemon monitoring info (Tor only).
    pub fn tor_monitoring(&self) -> Option<TorMonitoringInfo> {
        match self {
            TransportHandle::Tor(t) => t.cached_monitoring(),
            _ => None,
        }
    }

    /// Get the Tor transport mode (Tor only).
    pub fn tor_mode(&self) -> Option<&str> {
        match self {
            TransportHandle::Tor(t) => Some(t.mode()),
            _ => None,
        }
    }

    /// Drain discovered peers from this transport.
    pub fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        match self {
            TransportHandle::Udp(t) => t.discover(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.discover(),
            TransportHandle::Tcp(t) => t.discover(),
            TransportHandle::Tor(t) => t.discover(),
            TransportHandle::Nym(t) => t.discover(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.discover(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.discover(),
        }
    }

    /// Whether this transport auto-connects to discovered peers.
    pub fn auto_connect(&self) -> bool {
        match self {
            TransportHandle::Udp(t) => t.auto_connect(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.auto_connect(),
            TransportHandle::Tcp(t) => t.auto_connect(),
            TransportHandle::Tor(t) => t.auto_connect(),
            TransportHandle::Nym(t) => t.auto_connect(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.auto_connect(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.auto_connect(),
        }
    }

    /// Whether this transport accepts inbound connections.
    pub fn accept_connections(&self) -> bool {
        match self {
            TransportHandle::Udp(t) => t.accept_connections(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.accept_connections(),
            TransportHandle::Tcp(t) => t.accept_connections(),
            TransportHandle::Tor(t) => t.accept_connections(),
            TransportHandle::Nym(t) => t.accept_connections(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.accept_connections(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.accept_connections(),
        }
    }

    /// Initiate a non-blocking connection to a remote address.
    ///
    /// For connection-oriented transports (TCP, Tor, Nym), spawns a background
    /// task to establish the connection. For connectionless transports
    /// (UDP, Ethernet), this is a no-op that returns Ok immediately.
    ///
    /// Poll `connection_state()` to check when the connection is ready.
    pub async fn connect(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        match self {
            TransportHandle::Udp(_) => Ok(()), // connectionless
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => Ok(()), // connectionless
            TransportHandle::Tcp(t) => t.connect_async(addr).await,
            TransportHandle::Tor(t) => t.connect_async(addr).await,
            TransportHandle::Nym(t) => t.connect_async(addr).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.connect_async(addr).await,
            #[cfg(test)]
            TransportHandle::Loopback(_) => Ok(()), // connectionless
        }
    }

    /// Query the state of a connection attempt to a remote address.
    ///
    /// For connectionless transports, always returns `ConnectionState::Connected`
    /// (they are always "connected"). For connection-oriented transports, returns
    /// the current state of the background connection attempt.
    pub fn connection_state(&self, addr: &TransportAddr) -> ConnectionState {
        match self {
            TransportHandle::Udp(_) => ConnectionState::Connected,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => ConnectionState::Connected,
            TransportHandle::Tcp(t) => t.connection_state_sync(addr),
            TransportHandle::Tor(t) => t.connection_state_sync(addr),
            TransportHandle::Nym(t) => t.connection_state_sync(addr),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.connection_state_sync(addr),
            #[cfg(test)]
            TransportHandle::Loopback(_) => ConnectionState::Connected,
        }
    }

    /// Close a specific connection on this transport.
    ///
    /// No-op for connectionless transports. For TCP/Tor/Nym, removes the
    /// connection from the pool and drops the stream.
    pub async fn close_connection(&self, addr: &TransportAddr) {
        match self {
            TransportHandle::Udp(t) => t.close_connection(addr),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.close_connection(addr),
            TransportHandle::Tcp(t) => t.close_connection_async(addr).await,
            TransportHandle::Tor(t) => t.close_connection_async(addr).await,
            TransportHandle::Nym(t) => t.close_connection_async(addr).await,
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => t.close_connection_async(addr).await,
            #[cfg(test)]
            TransportHandle::Loopback(_) => {} // connectionless no-op
        }
    }

    /// Check if transport is operational.
    pub fn is_operational(&self) -> bool {
        self.state().is_operational()
    }

    /// Query transport-local congestion indicators.
    ///
    /// Returns a snapshot of congestion signals that the transport can
    /// observe locally (e.g., kernel receive buffer drops). Fields are
    /// `None` when the transport doesn't support that signal.
    pub fn congestion(&self) -> TransportCongestion {
        match self {
            TransportHandle::Udp(t) => t.congestion(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => TransportCongestion::default(),
            TransportHandle::Tcp(_) => TransportCongestion::default(),
            TransportHandle::Tor(_) => TransportCongestion::default(),
            TransportHandle::Nym(_) => TransportCongestion::default(),
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(_) => TransportCongestion::default(),
            #[cfg(test)]
            TransportHandle::Loopback(_) => TransportCongestion::default(),
        }
    }

    /// Get transport-specific stats as a JSON value.
    ///
    /// Returns a snapshot of counters for the specific transport type.
    pub fn transport_stats(&self) -> serde_json::Value {
        match self {
            TransportHandle::Udp(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            TransportHandle::Tcp(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            TransportHandle::Tor(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            TransportHandle::Nym(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            #[cfg(target_os = "linux")]
            TransportHandle::Ble(t) => {
                serde_json::to_value(t.stats().snapshot()).unwrap_or_default()
            }
            #[cfg(test)]
            TransportHandle::Loopback(_) => serde_json::json!({}),
        }
    }
}

// ============================================================================
// DNS Resolution
// ============================================================================

/// Resolve a TransportAddr to a SocketAddr.
///
/// Fast path: if the address parses as a numeric IP:port, returns
/// immediately with no DNS lookup. Otherwise, treats the address as
/// `hostname:port` and performs async DNS resolution via the system
/// resolver.
pub(crate) async fn resolve_socket_addr(
    addr: &TransportAddr,
) -> Result<SocketAddr, TransportError> {
    let s = addr
        .as_str()
        .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?;

    // Fast path: numeric IP address — no DNS lookup
    if let Ok(sock_addr) = s.parse::<SocketAddr>() {
        return Ok(sock_addr);
    }

    // Slow path: DNS resolution
    tokio::net::lookup_host(s)
        .await
        .map_err(|e| {
            TransportError::InvalidAddress(format!("DNS resolution failed for {}: {}", s, e))
        })?
        .next()
        .ok_or_else(|| {
            TransportError::InvalidAddress(format!(
                "DNS resolution returned no addresses for {}",
                s
            ))
        })
}

// ============================================================================
// Tests
// ============================================================================

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
        let addr = TransportAddr::from_string("192.168.1.1:2121");
        assert_eq!(format!("{}", addr), "192.168.1.1:2121");
        assert_eq!(addr.as_str(), Some("192.168.1.1:2121"));
    }

    #[test]
    fn test_transport_addr_binary() {
        // A 6-byte non-UTF-8 address renders as a colon-separated MAC.
        let binary = TransportAddr::new(vec![0xff, 0x80, 0x2b, 0x3c, 0x4d, 0x5e]);
        assert_eq!(format!("{}", binary), "ff:80:2b:3c:4d:5e");
        assert!(binary.as_str().is_none());
        assert_eq!(binary.len(), 6);
    }

    #[test]
    fn test_transport_addr_mac_display() {
        // Raw 6-byte MACs (as Ethernet stores via from_bytes) display in
        // standard colon-separated notation, not bare hex.
        let mac = TransportAddr::from_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(format!("{}", mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_transport_addr_non_mac_binary_is_bare_hex() {
        // Non-6-byte non-UTF-8 payloads stay bare hex (no separators).
        let three = TransportAddr::new(vec![0xff, 0x80, 0x2b]);
        assert_eq!(format!("{}", three), "ff802b");
        let seven = TransportAddr::new(vec![0xff, 0x80, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f]);
        assert_eq!(format!("{}", seven), "ff802b3c4d5e6f");
    }

    #[test]
    fn test_transport_addr_from_string() {
        let addr: TransportAddr = "test:1234".into();
        assert_eq!(addr.as_str(), Some("test:1234"));

        let addr2: TransportAddr = String::from("hello").into();
        assert_eq!(addr2.as_str(), Some("hello"));
    }

    #[test]
    fn test_transport_addr_from_socket_addr() {
        let addr = TransportAddr::from_socket_addr("127.0.0.1:2121".parse().unwrap());
        assert_eq!(addr.as_str(), Some("127.0.0.1:2121"));

        let addr = TransportAddr::from_socket_addr("[::1]:2121".parse().unwrap());
        assert_eq!(addr.as_str(), Some("[::1]:2121"));
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
            TransportAddr::from_string("192.168.1.1:2121"),
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

    #[test]
    fn test_received_packet() {
        let packet = ReceivedPacket::new(
            TransportId::new(1),
            TransportAddr::from_string("192.168.1.1:2121"),
            vec![1, 2, 3, 4],
        );

        assert_eq!(packet.transport_id, TransportId::new(1));
        assert_eq!(packet.data, vec![1, 2, 3, 4]);
        assert!(packet.timestamp_ms > 0);
    }

    #[test]
    fn test_received_packet_with_timestamp() {
        let packet = ReceivedPacket::with_timestamp(
            TransportId::new(1),
            TransportAddr::from_string("test"),
            vec![5, 6],
            12345,
        );

        assert_eq!(packet.timestamp_ms, 12345);
    }

    #[tokio::test]
    async fn test_packet_channel() {
        let (tx, mut rx) = packet_channel(10);

        let packet = ReceivedPacket::new(
            TransportId::new(1),
            TransportAddr::from_string("test"),
            vec![1, 2, 3],
        );

        tx.send(packet.clone()).await.unwrap();

        let received = rx.recv().await.unwrap();
        assert_eq!(received.data, vec![1, 2, 3]);
    }

    // ========================================================================
    // link_mtu tests
    // ========================================================================

    /// Minimal mock transport for testing the default link_mtu() behavior.
    struct MockTransport {
        id: TransportId,
        mtu_value: u16,
    }

    impl MockTransport {
        fn new(mtu: u16) -> Self {
            Self {
                id: TransportId::new(99),
                mtu_value: mtu,
            }
        }
    }

    impl Transport for MockTransport {
        fn transport_id(&self) -> TransportId {
            self.id
        }
        fn transport_type(&self) -> &TransportType {
            &TransportType::UDP
        }
        fn state(&self) -> TransportState {
            TransportState::Up
        }
        fn mtu(&self) -> u16 {
            self.mtu_value
        }
        fn start(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }
        fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
            Ok(vec![])
        }
    }

    /// Mock transport that overrides link_mtu() to return per-link values.
    struct PerLinkMtuTransport {
        id: TransportId,
        default_mtu: u16,
        /// Address-specific MTU overrides.
        overrides: Vec<(TransportAddr, u16)>,
    }

    impl PerLinkMtuTransport {
        fn new(default_mtu: u16, overrides: Vec<(TransportAddr, u16)>) -> Self {
            Self {
                id: TransportId::new(100),
                default_mtu,
                overrides,
            }
        }
    }

    impl Transport for PerLinkMtuTransport {
        fn transport_id(&self) -> TransportId {
            self.id
        }
        fn transport_type(&self) -> &TransportType {
            &TransportType::UDP
        }
        fn state(&self) -> TransportState {
            TransportState::Up
        }
        fn mtu(&self) -> u16 {
            self.default_mtu
        }
        fn link_mtu(&self, addr: &TransportAddr) -> u16 {
            for (a, mtu) in &self.overrides {
                if a == addr {
                    return *mtu;
                }
            }
            self.mtu()
        }
        fn start(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn stop(&mut self) -> Result<(), TransportError> {
            Ok(())
        }
        fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
            Ok(())
        }
        fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_link_mtu_default_falls_back_to_mtu() {
        let transport = MockTransport::new(1280);
        let addr = TransportAddr::from_string("192.168.1.1:2121");

        // Default link_mtu() should return the transport-wide mtu()
        assert_eq!(transport.link_mtu(&addr), 1280);
        assert_eq!(transport.link_mtu(&addr), transport.mtu());

        // Any address should return the same value
        let other_addr = TransportAddr::from_string("10.0.0.1:5000");
        assert_eq!(transport.link_mtu(&other_addr), 1280);
    }

    #[test]
    fn test_link_mtu_per_link_override() {
        let addr_a = TransportAddr::from_string("192.168.1.1:2121");
        let addr_b = TransportAddr::from_string("10.0.0.1:5000");
        let addr_unknown = TransportAddr::from_string("172.16.0.1:6000");

        let transport =
            PerLinkMtuTransport::new(1280, vec![(addr_a.clone(), 512), (addr_b.clone(), 247)]);

        // Known addresses return their per-link MTU
        assert_eq!(transport.link_mtu(&addr_a), 512);
        assert_eq!(transport.link_mtu(&addr_b), 247);

        // Unknown address falls back to transport-wide default
        assert_eq!(transport.link_mtu(&addr_unknown), 1280);
        assert_eq!(transport.mtu(), 1280);
    }

    #[test]
    fn test_transport_handle_link_mtu_delegation() {
        use crate::config::UdpConfig;
        use crate::transport::udp::UdpTransport;

        let config = UdpConfig::default();
        let expected_mtu = config.mtu();
        let (tx, _rx) = packet_channel(1);
        let transport = UdpTransport::new(TransportId::new(1), None, config, tx);
        let handle = TransportHandle::Udp(transport);

        let addr = TransportAddr::from_string("192.168.1.1:2121");

        // TransportHandle::link_mtu() should delegate and return the same
        // as TransportHandle::mtu() for UDP (no per-link overrides)
        assert_eq!(handle.link_mtu(&addr), expected_mtu);
        assert_eq!(handle.link_mtu(&addr), handle.mtu());
    }
}
