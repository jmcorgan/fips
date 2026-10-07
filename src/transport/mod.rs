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
pub mod usb;

#[cfg(any(target_os = "linux", target_os = "macos"))]
pub mod ethernet;

/// Kernel link-event notifications, shared by any transport or detector that
/// needs to react to interface state without polling for it.
///
/// Crate-internal on purpose. It is a mechanism the node's own subsystems
/// share, not a surface an embedder builds against, and publishing it would
/// commit the library to its shape before anything outside the crate has asked
/// for it.
#[cfg(unix)]
pub(crate) mod watcher;

/// Presence lifecycle for a transport bound to a local resource that can
/// disappear and come back: the phase machine, the absence policy, and the
/// damping that keeps a flapping resource from flapping node health with it.
///
/// Transport-agnostic on purpose. Only the *probe* — "is my thing there, and
/// is it still the same one?" — is specific to what is bound, and that stays
/// with the transport that knows how to ask.
///
/// Crate-internal on purpose, for the same reason as `watcher` above: it is a
/// mechanism the crate's own transports share, not a surface an embedder
/// builds against. `ethernet` re-exports the two types it used to own, so the
/// published path stays `transport::ethernet::{AbsencePolicy, Presence}`.
/// Gated with the one transport that binds through it today; widen the gate
/// when a second binder arrives.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) mod presence;

#[cfg(ble_available)]
pub mod ble;

#[cfg(ble_available)]
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
use usb::UsbTransport;

pub(crate) mod framing;
pub(crate) mod stream;

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

/// Operator-visible interface presence, rendered by `show_transports`.
///
/// Worth as much as the retry itself. The original boot-race bug was expensive
/// precisely because the 802.11s peer link formed regardless of the daemon, so
/// nothing an operator could see said the node was deaf.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InterfacePresence {
    /// `absent`, `binding`, or `present`.
    pub presence: &'static str,
    /// Whether the interface currently has carrier (`IFF_RUNNING`).
    ///
    /// Reported, never acted on. Presence is `IFF_UP`, because binding does
    /// not need carrier and a socket outlives a carrier flap — but "is
    /// anything plugged in" is still what an operator wants to know when a
    /// bound transport is carrying nothing, so it is reported here instead of
    /// steering the daemon.
    pub carrier: bool,
    /// `required` or `optional`.
    pub policy: &'static str,
    /// How long the current phase has been held.
    pub since_secs: u64,
    /// Successful binds since the transport was created (`1` after a clean
    /// start; more means it has rebound).
    pub binds: u64,
    /// Failed bind attempts since the last successful bind.
    pub failed_attempts: u32,
}

/// A presence edge published by an interface-bound transport.
///
/// Absence and return are the same transition seen from two sides, so one
/// event type carries both: `present: false` on detach (including a start
/// where the interface was never there), `present: true` on every successful
/// bind after the first observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransportPresence {
    /// The transport whose interface changed presence.
    pub transport_id: TransportId,
    /// Whether the interface is now bound.
    pub present: bool,
    /// Whether this edge should move node health.
    ///
    /// `false` for an `optional` interface, whose absence is normal and must
    /// not take the node off `Full`. The edge is still published, because the
    /// bound set changed either way and the node's egress MTU floor is derived
    /// from it — health and MTU are two different questions riding one
    /// channel, and only the first one is policy-filtered.
    pub health_relevant: bool,
}

/// Channel sender for transport presence edges.
pub type PresenceTx = tokio::sync::mpsc::Sender<TransportPresence>;

/// Channel receiver for transport presence edges.
pub type PresenceRx = tokio::sync::mpsc::Receiver<TransportPresence>;

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

    /// The named network interface is not usable right now: it does not exist,
    /// or it exists but is administratively down (no `IFF_UP`).
    ///
    /// Distinct from [`TransportError::StartFailed`] because absence is a
    /// *state*, not a fault. Interface-bound transports treat it as "not bound
    /// yet" and keep a presence watcher running; a `StartFailed` carrying the
    /// same text could not be told apart from a typo'd interface name or a
    /// missing capability.
    #[error("interface unavailable: {interface}")]
    InterfaceUnavailable {
        /// The configured interface name.
        interface: String,
    },

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

    /// No connection to the address exists, and the send did not open one.
    /// The connection a reply was meant for has gone; the remote's next
    /// attempt arrives on a new one.
    #[error("not connected")]
    NotConnected,

    #[error("transport not supported: {0}")]
    NotSupported(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl TransportError {
    /// Whether the kernel refused the send for want of a route: the
    /// interface is up but nothing is reachable through it. A hard signal
    /// that the path is gone (`ENETUNREACH`, `EHOSTUNREACH`), distinct from
    /// `is_transient`: the binder is not going to fix this.
    pub fn is_unreachable(&self) -> bool {
        match self {
            Self::Io(e) => matches!(
                e.kind(),
                std::io::ErrorKind::NetworkUnreachable | std::io::ErrorKind::HostUnreachable
            ),
            _ => false,
        }
    }

    /// Whether this failure is expected to clear on its own.
    ///
    /// The distinction callers need is not *what* went wrong but whether
    /// waiting fixes it. A transient failure means the operation was refused
    /// by a condition the daemon is already working to resolve, so the state
    /// built up around it — a half-finished handshake, a route, a queued
    /// packet — is worth keeping. A terminal one means the state is worth
    /// tearing down.
    ///
    /// This lives here, on the error, rather than being re-derived at each
    /// call site: `InterfaceUnavailable` used to be flattened into a
    /// formatted string on its way out of the transport layer, so every
    /// caller downstream saw a generic send failure and could only treat a
    /// two-second interface flap exactly as it treated a permanent fault.
    ///
    /// Deliberately narrow. [`Self::Timeout`] and [`Self::ConnectionRefused`]
    /// are *not* transient here: they describe a remote that did not answer,
    /// which is a statement about the peer rather than about this node's
    /// ability to transmit, and the existing retry paths for them already sit
    /// at a different layer.
    pub fn is_transient(&self) -> bool {
        match self {
            // The interface is absent or mid-rebind. The binder is polling for
            // it and will bind it the moment it returns.
            Self::InterfaceUnavailable { .. } => true,
            Self::NotStarted
            | Self::AlreadyStarted
            | Self::StartFailed(_)
            | Self::ShutdownFailed(_)
            | Self::LinkFailed(_)
            | Self::SendFailed(_)
            | Self::RecvFailed(_)
            | Self::InvalidAddress(_)
            | Self::MtuExceeded { .. }
            | Self::Timeout
            | Self::ConnectionRefused
            // The connection the frame was meant for has gone, and the send
            // did not reopen it; the remote's next attempt arrives on a new
            // connection.
            | Self::NotConnected
            | Self::NotSupported(_)
            | Self::Io(_) => false,
        }
    }
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

    /// USB transport: an Android Open Accessory bulk pipe between two nodes.
    pub const USB: TransportType = TransportType {
        name: "usb",
        connection_oriented: true,
        reliable: true, // USB bulk transfers are acknowledged and retried
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
        // The longest form is 58 bytes: [39-byte IPv6%10-digit scope]:65535.
        let mut buf = [0u8; 64];
        let mut cursor = &mut buf[..];
        write!(&mut cursor, "{addr}").expect("64 bytes is enough for any SocketAddr");
        let len = 64 - cursor.len();
        Self::from_bytes(&buf[..len])
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

    /// Point the link at another transport and address.
    ///
    /// A peer whose active path switched keeps its link (the control machine
    /// is keyed on it); the record follows the traffic.
    pub fn rebind(&mut self, transport_id: TransportId, remote_addr: TransportAddr) {
        self.transport_id = transport_id;
        self.remote_addr = remote_addr;
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

    /// The transport's path-selection role. Default: normal. Concrete
    /// transports read from their own config.
    fn role(&self) -> crate::config::TransportRole {
        crate::config::TransportRole::Normal
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
// Background Connects
// ============================================================================

/// What a background connect task yields: the connected stream and the MTU
/// to use on it.
pub(crate) type ConnectOutcome = Result<(tokio::net::TcpStream, u16), TransportError>;

/// Take the background connect for `addr` out of `connecting` if its task
/// has finished, and return what it produced.
///
/// Returns `None`, leaving the map untouched, when there is no attempt for
/// the address or it is still running.
pub(crate) fn take_finished_connect<E>(
    connecting: &mut std::collections::HashMap<TransportAddr, E>,
    addr: &TransportAddr,
) -> Option<ConnectOutcome>
where
    E: AsMut<tokio::task::JoinHandle<ConnectOutcome>>,
{
    use futures::FutureExt;

    let task = connecting.get_mut(addr)?.as_mut();
    if !task.is_finished() {
        return None;
    }
    // Polling a JoinHandle spends the caller's cooperative budget, and with
    // none left it reads pending even though the task has finished. Poll it
    // unconstrained, and remove the entry only once its output is in hand,
    // so a connected stream is never dropped unread.
    let joined = tokio::task::unconstrained(task).now_or_never()?;
    connecting.remove(addr);
    match joined {
        Ok(outcome) => Some(outcome),
        Err(e) => Some(Err(TransportError::LinkFailed(format!(
            "connect task failed: {e}"
        )))),
    }
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
    #[cfg(ble_available)]
    Ble(DefaultBleTransport),
    /// USB (Android Open Accessory) transport.
    Usb(UsbTransport),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.start_async().await,
            TransportHandle::Usb(t) => t.start_async().await,
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.stop_async().await,
            TransportHandle::Usb(t) => t.stop_async().await,
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.send_async(addr, data).await,
            TransportHandle::Usb(t) => t.send_async(addr, data).await,
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.send_async(addr, data).await,
        }
    }

    /// Send data only over a connection that already exists; never dial.
    ///
    /// On TCP, Tor and Nym, a background connect that has finished is taken
    /// into the pool and used; otherwise the call fails at once with
    /// [`TransportError::NotConnected`] and opens nothing. Connectionless
    /// transports have no connection to look up and send as
    /// [`send`](Self::send) does. BLE's send never waits on a connect and is
    /// used as is.
    ///
    /// Use this from anything the rx loop awaits: a dial there holds every
    /// other frame for up to the transport's connect timeout.
    pub async fn send_existing(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        match self {
            TransportHandle::Udp(t) => t.send_async(addr, data).await,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.send_async(addr, data).await,
            TransportHandle::Tcp(t) => t.send_existing(addr, data).await,
            TransportHandle::Tor(t) => t.send_existing(addr, data).await,
            TransportHandle::Nym(t) => t.send_existing(addr, data).await,
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.send_async(addr, data).await,
            TransportHandle::Usb(t) => t.send_async(addr, data).await,
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.send_async(addr, data).await,
        }
    }

    /// Whether a connection to `addr` is already pooled: true exactly when
    /// [`send_existing`](Self::send_existing) would find one there.
    ///
    /// Changes nothing. Unlike
    /// [`connection_state`](Self::connection_state), it does not move a
    /// finished background connect into the pool, start a connect, or report
    /// a connection absent because the pool lock was busy. A finished connect
    /// that has not been pooled yet is reported false, although
    /// `send_existing` would promote it and send. Connectionless transports
    /// have no connection to look up and report true, as `connection_state`
    /// does.
    pub async fn has_connection(&self, addr: &TransportAddr) -> bool {
        match self {
            TransportHandle::Udp(_) => true,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => true,
            TransportHandle::Tcp(t) => t.has_connection(addr).await,
            TransportHandle::Tor(t) => t.has_connection(addr).await,
            TransportHandle::Nym(t) => t.has_connection(addr).await,
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.has_connection(addr).await,
            TransportHandle::Usb(t) => t.has_connection(addr).await,
            #[cfg(test)]
            TransportHandle::Loopback(_) => true,
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.transport_id(),
            TransportHandle::Usb(t) => t.transport_id(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.name(),
            TransportHandle::Usb(t) => t.name(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.transport_type(),
            TransportHandle::Usb(t) => t.transport_type(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.state(),
            TransportHandle::Usb(t) => t.state(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.mtu(),
            TransportHandle::Usb(t) => t.mtu(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.link_mtu(addr),
            TransportHandle::Usb(t) => t.mtu(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(_) => None,
            TransportHandle::Usb(_) => None,
            #[cfg(test)]
            TransportHandle::Loopback(_) => None,
        }
    }

    /// Get the raw file descriptor of the bound socket (UDP only, returns None
    /// for other transports and before the transport has started). Unix-only,
    /// since `RawFd` is a unix concept and the Windows UDP backend has no
    /// descriptor.
    #[cfg(unix)]
    pub fn raw_fd(&self) -> Option<std::os::unix::io::RawFd> {
        match self {
            TransportHandle::Udp(t) => t.raw_fd(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(_) => None,
            TransportHandle::Tcp(_) => None,
            TransportHandle::Tor(_) => None,
            TransportHandle::Nym(_) => None,
            #[cfg(ble_available)]
            TransportHandle::Ble(_) => None,
            TransportHandle::Usb(_) => None,
            #[cfg(test)]
            TransportHandle::Loopback(_) => None,
        }
    }

    /// Interface presence for interface-bound transports: the phase label, the
    /// absence policy, how long the phase has been held, and the failed-bind
    /// count since the last successful bind.
    ///
    /// `None` for transports that are not bound to a named interface — for
    /// those, presence is not a concept and an operator should not be shown an
    /// always-`present` column.
    pub fn interface_presence(&self) -> Option<InterfacePresence> {
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => {
                let state = t.presence_state();
                Some(InterfacePresence {
                    presence: t.presence().as_str(),
                    carrier: t.has_carrier(),
                    policy: t.absence_policy().as_str(),
                    since_secs: state.since().as_secs(),
                    binds: state.binds(),
                    failed_attempts: state.attempts(),
                })
            }
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.carrier().map(|carrier| InterfacePresence {
                presence: "present",
                carrier,
                policy: "optional",
                since_secs: 0,
                binds: 1,
                failed_attempts: 0,
            }),
            _ => None,
        }
    }

    /// Whether this transport can actually put a frame on the wire *now*.
    ///
    /// [`Self::is_operational`] answers a different question: it means the
    /// transport was started, which for an interface-bound transport no longer
    /// implies a live socket — that is the whole point of presence. Callers
    /// that are choosing a transport to use, or deriving a value from one,
    /// want this; callers reasoning about lifecycle want `is_operational`.
    ///
    /// `true` for every transport that is not interface-bound, so this is
    /// `is_operational` with the presence refinement applied where it exists.
    pub fn is_bound(&self) -> bool {
        if !self.is_operational() {
            return false;
        }
        match self {
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.presence() == ethernet::Presence::Present,
            _ => true,
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
            #[cfg(ble_available)]
            TransportHandle::Ble(_) => None,
            TransportHandle::Usb(_) => None,
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.discover(),
            TransportHandle::Usb(t) => t.discover(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.discover(),
        }
    }

    /// The transport's path-selection role.
    pub fn role(&self) -> crate::config::TransportRole {
        match self {
            TransportHandle::Udp(t) => t.role(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => t.role(),
            TransportHandle::Tcp(t) => t.role(),
            TransportHandle::Tor(t) => t.role(),
            TransportHandle::Nym(t) => t.role(),
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.role(),
            TransportHandle::Usb(t) => t.role(),
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.role(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.auto_connect(),
            TransportHandle::Usb(t) => t.auto_connect(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.accept_connections(),
            TransportHandle::Usb(t) => t.accept_connections(),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.connect_async(addr).await,
            TransportHandle::Usb(t) => t.connect_async(addr).await,
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.connection_state_sync(addr),
            TransportHandle::Usb(t) => t.connection_state_sync(addr),
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
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => t.close_connection_async(addr).await,
            TransportHandle::Usb(t) => t.close_connection_async(addr).await,
            #[cfg(test)]
            TransportHandle::Loopback(t) => t.record_close(addr), // connectionless; recorded for tests
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
            #[cfg(ble_available)]
            TransportHandle::Ble(_) => TransportCongestion::default(),
            TransportHandle::Usb(_) => TransportCongestion::default(),
            #[cfg(test)]
            TransportHandle::Loopback(_) => TransportCongestion::default(),
        }
    }

    /// Get transport-specific stats as a JSON value.
    ///
    /// Returns a snapshot of counters for the specific transport type.
    pub fn transport_stats(&self) -> serde_json::Value {
        self.live_stats().to_json()
    }

    /// The transport's shared counters, for reading live off the rx loop.
    ///
    /// The counters are atomics the transport updates from its own tasks and
    /// threads, so a holder sees them move without anything republishing
    /// them.
    pub(crate) fn live_stats(&self) -> LiveStats {
        match self {
            TransportHandle::Udp(t) => LiveStats::Udp(t.stats().clone()),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            TransportHandle::Ethernet(t) => LiveStats::Ethernet(t.stats().clone()),
            TransportHandle::Tcp(t) => LiveStats::Tcp(t.stats().clone()),
            TransportHandle::Tor(t) => LiveStats::Tor(t.stats().clone()),
            TransportHandle::Nym(t) => LiveStats::Nym(t.stats().clone()),
            #[cfg(ble_available)]
            TransportHandle::Ble(t) => LiveStats::Ble(t.stats().clone()),
            TransportHandle::Usb(t) => LiveStats::Usb(t.stats().clone()),
            #[cfg(test)]
            TransportHandle::Loopback(_) => LiveStats::Empty,
        }
    }
}

/// A transport's shared counters, held by reference rather than copied.
///
/// Cloning shares the counters. `show_transports` holds one per transport in
/// its published row and reads it at request time, so the counters it shows
/// are current even when nothing has republished the row.
#[derive(Clone)]
pub(crate) enum LiveStats {
    /// UDP transport counters.
    Udp(std::sync::Arc<udp::UdpStats>),
    /// Ethernet transport counters.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Ethernet(std::sync::Arc<ethernet::stats::EthernetStats>),
    /// TCP transport counters.
    Tcp(std::sync::Arc<tcp::stats::TcpStats>),
    /// Tor transport counters.
    Tor(std::sync::Arc<tor::stats::TorStats>),
    /// Nym transport counters.
    Nym(std::sync::Arc<nym::stats::NymStats>),
    /// BLE transport counters.
    #[cfg(ble_available)]
    Ble(std::sync::Arc<ble::stats::BleStats>),
    /// USB transport counters.
    Usb(std::sync::Arc<usb::stats::UsbStats>),
    /// No counters (the test loopback transport).
    #[cfg(test)]
    Empty,
}

impl LiveStats {
    /// Read the counters now, as the JSON `show_transports` reports under
    /// `stats`.
    pub(crate) fn to_json(&self) -> serde_json::Value {
        match self {
            LiveStats::Udp(s) => serde_json::to_value(s.snapshot()).unwrap_or_default(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            LiveStats::Ethernet(s) => serde_json::to_value(s.snapshot()).unwrap_or_default(),
            LiveStats::Tcp(s) => serde_json::to_value(s.snapshot()).unwrap_or_default(),
            LiveStats::Tor(s) => serde_json::to_value(s.snapshot()).unwrap_or_default(),
            LiveStats::Nym(s) => serde_json::to_value(s.snapshot()).unwrap_or_default(),
            #[cfg(ble_available)]
            LiveStats::Ble(s) => serde_json::to_value(s.snapshot()).unwrap_or_default(),
            LiveStats::Usb(s) => serde_json::to_value(s.snapshot()).unwrap_or_default(),
            #[cfg(test)]
            LiveStats::Empty => serde_json::json!({}),
        }
    }
}

/// Two values are equal when they share the same counters, not when the
/// counters happen to read the same.
impl PartialEq for LiveStats {
    fn eq(&self, other: &Self) -> bool {
        use std::sync::Arc;
        match (self, other) {
            (LiveStats::Udp(a), LiveStats::Udp(b)) => Arc::ptr_eq(a, b),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            (LiveStats::Ethernet(a), LiveStats::Ethernet(b)) => Arc::ptr_eq(a, b),
            (LiveStats::Tcp(a), LiveStats::Tcp(b)) => Arc::ptr_eq(a, b),
            (LiveStats::Tor(a), LiveStats::Tor(b)) => Arc::ptr_eq(a, b),
            (LiveStats::Nym(a), LiveStats::Nym(b)) => Arc::ptr_eq(a, b),
            #[cfg(ble_available)]
            (LiveStats::Ble(a), LiveStats::Ble(b)) => Arc::ptr_eq(a, b),
            (LiveStats::Usb(a), LiveStats::Usb(b)) => Arc::ptr_eq(a, b),
            #[cfg(test)]
            (LiveStats::Empty, LiveStats::Empty) => true,
            _ => false,
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
    resolve_socket_addrs(addr).await?.next().ok_or_else(|| {
        TransportError::InvalidAddress(format!("DNS resolution returned no addresses for {}", addr))
    })
}

/// Resolve every socket address in resolver order, bypassing DNS for numeric IPs.
pub(crate) async fn resolve_socket_addrs(
    addr: &TransportAddr,
) -> Result<impl Iterator<Item = SocketAddr>, TransportError> {
    let s = addr
        .as_str()
        .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?;

    // lookup_host handles numeric addresses without allocating or querying DNS.
    tokio::net::lookup_host(s).await.map_err(|e| {
        TransportError::InvalidAddress(format!("DNS resolution failed for {}: {}", s, e))
    })
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// A connecting-pool entry holding only its connect task.
    struct TaskEntry(tokio::task::JoinHandle<ConnectOutcome>);

    impl AsMut<tokio::task::JoinHandle<ConnectOutcome>> for TaskEntry {
        /// The background connect task.
        fn as_mut(&mut self) -> &mut tokio::task::JoinHandle<ConnectOutcome> {
            &mut self.0
        }
    }

    /// A finished connect is handed back even when the calling task has
    /// spent its cooperative budget, which makes a plain poll of the task
    /// read pending. Losing it there would close a connected stream unseen.
    #[tokio::test]
    async fn take_finished_connect_returns_the_outcome_when_the_caller_budget_is_spent() {
        let addr = TransportAddr::from_socket_addr("192.0.2.1:2121".parse().unwrap());
        let task = tokio::spawn(async { Err(TransportError::ConnectionRefused) });
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
        let mut connecting = std::collections::HashMap::from([(addr.clone(), TaskEntry(task))]);

        for _ in 0..10_000 {
            if !tokio::task::coop::has_budget_remaining() {
                break;
            }
            tokio::task::consume_budget().await;
        }
        assert!(
            !tokio::task::coop::has_budget_remaining(),
            "the test runtime must budget this task, or the case is not exercised"
        );

        let outcome = take_finished_connect(&mut connecting, &addr);
        assert!(
            matches!(outcome, Some(Err(TransportError::ConnectionRefused))),
            "finished connect not returned: {outcome:?}"
        );
        assert!(connecting.is_empty());
    }

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
        // Raw 6-byte non-UTF-8 values from from_bytes display in standard
        // colon-separated notation, not bare hex.
        let mac = TransportAddr::from_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(format!("{}", mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn a_mac_address_whose_bytes_are_valid_utf8_displays_as_a_mac() {
        let bytes = [0x32, 0x7c, 0xd1, 0xac, 0x5a, 0x64];
        assert!(core::str::from_utf8(&bytes).is_ok());
        let mac = TransportAddr::from_mac(bytes);
        assert_eq!(mac.to_string(), "32:7c:d1:ac:5a:64");
        assert_eq!(format!("{:?}", mac), "TransportAddr(32:7c:d1:ac:5a:64)");
        assert_eq!(mac.as_bytes(), &bytes);
    }

    #[test]
    fn a_mac_address_equals_and_hashes_as_its_bytes() {
        use std::hash::BuildHasher;
        let bytes = [0x32, 0x7c, 0xd1, 0xac, 0x5a, 0x64];
        let mac = TransportAddr::from_mac(bytes);
        let raw = TransportAddr::from_bytes(&bytes);
        assert_eq!(mac, raw);
        let hasher = std::collections::hash_map::RandomState::new();
        assert_eq!(hasher.hash_one(&mac), hasher.hash_one(&raw));
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
        for text in [
            "0.0.0.0:0",
            "127.0.0.1:2121",
            "255.255.255.255:65535",
            "[::1]:2121",
            "[2001:db8::1]:2121",
            "[::ffff:255.255.255.255]:65535",
            "[fe80::1%4294967295]:65535",
            "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff%4294967295]:65535",
        ] {
            let socket: std::net::SocketAddr = text.parse().unwrap();
            let addr = TransportAddr::from_socket_addr(socket);
            assert_eq!(addr.as_str(), Some(text));
            assert_eq!(addr.as_bytes(), socket.to_string().as_bytes());
            assert_eq!(
                addr.as_str()
                    .unwrap()
                    .parse::<std::net::SocketAddr>()
                    .unwrap(),
                socket
            );
        }
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

    #[test]
    fn only_an_absent_interface_classifies_as_transient() {
        // The whole point of the classification is that it is narrow. An
        // interface the binder is already polling for will come back; nothing
        // else on this list resolves itself by waiting, and treating one of
        // them as transient would mean holding state open for a fault that is
        // never going to clear.
        assert!(
            TransportError::InterfaceUnavailable {
                interface: "eth0".into()
            }
            .is_transient()
        );

        for terminal in [
            TransportError::NotStarted,
            TransportError::AlreadyStarted,
            TransportError::StartFailed("no CAP_NET_RAW".into()),
            TransportError::SendFailed("ENOBUFS".into()),
            TransportError::MtuExceeded {
                packet_size: 2000,
                mtu: 1500,
            },
            // Deliberately terminal: both describe a remote that did not
            // answer, not this node's inability to transmit.
            TransportError::Timeout,
            TransportError::ConnectionRefused,
            // The connection is gone and nothing will bring it back.
            TransportError::NotConnected,
        ] {
            assert!(
                !terminal.is_transient(),
                "{terminal:?} must not be classified transient"
            );
        }
    }
}
