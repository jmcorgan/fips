//! Ethernet Transport Implementation
//!
//! Provides raw Ethernet transport for FIPS peer communication using
//! AF_PACKET sockets with SOCK_DGRAM. Works on wired Ethernet and WiFi
//! interfaces (kernel mac80211 abstracts 802.11 transparently).

pub mod discovery;
pub mod socket;
pub mod stats;

use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::EthernetConfig;
use discovery::{
    build_beacon, parse_beacon, DiscoveryBuffer, FRAME_TYPE_BEACON, FRAME_TYPE_DATA,
};
use socket::{AsyncPacketSocket, PacketSocket, ETHERNET_BROADCAST};
use stats::EthernetStats;

use secp256k1::XOnlyPublicKey;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

/// Ethernet transport for FIPS.
///
/// Uses AF_PACKET with SOCK_DGRAM for raw Ethernet frame I/O. A single
/// socket per interface serves all peers; links are virtual tuples of
/// (transport_id, remote_mac).
pub struct EthernetTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: EthernetConfig,
    /// Current state.
    state: TransportState,
    /// Async socket (None until started).
    socket: Option<Arc<AsyncPacketSocket>>,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Receive loop task handle.
    recv_task: Option<JoinHandle<()>>,
    /// Beacon sender task handle.
    beacon_task: Option<JoinHandle<()>>,
    /// Local MAC address (after start).
    local_mac: Option<[u8; 6]>,
    /// Interface name (from config).
    interface: String,
    /// Effective MTU (interface MTU - 1 for frame type prefix).
    effective_mtu: u16,
    /// Discovery buffer for discovered peers.
    discovery_buffer: Arc<DiscoveryBuffer>,
    /// Transport-level statistics.
    stats: Arc<EthernetStats>,
    /// Node's public key for beacon construction.
    local_pubkey: Option<XOnlyPublicKey>,
}

impl EthernetTransport {
    /// Create a new Ethernet transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: EthernetConfig,
        packet_tx: PacketTx,
    ) -> Self {
        let interface = config.interface.clone();
        let discovery_buffer = Arc::new(DiscoveryBuffer::new(transport_id));
        let stats = Arc::new(EthernetStats::new());

        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            socket: None,
            packet_tx,
            recv_task: None,
            beacon_task: None,
            local_mac: None,
            interface,
            effective_mtu: 1499, // default, updated on start
            discovery_buffer,
            stats,
            local_pubkey: None,
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the interface name.
    pub fn interface_name(&self) -> &str {
        &self.interface
    }

    /// Get the local MAC address (only valid after start).
    pub fn local_mac(&self) -> Option<[u8; 6]> {
        self.local_mac
    }

    /// Set the node's public key for beacon construction.
    ///
    /// Must be called before start if announce is enabled.
    pub fn set_local_pubkey(&mut self, pubkey: XOnlyPublicKey) {
        self.local_pubkey = Some(pubkey);
    }

    /// Get a reference to the statistics.
    pub fn stats(&self) -> &Arc<EthernetStats> {
        &self.stats
    }

    /// Start the transport asynchronously.
    ///
    /// Creates the AF_PACKET socket, spawns the receive loop, and
    /// optionally spawns the beacon sender task.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        // Create and bind AF_PACKET socket
        let raw_socket = PacketSocket::open(&self.config.interface, self.config.ethertype())?;

        // Get local MAC and MTU
        let local_mac = raw_socket.local_mac()?;
        let if_mtu = raw_socket.interface_mtu()?;

        // Effective MTU: interface MTU minus 1 byte for frame type prefix
        let effective_mtu = if let Some(configured_mtu) = self.config.mtu {
            // Config MTU cannot exceed interface MTU - 1
            configured_mtu.min(if_mtu.saturating_sub(1))
        } else {
            if_mtu.saturating_sub(1)
        };
        self.effective_mtu = effective_mtu;
        self.local_mac = Some(local_mac);

        // Set buffer sizes
        raw_socket.set_recv_buffer_size(self.config.recv_buf_size())?;
        raw_socket.set_send_buffer_size(self.config.send_buf_size())?;

        // Wrap in async
        let async_socket = raw_socket.into_async()?;
        let socket = Arc::new(async_socket);
        self.socket = Some(socket.clone());

        // Spawn receive loop
        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let mtu = self.effective_mtu;
        let discovery_enabled = self.config.discovery();
        let discovery_buffer = self.discovery_buffer.clone();
        let stats = self.stats.clone();
        let recv_socket = socket.clone();

        let recv_task = tokio::spawn(async move {
            ethernet_receive_loop(
                recv_socket,
                transport_id,
                packet_tx,
                mtu,
                discovery_enabled,
                discovery_buffer,
                stats,
            )
            .await;
        });
        self.recv_task = Some(recv_task);

        // Spawn beacon sender if announce is enabled
        if self.config.announce() {
            if let Some(pubkey) = self.local_pubkey {
                let beacon_socket = socket.clone();
                let interval_secs = self.config.beacon_interval_secs();
                let beacon_stats = self.stats.clone();
                let beacon_transport_id = self.transport_id;

                let beacon_task = tokio::spawn(async move {
                    beacon_sender_loop(
                        beacon_socket,
                        pubkey,
                        interval_secs,
                        beacon_stats,
                        beacon_transport_id,
                    )
                    .await;
                });
                self.beacon_task = Some(beacon_task);
            } else {
                warn!(
                    transport_id = %self.transport_id,
                    "Announce enabled but no local pubkey set; beacons disabled"
                );
            }
        }

        self.state = TransportState::Up;

        if let Some(ref name) = self.name {
            info!(
                name = %name,
                interface = %self.interface,
                mac = %format_mac(&local_mac),
                mtu = effective_mtu,
                if_mtu = if_mtu,
                "Ethernet transport started"
            );
        } else {
            info!(
                interface = %self.interface,
                mac = %format_mac(&local_mac),
                mtu = effective_mtu,
                if_mtu = if_mtu,
                "Ethernet transport started"
            );
        }

        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort beacon task
        if let Some(task) = self.beacon_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Abort receive task
        if let Some(task) = self.recv_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Drop socket
        self.socket.take();
        self.local_mac = None;

        self.state = TransportState::Down;

        info!(
            transport_id = %self.transport_id,
            interface = %self.interface,
            "Ethernet transport stopped"
        );

        Ok(())
    }

    /// Send a packet asynchronously.
    ///
    /// The data is prepended with a FRAME_TYPE_DATA prefix byte before
    /// transmission.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        if data.len() > self.effective_mtu as usize {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.effective_mtu,
            });
        }

        let dest_mac = parse_mac_addr(addr)?;
        let socket = self.socket.as_ref().ok_or(TransportError::NotStarted)?;

        // Prepend frame type prefix
        let mut frame = Vec::with_capacity(1 + data.len());
        frame.push(FRAME_TYPE_DATA);
        frame.extend_from_slice(data);

        let bytes_sent = socket.send_to(&frame, &dest_mac).await?;
        self.stats.record_send(bytes_sent);

        trace!(
            transport_id = %self.transport_id,
            remote_mac = %format_mac(&dest_mac),
            bytes = bytes_sent,
            "Ethernet frame sent"
        );

        // Return the data bytes sent (excluding frame type prefix)
        Ok(bytes_sent.saturating_sub(1))
    }
}

impl Transport for EthernetTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::ETHERNET
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.effective_mtu
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for Ethernet transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for Ethernet transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for Ethernet transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(self.discovery_buffer.take())
    }

    fn auto_connect(&self) -> bool {
        self.config.auto_connect()
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }
}

// ============================================================================
// Receive Loop
// ============================================================================

/// Ethernet receive loop — runs as a spawned task.
async fn ethernet_receive_loop(
    socket: Arc<AsyncPacketSocket>,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mtu: u16,
    discovery_enabled: bool,
    discovery_buffer: Arc<DiscoveryBuffer>,
    stats: Arc<EthernetStats>,
) {
    // Buffer with headroom: frame type prefix + MTU + some extra
    let mut buf = vec![0u8; mtu as usize + 100];

    debug!(transport_id = %transport_id, "Ethernet receive loop starting");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src_mac)) => {
                if len == 0 {
                    continue;
                }

                stats.record_recv(len);

                let frame_type = buf[0];
                match frame_type {
                    FRAME_TYPE_DATA => {
                        // Strip the frame type prefix, deliver payload
                        let data = buf[1..len].to_vec();
                        let addr = TransportAddr::from_bytes(&src_mac);
                        let packet = ReceivedPacket::new(transport_id, addr, data);

                        trace!(
                            transport_id = %transport_id,
                            remote_mac = %format_mac(&src_mac),
                            bytes = len - 1,
                            "Ethernet data frame received"
                        );

                        if packet_tx.send(packet).await.is_err() {
                            info!(
                                transport_id = %transport_id,
                                "Packet channel closed, stopping receive loop"
                            );
                            break;
                        }
                    }
                    FRAME_TYPE_BEACON => {
                        stats.record_beacon_recv();

                        if discovery_enabled
                            && let Some(pubkey) = parse_beacon(&buf[..len])
                        {
                            discovery_buffer.add_peer(src_mac, pubkey);
                            trace!(
                                transport_id = %transport_id,
                                remote_mac = %format_mac(&src_mac),
                                "Discovery beacon received"
                            );
                        }
                    }
                    _ => {
                        // Unknown frame type, ignore
                        trace!(
                            transport_id = %transport_id,
                            frame_type = frame_type,
                            "Unknown frame type, dropping"
                        );
                    }
                }
            }
            Err(e) => {
                stats.record_recv_error();
                warn!(
                    transport_id = %transport_id,
                    error = %e,
                    "Ethernet receive error"
                );
            }
        }
    }

    debug!(transport_id = %transport_id, "Ethernet receive loop stopped");
}

// ============================================================================
// Beacon Sender
// ============================================================================

/// Periodic beacon sender loop.
async fn beacon_sender_loop(
    socket: Arc<AsyncPacketSocket>,
    pubkey: XOnlyPublicKey,
    interval_secs: u64,
    stats: Arc<EthernetStats>,
    transport_id: TransportId,
) {
    let beacon = build_beacon(&pubkey);
    let interval = tokio::time::Duration::from_secs(interval_secs);

    debug!(
        transport_id = %transport_id,
        interval_secs,
        "Beacon sender starting"
    );

    // Send an initial beacon immediately at startup
    if let Err(e) = socket.send_to(&beacon, &ETHERNET_BROADCAST).await {
        warn!(
            transport_id = %transport_id,
            error = %e,
            "Failed to send initial beacon"
        );
    } else {
        stats.record_beacon_sent();
    }

    let mut interval_timer = tokio::time::interval(interval);
    interval_timer.tick().await; // consume the immediate first tick

    loop {
        interval_timer.tick().await;

        match socket.send_to(&beacon, &ETHERNET_BROADCAST).await {
            Ok(_) => {
                stats.record_beacon_sent();
                trace!(
                    transport_id = %transport_id,
                    "Beacon sent"
                );
            }
            Err(e) => {
                stats.record_send_error();
                warn!(
                    transport_id = %transport_id,
                    error = %e,
                    "Failed to send beacon"
                );
            }
        }
    }
}

// ============================================================================
// MAC Address Helpers
// ============================================================================

/// Parse a TransportAddr as a 6-byte MAC address.
fn parse_mac_addr(addr: &TransportAddr) -> Result<[u8; 6], TransportError> {
    let bytes = addr.as_bytes();
    if bytes.len() != 6 {
        return Err(TransportError::InvalidAddress(format!(
            "expected 6-byte MAC, got {} bytes",
            bytes.len()
        )));
    }
    if bytes == [0, 0, 0, 0, 0, 0] {
        return Err(TransportError::InvalidAddress(
            "destination MAC is all zeros".into(),
        ));
    }
    let mut mac = [0u8; 6];
    mac.copy_from_slice(bytes);
    Ok(mac)
}

/// Format a MAC address as colon-separated hex for display.
pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parse a colon-separated MAC string (e.g., "aa:bb:cc:dd:ee:ff") into bytes.
pub fn parse_mac_string(s: &str) -> Result<[u8; 6], TransportError> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(TransportError::InvalidAddress(format!(
            "invalid MAC format: expected 6 colon-separated hex bytes, got '{}'",
            s
        )));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16).map_err(|_| {
            TransportError::InvalidAddress(format!("invalid hex byte '{}' in MAC address", part))
        })?;
    }
    Ok(mac)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_mac_addr_valid() {
        let addr = TransportAddr::from_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mac = parse_mac_addr(&addr).unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_addr_wrong_length() {
        let addr = TransportAddr::from_bytes(&[0xaa, 0xbb, 0xcc]);
        assert!(parse_mac_addr(&addr).is_err());

        let addr = TransportAddr::from_string("192.168.1.1:2121");
        assert!(parse_mac_addr(&addr).is_err());
    }

    #[test]
    fn test_parse_mac_addr_all_zeros() {
        let addr = TransportAddr::from_bytes(&[0, 0, 0, 0, 0, 0]);
        assert!(parse_mac_addr(&addr).is_err());
    }

    #[test]
    fn test_format_mac() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn test_format_mac_leading_zeros() {
        let mac = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        assert_eq!(format_mac(&mac), "01:02:03:04:05:06");
    }

    #[test]
    fn test_parse_mac_string_valid() {
        let mac = parse_mac_string("aa:bb:cc:dd:ee:ff").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_string_uppercase() {
        let mac = parse_mac_string("AA:BB:CC:DD:EE:FF").unwrap();
        assert_eq!(mac, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_parse_mac_string_invalid() {
        assert!(parse_mac_string("aa:bb:cc").is_err());
        assert!(parse_mac_string("not:a:mac:at:all:x").is_err());
        assert!(parse_mac_string("").is_err());
        assert!(parse_mac_string("aa-bb-cc-dd-ee-ff").is_err());
    }

    #[test]
    fn test_frame_type_data_prefix() {
        // Verify data frames are prefixed with 0x00
        let data = vec![1, 2, 3, 4];
        let mut frame = Vec::with_capacity(1 + data.len());
        frame.push(FRAME_TYPE_DATA);
        frame.extend_from_slice(&data);

        assert_eq!(frame[0], 0x00);
        assert_eq!(&frame[1..], &[1, 2, 3, 4]);
    }

    #[test]
    fn test_beacon_size() {
        assert_eq!(discovery::BEACON_SIZE, 34);
    }
}
