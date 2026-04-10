//! Ethernet Transport Implementation
//!
//! Provides raw Ethernet transport for FIPS peer communication. On Linux,
//! uses AF_PACKET/SOCK_DGRAM sockets; on macOS, uses BPF devices (`/dev/bpf*`).
//! Works on wired Ethernet and WiFi interfaces (kernel mac80211 abstracts
//! 802.11 transparently on Linux).

pub mod discovery;
pub mod socket;
pub mod stats;

use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::EthernetConfig;
use discovery::{DiscoveryBuffer, FRAME_TYPE_BEACON, FRAME_TYPE_DATA, build_beacon, parse_beacon};
use socket::{AsyncPacketSocket, ETHERNET_BROADCAST, PacketSocket};
use stats::EthernetStats;

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
    /// Effective MTU (interface MTU - 4 for frame header).
    effective_mtu: u16,
    /// Discovery buffer for discovered peers.
    discovery_buffer: Arc<DiscoveryBuffer>,
    /// Transport-level statistics.
    stats: Arc<EthernetStats>,
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
            effective_mtu: 1496, // default, updated on start
            discovery_buffer,
            stats,
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

        // Effective MTU: interface MTU minus 4 bytes for frame header
        // (1 byte frame type + 1 byte flags + 2 bytes LE payload length)
        let effective_mtu = if let Some(configured_mtu) = self.config.mtu {
            // Config MTU cannot exceed interface MTU - 4
            configured_mtu.min(if_mtu.saturating_sub(4))
        } else {
            if_mtu.saturating_sub(4)
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
            let beacon_socket = socket.clone();
            let interval_secs = self.config.beacon_interval_secs();
            let beacon_stats = self.stats.clone();
            let beacon_transport_id = self.transport_id;
            let beacon_interface = self.config.interface.clone();
            let beacon_ethertype = self.config.ethertype();

            let beacon_task = tokio::spawn(async move {
                beacon_sender_loop(
                    beacon_socket,
                    interval_secs,
                    beacon_stats,
                    beacon_transport_id,
                    beacon_interface,
                    beacon_ethertype,
                )
                .await;
            });
            self.beacon_task = Some(beacon_task);
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

        // Signal the socket to shut down. On macOS this writes to the
        // shutdown pipe, waking the reader thread's select() immediately.
        // On Linux this is a no-op (AsyncFd cancellation handles it).
        if let Some(ref socket) = self.socket {
            socket.shutdown();
        }

        // Abort tasks. On Linux, safe to await since all I/O is
        // AsyncFd-based and cancellation-safe. On macOS, do NOT await —
        // on a current_thread runtime the aborted task can't be polled
        // while we're blocked on the JoinHandle, causing a deadlock.
        if let Some(task) = self.beacon_task.take() {
            task.abort();
            #[cfg(not(target_os = "macos"))]
            {
                let _ = task.await;
            }
        }
        if let Some(task) = self.recv_task.take() {
            task.abort();
            #[cfg(not(target_os = "macos"))]
            {
                let _ = task.await;
            }
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
    /// The data is prepended with a 4-byte frame header before transmission.
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

        // Prepend 4-byte frame header: type(1) + flags(1) + length(2 LE).
        // The length field lets the receiver trim Ethernet minimum-frame padding
        // (NICs pad frames shorter than 46 bytes payload to 46 bytes with zeros,
        // which would otherwise corrupt AEAD ciphertext verification).
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.push(FRAME_TYPE_DATA);
        frame.push(0x00); // flags (reserved)
        frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(data);

        let bytes_sent = socket.send_to(&frame, &dest_mac).await?;
        self.stats.record_send(bytes_sent);

        trace!(
            transport_id = %self.transport_id,
            remote_mac = %format_mac(&dest_mac),
            bytes = bytes_sent,
            "Ethernet frame sent"
        );

        // Return the data bytes sent (excluding 4-byte frame header)
        Ok(bytes_sent.saturating_sub(4))
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
                        // Data frame: [type:1][flags:1][length:2 LE][payload:N]
                        if len < 4 {
                            trace!("Data frame too short ({len} bytes), ignoring");
                            continue;
                        }
                        // buf[1] is flags (reserved, ignored for now)
                        let payload_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
                        if payload_len > len - 4 {
                            trace!(
                                "Data frame length field ({payload_len}) exceeds \
                                 available bytes ({}), ignoring",
                                len - 4
                            );
                            continue;
                        }
                        let data = buf[4..4 + payload_len].to_vec();
                        let addr = TransportAddr::from_bytes(&src_mac);
                        let packet = ReceivedPacket::new(transport_id, addr, data);

                        trace!(
                            transport_id = %transport_id,
                            remote_mac = %format_mac(&src_mac),
                            bytes = payload_len,
                            "Ethernet data frame received"
                        );

                        if packet_tx.send(packet).await.is_err() {
                            debug!(
                                transport_id = %transport_id,
                                "Packet channel closed, stopping receive loop"
                            );
                            break;
                        }
                    }
                    FRAME_TYPE_BEACON => {
                        stats.record_beacon_recv();

                        if discovery_enabled && parse_beacon(&buf[..len]) {
                            discovery_buffer.add_peer(src_mac);
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
///
/// Detects stale AF_PACKET sockets (ENXIO / os error 6) that occur when
/// the underlying veth interface is destroyed and recreated (e.g., during
/// node churn in chaos tests). After `REOPEN_THRESHOLD` consecutive send
/// failures, attempts to open a fresh socket on the same interface.
async fn beacon_sender_loop(
    mut socket: Arc<AsyncPacketSocket>,
    interval_secs: u64,
    stats: Arc<EthernetStats>,
    transport_id: TransportId,
    interface: String,
    ethertype: u16,
) {
    /// Number of consecutive ENXIO errors before attempting socket reopen.
    const REOPEN_THRESHOLD: u32 = 3;

    let beacon = build_beacon();
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
    let mut consecutive_errors: u32 = 0;

    loop {
        interval_timer.tick().await;

        match socket.send_to(&beacon, &ETHERNET_BROADCAST).await {
            Ok(_) => {
                if consecutive_errors > 0 {
                    debug!(
                        transport_id = %transport_id,
                        "Beacon send recovered after {} errors", consecutive_errors,
                    );
                }
                consecutive_errors = 0;
                stats.record_beacon_sent();
                trace!(
                    transport_id = %transport_id,
                    "Beacon sent"
                );
            }
            Err(e) => {
                consecutive_errors += 1;
                stats.record_send_error();

                let is_enxio = format!("{e}").contains("os error 6");

                // Log only the first error in a streak to avoid log spam
                if consecutive_errors == 1 {
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "Failed to send beacon"
                    );
                }

                if is_enxio && consecutive_errors >= REOPEN_THRESHOLD {
                    info!(
                        transport_id = %transport_id,
                        consecutive_errors,
                        interface = %interface,
                        "Stale veth detected (ENXIO), attempting socket reopen"
                    );
                    match reopen_beacon_socket(&interface, ethertype) {
                        Ok(new_socket) => {
                            socket = Arc::new(new_socket);
                            consecutive_errors = 0;
                            info!(
                                transport_id = %transport_id,
                                interface = %interface,
                                "Beacon socket reopened successfully"
                            );
                        }
                        Err(e) => {
                            warn!(
                                transport_id = %transport_id,
                                error = %e,
                                interface = %interface,
                                "Failed to reopen beacon socket, will retry"
                            );
                        }
                    }
                }
            }
        }
    }
}

/// Attempt to open a fresh AF_PACKET socket for beacon sending.
///
/// This is called when the beacon sender detects that the underlying veth
/// has been recreated and the old socket FD is stale (ENXIO).
fn reopen_beacon_socket(
    interface: &str,
    ethertype: u16,
) -> Result<AsyncPacketSocket, TransportError> {
    let raw_socket = PacketSocket::open(interface, ethertype)?;
    raw_socket.into_async()
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
        // Verify data frames have 4-byte header + payload
        let data = vec![1, 2, 3, 4];
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.push(FRAME_TYPE_DATA);
        frame.push(0x00); // flags
        frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(&data);

        assert_eq!(frame[0], 0x00); // frame type
        assert_eq!(frame[1], 0x00); // flags
        assert_eq!(u16::from_le_bytes([frame[2], frame[3]]), 4); // length
        assert_eq!(&frame[4..], &[1, 2, 3, 4]); // payload
    }

    #[test]
    fn test_data_frame_padding_trimmed() {
        // Simulate Ethernet minimum-frame padding: a 4-byte payload produces
        // an 8-byte frame (header + payload), padded to 46 bytes by NIC.
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let payload_len = payload.len() as u16;

        // Build frame as sender would
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.push(FRAME_TYPE_DATA);
        frame.push(0x00); // flags
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&payload);

        // Simulate NIC padding to 46 bytes
        frame.resize(46, 0x00);

        // Receiver extracts using length field
        let recv_len = u16::from_le_bytes([frame[2], frame[3]]) as usize;
        let extracted = &frame[4..4 + recv_len];
        assert_eq!(extracted, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_beacon_size() {
        assert_eq!(discovery::BEACON_SIZE, 5);
    }

    #[test]
    fn test_unified_header_flags_byte() {
        // Build a data frame and verify the flags byte at offset 1 is 0x00
        let data = vec![0x42];
        let mut frame = Vec::with_capacity(4 + data.len());
        frame.push(FRAME_TYPE_DATA);
        frame.push(0x00); // flags
        frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(&data);

        assert_eq!(frame[1], 0x00);
    }
}
