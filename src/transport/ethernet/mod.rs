//! Ethernet Transport Implementation
//!
//! Provides raw Ethernet transport for FIPS peer communication. On Linux,
//! uses AF_PACKET/SOCK_DGRAM sockets; on macOS, uses BPF devices (`/dev/bpf*`).
//! Works on wired Ethernet and WiFi interfaces (kernel mac80211 abstracts
//! 802.11 transparently on Linux).

pub mod addr;
pub mod io;
pub mod neighbor;
pub mod stats;

pub use addr::parse_mac_string;

use super::{
    DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};
use crate::config::EthernetConfig;
use io::{AsyncPacketSocket, ETHERNET_BROADCAST, PacketSocket};
use neighbor::{FRAME_TYPE_BEACON, FRAME_TYPE_DATA, NeighborBuffer, build_beacon, parse_beacon};
use stats::EthernetStats;

use secp256k1::XOnlyPublicKey;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

/// How often the receive loop checks whether its interface was recreated.
const REBIND_CHECK: Duration = Duration::from_secs(5);

/// The transport's current socket. The receive loop replaces it when the
/// interface is deleted and recreated; every other user reads it per use.
type SocketSlot = Arc<RwLock<Arc<AsyncPacketSocket>>>;

/// The socket in `slot` now. The lock is held only for the clone, never
/// across an `.await`.
fn current(slot: &SocketSlot) -> Arc<AsyncPacketSocket> {
    slot.read().unwrap_or_else(|e| e.into_inner()).clone()
}

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
    /// Async socket (None until started), replaced by a rebind.
    socket: Option<SocketSlot>,
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
    /// Effective payload MTU: interface MTU minus 3 bytes of frame header
    /// (`[type:1][length:2 LE][payload]`). The 2-byte length field is required
    /// to trim NIC minimum-frame padding before AEAD verification.
    effective_mtu: u16,
    /// Neighbor buffer for discovered peers.
    neighbor_buffer: Arc<NeighborBuffer>,
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
        let neighbor_buffer = Arc::new(NeighborBuffer::new(transport_id));
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
            neighbor_buffer,
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

        let (async_socket, local_mac, if_mtu) = open_bound(
            &self.config.interface,
            self.config.ethertype(),
            self.config.recv_buf_size(),
            self.config.send_buf_size(),
        )?;

        // Effective MTU: interface MTU minus 3 bytes for frame header
        // (1 byte frame type + 2 bytes LE payload length)
        let effective_mtu = if let Some(configured_mtu) = self.config.mtu {
            // Config MTU cannot exceed interface MTU - 3
            configured_mtu.min(if_mtu.saturating_sub(3))
        } else {
            if_mtu.saturating_sub(3)
        };
        self.effective_mtu = effective_mtu;
        self.local_mac = Some(local_mac);

        let socket: SocketSlot = Arc::new(RwLock::new(Arc::new(async_socket)));
        self.socket = Some(socket.clone());

        // Spawn receive loop
        let transport_id = self.transport_id;
        let packet_tx = self.packet_tx.clone();
        let mtu = self.effective_mtu;
        let listen_enabled = self.config.listen();
        let neighbor_buffer = self.neighbor_buffer.clone();
        let stats = self.stats.clone();
        let recv_socket = socket.clone();
        let rebind = Rebind {
            interface: self.config.interface.clone(),
            ethertype: self.config.ethertype(),
            recv_buf: self.config.recv_buf_size(),
            send_buf: self.config.send_buf_size(),
            mtu,
        };

        let recv_task = tokio::spawn(async move {
            ethernet_receive_loop(
                recv_socket,
                transport_id,
                packet_tx,
                listen_enabled,
                neighbor_buffer,
                stats,
                rebind,
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

        // Signal the socket to shut down. On macOS this writes to the
        // shutdown pipe, waking the reader thread's select() immediately.
        // On Linux this is a no-op (AsyncFd cancellation handles it).
        if let Some(ref slot) = self.socket {
            current(slot).shutdown();
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
        let socket = current(self.socket.as_ref().ok_or(TransportError::NotStarted)?);

        // Prepend frame type prefix and 2-byte LE payload length.
        // The length field lets the receiver trim Ethernet minimum-frame padding
        // (NICs pad frames shorter than 46 bytes payload to 46 bytes with zeros,
        // which would otherwise corrupt AEAD ciphertext verification).
        let mut frame = Vec::with_capacity(3 + data.len());
        frame.push(FRAME_TYPE_DATA);
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

        // Return the data bytes sent (excluding frame type prefix and length field)
        Ok(bytes_sent.saturating_sub(3))
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
        Ok(self.neighbor_buffer.take())
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

/// Why a received data frame was dropped by [`data_payload`].
///
/// Private and only logged at trace, so not a `thiserror` type.
#[derive(Debug, PartialEq, Eq)]
enum DataFrameError {
    /// Fewer bytes than the type byte and the length field.
    TooShort { len: usize },
    /// The length field names more payload than the frame carries.
    LengthExceeds {
        payload_len: usize,
        available: usize,
    },
}

/// Extract the payload of a received data frame.
///
/// `frame` is the received bytes including the type byte, which the caller
/// has already matched as `FRAME_TYPE_DATA`. The layout is
/// `[type:1][length:2 LE][payload:N][padding]`: the length field is what
/// trims Ethernet minimum-frame padding, which would otherwise be handed to
/// AEAD verification as ciphertext.
fn data_payload(frame: &[u8]) -> Result<&[u8], DataFrameError> {
    if frame.len() < 3 {
        return Err(DataFrameError::TooShort { len: frame.len() });
    }
    let payload_len = u16::from_le_bytes([frame[1], frame[2]]) as usize;
    let available = frame.len() - 3;
    if payload_len > available {
        return Err(DataFrameError::LengthExceeds {
            payload_len,
            available,
        });
    }
    Ok(&frame[3..3 + payload_len])
}

/// Open a socket bound to `interface`, with the configured buffer sizes,
/// returning it with the interface's MAC address and MTU.
fn open_bound(
    interface: &str,
    ethertype: u16,
    recv_buf: usize,
    send_buf: usize,
) -> Result<(AsyncPacketSocket, [u8; 6], u16), TransportError> {
    let raw_socket = PacketSocket::open(interface, ethertype)?;
    let local_mac = raw_socket.local_mac()?;
    let if_mtu = raw_socket.interface_mtu()?;
    raw_socket.set_recv_buffer_size(recv_buf)?;
    raw_socket.set_send_buffer_size(send_buf)?;
    Ok((raw_socket.into_async()?, local_mac, if_mtu))
}

/// What the receive loop needs to reopen its socket on a recreated
/// interface: the socket parameters `start_async` used, and the effective
/// MTU the transport advertises.
struct Rebind {
    interface: String,
    ethertype: u16,
    recv_buf: usize,
    send_buf: usize,
    mtu: u16,
}

impl Rebind {
    /// Reopen the socket in `slot` when the interface it is bound to was
    /// unregistered and is back: deleted and recreated, which gives it a new
    /// index, or moved to another namespace and returned, which can keep the
    /// index. The kernel unhooks the old socket either way, and on Linux
    /// then reports it bound to no index, so the two indices differ. Nothing
    /// happens while the interface is absent or the socket is still bound to
    /// it. A failed open is retried at the next check.
    fn check(&self, slot: &SocketSlot, socket: &AsyncPacketSocket, transport_id: TransportId) {
        let Some(index) = io::interface_index(&self.interface) else {
            return;
        };
        if i64::from(index) == i64::from(socket.get_ref().bound_index()) {
            return;
        }
        let (fresh, mac, if_mtu) = match open_bound(
            &self.interface,
            self.ethertype,
            self.recv_buf,
            self.send_buf,
        ) {
            Ok(opened) => opened,
            Err(e) => {
                warn!(
                    transport_id = %transport_id,
                    interface = %self.interface,
                    error = %e,
                    "Ethernet interface was recreated; reopening its socket failed, will retry"
                );
                return;
            }
        };
        *slot.write().unwrap_or_else(|e| e.into_inner()) = Arc::new(fresh);
        socket.shutdown();
        info!(
            transport_id = %transport_id,
            interface = %self.interface,
            index,
            mac = %format_mac(&mac),
            "Ethernet interface was recreated; socket rebound"
        );
        if if_mtu.saturating_sub(3) < self.mtu {
            warn!(
                transport_id = %transport_id,
                interface = %self.interface,
                if_mtu,
                mtu = self.mtu,
                "Recreated Ethernet interface has a smaller MTU than the transport advertises"
            );
        }
    }
}

/// Ethernet receive loop — runs as a spawned task.
///
/// Also the one owner of rebinding: every `REBIND_CHECK` it checks whether
/// the interface was recreated and, if so, replaces the socket every user of
/// the transport reads.
async fn ethernet_receive_loop(
    slot: SocketSlot,
    transport_id: TransportId,
    packet_tx: PacketTx,
    listen_enabled: bool,
    neighbor_buffer: Arc<NeighborBuffer>,
    stats: Arc<EthernetStats>,
    rebind: Rebind,
) {
    // Buffer with headroom: frame type prefix + MTU + some extra
    let mut buf = vec![0u8; rebind.mtu as usize + 100];
    let mut checks =
        tokio::time::interval_at(tokio::time::Instant::now() + REBIND_CHECK, REBIND_CHECK);
    checks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    debug!(transport_id = %transport_id, "Ethernet receive loop starting");

    loop {
        let socket = current(&slot);
        // recv_from is readiness-based, so dropping it for a check loses
        // no frame already read.
        let received = tokio::select! {
            received = socket.recv_from(&mut buf) => received,
            _ = checks.tick() => {
                rebind.check(&slot, &socket, transport_id);
                continue;
            }
        };
        match received {
            Ok((len, src_mac)) => {
                if len == 0 {
                    continue;
                }

                stats.record_recv(len);

                let frame_type = buf[0];
                match frame_type {
                    FRAME_TYPE_DATA => {
                        let data = match data_payload(&buf[..len]) {
                            Ok(payload) => payload.to_vec(),
                            Err(DataFrameError::TooShort { len }) => {
                                trace!("Data frame too short ({len} bytes), ignoring");
                                continue;
                            }
                            Err(DataFrameError::LengthExceeds {
                                payload_len,
                                available,
                            }) => {
                                trace!(
                                    "Data frame length field ({payload_len}) exceeds \
                                     available bytes ({available}), ignoring"
                                );
                                continue;
                            }
                        };
                        let bytes = data.len();
                        let addr = TransportAddr::from_mac(src_mac);
                        let packet = ReceivedPacket::new(transport_id, addr, data);

                        trace!(
                            transport_id = %transport_id,
                            remote_mac = %format_mac(&src_mac),
                            bytes,
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

                        if listen_enabled && let Some(pubkey) = parse_beacon(&buf[..len]) {
                            // `add_peer` reports whether the buffer took the
                            // beacon. It refuses once the distinct-MAC cap is
                            // reached, which is the bound on an unauthenticated
                            // broadcast frame naming a fresh MAC every time.
                            if !neighbor_buffer.add_peer(src_mac, pubkey) {
                                stats.record_beacon_dropped();
                            }
                            trace!(
                                transport_id = %transport_id,
                                remote_mac = %format_mac(&src_mac),
                                "Neighbor beacon received"
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
/// Sends on the transport's current socket each time, so after the receive
/// loop rebinds a recreated interface the next beacon goes out on it.
async fn beacon_sender_loop(
    slot: SocketSlot,
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
    if let Err(e) = current(&slot).send_to(&beacon, &ETHERNET_BROADCAST).await {
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

        match current(&slot).send_to(&beacon, &ETHERNET_BROADCAST).await {
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

                // Log only the first error in a streak to avoid log spam
                if consecutive_errors == 1 {
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "Failed to send beacon"
                    );
                }
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

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, target_os = "linux"))]
#[path = "tests/rebind.rs"]
mod rebind_tests;

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
        // Verify data frames have type prefix + 2-byte LE length + payload
        let data = vec![1, 2, 3, 4];
        let mut frame = Vec::with_capacity(3 + data.len());
        frame.push(FRAME_TYPE_DATA);
        frame.extend_from_slice(&(data.len() as u16).to_le_bytes());
        frame.extend_from_slice(&data);

        assert_eq!(frame[0], 0x00); // frame type
        assert_eq!(u16::from_le_bytes([frame[1], frame[2]]), 4); // length
        assert_eq!(&frame[3..], &[1, 2, 3, 4]); // payload
    }

    /// Build a data frame as the sender does: type, LE length, payload.
    fn data_frame(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(3 + payload.len());
        frame.push(FRAME_TYPE_DATA);
        frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn test_data_frame_padding_trimmed() {
        // Simulate Ethernet minimum-frame padding: a 4-byte payload produces
        // a 7-byte frame (type + len + payload), padded to 46 bytes by NIC.
        // Drives the receive loop's own parse, not a copy of it.
        let mut frame = data_frame(&[0xAA, 0xBB, 0xCC, 0xDD]);
        frame.resize(46, 0x00);

        assert_eq!(data_payload(&frame), Ok(&[0xAA, 0xBB, 0xCC, 0xDD][..]));
    }

    #[test]
    fn test_data_payload_unpadded_frame_returns_whole_payload() {
        let payload: Vec<u8> = (0..200).map(|i| i as u8).collect();
        let frame = data_frame(&payload);

        assert_eq!(data_payload(&frame), Ok(&payload[..]));
    }

    #[test]
    fn test_data_payload_zero_length_padded_frame_returns_empty() {
        let mut frame = data_frame(&[]);
        frame.resize(46, 0x00);

        assert_eq!(data_payload(&frame), Ok(&[][..]));
    }

    #[test]
    fn test_data_payload_frame_shorter_than_header_is_rejected() {
        assert_eq!(
            data_payload(&[FRAME_TYPE_DATA, 0x04]),
            Err(DataFrameError::TooShort { len: 2 })
        );
    }

    #[test]
    fn test_data_payload_length_field_beyond_received_bytes_is_rejected() {
        let mut frame = data_frame(&[0xAA, 0xBB, 0xCC, 0xDD]);
        frame.truncate(6);

        assert_eq!(
            data_payload(&frame),
            Err(DataFrameError::LengthExceeds {
                payload_len: 4,
                available: 3
            })
        );
    }

    #[test]
    fn test_beacon_size() {
        assert_eq!(neighbor::BEACON_SIZE, 34);
    }
}
