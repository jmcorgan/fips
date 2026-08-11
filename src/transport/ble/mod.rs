//! BLE L2CAP Transport Implementation
//!
//! Provides BLE-based transport for FIPS peer communication over L2CAP
//! Connection-Oriented Channels.
//!
//! ## Packet boundaries
//!
//! Message-boundary preservation is a property of the *socket type* a
//! backend uses, not of L2CAP. BlueZ's `SOCK_SEQPACKET` preserves SDU
//! boundaries; other backends expose an L2CAP channel as a byte stream and
//! may return a fragment of a packet or several packets coalesced from one
//! read. The receive path therefore recovers boundaries from the FMP length
//! prefix via [`stream_read::BleStreamRead`] and
//! [`crate::transport::framing::read_fmp_packet`], which is a transparent
//! pass-through on a boundary-preserving backend.
//!
//! ## Architecture
//!
//! Transport logic (pool, neighbor, lifecycle) is separated from the
//! BlueZ/bluer stack via the `BleIo` trait. `BluerIo` provides the real
//! implementation (behind `cfg(bluer_available)`); `MockBleIo` provides
//! an in-memory test double for CI without hardware.
//!
//! ## Connection Pool
//!
//! BLE hardware limits concurrent connections (typically 4-10). The pool
//! enforces a configurable maximum (default 7) with priority eviction:
//! static (configured) peers get priority over discovered peers.

pub mod addr;
pub mod io;
pub mod neighbor;
pub mod pool;
pub mod stats;
pub mod stream_read;

use super::framing::{StreamError, read_fmp_packet};
use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::BleConfig;
use crate::identity::NodeAddr;
use addr::BleAddr;
use io::{BleIo, BleScanner, BleStream};
use neighbor::NeighborBuffer;
use pool::{BleConnection, ConnectionPool};
use stats::BleStats;
use stream_read::BleStreamRead;

use secp256k1::XOnlyPublicKey;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::AsyncReadExt;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

/// Default FIPS L2CAP PSM (Protocol Service Multiplexer).
///
/// 0x0085 (133) is in the dynamic range (0x0080-0x00FF).
pub const DEFAULT_PSM: u16 = 0x0085;

/// Concrete BLE transport type for use in TransportHandle.
///
/// Production builds on glibc-linux use `BluerIo` (real BlueZ stack).
/// Test builds, musl-linux, and non-Linux platforms use `MockBleIo`.
#[cfg(all(bluer_available, not(test)))]
pub type DefaultBleTransport = BleTransport<io::BluerIo>;

#[cfg(any(not(bluer_available), test))]
pub type DefaultBleTransport = BleTransport<io::MockBleIo>;

// ============================================================================
// BLE Transport
// ============================================================================

/// BLE transport for FIPS.
///
/// Provides connection-oriented, reliable delivery over BLE L2CAP CoC.
/// Each peer has its own L2CAP connection; the pool enforces hardware
/// connection limits with priority eviction.
pub struct BleTransport<I: BleIo> {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name.
    name: Option<String>,
    /// Configuration.
    config: BleConfig,
    /// Current state.
    state: TransportState,
    /// BLE I/O implementation (BluerIo or MockBleIo).
    io: Arc<I>,
    /// Established connection pool.
    pool: Arc<Mutex<ConnectionPool<Arc<I::Stream>>>>,
    /// Pending connection attempts.
    connecting: Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Accept loop task handle.
    accept_task: Option<JoinHandle<()>>,
    /// Combined scan + probe loop task handle.
    scan_probe_task: Option<JoinHandle<()>>,
    /// Neighbor buffer for discovered peers.
    neighbor_buffer: Arc<NeighborBuffer>,
    /// Transport statistics.
    stats: Arc<BleStats>,
    /// Our public key for pre-handshake identity exchange.
    ///
    /// BLE advertisements carry only the FIPS UUID, not the pubkey.
    /// After L2CAP connection, both sides exchange `[0x00][pubkey:32]`
    /// so the node layer can initiate the IK handshake.
    /// Temporary — removed when FMP switches to XX.
    local_pubkey: Option<[u8; 32]>,
}

/// A pending background connection attempt.
struct ConnectingEntry {
    task: JoinHandle<()>,
}

impl<I: BleIo> BleTransport<I> {
    /// Create a new BLE transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: BleConfig,
        io: I,
        packet_tx: PacketTx,
    ) -> Self {
        let max_conns = config.max_connections();
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            io: Arc::new(io),
            pool: Arc::new(Mutex::new(ConnectionPool::new(max_conns))),
            connecting: Arc::new(Mutex::new(HashMap::new())),
            packet_tx,
            accept_task: None,
            scan_probe_task: None,
            neighbor_buffer: Arc::new(NeighborBuffer::new(transport_id)),
            stats: Arc::new(BleStats::new()),
            local_pubkey: None,
        }
    }

    /// Get the instance name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<BleStats> {
        &self.stats
    }

    /// Get the I/O implementation (for test injection).
    pub fn io(&self) -> &Arc<I> {
        &self.io
    }

    /// Set the local public key for pre-handshake identity exchange.
    ///
    /// Must be called before `start_async()`. Without this, BLE
    /// connections skip the pubkey exchange and discovered peers
    /// won't have identity information for auto-connect.
    pub fn set_local_pubkey(&mut self, pubkey: [u8; 32]) {
        self.local_pubkey = Some(pubkey);
    }

    /// Start the transport asynchronously.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Starting;

        let psm = self.config.psm();
        let adapter = self.io.adapter_name().to_string();

        // Pre-compute local NodeAddr for cross-probe tie-breaking
        let local_node_addr = self.local_pubkey.and_then(|pk| {
            XOnlyPublicKey::from_slice(&pk)
                .ok()
                .map(|xonly| NodeAddr::from_pubkey(&xonly))
        });

        // Start L2CAP listener for inbound connections
        if self.config.accept_connections() {
            match self.io.listen(psm).await {
                Ok(acceptor) => {
                    let pool = Arc::clone(&self.pool);
                    let packet_tx = self.packet_tx.clone();
                    let transport_id = self.transport_id;
                    let stats = Arc::clone(&self.stats);
                    let max_conns = self.config.max_connections();

                    self.accept_task = Some(tokio::spawn(accept_loop(
                        acceptor,
                        pool,
                        packet_tx,
                        transport_id,
                        stats,
                        max_conns,
                        self.local_pubkey,
                        Arc::clone(&self.neighbor_buffer),
                        local_node_addr,
                    )));
                    debug!(adapter = %adapter, psm = psm, "BLE accept loop started");
                }
                Err(e) => {
                    warn!(adapter = %adapter, error = %e, "failed to start BLE listener");
                    self.state = TransportState::Failed;
                    return Err(e);
                }
            }
        }

        // Start continuous advertising
        if self.config.advertise() {
            if let Err(e) = self.io.start_advertising().await {
                warn!(adapter = %adapter, error = %e, "failed to start BLE advertising");
            } else {
                self.stats.record_advertisement();
                debug!(adapter = %adapter, "BLE advertising started (continuous)");
            }
        }

        // Start combined scan + probe loop
        if self.config.scan() {
            match self.io.start_scanning().await {
                Ok(scanner) => {
                    self.scan_probe_task = Some(tokio::spawn(scan_probe_loop::<I>(
                        scanner,
                        Arc::clone(&self.io),
                        Arc::clone(&self.pool),
                        Arc::clone(&self.neighbor_buffer),
                        Arc::clone(&self.stats),
                        self.local_pubkey,
                        self.config.psm(),
                        self.config.connect_timeout_ms(),
                        self.config.probe_cooldown_secs(),
                        local_node_addr,
                        self.packet_tx.clone(),
                        self.transport_id,
                    )));
                    debug!(adapter = %adapter, "BLE scan+probe loop started");
                }
                Err(e) => {
                    warn!(adapter = %adapter, error = %e, "failed to start BLE scanning");
                }
            }
        }

        self.state = TransportState::Up;
        info!(adapter = %adapter, psm = psm, "BLE transport started");
        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        // Stop advertising
        let _ = self.io.stop_advertising().await;

        // Abort accept loop
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }

        // Abort scan+probe loop
        if let Some(task) = self.scan_probe_task.take() {
            task.abort();
        }

        // Drain connecting pool
        {
            let mut connecting = self.connecting.lock().await;
            for (_, entry) in connecting.drain() {
                entry.task.abort();
            }
        }

        // Drain established connections (recv tasks aborted via Drop)
        {
            let mut pool = self.pool.lock().await;
            for addr in pool.addrs() {
                pool.remove(&addr);
            }
        }

        self.state = TransportState::Down;
        info!("BLE transport stopped");
        Ok(())
    }

    /// Send data to a remote BLE address.
    ///
    /// If no connection exists, triggers a background connect and fails
    /// fast. The next send retry (typically 1s later for handshake msg1)
    /// will find the connection established. This avoids blocking the
    /// event loop on L2CAP connect (up to 10s).
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        let pool = self.pool.lock().await;
        let conn = match pool.get(addr) {
            Some(c) => c,
            None => {
                // Drop pool lock before triggering background connect
                drop(pool);
                // Fire-and-forget: connect_async spawns a background task
                let _ = self.connect_async(addr).await;
                return Err(TransportError::SendFailed("not connected".into()));
            }
        };

        // MTU check
        let mtu = conn.effective_mtu() as usize;
        if data.len() > mtu {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: mtu as u16,
            });
        }

        match conn.stream.send(data).await {
            Ok(()) => {
                self.stats.record_send(data.len());
                Ok(data.len())
            }
            Err(e) => {
                self.stats.record_send_error();
                // Drop pool lock before removing to avoid deadlock
                drop(pool);
                let mut pool = self.pool.lock().await;
                pool.remove(addr);
                warn!(addr = %addr, error = %e, "BLE send failed, connection removed");
                Err(e)
            }
        }
    }

    /// Connect to a remote BLE device inline (blocking the caller).
    ///
    /// Not used in normal operation (send_async fails fast instead).
    /// Retained for manual debugging / testing scenarios.
    #[allow(dead_code)]
    async fn connect_inline(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        let ble_addr = BleAddr::parse(
            addr.as_str()
                .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?,
        )?;

        let psm = self.config.psm();
        let timeout_ms = self.config.connect_timeout_ms();

        let stream = match tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms),
            self.io.connect(&ble_addr, psm),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                debug!(addr = %addr, error = %e, "BLE connect-on-send failed");
                return Err(TransportError::ConnectionRefused);
            }
            Err(_) => {
                self.stats.record_connect_timeout();
                debug!(addr = %addr, "BLE connect-on-send timeout");
                return Err(TransportError::Timeout);
            }
        };

        // One reader for the life of the connection: the pubkey exchange and
        // the receive loop must share it, or bytes the peer coalesced behind
        // the exchange are dropped at the hand-off.
        let stream = Arc::new(stream);
        let recv_mtu = stream.recv_mtu();
        let mut reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

        // Pre-handshake pubkey exchange (temporary, pre-XX)
        let mut peer_node: Option<NodeAddr> = None;
        if let Some(ref our_pubkey) = self.local_pubkey {
            match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
                Ok(peer_pubkey) => {
                    debug!(addr = %addr, "BLE outbound pubkey exchange complete");
                    let node = NodeAddr::from_pubkey(&peer_pubkey);
                    peer_node = Some(node);
                    let announced = announced_addr(&self.pool, &node, &ble_addr).await;
                    self.neighbor_buffer
                        .add_peer_with_pubkey(&announced, peer_pubkey);
                }
                Err(e) => {
                    warn!(addr = %addr, error = %e, "BLE outbound pubkey exchange failed");
                    return Err(e);
                }
            }
        }

        self.promote_connection(addr, &ble_addr, stream, reader, peer_node)
            .await
    }

    /// Promote a newly established stream into the connection pool.
    ///
    /// Spawns the receive loop and inserts into the pool with eviction.
    async fn promote_connection(
        &self,
        addr: &TransportAddr,
        ble_addr: &BleAddr,
        stream: Arc<I::Stream>,
        reader: BleStreamRead<I::Stream>,
        node_addr: Option<NodeAddr>,
    ) -> Result<(), TransportError> {
        let send_mtu = stream.send_mtu();
        let recv_mtu = stream.recv_mtu();

        let recv_task = tokio::spawn(receive_loop(
            reader,
            addr.clone(),
            Arc::clone(&self.pool),
            self.packet_tx.clone(),
            self.transport_id,
            Arc::clone(&self.stats),
            recv_mtu,
        ));

        let conn = BleConnection {
            stream,
            recv_task: Some(recv_task),
            send_mtu,
            recv_mtu,
            established_at: tokio::time::Instant::now(),
            is_static: false,
            addr: ble_addr.clone(),
            node_addr,
        };

        let mut pool = self.pool.lock().await;
        match pool.insert(addr.clone(), conn) {
            Ok(Some(evicted)) => {
                self.stats.record_pool_eviction();
                debug!(addr = %addr, evicted = %evicted, "BLE connection established (evicted peer)");
            }
            Ok(None) => {
                debug!(addr = %addr, "BLE connection established");
            }
            Err(e) => {
                warn!(addr = %addr, error = %e, "BLE pool full, connection dropped");
                self.stats.record_connection_rejected();
                return Err(TransportError::SendFailed("pool full".into()));
            }
        }
        self.stats.record_connection_established();
        Ok(())
    }

    /// Initiate a non-blocking connection to a remote BLE device.
    ///
    /// Spawns a background task that connects with timeout and promotes
    /// to the pool on success. Poll `connection_state_sync()` to check.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        // Already connected?
        {
            let pool = self.pool.lock().await;
            if pool.contains(addr) {
                return Ok(());
            }
        }

        // Already connecting?
        {
            let connecting = self.connecting.lock().await;
            if connecting.contains_key(addr) {
                return Ok(());
            }
        }

        let ble_addr = BleAddr::parse(
            addr.as_str()
                .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?,
        )?;

        let io = Arc::clone(&self.io);
        let pool = Arc::clone(&self.pool);
        let connecting = Arc::clone(&self.connecting);
        let packet_tx = self.packet_tx.clone();
        let transport_id = self.transport_id;
        let stats = Arc::clone(&self.stats);
        let psm = self.config.psm();
        let timeout_ms = self.config.connect_timeout_ms();
        let addr_clone = addr.clone();
        let local_pubkey = self.local_pubkey;
        let neighbor_buffer = Arc::clone(&self.neighbor_buffer);

        let task = tokio::spawn(async move {
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                io.connect(&ble_addr, psm),
            )
            .await;

            // Remove from connecting pool
            connecting.lock().await.remove(&addr_clone);

            match result {
                Ok(Ok(stream)) => {
                    let send_mtu = stream.send_mtu();
                    let recv_mtu = stream.recv_mtu();
                    let stream = Arc::new(stream);
                    // One reader across both phases — see `pubkey_exchange`.
                    let mut reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

                    // Pre-handshake pubkey exchange (temporary, pre-XX)
                    let mut peer_node: Option<NodeAddr> = None;
                    if let Some(ref our_pubkey) = local_pubkey {
                        match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
                            Ok(peer_pubkey) => {
                                debug!(addr = %addr_clone, "BLE outbound pubkey exchange complete");
                                let node = NodeAddr::from_pubkey(&peer_pubkey);
                                peer_node = Some(node);
                                let announced = announced_addr(&pool, &node, &ble_addr).await;
                                neighbor_buffer.add_peer_with_pubkey(&announced, peer_pubkey);
                            }
                            Err(e) => {
                                warn!(
                                    addr = %addr_clone, error = %e,
                                    "BLE outbound pubkey exchange failed"
                                );
                                return;
                            }
                        }
                    }

                    let recv_task = tokio::spawn(receive_loop(
                        reader,
                        addr_clone.clone(),
                        Arc::clone(&pool),
                        packet_tx,
                        transport_id,
                        Arc::clone(&stats),
                        recv_mtu,
                    ));

                    let conn = BleConnection {
                        stream,
                        recv_task: Some(recv_task),
                        send_mtu,
                        recv_mtu,
                        established_at: tokio::time::Instant::now(),
                        is_static: false,
                        addr: ble_addr,
                        node_addr: peer_node,
                    };

                    let mut pool = pool.lock().await;
                    match pool.insert(addr_clone.clone(), conn) {
                        Ok(Some(evicted)) => {
                            stats.record_pool_eviction();
                            debug!(addr = %addr_clone, evicted = %evicted, "BLE connection established (evicted peer)");
                        }
                        Ok(None) => {
                            debug!(addr = %addr_clone, "BLE connection established");
                        }
                        Err(e) => {
                            warn!(addr = %addr_clone, error = %e, "BLE pool full, connection dropped");
                            stats.record_connection_rejected();
                            return;
                        }
                    }
                    stats.record_connection_established();
                }
                Ok(Err(e)) => {
                    debug!(addr = %addr_clone, error = %e, "BLE connect failed");
                }
                Err(_) => {
                    stats.record_connect_timeout();
                    debug!(addr = %addr_clone, "BLE connect timeout");
                }
            }
        });

        self.connecting
            .lock()
            .await
            .insert(addr.clone(), ConnectingEntry { task });

        Ok(())
    }

    /// Query the state of a connection attempt.
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        // Check established pool (try_lock to avoid blocking)
        if let Ok(pool) = self.pool.try_lock()
            && pool.contains(addr)
        {
            return ConnectionState::Connected;
        }

        // Check connecting pool
        if let Ok(connecting) = self.connecting.try_lock()
            && connecting.contains_key(addr)
        {
            return ConnectionState::Connecting;
        }

        ConnectionState::None
    }

    /// Close a specific connection.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut pool = self.pool.lock().await;
        if let Some(conn) = pool.remove(addr) {
            debug!(addr = %addr, "BLE connection closed");
            drop(conn); // recv_task aborted via Drop
        }
    }

    /// Get the link MTU for a specific address.
    pub fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        if let Ok(pool) = self.pool.try_lock()
            && let Some(conn) = pool.get(addr)
        {
            return conn.effective_mtu();
        }
        self.config.mtu()
    }
}

impl<I: BleIo> Transport for BleTransport<I> {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::BLE
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        self.link_mtu(addr)
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for BLE transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for BLE transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for BLE transport".into(),
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

    fn close_connection(&self, _addr: &TransportAddr) {
        // use close_connection_async()
    }
}

// ============================================================================
// Background Tasks
// ============================================================================

/// Pre-handshake pubkey exchange prefix byte.
///
/// Distinguishes the identity exchange from FMP packets (version ≥ 0x01).
/// Temporary — removed when FMP switches from IK to XX handshake.
///
/// Caution: this prefix is *not* distinguishable from an FMP packet by the
/// framer. `0x00` decodes as FMP version 0, phase 0 (established), with a
/// payload length read out of the pubkey's own bytes — i.e. arbitrary. Any
/// code that runs the framer over a connection before the exchange has been
/// fully consumed will mis-frame badly. Threading one reader through both
/// phases is what guarantees the ordering.
const PUBKEY_EXCHANGE_PREFIX: u8 = 0x00;

/// Pre-handshake pubkey exchange message size: `[0x00][pubkey:32]`.
const PUBKEY_EXCHANGE_SIZE: usize = 33;

/// Timeout for pubkey exchange recv (seconds).
///
/// The peer should respond in milliseconds; 5s is generous. Without this,
/// a peer that connects but never sends its pubkey blocks the calling task
/// forever — killing scan_probe_loop, accept_loop, or the event loop.
const PUBKEY_EXCHANGE_TIMEOUT_SECS: u64 = 5;

/// The link address a completed pubkey exchange should be announced under.
///
/// A peer using resolvable private addresses presents a different link
/// address on every rotation, so the address an exchange happened on is a
/// transient alias for the peer, not a durable way to name it. Announcing the
/// alias makes a consumer that compares addresses treat it as a *new path* to
/// a peer it is already connected to and dial it; the duplicate is declined
/// here, so it never reaches the pool, so nothing upstream remembers the
/// conclusion and the next discovery round pays the same connect and exchange
/// again. `scan_probe_loop` breaks that cycle for its own probes, but callers
/// that reach `connect_async` directly never consult it.
///
/// So when the peer is already connected, report the address its link is
/// actually on: same peer, named by the address that works. When it is not,
/// there is no incumbent and the observed address stands.
///
/// Canonicalising rather than withholding matters: suppressing the
/// announcement would also stop the peer being offered at all, and consumers
/// legitimately re-probe a peer whose link has gone idle to recover it.
async fn announced_addr<S>(
    pool: &Mutex<ConnectionPool<S>>,
    node: &NodeAddr,
    observed: &BleAddr,
) -> BleAddr {
    pool.lock()
        .await
        .live_addr_of_node(node)
        .unwrap_or_else(|| observed.clone())
}

/// Exchange public keys over a newly established L2CAP connection.
///
/// Both sides send `[0x00][our_pubkey:32]` and receive the peer's.
/// Returns the peer's XOnlyPublicKey on success.
///
/// Reads through the connection's `BleStreamRead` rather than calling
/// `recv` directly, for two reasons. It reassembles an exchange a
/// stream-oriented backend fragmented, which a single `recv` with an
/// exact-length check can never do. And anything the peer coalesced behind
/// the exchange stays buffered in the reader that the receive loop then
/// takes over, instead of being discarded at the hand-off.
async fn pubkey_exchange<S: BleStream + 'static>(
    stream: &S,
    reader: &mut BleStreamRead<S>,
    local_pubkey: &[u8; 32],
) -> Result<XOnlyPublicKey, TransportError> {
    // Send our pubkey
    let mut msg = [0u8; PUBKEY_EXCHANGE_SIZE];
    msg[0] = PUBKEY_EXCHANGE_PREFIX;
    msg[1..].copy_from_slice(local_pubkey);
    stream.send(&msg).await?;

    // Receive peer's pubkey (with timeout to prevent indefinite blocking)
    let mut buf = [0u8; PUBKEY_EXCHANGE_SIZE];
    let timeout = std::time::Duration::from_secs(PUBKEY_EXCHANGE_TIMEOUT_SECS);
    match tokio::time::timeout(timeout, reader.read_exact(&mut buf)).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return Err(TransportError::RecvFailed(format!(
                "pubkey exchange: {}",
                e
            )));
        }
        Err(_) => return Err(TransportError::Timeout),
    }
    if buf[0] != PUBKEY_EXCHANGE_PREFIX {
        return Err(TransportError::RecvFailed(format!(
            "pubkey exchange: bad prefix 0x{:02X}",
            buf[0]
        )));
    }

    XOnlyPublicKey::from_slice(&buf[1..])
        .map_err(|e| TransportError::RecvFailed(format!("pubkey exchange: invalid key: {}", e)))
}

// Beacon loop removed — advertising is now continuous (started once
// in start_async, stopped in stop_async). BLE advertising overhead
// is negligible (~0.15% duty cycle on advertising channels).

/// Accept loop: accepts inbound L2CAP connections, exchanges pubkeys,
/// and adds to pool.
#[allow(clippy::too_many_arguments)]
async fn accept_loop<A>(
    mut acceptor: A,
    pool: Arc<Mutex<ConnectionPool<Arc<A::Stream>>>>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: Arc<BleStats>,
    _max_conns: usize,
    local_pubkey: Option<[u8; 32]>,
    neighbor_buffer: Arc<NeighborBuffer>,
    local_node_addr: Option<NodeAddr>,
) where
    A: io::BleAcceptor,
    A::Stream: 'static,
{
    loop {
        match acceptor.accept().await {
            Ok(stream) => {
                let addr = stream.remote_addr().clone();
                let ta = addr.to_transport_addr();

                // Skip if already connected (outbound won the race)
                {
                    let pool_guard = pool.lock().await;
                    if pool_guard.contains(&ta) {
                        debug!(addr = %ta, "BLE inbound: already connected, skipping");
                        continue;
                    }
                }

                let send_mtu = stream.send_mtu();
                let recv_mtu = stream.recv_mtu();
                let stream = Arc::new(stream);
                // One reader across both phases — see `pubkey_exchange`.
                let mut reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

                // Pre-handshake pubkey exchange (temporary, pre-XX)
                let mut peer_node_addr: Option<NodeAddr> = None;
                if let Some(ref our_pubkey) = local_pubkey {
                    match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
                        Ok(peer_pubkey) => {
                            debug!(addr = %ta, "BLE inbound pubkey exchange complete");
                            let peer_node = NodeAddr::from_pubkey(&peer_pubkey);
                            peer_node_addr = Some(peer_node);
                            let announced = announced_addr(&pool, &peer_node, &addr).await;
                            neighbor_buffer.add_peer_with_pubkey(&announced, peer_pubkey);

                            // Already linked to this peer on another address?
                            // A peer using resolvable private addresses rotates
                            // continually, and every rotation dials in looking
                            // like a new device. Admitting those would put one
                            // peer in several pool slots and evict real ones.
                            // The incumbent link is kept: it is known-good, and
                            // a genuinely dead one is already reaped by the
                            // send-error and receive-loop paths.
                            let dup = {
                                let pool_guard = pool.lock().await;
                                pool_guard.find_by_node(&peer_node)
                            };
                            if let Some(existing) = dup
                                && existing != ta
                            {
                                debug!(
                                    addr = %ta,
                                    existing = %existing,
                                    "BLE inbound: peer already connected on another address, dropping duplicate"
                                );
                                stats.record_duplicate_node_decline();
                                continue;
                            }

                            // Cross-probe tie-breaker: smaller NodeAddr's
                            // outbound wins. If we're smaller, our outbound
                            // should win — drop this inbound.
                            if let Some(ref our_addr) = local_node_addr
                                && our_addr < &peer_node
                            {
                                debug!(
                                    addr = %ta,
                                    "BLE inbound tie-breaker: dropping (our addr < peer, outbound wins)"
                                );
                                continue;
                            }
                        }
                        Err(e) => {
                            debug!(addr = %ta, error = %e, "BLE inbound pubkey exchange failed");
                            continue;
                        }
                    }
                }

                // Spawn receive loop
                let recv_task = tokio::spawn(receive_loop(
                    reader,
                    ta.clone(),
                    Arc::clone(&pool),
                    packet_tx.clone(),
                    transport_id,
                    Arc::clone(&stats),
                    recv_mtu,
                ));

                let conn = BleConnection {
                    stream,
                    recv_task: Some(recv_task),
                    send_mtu,
                    recv_mtu,
                    established_at: tokio::time::Instant::now(),
                    is_static: false,
                    addr,
                    node_addr: peer_node_addr,
                };

                let mut pool_guard = pool.lock().await;
                match pool_guard.insert(ta.clone(), conn) {
                    Ok(Some(evicted)) => {
                        stats.record_pool_eviction();
                        info!(addr = %ta, evicted = %evicted, "BLE inbound accepted (evicted peer)");
                    }
                    Ok(None) => {
                        info!(addr = %ta, send_mtu, recv_mtu, "BLE inbound connection accepted");
                    }
                    Err(e) => {
                        warn!(addr = %ta, error = %e, "BLE pool full, inbound connection rejected");
                        stats.record_connection_rejected();
                        continue;
                    }
                }
                stats.record_connection_accepted();
            }
            Err(e) => {
                warn!(error = %e, "BLE accept error");
                break;
            }
        }
    }
}

/// Receive loop: reads packets from a BLE stream and delivers to node.
///
/// Takes the connection's `BleStreamRead` — already positioned past the
/// pubkey exchange, and still holding anything the peer coalesced behind it
/// — and pulls whole FIPS packets out of it using the FMP length prefix.
/// Boundaries come from the bytes, not from the backend's socket type, so a
/// fragment is reassembled and a coalesced tail is not lost.
async fn receive_loop<S: BleStream + 'static>(
    mut reader: BleStreamRead<S>,
    addr: TransportAddr,
    pool: Arc<Mutex<ConnectionPool<Arc<S>>>>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: Arc<BleStats>,
    recv_mtu: u16,
) {
    loop {
        match read_fmp_packet(&mut reader, recv_mtu).await {
            Ok(data) => {
                stats.record_recv(data.len());
                let packet = ReceivedPacket::new(transport_id, addr.clone(), data);
                if packet_tx.send(packet).await.is_err() {
                    trace!("BLE packet_tx closed, stopping receive loop");
                    break;
                }
            }
            Err(StreamError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                debug!(addr = %addr, "BLE connection closed by peer");
                break;
            }
            Err(e) => {
                debug!(addr = %addr, error = %e, "BLE receive error");
                stats.record_recv_error();
                break;
            }
        }
    }

    // Remove from pool
    let mut pool = pool.lock().await;
    pool.remove(&addr);
}

/// Combined scan + probe loop.
///
/// Scanner events arrive continuously (both sides advertise continuously).
/// Each scan result is probed immediately unless the address is in cooldown
/// (recently probed) or already connected. On successful probe, the
/// connection is promoted directly into the pool (no second L2CAP connect
/// needed) and the peer is reported to the neighbor buffer for the node
/// layer to auto-connect.
///
/// Cooldown prevents rapid re-probing of the same address: after any probe
/// attempt (success or failure), the address is suppressed for
/// `cooldown_secs`. Connected peers are filtered by pool membership.
#[allow(clippy::too_many_arguments)]
async fn scan_probe_loop<I: io::BleIo>(
    mut scanner: I::Scanner,
    io: Arc<I>,
    pool: Arc<Mutex<ConnectionPool<Arc<I::Stream>>>>,
    buffer: Arc<NeighborBuffer>,
    stats: Arc<BleStats>,
    local_pubkey: Option<[u8; 32]>,
    psm: u16,
    connect_timeout_ms: u64,
    cooldown_secs: u64,
    local_node_addr: Option<NodeAddr>,
    packet_tx: PacketTx,
    transport_id: TransportId,
) {
    // Track last probe time per address for cooldown
    let mut last_probed: HashMap<BleAddr, tokio::time::Instant> = HashMap::new();
    // Addresses discovered but not yet connected — retried after cooldown
    // even if the scanner doesn't fire again (BlueZ deduplicates).
    let mut pending_addrs: Vec<BleAddr> = Vec::new();
    // Link addresses already resolved to a node identity by a completed pubkey
    // exchange. Lets the loop skip an address it has *already* learned belongs
    // to a peer it is connected to, instead of paying a full connect and
    // exchange to rediscover that every cooldown. Rotation means this grows by
    // one per rotation, so entries are dropped once their node is no longer in
    // the pool — a peer that genuinely goes away is probed again normally.
    let mut known_node_of: HashMap<BleAddr, NodeAddr> = HashMap::new();
    let cooldown = std::time::Duration::from_secs(cooldown_secs);
    let retry_interval = tokio::time::interval(std::time::Duration::from_secs(cooldown_secs));
    tokio::pin!(retry_interval);
    retry_interval.tick().await; // consume initial tick

    loop {
        // Either a scanner event or the retry timer fires
        let addr = tokio::select! {
            result = scanner.next() => {
                match result {
                    Some(a) => a,
                    None => {
                        debug!("BLE scanner ended");
                        break;
                    }
                }
            }
            _ = retry_interval.tick() => {
                // Re-probe pending addresses that aren't connected
                let pool_guard = pool.lock().await;
                pending_addrs.retain(|a| !pool_guard.contains(&a.to_transport_addr()));
                drop(pool_guard);
                if let Some(a) = pending_addrs.first().cloned() {
                    a
                } else {
                    continue;
                }
            }
        };

        trace!(addr = %addr, "BLE scan result");
        stats.record_scan_result();

        // Skip if already connected
        {
            let pool_guard = pool.lock().await;
            if pool_guard.contains(&addr.to_transport_addr()) {
                pending_addrs.retain(|a| a != &addr);
                continue;
            }
        }

        // Track for retry in case probe fails and scanner doesn't re-fire
        if !pending_addrs.contains(&addr) {
            pending_addrs.push(addr.clone());
        }

        // Skip if in cooldown
        if last_probed
            .get(&addr)
            .is_some_and(|last| last.elapsed() < cooldown)
        {
            continue;
        }

        // Skip an address already known to belong to a peer we are connected
        // to. Without this the loop re-dials every rotated address of a live
        // peer once per cooldown, forever: the duplicate is declined so it
        // never enters the pool, so the pool-keyed guard above never sees it.
        if let Some(node) = known_node_of.get(&addr) {
            let still_connected = {
                let pool_guard = pool.lock().await;
                pool_guard.find_by_node(node).is_some()
            };
            if still_connected {
                pending_addrs.retain(|a| a != &addr);
                continue;
            }
            // That peer is gone — forget the mapping and probe normally.
            known_node_of.remove(&addr);
        }

        // Record probe time (before attempt, so cooldown applies on failure too)
        last_probed.insert(addr.clone(), tokio::time::Instant::now());

        // Need pubkey for probe
        let our_pubkey = match local_pubkey {
            Some(pk) => pk,
            None => {
                buffer.add_peer(&addr);
                continue;
            }
        };

        // L2CAP connect
        let stream = match tokio::time::timeout(
            std::time::Duration::from_millis(connect_timeout_ms),
            io.connect(&addr, psm),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                debug!(addr = %addr, error = %e, "BLE probe connect failed");
                continue;
            }
            Err(_) => {
                debug!(addr = %addr, "BLE probe connect timeout");
                stats.record_connect_timeout();
                continue;
            }
        };

        // Pubkey exchange, then promote connection to pool
        let ta = addr.to_transport_addr();
        let send_mtu = stream.send_mtu();
        let recv_mtu = stream.recv_mtu();
        let stream = Arc::new(stream);
        // One reader across both phases — see `pubkey_exchange`.
        let mut reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);
        match pubkey_exchange(stream.as_ref(), &mut reader, &our_pubkey).await {
            Ok(peer_pubkey) => {
                debug!(addr = %addr, "BLE probe complete");
                let peer_node = NodeAddr::from_pubkey(&peer_pubkey);

                // Cross-probe tie-breaker: smaller NodeAddr's outbound wins.
                // If we lose, drop connection — accept_loop handles inbound.
                if let Some(ref our_addr) = local_node_addr
                    && our_addr >= &peer_node
                {
                    debug!(
                        addr = %addr,
                        "BLE probe tie-breaker: yielding to peer's outbound"
                    );
                    let announced = announced_addr(&pool, &peer_node, &addr).await;
                    buffer.add_peer_with_pubkey(&announced, peer_pubkey);
                    continue;
                }

                // Same duplicate guard as the inbound path: a rotated address
                // for a peer we already hold a link to must not become a
                // second pool entry. Checked after the tie-breaker so the two
                // decisions stay independent.
                let dup = {
                    let pool_guard = pool.lock().await;
                    pool_guard.find_by_node(&peer_node)
                };
                if let Some(existing) = dup
                    && existing != ta
                {
                    debug!(
                        addr = %ta,
                        existing = %existing,
                        "BLE probe: peer already connected on another address, dropping duplicate"
                    );
                    stats.record_duplicate_node_decline();
                    // Remember what this address resolved to, so the next
                    // cooldown skips it outright rather than paying another
                    // connect and exchange to reach the same conclusion.
                    known_node_of.insert(addr.clone(), peer_node);
                    // Report the peer under the address its live link is on,
                    // so the node layer is not handed an alias with no
                    // connection behind it.
                    let announced = announced_addr(&pool, &peer_node, &addr).await;
                    buffer.add_peer_with_pubkey(&announced, peer_pubkey);
                    pending_addrs.retain(|a| a != &addr);
                    continue;
                }

                // Promote connection to pool — no second L2CAP connect needed
                let recv_task = tokio::spawn(receive_loop(
                    reader,
                    ta.clone(),
                    Arc::clone(&pool),
                    packet_tx.clone(),
                    transport_id,
                    Arc::clone(&stats),
                    recv_mtu,
                ));

                let conn = BleConnection {
                    stream,
                    recv_task: Some(recv_task),
                    send_mtu,
                    recv_mtu,
                    established_at: tokio::time::Instant::now(),
                    is_static: false,
                    addr: addr.clone(),
                    node_addr: Some(peer_node),
                };

                let mut pool_guard = pool.lock().await;
                match pool_guard.insert(ta.clone(), conn) {
                    Ok(Some(evicted)) => {
                        stats.record_pool_eviction();
                        debug!(addr = %ta, evicted = %evicted, "BLE probe promoted (evicted peer)");
                    }
                    Ok(None) => {
                        debug!(addr = %ta, "BLE probe promoted to pool");
                    }
                    Err(e) => {
                        warn!(addr = %ta, error = %e, "BLE pool full, probe connection dropped");
                        stats.record_connection_rejected();
                    }
                }
                drop(pool_guard);
                stats.record_connection_established();
                pending_addrs.retain(|a| a != &addr);

                // Report to node layer for auto-connect / handshake
                buffer.add_peer_with_pubkey(&addr, peer_pubkey);
            }
            Err(e) => {
                debug!(addr = %addr, error = %e, "BLE probe pubkey exchange failed");
            }
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::framing::build_established_frame;
    use io::{MockBleIo, MockBleStream};
    use secp256k1::{Secp256k1, SecretKey};

    /// Deterministic x-only pubkey for exchange tests.
    fn test_pubkey(seed: u8) -> [u8; 32] {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        sk.public_key(&secp).x_only_public_key().0.serialize()
    }

    /// Handles a receive-loop test needs to observe: the task, the packets
    /// it delivers, and the pool it reaps its entry from.
    type ReceiveLoopHarness = (
        JoinHandle<()>,
        tokio::sync::mpsc::Receiver<ReceivedPacket>,
        Arc<Mutex<ConnectionPool<Arc<MockBleStream>>>>,
    );

    /// Wire up a receive loop over one end of a mock stream pair.
    fn spawn_receive_loop(local: MockBleStream) -> ReceiveLoopHarness {
        let addr = test_addr(2).to_transport_addr();
        let pool = Arc::new(Mutex::new(ConnectionPool::new(7)));
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let reader = BleStreamRead::new(Arc::new(local), 2048);
        let task = tokio::spawn(receive_loop(
            reader,
            addr,
            Arc::clone(&pool),
            tx,
            TransportId::new(1),
            Arc::new(BleStats::new()),
            2048,
        ));
        (task, rx, pool)
    }

    fn test_addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    fn make_transport(
        io: MockBleIo,
    ) -> (
        BleTransport<MockBleIo>,
        tokio::sync::mpsc::Receiver<ReceivedPacket>,
    ) {
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let config = BleConfig::default();
        let transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        (transport, rx)
    }

    #[test]
    fn test_transport_type() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (transport, _rx) = make_transport(io);
        assert_eq!(transport.transport_type().name, "ble");
        assert!(transport.transport_type().connection_oriented);
        assert!(transport.transport_type().reliable);
    }

    #[test]
    fn test_transport_initial_state() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (transport, _rx) = make_transport(io);
        assert_eq!(transport.state(), TransportState::Configured);
    }

    #[test]
    fn test_transport_default_mtu() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (transport, _rx) = make_transport(io);
        assert_eq!(transport.mtu(), 2048);
    }

    #[tokio::test]
    async fn test_transport_start_stop() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (mut transport, _rx) = make_transport(io);
        transport.start_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Up);

        transport.stop_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Down);
    }

    #[tokio::test(start_paused = true)]
    async fn test_scan_discovers_peers() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (mut transport, _rx) = make_transport(io);
        transport.start_async().await.unwrap();

        // Inject scan results via the I/O mock
        transport.io.inject_scan_result(test_addr(2)).await;
        transport.io.inject_scan_result(test_addr(3)).await;

        // Let scan_probe_loop pick up results and schedule jitter
        tokio::task::yield_now().await;
        // Advance past max jitter (5s) so probes fire
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        // Let the expired entries get processed
        tokio::task::yield_now().await;

        // Without pubkey set, scan results go to neighbor buffer as bare MACs
        let peers = transport.neighbor_buffer.take();
        assert_eq!(peers.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_scan_deduplicates() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (mut transport, _rx) = make_transport(io);
        transport.start_async().await.unwrap();

        // Same address twice
        transport.io.inject_scan_result(test_addr(2)).await;
        transport.io.inject_scan_result(test_addr(2)).await;

        // Let scan_probe_loop pick up results
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(6)).await;
        tokio::task::yield_now().await;

        let peers = transport.neighbor_buffer.take();
        assert_eq!(peers.len(), 1);
    }

    #[test]
    fn test_transport_auto_connect_default() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (transport, _rx) = make_transport(io);
        assert!(!transport.auto_connect());
    }

    #[test]
    fn test_connection_state_none() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (transport, _rx) = make_transport(io);
        let addr = test_addr(2).to_transport_addr();
        assert_eq!(
            transport.connection_state_sync(&addr),
            ConnectionState::None
        );
    }

    /// Verify that the cross-probe tie-breaker follows the same convention
    /// as `cross_connection_winner`: smaller NodeAddr's outbound wins.
    #[test]
    fn test_tiebreaker_convention() {
        use secp256k1::{Secp256k1, SecretKey};

        let secp = Secp256k1::new();
        let sk_a = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk_b = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let (pk_a, _) = sk_a.public_key(&secp).x_only_public_key();
        let (pk_b, _) = sk_b.public_key(&secp).x_only_public_key();

        let addr_a = NodeAddr::from_pubkey(&pk_a);
        let addr_b = NodeAddr::from_pubkey(&pk_b);

        // Determine which is smaller
        let (smaller, larger) = if addr_a < addr_b {
            (addr_a, addr_b)
        } else {
            (addr_b, addr_a)
        };

        // scan_loop (outbound): promotes when our_addr < peer_addr
        // Smaller node scanning larger → our_addr < peer_addr → promote (win)
        assert!(smaller < larger, "test setup: smaller < larger");

        // accept_loop (inbound): drops when our_addr < peer_addr
        // Smaller node accepting from larger → drops inbound (outbound wins)
        // This means: smaller always uses outbound, larger always uses inbound
    }

    // ------------------------------------------------------------------
    // Packet boundary recovery
    // ------------------------------------------------------------------

    /// Two whole FMP packets delivered in one `recv` must both arrive.
    /// Before reframing the tail was silently truncated and lost.
    #[tokio::test]
    async fn test_receive_loop_splits_coalesced_packets() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let (task, mut rx, _pool) = spawn_receive_loop(local);

        let first = build_established_frame(16);
        let second = build_established_frame(48);
        let mut both = first.clone();
        both.extend_from_slice(&second);
        peer.send(&both).await.unwrap();

        assert_eq!(rx.recv().await.unwrap().data, first);
        assert_eq!(rx.recv().await.unwrap().data, second);
        task.abort();
    }

    /// One FMP packet split across three `recv`s arrives once, whole —
    /// not as three runts that FMP and Noise would reject.
    #[tokio::test]
    async fn test_receive_loop_reassembles_fragmented_packet() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let (task, mut rx, _pool) = spawn_receive_loop(local);

        let frame = build_established_frame(64);
        let third = frame.len() / 3;
        peer.send(&frame[..third]).await.unwrap();
        peer.send(&frame[third..2 * third]).await.unwrap();
        peer.send(&frame[2 * third..]).await.unwrap();

        assert_eq!(rx.recv().await.unwrap().data, frame);
        assert!(rx.try_recv().is_err(), "no runt packets");
        task.abort();
    }

    /// One `send` per packet still yields one packet per `send`, byte for
    /// byte — the boundary-preserving backend regression.
    #[tokio::test]
    async fn test_receive_loop_passes_through_whole_packets() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let (task, mut rx, _pool) = spawn_receive_loop(local);

        let frames: Vec<Vec<u8>> = [8u16, 0, 512]
            .iter()
            .map(|n| build_established_frame(*n))
            .collect();
        for f in &frames {
            peer.send(f).await.unwrap();
        }
        for f in &frames {
            assert_eq!(&rx.recv().await.unwrap().data, f);
        }
        task.abort();
    }

    /// A malformed frame closes the connection and drops it from the pool
    /// rather than spinning the loop.
    #[tokio::test]
    async fn test_receive_loop_drops_connection_on_bad_frame() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let ta = test_addr(2).to_transport_addr();
        let (task, _rx, pool) = spawn_receive_loop(local);

        // Put a pool entry in place so its removal is observable.
        let (parked, _other) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        pool.lock()
            .await
            .insert(
                ta.clone(),
                BleConnection {
                    stream: Arc::new(parked),
                    recv_task: None,
                    send_mtu: 2048,
                    recv_mtu: 2048,
                    established_at: tokio::time::Instant::now(),
                    is_static: false,
                    addr: test_addr(2),
                    node_addr: None,
                },
            )
            .unwrap();
        assert!(pool.lock().await.contains(&ta));

        // 0x16 is a TLS ClientHello record type; it parses as FMP version 1.
        peer.send(&[0x16, 0x03, 0x01, 0x00]).await.unwrap();

        // The loop exits and clears the pool entry.
        for _ in 0..50 {
            if !pool.lock().await.contains(&ta) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(!pool.lock().await.contains(&ta));
        assert!(task.await.is_ok(), "loop exited cleanly");
    }

    /// A peer that coalesces its first data packet behind the 33-byte
    /// pubkey exchange must not lose it at the hand-off to the framer.
    #[tokio::test]
    async fn test_pubkey_exchange_preserves_coalesced_data() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let local = Arc::new(local);
        let mut reader = BleStreamRead::new(Arc::clone(&local), 2048);

        let peer_pk = test_pubkey(2);
        let frame = build_established_frame(24);
        let mut wire = vec![PUBKEY_EXCHANGE_PREFIX];
        wire.extend_from_slice(&peer_pk);
        wire.extend_from_slice(&frame);
        peer.send(&wire).await.unwrap();

        let got = pubkey_exchange(local.as_ref(), &mut reader, &test_pubkey(1))
            .await
            .unwrap();
        assert_eq!(got.serialize(), peer_pk);

        let packet = read_fmp_packet(&mut reader, 2048).await.unwrap();
        assert_eq!(packet, frame);
    }

    /// A fragmented pubkey exchange completes. The old exact-length `recv`
    /// check could never satisfy this.
    #[tokio::test]
    async fn test_pubkey_exchange_reassembles_fragments() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let local = Arc::new(local);
        let mut reader = BleStreamRead::new(Arc::clone(&local), 2048);

        let peer_pk = test_pubkey(3);
        let mut wire = vec![PUBKEY_EXCHANGE_PREFIX];
        wire.extend_from_slice(&peer_pk);
        peer.send(&wire[..17]).await.unwrap();
        peer.send(&wire[17..]).await.unwrap();

        let got = pubkey_exchange(local.as_ref(), &mut reader, &test_pubkey(1))
            .await
            .unwrap();
        assert_eq!(got.serialize(), peer_pk);
    }

    // ------------------------------------------------------------------
    // Node identity vs. rotating link address
    // ------------------------------------------------------------------

    /// Two pubkeys, returned as `(smaller_node_addr, larger_node_addr)`.
    ///
    /// The cross-probe tie-breaker is decided by `NodeAddr` ordering, so a
    /// test that wants a connection admitted has to know which side it is.
    fn pubkeys_ordered_by_node_addr() -> ([u8; 32], [u8; 32]) {
        let a = test_pubkey(1);
        let b = test_pubkey(2);
        let na = NodeAddr::from_pubkey(&XOnlyPublicKey::from_slice(&a).unwrap());
        let nb = NodeAddr::from_pubkey(&XOnlyPublicKey::from_slice(&b).unwrap());
        if na < nb { (a, b) } else { (b, a) }
    }

    /// Run the peer half of the pubkey exchange over a mock stream end.
    async fn peer_side_exchange(peer: &MockBleStream, peer_pubkey: &[u8; 32]) {
        let mut msg = [0u8; PUBKEY_EXCHANGE_SIZE];
        msg[0] = PUBKEY_EXCHANGE_PREFIX;
        msg[1..].copy_from_slice(peer_pubkey);
        peer.send(&msg).await.unwrap();
        let mut buf = [0u8; PUBKEY_EXCHANGE_SIZE];
        let n = peer.recv(&mut buf).await.unwrap();
        assert_eq!(n, PUBKEY_EXCHANGE_SIZE);
    }

    fn identity_test_config() -> BleConfig {
        BleConfig {
            adapter: Some("hci0".to_string()),
            scan: Some(false),
            advertise: Some(false),
            accept_connections: Some(true),
            probe_cooldown_secs: Some(1),
            ..Default::default()
        }
    }

    /// Let spawned loops make progress.
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    /// A second inbound connection from a rotated address for a peer already
    /// in the pool is declined, the incumbent link is kept, and the peer is
    /// still announced — under the address its live link is on.
    #[tokio::test]
    async fn test_inbound_rotation_is_declined_and_keeps_the_incumbent() {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();
        let io = MockBleIo::new("hci0", test_addr(1));
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport =
            BleTransport::new(TransportId::new(1), None, identity_test_config(), io, tx);
        // We take the larger node address, so the inbound tie-breaker admits
        // rather than drops — the duplicate guard is what is under test.
        transport.set_local_pubkey(larger);
        transport.start_async().await.unwrap();

        // First inbound, on link address 2.
        let (ours, peer_a) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        transport.io.inject_inbound(ours).await;
        peer_side_exchange(&peer_a, &smaller).await;
        settle().await;

        assert_eq!(transport.pool.lock().await.len(), 1);
        assert!(
            transport
                .pool
                .lock()
                .await
                .contains(&test_addr(2).to_transport_addr())
        );

        // The same node dials in again after rotating to link address 3.
        let (ours2, peer_b) = MockBleStream::pair(test_addr(1), test_addr(3), 2048);
        transport.io.inject_inbound(ours2).await;
        peer_side_exchange(&peer_b, &smaller).await;
        settle().await;

        let pool = transport.pool.lock().await;
        assert_eq!(pool.len(), 1, "the rotation must not become a second link");
        assert!(
            pool.contains(&test_addr(2).to_transport_addr()),
            "the incumbent link is kept"
        );
        assert!(!pool.contains(&test_addr(3).to_transport_addr()));
        drop(pool);

        assert_eq!(transport.stats.snapshot().duplicate_node_declines, 1);

        // Discovery names the peer by the address its link is actually on,
        // not by the alias the rotation arrived from — otherwise the node
        // layer is handed an address with no connection behind it.
        let peers = transport.neighbor_buffer.take();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, test_addr(2).to_transport_addr());

        transport.stop_async().await.unwrap();
        drop((peer_a, peer_b));
    }

    /// Once a rotated alias has been resolved to a peer that holds a live
    /// link, the scan loop stops paying a connect and exchange to reach that
    /// same conclusion every cooldown.
    #[tokio::test(start_paused = true)]
    async fn test_scan_loop_stops_reprobing_a_resolved_alias() {
        use std::sync::Mutex as StdMutex;

        let (smaller, larger) = pubkeys_ordered_by_node_addr();
        let io = MockBleIo::new("hci0", test_addr(1));

        let connects: Arc<StdMutex<Vec<BleAddr>>> = Arc::new(StdMutex::new(Vec::new()));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let connects = Arc::clone(&connects);
            io.set_connect_handler(move |addr, _psm| {
                let (ours, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
                connects.lock().unwrap().push(addr.clone());
                peer_tx
                    .send(theirs)
                    .map_err(|_| TransportError::ConnectionRefused)?;
                Ok(ours)
            });
        }

        // The remote answers every probe with one identity, whichever link
        // address the probe went to.
        tokio::spawn(async move {
            let mut alive = Vec::new();
            while let Some(theirs) = peer_rx.recv().await {
                peer_side_exchange(&theirs, &larger).await;
                alive.push(theirs);
            }
        });

        let config = BleConfig {
            scan: Some(true),
            accept_connections: Some(false),
            ..identity_test_config()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        // We take the smaller node address, so our outbound wins the
        // tie-breaker and the probe is promoted.
        transport.set_local_pubkey(smaller);
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(2)).await;
        settle().await;
        assert_eq!(transport.pool.lock().await.len(), 1);
        assert_eq!(connects.lock().unwrap().len(), 1);

        // The peer rotates to address 3. That probe is paid once and declined.
        transport.io.inject_scan_result(test_addr(3)).await;
        settle().await;
        assert_eq!(connects.lock().unwrap().len(), 2);
        assert_eq!(transport.stats.snapshot().duplicate_node_declines, 1);
        assert_eq!(transport.pool.lock().await.len(), 1);

        // The alias is advertised again after the cooldown expires. It must
        // not be dialled a third time: the loop already knows whose it is.
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        transport.io.inject_scan_result(test_addr(3)).await;
        settle().await;
        assert_eq!(
            connects.lock().unwrap().len(),
            2,
            "a resolved alias of a live peer must not be re-dialled"
        );

        transport.stop_async().await.unwrap();
    }

    /// A peer that opens with something other than the exchange prefix is
    /// rejected before the framer ever sees the bytes.
    #[tokio::test]
    async fn test_pubkey_exchange_rejects_bad_prefix() {
        let (peer, local) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let local = Arc::new(local);
        let mut reader = BleStreamRead::new(Arc::clone(&local), 2048);

        let mut wire = vec![0xFFu8];
        wire.extend_from_slice(&test_pubkey(4));
        peer.send(&wire).await.unwrap();

        let err = pubkey_exchange(local.as_ref(), &mut reader, &test_pubkey(1))
            .await
            .unwrap_err();
        assert!(matches!(err, TransportError::RecvFailed(_)));
    }
}
