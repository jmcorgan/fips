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
//! `crate::transport::framing::read_fmp_packet`, which is a transparent
//! pass-through on a boundary-preserving backend.
//!
//! ## Architecture
//!
//! Transport logic (pool, neighbor, lifecycle) is separated from any one
//! Bluetooth stack via the `BleIo` trait. `BluerIo` drives BlueZ (behind
//! `cfg(bluer_available)`), [`io_android::AndroidIo`] drives a radio the
//! embedder supplies, and `MockBleIo` is an in-memory double for tests
//! without hardware. Which one `DefaultBleTransport` resolves to is decided
//! by the cascade below, and the whole module is compiled only on platforms
//! that have one of them — see `ble_available` in `build.rs`.
//!
//! ## Connection Pool
//!
//! BLE hardware limits concurrent connections (typically 4-10). The pool
//! enforces a configurable maximum (default 7) with priority eviction:
//! static (configured) peers get priority over discovered peers.

pub mod addr;
pub mod io;
/// A backend whose radio is supplied by the embedder rather than opened in
/// process.
///
/// Compiled under `cfg(test)` on every host as well as on the platform that
/// will select it, so its channel machinery, slot semantics and connect
/// routing are exercised by an ordinary test run on an ordinary runner. The
/// platform build of it is linted but executed nowhere, which is exactly why
/// the logic must not be behind a platform-only gate.
#[cfg(any(target_os = "android", test))]
pub mod io_android;
#[cfg(bluer_available)]
pub mod io_linux;
pub mod neighbor;
pub mod pool;
pub mod psm;
pub mod stats;
pub mod stream_read;

use super::framing::{StreamError, read_fmp_packet};
use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::BleConfig;
use addr::BleAddr;
use io::{BleIo, BleScanner, BleStream};
use neighbor::NeighborBuffer;
use pool::{BleConnection, ConnectionPool};
use stats::BleStats;
use stream_read::BleStreamRead;

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info, trace, warn};

/// Default FIPS L2CAP PSM (Protocol Service Multiplexer).
///
/// 0x0085 (133) is in the dynamic range (0x0080-0x00FF).
///
/// This is a request and a fallback, not a guarantee. A backend whose
/// platform assigns the PSM reports back what it actually bound (see
/// [`io::BleIo::listen`]), and a peer that advertises its own PSM (see
/// [`psm`]) is dialled there instead. The configured value is what a peer is
/// dialled at when it advertises nothing.
pub const DEFAULT_PSM: u16 = 0x0085;

/// Concrete BLE transport type for use in `TransportHandle`.
///
/// Three arms, in priority order: an in-process BlueZ stack where one exists,
/// otherwise a radio the embedder supplies, otherwise — and *only* in a test
/// build — the in-memory double.
///
/// The mock arm is deliberately not written as "anything that is not BlueZ".
/// That phrasing is what makes widening the module gate dangerous: a platform
/// added to `ble_available` without a backend would silently land on an
/// in-memory transport that compiles, starts, reports [`TransportState::Up`]
/// and never peers, with nothing anywhere to say so. The tripwire below makes
/// that state unrepresentable instead.
#[cfg(all(bluer_available, not(test)))]
pub type DefaultBleTransport = BleTransport<io_linux::BluerIo>;

#[cfg(all(target_os = "android", not(bluer_available), not(test)))]
pub type DefaultBleTransport = BleTransport<io_android::AndroidIo>;

#[cfg(test)]
pub type DefaultBleTransport = BleTransport<io::MockBleIo>;

// The tripwire. This module is only compiled when `ble_available`, so
// reaching here means a platform declared it has BLE while having no concrete
// backend to provide it. It cannot fire today; it exists for whoever next
// widens `ble_available`, and it fails the build rather than shipping a
// transport that quietly never connects.
#[cfg(all(not(test), not(bluer_available), not(target_os = "android")))]
compile_error!(
    "this target is `ble_available` but has no concrete `BleIo` backend. \
     Add its backend and an arm to the `DefaultBleTransport` cascade in \
     src/transport/ble/mod.rs, or drop the target from `ble_available` in \
     build.rs. Falling back to the in-memory mock in a non-test build would \
     produce a BLE transport that starts, reports itself up, and never peers."
);

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

    /// Start the transport asynchronously.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Starting;

        let configured_psm = self.config.psm();
        let adapter = self.io.adapter_name().to_string();

        // The PSM peers should dial us on. Only the listener knows it: a
        // backend whose platform assigns PSMs reports back something other
        // than what was requested, and that is what has to be advertised.
        let mut listener_psm = configured_psm;

        // Start L2CAP listener for inbound connections
        if self.config.accept_connections() {
            match self.io.listen(configured_psm).await {
                Ok((acceptor, bound_psm)) => {
                    listener_psm = bound_psm;
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
                        Arc::clone(&self.neighbor_buffer),
                    )));
                    debug!(
                        adapter = %adapter,
                        psm = listener_psm,
                        requested_psm = configured_psm,
                        "BLE accept loop started"
                    );
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
            if let Err(e) = self.io.start_advertising(listener_psm).await {
                warn!(adapter = %adapter, error = %e, "failed to start BLE advertising");
            } else {
                self.stats.record_advertisement();
                debug!(
                    adapter = %adapter,
                    psm = listener_psm,
                    "BLE advertising started (continuous)"
                );
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
                        self.config.psm(),
                        self.config.connect_timeout_ms(),
                        self.config.probe_cooldown_secs(),
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
        info!(adapter = %adapter, psm = listener_psm, "BLE transport started");
        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        // Stop advertising
        let _ = self.io.stop_advertising().await;

        // Stop scanning. Aborting the scan task below stops us reading
        // adverts; on a backend whose radio the embedder owns, only this
        // stops the radio.
        let _ = self.io.stop_scanning().await;

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
                self.stats.record_connect_error();
                debug!(
                    addr = %addr, role = "central", outcome = "connect-error", error = %e,
                    "BLE connect-on-send failed"
                );
                return Err(TransportError::ConnectionRefused);
            }
            Err(_) => {
                self.stats.record_connect_timeout();
                debug!(
                    addr = %addr, role = "central", outcome = "connect-timeout",
                    "BLE connect-on-send timeout"
                );
                return Err(TransportError::Timeout);
            }
        };

        // One reader for the life of the connection: it buffers what one
        // `recv` left over, so packet boundaries come from the FMP length
        // prefix rather than from the L2CAP SDU boundary.
        let stream = Arc::new(stream);
        let recv_mtu = stream.recv_mtu();
        let reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

        self.neighbor_buffer.add_peer(&ble_addr);
        self.promote_connection(addr, &ble_addr, stream, reader)
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
                    // Boundaries come from the FMP length prefix, not from
                    // the L2CAP SDU boundary.
                    let reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);
                    neighbor_buffer.add_peer(&ble_addr);

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
                    stats.record_connect_error();
                    debug!(
                        addr = %addr_clone, role = "central", outcome = "connect-error",
                        error = %e, "BLE connect failed"
                    );
                }
                Err(_) => {
                    stats.record_connect_timeout();
                    debug!(
                        addr = %addr_clone, role = "central", outcome = "connect-timeout",
                        "BLE connect timeout"
                    );
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

// Beacon loop removed — advertising is now continuous (started once
// in start_async, stopped in stop_async). BLE advertising overhead
// is negligible (~0.15% duty cycle on advertising channels).

/// Accept loop: accepts inbound L2CAP connections and adds them to the pool.
///
/// One reader is built per connection and handed to the receive loop, so
/// packet boundaries come from the FMP length prefix rather than from the
/// L2CAP SDU boundary.
#[allow(clippy::too_many_arguments)]
async fn accept_loop<A>(
    mut acceptor: A,
    pool: Arc<Mutex<ConnectionPool<Arc<A::Stream>>>>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: Arc<BleStats>,
    _max_conns: usize,
    neighbor_buffer: Arc<NeighborBuffer>,
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

                neighbor_buffer.add_peer(&addr);

                let stream = Arc::new(stream);
                let reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

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
                        stats.record_connection_rejected();
                        warn!(
                            addr = %ta, role = "peripheral", outcome = "pool-rejected",
                            error = %e, "BLE pool full, inbound connection rejected"
                        );
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

/// Consecutive-failure backoff ceiling for a pending address, as a power of
/// two multiple of the base cooldown. At the 30 s default this caps a failing
/// address at one dial attempt every 16 minutes.
const MAX_PROBE_BACKOFF_SHIFT: u32 = 5;

/// Ceiling on how many discovered-but-unconnected addresses are kept for
/// retry. Resolvable private addresses rotate, so without a bound the book
/// grows for the life of the process; with one, the total retry dial rate is
/// bounded too (at most one dial per retry tick, spread over the book).
const MAX_PENDING_PROBES: usize = 32;

/// One discovered address awaiting a successful probe.
#[derive(Debug, Clone)]
struct PendingProbe {
    addr: BleAddr,
    /// Consecutive failed probes. Reset only by removal from the book, which
    /// every conclusive outcome (connected, duplicate declined, already
    /// pooled) performs.
    failures: u32,
    /// Earliest instant at which this address may be dialled again.
    next_attempt: tokio::time::Instant,
}

/// The retry book for addresses the scanner has offered but which are not yet
/// connected.
///
/// Exists because a scanner is not a reliable repeat source: BlueZ emits
/// `DeviceAdded` once per address per discovery session, so an address the
/// probe loop forgets is never offered again. Everything here therefore
/// throttles rather than discards — an entry leaves the book on a *conclusive*
/// outcome, or when [`MAX_PENDING_PROBES`] other addresses compete for its
/// slot, never because it failed.
///
/// Two properties matter:
///
/// - **Consecutive failures back an address off exponentially.** A dead
///   address is retried on a doubling interval up to
///   [`MAX_PROBE_BACKOFF_SHIFT`], instead of being re-dialled every cooldown
///   forever. Addresses rotate and links are lossy, so a handful of failures
///   is normal and must not retire a peer that is still there.
/// - **The retry tick rotates.** Probing only the head of the book let one
///   slow or dead address starve every other pending address behind it, which
///   on a busy radio is most of them.
#[derive(Debug)]
struct PendingProbes {
    entries: Vec<PendingProbe>,
    cooldown: std::time::Duration,
}

impl PendingProbes {
    fn new(cooldown: std::time::Duration) -> Self {
        Self {
            entries: Vec::new(),
            cooldown,
        }
    }

    fn position(&self, addr: &BleAddr) -> Option<usize> {
        self.entries.iter().position(|e| &e.addr == addr)
    }

    /// Record a sighting. A previously unseen address becomes immediately
    /// eligible; a known one keeps whatever backoff it has earned, so a
    /// scanner that re-reports the same address many times a second cannot
    /// wash out the backoff.
    ///
    /// When the book is full the *most-failed* entry is evicted to make room,
    /// which is the entry least likely to still have a peer behind it.
    fn observe(&mut self, addr: &BleAddr, now: tokio::time::Instant) {
        if self.position(addr).is_some() {
            return;
        }
        if self.entries.len() >= MAX_PENDING_PROBES
            && let Some(worst) = self
                .entries
                .iter()
                .enumerate()
                .max_by_key(|(_, e)| (e.failures, e.next_attempt))
                .map(|(i, _)| i)
        {
            self.entries.remove(worst);
        }
        self.entries.push(PendingProbe {
            addr: addr.clone(),
            failures: 0,
            next_attempt: now,
        });
    }

    /// Whether `addr` may be dialled now. An address that is not in the book
    /// has no history to hold it back.
    fn is_due(&self, addr: &BleAddr, now: tokio::time::Instant) -> bool {
        match self.position(addr) {
            Some(i) => self.entries[i].next_attempt <= now,
            None => true,
        }
    }

    /// Note that a probe is starting: hold the address for one base cooldown
    /// so the attempt in flight is not duplicated.
    fn mark_attempt(&mut self, addr: &BleAddr, now: tokio::time::Instant) {
        if let Some(i) = self.position(addr) {
            self.entries[i].next_attempt = now + self.cooldown;
        }
    }

    /// Note that a probe failed. Returns the new consecutive-failure count.
    fn record_failure(&mut self, addr: &BleAddr, now: tokio::time::Instant) -> u32 {
        let Some(i) = self.position(addr) else {
            return 0;
        };
        let e = &mut self.entries[i];
        e.failures = e.failures.saturating_add(1);
        let shift = (e.failures - 1).min(MAX_PROBE_BACKOFF_SHIFT);
        e.next_attempt = now + self.cooldown * 2u32.pow(shift);
        e.failures
    }

    /// Drop an address that reached a conclusive outcome.
    fn resolve(&mut self, addr: &BleAddr) {
        self.entries.retain(|e| &e.addr != addr);
    }

    /// Drop every address for which `connected` reports a live pool entry.
    fn drop_connected(&mut self, connected: impl Fn(&BleAddr) -> bool) {
        self.entries.retain(|e| !connected(&e.addr));
    }

    /// The next address due for a retry, rotated to the back of the book so
    /// the following tick starts after it rather than on it.
    fn next_due(&mut self, now: tokio::time::Instant) -> Option<BleAddr> {
        let i = self.entries.iter().position(|e| e.next_attempt <= now)?;
        let entry = self.entries.remove(i);
        let addr = entry.addr.clone();
        self.entries.push(entry);
        Some(addr)
    }
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
    configured_psm: u16,
    connect_timeout_ms: u64,
    cooldown_secs: u64,
    packet_tx: PacketTx,
    transport_id: TransportId,
) {
    // Addresses discovered but not yet connected — retried after cooldown even
    // if the scanner doesn't fire again (BlueZ deduplicates), on a per-address
    // backoff that widens with consecutive failures. Also the cooldown record:
    // an address leaves the book the moment it reaches a conclusive outcome,
    // after which the pool guard below covers it.
    let mut pending = PendingProbes::new(std::time::Duration::from_secs(cooldown_secs));
    // L2CAP listener PSMs read out of peers' advertisements. A peer whose
    // platform assigns its listener PSM cannot be dialled at a configured
    // constant, so it publishes the number it actually bound and we dial
    // that. A peer that advertises nothing is dialled at `configured_psm`,
    // which is every peer that predates this and every backend that does not
    // advertise service data.
    let mut learned_psm: HashMap<BleAddr, u16> = HashMap::new();
    let retry_interval = tokio::time::interval(std::time::Duration::from_secs(cooldown_secs));
    tokio::pin!(retry_interval);
    retry_interval.tick().await; // consume initial tick

    loop {
        // Either a scanner event or the retry timer fires
        let addr = tokio::select! {
            result = scanner.next() => {
                match result {
                    Some(advert) => {
                        if let Some(psm) = advert.psm {
                            trace!(addr = %advert.addr, psm, "BLE scan: learned peer PSM");
                            learned_psm.insert(advert.addr.clone(), psm);
                        }
                        advert.addr
                    }
                    None => {
                        debug!("BLE scanner ended");
                        break;
                    }
                }
            }
            _ = retry_interval.tick() => {
                // Re-probe pending addresses that aren't connected
                let pool_guard = pool.lock().await;
                pending.drop_connected(|a| pool_guard.contains(&a.to_transport_addr()));
                drop(pool_guard);
                // Rotating rather than always taking the head is what stops one
                // slow or dead address from starving every other pending one.
                match pending.next_due(tokio::time::Instant::now()) {
                    Some(a) => a,
                    None => continue,
                }
            }
        };

        trace!(addr = %addr, "BLE scan result");
        stats.record_scan_result();

        // Skip if already connected
        {
            let pool_guard = pool.lock().await;
            if pool_guard.contains(&addr.to_transport_addr()) {
                pending.resolve(&addr);
                continue;
            }
        }

        // Track for retry in case probe fails and scanner doesn't re-fire
        let now = tokio::time::Instant::now();
        pending.observe(&addr, now);

        // Skip if in cooldown, or backed off after consecutive failures
        if !pending.is_due(&addr, now) {
            continue;
        }

        // Record probe time (before attempt, so cooldown applies on failure too)
        pending.mark_attempt(&addr, now);

        // L2CAP connect, at whatever PSM this peer advertised.
        let dial_psm = learned_psm.get(&addr).copied().unwrap_or(configured_psm);
        // Stamped here so every outcome below can report how long the peer
        // took to go from advertisement to conclusion.
        let probe_started = tokio::time::Instant::now();
        let stream = match tokio::time::timeout(
            std::time::Duration::from_millis(connect_timeout_ms),
            io.connect(&addr, dial_psm),
        )
        .await
        {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                stats.record_connect_error();
                let failures = pending.record_failure(&addr, tokio::time::Instant::now());
                debug!(
                    addr = %addr, role = "central", outcome = "connect-error",
                    psm = dial_psm, discovery_ms = probe_started.elapsed().as_millis() as u64,
                    failures, error = %e, "BLE probe connect failed"
                );
                // A learned PSM that does not answer is stale — forget it, so
                // the next advert re-learns it and the fallback applies in the
                // meantime. Costs one retry.
                learned_psm.remove(&addr);
                continue;
            }
            Err(_) => {
                stats.record_connect_timeout();
                let failures = pending.record_failure(&addr, tokio::time::Instant::now());
                debug!(
                    addr = %addr, role = "central", outcome = "connect-timeout",
                    psm = dial_psm, discovery_ms = probe_started.elapsed().as_millis() as u64,
                    failures, "BLE probe connect timeout"
                );
                learned_psm.remove(&addr);
                continue;
            }
        };

        // Promote the connection to the pool.
        let ta = addr.to_transport_addr();
        let send_mtu = stream.send_mtu();
        let recv_mtu = stream.recv_mtu();
        let stream = Arc::new(stream);
        // Boundaries come from the FMP length prefix, not the SDU boundary.
        let reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

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
        };

        let mut pool_guard = pool.lock().await;
        match pool_guard.insert(ta.clone(), conn) {
            Ok(Some(evicted)) => {
                stats.record_pool_eviction();
                debug!(addr = %ta, evicted = %evicted, "BLE probe promoted (evicted peer)");
            }
            Ok(None) => {
                debug!(
                    addr = %ta, role = "central", outcome = "connected",
                    discovery_ms = probe_started.elapsed().as_millis() as u64,
                    "BLE probe promoted to pool"
                );
            }
            Err(e) => {
                stats.record_connection_rejected();
                warn!(
                    addr = %ta, role = "central", outcome = "pool-rejected",
                    error = %e, "BLE pool full, probe connection dropped"
                );
                // The connection is dropped with `conn`, so there is nothing to
                // report and nothing to resolve. Leaving the address in the
                // retry book is the point: a slot may free before the peer is
                // advertised again. The inbound path already continues here
                // rather than falling through.
                continue;
            }
        }
        drop(pool_guard);
        stats.record_connection_established();
        pending.resolve(&addr);

        // Report to node layer for auto-connect / handshake
        buffer.add_peer(&addr);
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

    // ------------------------------------------------------------------
    // PendingProbes — the retry/backoff policy for discovered addresses
    // ------------------------------------------------------------------

    const TEST_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(30);

    fn probes() -> PendingProbes {
        PendingProbes::new(TEST_COOLDOWN)
    }

    fn a(n: u8) -> BleAddr {
        BleAddr::parse(&format!("ble0/AA:BB:CC:DD:EE:{:02X}", n)).unwrap()
    }

    /// A fresh sighting is dialled straight away — discovery must not wait a
    /// cooldown to try a peer it has never met.
    #[test]
    fn a_newly_seen_address_is_due_immediately() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        p.observe(&a(1), t0);
        assert!(p.is_due(&a(1), t0));
    }

    /// The regression this policy exists for: an address that keeps failing
    /// must be dialled exponentially less often, not once per cooldown for as
    /// long as the process lives.
    #[test]
    fn consecutive_failures_back_an_address_off_exponentially() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        p.observe(&a(1), t0);

        for expected_shift in 0..MAX_PROBE_BACKOFF_SHIFT {
            let n = p.record_failure(&a(1), t0);
            assert_eq!(n, expected_shift + 1);
            let wait = TEST_COOLDOWN * 2u32.pow(expected_shift);
            assert!(
                !p.is_due(&a(1), t0 + wait - std::time::Duration::from_millis(1)),
                "due too early after {n} failures"
            );
            assert!(p.is_due(&a(1), t0 + wait), "not due after {n} failures");
        }

        // And the interval stops growing at the ceiling rather than running
        // away to hours.
        let capped = TEST_COOLDOWN * 2u32.pow(MAX_PROBE_BACKOFF_SHIFT);
        for _ in 0..8 {
            p.record_failure(&a(1), t0);
            assert!(p.is_due(&a(1), t0 + capped));
        }
    }

    /// Under the old policy an address failing every 30 s for 37 minutes was
    /// dialled 49 times. Pin the improvement rather than just the formula.
    #[test]
    fn a_dead_address_is_dialled_a_handful_of_times_an_hour() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        p.observe(&a(1), t0);

        let mut dials = 0;
        let mut now = t0;
        let deadline = t0 + std::time::Duration::from_secs(37 * 60);
        // Tick at the retry interval, exactly as the loop does.
        while now <= deadline {
            if p.is_due(&a(1), now) {
                p.mark_attempt(&a(1), now);
                p.record_failure(&a(1), now);
                dials += 1;
            }
            now += TEST_COOLDOWN;
        }
        assert!(
            (1..=10).contains(&dials),
            "expected a handful of dials in 37 minutes, got {dials}"
        );
    }

    /// A scanner that re-reports the same address many times a second (which
    /// Android does, at roughly 52/min) must not wash the backoff out.
    #[test]
    fn repeated_sightings_do_not_reset_the_backoff() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        p.observe(&a(1), t0);
        for _ in 0..4 {
            p.record_failure(&a(1), t0);
        }
        let still_blocked = t0 + TEST_COOLDOWN;
        for _ in 0..100 {
            p.observe(&a(1), still_blocked);
        }
        assert!(!p.is_due(&a(1), still_blocked));
        assert_eq!(p.entries.len(), 1);
    }

    /// Failing never removes an address. This is what keeps a BlueZ node
    /// recoverable: BlueZ emits `DeviceAdded` once per address per discovery
    /// session, so an address dropped from the book would never be offered
    /// again and the peer behind it would be unreachable for the life of the
    /// process.
    #[test]
    fn failures_never_evict_the_address_itself() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        p.observe(&a(1), t0);
        for _ in 0..500 {
            p.record_failure(&a(1), t0);
        }
        assert_eq!(p.entries.len(), 1);
        // Still reachable: once the (capped) backoff elapses it is dialled
        // again, so a peer that comes back is picked up without a new sighting.
        let capped = TEST_COOLDOWN * 2u32.pow(MAX_PROBE_BACKOFF_SHIFT);
        assert_eq!(p.next_due(t0 + capped), Some(a(1)));
    }

    /// Conclusive outcomes clear the address *and* its failure history, so a
    /// peer that reconnects later starts from a clean slate.
    #[test]
    fn resolving_clears_the_failure_history() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        p.observe(&a(1), t0);
        for _ in 0..5 {
            p.record_failure(&a(1), t0);
        }
        p.resolve(&a(1));
        assert!(p.entries.is_empty());
        p.observe(&a(1), t0);
        assert!(p.is_due(&a(1), t0));
    }

    /// The head-of-line half of the bug: probing only the first entry let one
    /// address monopolise the retry tick. Rotation gives every due address a
    /// turn.
    #[test]
    fn the_retry_tick_rotates_across_due_addresses() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        for n in 0..3 {
            p.observe(&a(n), t0);
        }
        let order: Vec<_> = (0..6).filter_map(|_| p.next_due(t0)).collect();
        assert_eq!(order, vec![a(0), a(1), a(2), a(0), a(1), a(2)]);
    }

    /// A backed-off address is skipped by the tick rather than blocking the
    /// addresses behind it.
    #[test]
    fn a_backed_off_address_does_not_block_the_others() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        p.observe(&a(0), t0);
        p.observe(&a(1), t0);
        p.record_failure(&a(0), t0);
        assert_eq!(p.next_due(t0), Some(a(1)));
        assert_eq!(p.next_due(t0), Some(a(1)));
    }

    /// Nothing is due when everything is backed off — the tick idles rather
    /// than dialling something it just said it would not.
    #[test]
    fn next_due_yields_nothing_when_all_are_backed_off() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        p.observe(&a(0), t0);
        p.record_failure(&a(0), t0);
        assert_eq!(p.next_due(t0), None);
    }

    /// Addresses rotate, so the book is capacity-bounded. Eviction is by
    /// failure count, so the entry least likely to have a peer behind it goes
    /// first and a healthy address is never displaced by a dead one.
    #[test]
    fn a_full_book_evicts_the_most_failed_address() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        for n in 0..MAX_PENDING_PROBES as u8 {
            p.observe(&a(n), t0);
        }
        // One entry is much worse than the rest.
        for _ in 0..3 {
            p.record_failure(&a(7), t0);
        }
        p.observe(&a(200), t0);
        assert_eq!(p.entries.len(), MAX_PENDING_PROBES);
        assert!(p.position(&a(7)).is_none(), "the worst entry should go");
        assert!(p.position(&a(200)).is_some(), "the new entry should land");
        assert!(p.position(&a(0)).is_some(), "healthy entries should stay");
    }

    /// Pool membership clears entries in bulk on the retry tick.
    #[test]
    fn connected_addresses_leave_the_book() {
        let mut p = probes();
        let t0 = tokio::time::Instant::now();
        for n in 0..3 {
            p.observe(&a(n), t0);
        }
        p.drop_connected(|addr| addr == &a(1));
        assert_eq!(p.entries.len(), 2);
        assert!(p.position(&a(1)).is_none());
    }

    /// The mock backend is a *test* backend. Any target that compiles this
    /// module must have a real one behind it, or a release build of it would
    /// ship a BLE transport that starts, reports itself up, and never peers.
    ///
    /// The `compile_error!` above is what enforces that in a non-test build —
    /// and by construction it cannot fire in a test build, which is exactly
    /// the build everybody runs. This closes that gap: the `cfg!` values below
    /// are evaluated for the *target*, not for the test profile, so this
    /// asserts the same condition the tripwire does, from the one place a
    /// developer will actually see it.
    #[test]
    fn a_target_that_compiles_this_module_has_a_real_backend() {
        let has_concrete_backend = cfg!(bluer_available) || cfg!(target_os = "android");
        assert!(
            has_concrete_backend,
            "target {} is `ble_available` but has no concrete `BleIo` backend, \
             so a non-test build of it would select the in-memory mock. Add \
             its backend and an arm to the `DefaultBleTransport` cascade, or \
             drop it from `ble_available` in build.rs.",
            std::env::consts::OS,
        );
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

    /// `stop_async` has always stopped advertising; it must stop scanning
    /// too. Aborting the scan task only stops the transport reading adverts —
    /// on a backend whose radio the embedder owns, the radio keeps scanning
    /// until it is told, which on a phone costs battery and keeps
    /// broadcasting after the feature was switched off.
    #[tokio::test]
    async fn stop_async_tells_the_backend_to_stop_scanning() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let config = BleConfig {
            adapter: Some("hci0".to_string()),
            scan: Some(true),
            advertise: Some(false),
            accept_connections: Some(false),
            ..Default::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.start_async().await.unwrap();
        assert_eq!(transport.io.stop_scan_calls(), 0);

        transport.stop_async().await.unwrap();
        assert_eq!(
            transport.io.stop_scan_calls(),
            1,
            "stopping the transport must reach the backend's scan"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_scan_discovers_peers() {
        let io = MockBleIo::new("hci0", test_addr(1));
        // Probe connect must succeed for peers to reach the neighbor buffer
        let local = test_addr(1);
        io.set_connect_handler(move |addr, _psm| {
            let (stream, _peer) = io::MockBleStream::pair(local.clone(), addr.clone(), 2048);
            Ok(stream)
        });
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

        // Scan results reach the neighbor buffer as bare addresses after probe
        let peers = transport.neighbor_buffer.take();
        assert_eq!(peers.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn test_scan_deduplicates() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let local = test_addr(1);
        io.set_connect_handler(move |addr, _psm| {
            let (stream, _peer) = io::MockBleStream::pair(local.clone(), addr.clone(), 2048);
            Ok(stream)
        });
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

    // ------------------------------------------------------------------
    // Node identity vs. rotating link address
    // ------------------------------------------------------------------

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
    ///
    /// Cooperative only: this hands the scheduler control, it does not move
    /// the clock. Anything gated on a `tokio::time` timer needs
    /// [`wait_for`] instead.
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    /// A probe the pool refuses is not a connection, and must not be recorded
    /// as one. The inbound path already continues on rejection; this pins the
    /// outbound probe path to the same shape.
    ///
    /// Reaching the refusal needs `max_connections: 0`. `ConnectionPool::insert`
    /// only fails when the pool is full *and* every slot is static, and every
    /// BLE connection is built with `is_static: false`, so a non-empty pool
    /// always has an evictable slot. That makes this arm unreachable in a
    /// default deployment today and reachable the moment anything marks a
    /// connection static, which the pool is already written for.
    #[tokio::test(start_paused = true)]
    async fn a_pool_rejected_probe_is_neither_established_nor_reported() {
        use std::sync::Mutex as StdMutex;

        let io = MockBleIo::new("hci0", test_addr(1));

        let connects: Arc<StdMutex<Vec<BleAddr>>> = Arc::new(StdMutex::new(Vec::new()));
        {
            let connects = Arc::clone(&connects);
            io.set_connect_handler(move |addr, _psm| {
                let (mine, _theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
                connects.lock().unwrap().push(addr.clone());
                Ok(mine)
            });
        }

        let config = BleConfig {
            scan: Some(true),
            accept_connections: Some(false),
            max_connections: Some(0),
            ..identity_test_config()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(2)).await;
        settle().await;

        // The dial happened; only the pool refused.
        assert_eq!(connects.lock().unwrap().len(), 1, "the peer was dialled");
        let snap = transport.stats.snapshot();
        assert_eq!(snap.connections_rejected, 1, "the refusal is recorded");
        assert_eq!(
            snap.connections_established, 0,
            "a refused probe is not an established connection"
        );
        assert_eq!(transport.pool.lock().await.len(), 0);
        assert!(
            transport.neighbor_buffer.take().is_empty(),
            "the node layer must not be handed a peer with no connection behind it"
        );

        // It stayed in the retry book, so a freed slot can still admit it.
        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        settle().await;
        assert!(
            connects.lock().unwrap().len() >= 2,
            "a refused address is retried, not resolved away"
        );

        transport.stop_async().await.unwrap();
    }

    // ------------------------------------------------------------------
    // Per-peer listener PSM
    // ------------------------------------------------------------------

    /// Every `(address, psm)` the transport tried to dial.
    type DialLog = Arc<std::sync::Mutex<Vec<(BleAddr, u16)>>>;

    /// A scanning transport whose dials all fail, recording the PSM each was
    /// attempted at.
    fn psm_probe_transport(
        dials: DialLog,
    ) -> (
        BleTransport<MockBleIo>,
        tokio::sync::mpsc::Receiver<ReceivedPacket>,
    ) {
        let io = MockBleIo::new("hci0", test_addr(1));
        io.set_connect_handler(move |addr, psm| {
            dials.lock().unwrap().push((addr.clone(), psm));
            Err(TransportError::ConnectionRefused)
        });
        let config = BleConfig {
            adapter: Some("hci0".to_string()),
            scan: Some(true),
            advertise: Some(false),
            accept_connections: Some(false),
            probe_cooldown_secs: Some(1),
            ..Default::default()
        };
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        let transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        (transport, rx)
    }

    /// A peer that advertises its listener PSM is dialled there, not at the
    /// configured one — the whole point of learning it.
    #[tokio::test(start_paused = true)]
    async fn test_advertised_psm_is_dialled() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        transport.start_async().await.unwrap();

        transport
            .io
            .inject_scan_advert(io::ScanAdvert::with_psm(test_addr(2), 0x00C1))
            .await;
        settle().await;

        assert_eq!(dials.lock().unwrap().as_slice(), &[(test_addr(2), 0x00C1)]);
        transport.stop_async().await.unwrap();
    }

    /// A legacy UUID-only advertiser carries no PSM, so the configured one is
    /// used. This is the path every existing peer takes and it must not
    /// regress.
    #[tokio::test(start_paused = true)]
    async fn test_advert_without_a_psm_falls_back_to_the_configured_one() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(2)).await;
        settle().await;

        assert_eq!(
            dials.lock().unwrap().as_slice(),
            &[(test_addr(2), DEFAULT_PSM)]
        );
        transport.stop_async().await.unwrap();
    }

    /// A learned PSM that does not answer is forgotten, so a stale value
    /// costs one retry rather than making the peer permanently unreachable.
    #[tokio::test(start_paused = true)]
    async fn test_a_failed_dial_forgets_the_learned_psm() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        transport.start_async().await.unwrap();

        transport
            .io
            .inject_scan_advert(io::ScanAdvert::with_psm(test_addr(2), 0x00C1))
            .await;
        settle().await;
        assert_eq!(dials.lock().unwrap().len(), 1);

        // The retry after the cooldown must not repeat the PSM that failed.
        tokio::time::advance(std::time::Duration::from_secs(3)).await;
        settle().await;

        let log = dials.lock().unwrap().clone();
        assert!(log.len() >= 2, "the address is retried after the cooldown");
        assert_eq!(log[0], (test_addr(2), 0x00C1));
        assert!(
            log[1..].iter().all(|(_, psm)| *psm == DEFAULT_PSM),
            "retries fall back to the configured PSM: {log:?}"
        );
        transport.stop_async().await.unwrap();
    }

    /// The advertisement carries the PSM the listener actually bound, not the
    /// one that was requested. This is the whole OS-assigned-PSM case, with
    /// no platform in the assertion.
    #[tokio::test]
    async fn test_the_advertised_psm_is_the_one_actually_bound() {
        let io = MockBleIo::new("hci0", test_addr(1));
        io.set_bound_psm(0x00C1);
        let config = BleConfig {
            adapter: Some("hci0".to_string()),
            scan: Some(false),
            advertise: Some(true),
            accept_connections: Some(true),
            ..Default::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.start_async().await.unwrap();

        assert_ne!(DEFAULT_PSM, 0x00C1, "test setup: the bound PSM differs");
        assert_eq!(transport.io.advertised_psm(), Some(0x00C1));
        transport.stop_async().await.unwrap();
    }

    /// A backend that binds what it was asked for advertises that — the BlueZ
    /// path, unchanged.
    #[tokio::test]
    async fn test_a_backend_that_honours_the_request_advertises_it() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let config = BleConfig {
            adapter: Some("hci0".to_string()),
            scan: Some(false),
            advertise: Some(true),
            accept_connections: Some(true),
            ..Default::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.start_async().await.unwrap();

        assert_eq!(transport.io.advertised_psm(), Some(DEFAULT_PSM));
        transport.stop_async().await.unwrap();
    }

    // ------------------------------------------------------------------
    // Connect outcome counters
    // ------------------------------------------------------------------

    /// A dial that errors is counted as an error, not as a timeout. The two
    /// are different faults and blur into one useless number if merged.
    #[tokio::test(start_paused = true)]
    async fn test_a_refused_dial_counts_as_an_error_not_a_timeout() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(2)).await;
        settle().await;

        let snap = transport.stats.snapshot();
        assert_eq!(snap.connect_errors, 1);
        assert_eq!(snap.connect_timeouts, 0);
        assert_eq!(snap.connections_established, 0);
        transport.stop_async().await.unwrap();
    }

    /// An oversized packet is a caller bug, not a property of the peer's
    /// link. Folding it into `send_errors` would make that number useless as
    /// evidence.
    #[tokio::test]
    async fn test_mtu_rejection_does_not_count_as_a_send_error() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let transport =
            BleTransport::new(TransportId::new(1), None, identity_test_config(), io, tx);

        let ta = test_addr(2).to_transport_addr();
        let (parked, _peer) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        transport
            .pool
            .lock()
            .await
            .insert(
                ta.clone(),
                BleConnection {
                    stream: Arc::new(parked),
                    recv_task: None,
                    send_mtu: 64,
                    recv_mtu: 64,
                    established_at: tokio::time::Instant::now(),
                    is_static: false,
                    addr: test_addr(2),
                },
            )
            .unwrap();

        let err = transport.send_async(&ta, &[0u8; 128]).await.unwrap_err();
        assert!(matches!(err, TransportError::MtuExceeded { .. }));

        let snap = transport.stats.snapshot();
        assert_eq!(snap.mtu_exceeded, 1);
        assert_eq!(snap.send_errors, 0);
    }

    /// The snapshot is the control-socket contract. Pin every key so a field
    /// cannot be dropped or renamed without a test saying so.
    #[test]
    fn test_snapshot_carries_every_counter() {
        let value = serde_json::to_value(BleStats::new().snapshot()).unwrap();
        let object = value.as_object().unwrap();
        let expected = [
            "packets_sent",
            "bytes_sent",
            "packets_recv",
            "bytes_recv",
            "send_errors",
            "recv_errors",
            "mtu_exceeded",
            "connections_established",
            "connections_accepted",
            "connections_rejected",
            "connect_timeouts",
            "connect_errors",
            "pool_evictions",
            "advertisements_sent",
            "scan_results",
        ];
        for key in expected {
            assert!(object.contains_key(key), "snapshot lost `{key}`");
        }
        assert_eq!(object.len(), expected.len(), "snapshot gained a key");
    }
}
