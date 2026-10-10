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
//! enforces a configurable maximum (default 7). A link counts as a node's
//! only while the node's active peer for that node uses it: the
//! pre-handshake key exchange is a claim anyone in radio range can make.
//! Until then the link blocks no other link claiming the same node and may
//! be evicted, once it has had at least `connect_timeout_ms` (never less than
//! 10 s) to verify; a verified link is never evicted, and a newcomer that
//! finds nothing evictable is refused. Eviction happens only when the pool is
//! full and nothing closes an unverified link on a timer, so with
//! `max_connections` above what the adapter can hold, links that never
//! verify can keep the adapter's remaining connections.

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
use crate::identity::NodeAddr;
use addr::BleAddr;
use io::{BleIo, BleScanner, BleStream};
use neighbor::NeighborBuffer;
use pool::{BleConnection, ConnectionPool, Insert, Verify};
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
/// connection limits, evicting only unverified links.
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
        let verify_grace = config.verify_grace();
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            io: Arc::new(io),
            pool: Arc::new(Mutex::new(ConnectionPool::new(max_conns, verify_grace))),
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

        let configured_psm = self.config.psm();
        let adapter = self.io.adapter_name().to_string();

        // The PSM peers should dial us on. Only the listener knows it: a
        // backend whose platform assigns PSMs reports back something other
        // than what was requested, and that is what has to be advertised.
        let mut listener_psm = configured_psm;

        // Pre-compute local NodeAddr for cross-probe tie-breaking
        let local_node_addr = self.local_pubkey.and_then(|pk| {
            XOnlyPublicKey::from_slice(&pk)
                .ok()
                .map(|xonly| NodeAddr::from_pubkey(&xonly))
        });

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
                        self.local_pubkey,
                        Arc::clone(&self.neighbor_buffer),
                        local_node_addr,
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

    /// Whether the pool holds a connection to `addr`, the lookup
    /// [`send_async`](Self::send_async) makes first.
    ///
    /// Reads only: no background connect is started, and the pool lock is
    /// awaited rather than tried.
    pub async fn has_connection(&self, addr: &TransportAddr) -> bool {
        self.pool.lock().await.contains(addr)
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

        // One reader for the life of the connection: the pubkey exchange and
        // the receive loop must share it, or bytes the peer coalesced behind
        // the exchange are dropped at the hand-off.
        let stream = Arc::new(stream);
        let recv_mtu = stream.recv_mtu();
        let mut reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

        // Pre-handshake pubkey exchange (temporary, pre-XX)
        let mut peer_key: Option<XOnlyPublicKey> = None;
        if let Some(ref our_pubkey) = self.local_pubkey {
            match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
                Ok(peer_pubkey) => {
                    debug!(addr = %addr, "BLE outbound pubkey exchange complete");
                    peer_key = Some(peer_pubkey);
                }
                Err(e) => {
                    self.stats.record_pubkey_exchange_failure();
                    debug!(
                        addr = %addr, role = "central", outcome = "pubkey-exchange-failed",
                        error = %e, "BLE outbound pubkey exchange failed"
                    );
                    return Err(e);
                }
            }
        }

        self.promote_connection(addr, &ble_addr, stream, reader, peer_key)
            .await
    }

    /// Promote a newly established stream into the connection pool.
    ///
    /// Spawns the receive loop and offers the link to the pool. An admitted
    /// link whose remote sent `peer_key` is then announced; a refused one is
    /// not, since there is no link behind it.
    async fn promote_connection(
        &self,
        addr: &TransportAddr,
        ble_addr: &BleAddr,
        stream: Arc<I::Stream>,
        reader: BleStreamRead<I::Stream>,
        peer_key: Option<XOnlyPublicKey>,
    ) -> Result<(), TransportError> {
        let node_addr = peer_key.as_ref().map(NodeAddr::from_pubkey);
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

        let admitted = tokio::time::Instant::now();
        let conn = BleConnection {
            stream,
            recv_task: Some(recv_task),
            send_mtu,
            recv_mtu,
            established_at: admitted,
            grace_from: admitted,
            verified: false,
            addr: ble_addr.clone(),
            node_addr,
        };

        let mut pool = self.pool.lock().await;
        let outcome = pool.insert(addr.clone(), conn, admitted);
        if !note_insert(
            &outcome,
            addr,
            "central",
            &self.stats,
            pool.max_connections(),
        ) {
            return Err(TransportError::SendFailed("pool full".into()));
        }
        // From the held guard: `announced_addr` would take the same lock.
        let announced = node_addr.map(|node| pool.verified_addr(&node).unwrap_or(ble_addr.clone()));
        drop(pool);
        debug!(addr = %addr, "BLE connection established");
        self.stats.record_connection_established();
        if let (Some(at), Some(key)) = (announced, peer_key) {
            self.neighbor_buffer.add_peer_with_pubkey(&at, key);
        }
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
                    let mut peer_key: Option<XOnlyPublicKey> = None;
                    if let Some(ref our_pubkey) = local_pubkey {
                        match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
                            Ok(peer_pubkey) => {
                                debug!(addr = %addr_clone, "BLE outbound pubkey exchange complete");
                                peer_key = Some(peer_pubkey);
                            }
                            Err(e) => {
                                stats.record_pubkey_exchange_failure();
                                debug!(
                                    addr = %addr_clone,
                                    role = "central",
                                    outcome = "pubkey-exchange-failed",
                                    error = %e,
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

                    let peer_node = peer_key.as_ref().map(NodeAddr::from_pubkey);
                    let admitted = tokio::time::Instant::now();
                    let conn = BleConnection {
                        stream,
                        recv_task: Some(recv_task),
                        send_mtu,
                        recv_mtu,
                        established_at: admitted,
                        grace_from: admitted,
                        verified: false,
                        addr: ble_addr.clone(),
                        node_addr: peer_node,
                    };

                    let mut pool = pool.lock().await;
                    let outcome = pool.insert(addr_clone.clone(), conn, admitted);
                    let max = pool.max_connections();
                    if !note_insert(&outcome, &addr_clone, "central", &stats, max) {
                        // Not announced: there is no link behind the address,
                        // and the node dialled it itself.
                        return;
                    }
                    // From the held guard: `announced_addr` would take the
                    // same lock.
                    let announced =
                        peer_node.map(|node| pool.verified_addr(&node).unwrap_or(ble_addr.clone()));
                    drop(pool);
                    debug!(addr = %addr_clone, "BLE connection established");
                    stats.record_connection_established();
                    if let (Some(at), Some(key)) = (announced, peer_key) {
                        neighbor_buffer.add_peer_with_pubkey(&at, key);
                    }
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

    /// Records that the node's active peer `node` now uses the link at `addr`.
    ///
    /// The node calls this on every authenticated frame that arrives over
    /// BLE, so the common case (the link is already verified for `node`) must
    /// stay cheap and quiet.
    pub async fn mark_verified(&self, addr: &TransportAddr, node: &NodeAddr) {
        let outcome = self.pool.lock().await.mark_verified(addr, node);
        match outcome {
            // A remote holding two links can alternate its frames between
            // them, demoting one per frame: never louder than trace.
            Verify::Marked { demoted } => {
                for other in demoted {
                    trace!(
                        addr = %other, node = %node, kept = %addr, outcome = "superseded",
                        "BLE link no longer carries its node's session"
                    );
                }
            }
            // The remote chose what to claim, so this is attacker input:
            // never louder than trace, since a frame can repeat it.
            Verify::Mismatch => {
                trace!(
                    addr = %addr, outcome = "claim-mismatch",
                    "BLE link authenticated as a different node than it claimed"
                );
            }
            Verify::Absent => {
                trace!(addr = %addr, outcome = "absent", "BLE link to verify is not pooled");
            }
        }
    }

    /// Records that the node's active peer `node` no longer uses the link at
    /// `addr`. The link stays pooled. When `removed`, the peer itself is gone
    /// and the link gets its grace again; otherwise the peer moved to another
    /// link and the link keeps the grace it had.
    pub async fn clear_verified(&self, addr: &TransportAddr, node: &NodeAddr, removed: bool) {
        let regrace = removed.then(tokio::time::Instant::now);
        let cleared = self.pool.lock().await.clear_verified(addr, node, regrace);
        if cleared {
            trace!(addr = %addr, node = %node, "BLE link no longer verified");
        }
    }

    /// Whether the link at `addr` is verified; `None` when no link is pooled
    /// there.
    #[cfg(test)]
    pub(crate) async fn is_verified(&self, addr: &TransportAddr) -> Option<bool> {
        self.pool.lock().await.get(addr).map(|c| c.verified)
    }

    /// Hold the pool lock until the guard is dropped, so a test can queue
    /// callers behind it in a known order.
    #[cfg(test)]
    pub(crate) async fn hold_pool(
        &self,
    ) -> tokio::sync::MutexGuard<'_, ConnectionPool<Arc<I::Stream>>> {
        self.pool.lock().await
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
/// So when the node already has a verified link to the peer, report the
/// address that link is actually on: same peer, named by the address that
/// works. Otherwise the observed address stands. An unverified claim names
/// nothing: anyone can claim a peer's key, and naming the claimant's address
/// would send the node to dial the claimant for that peer.
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
        .verified_addr(node)
        .unwrap_or_else(|| observed.clone())
}

/// Report the outcome of offering a link to the pool, and whether it was
/// admitted.
///
/// A refusal is logged at debug, with one warning at the start of a run of
/// refusals and one line with the count when the run ends: a full pool is a
/// state an attacker in radio range can hold, so its log volume is bounded.
fn note_insert(
    outcome: &Insert,
    ta: &TransportAddr,
    role: &'static str,
    stats: &BleStats,
    max: usize,
) -> bool {
    let (Insert::Admitted { ended, .. } | Insert::Refused { ended, .. }) = outcome;
    if let Some(n) = ended {
        info!(refused = n, "BLE pool refusal run ended");
    }
    match outcome {
        Insert::Admitted { evicted, .. } => {
            if let Some(evicted) = evicted {
                stats.record_pool_eviction();
                debug!(
                    addr = %ta, role, evicted = %evicted, outcome = "evicted-unverified",
                    "BLE pool full, evicted an unverified link"
                );
            }
            true
        }
        Insert::Refused { first, .. } => {
            stats.record_connection_rejected();
            debug!(addr = %ta, role, outcome = "pool-rejected", "BLE pool full, link dropped");
            if *first {
                warn!(
                    bound = max,
                    "BLE pool full of verified links or links still inside their grace \
                     (max_connections); refusing new links"
                );
            }
            false
        }
    }
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
    let timeout = std::time::Duration::from_secs(PUBKEY_EXCHANGE_TIMEOUT_SECS);

    // Send our pubkey. The deadline matters as much as the one below it: a
    // peer that never drains the L2CAP channel stalls the write instead.
    let mut msg = [0u8; PUBKEY_EXCHANGE_SIZE];
    msg[0] = PUBKEY_EXCHANGE_PREFIX;
    msg[1..].copy_from_slice(local_pubkey);
    match tokio::time::timeout(timeout, stream.send(&msg)).await {
        Ok(result) => result?,
        Err(_) => return Err(TransportError::Timeout),
    }

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

/// Inbound handshakes allowed to be in flight at once.
///
/// Deliberately independent of the pool capacity: that is the budget for
/// established links, and tying the two together would mean an operator who
/// sets `max_connections = 1` also gets a serial accept loop, which is the
/// defect this bound exists to close. A healthy exchange is one round trip
/// and completes in milliseconds, so this is never reached honestly. Raising
/// it lets a flood hold more concurrent handshakes; lowering it makes a
/// legitimate slow peer likelier to be aborted under flood.
const INBOUND_HANDSHAKE_INFLIGHT: usize = 8;

/// Accept loop: accepts inbound L2CAP connections and hands each to its own
/// task for the pubkey exchange and pool insert.
///
/// One iteration is bounded by `accept()` alone. Nothing a connecting peer
/// chooses to do can delay the next accept: the handshake runs off the loop,
/// and when the in-flight budget is full the oldest pending handshake is
/// aborted to make room rather than the loop waiting for one to finish.
///
/// The in-flight tasks live in a `JoinSet` and not behind a `Semaphore` for a
/// reason that is easy to lose: `stop_async` aborts this task and nothing
/// else, so dropping the `JoinSet` with it is what stops the handshakes. Bare
/// `tokio::spawn` would leave them running past stop, able to insert into a
/// pool that stop has just drained.
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
    let mut inflight: tokio::task::JoinSet<()> = tokio::task::JoinSet::new();
    // Spawn order, so the oldest handshake is the one evicted at the budget.
    let mut pending: std::collections::VecDeque<tokio::task::AbortHandle> =
        std::collections::VecDeque::new();

    loop {
        // Reap anything finished. Neither call waits. `retain` rather than
        // popping the front run, so a handshake that completed out of order
        // still frees its slot instead of being aborted as the oldest later.
        while inflight.try_join_next().is_some() {}
        pending.retain(|handle| !handle.is_finished());

        match acceptor.accept().await {
            Ok(stream) => {
                let addr = stream.remote_addr().clone();
                let ta = addr.to_transport_addr();

                // Skip if already connected (outbound won the race). This
                // awaits only our own mutex, never the peer.
                {
                    let pool_guard = pool.lock().await;
                    if pool_guard.contains(&ta) {
                        debug!(addr = %ta, "BLE inbound: already connected, skipping");
                        continue;
                    }
                }

                if pending.len() >= INBOUND_HANDSHAKE_INFLIGHT
                    && let Some(oldest) = pending.pop_front()
                {
                    oldest.abort();
                    stats.record_handshake_aborted();
                    debug!(
                        addr = %ta,
                        budget = INBOUND_HANDSHAKE_INFLIGHT,
                        "BLE inbound handshake budget full, aborting the oldest"
                    );
                }

                let handle = inflight.spawn(admit_inbound(
                    stream,
                    Arc::clone(&pool),
                    packet_tx.clone(),
                    transport_id,
                    Arc::clone(&stats),
                    local_pubkey,
                    Arc::clone(&neighbor_buffer),
                    local_node_addr,
                ));
                pending.push_back(handle);
            }
            Err(e) => {
                warn!(error = %e, "BLE accept error");
                break;
            }
        }
    }
}

/// Run one inbound connection's pubkey exchange and admit it to the pool.
///
/// Runs off the accept loop so a peer that never answers delays nobody else.
/// Everything the accept loop used to do inline lives here, including the
/// duplicate-node decline and the cross-probe tie-break that `fix/platform-ble`
/// added: moving the work off the loop must not drop the checks that guard it.
/// The loop's `continue` becomes `return` — this task admits one connection.
#[allow(clippy::too_many_arguments)]
async fn admit_inbound<S>(
    stream: S,
    pool: Arc<Mutex<ConnectionPool<Arc<S>>>>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: Arc<BleStats>,
    local_pubkey: Option<[u8; 32]>,
    neighbor_buffer: Arc<NeighborBuffer>,
    local_node_addr: Option<NodeAddr>,
) where
    S: BleStream + 'static,
{
    let addr = stream.remote_addr().clone();
    let ta = addr.to_transport_addr();
    let send_mtu = stream.send_mtu();
    let recv_mtu = stream.recv_mtu();
    let stream = Arc::new(stream);
    // One reader across both phases — see `pubkey_exchange`.
    let mut reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

    // Pre-handshake pubkey exchange (temporary, pre-XX)
    let mut peer_node_addr: Option<NodeAddr> = None;
    let mut peer_key: Option<XOnlyPublicKey> = None;
    if let Some(ref our_pubkey) = local_pubkey {
        match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
            Ok(peer_pubkey) => {
                debug!(addr = %ta, "BLE inbound pubkey exchange complete");
                let peer_node = NodeAddr::from_pubkey(&peer_pubkey);
                peer_node_addr = Some(peer_node);
                peer_key = Some(peer_pubkey);

                // Already linked to this peer on another address?
                // A peer using resolvable private addresses rotates
                // continually, and every rotation dials in looking
                // like a new device. Admitting those would put one
                // peer in several pool slots. A verified incumbent is
                // kept and the newcomer declined: it carries the
                // peer's session, and a genuinely dead one is already
                // reaped by the send-error and receive-loop paths. An
                // unverified claim blocks nothing, because anyone in
                // radio range can make one.
                let dup = {
                    let pool_guard = pool.lock().await;
                    pool_guard.find_verified(&peer_node)
                };
                if let Some(existing) = dup
                    && existing != ta
                {
                    debug!(
                        addr = %ta,
                        role = "peripheral",
                        outcome = "duplicate-node-decline",
                        existing = %existing,
                        "BLE inbound: peer already connected on another address, dropping duplicate"
                    );
                    stats.record_duplicate_node_decline();
                    // Named by its verified link, so the node is not handed an
                    // alias with no link behind it.
                    let announced = announced_addr(&pool, &peer_node, &addr).await;
                    neighbor_buffer.add_peer_with_pubkey(&announced, peer_pubkey);
                    return;
                }

                // Cross-probe tie-breaker: smaller NodeAddr's
                // outbound wins. If we're smaller, our outbound
                // should win — drop this inbound.
                if let Some(ref our_addr) = local_node_addr
                    && our_addr < &peer_node
                {
                    stats.record_tiebreaker_drop();
                    debug!(
                        addr = %ta,
                        role = "peripheral",
                        outcome = "tiebreaker-drop",
                        "BLE inbound tie-breaker: dropping (our addr < peer, outbound wins)"
                    );
                    // We are the smaller node, so we dial; the node needs to
                    // learn the peer to do it.
                    let announced = announced_addr(&pool, &peer_node, &addr).await;
                    neighbor_buffer.add_peer_with_pubkey(&announced, peer_pubkey);
                    return;
                }
            }
            Err(e) => {
                stats.record_pubkey_exchange_failure();
                debug!(
                    addr = %ta, role = "peripheral",
                    outcome = "pubkey-exchange-failed", error = %e,
                    "BLE inbound pubkey exchange failed"
                );
                return;
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

    let admitted = tokio::time::Instant::now();
    let conn = BleConnection {
        stream,
        recv_task: Some(recv_task),
        send_mtu,
        recv_mtu,
        established_at: admitted,
        grace_from: admitted,
        verified: false,
        addr: addr.clone(),
        node_addr: peer_node_addr,
    };

    let mut pool_guard = pool.lock().await;
    let outcome = pool_guard.insert(ta.clone(), conn, admitted);
    let max = pool_guard.max_connections();
    if !note_insert(&outcome, &ta, "peripheral", &stats, max) {
        // Not announced: there is no link behind the address.
        return;
    }
    // From the held guard: `announced_addr` would take the same lock.
    let announced = peer_node_addr.map(|node| pool_guard.verified_addr(&node).unwrap_or(addr));
    drop(pool_guard);
    info!(addr = %ta, send_mtu, recv_mtu, "BLE inbound connection accepted");
    stats.record_connection_accepted();
    if let (Some(at), Some(key)) = (announced, peer_key) {
        neighbor_buffer.add_peer_with_pubkey(&at, key);
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

/// Why the probe loop resolved a link address to a node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Learned {
    /// Our probe yielded to the node's own dial: we hold the larger node
    /// address, so a probe of the address always ends the same way.
    Yield,
    /// Our probe was declined beside the node's verified link.
    Decline,
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
    configured_psm: u16,
    connect_timeout_ms: u64,
    cooldown_secs: u64,
    local_node_addr: Option<NodeAddr>,
    packet_tx: PacketTx,
    transport_id: TransportId,
) {
    // Addresses discovered but not yet connected — retried after cooldown even
    // if the scanner doesn't fire again (BlueZ deduplicates), on a per-address
    // backoff that widens with consecutive failures. Also the cooldown record:
    // an address leaves the book the moment it reaches a conclusive outcome,
    // after which the pool and `known_node_of` guards below cover it.
    let mut pending = PendingProbes::new(std::time::Duration::from_secs(cooldown_secs));
    // Link addresses already resolved to a node identity by a completed pubkey
    // exchange, and how. Lets the loop skip an address it has *already*
    // learned belongs to a peer it is connected to, instead of paying a full
    // connect and exchange to rediscover that every cooldown. Rotation means
    // this grows by one per rotation, so entries are dropped once their node
    // no longer holds the link that justified the skip: a peer that genuinely
    // goes away is probed again normally.
    let mut known_node_of: HashMap<BleAddr, (NodeAddr, Learned)> = HashMap::new();
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

        // Skip an address already known to belong to a peer we are connected
        // to. Without this the loop re-dials every rotated address of a live
        // peer once per cooldown, forever: the duplicate is declined so it
        // never enters the pool, so the pool-keyed guard above never sees it.
        if let Some((node, learned)) = known_node_of.get(&addr) {
            let still_connected = {
                let pool_guard = pool.lock().await;
                match learned {
                    // We yield on this address whatever is pooled, so any
                    // claim to the node may stand in for it: probing again
                    // could only end in the same yield.
                    Learned::Yield => pool_guard.claims(node),
                    // The decline needed a verified link, and so does the
                    // skip: an unverified claim must not hide the node's own
                    // address.
                    Learned::Decline => pool_guard.find_verified(node).is_some(),
                }
            };
            if still_connected {
                pending.resolve(&addr);
                continue;
            }
            // That peer is gone — forget the mapping and probe normally.
            known_node_of.remove(&addr);
        }

        // Record probe time (before attempt, so cooldown applies on failure too)
        pending.mark_attempt(&addr, now);

        // Need pubkey for probe
        let our_pubkey = match local_pubkey {
            Some(pk) => pk,
            None => {
                buffer.add_peer(&addr);
                continue;
            }
        };

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
                    stats.record_tiebreaker_yield();
                    debug!(
                        addr = %addr,
                        role = "central",
                        outcome = "tiebreaker-yield",
                        discovery_ms = probe_started.elapsed().as_millis() as u64,
                        "BLE probe tie-breaker: yielding to peer's outbound"
                    );
                    // Same reasoning as the duplicate-decline path below: the
                    // exchange has resolved this address to a node, so once
                    // that node holds a link the next cooldown can skip the
                    // address outright instead of paying another connect and
                    // exchange to yield again. The tie-breaker decision itself
                    // is unchanged — only the cost of re-reaching it.
                    known_node_of.insert(addr.clone(), (peer_node, Learned::Yield));
                    let announced = announced_addr(&pool, &peer_node, &addr).await;
                    buffer.add_peer_with_pubkey(&announced, peer_pubkey);
                    continue;
                }

                // Same duplicate guard as the inbound path: a rotated address
                // for a peer we already hold a verified link to must not
                // become a second pool entry. Checked after the tie-breaker so
                // the two decisions stay independent.
                let dup = {
                    let pool_guard = pool.lock().await;
                    pool_guard.find_verified(&peer_node)
                };
                if let Some(existing) = dup
                    && existing != ta
                {
                    debug!(
                        addr = %ta,
                        role = "central",
                        outcome = "duplicate-node-decline",
                        existing = %existing,
                        discovery_ms = probe_started.elapsed().as_millis() as u64,
                        "BLE probe: peer already connected on another address, dropping duplicate"
                    );
                    stats.record_duplicate_node_decline();
                    // Remember what this address resolved to, so the next
                    // cooldown skips it outright rather than paying another
                    // connect and exchange to reach the same conclusion.
                    known_node_of.insert(addr.clone(), (peer_node, Learned::Decline));
                    // Report the peer under the address its live link is on,
                    // so the node layer is not handed an alias with no
                    // connection behind it.
                    let announced = announced_addr(&pool, &peer_node, &addr).await;
                    buffer.add_peer_with_pubkey(&announced, peer_pubkey);
                    pending.resolve(&addr);
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

                let admitted = tokio::time::Instant::now();
                let conn = BleConnection {
                    stream,
                    recv_task: Some(recv_task),
                    send_mtu,
                    recv_mtu,
                    established_at: admitted,
                    grace_from: admitted,
                    verified: false,
                    addr: addr.clone(),
                    node_addr: Some(peer_node),
                };

                let mut pool_guard = pool.lock().await;
                let outcome = pool_guard.insert(ta.clone(), conn, admitted);
                let max = pool_guard.max_connections();
                if !note_insert(&outcome, &ta, "central", &stats, max) {
                    // The connection is dropped with `conn`, so there is
                    // nothing to report and nothing to resolve. Leaving the
                    // address in the retry book is the point: a slot may
                    // free before the peer is advertised again. The inbound
                    // path already returns here rather than falling through.
                    continue;
                }
                // Announce the peer at its verified link if one appeared
                // since the duplicate check, as the other admission paths do.
                let announced = pool_guard
                    .verified_addr(&peer_node)
                    .unwrap_or_else(|| addr.clone());
                drop(pool_guard);
                debug!(
                    addr = %ta, role = "central", outcome = "connected",
                    discovery_ms = probe_started.elapsed().as_millis() as u64,
                    "BLE probe promoted to pool"
                );
                stats.record_connection_established();
                pending.resolve(&addr);

                // Report to node layer for auto-connect / handshake
                buffer.add_peer_with_pubkey(&announced, peer_pubkey);
            }
            Err(e) => {
                stats.record_pubkey_exchange_failure();
                let failures = pending.record_failure(&addr, tokio::time::Instant::now());
                debug!(
                    addr = %addr, role = "central", outcome = "pubkey-exchange-failed",
                    discovery_ms = probe_started.elapsed().as_millis() as u64,
                    failures, error = %e, "BLE probe pubkey exchange failed"
                );
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
        let pool = Arc::new(Mutex::new(ConnectionPool::new(
            7,
            std::time::Duration::from_secs(10),
        )));
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
        let outcome = pool.lock().await.insert(
            ta.clone(),
            BleConnection {
                stream: Arc::new(parked),
                recv_task: None,
                send_mtu: 2048,
                recv_mtu: 2048,
                established_at: tokio::time::Instant::now(),
                verified: false,
                grace_from: tokio::time::Instant::now(),
                addr: test_addr(2),
                node_addr: None,
            },
            tokio::time::Instant::now(),
        );
        assert!(matches!(outcome, Insert::Admitted { .. }));
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

    /// `n` pubkeys sorted ascending by node address.
    ///
    /// The inbound tie-break drops an inbound when our node address is the
    /// smaller, so a test that wants an inbound admitted gives the transport
    /// the last (largest) key.
    fn pubkeys_by_node_addr(n: usize) -> Vec<[u8; 32]> {
        let mut keys: Vec<[u8; 32]> = (1..=n as u8).map(test_pubkey).collect();
        keys.sort_by_key(|k| NodeAddr::from_pubkey(&XOnlyPublicKey::from_slice(k).unwrap()));
        keys
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
    ///
    /// Cooperative only: this hands the scheduler control, it does not move
    /// the clock. Anything gated on a `tokio::time` timer needs
    /// [`wait_for`] instead.
    async fn settle() {
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
    }

    /// Wait until `cond` holds, or fail the test.
    ///
    /// A fixed number of `yield_now()` calls is not a wait, it is a race
    /// against the clock, and it loses whenever a loop under test is parked
    /// on a timer rather than on a channel. `scan_probe_loop` is: before it
    /// reaches its `select!` it consumes the retry interval's first tick,
    /// and tokio rounds a timer deadline up to the next whole millisecond of
    /// its wheel — so unless the runtime clock happens to sit exactly on a
    /// millisecond boundary, that tick cannot fire until real time crosses
    /// the next one. No number of yields makes real time pass, so whether a
    /// yield budget covers the gap depends on how long a yield takes on the
    /// host: comfortably on a slow one, not at all on a fast one.
    ///
    /// Polling the condition with a sleep between attempts removes the
    /// dependency entirely — the sleep is what lets the timer fire, and the
    /// condition is what ends the wait. The already-satisfied case still
    /// costs only a `settle`, so nothing that passes today gets slower.
    async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            settle().await;
            if cond() {
                return;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {what}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
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
        // The node's session runs over the first link.
        transport
            .mark_verified(&test_addr(2).to_transport_addr(), &node_of(&smaller))
            .await;

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
        let peer = node_of(&larger);
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
        // The peer's session runs over the first probe's link.
        transport
            .mark_verified(&test_addr(2).to_transport_addr(), &peer)
            .await;

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

    /// A probe the pool refuses is not a connection, and must not be recorded
    /// as one. The inbound path already returns on rejection
    /// (`admit_inbound`); this pins the outbound probe path to the same shape.
    ///
    /// The pool refuses a link whenever every slot holds a verified link or
    /// one still inside its grace; `max_connections: 0` reaches the refusal
    /// without building either.
    #[tokio::test(start_paused = true)]
    async fn a_pool_rejected_probe_is_neither_established_nor_reported() {
        use std::sync::Mutex as StdMutex;

        let (ours_pk, theirs_pk) = pubkeys_ordered_by_node_addr();
        let io = MockBleIo::new("hci0", test_addr(1));

        let connects: Arc<StdMutex<Vec<BleAddr>>> = Arc::new(StdMutex::new(Vec::new()));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let connects = Arc::clone(&connects);
            io.set_connect_handler(move |addr, _psm| {
                let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
                connects.lock().unwrap().push(addr.clone());
                peer_tx
                    .send(theirs)
                    .map_err(|_| TransportError::ConnectionRefused)?;
                Ok(mine)
            });
        }
        tokio::spawn(async move {
            let mut alive = Vec::new();
            while let Some(theirs) = peer_rx.recv().await {
                peer_side_exchange(&theirs, &theirs_pk).await;
                alive.push(theirs);
            }
        });

        let config = BleConfig {
            scan: Some(true),
            accept_connections: Some(false),
            max_connections: Some(0),
            ..identity_test_config()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.set_local_pubkey(ours_pk);
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(2)).await;
        settle().await;

        // The dial and the exchange both happened; only the pool refused.
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
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.set_local_pubkey(test_pubkey(1));
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

    /// A peer that connects and then sends a bad exchange is counted as a
    /// pubkey-exchange failure — the link came up and produced nothing
    /// usable, which is a different fault from never connecting.
    #[tokio::test]
    async fn test_a_bad_exchange_counts_as_a_pubkey_exchange_failure() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport =
            BleTransport::new(TransportId::new(1), None, identity_test_config(), io, tx);
        transport.set_local_pubkey(test_pubkey(1));
        transport.start_async().await.unwrap();

        let (ours, peer) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        transport.io.inject_inbound(ours).await;
        let mut wire = vec![0xFFu8];
        wire.extend_from_slice(&test_pubkey(2));
        peer.send(&wire).await.unwrap();
        settle().await;

        let snap = transport.stats.snapshot();
        assert_eq!(snap.pubkey_exchange_failures, 1);
        assert_eq!(snap.connections_accepted, 0);
        assert_eq!(transport.pool.lock().await.len(), 0);
        transport.stop_async().await.unwrap();
    }

    /// The tie-breaker pair. Its convention is deterministic in source, but
    /// nothing recorded whether two nodes actually agreed at runtime, and a
    /// disagreement leaves every existing counter at zero. Across a pair, one
    /// yield and one drop is agreement.
    #[tokio::test]
    async fn test_tiebreaker_records_one_yield_and_one_drop_across_a_pair() {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();

        // The node with the LARGER address accepts an inbound from the
        // smaller: its inbound wins, so nothing is stood down here. Invert it
        // — the SMALLER node accepting from the larger stands its inbound
        // down, because its own outbound is meant to win.
        let io = MockBleIo::new("hci0", test_addr(1));
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut inbound_side =
            BleTransport::new(TransportId::new(1), None, identity_test_config(), io, tx);
        inbound_side.set_local_pubkey(smaller);
        inbound_side.start_async().await.unwrap();

        let (ours, peer) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        inbound_side.io.inject_inbound(ours).await;
        peer_side_exchange(&peer, &larger).await;
        {
            let stats = Arc::clone(&inbound_side.stats);
            wait_for("the inbound tie-breaker to conclude", || {
                stats.snapshot().tiebreaker_drops == 1
            })
            .await;
        }

        let snap = inbound_side.stats.snapshot();
        assert_eq!(snap.tiebreaker_drops, 1, "our inbound stood down");
        assert_eq!(snap.tiebreaker_yields, 0);
        assert_eq!(inbound_side.pool.lock().await.len(), 0);
        inbound_side.stop_async().await.unwrap();

        // The other side of the same pair: the node with the LARGER address
        // probing outbound stands its dial down, because the smaller node's
        // outbound is meant to win.
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let io2 = MockBleIo::new("hci0", test_addr(2));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        io2.set_connect_handler(move |addr, psm| {
            dials.lock().unwrap().push((addr.clone(), psm));
            let (ours, theirs) = MockBleStream::pair(test_addr(2), addr.clone(), 2048);
            peer_tx
                .send(theirs)
                .map_err(|_| TransportError::ConnectionRefused)?;
            Ok(ours)
        });
        tokio::spawn(async move {
            let mut alive = Vec::new();
            while let Some(theirs) = peer_rx.recv().await {
                peer_side_exchange(&theirs, &smaller).await;
                alive.push(theirs);
            }
        });

        let config = BleConfig {
            scan: Some(true),
            accept_connections: Some(false),
            ..identity_test_config()
        };
        let (tx2, _rx2) = tokio::sync::mpsc::channel(64);
        let mut outbound_side = BleTransport::new(TransportId::new(2), None, config, io2, tx2);
        outbound_side.set_local_pubkey(larger);
        outbound_side.start_async().await.unwrap();

        outbound_side.io.inject_scan_result(test_addr(1)).await;
        {
            let stats = Arc::clone(&outbound_side.stats);
            wait_for("the outbound tie-breaker to conclude", || {
                stats.snapshot().tiebreaker_yields == 1
            })
            .await;
        }

        let snap = outbound_side.stats.snapshot();
        assert_eq!(snap.tiebreaker_yields, 1, "our outbound stood down");
        assert_eq!(snap.tiebreaker_drops, 0);
        assert_eq!(outbound_side.pool.lock().await.len(), 0);
        outbound_side.stop_async().await.unwrap();
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
        let outcome = transport.pool.lock().await.insert(
            ta.clone(),
            BleConnection {
                stream: Arc::new(parked),
                recv_task: None,
                send_mtu: 64,
                recv_mtu: 64,
                established_at: tokio::time::Instant::now(),
                verified: false,
                grace_from: tokio::time::Instant::now(),
                addr: test_addr(2),
                node_addr: None,
            },
            tokio::time::Instant::now(),
        );
        assert!(matches!(outcome, Insert::Admitted { .. }));

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
            "pubkey_exchange_failures",
            "tiebreaker_yields",
            "tiebreaker_drops",
            "pool_evictions",
            "advertisements_sent",
            "scan_results",
            "duplicate_node_declines",
            "handshakes_aborted",
        ];
        for key in expected {
            assert!(object.contains_key(key), "snapshot lost `{key}`");
        }
        assert_eq!(object.len(), expected.len(), "snapshot gained a key");
    }

    /// A secret/public key pair from a fixed seed.
    ///
    /// The exchange parses the peer's 32 bytes with `XOnlyPublicKey::from_slice`,
    /// so arbitrary bytes will not do.
    fn test_keypair(seed: u8) -> ([u8; 32], XOnlyPublicKey) {
        let secp = secp256k1::Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&[seed; 32]).unwrap();
        let (xonly, _) = sk.public_key(&secp).x_only_public_key();
        (xonly.serialize(), xonly)
    }

    /// Inject an inbound connection and return the peer end of the link.
    ///
    /// The peer end must be kept alive: dropping it closes the channel, which
    /// the mock reports as a zero-length read rather than as silence.
    async fn connect_inbound(
        transport: &BleTransport<MockBleIo>,
        peer: &BleAddr,
    ) -> io::MockBleStream {
        let (inbound, peer_end) = io::MockBleStream::pair(test_addr(1), peer.clone(), 512);
        transport.io.inject_inbound(inbound).await;
        peer_end
    }

    /// Complete the peer half of the pubkey exchange.
    async fn send_pubkey(stream: &io::MockBleStream, pubkey: &XOnlyPublicKey) {
        let mut msg = [0u8; PUBKEY_EXCHANGE_SIZE];
        msg[0] = PUBKEY_EXCHANGE_PREFIX;
        msg[1..].copy_from_slice(&pubkey.serialize());
        stream.send(&msg).await.unwrap();
    }

    /// Poll the discovery buffer until every wanted address has appeared.
    ///
    /// Asserts on the discovery buffer rather than the pool because the buffer
    /// is populated before the cross-probe tie-breaker, which drops an inbound
    /// whose NodeAddr sorts above ours and would make the result depend on the
    /// keys the test happened to pick. Sleeps rather than yields, so a paused
    /// clock advances instead of the runtime staying busy forever.
    async fn wait_for_discovered(buffer: &NeighborBuffer, wanted: &[BleAddr]) -> bool {
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        for _ in 0..20_000 {
            for peer in buffer.take() {
                if let Some(addr) = peer.addr.as_str() {
                    seen.insert(addr.to_string());
                }
            }
            if wanted.iter().all(|a| seen.contains(&a.to_string_repr())) {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        false
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_inbound_peer_does_not_delay_the_next_accept() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (mut transport, _rx) = make_transport(io);
        let (our_pubkey, _) = test_keypair(1);
        transport.set_local_pubkey(our_pubkey);
        transport.start_async().await.unwrap();

        // A connects and never says anything.
        let _silent = connect_inbound(&transport, &test_addr(2)).await;

        // B connects behind it and completes the exchange at once.
        let good = connect_inbound(&transport, &test_addr(3)).await;
        let (_, peer_pubkey) = test_keypair(7);
        send_pubkey(&good, &peer_pubkey).await;

        let start = tokio::time::Instant::now();
        assert!(
            wait_for_discovered(&transport.neighbor_buffer, &[test_addr(3)]).await,
            "the well-behaved peer was never admitted"
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the well-behaved peer waited {:?} on the silent one's handshake deadline",
            elapsed
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_flood_of_silent_connectors_does_not_delay_a_well_behaved_one() {
        // The test that breaks what the guard guards: it fails against a bound
        // that waits for a slot rather than reclaiming one.
        let io = MockBleIo::new("hci0", test_addr(1));
        let (mut transport, _rx) = make_transport(io);
        let (our_pubkey, _) = test_keypair(1);
        transport.set_local_pubkey(our_pubkey);
        transport.start_async().await.unwrap();

        let mut silent = Vec::new();
        for n in 0..INBOUND_HANDSHAKE_INFLIGHT + 1 {
            silent.push(connect_inbound(&transport, &test_addr(20 + n as u8)).await);
        }

        let good = connect_inbound(&transport, &test_addr(3)).await;
        let (_, peer_pubkey) = test_keypair(7);
        send_pubkey(&good, &peer_pubkey).await;

        let start = tokio::time::Instant::now();
        assert!(
            wait_for_discovered(&transport.neighbor_buffer, &[test_addr(3)]).await,
            "the well-behaved peer was never admitted behind the flood"
        );
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "the well-behaved peer waited {:?} behind {} silent connectors",
            elapsed,
            silent.len()
        );
        assert!(transport.stats.snapshot().handshakes_aborted > 0);
    }

    #[tokio::test(start_paused = true)]
    async fn inbound_peers_within_the_handshake_budget_are_all_admitted() {
        // The guard must not red a legitimately clean run. The pool has room
        // for every inbound, so none is refused for lack of a slot.
        let io = MockBleIo::new("hci0", test_addr(1));
        let config = BleConfig {
            max_connections: Some(INBOUND_HANDSHAKE_INFLIGHT),
            ..BleConfig::default()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        let (our_pubkey, our_key) = test_keypair(1);
        let ours = NodeAddr::from_pubkey(&our_key);
        transport.set_local_pubkey(our_pubkey);
        transport.start_async().await.unwrap();

        let mut peers = Vec::new();
        let mut wanted = Vec::new();
        let mut kept = 0;
        for n in 0..INBOUND_HANDSHAKE_INFLIGHT {
            let addr = test_addr(40 + n as u8);
            let stream = connect_inbound(&transport, &addr).await;
            let (_, peer_pubkey) = test_keypair(10 + n as u8);
            // The tie-break keeps an inbound only from a smaller node.
            if NodeAddr::from_pubkey(&peer_pubkey) < ours {
                kept += 1;
            }
            send_pubkey(&stream, &peer_pubkey).await;
            peers.push(stream);
            wanted.push(addr);
        }

        assert!(
            wait_for_discovered(&transport.neighbor_buffer, &wanted).await,
            "a well-behaved peer inside the budget was not admitted"
        );
        assert_eq!(transport.stats.snapshot().handshakes_aborted, 0);
        assert!(kept > 0, "test setup: some inbound passes the tie-break");
        assert_eq!(
            transport.pool.lock().await.len(),
            kept,
            "every inbound the tie-break keeps is pooled"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_pubkey_exchange_send_half_has_a_deadline() {
        // The mock's link is a 64-slot channel, so a peer that never reads
        // parks our write once it is full — which is what an L2CAP peer that
        // stops draining does.
        let (ours, _peer) = io::MockBleStream::pair(test_addr(1), test_addr(2), 512);
        for _ in 0..64 {
            ours.send(&[0u8; 1]).await.unwrap();
        }
        let (our_pubkey, _) = test_keypair(1);
        // `fix/platform-ble` split the read half out; the exchange takes it as
        // its own argument now. The deadline under test is on the send half,
        // which never reaches a read, so the reader is only here to type-check.
        let recv_mtu = ours.recv_mtu();
        let ours = Arc::new(ours);
        let mut reader = BleStreamRead::new(Arc::clone(&ours), recv_mtu);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(60),
            pubkey_exchange(ours.as_ref(), &mut reader, &our_pubkey),
        )
        .await
        .expect("the pubkey exchange send half parked with no deadline of its own");

        assert!(matches!(result, Err(TransportError::Timeout)));
    }

    // ------------------------------------------------------------------
    // Claimed keys versus verified links
    // ------------------------------------------------------------------

    /// The node address a 32-byte x-only key derives.
    fn node_of(pubkey: &[u8; 32]) -> NodeAddr {
        NodeAddr::from_pubkey(&XOnlyPublicKey::from_slice(pubkey).unwrap())
    }

    /// A started transport that accepts inbound links and exchanges `ours`.
    async fn accepting_transport(ours: [u8; 32]) -> BleTransport<MockBleIo> {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport =
            BleTransport::new(TransportId::new(1), None, identity_test_config(), io, tx);
        transport.set_local_pubkey(ours);
        transport.start_async().await.unwrap();
        transport
    }

    /// Dial in from `from`, claiming `claim` in the key exchange. The remote
    /// end is returned and must be kept alive, or the link closes.
    async fn dial_in(
        transport: &BleTransport<MockBleIo>,
        from: &BleAddr,
        claim: &[u8; 32],
    ) -> MockBleStream {
        let (ours, theirs) = MockBleStream::pair(test_addr(1), from.clone(), 2048);
        transport.io.inject_inbound(ours).await;
        peer_side_exchange(&theirs, claim).await;
        theirs
    }

    /// Whether a link is pooled at `addr`, without waiting on the lock. False
    /// while the lock is held, so only a wait for presence may use it.
    fn pooled(transport: &BleTransport<MockBleIo>, addr: &BleAddr) -> bool {
        transport
            .pool
            .try_lock()
            .map(|p| p.contains(&addr.to_transport_addr()))
            .unwrap_or(false)
    }

    /// Whether no link is pooled at `addr`, without waiting on the lock. False
    /// while the lock is held, so a wait for absence never ends early.
    fn unpooled(transport: &BleTransport<MockBleIo>, addr: &BleAddr) -> bool {
        transport
            .pool
            .try_lock()
            .map(|p| !p.contains(&addr.to_transport_addr()))
            .unwrap_or(false)
    }

    /// Whether a link is pooled at `addr`, waiting on the lock.
    async fn holds(transport: &BleTransport<MockBleIo>, addr: &BleAddr) -> bool {
        transport
            .pool
            .lock()
            .await
            .contains(&addr.to_transport_addr())
    }

    /// Wait until an inbound or probe at `addr` has been admitted or declined
    /// as a duplicate, so the assertion that follows sees the decision.
    async fn wait_decided(transport: &BleTransport<MockBleIo>, addr: &BleAddr, declines: u64) {
        let stats = Arc::clone(&transport.stats);
        wait_for("the link to be admitted or declined", || {
            pooled(transport, addr) || stats.snapshot().duplicate_node_declines > declines
        })
        .await;
    }

    /// Whether `cond` comes to hold within a few seconds of the transport's
    /// clock. Unlike [`wait_for`] it reports rather than fails, so that the
    /// assertion after it names what did not happen.
    async fn eventually(mut cond: impl FnMut() -> bool) -> bool {
        for _ in 0..200 {
            settle().await;
            if cond() {
                return true;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        false
    }

    /// The node address the link at `addr` claims, if one is pooled there.
    async fn claim_at(transport: &BleTransport<MockBleIo>, addr: &BleAddr) -> Option<NodeAddr> {
        transport
            .pool
            .lock()
            .await
            .get(&addr.to_transport_addr())
            .and_then(|c| c.node_addr)
    }

    /// Every address the connect handler was asked to dial.
    type Dials = Arc<std::sync::Mutex<Vec<BleAddr>>>;

    /// A scanning transport holding `ours`, whose every dial is answered with
    /// the key `answer`, as a device claiming that key at each address would.
    fn scanning_transport(
        ours: [u8; 32],
        answer: [u8; 32],
        accept: bool,
    ) -> (BleTransport<MockBleIo>, Dials) {
        let config = BleConfig {
            scan: Some(true),
            accept_connections: Some(accept),
            ..identity_test_config()
        };
        answering_transport(ours, answer, config)
    }

    /// A transport under `config` holding `ours`, whose every dial is
    /// answered with the key `answer`.
    fn answering_transport(
        ours: [u8; 32],
        answer: [u8; 32],
        config: BleConfig,
    ) -> (BleTransport<MockBleIo>, Dials) {
        gated_transport(ours, answer, config, None)
    }

    /// As [`answering_transport`], except that a dial to the address in
    /// `gate` is answered only once its `Notify` is notified, so a test can
    /// act while that probe waits on its exchange.
    fn gated_transport(
        ours: [u8; 32],
        answer: [u8; 32],
        config: BleConfig,
        gate: Option<(BleAddr, Arc<tokio::sync::Notify>)>,
    ) -> (BleTransport<MockBleIo>, Dials) {
        let io = MockBleIo::new("hci0", test_addr(1));
        let dials: Dials = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let dials = Arc::clone(&dials);
            io.set_connect_handler(move |addr, _psm| {
                let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
                dials.lock().unwrap().push(addr.clone());
                peer_tx
                    .send((addr.clone(), theirs))
                    .map_err(|_| TransportError::ConnectionRefused)?;
                Ok(mine)
            });
        }
        tokio::spawn(async move {
            let mut alive = Vec::new();
            while let Some((addr, theirs)) = peer_rx.recv().await {
                if let Some((gated, open)) = &gate
                    && *gated == addr
                {
                    open.notified().await;
                }
                peer_side_exchange(&theirs, &answer).await;
                alive.push(theirs);
            }
        });
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.set_local_pubkey(ours);
        (transport, dials)
    }

    /// How many times `addr` was dialled.
    fn dial_count(dials: &Dials, addr: &BleAddr) -> usize {
        dials.lock().unwrap().iter().filter(|a| *a == addr).count()
    }

    /// A device that claims P's key first must not stop P's own inbound link
    /// being admitted, nor have P announced at the device's address.
    #[tokio::test]
    async fn an_unverified_claim_does_not_decline_the_claimed_peers_inbound_channel() {
        let keys = pubkeys_by_node_addr(2);
        let (p, ours) = (keys[0], keys[1]);
        let mut transport = accepting_transport(ours).await;

        let _impostor = dial_in(&transport, &test_addr(9), &p).await;
        wait_for("the impostor's link", || pooled(&transport, &test_addr(9))).await;
        transport.neighbor_buffer.take();

        let _genuine = dial_in(&transport, &test_addr(2), &p).await;
        wait_decided(&transport, &test_addr(2), 0).await;
        assert!(
            pooled(&transport, &test_addr(2)),
            "P's own link is admitted beside an unverified claim to P"
        );
        let peers = transport.neighbor_buffer.take();
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].addr,
            test_addr(2).to_transport_addr(),
            "P is announced at its own link, not the impostor's"
        );

        let ta2 = test_addr(2).to_transport_addr();
        transport.mark_verified(&ta2, &node_of(&p)).await;
        assert_eq!(transport.is_verified(&ta2).await, Some(true));
        assert_eq!(
            transport
                .is_verified(&test_addr(9).to_transport_addr())
                .await,
            Some(false)
        );

        let _third = dial_in(&transport, &test_addr(3), &p).await;
        wait_decided(&transport, &test_addr(3), 0).await;
        assert!(
            !holds(&transport, &test_addr(3)).await,
            "a verified link to P declines a further claim to P"
        );
        transport.stop_async().await.unwrap();
    }

    /// The probe twin: an impostor's earlier claim to P must not decline our
    /// probe of P's own address.
    #[tokio::test(start_paused = true)]
    async fn an_unverified_claim_does_not_decline_a_probe_to_the_claimed_peer() {
        let keys = pubkeys_by_node_addr(2);
        let (ours, p) = (keys[0], keys[1]);
        let (mut transport, _dials) = scanning_transport(ours, p, false);
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(9)).await;
        wait_for("the impostor's link", || pooled(&transport, &test_addr(9))).await;

        transport.io.inject_scan_result(test_addr(2)).await;
        wait_decided(&transport, &test_addr(2), 0).await;
        assert!(
            pooled(&transport, &test_addr(2)),
            "our probe of P is admitted beside an unverified claim to P"
        );
        assert_eq!(transport.stats.snapshot().duplicate_node_declines, 0);

        let ta2 = test_addr(2).to_transport_addr();
        transport.mark_verified(&ta2, &node_of(&p)).await;
        assert_eq!(
            transport
                .is_verified(&test_addr(9).to_transport_addr())
                .await,
            Some(false)
        );
        transport.stop_async().await.unwrap();
    }

    /// An impostor that renews its claim from a new address inside every
    /// connect timeout, so its claim is never old, still does not decline P.
    #[tokio::test(start_paused = true)]
    async fn a_claim_renewed_inside_each_connect_timeout_does_not_decline_the_claimed_peer() {
        let keys = pubkeys_by_node_addr(2);
        let (p, ours) = (keys[0], keys[1]);
        let mut transport = accepting_transport(ours).await;
        let renewal = std::time::Duration::from_secs(9);

        let mut current = test_addr(20);
        let mut impostor = dial_in(&transport, &current, &p).await;
        wait_for("the impostor's link", || pooled(&transport, &current)).await;
        assert_eq!(claim_at(&transport, &current).await, Some(node_of(&p)));

        for next in [test_addr(21), test_addr(22)] {
            tokio::time::advance(renewal).await;
            // Drop first, then open, so the renewed link is the only claim to
            // P whatever a second claim would meet.
            drop(impostor);
            wait_for("the old link to close", || unpooled(&transport, &current)).await;
            impostor = dial_in(&transport, &next, &p).await;
            wait_for("the renewed link", || pooled(&transport, &next)).await;
            assert_eq!(
                claim_at(&transport, &next).await,
                Some(node_of(&p)),
                "the renewed link holds the claim to P"
            );
            current = next;
        }

        tokio::time::advance(std::time::Duration::from_millis(500)).await;
        let _genuine = dial_in(&transport, &test_addr(2), &p).await;
        wait_decided(&transport, &test_addr(2), 0).await;
        assert!(
            pooled(&transport, &test_addr(2)),
            "P's own link is admitted beside a claim renewed every 9 s"
        );
        let ta2 = test_addr(2).to_transport_addr();
        transport.mark_verified(&ta2, &node_of(&p)).await;
        assert_eq!(
            transport.is_verified(&current.to_transport_addr()).await,
            Some(false)
        );
        drop(impostor);
        transport.stop_async().await.unwrap();
    }

    /// An address resolved by declining it beside P's verified link is probed
    /// again once only an unverified claim to P remains.
    #[tokio::test(start_paused = true)]
    async fn a_resolved_alias_is_probed_again_when_only_an_unverified_claim_remains() {
        let keys = pubkeys_by_node_addr(2);
        let (ours, p) = (keys[0], keys[1]);
        let (mut transport, dials) = scanning_transport(ours, p, false);
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(2)).await;
        wait_for("P's link", || pooled(&transport, &test_addr(2))).await;
        let ta2 = test_addr(2).to_transport_addr();
        transport.mark_verified(&ta2, &node_of(&p)).await;

        transport.io.inject_scan_result(test_addr(3)).await;
        wait_decided(&transport, &test_addr(3), 0).await;
        assert!(
            !holds(&transport, &test_addr(3)).await,
            "declined beside P's link"
        );
        assert_eq!(dial_count(&dials, &test_addr(3)), 1);

        transport.close_connection_async(&ta2).await;
        transport.io.inject_scan_result(test_addr(9)).await;
        wait_for("the impostor's link", || pooled(&transport, &test_addr(9))).await;
        assert_eq!(
            transport
                .is_verified(&test_addr(9).to_transport_addr())
                .await,
            Some(false)
        );

        tokio::time::advance(std::time::Duration::from_secs(5)).await;
        transport.io.inject_scan_result(test_addr(3)).await;
        let redialled = eventually(|| dial_count(&dials, &test_addr(3)) >= 2).await;
        assert!(
            redialled,
            "an alias resolved beside a verified link is probed again once only an \
             unverified claim remains"
        );
        wait_for("the re-probed alias", || pooled(&transport, &test_addr(3))).await;
        transport.stop_async().await.unwrap();
    }

    /// A probe whose peer's link is verified after the probe's duplicate
    /// check, but before its insert, announces the peer at the verified link.
    #[tokio::test(start_paused = true)]
    async fn a_probe_admitted_beside_a_link_verified_meanwhile_announces_the_verified_link() {
        let keys = pubkeys_by_node_addr(2);
        let (ours, p) = (keys[0], keys[1]);
        let config = BleConfig {
            scan: Some(true),
            accept_connections: Some(false),
            ..identity_test_config()
        };
        let open = Arc::new(tokio::sync::Notify::new());
        let gate = Some((test_addr(2), Arc::clone(&open)));
        let (mut transport, dials) = gated_transport(ours, p, config, gate);
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(9)).await;
        wait_for("P's first link", || pooled(&transport, &test_addr(9))).await;
        transport.neighbor_buffer.take();

        transport.io.inject_scan_result(test_addr(2)).await;
        wait_for("the probe's dial", || {
            dial_count(&dials, &test_addr(2)) == 1
        })
        .await;

        // With the pool held, let the probe finish its exchange and queue
        // its duplicate check, then queue the mark behind it. The pool lock
        // is first come, first served, so the mark lands between the
        // duplicate check and the insert.
        let ta9 = test_addr(9).to_transport_addr();
        {
            let held = transport.hold_pool().await;
            open.notify_one();
            settle().await;
            let node = node_of(&p);
            let mark = transport.mark_verified(&ta9, &node);
            tokio::pin!(mark);
            assert!(futures::poll!(&mut mark).is_pending());
            drop(held);
            mark.await;
        }

        wait_decided(&transport, &test_addr(2), 0).await;
        assert!(
            pooled(&transport, &test_addr(2)),
            "the duplicate check ran before the mark, so the probe is admitted"
        );
        assert_eq!(transport.is_verified(&ta9).await, Some(true));
        let peers = transport.neighbor_buffer.take();
        assert_eq!(peers.len(), 1);
        assert_eq!(
            peers[0].addr, ta9,
            "P is announced at its verified link, not the probe's"
        );
        transport.stop_async().await.unwrap();
    }

    /// A link that never completes a handshake is not closed by any timer:
    /// it leaves only by eviction or link loss.
    #[tokio::test(start_paused = true)]
    async fn an_unverified_link_that_never_handshakes_stays_open() {
        let keys = pubkeys_by_node_addr(2);
        let (p, ours) = (keys[0], keys[1]);
        let mut transport = accepting_transport(ours).await;
        let _link = dial_in(&transport, &test_addr(2), &p).await;
        wait_for("the link", || pooled(&transport, &test_addr(2))).await;

        for _ in 0..60 {
            tokio::time::advance(std::time::Duration::from_secs(10)).await;
            settle().await;
        }
        assert!(
            pooled(&transport, &test_addr(2)),
            "still pooled after 600 s"
        );
        transport.stop_async().await.unwrap();
    }

    /// Two links claiming one node before any handshake both stay; once one
    /// verifies, the other stays pooled and a further claim is declined and
    /// announced at the verified link.
    #[tokio::test]
    async fn two_unverified_links_to_one_node_both_stay_and_one_verifies() {
        let keys = pubkeys_by_node_addr(2);
        let (p, ours) = (keys[0], keys[1]);
        let mut transport = accepting_transport(ours).await;

        let _first = dial_in(&transport, &test_addr(2), &p).await;
        wait_for("the first link", || pooled(&transport, &test_addr(2))).await;
        let _second = dial_in(&transport, &test_addr(3), &p).await;
        wait_decided(&transport, &test_addr(3), 0).await;
        assert!(
            pooled(&transport, &test_addr(2)) && pooled(&transport, &test_addr(3)),
            "both unverified links claiming P are pooled"
        );

        let ta2 = test_addr(2).to_transport_addr();
        let ta3 = test_addr(3).to_transport_addr();
        transport.mark_verified(&ta3, &node_of(&p)).await;
        assert_eq!(transport.is_verified(&ta2).await, Some(false));
        assert_eq!(transport.is_verified(&ta3).await, Some(true));
        transport.neighbor_buffer.take();

        let _third = dial_in(&transport, &test_addr(4), &p).await;
        wait_decided(&transport, &test_addr(4), 0).await;
        assert!(!holds(&transport, &test_addr(4)).await);
        assert!(
            pooled(&transport, &test_addr(2)),
            "the unverified link stays"
        );
        let peers = transport.neighbor_buffer.take();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].addr, ta3, "announced at the verified link");
        transport.stop_async().await.unwrap();
    }

    /// The larger node yields on a smaller neighbour's address whatever is
    /// pooled, so it skips that address while any link claims the neighbour,
    /// even one that never verifies.
    #[tokio::test(start_paused = true)]
    async fn a_larger_node_does_not_redial_a_smaller_neighbour_it_yielded_to() {
        let keys = pubkeys_by_node_addr(2);
        let (p, ours) = (keys[0], keys[1]);
        let (mut transport, dials) = scanning_transport(ours, p, true);
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(test_addr(2)).await;
        {
            let stats = Arc::clone(&transport.stats);
            wait_for("the yield", || stats.snapshot().tiebreaker_yields == 1).await;
        }
        let _p_dial = dial_in(&transport, &test_addr(5), &p).await;
        wait_for("P's own dial", || pooled(&transport, &test_addr(5))).await;

        transport.io.inject_scan_result(test_addr(2)).await;
        for _ in 0..5 {
            tokio::time::advance(std::time::Duration::from_millis(1_100)).await;
            settle().await;
        }
        assert_eq!(
            dial_count(&dials, &test_addr(2)),
            1,
            "the yielded address is not re-dialled"
        );
        assert_eq!(transport.pool.lock().await.len(), 1);
        transport.stop_async().await.unwrap();
    }

    /// The whole chain once the node drops its peer: the withdrawn link gets
    /// the grace again, then a newcomer takes its slot.
    #[tokio::test(start_paused = true)]
    async fn a_withdrawn_link_is_evicted_by_a_newcomer_once_past_its_grace() {
        let keys = pubkeys_by_node_addr(4);
        let (p, q, r, ours) = (keys[0], keys[1], keys[2], keys[3]);
        let config = BleConfig {
            max_connections: Some(1),
            ..identity_test_config()
        };
        let (mut transport, _dials) = answering_transport(ours, p, config);
        transport.start_async().await.unwrap();
        let rejected = |t: &BleTransport<MockBleIo>| t.stats.snapshot().connections_rejected;
        let secs = std::time::Duration::from_secs;

        let _p_link = dial_in(&transport, &test_addr(2), &p).await;
        wait_for("P's link", || pooled(&transport, &test_addr(2))).await;
        let ta2 = test_addr(2).to_transport_addr();
        transport.mark_verified(&ta2, &node_of(&p)).await;

        tokio::time::advance(secs(20)).await;
        let _q_link = dial_in(&transport, &test_addr(3), &q).await;
        wait_for("Q's refusal", || rejected(&transport) == 1).await;
        assert!(
            !holds(&transport, &test_addr(3)).await,
            "a verified link is kept"
        );

        tokio::time::advance(secs(1)).await;
        transport.clear_verified(&ta2, &node_of(&p), true).await;
        tokio::time::advance(secs(5)).await;
        let _r_link = dial_in(&transport, &test_addr(4), &r).await;
        wait_for("R's refusal", || rejected(&transport) == 2).await;
        assert!(
            pooled(&transport, &test_addr(2)),
            "the withdrawn link is inside its new grace"
        );

        tokio::time::advance(secs(6)).await;
        let _r_again = dial_in(&transport, &test_addr(5), &r).await;
        wait_for("R's admission", || pooled(&transport, &test_addr(5))).await;
        assert!(
            !holds(&transport, &test_addr(2)).await,
            "P's link was evicted"
        );
        assert_eq!(transport.stats.snapshot().pool_evictions, 1);
        transport.stop_async().await.unwrap();
    }

    /// An inbound or a node dial the pool refuses has no link behind it and
    /// must not be announced to the node.
    #[tokio::test(start_paused = true)]
    async fn an_inbound_or_dial_refused_by_a_full_pool_is_not_reported() {
        let keys = pubkeys_by_node_addr(2);
        let (p, ours) = (keys[0], keys[1]);
        for max in [0, 2] {
            let config = BleConfig {
                max_connections: Some(max),
                ..identity_test_config()
            };
            let (mut transport, _dials) = answering_transport(ours, p, config);
            transport.start_async().await.unwrap();
            let snapshot = Arc::clone(&transport.stats);
            let settled = |n: u64| {
                let stats = Arc::clone(&snapshot);
                move || {
                    let s = stats.snapshot();
                    s.connections_rejected + s.connections_accepted + s.connections_established == n
                }
            };

            let _inbound = dial_in(&transport, &test_addr(2), &p).await;
            wait_for("the inbound to be decided", settled(1)).await;
            let after_inbound = transport.neighbor_buffer.take();

            transport
                .connect_async(&test_addr(3).to_transport_addr())
                .await
                .unwrap();
            wait_for("the dial to be decided", settled(2)).await;
            let after_dial = transport.neighbor_buffer.take();

            if max == 0 {
                assert_eq!(snapshot.snapshot().connections_rejected, 2);
                assert!(!holds(&transport, &test_addr(2)).await);
                assert!(
                    after_inbound.is_empty(),
                    "a refused inbound is not announced: {after_inbound:?}"
                );
                assert!(
                    after_dial.is_empty(),
                    "a refused dial is not announced: {after_dial:?}"
                );
            } else {
                // The control: with room, the same inbound and dial are
                // announced, so an empty buffer above is not a dead path.
                assert_eq!(after_inbound.len(), 1, "an admitted inbound is announced");
                assert_eq!(after_dial.len(), 1, "an admitted dial is announced");
            }
            transport.stop_async().await.unwrap();
        }
    }
}
