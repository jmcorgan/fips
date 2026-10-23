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
//! `cfg(bluer_available)`), [`io_radio::RadioIo`] drives a radio operated
//! through commands and callbacks — the Android embedder's, or macOS's
//! CoreBluetooth via [`io_macos`] — and `MockBleIo` is an in-memory double
//! for tests without hardware. Which one `DefaultBleTransport` resolves to is decided
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
/// The Android names for [`io_radio`], kept for the embedder API.
#[cfg(any(target_os = "android", test))]
pub mod io_android;
#[cfg(bluer_available)]
pub mod io_linux;
/// The CoreBluetooth backend.
///
/// Compiled under `cfg(test)` on every host, like [`io_radio`]: everything in
/// it that is not a CoreBluetooth call — the dial PSM decision, address
/// mapping, the stream pumps — is platform-neutral and tested anywhere. Only
/// its `corebluetooth` submodule is macOS-only.
#[cfg(any(target_os = "macos", test))]
pub mod io_macos;
/// A backend over a radio driven through commands and callbacks rather than
/// opened in process: the Android embedder's, or macOS's CoreBluetooth.
///
/// Compiled under `cfg(test)` on every host as well as on the platforms that
/// select it, so its channel machinery, slot semantics and connect routing
/// are exercised by an ordinary test run on an ordinary runner. The Android
/// build of it is linted but executed nowhere, which is exactly why the logic
/// must not be behind a platform-only gate.
#[cfg(any(target_os = "android", target_os = "macos", test))]
pub mod io_radio;
pub mod neighbor;
pub mod pool;
pub mod psm;
mod recall;
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
use recall::Recall;
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
/// Arms in priority order: an in-process BlueZ stack where one exists,
/// otherwise a radio driven through [`io_radio`] — supplied by the embedder
/// on Android, by [`io_macos`] on macOS — otherwise, and *only* in a test
/// build, the in-memory double.
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
pub type DefaultBleTransport = BleTransport<io_radio::RadioIo>;

#[cfg(all(target_os = "macos", not(test)))]
pub type DefaultBleTransport = BleTransport<io_radio::RadioIo>;

#[cfg(test)]
pub type DefaultBleTransport = BleTransport<io::MockBleIo>;

// The tripwire. This module is only compiled when `ble_available`, so
// reaching here means a platform declared it has BLE while having no concrete
// backend to provide it. It cannot fire today; it exists for whoever next
// widens `ble_available`, and it fails the build rather than shipping a
// transport that quietly never connects.
#[cfg(all(
    not(test),
    not(bluer_available),
    not(target_os = "android"),
    not(target_os = "macos")
))]
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
    /// L2CAP listener PSMs read out of peers' advertisements, by link
    /// address. A peer whose platform assigns its listener PSM cannot be
    /// dialled at a configured constant, so it publishes the number it
    /// actually bound and every dial to it — the scan loop's probe and the
    /// node's [`connect_async`](Self::connect_async) alike — goes there. A
    /// peer that advertises nothing is dialled at the configured PSM.
    learned_psm: LearnedPsm,
    /// Link addresses the scan + probe loop has resolved to a node identity;
    /// a fresh memory for each loop started. See [`KnownNodes`].
    known_node_of: KnownNodes,
}

/// Advertised listener PSM by link address, shared between the scan loop
/// that learns it and the dials that need it. A plain mutex: never held
/// across an await. Bounded: see [`Recall`].
type LearnedPsm = Arc<std::sync::Mutex<Recall<u16>>>;

/// Link addresses already resolved to a node identity by a completed pubkey
/// exchange that was declined beside another link to that node, shared
/// between the scan loop and its transport. Lets the loop skip an address it
/// has *already* learned belongs to a peer it is connected to, instead of
/// paying a full connect and exchange to rediscover that every cooldown.
/// Rotation adds one per rotation, so an entry is dropped once its node no
/// longer holds a verified link: a peer that genuinely goes away is probed
/// again normally. A plain mutex: never held across an await. Bounded: see
/// [`Recall`].
type KnownNodes = Arc<std::sync::Mutex<Recall<NodeAddr>>>;

/// Lock an address memory. A panic while it was held leaves nothing half
/// written that its users rely on, so a poisoned lock is used as it is.
fn recall<V>(memory: &Arc<std::sync::Mutex<Recall<V>>>) -> std::sync::MutexGuard<'_, Recall<V>> {
    memory.lock().unwrap_or_else(|e| e.into_inner())
}

/// The PSM to dial `addr` at: what it advertised, else `configured`.
fn dial_psm_for(learned: &LearnedPsm, addr: &BleAddr, configured: u16) -> u16 {
    recall(learned).get(addr).copied().unwrap_or(configured)
}

/// A learned PSM that refused a dial is stale — forget it, so the next
/// advert re-learns it and the fallback applies in the meantime.
///
/// Only the PSM that was actually dialled is forgotten. A dial that went out
/// at the configured fallback, or at a value the scan loop has since
/// replaced, says nothing about the entry the map holds now.
///
/// Callers forget on a refusal only, never on a timeout: a timeout says the
/// peer was out of reach, not that it listens elsewhere, and on BlueZ
/// nothing would re-learn the entry — `DeviceAdded` fires once per
/// discovery session.
fn forget_psm(learned: &LearnedPsm, addr: &BleAddr, dialled: u16) {
    let mut learned = recall(learned);
    if learned.get(addr) == Some(&dialled) {
        learned.remove(addr);
    }
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
            learned_psm: Arc::default(),
            known_node_of: Arc::default(),
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

    /// How close together two links to one peer must complete to count as a
    /// race — see `arbitrate`.
    fn tie_window(&self) -> std::time::Duration {
        std::time::Duration::from_millis(self.config.connect_timeout_ms())
    }

    /// Start the transport asynchronously.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Starting;

        let configured_psm = self.config.psm();
        let adapter = self.io.adapter_name().to_string();
        // Two links to one peer that complete within a connect timeout of
        // each other raced, and are settled by node order — see `arbitrate`.
        let local_node = local_node_of(self.local_pubkey);
        let tie_window = self.tie_window();

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
                        self.local_pubkey,
                        local_node,
                        tie_window,
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
                    self.known_node_of = KnownNodes::default();
                    self.scan_probe_task = Some(tokio::spawn(scan_probe_loop::<I>(
                        scanner,
                        Arc::clone(&self.io),
                        Arc::clone(&self.pool),
                        Arc::clone(&self.neighbor_buffer),
                        Arc::clone(&self.stats),
                        self.local_pubkey,
                        local_node,
                        tie_window,
                        self.config.psm(),
                        self.config.connect_timeout_ms(),
                        self.config.probe_cooldown_secs(),
                        Arc::clone(&self.learned_psm),
                        Arc::clone(&self.known_node_of),
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
        // Take the MTU and the connection's send queue, then release the pool
        // lock. Everything after this point must be lock-free: the previous
        // shape awaited the L2CAP write while still holding this guard, so a
        // peer that stopped draining blocked not just its own sender but every
        // other BLE operation — connect, eviction, the receive loops' teardown.
        let found = {
            let pool = self.pool.lock().await;
            pool.get(addr)
                .map(|c| (c.effective_mtu() as usize, c.send_tx.clone()))
        };
        let (mtu, send_tx) = match found {
            Some(pair) => pair,
            None => {
                // Fire-and-forget: connect_async spawns a background task
                let _ = self.connect_async(addr).await;
                return Err(TransportError::SendFailed("not connected".into()));
            }
        };

        // MTU check
        if data.len() > mtu {
            self.stats.record_mtu_exceeded();
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: mtu as u16,
            });
        }

        // Queue the frame for the connection's writer task. `try_send`, not
        // `send`: waiting for a slot is the same stall in a different shape,
        // which is what the Android backend's own queue does one layer down.
        // The byte count is what was queued; bytes on the link are recorded by
        // the writer task.
        match send_tx.try_send(data.to_vec()) {
            Ok(()) => Ok(data.len()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                self.stats.record_send_error();
                debug!(
                    addr = %addr,
                    depth = pool::SEND_QUEUE_DEPTH,
                    "BLE outbound queue full; peer is not draining"
                );
                Err(TransportError::SendFailed(
                    "outbound queue full: peer not draining".into(),
                ))
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                self.stats.record_send_error();
                Err(TransportError::SendFailed("connection writer gone".into()))
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
        let mut peer: Option<(NodeAddr, XOnlyPublicKey)> = None;
        if let Some(ref our_pubkey) = self.local_pubkey {
            match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
                Ok(peer_pubkey) => {
                    debug!(addr = %addr, "BLE outbound pubkey exchange complete");
                    peer = Some((NodeAddr::from_pubkey(&peer_pubkey), peer_pubkey));
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

        self.promote_connection(addr, &ble_addr, stream, reader, peer)
            .await
    }

    /// Promote a newly established stream into the connection pool.
    ///
    /// Offers the link to the pool, after settling it against any other link
    /// to the same node, starting its receive loop once pooled. An admitted
    /// link whose remote sent its key is then announced; a refused one is
    /// not, since there is no link behind it. A link refused because the
    /// address already holds one is not an error: the address is connected.
    async fn promote_connection(
        &self,
        addr: &TransportAddr,
        ble_addr: &BleAddr,
        stream: Arc<I::Stream>,
        reader: BleStreamRead<I::Stream>,
        peer: Option<(NodeAddr, XOnlyPublicKey)>,
    ) -> Result<(), TransportError> {
        let node_addr = peer.map(|(node, _)| node);
        let mut pool = self.pool.lock().await;
        match settle_dialled(
            &mut pool,
            local_node_of(self.local_pubkey),
            node_addr,
            self.tie_window(),
            addr,
            &self.stats,
        ) {
            Dialled::Keep => {}
            Dialled::Decline(kept) => {
                drop(pool);
                if let Some((_, peer_pubkey)) = peer {
                    self.neighbor_buffer.add_peer_with_pubkey(
                        &kept.unwrap_or_else(|| ble_addr.clone()),
                        peer_pubkey,
                    );
                }
                return Ok(());
            }
            // Not announced: the link already at the address was announced
            // when it was pooled.
            Dialled::Occupied => return Ok(()),
        }
        let (conn, receive) = spawn_connection(
            stream,
            reader,
            addr,
            ble_addr.clone(),
            node_addr,
            true,
            &self.pool,
            self.packet_tx.clone(),
            self.transport_id,
            &self.stats,
        );
        let admitted = conn.established_at;
        let outcome = pool_link(&mut pool, addr, conn, admitted, receive);
        if !note_insert(
            &outcome,
            addr,
            "central",
            &self.stats,
            pool.max_connections(),
        ) {
            if outcome == Insert::Occupied {
                return Ok(());
            }
            return Err(TransportError::SendFailed("pool full".into()));
        }
        drop(pool);
        debug!(addr = %addr, "BLE connection established");
        self.stats.record_connection_established();
        if let Some((_, peer_pubkey)) = peer {
            self.neighbor_buffer
                .add_peer_with_pubkey(ble_addr, peer_pubkey);
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
        // At whatever PSM this peer advertised. The configured value is only
        // right for a peer that advertises nothing; on a platform that
        // assigns listener PSMs it is never the one the peer is listening on.
        let learned_psm = Arc::clone(&self.learned_psm);
        let psm = dial_psm_for(&learned_psm, &ble_addr, self.config.psm());
        let timeout_ms = self.config.connect_timeout_ms();
        let addr_clone = addr.clone();
        let local_pubkey = self.local_pubkey;
        let local_node = local_node_of(self.local_pubkey);
        let tie_window = self.tie_window();
        let neighbor_buffer = Arc::clone(&self.neighbor_buffer);

        let task = tokio::spawn(async move {
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(timeout_ms),
                io.connect(&ble_addr, psm),
            )
            .await;
            if matches!(result, Ok(Err(_))) {
                forget_psm(&learned_psm, &ble_addr, psm);
            }

            // Remove from connecting pool
            connecting.lock().await.remove(&addr_clone);

            match result {
                Ok(Ok(stream)) => {
                    let recv_mtu = stream.recv_mtu();
                    let stream = Arc::new(stream);
                    // One reader across both phases — see `pubkey_exchange`.
                    let mut reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

                    // Pre-handshake pubkey exchange (temporary, pre-XX)
                    let mut peer: Option<(NodeAddr, XOnlyPublicKey)> = None;
                    if let Some(ref our_pubkey) = local_pubkey {
                        match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
                            Ok(peer_pubkey) => {
                                debug!(addr = %addr_clone, "BLE outbound pubkey exchange complete");
                                peer = Some((NodeAddr::from_pubkey(&peer_pubkey), peer_pubkey));
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

                    // Arbitrate and insert under one guard, like the inbound
                    // and probe paths: the peer may have dialled us while
                    // this dial was in flight. The peer is announced only
                    // once that is settled, under the link that survived:
                    // a dial that replaces the incumbent must not report
                    // the address it just closed.
                    let peer_node = peer.map(|(node, _)| node);
                    let mut pool_guard = pool.lock().await;
                    match settle_dialled(
                        &mut pool_guard,
                        local_node,
                        peer_node,
                        tie_window,
                        &addr_clone,
                        &stats,
                    ) {
                        Dialled::Keep => {}
                        Dialled::Decline(kept) => {
                            drop(pool_guard);
                            if let Some((_, peer_pubkey)) = peer {
                                neighbor_buffer
                                    .add_peer_with_pubkey(&kept.unwrap_or(ble_addr), peer_pubkey);
                            }
                            return;
                        }
                        // Not announced: the link already at the address was
                        // announced when it was pooled.
                        Dialled::Occupied => return,
                    }
                    let (conn, receive) = spawn_connection(
                        stream,
                        reader,
                        &addr_clone,
                        ble_addr.clone(),
                        peer_node,
                        true,
                        &pool,
                        packet_tx,
                        transport_id,
                        &stats,
                    );
                    let admitted = conn.established_at;
                    let outcome = pool_link(&mut pool_guard, &addr_clone, conn, admitted, receive);
                    let max = pool_guard.max_connections();
                    if !note_insert(&outcome, &addr_clone, "central", &stats, max) {
                        // Not announced: the node dialled the address itself,
                        // and either no link is behind it or the link already
                        // there was announced when it was pooled.
                        return;
                    }
                    drop(pool_guard);
                    debug!(addr = %addr_clone, "BLE connection established");
                    stats.record_connection_established();
                    if let Some((_, peer_pubkey)) = peer {
                        neighbor_buffer.add_peer_with_pubkey(&ble_addr, peer_pubkey);
                    }
                }
                Ok(Err(e)) => {
                    stats.record_connect_error();
                    debug!(
                        addr = %addr_clone, role = "central", outcome = "connect-error",
                        psm, error = %e, "BLE connect failed"
                    );
                }
                Err(_) => {
                    stats.record_connect_timeout();
                    debug!(
                        addr = %addr_clone, role = "central", outcome = "connect-timeout",
                        psm, "BLE connect timeout"
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
/// FMP packets also begin with version 0, so the framer cannot tell them
/// apart; see the caution below.
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

/// The node address a local pubkey stands for, if it parses.
fn local_node_of(pubkey: Option<[u8; 32]>) -> Option<NodeAddr> {
    pubkey
        .and_then(|pk| XOnlyPublicKey::from_slice(&pk).ok())
        .map(|xonly| NodeAddr::from_pubkey(&xonly))
}

/// What to do with a newly identified link, given the pool's other links.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Admission {
    /// No link to this node blocks it: admit it.
    Admit,
    /// Keep the link already pooled at this address; drop the newcomer.
    Decline(TransportAddr),
    /// The newcomer wins the tie-break: the link pooled at this address goes.
    Replace(TransportAddr),
    /// The newcomer's address already holds a link claiming another node, or
    /// none: keep it and drop the newcomer without announcing it. Unlike
    /// `Decline`, nothing links the newcomer's claim to the kept link, so the
    /// claim must not be reported at that link's address.
    Occupied,
}

/// Arbitrate a newly identified link to `peer`, arriving at `ta`, against
/// the links the pool already holds claiming the same node, whatever address
/// they arrived on.
///
/// A verified link to the node carries its session, so a newcomer beside it
/// is declined whatever its age or direction.
///
/// A claim that is not yet verified proves nothing: anyone in radio range
/// can claim any key. Such a link still settles an honest simultaneous dial,
/// since both ends' first links are unverified until a handshake completes
/// on one of them. When the incumbent is younger than `tie_window` and the
/// two links run in opposite directions, both sides keep **the link the
/// smaller node dialled**. That rule only ever chooses between two links,
/// never refuses the only one, and it is the one both ends compute alike.
/// Each end admits the links in its own order — in a simultaneous dial, A
/// can admit B's link first while B admits A's — so "keep whichever came
/// first" leaves each side holding the channel the other just closed. The
/// node ordering is shared; the arrival order is not.
///
/// An incumbent at the newcomer's own address that claims another node, or
/// none, is kept whatever its age or verification: the newcomer's claim is
/// unproven and the incumbent may carry a session, and the pool is keyed by
/// link address. The newcomer is refused as `Occupied`, never declined in
/// favour of the incumbent, which would report the newcomer's node at a link
/// that does not reach it.
///
/// An unverified incumbent at the newcomer's own address claiming the same
/// node is settled by the same rule inside the window and kept outside it,
/// since admitting the newcomer would replace it. Any other
/// unverified incumbent — one in the same direction, which is a rotation
/// rather than a race between the ends, or one older than the window —
/// blocks nothing, and the newcomer is admitted beside it.
fn arbitrate<S>(
    pool: &ConnectionPool<S>,
    local: &NodeAddr,
    peer: &NodeAddr,
    ta: &TransportAddr,
    newcomer_outbound: bool,
    tie_window: std::time::Duration,
) -> Admission {
    if let Some(existing) = pool.find_verified(peer) {
        return Admission::Decline(existing);
    }
    if pool
        .get(ta)
        .is_some_and(|c| c.node_addr.as_ref() != Some(peer))
    {
        return Admission::Occupied;
    }
    let local_is_smaller = local < peer;
    let racing = |c: &BleConnection<S>| c.established_at.elapsed() < tie_window;
    if let Some(incumbent) = pool.get(ta).filter(|c| c.node_addr.as_ref() == Some(peer)) {
        return if racing(incumbent)
            && newcomer_wins(local_is_smaller, newcomer_outbound, incumbent.outbound)
        {
            Admission::Replace(ta.clone())
        } else {
            Admission::Decline(ta.clone())
        };
    }
    let rival = pool
        .unverified_claims(peer)
        .filter(|(_, c)| racing(c) && c.outbound != newcomer_outbound)
        .min_by_key(|(_, c)| c.established_at)
        .map(|(addr, c)| (addr.clone(), c.outbound));
    match rival {
        Some((existing, incumbent_outbound))
            if newcomer_wins(local_is_smaller, newcomer_outbound, incumbent_outbound) =>
        {
            Admission::Replace(existing)
        }
        Some((existing, _)) => Admission::Decline(existing),
        None => Admission::Admit,
    }
}

/// Whether a newcomer link displaces a racing incumbent to the same node.
///
/// The link the smaller node dialled is outbound on the smaller side and
/// inbound on the larger, so each side keeps its outbound link exactly when
/// it is the smaller. Two links in the same direction — a rotated address
/// dialling in twice — are no race between the ends, and the incumbent stays.
fn newcomer_wins(
    local_is_smaller: bool,
    newcomer_outbound: bool,
    incumbent_outbound: bool,
) -> bool {
    let keep_outbound = local_is_smaller;
    newcomer_outbound == keep_outbound && incumbent_outbound != keep_outbound
}

/// What `settle_dialled` decided for a link this side dialled.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Dialled {
    /// The way is clear: insert the dialled link.
    Keep,
    /// Drop the dialled link. The peer stays on its incumbent, whose link
    /// address this is, read under the same guard as the decision.
    Decline(Option<BleAddr>),
    /// Drop the dialled link without announcing it: its address already
    /// holds a link claiming another node, or none.
    Occupied,
}

/// Settle a link this side dialled at `ta` against the pool, under the
/// caller's guard: clear the way for it, or report that it must be dropped
/// and which link the peer stays on.
///
/// For the node-initiated dials. The scan loop's probe settles its own,
/// because it also records what a declined address resolved to.
fn settle_dialled<S>(
    pool: &mut ConnectionPool<S>,
    local_node: Option<NodeAddr>,
    peer_node: Option<NodeAddr>,
    tie_window: std::time::Duration,
    ta: &TransportAddr,
    stats: &BleStats,
) -> Dialled {
    let (Some(local), Some(peer)) = (local_node, peer_node) else {
        return Dialled::Keep;
    };
    match arbitrate(pool, &local, &peer, ta, true, tie_window) {
        Admission::Admit => Dialled::Keep,
        Admission::Replace(existing) => {
            pool.remove(&existing);
            debug!(
                addr = %ta,
                role = "central",
                outcome = "duplicate-link-replaced",
                existing = %existing,
                "BLE connect: raced a link to the same peer and won the tie-break"
            );
            stats.record_duplicate_link_replacement();
            Dialled::Keep
        }
        Admission::Decline(existing) => {
            debug!(
                addr = %ta,
                role = "central",
                outcome = "duplicate-node-decline",
                existing = %existing,
                "BLE connect: peer already linked, dropping duplicate"
            );
            stats.record_duplicate_node_decline();
            Dialled::Decline(pool.get(&existing).map(|c| c.addr.clone()))
        }
        Admission::Occupied => {
            log_occupied(ta, "central");
            Dialled::Occupied
        }
    }
}

/// Start a link's writer task and wrap it as a pool entry, returning the
/// entry with its receive loop unstarted, for [`pool_link`] to start once
/// the pool admits the link.
///
/// The writer is spawned before the entry is inserted, so callers that
/// arbitrate do so and insert under one pool guard: it cannot reap its entry
/// until that guard is released, and dropping an entry aborts it. It sends
/// only what is queued on the entry, so a refused entry's writer sends
/// nothing. The receive loop delivers packets under `ta` and removes `ta`
/// from the pool when it ends, so it must not run for a link the pool
/// refuses.
#[allow(clippy::too_many_arguments)]
fn spawn_connection<S: BleStream + 'static>(
    stream: Arc<S>,
    reader: BleStreamRead<S>,
    ta: &TransportAddr,
    addr: BleAddr,
    node_addr: Option<NodeAddr>,
    outbound: bool,
    pool: &Arc<Mutex<ConnectionPool<Arc<S>>>>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: &Arc<BleStats>,
) -> (
    BleConnection<Arc<S>>,
    impl std::future::Future<Output = ()> + Send + 'static,
) {
    let send_mtu = stream.send_mtu();
    let recv_mtu = stream.recv_mtu();
    let admitted = tokio::time::Instant::now();

    let receive = receive_loop(
        reader,
        ta.clone(),
        Arc::clone(pool),
        packet_tx,
        transport_id,
        Arc::clone(stats),
        recv_mtu,
    );

    let (send_tx, send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
    let send_task = tokio::spawn(send_loop(
        Arc::clone(&stream),
        send_rx,
        ta.clone(),
        Arc::clone(pool),
        Arc::clone(stats),
    ));

    let conn = BleConnection {
        stream,
        send_tx,
        send_task: Some(send_task),
        recv_task: None,
        send_mtu,
        recv_mtu,
        established_at: admitted,
        grace_from: admitted,
        verified: false,
        outbound,
        addr,
        node_addr,
    };
    (conn, receive)
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
    if let Insert::Admitted { ended, .. } | Insert::Refused { ended, .. } = outcome
        && let Some(n) = ended
    {
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
        Insert::Occupied => {
            log_occupied(ta, role);
            false
        }
    }
}

/// Log a link dropped because its address already holds one.
///
/// What the newcomer claims is unproven and the pooled link may carry a
/// session, so the newcomer is dropped. Attacker input: debug only.
fn log_occupied(ta: &TransportAddr, role: &'static str) {
    debug!(
        addr = %ta, role, outcome = "address-occupied",
        "BLE link offered at an address already pooled, link dropped"
    );
}

/// Offer a link to the pool, starting its receive loop only once it is pooled.
///
/// The loop delivers packets under `ta` and removes `ta` from the pool when it
/// ends, so a loop started for a link the pool then refuses would act on the
/// link that holds the address. `receive` is the loop's unstarted future: it
/// is spawned under the caller's guard, and its handle is kept on the pooled
/// link, whose drop stops it. A refused link drops it unstarted.
fn pool_link<S, F>(
    pool: &mut ConnectionPool<S>,
    ta: &TransportAddr,
    conn: BleConnection<S>,
    now: tokio::time::Instant,
    receive: F,
) -> Insert
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    let outcome = pool.insert(ta.clone(), conn, now);
    if matches!(outcome, Insert::Admitted { .. })
        && let Some(conn) = pool.get_mut(ta)
    {
        conn.recv_task = Some(tokio::spawn(receive));
    }
    outcome
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
    local_node: Option<NodeAddr>,
    tie_window: std::time::Duration,
    neighbor_buffer: Arc<NeighborBuffer>,
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

                // Skip if a settled link to this address already exists. A
                // young one may be racing this inbound, and only `arbitrate`
                // can settle that the same way the peer will, so it is let
                // through to the exchange. This awaits only our own mutex,
                // never the peer.
                {
                    let pool_guard = pool.lock().await;
                    if pool_guard
                        .get(&ta)
                        .is_some_and(|c| c.established_at.elapsed() >= tie_window)
                    {
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
                    local_node,
                    tie_window,
                    Arc::clone(&neighbor_buffer),
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
/// duplicate-node arbitration: moving the work off the loop must not drop the
/// checks that guard it. The loop's `continue` becomes `return` — this task
/// admits one connection.
#[allow(clippy::too_many_arguments)]
async fn admit_inbound<S>(
    stream: S,
    pool: Arc<Mutex<ConnectionPool<Arc<S>>>>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: Arc<BleStats>,
    local_pubkey: Option<[u8; 32]>,
    local_node: Option<NodeAddr>,
    tie_window: std::time::Duration,
    neighbor_buffer: Arc<NeighborBuffer>,
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
    let mut peer = None;
    if let Some(ref our_pubkey) = local_pubkey {
        match pubkey_exchange(stream.as_ref(), &mut reader, our_pubkey).await {
            Ok(peer_pubkey) => {
                debug!(addr = %ta, "BLE inbound pubkey exchange complete");
                peer = Some((NodeAddr::from_pubkey(&peer_pubkey), peer_pubkey));
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
    let peer_node_addr = peer.map(|(node, _)| node);

    // Arbitrate and insert under one guard, so nothing can land between the
    // decision and the insert it decides.
    let mut pool_guard = pool.lock().await;

    // Already linked to this peer, on this address or another? A peer using
    // resolvable private addresses rotates continually, and every rotation
    // dials in looking like a new device; a peer dialling from a public
    // address dials in at the same one. Either way a second link to one
    // node is arbitrated, never simply added — see `arbitrate`.
    let admission = match (local_node, peer_node_addr) {
        (Some(local), Some(peer_node)) => {
            arbitrate(&pool_guard, &local, &peer_node, &ta, false, tie_window)
        }
        _ => Admission::Admit,
    };
    let announced = match &admission {
        Admission::Decline(existing) => {
            let kept = pool_guard.get(existing).map(|c| c.addr.clone());
            drop(pool_guard);
            debug!(
                addr = %ta,
                role = "peripheral",
                outcome = "duplicate-node-decline",
                existing = %existing,
                "BLE inbound: peer already linked, dropping duplicate"
            );
            stats.record_duplicate_node_decline();
            // Report the peer under the address its live link is on, so the
            // node layer is not handed an alias with no connection behind it.
            if let Some((_, peer_pubkey)) = peer {
                neighbor_buffer.add_peer_with_pubkey(&kept.unwrap_or(addr), peer_pubkey);
            }
            return;
        }
        Admission::Replace(existing) => {
            pool_guard.remove(existing);
            debug!(
                addr = %ta,
                role = "peripheral",
                outcome = "duplicate-link-replaced",
                existing = %existing,
                "BLE inbound: raced a link to the same peer and won the tie-break"
            );
            stats.record_duplicate_link_replacement();
            addr.clone()
        }
        Admission::Occupied => {
            drop(pool_guard);
            // Not announced: the link already at the address was announced
            // when it was pooled.
            log_occupied(&ta, "peripheral");
            return;
        }
        Admission::Admit => addr.clone(),
    };

    let (conn, receive) = spawn_connection(
        stream,
        reader,
        &ta,
        addr,
        peer_node_addr,
        false,
        &pool,
        packet_tx,
        transport_id,
        &stats,
    );

    let admitted = conn.established_at;
    let outcome = pool_link(&mut pool_guard, &ta, conn, admitted, receive);
    let max = pool_guard.max_connections();
    if !note_insert(&outcome, &ta, "peripheral", &stats, max) {
        // Not announced: there is no link behind this inbound, and a link
        // already at the address was announced when it was pooled.
        return;
    }
    drop(pool_guard);
    info!(addr = %ta, send_mtu, recv_mtu, "BLE inbound connection accepted");
    stats.record_connection_accepted();
    if let Some((_, peer_pubkey)) = peer {
        neighbor_buffer.add_peer_with_pubkey(&announced, peer_pubkey);
    }
}

/// Per-connection writer task: the only place a BLE write is ever awaited.
///
/// The BLE case was the worst of the connection-oriented transports. The write
/// was awaited by the caller *while holding the pool mutex*, so a peer that
/// stopped draining its L2CAP link blocked every other BLE operation as well
/// as the caller's task — connects, evictions and each receive loop's
/// teardown all queue behind that one guard. Moving the write here removes
/// both halves of that: the caller enqueues and returns, and the pool lock is
/// never held across the link.
///
/// On a write error the connection is removed from the pool, which is where
/// the old inline path put it too. Dropping the pool entry aborts this task
/// and the receive task through `BleConnection`'s `Drop`.
async fn send_loop<S: BleStream + 'static>(
    stream: Arc<S>,
    mut frames: tokio::sync::mpsc::Receiver<Vec<u8>>,
    addr: TransportAddr,
    pool: Arc<Mutex<ConnectionPool<Arc<S>>>>,
    stats: Arc<BleStats>,
) {
    while let Some(frame) = frames.recv().await {
        match stream.send(&frame).await {
            Ok(()) => stats.record_send(frame.len()),
            Err(e) => {
                stats.record_send_error();
                warn!(addr = %addr, error = %e, "BLE send failed, connection removed");
                pool.lock().await.remove(&addr);
                return;
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

    /// Whether `addr` is in the book.
    fn contains(&self, addr: &BleAddr) -> bool {
        self.position(addr).is_some()
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

/// Log the addresses an address memory forgot to stay within its bound.
fn log_evicted(evicted: Vec<BleAddr>) {
    for addr in evicted {
        debug!(
            addr = %addr, bound = recall::MAX_RECALLED_ADDRS, outcome = "recall-evicted",
            "BLE probe memory full, forgot the oldest address not in use"
        );
    }
}

/// Whether the probe loop still depends on what it learned about `addr`: a
/// link is pooled there, or the address is in the retry book.
fn is_live<S>(pool: &ConnectionPool<S>, pending: &PendingProbes, addr: &BleAddr) -> bool {
    pending.contains(addr) || pool.contains(&addr.to_transport_addr())
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
    local_node: Option<NodeAddr>,
    tie_window: std::time::Duration,
    configured_psm: u16,
    connect_timeout_ms: u64,
    cooldown_secs: u64,
    learned_psm: LearnedPsm,
    known_node_of: KnownNodes,
    packet_tx: PacketTx,
    transport_id: TransportId,
) {
    // Addresses discovered but not yet connected — retried after cooldown even
    // if the scanner doesn't fire again (BlueZ deduplicates), on a per-address
    // backoff that widens with consecutive failures. Also the cooldown record:
    // an address leaves the book the moment it reaches a conclusive outcome,
    // after which the pool and `known_node_of` guards below cover it.
    let mut pending = PendingProbes::new(std::time::Duration::from_secs(cooldown_secs));
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
                            let pool_guard = pool.lock().await;
                            log_evicted(recall(&learned_psm).note(
                                &advert.addr,
                                psm,
                                tokio::time::Instant::now(),
                                |a| is_live(&pool_guard, &pending, a),
                            ));
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
                {
                    let now = tokio::time::Instant::now();
                    let live = |a: &BleAddr| is_live(&pool_guard, &pending, a);
                    recall(&known_node_of).prune(now, live);
                    recall(&learned_psm).prune(now, live);
                }
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
        let known = recall(&known_node_of).get(&addr).copied();
        if let Some(node) = known {
            // Only a verified link justifies the skip: an unverified claim to
            // the node must not hide the node's own address.
            let still_connected = {
                let pool_guard = pool.lock().await;
                let held = pool_guard.find_verified(&node).is_some();
                if held {
                    // Still in use: seen now.
                    pending.resolve(&addr);
                    log_evicted(
                        recall(&known_node_of)
                            .note(&addr, node, now, |a| is_live(&pool_guard, &pending, a)),
                    );
                }
                held
            };
            if still_connected {
                continue;
            }
            // That peer is gone — forget the mapping and probe normally.
            recall(&known_node_of).remove(&addr);
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
        let dial_psm = dial_psm_for(&learned_psm, &addr, configured_psm);
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
                // Costs one retry — see `forget_psm`.
                forget_psm(&learned_psm, &addr, dial_psm);
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
                continue;
            }
        };

        // Pubkey exchange, then promote connection to pool
        let ta = addr.to_transport_addr();
        let recv_mtu = stream.recv_mtu();
        let stream = Arc::new(stream);
        // One reader across both phases — see `pubkey_exchange`.
        let mut reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);
        match pubkey_exchange(stream.as_ref(), &mut reader, &our_pubkey).await {
            Ok(peer_pubkey) => {
                debug!(addr = %addr, "BLE probe complete");
                let peer_node = NodeAddr::from_pubkey(&peer_pubkey);

                // Arbitrate and insert under one guard. A peer we already
                // hold a link to — a rotated address of it, or the inbound it
                // opened while this probe was in flight — is the same case as
                // on the inbound path, and is settled by the same rule.
                let mut pool_guard = pool.lock().await;
                let admission = match local_node {
                    Some(local) => {
                        arbitrate(&pool_guard, &local, &peer_node, &ta, true, tie_window)
                    }
                    None => Admission::Admit,
                };
                match admission {
                    Admission::Decline(existing) => {
                        drop(pool_guard);
                        debug!(
                            addr = %ta,
                            role = "central",
                            outcome = "duplicate-node-decline",
                            existing = %existing,
                            discovery_ms = probe_started.elapsed().as_millis() as u64,
                            "BLE probe: peer already linked, dropping duplicate"
                        );
                        stats.record_duplicate_node_decline();
                        // Remember what this address resolved to, so the next
                        // cooldown skips it outright rather than paying another
                        // connect and exchange to reach the same conclusion.
                        {
                            let pool_guard = pool.lock().await;
                            log_evicted(recall(&known_node_of).note(
                                &addr,
                                peer_node,
                                tokio::time::Instant::now(),
                                |a| is_live(&pool_guard, &pending, a),
                            ));
                        }
                        // Report the peer under the address its live link is on,
                        // so the node layer is not handed an alias with no
                        // connection behind it.
                        let announced = announced_addr(&pool, &peer_node, &addr).await;
                        buffer.add_peer_with_pubkey(&announced, peer_pubkey);
                        pending.resolve(&addr);
                        continue;
                    }
                    Admission::Replace(existing) => {
                        pool_guard.remove(&existing);
                        debug!(
                            addr = %ta,
                            role = "central",
                            outcome = "duplicate-link-replaced",
                            existing = %existing,
                            discovery_ms = probe_started.elapsed().as_millis() as u64,
                            "BLE probe: raced a link to the same peer and won the tie-break"
                        );
                        stats.record_duplicate_link_replacement();
                    }
                    Admission::Occupied => {
                        // A link landed at the address during the probe and
                        // was announced when it was pooled. Conclusive, as
                        // the already-pooled skip above is, and nothing is
                        // learned.
                        drop(pool_guard);
                        log_occupied(&ta, "central");
                        pending.resolve(&addr);
                        continue;
                    }
                    Admission::Admit => {}
                }

                // Promote connection to pool — no second L2CAP connect needed.
                // Its receive loop starts only once it is pooled.
                let (conn, receive) = spawn_connection(
                    stream,
                    reader,
                    &ta,
                    addr.clone(),
                    Some(peer_node),
                    true,
                    &pool,
                    packet_tx.clone(),
                    transport_id,
                    &stats,
                );

                let admitted = conn.established_at;
                let outcome = pool_link(&mut pool_guard, &ta, conn, admitted, receive);
                let max = pool_guard.max_connections();
                if outcome == Insert::Occupied {
                    // A link landed at the address during the probe and was
                    // announced when it was pooled. Conclusive, as the
                    // already-pooled skip above is, and nothing is learned.
                    let _ = note_insert(&outcome, &ta, "central", &stats, max);
                    drop(pool_guard);
                    pending.resolve(&addr);
                    continue;
                }
                if !note_insert(&outcome, &ta, "central", &stats, max) {
                    // The connection is dropped with `conn`, so there is
                    // nothing to report and nothing to resolve. Leaving the
                    // address in the retry book is the point: a slot may
                    // free before the peer is advertised again. The inbound
                    // path already returns here rather than falling through.
                    continue;
                }
                drop(pool_guard);
                debug!(
                    addr = %ta, role = "central", outcome = "connected",
                    discovery_ms = probe_started.elapsed().as_millis() as u64,
                    "BLE probe promoted to pool"
                );
                stats.record_connection_established();
                pending.resolve(&addr);

                // Report to node layer for auto-connect / handshake
                buffer.add_peer_with_pubkey(&addr, peer_pubkey);
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
    use std::time::Duration;

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
        let has_concrete_backend =
            cfg!(bluer_available) || cfg!(target_os = "android") || cfg!(target_os = "macos");
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

    /// `has_connection` reports whether the pool holds a connection to the
    /// address, the lookup `send_async` makes first, and unlike a send to an
    /// unpooled address it starts no connect.
    #[tokio::test]
    async fn has_connection_reports_the_pool_and_starts_no_connect() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (transport, _rx) = make_transport(io);
        let ta = test_addr(2).to_transport_addr();

        assert!(
            !transport.has_connection(&ta).await,
            "no connection before one is pooled"
        );
        assert!(
            transport.connecting.lock().await.is_empty(),
            "the query started a connect"
        );

        let (near, _far) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let (send_tx, _send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
        let outcome = transport.pool.lock().await.insert(
            ta.clone(),
            BleConnection {
                stream: Arc::new(near),
                send_tx,
                send_task: None,
                recv_task: None,
                send_mtu: 2048,
                recv_mtu: 2048,
                established_at: tokio::time::Instant::now(),
                verified: false,
                grace_from: tokio::time::Instant::now(),
                outbound: false,
                addr: test_addr(2),
                node_addr: None,
            },
            tokio::time::Instant::now(),
        );
        assert!(matches!(outcome, Insert::Admitted { .. }));
        assert!(
            transport.has_connection(&ta).await,
            "the pooled connection is reported"
        );
    }

    /// **The property the writer task exists to guarantee, on the transport
    /// where it mattered most.**
    ///
    /// BLE was the worst of the connection-oriented transports: `send_async`
    /// awaited the L2CAP write *while holding the pool mutex*, so a peer that
    /// stopped draining blocked not only its own sender but every other BLE
    /// operation — connects, evictions, and each receive loop's teardown all
    /// queue behind that guard.
    ///
    /// The mock stream's send half is a bounded channel, so a peer that never
    /// reads is a peer whose link has stopped draining. This inserts such a
    /// connection with a real writer task behind it, pushes far more than
    /// either queue holds, and asserts that every call returns promptly and
    /// that the pool stays lockable throughout.
    #[tokio::test]
    async fn a_ble_peer_that_stops_reading_cannot_block_the_sender_or_the_pool() {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (transport, _rx) = make_transport(io);

        // `_deaf` is the far end. Holding it without ever calling `recv` is
        // what makes this a stalled link rather than a closed one.
        let (near, _deaf) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        let stream = Arc::new(near);
        let ta = TransportAddr::from_string("AA:BB:CC:DD:EE:02");

        let (send_tx, send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
        let send_task = tokio::spawn(send_loop(
            Arc::clone(&stream),
            send_rx,
            ta.clone(),
            Arc::clone(&transport.pool),
            Arc::clone(&transport.stats),
        ));

        let outcome = transport.pool.lock().await.insert(
            ta.clone(),
            BleConnection {
                stream,
                send_tx,
                send_task: Some(send_task),
                recv_task: None,
                send_mtu: 2048,
                recv_mtu: 2048,
                established_at: tokio::time::Instant::now(),
                verified: false,
                grace_from: tokio::time::Instant::now(),
                outbound: false,
                addr: test_addr(2),
                node_addr: None,
            },
            tokio::time::Instant::now(),
        );
        assert!(matches!(outcome, Insert::Admitted { .. }));

        let frame = vec![0xAB; 512];
        let mut queued = 0usize;
        let mut refused = 0usize;
        for _ in 0..512 {
            match tokio::time::timeout(Duration::from_secs(2), transport.send_async(&ta, &frame))
                .await
            {
                Ok(Ok(_)) => queued += 1,
                Ok(Err(_)) => refused += 1,
                Err(_) => panic!(
                    "send blocked on a BLE peer that stopped reading; the write is back \
                     on the caller's task"
                ),
            }

            // The pool must stay available the whole time. Before the writer
            // task this guard was held across the L2CAP write, so a stalled
            // link froze every other BLE operation too.
            let guard = tokio::time::timeout(Duration::from_millis(100), transport.pool.lock())
                .await
                .expect("the pool lock must never be held across a BLE write");
            drop(guard);
        }

        assert!(queued > 0, "the first sends must be accepted");
        assert!(
            refused > 0,
            "a BLE peer that never drains must eventually have sends refused rather \
             than queued without bound: queued={queued}"
        );
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
                send_tx: tokio::sync::mpsc::channel(1).0,
                send_task: None,
                recv_task: None,
                send_mtu: 2048,
                recv_mtu: 2048,
                established_at: tokio::time::Instant::now(),
                verified: false,
                grace_from: tokio::time::Instant::now(),
                outbound: false,
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
    /// Two links to one peer that race are settled by `NodeAddr` ordering
    /// (see `arbitrate`), so a test that races them has to know which side
    /// it is.
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
        // Both links are inbound, so node order plays no part: the second
        // is a rotation of the first, and the duplicate guard declines it.
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

    /// A dial the node layer started, completing while the same peer's
    /// inbound link is young, is settled by the same rule as the probe: kept
    /// only as the link the smaller node dialled.
    ///
    /// The dial goes to link address `dial_at` (2 is the inbound's own) and
    /// is in flight before the inbound arrives, which is the race: dialling
    /// an address already pooled returns early and never races at all.
    /// Returns the transport and every address the dial announced the peer
    /// under.
    async fn node_dial_racing_an_inbound(
        local: [u8; 32],
        peer: [u8; 32],
        dial_at: u8,
    ) -> (BleTransport<MockBleIo>, Vec<TransportAddr>) {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (peers_tx, mut peers_rx) = tokio::sync::mpsc::unbounded_channel();
        io.set_connect_handler(move |remote, _psm| {
            let (ours, theirs) = MockBleStream::pair(test_addr(1), remote.clone(), 2048);
            peers_tx.send(theirs).unwrap();
            Ok(ours)
        });
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport =
            BleTransport::new(TransportId::new(1), None, identity_test_config(), io, tx);
        transport.set_local_pubkey(local);
        transport.start_async().await.unwrap();

        // The node's own dial connects, and waits on the peer's exchange.
        transport
            .connect_async(&test_addr(dial_at).to_transport_addr())
            .await
            .unwrap();
        let dialled_peer = peers_rx.recv().await.unwrap();

        // Meanwhile the peer's inbound arrives on link address 2.
        let (ours, inbound_peer) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        transport.io.inject_inbound(ours).await;
        peer_side_exchange(&inbound_peer, &peer).await;
        let stats = Arc::clone(&transport.stats);
        wait_for("the inbound to be admitted", || {
            stats.snapshot().connections_accepted == 1
        })
        .await;
        // The inbound's own announcement is not the dial's.
        transport.neighbor_buffer.take();

        // Now the dial's exchange completes, and it settles against the
        // inbound.
        peer_side_exchange(&dialled_peer, &peer).await;
        wait_for("the dial to be settled", || {
            let s = stats.snapshot();
            s.duplicate_node_declines + s.connections_established >= 1
        })
        .await;
        let mut announced: Vec<TransportAddr> = Vec::new();
        wait_for("the dial to announce the peer", || {
            announced.extend(transport.neighbor_buffer.take().into_iter().map(|p| p.addr));
            !announced.is_empty()
        })
        .await;
        settle().await;
        announced.extend(transport.neighbor_buffer.take().into_iter().map(|p| p.addr));

        // Keep the peer ends open so neither link is reaped as closed.
        std::mem::forget((inbound_peer, dialled_peer));
        (transport, announced)
    }

    #[tokio::test]
    async fn test_a_smaller_nodes_dial_replaces_a_racing_inbound() {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();
        let (transport, announced) = node_dial_racing_an_inbound(smaller, larger, 3).await;
        let dialled = test_addr(3).to_transport_addr();
        assert_eq!(sole_link(&transport).await, (dialled.clone(), true));
        assert_eq!(transport.stats.snapshot().duplicate_link_replacements, 1);
        assert_eq!(
            announced,
            vec![dialled],
            "the peer is announced at the link that survived, not the one it replaced"
        );
    }

    #[tokio::test]
    async fn test_a_larger_nodes_dial_yields_to_a_racing_inbound() {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();
        let (transport, announced) = node_dial_racing_an_inbound(larger, smaller, 3).await;
        let inbound = test_addr(2).to_transport_addr();
        assert_eq!(sole_link(&transport).await, (inbound.clone(), false));
        assert_eq!(transport.stats.snapshot().duplicate_node_declines, 1);
        assert_eq!(
            announced,
            vec![inbound],
            "the peer is announced at the kept link"
        );
    }

    #[tokio::test]
    async fn test_a_smaller_nodes_dial_at_the_inbounds_address_replaces_it() {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();
        let (transport, announced) = node_dial_racing_an_inbound(smaller, larger, 2).await;
        let addr = test_addr(2).to_transport_addr();
        assert_eq!(sole_link(&transport).await, (addr.clone(), true));
        let s = transport.stats.snapshot();
        assert_eq!(
            s.duplicate_link_replacements, 1,
            "replaced, not overwritten"
        );
        assert_eq!(s.duplicate_node_declines, 0);
        assert_eq!(announced, vec![addr]);
    }

    #[tokio::test]
    async fn test_a_larger_nodes_dial_at_the_inbounds_address_keeps_the_inbound() {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();
        let (transport, announced) = node_dial_racing_an_inbound(larger, smaller, 2).await;
        let addr = test_addr(2).to_transport_addr();
        assert_eq!(
            sole_link(&transport).await,
            (addr.clone(), false),
            "the dial must not overwrite the inbound"
        );
        let s = transport.stats.snapshot();
        assert_eq!(s.duplicate_node_declines, 1);
        assert_eq!(s.duplicate_link_replacements, 0);
        assert_eq!(announced, vec![addr]);
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

    /// The node's own dial to a peer — a path probe, an auto-connect to a
    /// known address — goes to the advertised PSM too, not only the scan
    /// loop's probe. On a platform that assigns listener PSMs the configured
    /// value is never the one the peer listens on, so a node dial that used
    /// it failed every time, and the only BLE links that ever formed were the
    /// scan loop's.
    #[tokio::test]
    async fn test_a_node_dial_uses_the_advertised_psm() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        transport.start_async().await.unwrap();

        // What the scan loop would have learned from the peer's advert. Set
        // directly: the loop's own probe of that advert is refused by this
        // mock and would forget it again, and the loop is not what is under
        // test here.
        let _ = transport.learned_psm.lock().unwrap().note(
            &test_addr(2),
            0x00C1,
            tokio::time::Instant::now(),
            |_| false,
        );

        transport
            .connect_async(&test_addr(2).to_transport_addr())
            .await
            .unwrap();
        settle().await;
        assert_eq!(
            dials.lock().unwrap().as_slice(),
            &[(test_addr(2), 0x00C1)],
            "a node dial must go where the peer said it listens"
        );

        // The refused dial forgot the learned PSM; the next one falls back.
        transport
            .connect_async(&test_addr(2).to_transport_addr())
            .await
            .unwrap();
        settle().await;
        assert_eq!(
            dials.lock().unwrap().last(),
            Some(&(test_addr(2), DEFAULT_PSM))
        );
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

    /// A dial that times out keeps the learned PSM. A timeout says the peer
    /// was out of reach, not that it listens elsewhere — and on BlueZ nothing
    /// would re-learn a forgotten entry, since `DeviceAdded` fires once per
    /// discovery session.
    #[tokio::test(start_paused = true)]
    async fn test_a_timed_out_dial_keeps_the_learned_psm() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        transport.io.set_connect_stall();
        transport.start_async().await.unwrap();

        transport
            .io
            .inject_scan_advert(io::ScanAdvert::with_psm(test_addr(2), 0x00C1))
            .await;
        settle().await;
        tokio::time::advance(std::time::Duration::from_millis(
            transport.config.connect_timeout_ms() + 1,
        ))
        .await;
        {
            let stats = Arc::clone(&transport.stats);
            wait_for("the probe to time out", || {
                stats.snapshot().connect_timeouts == 1
            })
            .await;
        }

        assert_eq!(
            transport.learned_psm.lock().unwrap().get(&test_addr(2)),
            Some(&0x00C1),
            "a timeout must not forget where the peer listens"
        );
        transport.stop_async().await.unwrap();
    }

    /// A refusal forgets only the PSM that was dialled. Here the scan loop
    /// learns a new value while the dial is in flight; the refusal of the old
    /// one must not take the new one with it.
    #[tokio::test]
    async fn test_a_refusal_forgets_only_the_psm_it_dialled() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        transport.start_async().await.unwrap();

        let learned = Arc::clone(&transport.learned_psm);
        let _ = learned.lock().unwrap().note(
            &test_addr(2),
            0x00C1,
            tokio::time::Instant::now(),
            |_| false,
        );
        {
            let learned = Arc::clone(&learned);
            transport.io.set_connect_handler(move |addr, psm| {
                dials.lock().unwrap().push((addr.clone(), psm));
                // The peer re-advertised on a new PSM meanwhile.
                let _ =
                    learned
                        .lock()
                        .unwrap()
                        .note(addr, 0x00C2, tokio::time::Instant::now(), |_| false);
                Err(TransportError::ConnectionRefused)
            });
        }

        transport
            .connect_async(&test_addr(2).to_transport_addr())
            .await
            .unwrap();
        {
            let stats = Arc::clone(&transport.stats);
            wait_for("the dial to be refused", || {
                stats.snapshot().connect_errors == 1
            })
            .await;
        }

        assert_eq!(
            learned.lock().unwrap().get(&test_addr(2)),
            Some(&0x00C2),
            "the refusal of 0x00C1 says nothing about 0x00C2"
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

    /// A lone link is always admitted, whichever node dialled it. The node
    /// with the smaller address used to stand its inbound down so that its
    /// own outbound would win, before it had any outbound to keep; when that
    /// outbound could not succeed it stood a working link down forever. Node
    /// order now only chooses between two racing links (see `arbitrate`).
    /// Here the smaller node has nothing: the inbound from the larger is kept.
    #[tokio::test]
    async fn test_smaller_node_keeps_an_inbound_it_has_no_link_to_replace() {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();

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
            wait_for("the inbound to be admitted", || {
                stats.snapshot().connections_accepted == 1
            })
            .await;
        }

        let snap = inbound_side.stats.snapshot();
        assert_eq!(snap.connections_accepted, 1, "a working inbound is a link");
        assert_eq!(snap.duplicate_node_declines, 0);
        assert_eq!(inbound_side.pool.lock().await.len(), 1);
        inbound_side.stop_async().await.unwrap();
    }

    /// The other half of the same rule: the larger node probing outbound
    /// used to yield to the smaller's outbound on principle, before the
    /// smaller had dialled anything. With no link to yield to, the probe is
    /// promoted.
    #[tokio::test]
    async fn test_larger_node_promotes_a_probe_when_it_holds_no_link() {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();

        let io = MockBleIo::new("hci0", test_addr(2));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        io.set_connect_handler(move |addr, _psm| {
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
        let mut outbound_side = BleTransport::new(TransportId::new(2), None, config, io, tx2);
        outbound_side.set_local_pubkey(larger);
        outbound_side.start_async().await.unwrap();

        outbound_side.io.inject_scan_result(test_addr(1)).await;
        {
            let stats = Arc::clone(&outbound_side.stats);
            wait_for("the probe to be promoted", || {
                stats.snapshot().connections_established == 1
            })
            .await;
        }
        assert_eq!(outbound_side.pool.lock().await.len(), 1);
        outbound_side.stop_async().await.unwrap();
    }

    /// What one side's pool holds once a probe has raced an inbound link to
    /// the same peer: the counters, and each pooled link's address and
    /// direction.
    struct RaceOutcome {
        snap: stats::BleStatsSnapshot,
        links: Vec<(TransportAddr, bool)>,
        verified: Vec<TransportAddr>,
    }

    /// One side of the simultaneous-dial race: our probe to the peer at link
    /// address 2 stalls in its pubkey exchange while the peer's own dial
    /// arrives on `inbound_addr` and is admitted; then, after `hold`, the
    /// probe completes and is arbitrated against the inbound.
    async fn probe_completing_after_an_inbound(
        local_is_smaller: bool,
        inbound_addr: u8,
        hold: std::time::Duration,
    ) -> RaceOutcome {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();
        let (ours_pk, theirs_pk) = if local_is_smaller {
            (smaller, larger)
        } else {
            (larger, smaller)
        };

        let io = MockBleIo::new("hci0", test_addr(1));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let dials = Arc::clone(&dials);
            io.set_connect_handler(move |addr, _psm| {
                let (ours, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
                dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                peer_tx
                    .send(theirs)
                    .map_err(|_| TransportError::ConnectionRefused)?;
                Ok(ours)
            });
        }
        // The peer answers our probe only once released.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let mut alive = Vec::new();
            let _ = release_rx.await;
            while let Some(theirs) = peer_rx.recv().await {
                peer_side_exchange(&theirs, &theirs_pk).await;
                alive.push(theirs);
            }
        });

        let config = BleConfig {
            scan: Some(true),
            connect_timeout_ms: Some(500),
            ..identity_test_config()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.set_local_pubkey(ours_pk);
        transport.start_async().await.unwrap();

        // Our probe goes out to the peer's advertised address and stalls in
        // its pubkey exchange. Waited for, not settled: the scan loop parks
        // on a timer tick first, and a probe that has not dialled by the time
        // the inbound lands at the same address is skipped, not raced.
        transport.io.inject_scan_result(test_addr(2)).await;
        wait_for("the probe to dial", || {
            dials.load(std::sync::atomic::Ordering::Relaxed) == 1
        })
        .await;
        assert_eq!(transport.pool.lock().await.len(), 0);

        // ...while the peer's own dial arrives and is admitted.
        let (ours, peer) = MockBleStream::pair(test_addr(1), test_addr(inbound_addr), 2048);
        transport.io.inject_inbound(ours).await;
        peer_side_exchange(&peer, &theirs_pk).await;
        {
            let stats = Arc::clone(&transport.stats);
            wait_for("the inbound to be admitted", || {
                stats.snapshot().connections_accepted == 1
            })
            .await;
        }
        tokio::time::sleep(hold).await;

        // Now the probe completes: a second link to the same peer.
        let _ = release_tx.send(());
        {
            let stats = Arc::clone(&transport.stats);
            wait_for("the probe to be arbitrated", || {
                let s = stats.snapshot();
                s.duplicate_node_declines + s.connections_established == 1
            })
            .await;
        }
        settle().await;

        let outcome = RaceOutcome {
            snap: transport.stats.snapshot(),
            links: {
                let pool = transport.pool.lock().await;
                pool.addrs()
                    .into_iter()
                    .map(|a| {
                        let outbound = pool.get(&a).unwrap().outbound;
                        (a, outbound)
                    })
                    .collect()
            },
            verified: {
                let pool = transport.pool.lock().await;
                pool.addrs()
                    .into_iter()
                    .filter(|a| pool.get(a).unwrap().verified)
                    .collect()
            },
        };
        transport.stop_async().await.unwrap();
        drop(peer);
        outcome
    }

    /// The larger node's probe yields to an inbound that raced it: that
    /// inbound is the link the smaller node dialled, which is the one the
    /// smaller node keeps too.
    #[tokio::test]
    async fn test_a_larger_nodes_probe_yields_to_a_racing_inbound() {
        for inbound_addr in [2, 3] {
            let out =
                probe_completing_after_an_inbound(false, inbound_addr, std::time::Duration::ZERO)
                    .await;
            assert_eq!(out.snap.duplicate_node_declines, 1, "addr {inbound_addr}");
            assert_eq!(out.snap.duplicate_link_replacements, 0);
            assert_eq!(out.snap.connections_established, 0);
            assert_eq!(
                out.links,
                vec![(test_addr(inbound_addr).to_transport_addr(), false)],
                "the inbound is kept"
            );
        }
    }

    /// The smaller node's probe replaces an inbound that raced it: the probe
    /// is the link the smaller node dialled, and the larger node keeps it
    /// too. Keeping whichever link arrived first instead lets the two sides
    /// keep different links, each holding the channel the other closed.
    #[tokio::test]
    async fn test_a_smaller_nodes_probe_replaces_a_racing_inbound() {
        for inbound_addr in [2, 3] {
            let out =
                probe_completing_after_an_inbound(true, inbound_addr, std::time::Duration::ZERO)
                    .await;
            assert_eq!(
                out.snap.duplicate_link_replacements, 1,
                "addr {inbound_addr}"
            );
            assert_eq!(out.snap.duplicate_node_declines, 0);
            assert_eq!(out.snap.connections_established, 1);
            assert_eq!(
                out.links,
                vec![(test_addr(2).to_transport_addr(), true)],
                "the probe is kept"
            );
        }
    }

    /// A second link to a peer whose link has settled — older than one
    /// connect timeout — never displaces it, whichever node dialled it. This
    /// is what stops address rotation, or a late redial, from churning a
    /// working link. At the same address the late probe is declined, since a
    /// second link there would overwrite the pool entry. At another address
    /// the settled link, unverified, blocks nothing: the probe is admitted
    /// beside it and both stay pooled.
    #[tokio::test]
    async fn test_a_settled_link_is_kept_against_a_late_probe() {
        let out =
            probe_completing_after_an_inbound(true, 2, std::time::Duration::from_millis(600)).await;
        assert_eq!(out.snap.duplicate_node_declines, 1);
        assert_eq!(out.snap.duplicate_link_replacements, 0);
        assert_eq!(out.snap.connections_established, 0);
        assert_eq!(
            out.links,
            vec![(test_addr(2).to_transport_addr(), false)],
            "the settled inbound is kept"
        );

        let mut out =
            probe_completing_after_an_inbound(true, 3, std::time::Duration::from_millis(600)).await;
        assert_eq!(out.snap.duplicate_node_declines, 0);
        assert_eq!(out.snap.duplicate_link_replacements, 0);
        assert_eq!(out.snap.connections_established, 1);
        out.links.sort_by_key(|(addr, _)| addr.to_string());
        assert_eq!(
            out.links,
            vec![
                (test_addr(2).to_transport_addr(), true),
                (test_addr(3).to_transport_addr(), false),
            ],
            "the settled inbound is kept beside the probe"
        );
        assert!(
            out.verified.is_empty(),
            "the settled inbound stays unverified"
        );
    }

    /// The tie-break rule itself: each side keeps its outbound link exactly
    /// when it is the smaller node, and two links in the same direction are
    /// no race between the ends.
    #[test]
    fn test_newcomer_wins_only_as_the_link_the_smaller_node_dialled() {
        // (local_is_smaller, newcomer_outbound, incumbent_outbound) -> wins
        let cases = [
            (true, true, false, true),
            (true, false, true, false),
            (false, false, true, true),
            (false, true, false, false),
            (true, true, true, false),
            (true, false, false, false),
            (false, true, true, false),
            (false, false, false, false),
        ];
        for (smaller, new_out, inc_out, wins) in cases {
            assert_eq!(
                newcomer_wins(smaller, new_out, inc_out),
                wins,
                "smaller={smaller} newcomer_outbound={new_out} incumbent_outbound={inc_out}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Two-sided simultaneous dial
    // ------------------------------------------------------------------

    /// One direction of a relayed link: forwards what `src` receives into
    /// `dst`, holding everything until `gate` opens.
    async fn pump(
        src: Arc<MockBleStream>,
        dst: Arc<MockBleStream>,
        mut gate: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut buf = vec![0u8; 4096];
        loop {
            let n = match src.recv(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(n) => n,
            };
            if gate.wait_for(|open| *open).await.is_err() {
                return;
            }
            if dst.send(&buf[..n]).await.is_err() {
                return;
            }
        }
    }

    /// Relay a link between its two ends, one gate per direction. When
    /// either end closes, the whole link closes, as a real channel does.
    fn relay(
        a: MockBleStream,
        b: MockBleStream,
        a_to_b: tokio::sync::watch::Receiver<bool>,
        b_to_a: tokio::sync::watch::Receiver<bool>,
    ) {
        let (a, b) = (Arc::new(a), Arc::new(b));
        tokio::spawn(async move {
            let mut pumps = tokio::task::JoinSet::new();
            pumps.spawn(pump(Arc::clone(&a), Arc::clone(&b), a_to_b));
            pumps.spawn(pump(Arc::clone(&b), Arc::clone(&a), b_to_a));
            pumps.join_next().await;
            pumps.abort_all();
            while pumps.join_next().await.is_some() {}
        });
    }

    /// The two links of a simultaneous dial: `T1` dials `L1`, `T2` dials `L2`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Link {
        L1,
        L2,
    }

    /// How both sides start their dial: from a scan result, through the
    /// scan loop's probe, or as a dial the node layer asked for.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Dial {
        Probe,
        Node,
    }

    /// A link's gates: what its dialler receives, and what its acceptor
    /// receives. A side's pubkey exchange on a link completes when the
    /// direction toward that side opens.
    struct Gates {
        to_dialler: tokio::sync::watch::Sender<bool>,
        to_acceptor: tokio::sync::watch::Sender<bool>,
    }

    type GateRx = (
        tokio::sync::watch::Receiver<bool>,
        tokio::sync::watch::Receiver<bool>,
    );

    fn gates() -> (Gates, GateRx) {
        let (to_dialler, dialler_rx) = tokio::sync::watch::channel(false);
        let (to_acceptor, acceptor_rx) = tokio::sync::watch::channel(false);
        (
            Gates {
                to_dialler,
                to_acceptor,
            },
            (dialler_rx, acceptor_rx),
        )
    }

    /// Make `dialler`'s dials land on `acceptor` through a gated relay, and
    /// return a count of the dials made.
    ///
    /// The first dial uses `first`; any later one — a retry after the race —
    /// is relayed ungated. `seen_as` is the link address the acceptor sees
    /// the dialler on, so a test can choose between a peer that dials from
    /// the address it advertises and one that dials from a rotated one.
    fn cross_wire(
        dialler: &BleTransport<MockBleIo>,
        acceptor: &BleTransport<MockBleIo>,
        seen_as: BleAddr,
        first: GateRx,
    ) -> Arc<std::sync::atomic::AtomicUsize> {
        let acceptor_io = Arc::clone(acceptor.io());
        let first = std::sync::Mutex::new(Some(first));
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counted = Arc::clone(&dials);
        dialler.io().set_connect_handler(move |addr, _psm| {
            counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let (to_dialler, to_acceptor) = first.lock().unwrap().take().unwrap_or_else(|| {
                (
                    tokio::sync::watch::channel(true).1,
                    tokio::sync::watch::channel(true).1,
                )
            });
            let (dialler_end, a) = MockBleStream::pair(test_addr(0xF0), addr.clone(), 2048);
            let (b, acceptor_end) = MockBleStream::pair(seen_as.clone(), test_addr(0xF1), 2048);
            relay(a, b, to_acceptor, to_dialler);
            let acceptor_io = Arc::clone(&acceptor_io);
            tokio::spawn(async move { acceptor_io.inject_inbound(acceptor_end).await });
            Ok(dialler_end)
        });
        dials
    }

    /// One side of a simultaneous dial, read in a single pass.
    struct Side {
        dials: usize,
        stats: stats::BleStatsSnapshot,
        /// Each pooled link: its key, whether this side dialled it, and how
        /// long ago it was admitted.
        links: Vec<(TransportAddr, bool, Duration)>,
    }

    impl Side {
        /// Read a side's dial count, stats and pool. The pool is read under
        /// its lock, so a link being admitted or dropped is seen before or
        /// after, never as a missed read.
        async fn read(t: &BleTransport<MockBleIo>, dials: &std::sync::atomic::AtomicUsize) -> Self {
            let pool = t.pool.lock().await;
            let links = pool
                .addrs()
                .into_iter()
                .map(|a| {
                    let c = pool.get(&a).unwrap();
                    (a, c.outbound, c.established_at.elapsed())
                })
                .collect();
            Self {
                dials: dials.load(std::sync::atomic::Ordering::SeqCst),
                stats: t.stats.snapshot(),
                links,
            }
        }

        /// Links this side admitted, as dialler or acceptor.
        fn admitted(&self) -> u64 {
            self.stats.connections_established + self.stats.connections_accepted
        }

        /// Conclusions this side reached. Each link reaches one per side:
        /// admitted, declined, or closed by the far end before its exchange
        /// finished. A replaced link was admitted first, and the peer can
        /// close a side's incumbent before that side's second exchange
        /// completes, so counting outcomes is the only wait that fits every
        /// order.
        fn concluded(&self) -> u64 {
            self.admitted()
                + self.stats.duplicate_node_declines
                + self.stats.pubkey_exchange_failures
        }

        /// Everything a timed-out wait needs to say which way the race went.
        fn describe(&self) -> String {
            let s = &self.stats;
            let links: Vec<String> = self
                .links
                .iter()
                .map(|(a, out, age)| {
                    let dir = if *out { "out" } else { "in" };
                    format!("{a} {dir} age={}ms", age.as_millis())
                })
                .collect();
            format!(
                "dials={} established={} accepted={} declined={} replaced={} \
                 exchange_failures={} connect_errors={} connect_timeouts={} \
                 rejected={} aborted={} links=[{}]",
                self.dials,
                s.connections_established,
                s.connections_accepted,
                s.duplicate_node_declines,
                s.duplicate_link_replacements,
                s.pubkey_exchange_failures,
                s.connect_errors,
                s.connect_timeouts,
                s.connections_rejected,
                s.handshakes_aborted,
                links.join(", ")
            )
        }
    }

    /// The two sides of a simultaneous dial and their dial counters.
    struct Race<'a> {
        case: &'a str,
        t1: &'a BleTransport<MockBleIo>,
        t2: &'a BleTransport<MockBleIo>,
        dials1: Arc<std::sync::atomic::AtomicUsize>,
        dials2: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Race<'_> {
        /// Wait until `cond` holds for both sides, or fail naming the case,
        /// the step, and both sides' state. Polls as [`wait_for`] does.
        async fn wait(&self, what: &str, cond: impl Fn(&Side, &Side) -> bool) {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
            loop {
                settle().await;
                let s1 = Side::read(self.t1, &self.dials1).await;
                let s2 = Side::read(self.t2, &self.dials2).await;
                if cond(&s1, &s2) {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "{}: timed out waiting for {what}\n  T1: {}\n  T2: {}",
                    self.case,
                    s1.describe(),
                    s2.describe()
                );
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
    }

    /// The one link a side holds once the race settles.
    async fn sole_link(t: &BleTransport<MockBleIo>) -> (TransportAddr, bool) {
        let pool = t.pool.lock().await;
        let addrs = pool.addrs();
        assert_eq!(addrs.len(), 1, "exactly one link to the peer: {addrs:?}");
        let outbound = pool.get(&addrs[0]).unwrap().outbound;
        (addrs[0].clone(), outbound)
    }

    /// Both nodes dial each other at once, and each admits the two links in
    /// a chosen order. Whatever the orders, both must end up holding the
    /// same link — the one the smaller node dialled — and it must carry
    /// traffic both ways.
    async fn simultaneous_dial(
        dial: Dial,
        t1_is_smaller: bool,
        first_at_t1: Link,
        first_at_t2: Link,
        rotated: bool,
    ) {
        let (smaller, larger) = pubkeys_ordered_by_node_addr();
        let case = format!(
            "dial={dial:?} t1_smaller={t1_is_smaller} first_at_t1={first_at_t1:?} \
             first_at_t2={first_at_t2:?} rotated={rotated}"
        );
        let (pk1, pk2) = if t1_is_smaller {
            (smaller, larger)
        } else {
            (larger, smaller)
        };
        let config = BleConfig {
            scan: Some(true),
            ..identity_test_config()
        };
        let (tx1, mut rx1) = tokio::sync::mpsc::channel(64);
        let (tx2, mut rx2) = tokio::sync::mpsc::channel(64);
        let mut t1 = BleTransport::new(
            TransportId::new(1),
            None,
            config.clone(),
            MockBleIo::new("hci0", test_addr(1)),
            tx1,
        );
        let mut t2 = BleTransport::new(
            TransportId::new(2),
            None,
            config,
            MockBleIo::new("hci0", test_addr(2)),
            tx2,
        );
        t1.set_local_pubkey(pk1);
        t2.set_local_pubkey(pk2);

        // A rotated peer dials from an address other than the one it
        // advertises; otherwise both links sit at the same pool key.
        let offset = if rotated { 10 } else { 0 };
        let (l1, l1_rx) = gates();
        let (l2, l2_rx) = gates();
        let dials1 = cross_wire(&t1, &t2, test_addr(1 + offset), l1_rx);
        let dials2 = cross_wire(&t2, &t1, test_addr(2 + offset), l2_rx);
        t1.start_async().await.unwrap();
        t2.start_async().await.unwrap();
        let race = Race {
            case: &case,
            t1: &t1,
            t2: &t2,
            dials1,
            dials2,
        };

        match dial {
            Dial::Probe => {
                t1.io.inject_scan_result(test_addr(2)).await;
                t2.io.inject_scan_result(test_addr(1)).await;
            }
            Dial::Node => {
                t1.connect_async(&test_addr(2).to_transport_addr())
                    .await
                    .unwrap();
                t2.connect_async(&test_addr(1).to_transport_addr())
                    .await
                    .unwrap();
            }
        }
        // No gate opens until both dials are in flight. A side whose dial
        // had not started yet would find the other's link already in its
        // pool and never dial at all: no race, one link, and a count that
        // can never reach two.
        race.wait("both sides to dial", |s1, s2| {
            s1.dials == 1 && s2.dials == 1
        })
        .await;

        // T1 completes L1 as its dialler and L2 as its acceptor; T2 the
        // reverse. A gate on a link that has already closed has no reader;
        // opening it is then a no-op, and the next wait reports the state.
        let open_at_t1 = |link: Link| match link {
            Link::L1 => l1.to_dialler.send_replace(true),
            Link::L2 => l2.to_acceptor.send_replace(true),
        };
        let open_at_t2 = |link: Link| match link {
            Link::L1 => l1.to_acceptor.send_replace(true),
            Link::L2 => l2.to_dialler.send_replace(true),
        };
        let other = |link: Link| match link {
            Link::L1 => Link::L2,
            Link::L2 => Link::L1,
        };
        open_at_t1(first_at_t1);
        race.wait("T1 to admit its first link", |s1, _| s1.admitted() == 1)
            .await;
        open_at_t2(first_at_t2);
        race.wait("T2 to admit its first link", |_, s2| s2.admitted() == 1)
            .await;
        open_at_t1(other(first_at_t1));
        open_at_t2(other(first_at_t2));
        // Exactly two conclusions from exactly one dial each: the race
        // settled by itself, not through a retry after both links died.
        race.wait("both sides to settle on one link", |s1, s2| {
            [s1, s2]
                .iter()
                .all(|s| s.dials == 1 && s.concluded() == 2 && s.links.len() == 1)
        })
        .await;
        settle().await;

        let (key1, out1) = sole_link(&t1).await;
        let (key2, out2) = sole_link(&t2).await;
        assert_eq!(
            out1, t1_is_smaller,
            "{case}: T1 keeps the link the smaller node dialled"
        );
        assert_eq!(
            out2, !t1_is_smaller,
            "{case}: T2 keeps the link the smaller node dialled"
        );

        // The decisive check: the link each side kept is the same channel,
        // so it carries traffic in both directions.
        let frame = build_established_frame(16);
        t1.send_async(&key1, &frame).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), rx2.recv()).await;
        assert_eq!(
            got.ok().flatten().map(|p| p.data),
            Some(frame.clone()),
            "{case}: T1 -> T2"
        );
        t2.send_async(&key2, &frame).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(2), rx1.recv()).await;
        assert_eq!(
            got.ok().flatten().map(|p| p.data),
            Some(frame),
            "{case}: T2 -> T1"
        );

        t1.stop_async().await.unwrap();
        t2.stop_async().await.unwrap();
    }

    /// Every admission order, either node smaller, same address and rotated.
    /// The orders where the two sides admit different links first are the
    /// ones "first link wins" got wrong: each side kept the link the other
    /// had just dropped, and both went down.
    ///
    /// Both tests run on the paused clock. The tie window, the probe retry
    /// tick, the pubkey-exchange timeout and the waits' deadline are then
    /// all virtual time, which moves only when the runtime is idle, and
    /// inside a wait the next timer due is always the wait's own 1 ms poll.
    /// A test thread that the host deschedules for seconds therefore cannot
    /// age an incumbent out of the tie window, expire an exchange, fire a
    /// retry mid-case, or run out a wait: the outcome no longer depends on
    /// how promptly the thread runs.
    async fn every_simultaneous_dial(dial: Dial) {
        for t1_is_smaller in [true, false] {
            for first_at_t1 in [Link::L1, Link::L2] {
                for first_at_t2 in [Link::L1, Link::L2] {
                    for rotated in [false, true] {
                        simultaneous_dial(dial, t1_is_smaller, first_at_t1, first_at_t2, rotated)
                            .await;
                    }
                }
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn test_a_simultaneous_dial_leaves_both_sides_on_the_same_link() {
        every_simultaneous_dial(Dial::Probe).await;
    }

    /// The same race when the node layer starts both dials, which reach the
    /// pool through `connect_async` rather than the scan loop's probe.
    #[tokio::test(start_paused = true)]
    async fn test_a_simultaneous_node_dial_leaves_both_sides_on_the_same_link() {
        every_simultaneous_dial(Dial::Node).await;
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
                send_tx: tokio::sync::mpsc::channel(1).0,
                send_task: None,
                recv_task: None,
                send_mtu: 64,
                recv_mtu: 64,
                established_at: tokio::time::Instant::now(),
                verified: false,
                grace_from: tokio::time::Instant::now(),
                outbound: false,
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
            "pool_evictions",
            "advertisements_sent",
            "scan_results",
            "duplicate_node_declines",
            "duplicate_link_replacements",
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
    /// Asserts on the discovery buffer rather than the pool because the
    /// buffer is what the node layer consumes, and it is populated whether or
    /// not the pool admits the link. Sleeps rather than yields, so a paused
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
        let (our_pubkey, _) = test_keypair(1);
        transport.set_local_pubkey(our_pubkey);
        transport.start_async().await.unwrap();

        let mut peers = Vec::new();
        let mut wanted = Vec::new();
        for n in 0..INBOUND_HANDSHAKE_INFLIGHT {
            let addr = test_addr(40 + n as u8);
            let stream = connect_inbound(&transport, &addr).await;
            let (_, peer_pubkey) = test_keypair(10 + n as u8);
            send_pubkey(&stream, &peer_pubkey).await;
            peers.push(stream);
            wanted.push(addr);
        }

        assert!(
            wait_for_discovered(&transport.neighbor_buffer, &wanted).await,
            "a well-behaved peer inside the budget was not admitted"
        );
        assert_eq!(transport.stats.snapshot().handshakes_aborted, 0);
        assert_eq!(
            transport.pool.lock().await.len(),
            INBOUND_HANDSHAKE_INFLIGHT,
            "every inbound is pooled"
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
            // Past the tie window, so the dial is not a race the inbound
            // settles: with room it is admitted beside the unverified inbound.
            tokio::time::advance(transport.tie_window() + Duration::from_millis(1)).await;

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

    // ------------------------------------------------------------------
    // A link landing at an address that already holds one
    // ------------------------------------------------------------------

    /// Start an inbound from `from` and wait until the transport has sent its
    /// half of the key exchange. The remote's half is held back; the returned
    /// end must be kept alive, or the link closes.
    async fn held_inbound(transport: &BleTransport<MockBleIo>, from: &BleAddr) -> MockBleStream {
        let (ours, theirs) = MockBleStream::pair(test_addr(1), from.clone(), 2048);
        transport.io.inject_inbound(ours).await;
        let mut buf = [0u8; PUBKEY_EXCHANGE_SIZE];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), theirs.recv(&mut buf))
            .await
            .expect("the transport starts the inbound's key exchange")
            .unwrap();
        assert_eq!(n, PUBKEY_EXCHANGE_SIZE);
        theirs
    }

    /// Send the remote's half of the key exchange, claiming `claim`.
    async fn release_claim(theirs: &MockBleStream, claim: &[u8; 32]) {
        let mut msg = [0u8; PUBKEY_EXCHANGE_SIZE];
        msg[0] = PUBKEY_EXCHANGE_PREFIX;
        msg[1..].copy_from_slice(claim);
        theirs.send(&msg).await.unwrap();
    }

    /// A transport holding the largest of three keys, whose every dial is
    /// answered claiming the middle one, with a dial to `x` pooled while an
    /// inbound from `x` waits on its exchange. Returns the transport, the
    /// held inbound's remote end, and the smallest and middle keys.
    async fn dial_lands_beside_a_held_inbound(
        x: &BleAddr,
    ) -> (BleTransport<MockBleIo>, MockBleStream, [u8; 32], [u8; 32]) {
        let keys = pubkeys_by_node_addr(3);
        let (p, q, ours) = (keys[0], keys[1], keys[2]);
        let (mut transport, dials) = answering_transport(ours, q, identity_test_config());
        transport.start_async().await.unwrap();

        let inbound = held_inbound(&transport, x).await;
        transport
            .connect_async(&x.to_transport_addr())
            .await
            .unwrap();
        wait_for("the dial to land at the address", || pooled(&transport, x)).await;
        assert_eq!(dial_count(&dials, x), 1);
        assert_eq!(claim_at(&transport, x).await, Some(node_of(&q)));
        let _ = transport.neighbor_buffer.take();
        (transport, inbound, p, q)
    }

    /// An inbound whose exchange completes after a dial landed at the same
    /// address must not replace the dialled link, nor be announced.
    #[tokio::test]
    async fn an_inbound_completing_after_a_dial_landed_at_its_address_does_not_replace_it() {
        let x = test_addr(5);
        let (mut transport, inbound, p, q) = dial_lands_beside_a_held_inbound(&x).await;

        release_claim(&inbound, &p).await;
        // Decided when the refused inbound's link closes; on the defect it
        // stays open, pooled over the dialled link.
        let mut buf = [0u8; 64];
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(2), inbound.recv(&mut buf)).await;

        assert_eq!(
            claim_at(&transport, &x).await,
            Some(node_of(&q)),
            "the inbound replaced the dialled link at its address"
        );
        assert!(
            matches!(closed, Ok(Ok(0))),
            "the inbound at the occupied address is dropped: {closed:?}"
        );
        let announced = transport.neighbor_buffer.take();
        assert!(
            announced
                .iter()
                .all(|d| d.pubkey_hint.map(|k| NodeAddr::from_pubkey(&k)) != Some(node_of(&p))),
            "the refused inbound's claim is not announced: {announced:?}"
        );
        transport.stop_async().await.unwrap();
    }

    /// A newcomer at an occupied address that closes as soon as its exchange
    /// is done must leave the link already pooled there in place.
    #[tokio::test]
    async fn a_newcomer_at_an_occupied_address_that_closes_at_once_leaves_the_incumbent_pooled() {
        let x = test_addr(5);
        let (mut transport, inbound, p, q) = dial_lands_beside_a_held_inbound(&x).await;

        release_claim(&inbound, &p).await;
        drop(inbound);

        let emptied = eventually(|| unpooled(&transport, &x)).await;
        assert!(
            !emptied,
            "the address no longer holds the dialled link after the newcomer closed"
        );
        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        {
            let pool = transport.pool.lock().await;
            let task = pool
                .get(&x.to_transport_addr())
                .and_then(|c| c.recv_task.as_ref());
            assert!(
                task.is_some_and(|t| !t.is_finished()),
                "the dialled link's receive loop still runs"
            );
        }
        transport.stop_async().await.unwrap();
    }

    /// A newcomer at an occupied address that sends an FMP frame right after
    /// its key exchange must have none of its frames delivered under the
    /// incumbent's address: its receive loop may start only once it is
    /// pooled, and it never is.
    #[tokio::test]
    async fn a_refused_newcomers_frame_is_never_delivered_under_the_incumbents_address() {
        let keys = pubkeys_by_node_addr(3);
        let (p, q, ours) = (keys[0], keys[1], keys[2]);
        let io = MockBleIo::new("hci0", test_addr(1));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        io.set_connect_handler(move |addr, _psm| {
            let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
            peer_tx
                .send(theirs)
                .map_err(|_| TransportError::ConnectionRefused)?;
            Ok(mine)
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut transport =
            BleTransport::new(TransportId::new(1), None, identity_test_config(), io, tx);
        transport.set_local_pubkey(ours);
        transport.start_async().await.unwrap();

        let x = test_addr(5);
        let inbound = held_inbound(&transport, &x).await;
        transport
            .connect_async(&x.to_transport_addr())
            .await
            .unwrap();
        let dialled = tokio::time::timeout(std::time::Duration::from_secs(5), peer_rx.recv())
            .await
            .expect("the dial reaches the remote")
            .unwrap();
        peer_side_exchange(&dialled, &q).await;
        wait_for("the dial to land at the address", || pooled(&transport, &x)).await;
        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));

        // Hold the pool so the newcomer finishes its exchange, sends its
        // frame and queues at its duplicate check; then queue a second
        // holder behind it. The pool lock is first come, first served, so
        // the newcomer's insert waits behind that holder, after the point
        // where a receive loop spawned early would already be reading.
        {
            let held = transport.hold_pool().await;
            release_claim(&inbound, &p).await;
            inbound.send(&build_established_frame(24)).await.unwrap();
            for _ in 0..20 {
                settle().await;
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let pool = Arc::clone(&transport.pool);
            tokio::spawn(async move {
                let g = pool.lock().await;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                drop(g);
            });
            settle().await;
            drop(held);
        }
        for _ in 0..20 {
            settle().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        let leaked = rx.try_recv();
        assert!(
            leaked.is_err(),
            "a frame from the refused newcomer was delivered under {x}: {leaked:?}"
        );
        drop(dialled);
        transport.stop_async().await.unwrap();
    }

    /// A dial whose remote sends an FMP frame right after its key exchange,
    /// completing after an inbound landed at the dialled address, must have
    /// none of its frames delivered under the incumbent's address: the
    /// dial's receive loop may start only once it is pooled, and it never is.
    #[tokio::test]
    async fn a_refused_dials_frame_is_never_delivered_under_the_incumbents_address() {
        let keys = pubkeys_by_node_addr(3);
        // Q < ours: the inbound from Q is kept by the inbound tie-breaker.
        let (q, ours, p) = (keys[0], keys[1], keys[2]);
        let io = MockBleIo::new("hci0", test_addr(1));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        io.set_connect_handler(move |addr, _psm| {
            let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
            peer_tx
                .send(theirs)
                .map_err(|_| TransportError::ConnectionRefused)?;
            Ok(mine)
        });
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut transport =
            BleTransport::new(TransportId::new(1), None, identity_test_config(), io, tx);
        transport.set_local_pubkey(ours);
        transport.start_async().await.unwrap();

        let x = test_addr(5);
        // The dial starts while the address is free.
        transport
            .connect_async(&x.to_transport_addr())
            .await
            .unwrap();
        let dialled = tokio::time::timeout(std::time::Duration::from_secs(5), peer_rx.recv())
            .await
            .expect("the dial reaches the remote")
            .unwrap();
        // An inbound claiming Q lands at the address first.
        let _inbound = dial_in(&transport, &x, &q).await;
        wait_for("the inbound to land at the address", || {
            pooled(&transport, &x)
        })
        .await;
        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));

        // Hold the pool while the dial's remote finishes its exchange as P
        // and sends a frame at once; the dial then waits on the pool.
        {
            let held = transport.hold_pool().await;
            peer_side_exchange(&dialled, &p).await;
            dialled.send(&build_established_frame(24)).await.unwrap();
            for _ in 0..20 {
                settle().await;
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            drop(held);
        }
        for _ in 0..20 {
            settle().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        let leaked = rx.try_recv();
        assert!(
            leaked.is_err(),
            "a frame from the refused dial was delivered under {x}: {leaked:?}"
        );
        drop(dialled);
        transport.stop_async().await.unwrap();
    }

    /// The probe twin: a probe whose remote sends an FMP frame right after
    /// its key exchange, completing after an inbound landed at the probed
    /// address, must have none of its frames delivered under the incumbent's
    /// address.
    #[tokio::test]
    async fn a_refused_probes_frame_is_never_delivered_under_the_incumbents_address() {
        let keys = pubkeys_by_node_addr(3);
        // Q < ours < P on both tie-breakers: the inbound from Q is kept, and
        // the probe answered by P reaches the pool rather than yielding.
        let (q, ours, p) = (keys[0], keys[1], keys[2]);
        let io = MockBleIo::new("hci0", test_addr(1));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        io.set_connect_handler(move |addr, _psm| {
            let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
            peer_tx
                .send(theirs)
                .map_err(|_| TransportError::ConnectionRefused)?;
            Ok(mine)
        });
        let config = BleConfig {
            scan: Some(true),
            ..identity_test_config()
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.set_local_pubkey(ours);
        transport.start_async().await.unwrap();

        let x = test_addr(5);
        // The probe starts while the address is free.
        transport.io.inject_scan_result(x.clone()).await;
        let probed = tokio::time::timeout(std::time::Duration::from_secs(5), peer_rx.recv())
            .await
            .expect("the probe reaches the remote")
            .unwrap();
        // An inbound claiming Q lands at the address first.
        let _inbound = dial_in(&transport, &x, &q).await;
        wait_for("the inbound to land at the address", || {
            pooled(&transport, &x)
        })
        .await;
        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));

        // Hold the pool while the probe's remote finishes its exchange as P
        // and sends a frame at once; the probe then queues at its duplicate
        // check. Queue a second holder behind it: the pool lock is first
        // come, first served, so the probe's insert waits behind that
        // holder, after the point where a receive loop spawned early would
        // already be reading.
        {
            let held = transport.hold_pool().await;
            peer_side_exchange(&probed, &p).await;
            probed.send(&build_established_frame(24)).await.unwrap();
            for _ in 0..20 {
                settle().await;
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            let pool = Arc::clone(&transport.pool);
            tokio::spawn(async move {
                let g = pool.lock().await;
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                drop(g);
            });
            settle().await;
            drop(held);
        }
        for _ in 0..20 {
            settle().await;
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        let leaked = rx.try_recv();
        assert!(
            leaked.is_err(),
            "a frame from the refused probe was delivered under {x}: {leaked:?}"
        );
        drop(probed);
        transport.stop_async().await.unwrap();
    }

    /// Collect announcements for a few seconds of the transport's clock and
    /// report whether any of them names `node`.
    async fn announces(transport: &BleTransport<MockBleIo>, node: NodeAddr) -> bool {
        let mut seen = Vec::new();
        eventually(|| {
            seen.extend(transport.neighbor_buffer.take());
            seen.iter()
                .any(|d| d.pubkey_hint.map(|k| NodeAddr::from_pubkey(&k)) == Some(node))
        })
        .await
    }

    /// A dial whose exchange completes after an inbound landed at the dialled
    /// address leaves the inbound in place and does not announce its claim.
    #[tokio::test(start_paused = true)]
    async fn a_dial_completing_at_an_address_an_inbound_holds_is_dropped_unannounced() {
        let keys = pubkeys_by_node_addr(3);
        let (p, q, ours) = (keys[0], keys[1], keys[2]);
        let x = test_addr(5);
        let open = Arc::new(tokio::sync::Notify::new());
        let gate = Some((x.clone(), Arc::clone(&open)));
        let (mut transport, dials) = gated_transport(ours, p, identity_test_config(), gate);
        transport.start_async().await.unwrap();

        transport
            .connect_async(&x.to_transport_addr())
            .await
            .unwrap();
        wait_for("the dial", || dial_count(&dials, &x) == 1).await;
        let _inbound = dial_in(&transport, &x, &q).await;
        wait_for("the inbound to land at the address", || {
            pooled(&transport, &x)
        })
        .await;
        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        transport.neighbor_buffer.take();

        open.notify_one();
        assert!(
            !announces(&transport, node_of(&p)).await,
            "the dial refused at an occupied address announced its claim"
        );
        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        transport.stop_async().await.unwrap();
    }

    /// A probe whose exchange completes after an inbound landed at the probed
    /// address leaves the inbound in place and does not announce its claim.
    #[tokio::test(start_paused = true)]
    async fn a_probe_completing_at_an_address_an_inbound_holds_is_dropped_unannounced() {
        let keys = pubkeys_by_node_addr(3);
        // Q < ours < P on both tie-breakers: the inbound from Q is kept, and
        // the probe answered by P reaches the pool rather than yielding.
        let (q, ours, p) = (keys[0], keys[1], keys[2]);
        let x = test_addr(5);
        let config = BleConfig {
            scan: Some(true),
            ..identity_test_config()
        };
        let open = Arc::new(tokio::sync::Notify::new());
        let gate = Some((x.clone(), Arc::clone(&open)));
        let (mut transport, dials) = gated_transport(ours, p, config, gate);
        transport.start_async().await.unwrap();

        transport.io.inject_scan_result(x.clone()).await;
        wait_for("the probe's dial", || dial_count(&dials, &x) == 1).await;
        let _inbound = dial_in(&transport, &x, &q).await;
        wait_for("the inbound to land at the address", || {
            pooled(&transport, &x)
        })
        .await;
        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        transport.neighbor_buffer.take();

        open.notify_one();
        assert!(
            !announces(&transport, node_of(&p)).await,
            "the probe refused at an occupied address announced its claim"
        );
        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        transport.stop_async().await.unwrap();
    }

    // ------------------------------------------------------------------
    // The probe loop's memory of addresses it has seen
    // ------------------------------------------------------------------

    /// One of a flood of distinct link addresses.
    fn flood_addr(i: u16) -> BleAddr {
        let [hi, lo] = i.to_be_bytes();
        BleAddr {
            adapter: "hci0".to_string(),
            device: [0x20, 0x00, 0x00, 0x00, hi, lo],
        }
    }

    /// Distinct addresses in each probe-memory flood: far more than any
    /// bound the memory could reasonably have.
    const FLOOD: u16 = 1_000;

    /// A peer that advertised its PSM once, connected and went away is not
    /// live, so a flood of new advertising addresses must not leave its PSM
    /// remembered for ever: an unbounded memory keeps every one of them.
    #[tokio::test]
    async fn a_departed_peers_learned_psm_is_not_kept_through_a_thousand_new_advertising_addresses()
    {
        let keys = pubkeys_by_node_addr(2);
        let (ours, peer) = (keys[0], keys[1]);
        let a = test_addr(2);
        let io = MockBleIo::new("hci0", test_addr(1));
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel();
        {
            let dials = Arc::clone(&dials);
            let a = a.clone();
            io.set_connect_handler(move |addr, psm| {
                dials.lock().unwrap().push((addr.clone(), psm));
                let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
                if *addr == a {
                    peer_tx
                        .send(theirs)
                        .map_err(|_| TransportError::ConnectionRefused)?;
                }
                // Every other remote hangs up at once, so its exchange fails
                // and nothing is pooled.
                Ok(mine)
            });
        }
        let config = BleConfig {
            scan: Some(true),
            accept_connections: Some(false),
            ..identity_test_config()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.set_local_pubkey(ours);
        transport.start_async().await.unwrap();

        // The peer advertises its PSM once, is probed and pooled, then leaves.
        transport
            .io
            .inject_scan_advert(io::ScanAdvert::with_psm(a.clone(), 0x00C1))
            .await;
        let theirs = tokio::time::timeout(std::time::Duration::from_secs(5), peer_rx.recv())
            .await
            .expect("the peer is probed")
            .unwrap();
        peer_side_exchange(&theirs, &peer).await;
        wait_for("the peer to be pooled", || pooled(&transport, &a)).await;
        drop(theirs);
        wait_for("the peer's link to close", || unpooled(&transport, &a)).await;

        for i in 0..FLOOD {
            transport
                .io
                .inject_scan_advert(io::ScanAdvert::with_psm(flood_addr(i), 0x00C3))
                .await;
        }
        let stats = Arc::clone(&transport.stats);
        wait_for("every flood address to be probed", || {
            stats.snapshot().pubkey_exchange_failures >= u64::from(FLOOD)
        })
        .await;

        // The departed peer is seen again by a scan that carries no PSM.
        transport.io.inject_scan_result(a.clone()).await;
        let redial = {
            let dials = Arc::clone(&dials);
            let a = a.clone();
            move || {
                dials
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|(d, _)| *d == a)
                    .count()
                    >= 2
            }
        };
        wait_for("the departed peer to be probed again", redial).await;
        let psms: Vec<u16> = dials
            .lock()
            .unwrap()
            .iter()
            .filter(|(d, _)| *d == a)
            .map(|(_, psm)| *psm)
            .collect();
        assert_eq!(
            psms,
            vec![0x00C1, DEFAULT_PSM],
            "the probe memory still held the departed peer's PSM after {FLOOD} newer \
             advertising addresses"
        );
        transport.stop_async().await.unwrap();
    }

    /// An address the probe declined beside its node's verified link is
    /// remembered so it is not probed again; a flood of new declined
    /// addresses must not leave every one of them remembered for ever.
    #[tokio::test]
    async fn an_old_declined_address_is_not_remembered_through_a_thousand_new_declined_addresses() {
        let keys = pubkeys_by_node_addr(2);
        let (ours, n) = (keys[0], keys[1]);
        let (mut transport, dials) = scanning_transport(ours, n, false);
        transport.start_async().await.unwrap();

        // The node's verified link, at address 2.
        transport.io.inject_scan_result(test_addr(2)).await;
        wait_for("the node's link to be pooled", || {
            pooled(&transport, &test_addr(2))
        })
        .await;
        transport
            .mark_verified(&test_addr(2).to_transport_addr(), &node_of(&n))
            .await;

        // Address 3 claims the same node and is declined, and remembered.
        let a = test_addr(3);
        transport.io.inject_scan_result(a.clone()).await;
        let stats = Arc::clone(&transport.stats);
        wait_for("the first decline", || {
            stats.snapshot().duplicate_node_declines == 1
        })
        .await;

        for i in 0..FLOOD {
            transport.io.inject_scan_result(flood_addr(i)).await;
        }
        wait_for("every flood address to be declined", || {
            stats.snapshot().duplicate_node_declines == 1 + u64::from(FLOOD)
        })
        .await;

        // Address 3 is seen again. A bounded memory has forgotten it among
        // the thousand newer ones, so it is probed (and declined) again.
        transport.io.inject_scan_result(a.clone()).await;
        let redialled = eventually(|| dial_count(&dials, &a) == 2).await;
        assert!(
            redialled,
            "the probe memory still remembered the old declined address after {FLOOD} \
             newer declined addresses, so it was skipped without a dial"
        );
        transport.stop_async().await.unwrap();
    }

    /// A probing transport holding `ours`, whose dials to `peer_at` hand the
    /// remote end to the returned receiver and whose every other dial is
    /// hung up at once, so its exchange fails and nothing is pooled.
    fn psm_flood_transport(
        ours: [u8; 32],
        peer_at: &BleAddr,
    ) -> (
        BleTransport<MockBleIo>,
        tokio::sync::mpsc::UnboundedReceiver<MockBleStream>,
    ) {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let peer_at = peer_at.clone();
        io.set_connect_handler(move |addr, _psm| {
            let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
            if *addr == peer_at {
                peer_tx
                    .send(theirs)
                    .map_err(|_| TransportError::ConnectionRefused)?;
            }
            Ok(mine)
        });
        let config = BleConfig {
            scan: Some(true),
            accept_connections: Some(false),
            ..identity_test_config()
        };
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
        transport.set_local_pubkey(ours);
        (transport, peer_rx)
    }

    /// Advertise each of `FLOOD` new addresses with a PSM and wait until
    /// every one has been probed and has failed its exchange.
    async fn flood_psm_adverts(transport: &BleTransport<MockBleIo>) {
        let before = transport.stats.snapshot().pubkey_exchange_failures;
        for i in 0..FLOOD {
            transport
                .io
                .inject_scan_advert(io::ScanAdvert::with_psm(flood_addr(i), 0x00C3))
                .await;
        }
        let stats = Arc::clone(&transport.stats);
        wait_for("every flood address to be probed", || {
            stats.snapshot().pubkey_exchange_failures >= before + u64::from(FLOOD)
        })
        .await;
    }

    /// Advertisements from ever new addresses whose exchanges fail must not
    /// grow the probe memory past its bound on non-live addresses, plus the
    /// retry book's addresses, which are live.
    #[tokio::test]
    async fn advertisements_from_ever_new_addresses_do_not_grow_the_probe_memory_past_its_bound() {
        let keys = pubkeys_by_node_addr(1);
        let (mut transport, _peer_rx) = psm_flood_transport(keys[0], &test_addr(2));
        transport.start_async().await.unwrap();

        flood_psm_adverts(&transport).await;

        let remembered = recall(&transport.learned_psm).len();
        assert!(
            remembered <= recall::MAX_RECALLED_ADDRS + MAX_PENDING_PROBES,
            "the probe memory holds {remembered} PSMs after {FLOOD} new advertising addresses"
        );
        transport.stop_async().await.unwrap();
    }

    /// A pooled peer is live, so a flood of new advertising addresses must
    /// not cost it the PSM it advertised.
    #[tokio::test]
    async fn a_pooled_peers_learned_psm_survives_an_address_flood() {
        let keys = pubkeys_by_node_addr(2);
        let (ours, peer) = (keys[0], keys[1]);
        let a = test_addr(2);
        let (mut transport, mut peer_rx) = psm_flood_transport(ours, &a);
        transport.start_async().await.unwrap();

        transport
            .io
            .inject_scan_advert(io::ScanAdvert::with_psm(a.clone(), 0x00C1))
            .await;
        let theirs = tokio::time::timeout(std::time::Duration::from_secs(5), peer_rx.recv())
            .await
            .expect("the peer is probed")
            .unwrap();
        peer_side_exchange(&theirs, &peer).await;
        wait_for("the peer to be pooled", || pooled(&transport, &a)).await;

        flood_psm_adverts(&transport).await;

        assert!(pooled(&transport, &a), "the peer's link is still pooled");
        assert_eq!(
            recall(&transport.learned_psm).get(&a).copied(),
            Some(0x00C1),
            "the pooled peer's learned PSM was lost to the flood"
        );
        drop(theirs);
        transport.stop_async().await.unwrap();
    }

    /// An inbound at the address of a young link claiming another node is
    /// refused without announcing its claim and without counting as a
    /// duplicate-node decline: the kept link does not reach the newcomer's
    /// node, so reporting the newcomer there would have the node dial it over
    /// that link.
    #[tokio::test]
    async fn an_inbound_at_a_young_links_address_claiming_another_node_is_refused_silently() {
        let x = test_addr(5);
        let (mut transport, inbound, p, q) = dial_lands_beside_a_held_inbound(&x).await;
        let declines = transport.stats.snapshot().duplicate_node_declines;
        {
            let pool = transport.pool.lock().await;
            let incumbent = pool
                .get(&x.to_transport_addr())
                .expect("the dial is pooled");
            assert!(
                incumbent.established_at.elapsed() < transport.tie_window(),
                "precondition: the dialled link is still inside the tie window"
            );
        }

        release_claim(&inbound, &p).await;
        let mut buf = [0u8; 64];
        let closed =
            tokio::time::timeout(std::time::Duration::from_secs(2), inbound.recv(&mut buf)).await;
        assert!(
            matches!(closed, Ok(Ok(0))),
            "the inbound at the occupied address is dropped: {closed:?}"
        );

        assert_eq!(claim_at(&transport, &x).await, Some(node_of(&q)));
        assert!(
            !announces(&transport, node_of(&p)).await,
            "the refused inbound's claim was announced"
        );
        assert_eq!(
            transport.stats.snapshot().duplicate_node_declines,
            declines,
            "a refusal at an occupied address is not a duplicate-node decline"
        );
        transport.stop_async().await.unwrap();
    }

    /// A dialled newcomer at an address that holds a link claiming another
    /// node is refused before the tie-break: winning it against a young rival
    /// link to its claimed node at another address would remove that rival,
    /// and the pool would then refuse the newcomer anyway.
    #[tokio::test]
    async fn a_newcomer_at_an_occupied_address_does_not_evict_a_rival_elsewhere() {
        fn node(n: u8) -> NodeAddr {
            let mut b = [0u8; 16];
            b[0] = n;
            NodeAddr::from_bytes(b)
        }
        fn ble(n: u8) -> BleAddr {
            BleAddr {
                adapter: "hci0".to_string(),
                device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
            }
        }
        fn conn(n: u8, claims: u8, outbound: bool) -> BleConnection<()> {
            let now = tokio::time::Instant::now();
            BleConnection {
                stream: (),
                send_tx: tokio::sync::mpsc::channel(1).0,
                send_task: None,
                recv_task: None,
                send_mtu: 2048,
                recv_mtu: 2048,
                established_at: now,
                verified: false,
                grace_from: now,
                outbound,
                addr: ble(n),
                node_addr: Some(node(claims)),
            }
        }
        let (local, p) = (node(1), node(2));
        let x = ble(5).to_transport_addr();
        let y = ble(6).to_transport_addr();
        let mut pool: ConnectionPool<()> =
            ConnectionPool::new(7, std::time::Duration::from_secs(10));
        let now = tokio::time::Instant::now();
        // X holds a link claiming node 3; Y holds a young inbound link claiming P.
        let _ = pool.insert(x.clone(), conn(5, 3, false), now);
        let _ = pool.insert(y.clone(), conn(6, 2, false), now);
        let stats = BleStats::new();
        let tie = std::time::Duration::from_secs(5);
        let dialled = settle_dialled(&mut pool, Some(local), Some(p), tie, &x, &stats);
        if matches!(dialled, Dialled::Keep) {
            let _ = pool_link(&mut pool, &x, conn(5, 2, true), now, async {});
        }
        assert!(
            pool.contains(&y),
            "the rival link to P at Y survives a newcomer refused at the occupied X"
        );
        assert_eq!(pool.get(&x).and_then(|c| c.node_addr), Some(node(3)));
    }
}
