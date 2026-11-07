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
//! enforces a configurable maximum (default 7). An address counts as
//! carrying a node's session only while the node's active peer uses it.
//! Until then it may be evicted, once it has had at least
//! `connect_timeout_ms` (never less than 10 s) to verify; a verified address
//! is never evicted, and a newcomer that finds nothing evictable is refused.
//! Eviction happens only when the pool is full and nothing closes an
//! unverified link on a timer, so with `max_connections` above what the
//! adapter can hold, links that never verify can keep the adapter's
//! remaining connections.

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
use pool::{Admission, Admitted, BleConnection, ConnectionPool, Verify};
use recall::Recall;
use stats::BleStats;
use stream_read::BleStreamRead;

use portable_atomic::AtomicU64;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
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
/// connection limits, evicting only unverified addresses.
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
    /// L2CAP listener PSMs read out of peers' advertisements, by link
    /// address. A peer whose platform assigns its listener PSM cannot be
    /// dialled at a configured constant, so it publishes the number it
    /// actually bound and every dial to it, the scan loop's probe and the
    /// node's [`connect_async`](Self::connect_async) alike, goes there. A
    /// peer that advertises nothing is dialled at the configured PSM.
    learned_psm: LearnedPsm,
    /// Source of channel ids, which tell channels at one address apart.
    next_id: Arc<AtomicU64>,
}

/// Advertised listener PSM by link address, shared between the scan loop
/// that learns it and the dials that need it. A plain mutex: never held
/// across an await. Bounded: see [`Recall`].
type LearnedPsm = Arc<std::sync::Mutex<Recall<u16>>>;

/// Lock an address memory. A panic while it was held leaves nothing half
/// written that its users rely on, so a poisoned lock is used as it is.
fn recall<V>(memory: &Arc<std::sync::Mutex<Recall<V>>>) -> std::sync::MutexGuard<'_, Recall<V>> {
    memory.lock().unwrap_or_else(|e| e.into_inner())
}

/// The PSM to dial `addr` at: what it advertised, else `configured`.
fn psm_for(learned: &LearnedPsm, addr: &BleAddr, configured: u16) -> u16 {
    recall(learned).get(addr).copied().unwrap_or(configured)
}

/// A learned PSM that refused a dial is stale: forget it, so the next
/// advert re-learns it and the fallback applies in the meantime.
///
/// Only the PSM that was actually dialled is forgotten. A dial that went out
/// at the configured fallback, or at a value the scan loop has since
/// replaced, says nothing about the entry the map holds now.
///
/// Callers forget on a refusal only, never on a timeout: a timeout says the
/// peer was out of reach, not that it listens elsewhere, and on BlueZ
/// nothing would re-learn the entry, because `DeviceAdded` fires once per
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

/// Everything a channel needs from its transport, shared by every path
/// that builds one: the accept loop, the scan loop's probe, and the node's
/// own dials. One place spawns a channel's tasks and offers it to the pool,
/// so the paths cannot drift apart.
struct Channels<S> {
    pool: Arc<Mutex<ConnectionPool<Arc<S>>>>,
    packet_tx: PacketTx,
    transport_id: TransportId,
    stats: Arc<BleStats>,
    next_id: Arc<AtomicU64>,
    /// How long a retired channel stays open for the peer's last frames
    /// before it is dropped.
    linger: std::time::Duration,
}

impl<S> Clone for Channels<S> {
    fn clone(&self) -> Self {
        Self {
            pool: Arc::clone(&self.pool),
            packet_tx: self.packet_tx.clone(),
            transport_id: self.transport_id,
            stats: Arc::clone(&self.stats),
            next_id: Arc::clone(&self.next_id),
            linger: self.linger,
        }
    }
}

impl<S: BleStream + 'static> Channels<S> {
    /// Start a channel's reader and writer and offer it to the pool at
    /// `addr`: the address dialled for an outbound channel, the stream's
    /// remote address for an inbound one.
    ///
    /// Records the outcome in the counters: a dial that is kept counts as
    /// established and an inbound as accepted, whether it is the address's
    /// only channel or held beside another; a channel retired on arrival
    /// counts only as a duplicate closed. On `Err` the pool was full and the
    /// channel is gone. Only [`Admission::Admit`] is a newly linked address
    /// that the node layer has not been told about.
    async fn admit(
        &self,
        stream: S,
        addr: BleAddr,
        outbound: bool,
    ) -> Result<Admitted, TransportError> {
        let ta = addr.to_transport_addr();
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let send_mtu = stream.send_mtu();
        let recv_mtu = stream.recv_mtu();
        let stream = Arc::new(stream);
        // One reader for the life of the channel: it buffers what one `recv`
        // left over, so packet boundaries come from the FMP length prefix
        // rather than from the L2CAP SDU boundary.
        let reader = BleStreamRead::new(Arc::clone(&stream), recv_mtu);

        let recv_task = tokio::spawn(receive_loop(
            reader,
            ta.clone(),
            id,
            Arc::clone(&self.pool),
            self.packet_tx.clone(),
            self.transport_id,
            Arc::clone(&self.stats),
            recv_mtu,
        ));
        let (send_tx, send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
        let send_task = tokio::spawn(send_loop(
            Arc::clone(&stream),
            send_rx,
            ta.clone(),
            id,
            Arc::clone(&self.pool),
            Arc::clone(&self.stats),
        ));

        let now = tokio::time::Instant::now();
        let conn = BleConnection {
            stream,
            send_tx,
            send_task: Some(send_task),
            recv_task: Some(recv_task),
            send_mtu,
            recv_mtu,
            established_at: now,
            addr,
            outbound,
            id,
        };

        let role = if outbound { "central" } else { "peripheral" };
        let (admitted, max) = {
            let mut pool = self.pool.lock().await;
            (pool.insert(ta.clone(), conn, now), pool.max_connections())
        };
        let (Ok(Admitted { ended, .. }) | Err(pool::Refused { ended, .. })) = &admitted;
        if let Some(n) = ended {
            info!(refused = n, "BLE pool refusal run ended");
        }
        // A full pool is a state an attacker in radio range can hold, so a
        // refusal logs at debug, with one warning at the start of a run.
        let admitted = match admitted {
            Ok(admitted) => admitted,
            Err(refused) => {
                self.stats.record_connection_rejected();
                debug!(addr = %ta, role, outcome = "pool-rejected", "BLE pool full, link dropped");
                if refused.first {
                    warn!(
                        bound = max,
                        "BLE pool full of verified links or links still inside their grace \
                         (max_connections); refusing new links"
                    );
                }
                return Err(TransportError::SendFailed("pool full".into()));
            }
        };
        if let Some(evicted) = &admitted.evicted {
            self.stats.record_pool_eviction();
            debug!(
                addr = %ta, role, evicted = %evicted, outcome = "evicted-unverified",
                "BLE pool full, evicted an unverified link"
            );
        }
        if admitted.admission != Admission::Retire {
            if outbound {
                self.stats.record_connection_established();
            } else {
                self.stats.record_connection_accepted();
            }
        }
        if admitted.admission == Admission::Hold {
            self.stats.record_duplicate_held();
        }
        debug!(
            addr = %ta, role, channel = id, admission = ?admitted.admission,
            send_mtu, recv_mtu, "BLE channel admitted"
        );
        self.linger(&ta, &admitted.retired);
        Ok(admitted)
    }

    /// Record which direction to keep at `addr`, and retire the held
    /// channels of the other direction.
    async fn settle(&self, addr: &TransportAddr, keep_outbound: bool) {
        let retired = self.pool.lock().await.settle(addr, keep_outbound);
        if !retired.is_empty() {
            debug!(addr = %addr, keep_outbound, "BLE link settled");
        }
        self.linger(addr, &retired);
    }

    /// Drop each retired channel once the linger passes, unless its reader
    /// has already seen the peer close it.
    fn linger(&self, addr: &TransportAddr, ids: &[u64]) {
        for &id in ids {
            self.stats.record_duplicate_closed();
            debug!(addr = %addr, channel = id, "BLE channel retired");
            let pool = Arc::clone(&self.pool);
            let addr = addr.clone();
            let linger = self.linger;
            tokio::spawn(async move {
                tokio::time::sleep(linger).await;
                pool.lock().await.remove_channel(&addr, id);
            });
        }
    }
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
            learned_psm: Arc::default(),
            next_id: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Get the instance name.
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// This transport's configured part in a link's paths.
    pub fn role(&self) -> crate::config::TransportRole {
        self.config.role
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<BleStats> {
        &self.stats
    }

    /// Whether the pool holds a connection to `addr`. Reads only: no
    /// background connect is started or promoted, and the pool lock is
    /// awaited rather than tried. A test hook: this line's node does not ask.
    #[cfg(test)]
    pub(crate) async fn has_connection(&self, addr: &TransportAddr) -> bool {
        self.pool.lock().await.contains(addr)
    }

    /// Get the I/O implementation (for test injection).
    pub fn io(&self) -> &Arc<I> {
        &self.io
    }

    /// The handle every channel-building path uses.
    fn channels(&self) -> Channels<I::Stream> {
        Channels {
            pool: Arc::clone(&self.pool),
            packet_tx: self.packet_tx.clone(),
            transport_id: self.transport_id,
            stats: Arc::clone(&self.stats),
            next_id: Arc::clone(&self.next_id),
            linger: std::time::Duration::from_millis(self.config.connect_timeout_ms()),
        }
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
                    self.accept_task = Some(tokio::spawn(accept_loop(
                        acceptor,
                        self.channels(),
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
                        self.channels(),
                        Arc::clone(&self.neighbor_buffer),
                        Arc::clone(&self.learned_psm),
                        self.config.psm(),
                        self.config.connect_timeout_ms(),
                        self.config.probe_cooldown_secs(),
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

        // Drain established connections (recv and writer tasks aborted via Drop)
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
        // the writer task, and so is a write error, which also removes the
        // connection from the pool rather than returning here.
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

        let psm = psm_for(&self.learned_psm, &ble_addr, self.config.psm());
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
                forget_psm(&self.learned_psm, &ble_addr, psm);
                debug!(
                    addr = %addr, role = "central", outcome = "connect-error", psm,
                    error = %e, "BLE connect-on-send failed"
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

        let admitted = self
            .channels()
            .admit(stream, ble_addr.clone(), true)
            .await
            .map_err(|_| TransportError::SendFailed("pool full".into()))?;
        if admitted.admission == Admission::Admit {
            self.neighbor_buffer.add_peer(&ble_addr);
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
        let channels = self.channels();
        let connecting = Arc::clone(&self.connecting);
        let stats = Arc::clone(&self.stats);
        let learned_psm = Arc::clone(&self.learned_psm);
        let psm = psm_for(&learned_psm, &ble_addr, self.config.psm());
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
                    // Reported only as a newly linked address: one held
                    // beside another, or retired, is already known.
                    if let Ok(admitted) = channels.admit(stream, ble_addr.clone(), true).await
                        && admitted.admission == Admission::Admit
                    {
                        neighbor_buffer.add_peer(&ble_addr);
                    }
                }
                Ok(Err(e)) => {
                    stats.record_connect_error();
                    forget_psm(&learned_psm, &ble_addr, psm);
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

    /// Settle the channels at `addr` once the handshake has named the peer:
    /// keep the one this side dialled if `keep_outbound`, else the one the
    /// peer dialled, and retire the rest.
    ///
    /// Both ends compute `keep_outbound` from node order, so both keep the
    /// same channel. Before the handshake there is nothing the two ends
    /// share to choose by, which is why a second channel is held until
    /// then. A verdict for a direction not yet held waits for that channel,
    /// so this never retires the only channel at an address.
    pub async fn settle_link(&self, addr: &TransportAddr, keep_outbound: bool) {
        self.channels().settle(addr, keep_outbound).await;
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
        // Every channel at the address goes; recv and writer tasks are
        // aborted via Drop.
        let closed = pool.remove(addr);
        if closed > 0 {
            debug!(addr = %addr, channels = closed, "BLE connection closed");
        }
    }

    /// Records that the node's active peer `node` now uses the address
    /// `addr`.
    ///
    /// The node calls this on every authenticated frame that arrives over
    /// BLE, so the common case (the address is already verified for `node`)
    /// must stay cheap and quiet.
    pub async fn mark_verified(&self, addr: &TransportAddr, node: &NodeAddr) {
        let outcome = self.pool.lock().await.mark_verified(addr, node);
        match outcome {
            // A remote holding two addresses can alternate its frames
            // between them, demoting one per frame: never louder than trace.
            Verify::Marked { demoted } => {
                for other in demoted {
                    trace!(
                        addr = %other, node = %node, kept = %addr, outcome = "superseded",
                        "BLE link no longer carries its node's session"
                    );
                }
            }
            Verify::Absent => {
                trace!(addr = %addr, outcome = "absent", "BLE link to verify is not pooled");
            }
        }
    }

    /// Records that the node's active peer `node` no longer uses the address
    /// `addr`. The address stays pooled. When `removed`, the peer itself is
    /// gone and the address gets its grace again; otherwise the peer moved
    /// to another address and this one keeps the grace it had.
    pub async fn clear_verified(&self, addr: &TransportAddr, node: &NodeAddr, removed: bool) {
        let regrace = removed.then(tokio::time::Instant::now);
        let cleared = self.pool.lock().await.clear_verified(addr, node, regrace);
        if cleared {
            trace!(addr = %addr, node = %node, "BLE link no longer verified");
        }
    }

    /// Whether the address `addr` is verified; `None` when nothing is pooled
    /// there.
    #[cfg(test)]
    pub(crate) async fn is_verified(&self, addr: &TransportAddr) -> Option<bool> {
        self.pool.lock().await.is_verified(addr)
    }

    /// `(id, outbound)` of each channel held at `addr`, oldest first, and
    /// the ids of the channels retiring there.
    #[cfg(test)]
    pub(crate) async fn channels_at(&self, addr: &TransportAddr) -> (Vec<(u64, bool)>, Vec<u64>) {
        let pool = self.pool.lock().await;
        (pool.held(addr), pool.retiring(addr))
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

/// Accept loop: accepts inbound L2CAP connections and offers them to the
/// pool.
///
/// An inbound at an address that already has a channel is not dropped: the
/// pool decides, and holds it if the peer dialled while we did (see
/// [`pool::admit`]). Only a newly linked address is reported to the node.
async fn accept_loop<A>(
    mut acceptor: A,
    channels: Channels<A::Stream>,
    neighbor_buffer: Arc<NeighborBuffer>,
) where
    A: io::BleAcceptor,
    A::Stream: 'static,
{
    loop {
        match acceptor.accept().await {
            Ok(stream) => {
                let addr = stream.remote_addr().clone();
                match channels.admit(stream, addr.clone(), false).await {
                    Ok(admitted) if admitted.admission == Admission::Admit => {
                        info!(addr = %addr.to_transport_addr(), "BLE inbound connection accepted");
                        neighbor_buffer.add_peer(&addr);
                    }
                    Ok(_) | Err(_) => {}
                }
            }
            Err(e) => {
                warn!(error = %e, "BLE accept error");
                break;
            }
        }
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
/// On a write error the channel is removed from the pool, which is where
/// the old inline path put it too. Dropping the pool entry aborts this task
/// and the receive task through `BleConnection`'s `Drop`; the abort does not
/// block and nothing is awaited after the `return`, so aborting ourselves here
/// is benign. Only this channel is removed, by its id, never another channel
/// at the same address.
///
/// When the channel is retired its queue's sender is dropped, so this loop
/// writes what is already queued and then ends on its own.
async fn send_loop<S: BleStream + 'static>(
    stream: Arc<S>,
    mut frames: tokio::sync::mpsc::Receiver<Vec<u8>>,
    addr: TransportAddr,
    id: u64,
    pool: Arc<Mutex<ConnectionPool<Arc<S>>>>,
    stats: Arc<BleStats>,
) {
    while let Some(frame) = frames.recv().await {
        match stream.send(&frame).await {
            Ok(()) => stats.record_send(frame.len()),
            Err(e) => {
                stats.record_send_error();
                warn!(addr = %addr, error = %e, "BLE send failed, connection removed");
                pool.lock().await.remove_channel(&addr, id);
                return;
            }
        }
    }
}

/// Receive loop: reads packets from a BLE stream and delivers to node.
///
/// Takes the connection's `BleStreamRead` and pulls whole FIPS packets out
/// of it using the FMP length prefix. Boundaries come from the bytes, not
/// from the backend's socket type, so a fragment is reassembled and a
/// coalesced tail is not lost.
///
/// When the channel ends, only this channel is removed from the pool, by its
/// id. A retired channel's reader keeps running until then, so frames the
/// peer sent on it before it settled are still delivered.
#[allow(clippy::too_many_arguments)]
async fn receive_loop<S: BleStream + 'static>(
    mut reader: BleStreamRead<S>,
    addr: TransportAddr,
    id: u64,
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

    // Remove this channel, and only this one, from the pool
    let mut pool = pool.lock().await;
    pool.remove_channel(&addr, id);
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
    channels: Channels<I::Stream>,
    buffer: Arc<NeighborBuffer>,
    learned_psm: LearnedPsm,
    configured_psm: u16,
    connect_timeout_ms: u64,
    cooldown_secs: u64,
) {
    let pool = Arc::clone(&channels.pool);
    let stats = Arc::clone(&channels.stats);
    // Addresses discovered but not yet connected — retried after cooldown even
    // if the scanner doesn't fire again (BlueZ deduplicates), on a per-address
    // backoff that widens with consecutive failures. Also the cooldown record:
    // an address leaves the book the moment it reaches a conclusive outcome,
    // after which the pool guard below covers it.
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
                recall(&learned_psm).prune(tokio::time::Instant::now(), |a| {
                    is_live(&pool_guard, &pending, a)
                });
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
        let dial_psm = psm_for(&learned_psm, &addr, configured_psm);
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

        // Offer the channel to the pool. Any channel the pool keeps or
        // retires is conclusive for the probe; only a full pool leaves the
        // address in the retry book, since a slot may free before the peer
        // is advertised again.
        match channels.admit(stream, addr.clone(), true).await {
            Ok(admitted) => {
                pending.resolve(&addr);
                debug!(
                    addr = %addr.to_transport_addr(), role = "central", outcome = "connected",
                    discovery_ms = probe_started.elapsed().as_millis() as u64,
                    admission = ?admitted.admission, "BLE probe connected"
                );
                // Report to node layer for auto-connect / handshake
                if admitted.admission == Admission::Admit {
                    buffer.add_peer(&addr);
                }
            }
            Err(_) => continue,
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
            0,
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

        // Put a pool entry in place so its removal is observable. It carries
        // the loop's channel id, because a loop removes only its own channel.
        let (parked, _other) = MockBleStream::pair(test_addr(1), test_addr(2), 2048);
        pool.lock()
            .await
            .insert(
                ta.clone(),
                BleConnection {
                    stream: Arc::new(parked),
                    // Nothing is sent to this connection: it exists so that its
                    // removal is observable, so a dropped receiver is correct.
                    send_tx: tokio::sync::mpsc::channel(1).0,
                    send_task: None,
                    recv_task: None,
                    send_mtu: 2048,
                    recv_mtu: 2048,
                    established_at: tokio::time::Instant::now(),
                    addr: test_addr(2),
                    outbound: false,
                    id: 0,
                },
                tokio::time::Instant::now(),
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

    /// Wait until `cond` holds, or fail the test.
    ///
    /// A fixed number of `yield_now()` calls is not a wait, it is a race
    /// against the clock, and it loses whenever a loop under test is parked
    /// on a timer rather than on a channel. `scan_probe_loop` is: before it
    /// reaches its `select!` it consumes the retry interval's first tick,
    /// and tokio rounds a timer deadline up to the next whole millisecond of
    /// its wheel. Polling the condition with a short sleep between attempts
    /// lets that timer fire, and the condition is what ends the wait.
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

    /// A probe the pool refuses is not a connection, and must not be recorded
    /// as one. The inbound path already continues on rejection; this pins the
    /// outbound probe path to the same shape.
    ///
    /// The pool refuses a link whenever every slot holds a verified address
    /// or one still inside its grace; `max_connections: 0` reaches the
    /// refusal without building either.
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

    /// The node's own dial goes to the PSM the scan loop learned. Before,
    /// only the probe read the learned value; `connect_async` dialled the
    /// configured PSM, which a platform that assigns listener PSMs never
    /// listens on, so a configured peer or a redial after a link loss failed
    /// every time against such a peer.
    #[tokio::test(start_paused = true)]
    async fn a_node_dial_goes_to_the_psm_the_scan_loop_learned() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        transport.start_async().await.unwrap();

        // A first sighting with no PSM: the probe dials the configured PSM,
        // is refused, and backs the address off for one cooldown.
        transport.io.inject_scan_result(test_addr(2)).await;
        wait_for("the first probe", || dials.lock().unwrap().len() == 1).await;
        assert_eq!(dials.lock().unwrap()[0], (test_addr(2), DEFAULT_PSM));

        // The peer's advert is learned, and the probe skips it as not due.
        transport
            .io
            .inject_scan_advert(io::ScanAdvert::with_psm(test_addr(2), 0x00C1))
            .await;
        {
            let stats = Arc::clone(&transport.stats);
            wait_for("the advert to be read", || {
                stats.snapshot().scan_results == 2
            })
            .await;
        }
        let before = dials.lock().unwrap().len();

        transport
            .connect_async(&test_addr(2).to_transport_addr())
            .await
            .unwrap();
        wait_for("the node's dial", || dials.lock().unwrap().len() > before).await;

        // Assert on the node's dial itself, not on the last dial: a probe
        // retry would dial the learned PSM too.
        let log = dials.lock().unwrap().clone();
        assert_eq!(
            log[before],
            (test_addr(2), 0x00C1),
            "the node's dial must go to the advertised PSM: {log:?}"
        );
        assert!(
            log[1..=before]
                .iter()
                .all(|entry| *entry != (test_addr(2), DEFAULT_PSM)),
            "nothing dialled the configured PSM after the advert: {log:?}"
        );
        transport.stop_async().await.unwrap();
    }

    /// A probe that times out keeps the learned PSM, so the retry goes to
    /// where the peer listens. A timeout says the peer was out of reach, not
    /// that it listens elsewhere, and on BlueZ nothing re-learns a forgotten
    /// entry: `DeviceAdded` fires once per address per discovery session.
    #[tokio::test(start_paused = true)]
    async fn a_timed_out_probe_redials_the_learned_psm() {
        let dials: DialLog = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (mut transport, _rx) = psm_probe_transport(Arc::clone(&dials));
        let (gate, gate_rx) = tokio::sync::watch::channel(false);
        transport.io.set_connect_gate(gate_rx);
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
        assert!(
            dials.lock().unwrap().is_empty(),
            "the gated dial never reached the handler"
        );

        // Let the retry through: the next tick re-probes after one cooldown.
        gate.send(true).unwrap();
        wait_for("the retry", || !dials.lock().unwrap().is_empty()).await;

        let log = dials.lock().unwrap().clone();
        assert_eq!(
            log[0],
            (test_addr(2), 0x00C1),
            "the retry after a timeout must go to the advertised PSM: {log:?}"
        );
        transport.stop_async().await.unwrap();
    }

    /// A refusal forgets only the PSM that was dialled. Here the scan loop
    /// learns a new value while the dial is in flight; the refusal of the old
    /// one must not take the new one with it.
    #[tokio::test]
    async fn a_refusal_forgets_only_the_psm_it_dialled() {
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
    ///
    /// It builds its connection by hand, so it does not exercise any of the
    /// four production construction sites; a site that stored a queue nobody
    /// writes would still pass this.
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
            0,
            Arc::clone(&transport.pool),
            Arc::clone(&transport.stats),
        ));

        transport
            .pool
            .lock()
            .await
            .insert(
                ta.clone(),
                BleConnection {
                    stream,
                    send_tx,
                    send_task: Some(send_task),
                    recv_task: None,
                    send_mtu: 2048,
                    recv_mtu: 2048,
                    established_at: tokio::time::Instant::now(),
                    addr: test_addr(2),
                    outbound: false,
                    id: 0,
                },
                tokio::time::Instant::now(),
            )
            .unwrap();

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

    // ------------------------------------------------------------------
    // Two channels to one address
    // ------------------------------------------------------------------

    /// One end of a two-sided test: a transport whose dials are served from
    /// a queue of pre-built channel ends and held at a connect gate, and
    /// whose inbound channels the test injects when it chooses.
    struct Side {
        transport: BleTransport<MockBleIo>,
        rx: tokio::sync::mpsc::Receiver<ReceivedPacket>,
        gate: tokio::sync::watch::Sender<bool>,
    }

    impl Side {
        /// Build and start a side at `local` whose dials are served, in
        /// order, from `dials`; a dial beyond those is refused, so a redial
        /// cannot rescue a lost link.
        async fn start(local: BleAddr, dials: Vec<MockBleStream>, config: BleConfig) -> Self {
            let io = MockBleIo::new("hci0", local);
            let queue = std::sync::Mutex::new(std::collections::VecDeque::from(dials));
            io.set_connect_handler(move |_addr, _psm| {
                queue
                    .lock()
                    .unwrap()
                    .pop_front()
                    .ok_or(TransportError::ConnectionRefused)
            });
            let (gate, gate_rx) = tokio::sync::watch::channel(false);
            io.set_connect_gate(gate_rx);
            let (tx, rx) = tokio::sync::mpsc::channel(64);
            let mut transport = BleTransport::new(TransportId::new(1), None, config, io, tx);
            transport.start_async().await.unwrap();
            Self {
                transport,
                rx,
                gate,
            }
        }

        /// Let held dials through and wait until `n` of them completed.
        async fn complete_dials(&self, n: u64) {
            self.gate.send(true).unwrap();
            let stats = Arc::clone(&self.transport.stats);
            wait_for("the dial to complete", || {
                stats.snapshot().connections_established == n
            })
            .await;
        }

        /// Hand the transport an inbound channel and let it be admitted.
        async fn accept(&self, stream: MockBleStream) {
            self.transport.io.inject_inbound(stream).await;
            settle().await;
        }

        /// Whether `frame`, sent by the peer, arrives here.
        async fn receives(&mut self, frame: &[u8]) -> bool {
            matches!(
                tokio::time::timeout(Duration::from_secs(1), self.rx.recv()).await,
                Ok(Some(packet)) if packet.data == frame
            )
        }
    }

    /// The configuration both ends of a two-sided test run with.
    fn race_config() -> BleConfig {
        BleConfig {
            adapter: Some("hci0".to_string()),
            scan: Some(false),
            advertise: Some(false),
            accept_connections: Some(true),
            ..Default::default()
        }
    }

    /// Two nodes that dial each other at once must be left with a link that
    /// carries traffic both ways. Before, each side kept the channel it had
    /// dialled: an inbound at a pooled address was dropped, and a dial
    /// completing at a pooled address overwrote whatever was there. Each
    /// side then held the channel the other had closed, and both died.
    ///
    /// L1 is the channel A dials and L2 the one B dials. Every order is
    /// driven: on each side, its own dial completes first or the peer's
    /// arrives first.
    #[tokio::test(start_paused = true)]
    async fn a_simultaneous_dial_at_one_address_leaves_a_working_link() {
        let (a, b) = (test_addr(1), test_addr(2));
        let mut failures = Vec::new();
        for (a_dial_first, b_dial_first) in
            [(true, true), (true, false), (false, true), (false, false)]
        {
            let (l1_a, l1_b) = MockBleStream::pair(a.clone(), b.clone(), 2048);
            let (l2_b, l2_a) = MockBleStream::pair(b.clone(), a.clone(), 2048);
            let mut side_a = Side::start(a.clone(), vec![l1_a], race_config()).await;
            let mut side_b = Side::start(b.clone(), vec![l2_b], race_config()).await;
            side_a
                .transport
                .connect_async(&b.to_transport_addr())
                .await
                .unwrap();
            side_b
                .transport
                .connect_async(&a.to_transport_addr())
                .await
                .unwrap();
            settle().await;

            let (mut l2_a, mut l1_b) = (Some(l2_a), Some(l1_b));
            if a_dial_first {
                side_a.complete_dials(1).await;
            } else {
                side_a.accept(l2_a.take().unwrap()).await;
            }
            if b_dial_first {
                side_b.complete_dials(1).await;
            } else {
                side_b.accept(l1_b.take().unwrap()).await;
            }
            match l2_a.take() {
                Some(inbound) => side_a.accept(inbound).await,
                None => side_a.complete_dials(1).await,
            }
            match l1_b.take() {
                Some(inbound) => side_b.accept(inbound).await,
                None => side_b.complete_dials(1).await,
            }
            settle().await;

            let order = format!("A dial first: {a_dial_first}, B dial first: {b_dial_first}");
            let to_b = build_established_frame(16);
            let to_a = build_established_frame(24);
            let sent_a = side_a
                .transport
                .send_async(&b.to_transport_addr(), &to_b)
                .await;
            let sent_b = side_b
                .transport
                .send_async(&a.to_transport_addr(), &to_a)
                .await;
            let b_got = side_b.receives(&to_b).await;
            let a_got = side_a.receives(&to_a).await;
            if sent_a.is_err() || sent_b.is_err() || !a_got || !b_got {
                failures.push(format!(
                    "{order}: A sent {sent_a:?}, B sent {sent_b:?}, \
                     B received A's frame: {b_got}, A received B's frame: {a_got}"
                ));
            }

            side_a.transport.stop_async().await.unwrap();
            side_b.transport.stop_async().await.unwrap();
        }
        assert!(
            failures.is_empty(),
            "orders left without a working link:\n{}",
            failures.join("\n")
        );
    }

    /// `(held, retiring)` channel counts at `addr` on this side.
    async fn channel_counts(side: &Side, addr: &BleAddr) -> (usize, usize) {
        let pool = side.transport.pool.lock().await;
        let ta = addr.to_transport_addr();
        (pool.held(&ta).len(), pool.retiring(&ta).len())
    }

    /// The MTU of the channel sends to `addr` use. The tests below build
    /// each channel with its own MTU, so this names the channel.
    async fn sending_mtu(side: &Side, addr: &BleAddr) -> Option<u16> {
        let pool = side.transport.pool.lock().await;
        pool.get(&addr.to_transport_addr()).map(|c| c.send_mtu)
    }

    /// A node that dials one address twice (the scan loop's probe and its
    /// own dial, both in flight) keeps one channel, and so does the peer
    /// that accepted both. Only the dialler decides: it retires its second
    /// dial, and the acceptor holds both until it reads end-of-stream on
    /// the retired one. Both accept orders are driven, the one matching the
    /// dialler's completion order and the inverse; if the acceptor also
    /// decided, the inverse would leave each end holding a channel the
    /// other closed.
    #[tokio::test(start_paused = true)]
    async fn a_double_dial_to_one_address_leaves_one_channel_on_both_ends() {
        let (a, b) = (test_addr(1), test_addr(2));
        for inverted in [false, true] {
            let (p1_a, p1_b) = MockBleStream::pair(a.clone(), b.clone(), 2048);
            let (p2_a, p2_b) = MockBleStream::pair(a.clone(), b.clone(), 1024);
            let mut far_ends = HashMap::from([(2048u16, p1_b), (1024u16, p2_b)]);
            let scanning = BleConfig {
                scan: Some(true),
                probe_cooldown_secs: Some(1),
                ..race_config()
            };
            let mut side_a = Side::start(a.clone(), vec![p1_a, p2_a], scanning).await;
            let mut side_b = Side::start(b.clone(), Vec::new(), race_config()).await;

            // Both of A's dials are in flight at once, held at its gate.
            side_a.transport.io.inject_scan_result(b.clone()).await;
            {
                let stats = Arc::clone(&side_a.transport.stats);
                wait_for("the probe", || stats.snapshot().scan_results == 1).await;
            }
            side_a
                .transport
                .connect_async(&b.to_transport_addr())
                .await
                .unwrap();
            settle().await;
            side_a.gate.send(true).unwrap();
            {
                let stats = Arc::clone(&side_a.transport.stats);
                wait_for("both of A's dials", || {
                    let snap = stats.snapshot();
                    snap.connections_established + snap.duplicates_closed == 2
                })
                .await;
            }
            // A sends on the channel it keeps; the other is retiring.
            let kept = sending_mtu(&side_a, &b).await.unwrap();
            let retired = if kept == 2048 { 1024 } else { 2048 };

            let order = if inverted {
                [retired, kept]
            } else {
                [kept, retired]
            };
            for mtu in order {
                side_b.accept(far_ends.remove(&mtu).unwrap()).await;
            }

            tokio::time::advance(Duration::from_millis(
                side_a.transport.config.connect_timeout_ms() + 1,
            ))
            .await;
            settle().await;

            let case = format!("inverted accept order: {inverted}");
            assert_eq!(
                channel_counts(&side_a, &b).await,
                (1, 0),
                "A keeps one channel ({case})"
            );
            assert_eq!(
                channel_counts(&side_b, &a).await,
                (1, 0),
                "B keeps one channel ({case})"
            );
            assert_eq!(sending_mtu(&side_a, &b).await, Some(kept), "{case}");
            assert_eq!(
                sending_mtu(&side_b, &a).await,
                Some(kept),
                "both ends keep the same channel ({case})"
            );

            let to_b = build_established_frame(16);
            let to_a = build_established_frame(24);
            side_a
                .transport
                .send_async(&b.to_transport_addr(), &to_b)
                .await
                .unwrap();
            side_b
                .transport
                .send_async(&a.to_transport_addr(), &to_a)
                .await
                .unwrap();
            assert!(side_b.receives(&to_b).await, "A's frame reaches B ({case})");
            assert!(side_a.receives(&to_a).await, "B's frame reaches A ({case})");

            side_a.transport.stop_async().await.unwrap();
            side_b.transport.stop_async().await.unwrap();
        }
    }

    /// A lone link is admitted and reported whichever side dialled it. On
    /// an earlier design a tie-breaker stood a lone inbound down so that its
    /// own outbound would win, which dropped a working link in favour of
    /// one that might never be built.
    #[tokio::test(start_paused = true)]
    async fn a_lone_inbound_link_is_admitted_whichever_side_dialled() {
        let (a, b) = (test_addr(1), test_addr(2));

        // The peer dialled: one inbound, nothing else.
        let (theirs, ours) = MockBleStream::pair(b.clone(), a.clone(), 2048);
        let mut side = Side::start(a.clone(), Vec::new(), race_config()).await;
        side.accept(ours).await;
        assert_eq!(
            channel_counts(&side, &b).await,
            (1, 0),
            "the inbound is kept"
        );
        assert_eq!(
            side.transport.neighbor_buffer.take().len(),
            1,
            "and reported"
        );
        drop(theirs);
        side.transport.stop_async().await.unwrap();

        // This side's probe dialled: one outbound, nothing else.
        let (ours, _theirs) = MockBleStream::pair(a.clone(), b.clone(), 2048);
        let scanning = BleConfig {
            scan: Some(true),
            ..race_config()
        };
        let mut side = Side::start(a.clone(), vec![ours], scanning).await;
        side.transport.io.inject_scan_result(b.clone()).await;
        side.complete_dials(1).await;
        assert_eq!(channel_counts(&side, &b).await, (1, 0), "the probe is kept");
        assert_eq!(
            side.transport.neighbor_buffer.take().len(),
            1,
            "and reported"
        );
        side.transport.stop_async().await.unwrap();
    }

    // ------------------------------------------------------------------
    // Settling two channels once the handshake names the peer
    // ------------------------------------------------------------------

    /// The MTU L1, the channel A dials, is built with. Each channel gets its
    /// own MTU, so a test can tell which one an end holds.
    const L1_MTU: u16 = 2048;
    /// The MTU L2, the channel B dials, is built with.
    const L2_MTU: u16 = 1024;

    /// One step of a race between A and B.
    #[derive(Clone, Copy, Debug)]
    enum Step {
        /// A's own dial (L1) completes.
        ADial,
        /// B's dial (L2) arrives at A.
        AAccept,
        /// B's own dial (L2) completes.
        BDial,
        /// L1 arrives at B.
        BAccept,
        /// A settles, keeping its outbound channel if `true`.
        ASettle(bool),
        /// B settles, keeping its outbound channel if `true`.
        BSettle(bool),
    }

    /// How many channels `side` has at `addr`, held and retiring together.
    fn channels_seen(side: &Side, addr: &BleAddr) -> usize {
        side.transport
            .pool
            .try_lock()
            .map(|pool| {
                let ta = addr.to_transport_addr();
                pool.held(&ta).len() + pool.retiring(&ta).len()
            })
            .unwrap_or(0)
    }

    impl Side {
        /// Let this side's one held dial through and wait until the pool
        /// has taken it, held or retired.
        async fn dial_through(&self, peer: &BleAddr) {
            let before = channels_seen(self, peer);
            self.gate.send(true).unwrap();
            wait_for("the dial to land in the pool", || {
                channels_seen(self, peer) == before + 1
            })
            .await;
        }
    }

    /// Run a race between A (`test_addr(1)`) and B (`test_addr(2)`): each
    /// starts one dial to the other, held at its gate, and `steps` then
    /// decides the order in which each end sees its own dial complete, the
    /// peer's dial arrive, and its settlement.
    async fn race(steps: &[Step]) -> (Side, Side) {
        let (a, b) = (test_addr(1), test_addr(2));
        let (l1_a, l1_b) = MockBleStream::pair(a.clone(), b.clone(), L1_MTU);
        let (l2_b, l2_a) = MockBleStream::pair(b.clone(), a.clone(), L2_MTU);
        let side_a = Side::start(a.clone(), vec![l1_a], race_config()).await;
        let side_b = Side::start(b.clone(), vec![l2_b], race_config()).await;
        side_a
            .transport
            .connect_async(&b.to_transport_addr())
            .await
            .unwrap();
        side_b
            .transport
            .connect_async(&a.to_transport_addr())
            .await
            .unwrap();
        settle().await;
        let (mut l2_a, mut l1_b) = (Some(l2_a), Some(l1_b));
        for step in steps {
            match *step {
                Step::ADial => side_a.dial_through(&b).await,
                Step::AAccept => side_a.accept(l2_a.take().unwrap()).await,
                Step::BDial => side_b.dial_through(&a).await,
                Step::BAccept => side_b.accept(l1_b.take().unwrap()).await,
                Step::ASettle(keep) => {
                    side_a
                        .transport
                        .settle_link(&b.to_transport_addr(), keep)
                        .await
                }
                Step::BSettle(keep) => {
                    side_b
                        .transport
                        .settle_link(&a.to_transport_addr(), keep)
                        .await
                }
            }
        }
        (side_a, side_b)
    }

    /// Advance past the linger, then report `(held, retiring)` on each end
    /// and the MTU each end sends on.
    async fn after_linger(side_a: &Side, side_b: &Side) -> [((usize, usize), Option<u16>); 2] {
        // Let each linger timer start its sleep before the clock moves.
        settle().await;
        tokio::time::advance(Duration::from_millis(
            side_a.transport.config.connect_timeout_ms() + 1,
        ))
        .await;
        settle().await;
        let (a, b) = (test_addr(1), test_addr(2));
        [
            (
                channel_counts(side_a, &b).await,
                sending_mtu(side_a, &b).await,
            ),
            (
                channel_counts(side_b, &a).await,
                sending_mtu(side_b, &a).await,
            ),
        ]
    }

    /// Whether a frame crosses each way between A and B.
    async fn frames_cross(side_a: &mut Side, side_b: &mut Side) -> bool {
        let (a, b) = (test_addr(1), test_addr(2));
        let to_b = build_established_frame(16);
        let to_a = build_established_frame(24);
        let sent = side_a
            .transport
            .send_async(&b.to_transport_addr(), &to_b)
            .await
            .is_ok()
            && side_b
                .transport
                .send_async(&a.to_transport_addr(), &to_a)
                .await
                .is_ok();
        sent && side_b.receives(&to_b).await && side_a.receives(&to_a).await
    }

    /// Both ends keep the channel the smaller node dialled, whichever order
    /// the channels arrived in and whenever each end settles: after both
    /// channels are in, between its two channels, or before the peer has
    /// settled at all. Either node may be the smaller.
    #[tokio::test(start_paused = true)]
    async fn both_ends_settle_on_the_link_the_smaller_node_dialled() {
        use Step::*;
        let orders = [
            [ADial, BDial, AAccept, BAccept],
            [ADial, BAccept, AAccept, BDial],
            [AAccept, BDial, ADial, BAccept],
            [AAccept, BAccept, ADial, BDial],
        ];
        let mut failures = Vec::new();
        for a_smaller in [true, false] {
            let (keep_a, keep_b) = (a_smaller, !a_smaller);
            let kept = if a_smaller { L1_MTU } else { L2_MTU };
            for order in orders {
                // Settle after both channels, A between its two, or both
                // between their two.
                let timings: [Vec<Step>; 3] = [
                    vec![
                        order[0],
                        order[1],
                        order[2],
                        order[3],
                        ASettle(keep_a),
                        BSettle(keep_b),
                    ],
                    vec![
                        order[0],
                        order[1],
                        ASettle(keep_a),
                        order[2],
                        order[3],
                        BSettle(keep_b),
                    ],
                    vec![
                        order[0],
                        order[1],
                        ASettle(keep_a),
                        BSettle(keep_b),
                        order[2],
                        order[3],
                    ],
                ];
                for steps in timings {
                    let (mut side_a, mut side_b) = race(&steps).await;
                    let ends = after_linger(&side_a, &side_b).await;
                    let crossed = frames_cross(&mut side_a, &mut side_b).await;
                    let want = ((1, 0), Some(kept));
                    if ends != [want, want] || !crossed {
                        failures.push(format!(
                            "{steps:?}: A {:?}, B {:?}, frames crossed: {crossed}",
                            ends[0], ends[1]
                        ));
                    }
                    side_a.transport.stop_async().await.unwrap();
                    side_b.transport.stop_async().await.unwrap();
                }
            }
        }
        assert!(
            failures.is_empty(),
            "ends that did not keep the smaller node's channel:\n{}",
            failures.join("\n")
        );
    }

    /// A frame queued on a channel that settlement then retires is still
    /// written. Dropping the channel at settlement would abort its writer
    /// with the frame still queued; on the node that is the handshake's
    /// msg3, queued on the oldest channel just before the promotion that
    /// settles the link.
    #[tokio::test(start_paused = true)]
    async fn a_frame_queued_on_a_losing_channel_still_arrives() {
        use Step::*;
        let (a, b) = (test_addr(1), test_addr(2));
        let (side_a, mut side_b) = race(&[ADial, BDial, AAccept, BAccept]).await;
        // A sends on its oldest channel, L1 (outbound); settle against it in
        // the same task, with nothing in between that yields.
        let frame = build_established_frame(16);
        side_a
            .transport
            .send_async(&b.to_transport_addr(), &frame)
            .await
            .unwrap();
        side_a
            .transport
            .settle_link(&b.to_transport_addr(), false)
            .await;
        assert_eq!(sending_mtu(&side_a, &b).await, Some(L2_MTU), "L1 retired");
        assert!(side_b.receives(&frame).await, "the queued frame arrives");
        let _ = a;
    }

    /// A frame the peer sends on a channel this end has already retired is
    /// still delivered: the peer may not have settled yet, and its sends go
    /// on its oldest channel until it does.
    #[tokio::test(start_paused = true)]
    async fn a_frame_the_peer_sends_on_a_losing_channel_still_arrives() {
        use Step::*;
        let a = test_addr(1);
        // B's oldest channel is L2, which B dialled; A retires it by keeping
        // its own outbound, L1, before B settles.
        let (mut side_a, side_b) = race(&[BDial, ADial, AAccept, BAccept, ASettle(true)]).await;
        assert_eq!(sending_mtu(&side_b, &a).await, Some(L2_MTU));
        let frame = build_established_frame(16);
        side_b
            .transport
            .send_async(&a.to_transport_addr(), &frame)
            .await
            .unwrap();
        assert!(side_a.receives(&frame).await, "the peer's frame arrives");
    }

    /// A retired channel closes once the linger passes, on both ends, and
    /// the survivor still carries traffic.
    #[tokio::test(start_paused = true)]
    async fn a_retired_channel_closes_after_the_linger() {
        use Step::*;
        let (mut side_a, mut side_b) = race(&[
            ADial,
            BDial,
            AAccept,
            BAccept,
            ASettle(true),
            BSettle(false),
        ])
        .await;
        let (a, b) = (test_addr(1), test_addr(2));
        assert_eq!(channel_counts(&side_a, &b).await, (1, 1));
        assert_eq!(channel_counts(&side_b, &a).await, (1, 1));

        let ends = after_linger(&side_a, &side_b).await;
        assert_eq!(ends, [((1, 0), Some(L1_MTU)), ((1, 0), Some(L1_MTU))]);
        assert!(frames_cross(&mut side_a, &mut side_b).await);
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
        // The receiver is held for the length of the test so that the queue is
        // open and the MTU check is what refuses the send. Dropping it would
        // still fail this test if the check moved below the enqueue, because a
        // closed queue returns `SendFailed` rather than `MtuExceeded` and
        // records a send error — so this is fidelity rather than added
        // coverage.
        let (send_tx, _send_rx) = tokio::sync::mpsc::channel(pool::SEND_QUEUE_DEPTH);
        transport
            .pool
            .lock()
            .await
            .insert(
                ta.clone(),
                BleConnection {
                    stream: Arc::new(parked),
                    send_tx,
                    send_task: None,
                    recv_task: None,
                    send_mtu: 64,
                    recv_mtu: 64,
                    established_at: tokio::time::Instant::now(),
                    addr: test_addr(2),
                    outbound: false,
                    id: 0,
                },
                tokio::time::Instant::now(),
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
            "duplicates_held",
            "duplicates_closed",
        ];
        for key in expected {
            assert!(object.contains_key(key), "snapshot lost `{key}`");
        }
        assert_eq!(object.len(), expected.len(), "snapshot gained a key");
    }

    // ------------------------------------------------------------------
    // Links carrying a session versus unverified links
    // ------------------------------------------------------------------

    /// A distinct node identity per `n`.
    fn node(n: u8) -> NodeAddr {
        let mut bytes = [0u8; 16];
        bytes[0] = n;
        NodeAddr::from_bytes(bytes)
    }

    /// A transport under `config` whose every dial is answered, keeping the
    /// remote ends alive.
    fn dialable_transport(config: BleConfig) -> BleTransport<MockBleIo> {
        let io = MockBleIo::new("hci0", test_addr(1));
        let alive: Arc<std::sync::Mutex<Vec<MockBleStream>>> = Arc::default();
        io.set_connect_handler(move |addr, _psm| {
            let (mine, theirs) = MockBleStream::pair(test_addr(1), addr.clone(), 2048);
            alive.lock().unwrap().push(theirs);
            Ok(mine)
        });
        let (tx, _rx) = tokio::sync::mpsc::channel(64);
        BleTransport::new(TransportId::new(1), None, config, io, tx)
    }

    /// Dial in from `from`. The remote end is returned and must be kept
    /// alive, or the link closes.
    async fn dial_in(transport: &BleTransport<MockBleIo>, from: &BleAddr) -> MockBleStream {
        let (ours, theirs) = MockBleStream::pair(test_addr(1), from.clone(), 2048);
        transport.io.inject_inbound(ours).await;
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

    /// Whether a link is pooled at `addr`, waiting on the lock.
    async fn holds(transport: &BleTransport<MockBleIo>, addr: &BleAddr) -> bool {
        transport
            .pool
            .lock()
            .await
            .contains(&addr.to_transport_addr())
    }

    /// A link that never completes a handshake is not closed by any timer:
    /// it leaves only by eviction or link loss.
    #[tokio::test(start_paused = true)]
    async fn an_unverified_link_that_never_handshakes_stays_open() {
        let mut transport = dialable_transport(identity_test_config());
        transport.start_async().await.unwrap();
        let _link = dial_in(&transport, &test_addr(2)).await;
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

    /// The whole chain once the node drops its peer: the withdrawn link gets
    /// the grace again, then a newcomer takes its slot.
    #[tokio::test(start_paused = true)]
    async fn a_withdrawn_link_is_evicted_by_a_newcomer_once_past_its_grace() {
        let config = BleConfig {
            max_connections: Some(1),
            ..identity_test_config()
        };
        let mut transport = dialable_transport(config);
        transport.start_async().await.unwrap();
        let rejected = |t: &BleTransport<MockBleIo>| t.stats.snapshot().connections_rejected;
        let secs = std::time::Duration::from_secs;

        let _p_link = dial_in(&transport, &test_addr(2)).await;
        wait_for("P's link", || pooled(&transport, &test_addr(2))).await;
        let ta2 = test_addr(2).to_transport_addr();
        transport.mark_verified(&ta2, &node(2)).await;

        tokio::time::advance(secs(20)).await;
        let _q_link = dial_in(&transport, &test_addr(3)).await;
        wait_for("Q's refusal", || rejected(&transport) == 1).await;
        assert!(
            !holds(&transport, &test_addr(3)).await,
            "a verified link is kept"
        );

        tokio::time::advance(secs(1)).await;
        transport.clear_verified(&ta2, &node(2), true).await;
        tokio::time::advance(secs(5)).await;
        let _r_link = dial_in(&transport, &test_addr(4)).await;
        wait_for("R's refusal", || rejected(&transport) == 2).await;
        assert!(
            pooled(&transport, &test_addr(2)),
            "the withdrawn link is inside its new grace"
        );

        tokio::time::advance(secs(6)).await;
        let _r_again = dial_in(&transport, &test_addr(5)).await;
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
        for max in [0, 2] {
            let config = BleConfig {
                max_connections: Some(max),
                ..identity_test_config()
            };
            let mut transport = dialable_transport(config);
            transport.start_async().await.unwrap();
            let snapshot = Arc::clone(&transport.stats);
            let settled = |n: u64| {
                let stats = Arc::clone(&snapshot);
                move || {
                    let s = stats.snapshot();
                    s.connections_rejected + s.connections_accepted + s.connections_established == n
                }
            };

            let _inbound = dial_in(&transport, &test_addr(2)).await;
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

    /// A probing transport whose dials are logged, whose dials to `peer_at`
    /// hand the remote end to the returned receiver, and whose every other
    /// dial is hung up at once, so its link leaves the pool as it arrives.
    fn psm_flood_transport(
        peer_at: &BleAddr,
        dials: DialLog,
    ) -> (
        BleTransport<MockBleIo>,
        tokio::sync::mpsc::UnboundedReceiver<MockBleStream>,
    ) {
        let io = MockBleIo::new("hci0", test_addr(1));
        let (peer_tx, peer_rx) = tokio::sync::mpsc::unbounded_channel();
        let peer_at = peer_at.clone();
        io.set_connect_handler(move |addr, psm| {
            dials.lock().unwrap().push((addr.clone(), psm));
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
        (
            BleTransport::new(TransportId::new(1), None, config, io, tx),
            peer_rx,
        )
    }

    /// Advertise each of `FLOOD` new addresses with a PSM and wait until the
    /// probe loop has read every one.
    async fn flood_psm_adverts(transport: &BleTransport<MockBleIo>) {
        let before = transport.stats.snapshot().scan_results;
        for i in 0..FLOOD {
            transport
                .io
                .inject_scan_advert(io::ScanAdvert::with_psm(flood_addr(i), 0x00C3))
                .await;
        }
        let stats = Arc::clone(&transport.stats);
        wait_for("every flood advert to be read", || {
            stats.snapshot().scan_results >= before + u64::from(FLOOD)
        })
        .await;
    }

    /// The dials made to `addr`, in order, with the PSM each went to.
    fn psms_dialled(dials: &DialLog, addr: &BleAddr) -> Vec<u16> {
        dials
            .lock()
            .unwrap()
            .iter()
            .filter(|(d, _)| d == addr)
            .map(|(_, psm)| *psm)
            .collect()
    }

    /// Advertisements from ever new addresses must not grow the probe memory
    /// past its bound on non-live addresses, plus the live ones: the retry
    /// book's addresses and the pool's, where each flood link sits until it
    /// closes.
    #[tokio::test]
    async fn advertisements_from_ever_new_addresses_do_not_grow_the_probe_memory_past_its_bound() {
        let dials: DialLog = Arc::default();
        let (mut transport, _peer_rx) = psm_flood_transport(&test_addr(2), dials);
        transport.start_async().await.unwrap();

        flood_psm_adverts(&transport).await;

        let remembered = recall(&transport.learned_psm).len();
        let live = MAX_PENDING_PROBES + transport.config.max_connections();
        assert!(
            remembered <= recall::MAX_RECALLED_ADDRS + live,
            "the probe memory holds {remembered} PSMs after {FLOOD} new advertising addresses"
        );
        transport.stop_async().await.unwrap();
    }

    /// A pooled peer is live, so a flood of new advertising addresses must
    /// not cost it the PSM it advertised.
    #[tokio::test]
    async fn a_pooled_peers_learned_psm_survives_an_address_flood() {
        let a = test_addr(2);
        let dials: DialLog = Arc::default();
        let (mut transport, mut peer_rx) = psm_flood_transport(&a, dials);
        transport.start_async().await.unwrap();

        transport
            .io
            .inject_scan_advert(io::ScanAdvert::with_psm(a.clone(), 0x00C1))
            .await;
        let theirs = tokio::time::timeout(std::time::Duration::from_secs(5), peer_rx.recv())
            .await
            .expect("the peer is probed")
            .unwrap();
        wait_for("the peer to be pooled", || pooled(&transport, &a)).await;
        transport
            .mark_verified(&a.to_transport_addr(), &node(2))
            .await;

        flood_psm_adverts(&transport).await;

        assert!(
            holds(&transport, &a).await,
            "the peer's link is still pooled"
        );
        assert_eq!(
            recall(&transport.learned_psm).get(&a).copied(),
            Some(0x00C1),
            "the pooled peer's learned PSM was lost to the flood"
        );
        drop(theirs);
        transport.stop_async().await.unwrap();
    }

    /// A peer that advertised its PSM once, connected and went away is not
    /// live, so a flood of new advertising addresses must not leave its PSM
    /// remembered for ever: an unbounded memory keeps every one of them.
    #[tokio::test]
    async fn a_departed_peers_learned_psm_is_not_kept_through_a_thousand_new_advertising_addresses()
    {
        let a = test_addr(2);
        let dials: DialLog = Arc::default();
        let (mut transport, mut peer_rx) = psm_flood_transport(&a, Arc::clone(&dials));
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
        wait_for("the peer to be pooled", || pooled(&transport, &a)).await;
        drop(theirs);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while holds(&transport, &a).await {
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for the peer's link to close"
            );
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }

        flood_psm_adverts(&transport).await;

        // The departed peer is seen again by a scan that carries no PSM.
        transport.io.inject_scan_result(a.clone()).await;
        wait_for("the departed peer to be probed again", || {
            psms_dialled(&dials, &a).len() >= 2
        })
        .await;
        assert_eq!(
            psms_dialled(&dials, &a),
            vec![0x00C1, DEFAULT_PSM],
            "the probe memory still held the departed peer's PSM after {FLOOD} newer \
             advertising addresses"
        );
        transport.stop_async().await.unwrap();
    }
}
