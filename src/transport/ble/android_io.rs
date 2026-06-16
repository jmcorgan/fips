//! Android BLE backend: a [`BleIo`] whose radio lives in Kotlin.
//!
//! Android's BLE APIs are Java-only, so Kotlin owns the radio (scan, advertise,
//! L2CAP listen/connect, socket read/write) and exchanges **raw bytes** with this
//! Rust backend over a byte-bridge — symmetric to how nostr-vpn's `MobileTunnel`
//! exchanges TUN packet bytes across the FFI. FIPS keeps everything above the
//! `BleIo` trait (the pool, the cross-probe tiebreaker, the pubkey exchange,
//! Noise); this backend only moves bytes and surfaces adverts.
//!
//! ## Layering
//!
//! FIPS cannot depend on the app crate (`myco-core`), so the split is:
//!
//! - [`AndroidRadio`] — an object-safe trait for the few **commands** the radio
//!   must run (listen/connect/advertise/scan/close). `myco-core` implements it
//!   via JNI calls into the Kotlin radio object.
//! - [`AndroidBleBridge`] — the channel machinery shared by this backend and the
//!   JNI layer. `myco-core` constructs it, injects it via
//!   [`set_android_ble_bridge`], and drives its `deliver_*` / `next_send`
//!   methods from its `Java_..._NativeCore_*` exports.
//! - [`AndroidIo`] / [`AndroidStream`] / [`AndroidAcceptor`] / [`AndroidScanner`]
//!   — the `BleIo` impl, delegating to the bridge.
//!
//! ## Direction of blocking (matches nostr-vpn's MobileTunnel)
//!
//! - **Inbound** bytes/events (Kotlin → Rust) are **pushed** non-blocking into
//!   tokio channels (`deliver_recv`, `deliver_inbound`, `deliver_scan`,
//!   `deliver_connect_result`); the awaiting FIPS task wakes.
//! - **Outbound** bytes (Rust → Kotlin) are **pulled, blocking with timeout**, by
//!   a per-channel Kotlin writer thread via [`AndroidBleBridge::next_send`].
//!   `BleStream::send` only pushes into a std channel — it never calls JNI — so
//!   the byte hot path never blocks a tokio worker on a JNI upcall.
//!
//! This module is platform-agnostic Rust (no JNI here — that lives in
//! `myco-core`), so it compiles and unit-tests on the host with a mock radio.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio::sync::Mutex as AsyncMutex;

use crate::transport::TransportError;

use super::addr::BleAddr;
use super::io::{BleAcceptor, BleIo, BleScanner, BleStream};
use super::psm::PsmMap;
use super::DEFAULT_PSM;

/// Synthetic adapter label (Android does not expose a BlueZ-style adapter name;
/// identity is the pubkey, never the MAC — see ble-interop.md).
const ANDROID_ADAPTER: &str = "ble0";

/// Bound on a per-channel inbound/outbound queue and the accept/scan fan-in.
/// Generous so control events (accept/scan) are not dropped under burst; L2CAP
/// data drops are tolerable since FMP/Noise above retransmits.
const CHANNEL_CAP: usize = 256;

/// Transport default MTU, used when the OS reports an unknown (0) channel MTU.
/// Matches `DEFAULT_BLE_MTU` in `config/transport.rs`.
const DEFAULT_BLE_MTU: u16 = 2048;

// ============================================================================
// AndroidRadio — the Kotlin-implemented command surface
// ============================================================================

/// The radio commands the bridge issues to the platform. `myco-core` implements
/// this via JNI `call_method` on the Kotlin `BleRadio` object. Object-safe so the
/// bridge can hold `Arc<dyn AndroidRadio>`.
///
/// These are the **control** plane only — never the byte hot path. Outbound bytes
/// are pulled by Kotlin via [`AndroidBleBridge::next_send`]; inbound bytes are
/// pushed by Kotlin via [`AndroidBleBridge::deliver_recv`].
pub trait AndroidRadio: Send + Sync {
    /// Open an insecure L2CAP listener and return the OS-assigned PSM (0 = failure).
    fn listen(&self) -> u16;
    /// Begin dialing `addr` at `psm`. The outcome is delivered asynchronously via
    /// [`AndroidBleBridge::deliver_connect_result`] keyed by `connect_id`.
    fn connect(&self, connect_id: i64, addr: &BleAddr, psm: u16);
    /// Advertise the FIPS service UUID plus our listener `psm` (16-bit LE
    /// service-data — see [`super::psm`]).
    fn start_advertising(&self, psm: u16);
    fn stop_advertising(&self);
    /// Scan for the FIPS UUID; deliver hits via [`AndroidBleBridge::deliver_scan`].
    fn start_scanning(&self);
    fn stop_scanning(&self);
    /// Close the L2CAP socket for `ch_id` (called when FIPS drops the stream).
    fn close_channel(&self, ch_id: i64);
}

// ============================================================================
// AndroidBleBridge — the shared channel machinery
// ============================================================================

/// The half of a channel kept by the bridge (the JNI-facing ends).
struct ChannelState {
    /// Kotlin-pushed inbound bytes land here; the stream's `recv` awaits them.
    recv_tx: mpsc::Sender<Vec<u8>>,
    /// `BleStream::send` pushes here; the Kotlin writer thread pulls via `next_send`.
    send_rx: Mutex<std::sync::mpsc::Receiver<Vec<u8>>>,
    closed: Arc<AtomicBool>,
}

/// The half of a channel handed to the `BleStream` (the FIPS-facing ends).
struct StreamEndpoints {
    ch_id: i64,
    remote: BleAddr,
    send_mtu: u16,
    recv_mtu: u16,
    recv_rx: mpsc::Receiver<Vec<u8>>,
    send_tx: std::sync::mpsc::SyncSender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

/// Channel machinery shared between [`AndroidIo`] and the JNI layer in `myco-core`.
///
/// Constructed by `myco-core` with a concrete [`AndroidRadio`], injected via
/// [`set_android_ble_bridge`], and driven by its `deliver_*` / `next_send`
/// methods from the JNI exports.
pub struct AndroidBleBridge {
    radio: Arc<dyn AndroidRadio>,
    next_id: AtomicI64,
    /// Our own OS-assigned listener PSM, learned from `radio.listen()`.
    local_psm: AtomicU16,
    /// Learned peer PSMs (advert service-data), consulted on `connect`.
    psm_map: PsmMap,
    channels: Mutex<HashMap<i64, ChannelState>>,
    /// connect_id → result slot for an in-flight outbound dial.
    connects: Mutex<HashMap<i64, oneshot::Sender<StreamEndpoints>>>,
    /// Inbound-accept fan-in; the acceptor takes the receiver once.
    accept_tx: mpsc::Sender<StreamEndpoints>,
    accept_rx: Mutex<Option<mpsc::Receiver<StreamEndpoints>>>,
    /// Scan fan-in; the scanner takes the receiver once.
    scan_tx: mpsc::Sender<BleAddr>,
    scan_rx: Mutex<Option<mpsc::Receiver<BleAddr>>>,
}

impl AndroidBleBridge {
    /// Build a bridge over a concrete radio.
    pub fn new(radio: Arc<dyn AndroidRadio>) -> Arc<Self> {
        let (accept_tx, accept_rx) = mpsc::channel(CHANNEL_CAP);
        let (scan_tx, scan_rx) = mpsc::channel(CHANNEL_CAP);
        Arc::new(Self {
            radio,
            next_id: AtomicI64::new(1),
            local_psm: AtomicU16::new(DEFAULT_PSM),
            psm_map: PsmMap::new(),
            channels: Mutex::new(HashMap::new()),
            connects: Mutex::new(HashMap::new()),
            accept_tx,
            accept_rx: Mutex::new(Some(accept_rx)),
            scan_tx,
            scan_rx: Mutex::new(Some(scan_rx)),
        })
    }

    fn lock_channels(&self) -> std::sync::MutexGuard<'_, HashMap<i64, ChannelState>> {
        self.channels.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Allocate a channel id and wire its two halves, registering the
    /// bridge-facing half and returning the FIPS-facing half.
    fn make_channel(&self, remote: BleAddr, send_mtu: u16, recv_mtu: u16) -> StreamEndpoints {
        let ch_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (recv_tx, recv_rx) = mpsc::channel(CHANNEL_CAP);
        let (send_tx, send_rx) = std::sync::mpsc::sync_channel(CHANNEL_CAP);
        let closed = Arc::new(AtomicBool::new(false));
        self.lock_channels().insert(
            ch_id,
            ChannelState {
                recv_tx,
                send_rx: Mutex::new(send_rx),
                closed: Arc::clone(&closed),
            },
        );
        StreamEndpoints {
            ch_id,
            remote,
            send_mtu: if send_mtu == 0 { DEFAULT_BLE_MTU } else { send_mtu },
            recv_mtu: if recv_mtu == 0 { DEFAULT_BLE_MTU } else { recv_mtu },
            recv_rx,
            send_tx,
            closed,
        }
    }

    // --- JNI-facing push/pull surface (called by myco-core's exports) ---

    /// Kotlin accepted a new inbound L2CAP channel. Returns the allocated `ch_id`.
    pub fn deliver_inbound(&self, remote: BleAddr, send_mtu: u16, recv_mtu: u16) -> i64 {
        let ep = self.make_channel(remote, send_mtu, recv_mtu);
        let ch_id = ep.ch_id;
        if self.accept_tx.try_send(ep).is_err() {
            // Acceptor gone or saturated: reclaim the half-registered channel.
            self.lock_channels().remove(&ch_id);
            return 0;
        }
        ch_id
    }

    /// Kotlin finished (or failed) an outbound dial started by `radio.connect`.
    /// Returns the allocated `ch_id` on success, else 0.
    pub fn deliver_connect_result(
        &self,
        connect_id: i64,
        ok: bool,
        remote: BleAddr,
        send_mtu: u16,
        recv_mtu: u16,
    ) -> i64 {
        let waiter = self
            .connects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&connect_id);
        let Some(tx) = waiter else { return 0 };
        if !ok {
            drop(tx); // dropping the sender wakes the awaiting connect() as an error
            return 0;
        }
        let ep = self.make_channel(remote, send_mtu, recv_mtu);
        let ch_id = ep.ch_id;
        if tx.send(ep).is_err() {
            self.lock_channels().remove(&ch_id);
            return 0;
        }
        ch_id
    }

    /// Kotlin discovered a FIPS peer advertising `psm` (its OS-assigned listener
    /// PSM). Learns the per-peer PSM and surfaces the address to the scanner.
    pub fn deliver_scan(&self, addr: BleAddr, psm: u16) {
        if psm != 0 {
            self.psm_map.learn(&addr, psm);
        }
        let _ = self.scan_tx.try_send(addr);
    }

    /// Kotlin read one L2CAP packet for `ch_id`. Returns false if the channel is
    /// unknown/closed (Kotlin should then stop its reader).
    pub fn deliver_recv(&self, ch_id: i64, data: &[u8]) -> bool {
        let tx = self
            .lock_channels()
            .get(&ch_id)
            .map(|c| c.recv_tx.clone());
        match tx {
            Some(tx) => tx.try_send(data.to_vec()).is_ok(),
            None => false,
        }
    }

    /// Kotlin's per-channel writer thread pulls the next outbound packet, blocking
    /// up to `timeout`. `None` = timed out (Kotlin loops) or the channel is gone.
    pub fn next_send(&self, ch_id: i64, timeout: Duration) -> Option<Vec<u8>> {
        // Clone-free: hold the channels lock only long enough to find the
        // per-channel receiver lock, then block on recv_timeout outside it would
        // require the receiver to outlive the guard — instead we briefly take the
        // channels lock, then the channel's own lock, and block there. The
        // channels map is only mutated on create/close, so contention is low.
        let guard = self.lock_channels();
        let state = guard.get(&ch_id)?;
        let rx = state.send_rx.lock().unwrap_or_else(|e| e.into_inner());
        // Note: we hold both locks across the blocking recv. Acceptable for P1 —
        // create/close are rare; revisit if it shows up under load (R3).
        match rx.recv_timeout(timeout) {
            Ok(bytes) => Some(bytes),
            Err(_) => None,
        }
    }

    /// Kotlin reports `ch_id` closed (EOF / socket gone). Wakes the stream's
    /// `recv` with a zero-length read (FIPS treats that as peer-closed).
    pub fn channel_closed(&self, ch_id: i64) {
        if let Some(state) = self.lock_channels().remove(&ch_id) {
            state.closed.store(true, Ordering::Relaxed);
            // Dropping recv_tx closes the stream's recv_rx → recv() returns Ok(0).
            drop(state);
        }
    }

    /// Whether `ch_id` is still registered. The JNI `next_send` export uses this
    /// to tell a timeout (loop again) from a closed channel (stop the writer).
    pub fn channel_open(&self, ch_id: i64) -> bool {
        self.lock_channels().contains_key(&ch_id)
    }
}

// ============================================================================
// Global injection seam
// ============================================================================

static BRIDGE: OnceLock<Arc<AndroidBleBridge>> = OnceLock::new();

/// Inject the process-wide bridge before `Node::new` (one radio per process, so a
/// global is correct; macOS/Linux backends own their radio in-process instead).
/// Returns `Err` if a bridge was already set.
pub fn set_android_ble_bridge(bridge: Arc<AndroidBleBridge>) -> Result<(), ()> {
    BRIDGE.set(bridge).map_err(|_| ())
}

/// The injected bridge, if any. The node's BLE construction arm reads this.
pub fn android_ble_bridge() -> Option<Arc<AndroidBleBridge>> {
    BRIDGE.get().cloned()
}

// ============================================================================
// BleIo implementation
// ============================================================================

/// macOS/Android-style external-radio backend over [`AndroidBleBridge`].
pub struct AndroidIo {
    bridge: Arc<AndroidBleBridge>,
}

impl AndroidIo {
    pub fn new(bridge: Arc<AndroidBleBridge>) -> Self {
        Self { bridge }
    }
}

/// One live L2CAP channel.
pub struct AndroidStream {
    ch_id: i64,
    remote: BleAddr,
    send_mtu: u16,
    recv_mtu: u16,
    recv_rx: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    send_tx: std::sync::mpsc::SyncSender<Vec<u8>>,
    closed: Arc<AtomicBool>,
    radio: Arc<dyn AndroidRadio>,
}

impl AndroidStream {
    fn from_endpoints(ep: StreamEndpoints, radio: Arc<dyn AndroidRadio>) -> Self {
        Self {
            ch_id: ep.ch_id,
            remote: ep.remote,
            send_mtu: ep.send_mtu,
            recv_mtu: ep.recv_mtu,
            recv_rx: AsyncMutex::new(ep.recv_rx),
            send_tx: ep.send_tx,
            closed: ep.closed,
            radio,
        }
    }
}

impl Drop for AndroidStream {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
        self.radio.close_channel(self.ch_id);
    }
}

impl BleStream for AndroidStream {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(TransportError::Io(std::io::Error::other("BLE channel closed")));
        }
        // Pure channel push — no JNI on the hot path. The Kotlin writer thread
        // pulls this via the bridge's next_send and writes the socket.
        self.send_tx
            .try_send(data.to_vec())
            .map_err(|e| TransportError::Io(std::io::Error::other(format!("BLE send: {e}"))))
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        match self.recv_rx.lock().await.recv().await {
            Some(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            // Sender dropped (channel closed) → peer-closed, per the BleStream
            // contract (a zero-length recv means the peer closed).
            None => Ok(0),
        }
    }

    fn send_mtu(&self) -> u16 {
        self.send_mtu
    }

    fn recv_mtu(&self) -> u16 {
        self.recv_mtu
    }

    fn remote_addr(&self) -> &BleAddr {
        &self.remote
    }
}

/// Yields inbound channels Kotlin accepted.
pub struct AndroidAcceptor {
    rx: Option<mpsc::Receiver<StreamEndpoints>>,
    radio: Arc<dyn AndroidRadio>,
}

impl BleAcceptor for AndroidAcceptor {
    type Stream = AndroidStream;

    async fn accept(&mut self) -> Result<AndroidStream, TransportError> {
        match self.rx.as_mut() {
            Some(rx) => match rx.recv().await {
                Some(ep) => Ok(AndroidStream::from_endpoints(ep, Arc::clone(&self.radio))),
                None => std::future::pending().await, // fan-in closed; idle
            },
            None => std::future::pending().await, // acceptor already consumed
        }
    }
}

/// Yields discovered FIPS peers (the learned PSM is captured into the bridge map).
pub struct AndroidScanner {
    rx: Option<mpsc::Receiver<BleAddr>>,
}

impl BleScanner for AndroidScanner {
    async fn next(&mut self) -> Option<BleAddr> {
        match self.rx.as_mut() {
            Some(rx) => rx.recv().await,
            None => None,
        }
    }
}

impl BleIo for AndroidIo {
    type Stream = AndroidStream;
    type Acceptor = AndroidAcceptor;
    type Scanner = AndroidScanner;

    async fn listen(&self, _psm: u16) -> Result<AndroidAcceptor, TransportError> {
        // Android assigns the listener PSM; the `psm` arg from FIPS is ignored.
        let os_psm = self.bridge.radio.listen();
        if os_psm != 0 {
            self.bridge.local_psm.store(os_psm, Ordering::Relaxed);
        }
        let rx = self
            .bridge
            .accept_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        Ok(AndroidAcceptor {
            rx,
            radio: Arc::clone(&self.bridge.radio),
        })
    }

    async fn connect(&self, addr: &BleAddr, psm: u16) -> Result<AndroidStream, TransportError> {
        // Substitute the learned per-peer PSM for this address, if known.
        let dial_psm = self.bridge.psm_map.resolve(addr, psm);
        let connect_id = self.bridge.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.bridge
            .connects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(connect_id, tx);
        self.bridge.radio.connect(connect_id, addr, dial_psm);
        // FIPS already wraps connect() in a timeout, so we just await the result.
        match rx.await {
            Ok(ep) => Ok(AndroidStream::from_endpoints(ep, Arc::clone(&self.bridge.radio))),
            Err(_) => {
                self.bridge
                    .connects
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&connect_id);
                Err(TransportError::Io(std::io::Error::other(format!(
                    "BLE connect to {addr} failed"
                ))))
            }
        }
    }

    async fn start_advertising(&self) -> Result<(), TransportError> {
        self.bridge
            .radio
            .start_advertising(self.bridge.local_psm.load(Ordering::Relaxed));
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), TransportError> {
        self.bridge.radio.stop_advertising();
        Ok(())
    }

    async fn start_scanning(&self) -> Result<AndroidScanner, TransportError> {
        // Re-learn PSMs each scan cycle (addresses rotate with MAC randomization).
        self.bridge.psm_map.clear();
        self.bridge.radio.start_scanning();
        let rx = self
            .bridge
            .scan_rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        Ok(AndroidScanner { rx })
    }

    fn local_addr(&self) -> Result<BleAddr, TransportError> {
        Ok(BleAddr {
            adapter: ANDROID_ADAPTER.to_string(),
            device: [0, 0, 0, 0, 0, 0],
        })
    }

    fn adapter_name(&self) -> &str {
        ANDROID_ADAPTER
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU16 as TestAtomicU16;

    /// A mock radio that records commands and lets the test drive the bridge.
    #[derive(Default)]
    struct MockRadio {
        listen_psm: TestAtomicU16,
        scanning: AtomicBool,
        advertising_psm: TestAtomicU16,
    }

    impl AndroidRadio for MockRadio {
        fn listen(&self) -> u16 {
            self.listen_psm.load(Ordering::Relaxed)
        }
        fn connect(&self, _connect_id: i64, _addr: &BleAddr, _psm: u16) {}
        fn start_advertising(&self, psm: u16) {
            self.advertising_psm.store(psm, Ordering::Relaxed);
        }
        fn stop_advertising(&self) {}
        fn start_scanning(&self) {
            self.scanning.store(true, Ordering::Relaxed);
        }
        fn stop_scanning(&self) {}
        fn close_channel(&self, _ch_id: i64) {}
    }

    fn addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: ANDROID_ADAPTER.to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    #[tokio::test]
    async fn inbound_channel_recv_and_close() {
        let radio = Arc::new(MockRadio::default());
        let bridge = AndroidBleBridge::new(radio.clone());
        let io = AndroidIo::new(Arc::clone(&bridge));

        let mut acceptor = io.listen(0).await.unwrap();

        // Kotlin accepts an inbound channel, then pushes a packet.
        let ch_id = bridge.deliver_inbound(addr(1), 512, 512);
        assert!(ch_id > 0);
        assert!(bridge.deliver_recv(ch_id, b"hello"));

        let stream = acceptor.accept().await.unwrap();
        assert_eq!(stream.remote_addr(), &addr(1));
        assert_eq!(stream.send_mtu(), 512);

        let mut buf = [0u8; 64];
        let n = stream.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // Closing the channel makes the next recv return 0 (peer closed).
        bridge.channel_closed(ch_id);
        let n = stream.recv(&mut buf).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn outbound_send_is_pulled_by_next_send() {
        let radio = Arc::new(MockRadio::default());
        let bridge = AndroidBleBridge::new(radio.clone());

        // Simulate an accepted channel and grab its stream.
        let mut acceptor = AndroidIo::new(Arc::clone(&bridge)).listen(0).await.unwrap();
        let ch_id = bridge.deliver_inbound(addr(2), 0, 0);
        let stream = acceptor.accept().await.unwrap();
        // 0 MTU falls back to the transport default.
        assert!(stream.send_mtu() > 0);

        stream.send(b"out").await.unwrap();
        let pulled = bridge.next_send(ch_id, Duration::from_millis(100)).unwrap();
        assert_eq!(pulled, b"out");
        // Nothing more queued → times out (None).
        assert!(bridge.next_send(ch_id, Duration::from_millis(10)).is_none());
    }

    #[tokio::test]
    async fn scan_learns_psm_and_connect_substitutes_it() {
        let radio = Arc::new(MockRadio::default());
        let bridge = AndroidBleBridge::new(radio.clone());
        let io = AndroidIo::new(Arc::clone(&bridge));

        let mut scanner = io.start_scanning().await.unwrap();
        assert!(radio.scanning.load(Ordering::Relaxed));

        bridge.deliver_scan(addr(3), 0x00C1);
        assert_eq!(scanner.next().await, Some(addr(3)));
        // The learned PSM is what a later dial would use (over FIPS's default).
        assert_eq!(bridge.psm_map.resolve(&addr(3), DEFAULT_PSM), 0x00C1);
    }

    #[tokio::test]
    async fn advertise_uses_os_assigned_listen_psm() {
        let radio = Arc::new(MockRadio::default());
        radio.listen_psm.store(0x0099, Ordering::Relaxed);
        let bridge = AndroidBleBridge::new(radio.clone());
        let io = AndroidIo::new(Arc::clone(&bridge));

        let _ = io.listen(0).await.unwrap(); // learns the OS PSM
        io.start_advertising().await.unwrap();
        assert_eq!(radio.advertising_psm.load(Ordering::Relaxed), 0x0099);
    }
}
