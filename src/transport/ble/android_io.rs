//! A [`BleIo`] backend whose radio is supplied by the embedder.
//!
//! The two backends that came before this one own a Bluetooth stack in
//! process: `BluerIo` talks to BlueZ over D-Bus, and `MockBleIo` is an
//! in-memory double. Some platforms allow neither. On Android every BLE
//! capability this transport needs — scanning, advertising, L2CAP listen and
//! connect, and the socket I/O itself — is a Java API held under a permission
//! and foreground-service model that only the application can satisfy. There
//! is no Rust-reachable radio to open.
//!
//! So this backend does not drive a radio; it drives *the embedder's* radio.
//!
//! # Shape
//!
//! - [`AndroidRadio`] is the command surface the embedder implements: open a
//!   listener, dial a peer, start and stop advertising and scanning, close a
//!   channel. It is object-safe, control-plane only, and deliberately tiny.
//! - [`AndroidBleBridge`] is the channel machinery around one radio. The
//!   embedder builds it over its `AndroidRadio` and drives its `deliver_*`
//!   and [`next_send`](AndroidBleBridge::next_send) methods from whatever
//!   foreign-function layer it has; nothing in this module knows about JNI.
//! - [`BleRadioSlot`] is where a bridge is installed. The node owns one and
//!   hands out shared handles; [`AndroidIo`] resolves it per operation.
//!
//! # Bytes never cross the command surface
//!
//! Inbound bytes are **pushed** into a tokio channel by the embedder
//! ([`deliver_recv`](AndroidBleBridge::deliver_recv)) and the awaiting
//! transport task wakes. Outbound bytes are **pulled** out of a bounded queue
//! by the embedder's writer thread
//! ([`next_send`](AndroidBleBridge::next_send)), which blocks with a timeout.
//! So [`BleStream::send`] is a channel push and never makes a foreign call on
//! the byte hot path, and no foreign upcall can block a runtime worker.
//!
//! The outbound queue is bounded and shallow on purpose: see
//! [`SEND_QUEUE_CAP`].
//!
//! # A radio that arrives late, and is replaced
//!
//! The radio's lifetime is not the node's. It belongs to a service the user
//! can start and stop — turning Bluetooth on after the mesh is already
//! running, or off and on again — and each start typically mints a fresh
//! radio object. A backend that captured its radio at construction, or a
//! transport built only once a radio existed, would make "the user enabled
//! Bluetooth" mean "tear the node down and rebuild it", dropping every peer,
//! session and route for as long as re-handshaking takes.
//!
//! Hence the slot. The transport is built and started whether or not a radio
//! is present; [`AndroidIo::listen`] and [`AndroidIo::start_scanning`]
//! succeed with an empty slot and hand back an acceptor and a scanner that
//! follow it, activating the radio when one is installed and re-activating it
//! when one replaces another. Dials attempted with an empty slot fail, and
//! the transport's own probe loop retries them later. Live streams keep the
//! bridge they were opened on rather than migrating: a channel belongs to the
//! socket that created it, and those die with the radio that owned them.
//!
//! The slot is owned by a node, not by a process global. A global is simpler
//! and wrong — it collapses as soon as two nodes share a process, which
//! includes any test that drives two backends at once.
//!
//! # Testing
//!
//! Everything here is ordinary Rust; the foreign-function layer lives in the
//! embedder. The module is therefore compiled under `cfg(test)` on any host,
//! so its channel machinery, slot semantics and connect routing are unit
//! tested and linted on an ordinary CI runner against a mock radio, with no
//! device and no cross-compilation.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwapOption;
use tokio::sync::Mutex as AsyncMutex;
use tokio::sync::{Notify, mpsc, oneshot};
use tracing::{debug, trace};

use crate::transport::TransportError;

use super::addr::BleAddr;
use super::io::{BleAcceptor, BleIo, BleScanner, BleStream, ScanAdvert};

/// Adapter label reported by this backend.
///
/// Platforms that hide the radio behind an application API also hide any
/// BlueZ-style adapter name, so there is nothing to report but a stable
/// placeholder. Nothing keys off it: peers are identified by node address,
/// never by adapter or MAC.
const ANDROID_ADAPTER: &str = "ble0";

/// Bound on the inbound byte queue and on the accept and scan fan-ins.
///
/// Generous, because these carry control events that should not be dropped
/// under a burst, and because inbound L2CAP data that is dropped here is
/// recovered by the retransmission above.
const CHANNEL_CAP: usize = 256;

/// Bound on the **outbound** byte queue, from this backend to the embedder's
/// writer.
///
/// Kept shallow deliberately. A BLE link's bandwidth-delay product is on the
/// order of a single packet, so a deep queue does not absorb a burst, it
/// bufferbloats: round-trip time balloons into seconds and the congestion
/// control above never finds the real capacity. A shallow *tail-drop* queue is
/// no better — it sheds packets and collapses throughput instead. So the queue
/// is both shallow and blocking: [`BleStream::send`] waits for a slot rather
/// than dropping, which propagates flow control up through the framing and
/// multiplexing layers to whatever is generating the traffic.
///
/// The value is the best one observed in a throughput sweep on real hardware —
/// shallower starved the radio's connection events, deeper regressed
/// throughput — but the sweep was noisy and non-monotonic, because run-to-run
/// BLE variance (RF conditions, and whether the OS grants the faster PHY and a
/// high-priority connection interval that session) rivals the effect of the
/// knob itself. Treat it as a working value pending re-measurement with PHY
/// and connection-interval instrumentation, not as a proven optimum.
const SEND_QUEUE_CAP: usize = 32;

/// Fallback channel MTU for a platform that reports an unknown (zero) one.
///
/// Matches the BLE transport's configured default so an unknown MTU behaves
/// like an unconfigured one rather than like a zero-capacity link.
const DEFAULT_BLE_MTU: u16 = 2048;

/// How long a full outbound queue is waited on before re-checking whether the
/// channel died underneath us.
const SEND_BACKPRESSURE_POLL: Duration = Duration::from_millis(2);

// ============================================================================
// AndroidRadio — the embedder-implemented command surface
// ============================================================================

/// The radio commands this backend issues to the embedder.
///
/// Object-safe, so a bridge can hold `Arc<dyn AndroidRadio>`. Control plane
/// only: bytes never cross this trait in either direction — outbound bytes are
/// pulled by the embedder via [`AndroidBleBridge::next_send`] and inbound bytes
/// are pushed by it via [`AndroidBleBridge::deliver_recv`].
///
/// Every method returns immediately. Outcomes that take time arrive back
/// through the bridge: an accepted inbound channel through
/// [`AndroidBleBridge::deliver_inbound`], a dial's result through
/// [`AndroidBleBridge::deliver_connect_result`], an advertisement through
/// [`AndroidBleBridge::deliver_scan`].
pub trait AndroidRadio: Send + Sync {
    /// Open an L2CAP listener and report the PSM it was bound to.
    ///
    /// Returns `0` if no listener could be opened. The PSM is chosen by the
    /// platform, not by this transport — which is the whole reason
    /// [`BleIo::listen`] reports a PSM back rather than being assumed to have
    /// bound the one it was asked for.
    fn listen(&self) -> u16;

    /// Begin dialing `addr` on `psm`.
    ///
    /// The outcome is delivered later through
    /// [`AndroidBleBridge::deliver_connect_result`], keyed by `connect_id`.
    /// The transport already bounds the wait, so a dial that is never answered
    /// is not a leak of anything but one map entry until the transport gives
    /// up on it.
    fn connect(&self, connect_id: i64, addr: &BleAddr, psm: u16);

    /// Advertise the FIPS service, carrying `psm` as the listener PSM peers
    /// should dial. See [`super::psm`] for the wire layout.
    fn start_advertising(&self, psm: u16);

    /// Stop advertising.
    fn stop_advertising(&self);

    /// Start scanning for FIPS advertisements, delivering each one through
    /// [`AndroidBleBridge::deliver_scan`].
    fn start_scanning(&self);

    /// Stop scanning.
    fn stop_scanning(&self);

    /// Close the L2CAP channel `ch_id`, called when this transport drops the
    /// stream that owned it.
    fn close_channel(&self, ch_id: i64);
}

// ============================================================================
// BleRadioSlot — where the embedder installs a radio
// ============================================================================

/// The node-owned slot an embedder installs its radio bridge into.
///
/// Reads are lock-free, because every backend operation resolves the slot
/// before doing anything else. Installing, replacing and clearing are safe at
/// any time and from any thread, including before the node has started and
/// long after it has.
///
/// Replacing a bridge does not migrate live streams onto the new radio. Their
/// channels belong to sockets the old radio owned and die with it; the
/// transport notices those deaths the way it notices any other link loss.
#[derive(Default)]
pub struct BleRadioSlot {
    current: ArcSwapOption<AndroidBleBridge>,
    /// Woken on every install and clear, so a backend parked on the old
    /// bridge's channels re-resolves immediately instead of polling.
    changed: Notify,
}

impl BleRadioSlot {
    /// An empty slot.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a bridge, replacing whatever was there.
    pub fn install(&self, bridge: Arc<AndroidBleBridge>) {
        self.current.store(Some(bridge));
        self.changed.notify_waiters();
    }

    /// Remove the installed bridge, if any.
    ///
    /// Operations then fail, or park, until one is installed again. Nothing is
    /// torn down here beyond this reference: the embedder owns the radio's
    /// lifetime and closes its sockets on its own schedule.
    pub fn clear(&self) {
        self.current.store(None);
        self.changed.notify_waiters();
    }

    /// The currently installed bridge, if any.
    pub fn current(&self) -> Option<Arc<AndroidBleBridge>> {
        self.current.load_full()
    }

    /// Whether a bridge is installed.
    pub fn is_installed(&self) -> bool {
        self.current.load().is_some()
    }
}

// ============================================================================
// AndroidBleBridge — channel machinery over one radio
// ============================================================================

/// The bridge-side half of one L2CAP channel.
struct ChannelState {
    /// Bytes the embedder pushed in; the stream's `recv` awaits them.
    recv_tx: mpsc::Sender<Vec<u8>>,
    /// Bytes waiting to go out; the embedder's writer pulls them.
    ///
    /// Behind an `Arc` so [`AndroidBleBridge::next_send`] can clone it out and
    /// release the channel map before blocking, rather than stalling every
    /// other channel's create and close for the length of one timeout.
    send_rx: Arc<Mutex<std::sync::mpsc::Receiver<Vec<u8>>>>,
    closed: Arc<AtomicBool>,
}

/// The stream-side half of one L2CAP channel, handed over once.
struct StreamEndpoints {
    ch_id: i64,
    remote: BleAddr,
    send_mtu: u16,
    recv_mtu: u16,
    recv_rx: mpsc::Receiver<Vec<u8>>,
    send_tx: std::sync::mpsc::SyncSender<Vec<u8>>,
    closed: Arc<AtomicBool>,
}

/// Channel machinery around one [`AndroidRadio`].
///
/// The embedder constructs one of these per radio it starts, installs it into
/// a [`BleRadioSlot`], keeps its own handle, and drives the `deliver_*` and
/// [`next_send`](Self::next_send) methods from its foreign-function layer.
pub struct AndroidBleBridge {
    radio: Arc<dyn AndroidRadio>,
    /// Source of channel and dial identifiers. Shared between the two so an
    /// identifier is unambiguous in a log line.
    next_id: AtomicI64,
    /// The listener PSM the platform assigned, or `0` before a listener has
    /// been opened.
    local_psm: AtomicU16,
    /// Set once each activation has been performed on this radio, so
    /// re-resolving the slot cannot issue it twice.
    listening: AtomicBool,
    /// The PSM currently being advertised on this radio, or `None` when it is
    /// not advertising. A lock rather than an atomic, so choosing the PSM and
    /// telling the radio about it are one step: two callers racing here would
    /// otherwise be free to land in the opposite order and leave the stale one
    /// on the air. See [`Self::advertise`].
    advertising: Mutex<Option<u16>>,
    scanning: AtomicBool,
    channels: Mutex<HashMap<i64, ChannelState>>,
    /// In-flight dials, by `connect_id`.
    connects: Mutex<HashMap<i64, oneshot::Sender<StreamEndpoints>>>,
    accept_tx: mpsc::Sender<StreamEndpoints>,
    accept_rx: Mutex<Option<mpsc::Receiver<StreamEndpoints>>>,
    scan_tx: mpsc::Sender<ScanAdvert>,
    scan_rx: Mutex<Option<mpsc::Receiver<ScanAdvert>>>,
}

impl AndroidBleBridge {
    /// Build a bridge over a radio.
    pub fn new(radio: Arc<dyn AndroidRadio>) -> Arc<Self> {
        let (accept_tx, accept_rx) = mpsc::channel(CHANNEL_CAP);
        let (scan_tx, scan_rx) = mpsc::channel(CHANNEL_CAP);
        Arc::new(Self {
            radio,
            next_id: AtomicI64::new(1),
            local_psm: AtomicU16::new(0),
            listening: AtomicBool::new(false),
            advertising: Mutex::new(None),
            scanning: AtomicBool::new(false),
            channels: Mutex::new(HashMap::new()),
            connects: Mutex::new(HashMap::new()),
            accept_tx,
            accept_rx: Mutex::new(Some(accept_rx)),
            scan_tx,
            scan_rx: Mutex::new(Some(scan_rx)),
        })
    }

    /// The PSM this radio's listener was bound to, or `0` if it has none.
    pub fn local_psm(&self) -> u16 {
        self.local_psm.load(Ordering::Relaxed)
    }

    fn lock_channels(&self) -> std::sync::MutexGuard<'_, HashMap<i64, ChannelState>> {
        self.channels.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Open this radio's listener if it has not been opened yet, and report
    /// the PSM it bound. Idempotent on *success*, so re-resolving the slot
    /// cannot open a second listener on the same radio.
    ///
    /// A failed attempt is deliberately not latched. Latching it would leave
    /// `local_psm` at zero for the life of the radio, so everything downstream
    /// would fall back to the configured PSM — and nothing would ever be
    /// listening on it. One radio that lost a race with the Bluetooth stack
    /// coming up would then be undialable until the service was restarted.
    /// Nothing here loops, so the retry costs one call per slot resolve.
    fn open_listener(&self) -> u16 {
        if !self.listening.swap(true, Ordering::AcqRel) {
            let psm = self.radio.listen();
            if psm == 0 {
                self.listening.store(false, Ordering::Release);
                debug!("no BLE listener could be opened on the installed radio");
                return 0;
            }
            self.local_psm.store(psm, Ordering::Relaxed);
            debug!(psm, "BLE listener opened on the installed radio");
            // The advertisement can already be on the air carrying the
            // configured fallback, because `start_advertising` is allowed to
            // reach a radio whose listener has not opened yet. Now that a real
            // PSM exists, it has to replace what is being announced.
            self.readvertise(psm);
        }
        self.local_psm.load(Ordering::Relaxed)
    }

    /// Advertise this radio's bound listener PSM, or `fallback` until the
    /// platform has assigned one.
    ///
    /// Choosing between the two happens *under the advertising lock*, in the
    /// same step as issuing it. Reading the bound PSM first and advertising
    /// second — as two steps — loses the race the transport's own start
    /// sequence runs: `listen` resolves an empty slot and reports the
    /// configured PSM, a radio is installed in the gap, and `start_advertising`
    /// then reads a zero bound PSM off it. Meanwhile the acceptor adopts that
    /// same radio, opens its listener and announces the real PSM — after
    /// which the first caller lands its stale fallback on top, and sticks.
    ///
    /// Sticking is what makes this fatal rather than untidy. A peer dials what
    /// it hears, so an advertisement carrying a PSM nothing is listening on
    /// makes this node permanently undialable: the platform rejects every
    /// inbound L2CAP connect request as an unknown PSM, below the application,
    /// so the node never learns why nobody reaches it.
    fn advertise(&self, fallback: u16) {
        let mut advertising = self.advertising.lock().unwrap_or_else(|e| e.into_inner());
        let bound = self.local_psm.load(Ordering::Relaxed);
        self.issue_advert(&mut advertising, if bound != 0 { bound } else { fallback });
    }

    /// Move a *live* advertisement onto `psm`.
    ///
    /// Does nothing if this radio was never asked to advertise: opening a
    /// listener is not itself such a request.
    fn readvertise(&self, psm: u16) {
        let mut advertising = self.advertising.lock().unwrap_or_else(|e| e.into_inner());
        if advertising.is_some() {
            self.issue_advert(&mut advertising, psm);
        }
    }

    /// Idempotent on the PSM, not on the call: a *different* PSM re-issues the
    /// advertisement rather than being swallowed, which is the whole point —
    /// see [`Self::advertise`]. Repeating the same one does not restart the
    /// advertiser, so the activations a slot-follower performs on every
    /// resolve stay free.
    fn issue_advert(&self, advertising: &mut Option<u16>, psm: u16) {
        if *advertising == Some(psm) {
            return;
        }
        *advertising = Some(psm);
        // Told under the lock, so the radio ends up carrying whatever the last
        // caller to *decide* chose. Releasing first would let a slower caller
        // land its already-superseded PSM afterwards.
        // `AndroidRadio::start_advertising` returns immediately by contract, so
        // nothing blocks here.
        self.radio.start_advertising(psm);
    }

    /// Stop advertising, so a later request starts it again.
    fn end_advertising(&self) {
        let mut advertising = self.advertising.lock().unwrap_or_else(|e| e.into_inner());
        if advertising.take().is_some() {
            self.radio.stop_advertising();
        }
    }

    /// Start scanning if this radio is not scanning already.
    fn begin_scanning(&self) {
        if !self.scanning.swap(true, Ordering::AcqRel) {
            self.radio.start_scanning();
        }
    }

    /// Allocate a channel, registering the bridge-side half and returning the
    /// stream-side half.
    fn make_channel(&self, remote: BleAddr, send_mtu: u16, recv_mtu: u16) -> StreamEndpoints {
        let ch_id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (recv_tx, recv_rx) = mpsc::channel(CHANNEL_CAP);
        let (send_tx, send_rx) = std::sync::mpsc::sync_channel(SEND_QUEUE_CAP);
        let closed = Arc::new(AtomicBool::new(false));
        self.lock_channels().insert(
            ch_id,
            ChannelState {
                recv_tx,
                send_rx: Arc::new(Mutex::new(send_rx)),
                closed: Arc::clone(&closed),
            },
        );
        StreamEndpoints {
            ch_id,
            remote,
            send_mtu: if send_mtu == 0 {
                DEFAULT_BLE_MTU
            } else {
                send_mtu
            },
            recv_mtu: if recv_mtu == 0 {
                DEFAULT_BLE_MTU
            } else {
                recv_mtu
            },
            recv_rx,
            send_tx,
            closed,
        }
    }

    // --- The surface the embedder drives ---------------------------------

    /// Report an inbound channel the radio accepted, and get back the channel
    /// identifier to use for it. `0` means the transport is not accepting and
    /// the socket should be closed.
    pub fn deliver_inbound(&self, remote: BleAddr, send_mtu: u16, recv_mtu: u16) -> i64 {
        let ep = self.make_channel(remote, send_mtu, recv_mtu);
        let ch_id = ep.ch_id;
        if self.accept_tx.try_send(ep).is_err() {
            // Nobody is accepting, or the fan-in is saturated. Reclaim the
            // half-registered channel rather than leaking it.
            self.lock_channels().remove(&ch_id);
            return 0;
        }
        ch_id
    }

    /// Report the outcome of a dial started by [`AndroidRadio::connect`].
    ///
    /// Returns the channel identifier on success, `0` on failure or if nothing
    /// is waiting on this `connect_id` any more — which is the normal outcome
    /// for a dial the transport already timed out.
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
            // Dropping the sender is what wakes the dial as a failure.
            drop(tx);
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

    /// Report one observed advertisement.
    ///
    /// `psm` is what the advertisement carried; pass `0` when it carried none,
    /// which is what a legacy advertiser produces. `rssi` is passed through
    /// unchanged when the platform reports one.
    pub fn deliver_scan(&self, addr: BleAddr, psm: u16, rssi: Option<i16>) {
        let advert = ScanAdvert {
            addr,
            psm: (psm != 0).then_some(psm),
            rssi,
        };
        if self.scan_tx.try_send(advert).is_err() {
            trace!("BLE scan fan-in full or unattached; advert dropped");
        }
    }

    /// Deliver bytes read from channel `ch_id`.
    ///
    /// Returns `false` when the channel is unknown or gone, which is the
    /// signal to stop reading it.
    pub fn deliver_recv(&self, ch_id: i64, data: &[u8]) -> bool {
        let tx = self.lock_channels().get(&ch_id).map(|c| c.recv_tx.clone());
        match tx {
            Some(tx) => tx.try_send(data.to_vec()).is_ok(),
            None => false,
        }
    }

    /// Pull the next outbound packet for channel `ch_id`, blocking up to
    /// `timeout`.
    ///
    /// `None` means either that nothing was queued within the timeout or that
    /// the channel is gone. The caller distinguishes them with
    /// [`channel_open`](Self::channel_open): still open means loop again, closed
    /// means stop the writer. Without that distinction a writer cannot tell an
    /// idle link from a dead one and spins on a closed channel forever.
    pub fn next_send(&self, ch_id: i64, timeout: Duration) -> Option<Vec<u8>> {
        // Clone the receiver and the closed flag out, then release the channel
        // map before blocking: holding it across the wait would stall every
        // other channel's create and close for up to `timeout`.
        let (send_rx, closed) = {
            let guard = self.lock_channels();
            let state = guard.get(&ch_id)?;
            (Arc::clone(&state.send_rx), Arc::clone(&state.closed))
        };
        let rx = send_rx.lock().unwrap_or_else(|e| e.into_inner());
        match rx.recv_timeout(timeout) {
            Ok(bytes) => Some(bytes),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => None,
            // The sending half is gone, so the stream was dropped. Mark the
            // channel closed so the writer's next `channel_open` says so.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                closed.store(true, Ordering::Relaxed);
                None
            }
        }
    }

    /// Whether channel `ch_id` is still open — registered, and not marked
    /// closed by a dropped stream.
    pub fn channel_open(&self, ch_id: i64) -> bool {
        self.lock_channels()
            .get(&ch_id)
            .map(|state| !state.closed.load(Ordering::Relaxed))
            .unwrap_or(false)
    }

    /// Report that channel `ch_id` is closed.
    ///
    /// Dropping the bridge-side sender is what wakes the stream's `recv` with
    /// a zero-length read, which is this transport's peer-closed signal.
    pub fn channel_closed(&self, ch_id: i64) {
        if let Some(state) = self.lock_channels().remove(&ch_id) {
            state.closed.store(true, Ordering::Relaxed);
        }
    }
}

// ============================================================================
// BleIo implementation
// ============================================================================

/// Reclaims an in-flight dial's slot in [`AndroidBleBridge::connects`] when
/// the dial goes away.
///
/// A dial cannot rely on its own code running to clean up after itself. The
/// transport bounds the wait with [`tokio::time::timeout`] and, when that
/// fires, simply *drops* the future — neither arm of the `rx.await` in
/// [`AndroidIo::connect`] gets to run. Without this the sender would sit in
/// the map waiting for an answer the embedder may never send, and a node whose
/// dials keep timing out would grow that map for the life of the process.
///
/// Answering a dial removes the entry first, so this is then a no-op.
struct InFlightDial {
    bridge: Arc<AndroidBleBridge>,
    connect_id: i64,
}

impl Drop for InFlightDial {
    fn drop(&mut self) {
        self.bridge
            .connects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.connect_id);
    }
}

/// Map an operation attempted with no radio installed onto a transport error.
///
/// Deliberately an ordinary I/O error rather than `NotSupported`: the radio is
/// absent right now, not absent in principle, and the caller should retry.
fn no_radio(op: &str) -> TransportError {
    TransportError::Io(std::io::Error::other(format!(
        "no BLE radio installed ({op})"
    )))
}

/// [`BleIo`] over whatever radio is currently installed in a [`BleRadioSlot`].
pub struct AndroidIo {
    slot: Arc<BleRadioSlot>,
    /// Shared with the acceptor and the scanner, so a radio installed later
    /// gets told everything the transport asked for at startup.
    intent: Arc<RadioIntent>,
}

impl AndroidIo {
    /// Drive whatever radio is installed in `slot`, now or later.
    pub fn new(slot: Arc<BleRadioSlot>) -> Self {
        Self {
            slot,
            intent: Arc::new(RadioIntent::default()),
        }
    }

    /// The slot this backend resolves.
    pub fn slot(&self) -> &Arc<BleRadioSlot> {
        &self.slot
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
        // Mark before closing: a writer that wakes between the two must see a
        // closed channel rather than an open one with no reader.
        self.closed.store(true, Ordering::Relaxed);
        self.radio.close_channel(self.ch_id);
    }
}

impl BleStream for AndroidStream {
    async fn send(&self, data: &[u8]) -> Result<(), TransportError> {
        // A channel push, never a foreign call: the embedder's writer pulls
        // this out via `next_send`. The queue is shallow (`SEND_QUEUE_CAP`) and
        // this waits for a slot rather than dropping, so backpressure reaches
        // the layers above instead of the link bufferbloating.
        let mut payload = data.to_vec();
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Err(TransportError::SendFailed("BLE channel closed".into()));
            }
            match self.send_tx.try_send(payload) {
                Ok(()) => return Ok(()),
                Err(std::sync::mpsc::TrySendError::Full(unsent)) => {
                    payload = unsent;
                    tokio::time::sleep(SEND_BACKPRESSURE_POLL).await;
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                    return Err(TransportError::SendFailed("BLE channel gone".into()));
                }
            }
        }
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        match self.recv_rx.lock().await.recv().await {
            Some(packet) => {
                let n = packet.len().min(buf.len());
                buf[..n].copy_from_slice(&packet[..n]);
                Ok(n)
            }
            // The bridge dropped its sender: peer closed. A zero-length read
            // is this transport's close signal.
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

/// What the transport asked this backend to do, held apart from any one
/// radio so it can be re-issued against the next one.
///
/// The transport issues `listen`, `start_advertising` and `start_scanning`
/// exactly once, at startup. A radio installed after that — or one replacing
/// another — has to be told the same things, or a node whose radio restarted
/// would sit there advertising nothing and scanning for nobody. Recording the
/// request rather than only performing it is what makes that possible.
#[derive(Default)]
struct RadioIntent {
    listen: AtomicBool,
    advertise: AtomicBool,
    /// PSM to advertise when the radio has no listener PSM of its own.
    advertise_fallback_psm: AtomicU16,
    scan: AtomicBool,
}

impl RadioIntent {
    /// Issue everything asked for so far against `bridge`.
    ///
    /// Each activation is idempotent per radio, so it does not matter which
    /// slot-follower gets here first after a swap, or how often.
    fn apply(&self, bridge: &AndroidBleBridge) {
        if self.listen.load(Ordering::Relaxed) {
            bridge.open_listener();
        }
        if self.advertise.load(Ordering::Relaxed) {
            // The bridge picks between its bound PSM and this fallback itself,
            // under the lock that also issues the advertisement. Deciding out
            // here would reintroduce the stale-PSM race — see
            // [`AndroidBleBridge::advertise`].
            bridge.advertise(self.advertise_fallback_psm.load(Ordering::Relaxed));
        }
        if self.scan.load(Ordering::Relaxed) {
            bridge.begin_scanning();
        }
    }
}

/// Resolve the slot, re-applying `intent` whenever the installed bridge is not
/// the one `seen` was resolved from.
///
/// Returns the current bridge, or `None` if the slot is empty. The caller
/// parks on [`BleRadioSlot::changed`] in that case.
fn resolve(
    slot: &BleRadioSlot,
    seen: &mut Option<Arc<AndroidBleBridge>>,
    intent: &RadioIntent,
) -> Option<Arc<AndroidBleBridge>> {
    let current = slot.current()?;
    let same = seen
        .as_ref()
        .is_some_and(|prev| Arc::ptr_eq(prev, &current));
    if !same {
        intent.apply(&current);
        *seen = Some(Arc::clone(&current));
    }
    Some(current)
}

/// Yields inbound channels the installed radio accepted.
///
/// Follows the slot: with no radio installed it parks rather than failing, and
/// a radio installed later is picked up and activated without the transport
/// being restarted.
pub struct AndroidAcceptor {
    slot: Arc<BleRadioSlot>,
    intent: Arc<RadioIntent>,
    /// The bridge `rx` was taken from, so a swap is detectable.
    seen: Option<Arc<AndroidBleBridge>>,
    rx: Option<mpsc::Receiver<StreamEndpoints>>,
    radio: Option<Arc<dyn AndroidRadio>>,
}

impl BleAcceptor for AndroidAcceptor {
    type Stream = AndroidStream;

    async fn accept(&mut self) -> Result<AndroidStream, TransportError> {
        loop {
            // Register interest before reading the slot, so an install that
            // races this resolve wakes the park below rather than being lost.
            let changed = self.slot.changed.notified();
            let previous = self.seen.clone();
            match resolve(&self.slot, &mut self.seen, &self.intent) {
                Some(bridge) => {
                    if !previous.is_some_and(|prev| Arc::ptr_eq(&prev, &bridge)) {
                        self.rx = bridge
                            .accept_rx
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .take();
                        self.radio = Some(Arc::clone(&bridge.radio));
                    }
                    let Some(rx) = self.rx.as_mut() else {
                        // Another acceptor already took this bridge's fan-in.
                        // Park until the slot changes rather than spinning.
                        changed.await;
                        continue;
                    };
                    let radio = self.radio.clone().expect("radio set alongside rx");
                    tokio::select! {
                        inbound = rx.recv() => match inbound {
                            Some(ep) => return Ok(AndroidStream::from_endpoints(ep, radio)),
                            // The bridge's fan-in is gone; wait for a new one.
                            None => self.rx = None,
                        },
                        _ = changed => {}
                    }
                }
                None => changed.await,
            }
        }
    }
}

/// Yields advertisements the installed radio observed.
///
/// Slot-following in the same way as [`AndroidAcceptor`]. It never reports
/// end-of-scan, because an absent radio is a gap rather than a stop.
pub struct AndroidScanner {
    slot: Arc<BleRadioSlot>,
    intent: Arc<RadioIntent>,
    seen: Option<Arc<AndroidBleBridge>>,
    rx: Option<mpsc::Receiver<ScanAdvert>>,
}

impl BleScanner for AndroidScanner {
    async fn next(&mut self) -> Option<ScanAdvert> {
        loop {
            let changed = self.slot.changed.notified();
            let previous = self.seen.clone();
            match resolve(&self.slot, &mut self.seen, &self.intent) {
                Some(bridge) => {
                    if !previous.is_some_and(|prev| Arc::ptr_eq(&prev, &bridge)) {
                        self.rx = bridge
                            .scan_rx
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .take();
                    }
                    let Some(rx) = self.rx.as_mut() else {
                        changed.await;
                        continue;
                    };
                    tokio::select! {
                        advert = rx.recv() => match advert {
                            Some(advert) => return Some(advert),
                            None => self.rx = None,
                        },
                        _ = changed => {}
                    }
                }
                None => changed.await,
            }
        }
    }
}

impl BleIo for AndroidIo {
    type Stream = AndroidStream;
    type Acceptor = AndroidAcceptor;
    type Scanner = AndroidScanner;

    async fn listen(&self, psm: u16) -> Result<(AndroidAcceptor, u16), TransportError> {
        // The requested PSM is a fallback only. This platform assigns the
        // listener's PSM, so what gets reported back — and therefore what gets
        // advertised — is whatever the radio bound.
        self.intent.listen.store(true, Ordering::Relaxed);
        let mut seen = None;
        let bound = match resolve(&self.slot, &mut seen, &self.intent) {
            Some(bridge) => {
                let bound = bridge.local_psm();
                if bound == 0 { psm } else { bound }
            }
            // No radio yet. Succeed anyway: the acceptor opens a listener on
            // whichever radio turns up, and until then there is simply nothing
            // to accept. Failing here would instead put the whole transport
            // into a failed state it never retries out of.
            None => psm,
        };
        let (rx, radio) = match seen.as_ref() {
            Some(bridge) => (
                bridge
                    .accept_rx
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .take(),
                Some(Arc::clone(&bridge.radio)),
            ),
            None => (None, None),
        };
        Ok((
            AndroidAcceptor {
                slot: Arc::clone(&self.slot),
                intent: Arc::clone(&self.intent),
                seen,
                rx,
                radio,
            },
            bound,
        ))
    }

    async fn connect(&self, addr: &BleAddr, psm: u16) -> Result<AndroidStream, TransportError> {
        let bridge = self.slot.current().ok_or_else(|| no_radio("connect"))?;
        let connect_id = bridge.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        bridge
            .connects
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(connect_id, tx);
        // Reclaims the entry however this dial ends — including the ending
        // that runs no code here at all. See [`InFlightDial`].
        let _in_flight = InFlightDial {
            bridge: Arc::clone(&bridge),
            connect_id,
        };
        bridge.radio.connect(connect_id, addr, psm);
        // The transport bounds this wait itself, so there is no timeout here.
        match rx.await {
            Ok(ep) => Ok(AndroidStream::from_endpoints(ep, Arc::clone(&bridge.radio))),
            Err(_) => Err(TransportError::Io(std::io::Error::other(format!(
                "BLE connect to {addr} failed"
            )))),
        }
    }

    async fn start_advertising(&self, psm: u16) -> Result<(), TransportError> {
        self.intent
            .advertise_fallback_psm
            .store(psm, Ordering::Relaxed);
        self.intent.advertise.store(true, Ordering::Relaxed);
        // With no radio installed there is nothing to advertise on yet, and
        // that is not an error: the intent is recorded, and whichever radio
        // turns up next is told to advertise as it is adopted.
        if let Some(bridge) = self.slot.current() {
            // `psm` is only a fallback here. The radio may have bound its own
            // by now — including in the window between this call and the
            // `listen` that produced `psm` — and the bridge is what resolves
            // that, atomically with putting it on the air.
            bridge.advertise(psm);
        }
        Ok(())
    }

    async fn stop_advertising(&self) -> Result<(), TransportError> {
        self.intent.advertise.store(false, Ordering::Relaxed);
        if let Some(bridge) = self.slot.current() {
            bridge.end_advertising();
        }
        Ok(())
    }

    async fn start_scanning(&self) -> Result<AndroidScanner, TransportError> {
        self.intent.scan.store(true, Ordering::Relaxed);
        let mut seen = None;
        let rx = match resolve(&self.slot, &mut seen, &self.intent) {
            Some(bridge) => bridge
                .scan_rx
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take(),
            // As with `listen`: succeed with nothing to yield yet, rather than
            // leaving the transport with no scanner for the rest of its life.
            None => None,
        };
        Ok(AndroidScanner {
            slot: Arc::clone(&self.slot),
            intent: Arc::clone(&self.intent),
            seen,
            rx,
        })
    }

    fn local_addr(&self) -> Result<BleAddr, TransportError> {
        // The platform does not expose the adapter's address, and nothing in
        // this transport needs it: peers are keyed by node address, and the
        // remote address of a channel comes from the channel itself.
        Ok(BleAddr {
            adapter: ANDROID_ADAPTER.to_string(),
            device: [0; 6],
        })
    }

    fn adapter_name(&self) -> &str {
        ANDROID_ADAPTER
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    /// Records what the transport asked the radio to do, and lets a test play
    /// the part of the embedder's foreign-function layer.
    #[derive(Default)]
    struct MockRadio {
        listen_psm: AtomicU16,
        listen_calls: AtomicU32,
        advertised_psm: AtomicU16,
        advertise_calls: AtomicU32,
        scan_calls: AtomicU32,
        closed_channels: Mutex<Vec<i64>>,
        dials: Mutex<Vec<(i64, BleAddr, u16)>>,
    }

    impl MockRadio {
        fn with_psm(psm: u16) -> Arc<Self> {
            let radio = Self::default();
            radio.listen_psm.store(psm, Ordering::Relaxed);
            Arc::new(radio)
        }

        fn dials(&self) -> Vec<(i64, BleAddr, u16)> {
            self.dials.lock().unwrap().clone()
        }
    }

    impl AndroidRadio for MockRadio {
        fn listen(&self) -> u16 {
            self.listen_calls.fetch_add(1, Ordering::Relaxed);
            self.listen_psm.load(Ordering::Relaxed)
        }
        fn connect(&self, connect_id: i64, addr: &BleAddr, psm: u16) {
            self.dials
                .lock()
                .unwrap()
                .push((connect_id, addr.clone(), psm));
        }
        fn start_advertising(&self, psm: u16) {
            self.advertise_calls.fetch_add(1, Ordering::Relaxed);
            self.advertised_psm.store(psm, Ordering::Relaxed);
        }
        fn stop_advertising(&self) {}
        fn start_scanning(&self) {
            self.scan_calls.fetch_add(1, Ordering::Relaxed);
        }
        fn stop_scanning(&self) {}
        fn close_channel(&self, ch_id: i64) {
            self.closed_channels.lock().unwrap().push(ch_id);
        }
    }

    fn addr(n: u8) -> BleAddr {
        BleAddr {
            adapter: ANDROID_ADAPTER.to_string(),
            device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
        }
    }

    fn slot_with(radio: Arc<MockRadio>) -> (Arc<BleRadioSlot>, Arc<AndroidBleBridge>) {
        let bridge = AndroidBleBridge::new(radio);
        let slot = Arc::new(BleRadioSlot::new());
        slot.install(Arc::clone(&bridge));
        (slot, bridge)
    }

    /// The PSM handed back by `listen` is the one the radio actually bound,
    /// not the one that was requested — the whole reason the seam reports a
    /// PSM at all.
    #[tokio::test]
    async fn listen_reports_the_psm_the_radio_bound() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, _bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);

        let (_acceptor, bound) = io.listen(0x0085).await.unwrap();

        assert_eq!(bound, 0x0099, "the OS-assigned PSM wins over the request");
        assert_eq!(radio.listen_calls.load(Ordering::Relaxed), 1);
    }

    /// And that bound PSM is what gets advertised, so peers dial where the
    /// listener really is.
    #[tokio::test]
    async fn advertising_carries_the_bound_psm() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, _bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);

        let (_acceptor, bound) = io.listen(0x0085).await.unwrap();
        io.start_advertising(bound).await.unwrap();

        assert_eq!(radio.advertised_psm.load(Ordering::Relaxed), 0x0099);
    }

    /// A radio that cannot open a listener reports zero, and the configured
    /// PSM is then the honest answer.
    #[tokio::test]
    async fn a_radio_with_no_listener_falls_back_to_the_requested_psm() {
        let radio = MockRadio::with_psm(0);
        let (slot, _bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);

        let (_acceptor, bound) = io.listen(0x0085).await.unwrap();

        assert_eq!(bound, 0x0085);
    }

    /// Bytes round-trip both ways: pushed in by the embedder and read by the
    /// stream, written by the stream and pulled out by the embedder.
    #[tokio::test]
    async fn bytes_round_trip_through_the_bridge() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();

        let ch_id = bridge.deliver_inbound(addr(1), 512, 512);
        assert!(ch_id > 0);
        assert!(bridge.deliver_recv(ch_id, b"inbound"));

        let stream = acceptor.accept().await.unwrap();
        assert_eq!(stream.remote_addr(), &addr(1));
        assert_eq!(stream.send_mtu(), 512);

        let mut buf = [0u8; 64];
        let n = stream.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"inbound");

        stream.send(b"outbound").await.unwrap();
        let pulled = bridge.next_send(ch_id, Duration::from_millis(100)).unwrap();
        assert_eq!(pulled, b"outbound");
    }

    /// An unknown channel MTU is treated as an unconfigured one, not as a
    /// zero-capacity link.
    #[tokio::test]
    async fn an_unknown_mtu_falls_back_to_the_transport_default() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();

        bridge.deliver_inbound(addr(2), 0, 0);
        let stream = acceptor.accept().await.unwrap();

        assert_eq!(stream.send_mtu(), DEFAULT_BLE_MTU);
        assert_eq!(stream.recv_mtu(), DEFAULT_BLE_MTU);
    }

    /// A writer must be able to tell "nothing queued" from "channel gone".
    /// Both make `next_send` return `None`; `channel_open` is what separates
    /// them, and without it a writer spins on a dead channel forever.
    #[tokio::test]
    async fn next_send_distinguishes_an_idle_channel_from_a_closed_one() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();

        let ch_id = bridge.deliver_inbound(addr(3), 512, 512);
        let stream = acceptor.accept().await.unwrap();

        assert!(bridge.next_send(ch_id, Duration::from_millis(5)).is_none());
        assert!(bridge.channel_open(ch_id), "idle, but still open");

        drop(stream);
        assert!(bridge.next_send(ch_id, Duration::from_millis(5)).is_none());
        assert!(
            !bridge.channel_open(ch_id),
            "a dropped stream must read as closed, not as idle",
        );
        assert_eq!(radio.closed_channels.lock().unwrap().as_slice(), &[ch_id]);
    }

    /// The bridge reporting a channel closed surfaces as a zero-length read,
    /// which is this transport's peer-closed signal.
    #[tokio::test]
    async fn a_closed_channel_reads_as_end_of_stream() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();

        let ch_id = bridge.deliver_inbound(addr(4), 512, 512);
        let stream = acceptor.accept().await.unwrap();

        bridge.channel_closed(ch_id);
        let mut buf = [0u8; 8];
        assert_eq!(stream.recv(&mut buf).await.unwrap(), 0);
    }

    /// The outbound queue is bounded: a sender that outruns the writer waits
    /// for a slot instead of the queue growing without bound.
    #[tokio::test(start_paused = true)]
    async fn a_full_outbound_queue_backpressures_rather_than_growing() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();

        let ch_id = bridge.deliver_inbound(addr(5), 512, 512);
        let stream = acceptor.accept().await.unwrap();

        for _ in 0..SEND_QUEUE_CAP {
            stream.send(b"x").await.unwrap();
        }

        let mut over_cap = Box::pin(stream.send(b"one too many"));
        assert!(
            futures::poll!(over_cap.as_mut()).is_pending(),
            "the {SEND_QUEUE_CAP}-deep queue is full, so the sender must wait",
        );

        // Draining one packet frees exactly one slot.
        assert!(bridge.next_send(ch_id, Duration::from_millis(1)).is_some());
        over_cap.await.unwrap();
    }

    /// Two dials in flight at once resolve to their own streams even when the
    /// embedder answers them out of order.
    #[tokio::test]
    async fn concurrent_dials_resolve_by_connect_id() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = Arc::new(AndroidIo::new(slot));

        let io_a = Arc::clone(&io);
        let dial_a = tokio::spawn(async move { io_a.connect(&addr(6), 0x00C1).await });
        let io_b = Arc::clone(&io);
        let dial_b = tokio::spawn(async move { io_b.connect(&addr(7), 0x00C2).await });

        // Wait for both dials to register before answering either.
        let dials = loop {
            let dials = radio.dials();
            if dials.len() == 2 {
                break dials;
            }
            tokio::task::yield_now().await;
        };
        let for_addr = |want: &BleAddr| {
            dials
                .iter()
                .find(|(_, a, _)| a == want)
                .cloned()
                .expect("dial registered")
        };
        let (id_a, _, psm_a) = for_addr(&addr(6));
        let (id_b, _, psm_b) = for_addr(&addr(7));
        assert_eq!((psm_a, psm_b), (0x00C1, 0x00C2), "each dial keeps its PSM");

        // Answer B first, then A.
        bridge.deliver_connect_result(id_b, true, addr(7), 512, 512);
        bridge.deliver_connect_result(id_a, true, addr(6), 512, 512);

        assert_eq!(dial_a.await.unwrap().unwrap().remote_addr(), &addr(6));
        assert_eq!(dial_b.await.unwrap().unwrap().remote_addr(), &addr(7));
    }

    /// A dial the embedder reports as failed surfaces as an error rather than
    /// hanging.
    #[tokio::test]
    async fn a_failed_dial_surfaces_as_an_error() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = Arc::new(AndroidIo::new(slot));

        let dialer = Arc::clone(&io);
        let dial = tokio::spawn(async move { dialer.connect(&addr(8), 0x0085).await });
        let connect_id = loop {
            if let Some(id) = radio.dials().first().map(|(id, _, _)| *id) {
                break id;
            }
            tokio::task::yield_now().await;
        };

        bridge.deliver_connect_result(connect_id, false, addr(8), 0, 0);
        assert!(dial.await.unwrap().is_err());
    }

    /// An advertised PSM reaches the shared driver through the scan advert,
    /// and an advert that carried none decodes to `None` rather than to zero.
    #[tokio::test]
    async fn scan_adverts_carry_the_advertised_psm() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);

        let mut scanner = io.start_scanning().await.unwrap();
        assert_eq!(radio.scan_calls.load(Ordering::Relaxed), 1);

        bridge.deliver_scan(addr(9), 0x00C1, Some(-42));
        assert_eq!(
            scanner.next().await,
            Some(ScanAdvert {
                addr: addr(9),
                psm: Some(0x00C1),
                rssi: Some(-42),
            }),
        );

        bridge.deliver_scan(addr(10), 0, None);
        assert_eq!(scanner.next().await, Some(ScanAdvert::new(addr(10))));
    }

    /// With an empty slot the transport still starts: `listen` and
    /// `start_scanning` succeed with nothing to yield yet, and only a dial —
    /// which the transport retries anyway — fails.
    #[tokio::test]
    async fn an_empty_slot_starts_cleanly_and_only_dials_fail() {
        let slot = Arc::new(BleRadioSlot::new());
        let io = AndroidIo::new(Arc::clone(&slot));

        assert!(!slot.is_installed());
        let (_acceptor, bound) = io.listen(0x0085).await.unwrap();
        assert_eq!(bound, 0x0085, "nothing bound one, so the request stands");
        assert!(io.start_scanning().await.is_ok());
        assert!(io.start_advertising(0x0085).await.is_ok());
        assert!(io.connect(&addr(11), 0x0085).await.is_err());
    }

    /// The requirement the slot exists for: a radio that arrives after the
    /// transport is already running is adopted in place. The acceptor opens a
    /// listener on it and starts delivering, with no node rebuild.
    #[tokio::test]
    async fn a_radio_installed_later_is_adopted_without_a_restart() {
        let slot = Arc::new(BleRadioSlot::new());
        let io = AndroidIo::new(Arc::clone(&slot));
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();
        io.start_advertising(0x0085).await.unwrap();

        assert!(io.connect(&addr(12), 0x0085).await.is_err());

        let accepting = tokio::spawn(async move { acceptor.accept().await });

        let radio = MockRadio::with_psm(0x00A1);
        let bridge = AndroidBleBridge::new(Arc::clone(&radio) as Arc<dyn AndroidRadio>);
        slot.install(Arc::clone(&bridge));

        // The acceptor picks the new radio up and opens its listener.
        let ch_id = loop {
            let ch_id = bridge.deliver_inbound(addr(12), 512, 512);
            if ch_id > 0 {
                break ch_id;
            }
            tokio::task::yield_now().await;
        };
        let stream = accepting.await.unwrap().unwrap();
        assert_eq!(stream.remote_addr(), &addr(12));
        assert!(bridge.channel_open(ch_id));
        assert_eq!(
            radio.listen_calls.load(Ordering::Relaxed),
            1,
            "the listener is opened once on the radio that turned up",
        );
        assert_eq!(
            radio.advertised_psm.load(Ordering::Relaxed),
            0x00A1,
            "and it advertises its own listener PSM, not the startup fallback",
        );
    }

    /// A radio installed *between* `listen` and `start_advertising` — the one
    /// window the transport's start sequence leaves open — is told to
    /// advertise the configured fallback, because its listener has not been
    /// opened yet and it has no PSM of its own to offer. The bound PSM arrives
    /// a moment later, and has to reach the air: an advertisement left
    /// carrying the fallback points every peer at a PSM nothing is listening
    /// on, and the platform rejects their connect requests below the
    /// application, so the node is silently undialable for as long as it runs.
    #[tokio::test]
    async fn a_bound_psm_replaces_a_fallback_that_is_already_on_the_air() {
        let slot = Arc::new(BleRadioSlot::new());
        let io = AndroidIo::new(Arc::clone(&slot));
        // Startup with an empty slot: nothing to bind, so the fallback stands.
        let (mut acceptor, bound) = io.listen(0x0085).await.unwrap();
        assert_eq!(bound, 0x0085, "no radio, so the request is all there is");

        // The radio turns up here — after `listen` resolved an empty slot and
        // before the transport gets to `start_advertising`.
        let radio = MockRadio::with_psm(0x00A1);
        let bridge = AndroidBleBridge::new(Arc::clone(&radio) as Arc<dyn AndroidRadio>);
        slot.install(Arc::clone(&bridge));

        io.start_advertising(bound).await.unwrap();
        assert_eq!(
            radio.advertised_psm.load(Ordering::Relaxed),
            0x0085,
            "with no listener open yet, the fallback is the only PSM there is",
        );

        // Driving the acceptor adopts the radio, which opens its listener.
        let accepting = tokio::spawn(async move { acceptor.accept().await });
        loop {
            if bridge.deliver_inbound(addr(16), 512, 512) > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
        accepting.await.unwrap().unwrap();

        assert_eq!(bridge.local_psm(), 0x00A1);
        assert_eq!(
            radio.advertised_psm.load(Ordering::Relaxed),
            0x00A1,
            "the bound PSM must replace the fallback on the air, not be swallowed \
             as 'already advertising'",
        );
    }

    /// The counterpart: re-issuing is keyed on the PSM changing, so the
    /// repeated activations a slot-follower performs do not restart the
    /// advertiser on every resolve.
    #[tokio::test]
    async fn re_advertising_the_same_psm_does_not_restart_the_advertiser() {
        let radio = MockRadio::with_psm(0x00A1);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(Arc::clone(&slot));
        let (_acceptor, bound) = io.listen(0x0085).await.unwrap();
        io.start_advertising(bound).await.unwrap();
        io.start_advertising(bound).await.unwrap();
        bridge.advertise(0x0085);

        assert_eq!(radio.advertised_psm.load(Ordering::Relaxed), 0x00A1);
        assert_eq!(
            radio.advertise_calls.load(Ordering::Relaxed),
            1,
            "one PSM, one advertisement",
        );
    }

    /// The stale-PSM race the *lock* is for, rather than the swallowed-call
    /// one above. A caller reaches this radio before its listener is open, so
    /// the only PSM it can offer is the configured fallback; the listener
    /// opens underneath it and announces the real one. Whichever order those
    /// two land in, the radio must be left carrying the bound PSM — which is
    /// only guaranteed because the choice between bound and fallback is made
    /// under the same lock that issues the advertisement, not before it.
    #[tokio::test]
    async fn a_fallback_decided_before_the_listener_opened_cannot_land_last() {
        let radio = MockRadio::with_psm(0x00A1);
        let bridge = AndroidBleBridge::new(Arc::clone(&radio) as Arc<dyn AndroidRadio>);

        // The listener opens first, and nothing is on the air yet, so opening
        // it does not start an advertisement of its own.
        assert_eq!(bridge.open_listener(), 0x00A1);
        assert_eq!(
            radio.advertise_calls.load(Ordering::Relaxed),
            0,
            "opening a listener is not a request to advertise",
        );

        // Now the caller that was holding the fallback gets there.
        bridge.advertise(0x0085);
        assert_eq!(
            radio.advertised_psm.load(Ordering::Relaxed),
            0x00A1,
            "the fallback is a fallback: a bound PSM outranks it, whenever the \
             caller happened to be handed it",
        );
    }

    /// A radio whose listener could not be opened is retried on the next slot
    /// resolve rather than being written off. Latching the failure would pin
    /// `local_psm` at zero for the life of the radio, so this node would go on
    /// advertising a configured PSM nothing is listening on — the same silent
    /// undialability, reached from the other direction.
    #[tokio::test]
    async fn a_listener_that_failed_to_open_is_retried_on_the_next_resolve() {
        let radio = Arc::new(MockRadio::default()); // listen() reports 0
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(Arc::clone(&slot));

        let (_acceptor, bound) = io.listen(0x0085).await.unwrap();
        assert_eq!(bound, 0x0085, "nothing bound, so the request stands");
        assert_eq!(radio.listen_calls.load(Ordering::Relaxed), 1);

        // The Bluetooth stack comes up; the next resolve gets a real listener.
        radio.listen_psm.store(0x00A1, Ordering::Relaxed);
        let _scanner = io.start_scanning().await.unwrap();

        assert_eq!(radio.listen_calls.load(Ordering::Relaxed), 2, "retried");
        assert_eq!(bridge.local_psm(), 0x00A1);
    }

    /// Opening a listener moves a *live* advertisement onto the bound PSM.
    /// This is the ordering the transport's start sequence actually produces
    /// when a radio is installed in the gap between `listen` and
    /// `start_advertising`, and it is the one the old `AtomicBool` swallowed.
    #[tokio::test]
    async fn opening_a_listener_moves_a_live_advert_onto_the_bound_psm() {
        let radio = MockRadio::with_psm(0x00A1);
        let bridge = AndroidBleBridge::new(Arc::clone(&radio) as Arc<dyn AndroidRadio>);

        bridge.advertise(0x0085);
        assert_eq!(radio.advertised_psm.load(Ordering::Relaxed), 0x0085);

        bridge.open_listener();
        assert_eq!(
            radio.advertised_psm.load(Ordering::Relaxed),
            0x00A1,
            "the live advert follows the listener onto its real PSM",
        );
        assert_eq!(radio.advertise_calls.load(Ordering::Relaxed), 2);
    }

    /// A dial the transport gives up on must not leave its entry behind. The
    /// transport bounds every dial with its own timeout and drops the future
    /// when it fires, so nothing in `connect` runs — the reclamation has to
    /// hang off the drop, or a node that keeps timing out grows the in-flight
    /// map for the life of the process. This is the BLE-side half of the
    /// Android leak: on the embedder's side the same dial is a socket holding
    /// an LE connect slot.
    #[tokio::test]
    async fn a_dial_the_transport_abandons_reclaims_its_in_flight_slot() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);

        let peer = addr(19);
        for _ in 0..50 {
            // A dial that is never answered, dropped the way
            // `tokio::time::timeout` drops one it has given up on.
            let mut dial = Box::pin(io.connect(&peer, 0x0085));
            assert!(futures::poll!(dial.as_mut()).is_pending());
            drop(dial);
        }

        assert_eq!(radio.dials().len(), 50, "every dial reached the radio");
        assert!(
            bridge
                .connects
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_empty(),
            "abandoned dials must not accumulate in the in-flight map",
        );
    }

    /// And an answer that arrives for a dial nobody is waiting on any more is
    /// reported as such rather than silently allocating a channel — otherwise
    /// the embedder would start a reader and writer over a stream the
    /// transport had already written off.
    #[tokio::test]
    async fn answering_an_abandoned_dial_allocates_nothing() {
        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);

        let peer = addr(20);
        let mut dial = Box::pin(io.connect(&peer, 0x0085));
        assert!(futures::poll!(dial.as_mut()).is_pending());
        let connect_id = radio.dials()[0].0;
        drop(dial);

        assert_eq!(
            bridge.deliver_connect_result(connect_id, true, addr(20), 512, 512),
            0,
            "nothing is waiting, so the embedder is told to close its socket",
        );
        assert!(bridge.lock_channels().is_empty());
    }

    /// Replacing a radio re-activates the transport's intent on the new one
    /// and routes new inbound channels there, while a stream opened on the old
    /// radio keeps the radio it was opened on.
    #[tokio::test]
    async fn replacing_a_radio_re_activates_it_and_leaves_live_streams_alone() {
        let first = MockRadio::with_psm(0x00A1);
        let (slot, first_bridge) = slot_with(Arc::clone(&first));
        let io = AndroidIo::new(Arc::clone(&slot));
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();

        let old_ch = first_bridge.deliver_inbound(addr(14), 512, 512);
        let old_stream = acceptor.accept().await.unwrap();

        let second = MockRadio::with_psm(0x00B2);
        let second_bridge = AndroidBleBridge::new(Arc::clone(&second) as Arc<dyn AndroidRadio>);
        slot.install(Arc::clone(&second_bridge));

        let new_ch = loop {
            let ch_id = second_bridge.deliver_inbound(addr(15), 512, 512);
            if ch_id > 0 {
                break ch_id;
            }
            tokio::task::yield_now().await;
        };
        let new_stream = acceptor.accept().await.unwrap();
        assert_eq!(new_stream.remote_addr(), &addr(15));
        assert_eq!(
            second.listen_calls.load(Ordering::Relaxed),
            1,
            "the replacement radio gets its own listener",
        );
        assert_eq!(second_bridge.local_psm(), 0x00B2);

        // The stream opened on the first radio still belongs to it.
        old_stream.send(b"still mine").await.unwrap();
        assert_eq!(
            first_bridge
                .next_send(old_ch, Duration::from_millis(10))
                .as_deref(),
            Some(&b"still mine"[..]),
        );
        assert!(second_bridge.channel_open(new_ch));
        drop(old_stream);
        assert_eq!(first.closed_channels.lock().unwrap().as_slice(), &[old_ch]);
    }

    /// Two nodes in one process each drive their own radio. This is the test a
    /// process-global bridge cannot pass, and the reason the slot is owned by
    /// a node.
    #[tokio::test]
    async fn two_slots_do_not_interfere() {
        let radio_a = MockRadio::with_psm(0x00A1);
        let radio_b = MockRadio::with_psm(0x00B2);
        let (slot_a, bridge_a) = slot_with(Arc::clone(&radio_a));
        let (slot_b, bridge_b) = slot_with(Arc::clone(&radio_b));
        let io_a = AndroidIo::new(slot_a);
        let io_b = AndroidIo::new(slot_b);

        let (mut acceptor_a, bound_a) = io_a.listen(0x0085).await.unwrap();
        let (mut acceptor_b, bound_b) = io_b.listen(0x0085).await.unwrap();
        assert_eq!((bound_a, bound_b), (0x00A1, 0x00B2));

        bridge_a.deliver_inbound(addr(16), 512, 512);
        let stream_a = acceptor_a.accept().await.unwrap();
        assert_eq!(stream_a.remote_addr(), &addr(16));

        bridge_b.deliver_inbound(addr(17), 512, 512);
        let stream_b = acceptor_b.accept().await.unwrap();
        assert_eq!(stream_b.remote_addr(), &addr(17));

        // Neither radio saw the other's traffic.
        assert_eq!(radio_a.listen_calls.load(Ordering::Relaxed), 1);
        assert_eq!(radio_b.listen_calls.load(Ordering::Relaxed), 1);
        drop(stream_a);
        drop(stream_b);
        assert_eq!(radio_a.closed_channels.lock().unwrap().len(), 1);
        assert_eq!(radio_b.closed_channels.lock().unwrap().len(), 1);
    }

    /// This backend is byte-oriented, so it is exactly the case the shared
    /// reframing adapter exists for: a peer's packet arriving in three pieces,
    /// and two packets arriving in one, still read back whole. Composed here
    /// against the real backend rather than against a mock stream, because
    /// this pairing is what a device actually does.
    #[tokio::test]
    async fn fragmented_and_coalesced_deliveries_reassemble() {
        use tokio::io::AsyncReadExt;

        let radio = MockRadio::with_psm(0x0099);
        let (slot, bridge) = slot_with(Arc::clone(&radio));
        let io = AndroidIo::new(slot);
        let (mut acceptor, _) = io.listen(0x0085).await.unwrap();

        let ch_id = bridge.deliver_inbound(addr(18), 512, 512);
        let stream = acceptor.accept().await.unwrap();
        let mut reader = super::super::stream_read::BleStreamRead::new(Arc::new(stream), 512);

        // One logical message split across three deliveries.
        for piece in [&b"abc"[..], b"defg", b"hij"] {
            assert!(bridge.deliver_recv(ch_id, piece));
        }
        let mut whole = [0u8; 10];
        reader.read_exact(&mut whole).await.unwrap();
        assert_eq!(&whole, b"abcdefghij");

        // Two logical messages coalesced into one delivery: the tail is not
        // lost.
        assert!(bridge.deliver_recv(ch_id, b"0123456789"));
        let mut head = [0u8; 4];
        reader.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"0123");
        let mut tail = [0u8; 6];
        reader.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"456789");
    }
}
