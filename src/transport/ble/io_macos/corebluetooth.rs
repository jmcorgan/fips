//! The CoreBluetooth radio: the only part of the macOS backend that speaks
//! Objective-C.
//!
//! [`MacRadio`] owns a `CBCentralManager` (scan, dial) and a
//! `CBPeripheralManager` (listen, advertise, serve the GATT PSM), both
//! delivering their delegate callbacks on one private serial dispatch queue.
//! Every CoreBluetooth call is made on that queue too: commands from the
//! transport arrive through [`Session`] and are re-dispatched onto it. So all
//! CoreBluetooth state lives in one [`QueueState`] that only the queue
//! touches, and no callback ever races another.
//!
//! # Lifecycle
//!
//! Bluetooth being up means both managers report `PoweredOn` and the L2CAP
//! listener has been published (its OS-assigned PSM is what
//! [`BleRadio::listen`] reports). At that point a fresh [`BleRadioBridge`]
//! over a new [`Session`] is installed into the slot, and the transport's
//! slot-followers re-issue listen, advertise and scan against it. When
//! either manager leaves `PoweredOn` the slot is cleared, pending dials fail
//! and open channels are closed; the next power-on installs a new bridge.
//! Sessions are numbered so a command from a bridge that has since been
//! replaced cannot act on the current one.
//!
//! # Channels
//!
//! An open `CBL2CAPChannel`'s streams are opened here and then pumped by
//! [`super::spawn_pumps`] on two threads doing blocking I/O; nothing is
//! scheduled on a run loop. The queue keeps its own reference to each
//! channel and closes its streams when the transport drops the stream or
//! Bluetooth goes down — that close is also what unblocks a reader parked
//! in `read`.

use std::collections::HashMap;
use std::io;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, Instant};

use dispatch2::{DispatchQueue, DispatchQueueAttr, DispatchRetained, DispatchTime};
use objc2::rc::Retained;
use objc2::runtime::{AnyObject, ProtocolObject};
use objc2::{AnyThread, DefinedClass, Message, define_class, msg_send};
use objc2_core_bluetooth::{
    CBAdvertisementDataServiceDataKey, CBAdvertisementDataServiceUUIDsKey, CBAttributePermissions,
    CBCentralManager, CBCentralManagerDelegate, CBCentralManagerScanOptionAllowDuplicatesKey,
    CBCharacteristic, CBCharacteristicProperties, CBL2CAPChannel, CBL2CAPPSM, CBManagerState,
    CBMutableCharacteristic, CBMutableService, CBPeer, CBPeripheral, CBPeripheralDelegate,
    CBPeripheralManager, CBPeripheralManagerDelegate, CBPeripheralState, CBService, CBUUID,
};
use objc2_foundation::{
    NSArray, NSData, NSDictionary, NSError, NSInputStream, NSNumber, NSObject, NSObjectProtocol,
    NSOutputStream, NSString,
};
use tracing::{debug, info, trace, warn};

use super::super::addr::BleAddr;
use super::super::io_radio::{BleRadio, BleRadioBridge, BleRadioSlot};
use super::super::psm;
use super::{
    ADVERT_REPORT_INTERVAL, AdvertThrottle, ChannelRead, ChannelWrite, DialPlan, DialStep,
    FIPS_SERVICE_UUID, is_psm_service_data_key, parse_uuid, peer_addr, spawn_pumps,
};

/// How long a dial may sit unanswered before the radio gives up on it.
///
/// CoreBluetooth never times out a `connectPeripheral` on its own: a pending
/// connection to a peer that has gone away waits forever, holding one of the
/// controller's few connection slots. The transport bounds its own wait far
/// sooner and moves on; this bounds the radio's.
const DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Peers beyond this prompt a sweep of ones not heard from in
/// [`PEER_FORGET_AFTER`].
const PEER_SWEEP_THRESHOLD: usize = 256;

/// How long a peer that has stopped advertising is remembered for dialling.
const PEER_FORGET_AFTER: Duration = Duration::from_secs(600);

/// RSSI CoreBluetooth reports when it has no reading.
const RSSI_UNAVAILABLE: i16 = 127;

/// Map a Foundation error onto an `io::Error`.
fn ns_err(context: &str, error: Option<&NSError>) -> io::Error {
    match error {
        Some(e) => io::Error::other(format!("{context}: {}", e.localizedDescription())),
        None => io::Error::other(context.to_string()),
    }
}

// ============================================================================
// MacRadio
// ============================================================================

/// The in-process CoreBluetooth radio.
///
/// Keeps `slot` holding a bridge whenever Bluetooth is up. Owned by the
/// transport's backend (see `RadioIo::with_owner`), so it lives exactly as
/// long as the transport, across any number of Bluetooth toggles.
pub struct MacRadio {
    shared: Arc<Shared>,
}

impl MacRadio {
    /// Bring up CoreBluetooth and start feeding `slot`.
    ///
    /// Returns at once. Bluetooth may come up later, or never — no permission,
    /// no adapter, switched off — in which case the slot stays empty and the
    /// transport idles exactly as it would on Android with no radio armed.
    pub fn start(slot: Arc<BleRadioSlot>, mtu: u16) -> Arc<Self> {
        Self::start_with(slot, mtu, None)
    }

    /// As [`Self::start`], calling `on_denied` once if CoreBluetooth refuses
    /// this process — which it always does to a root launchd daemon.
    pub fn start_with(
        slot: Arc<BleRadioSlot>,
        mtu: u16,
        on_denied: Option<Box<dyn FnOnce() + Send>>,
    ) -> Arc<Self> {
        let shared = Arc::new(Shared {
            queue: DispatchQueue::new("com.fips.ble", DispatchQueueAttr::SERIAL),
            slot,
            mtu,
            psm: AtomicU16::new(0),
            on_denied: Mutex::new(on_denied),
            state: Mutex::new(QueueState::default()),
        });
        let weak = Arc::downgrade(&shared);
        Shared::on_queue(&shared, move |_, st| {
            // SAFETY: on the queue, which is where these objects live.
            unsafe { st.init(weak) };
        });
        Arc::new(Self { shared })
    }
}

impl MacRadio {
    /// The PSM the L2CAP listener was published on, or 0 if it has none.
    pub fn listener_psm(&self) -> u16 {
        self.shared.psm.load(Ordering::Relaxed)
    }
}

impl Drop for MacRadio {
    /// Stops advertising and scanning and closes every channel, so a stopped
    /// transport leaves nothing on the air. CoreBluetooth's own objects are
    /// released on the queue once this last closure has run.
    fn drop(&mut self) {
        Shared::on_queue(&self.shared, |shared, st| {
            if let Some(manager) = &st.manager {
                unsafe {
                    manager.stopAdvertising();
                    manager.removeAllServices();
                    if let Some(psm) = st.published.filter(|&p| p != 0) {
                        manager.unpublishL2CAPChannel(psm);
                    }
                }
            }
            if let Some(central) = &st.central {
                unsafe { central.stopScan() };
            }
            shared.go_down(st);
            *st = QueueState::default();
        });
    }
}

/// The macOS BLE radio for the daemon: CoreBluetooth in process, or, when
/// CoreBluetooth refuses the process, the fips BLE agent over
/// `agent_socket`. Both feed the same `slot`; only one ever does.
///
/// The returned owner keeps whichever is running alive; hand it to
/// `RadioIo::with_owner`. Must be called inside a tokio runtime, which the
/// agent listener binds through.
pub fn start_daemon_radio(
    slot: Arc<BleRadioSlot>,
    mtu: u16,
    agent_socket: std::path::PathBuf,
) -> Arc<dyn std::any::Any + Send + Sync> {
    let agent: Arc<std::sync::OnceLock<Arc<super::agent_server::AgentServer>>> = Arc::default();
    let handle = tokio::runtime::Handle::current();
    let fallback = {
        let slot = Arc::clone(&slot);
        let agent = Arc::clone(&agent);
        Box::new(move || {
            let _runtime = handle.enter();
            match super::agent_server::AgentServer::start(slot, &agent_socket) {
                Ok(server) => {
                    let _ = agent.set(server);
                }
                Err(e) => warn!(
                    path = %agent_socket.display(),
                    error = %e,
                    "BLE: could not listen for the fips BLE agent"
                ),
            }
        })
    };
    let radio = MacRadio::start_with(slot, mtu, Some(fallback));
    Arc::new((radio, agent))
}

/// Run the BLE agent: CoreBluetooth in this login session, lent to the
/// daemon listening at `socket`, or at the default agent socket path —
/// resolved afresh on every attempt — when it is `None`. Runs until the
/// process is killed.
pub async fn run_agent(socket: Option<std::path::PathBuf>) -> io::Result<()> {
    let slot = Arc::new(BleRadioSlot::new());
    let radio = MacRadio::start(Arc::clone(&slot), crate::config::BleConfig::default().mtu());
    // Up is a bridge in the slot, which `MacRadio` installs only once the
    // listener's publish has completed, so its PSM is then final.
    let radio_psm = {
        let slot = Arc::clone(&slot);
        let radio = Arc::clone(&radio);
        move || slot.is_installed().then(|| radio.listener_psm())
    };
    let io = Arc::new(super::super::io_radio::RadioIo::with_owner(slot, radio));
    let socket = move || socket.clone().unwrap_or_else(super::agent_socket_path);
    super::agent::run(io, socket, super::super::DEFAULT_PSM, radio_psm).await
}

// ============================================================================
// Shared state
// ============================================================================

struct Shared {
    queue: DispatchRetained<DispatchQueue>,
    slot: Arc<BleRadioSlot>,
    mtu: u16,
    /// The published listener PSM, or 0. An atomic rather than queue state
    /// because [`BleRadio::listen`] is synchronous and is called from the
    /// transport, not from the queue.
    psm: AtomicU16,
    /// Called once, the first time CoreBluetooth reports `Unauthorized`.
    on_denied: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    state: Mutex<QueueState>,
}

impl Shared {
    /// Run `f` on the queue with the queue state.
    fn on_queue(this: &Arc<Self>, f: impl FnOnce(&Shared, &mut QueueState) + Send + 'static) {
        let shared = Arc::clone(this);
        this.queue.exec_async(move || {
            let mut st = shared.lock();
            f(&shared, &mut st);
        });
    }

    fn lock(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// CoreBluetooth refused this process; run the fallback, once.
    fn denied(&self) {
        let hook = self
            .on_denied
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some(hook) = hook {
            hook();
        }
    }

    /// The bridge for session `generation`, if that is still the live one.
    fn session(st: &QueueState, generation: u64) -> Option<Arc<BleRadioBridge>> {
        st.session
            .as_ref()
            .filter(|_| st.generation == generation)
            .cloned()
    }

    // --- power -----------------------------------------------------------

    /// Re-evaluate whether Bluetooth is up after either manager changed state.
    fn power_changed(&self, st: &mut QueueState, weak: &Weak<Shared>) {
        if !st.manager_on {
            // Publications and services do not survive the peripheral
            // manager powering off.
            st.published = None;
            st.publishing = false;
            st.service = None;
            self.psm.store(0, Ordering::Relaxed);
        } else if st.published.is_none()
            && !st.publishing
            && let Some(manager) = &st.manager
        {
            debug!("BLE: publishing L2CAP listener");
            st.publishing = true;
            unsafe { manager.publishL2CAPChannelWithEncryption(false) };
        }

        let up = st.central_on && st.manager_on && st.published.is_some();
        if up && st.session.is_none() {
            st.generation += 1;
            let bridge = BleRadioBridge::new(Arc::new(Session {
                shared: weak.clone(),
                generation: st.generation,
            }));
            st.session = Some(Arc::clone(&bridge));
            info!(
                psm = self.psm.load(Ordering::Relaxed),
                "BLE: CoreBluetooth radio up"
            );
            self.slot.install(bridge);
        } else if !up && st.session.is_some() {
            info!("BLE: CoreBluetooth radio down");
            self.go_down(st);
        }
    }

    /// Withdraw the session: empty the slot, fail pending dials, close every
    /// channel and forget every peer, whose peripheral objects are dead now.
    fn go_down(&self, st: &mut QueueState) {
        if st.session.take().is_some() {
            self.slot.clear();
        }
        for (addr, dial) in st.dials.drain() {
            dial.fail(&addr);
        }
        for (_, channel) in st.channels.drain() {
            channel.close();
        }
        st.peers.clear();
        st.throttle = None;
    }

    /// The listener was published, or failed to be.
    fn published(
        &self,
        st: &mut QueueState,
        weak: &Weak<Shared>,
        psm: u16,
        error: Option<&NSError>,
    ) {
        st.publishing = false;
        match error {
            Some(e) => {
                // Still come up: scanning and dialling work without a
                // listener, and `listen` reporting 0 tells the bridge so.
                warn!(error = %ns_err("publish", Some(e)), "BLE: no L2CAP listener");
                st.published = Some(0);
            }
            None => {
                debug!(psm, "BLE: L2CAP listener published");
                st.published = Some(psm);
                self.psm.store(psm, Ordering::Relaxed);
                // SAFETY: on the queue.
                unsafe { st.serve_psm(psm) };
            }
        }
        self.power_changed(st, weak);
    }

    // --- scanning --------------------------------------------------------

    fn discovered(
        &self,
        st: &mut QueueState,
        peripheral: &CBPeripheral,
        adv: &NSDictionary<NSString, AnyObject>,
        rssi: &NSNumber,
    ) {
        let Some(bridge) = st.session.clone() else {
            return;
        };
        let addr = addr_of(peripheral);
        let advertised = advertised_psm(adv);
        let now = Instant::now();
        if st.peers.len() >= PEER_SWEEP_THRESHOLD {
            // Address rotation mints a new identifier, and so a new entry, per
            // rotation; forget the ones that have gone quiet.
            st.peers
                .retain(|_, peer| now.saturating_duration_since(peer.seen) < PEER_FORGET_AFTER);
        }
        st.peers.insert(
            addr.clone(),
            Peer {
                peripheral: peripheral.retain(),
                advertised_psm: advertised,
                seen: now,
            },
        );
        let throttle = st
            .throttle
            .get_or_insert_with(|| AdvertThrottle::new(ADVERT_REPORT_INTERVAL));
        if throttle.admit(&addr, advertised, now) {
            let rssi = rssi.shortValue();
            trace!(addr = %addr, psm = ?advertised, rssi, "BLE: FIPS advert");
            bridge.deliver_scan(
                addr,
                advertised.unwrap_or(0),
                (rssi != RSSI_UNAVAILABLE).then_some(rssi),
            );
        }
    }

    // --- dialling --------------------------------------------------------

    fn dial(
        this: &Arc<Shared>,
        st: &mut QueueState,
        generation: u64,
        connect_id: i64,
        addr: BleAddr,
        psm: u16,
    ) {
        let Some(bridge) = Self::session(st, generation) else {
            // A dial from a replaced bridge has no one left to answer.
            return;
        };
        let mut dial = PendingDial {
            connect_id,
            plan: DialPlan::new(psm, None),
            generation,
            bridge,
            peripheral: None,
        };
        let Some(peer) = st.peers.get(&addr) else {
            debug!(addr = %addr, "BLE: dial to a peer this Mac has not scanned");
            dial.fail(&addr);
            return;
        };
        let peripheral = peer.peripheral.clone();
        dial.plan = DialPlan::new(psm, peer.advertised_psm);
        dial.peripheral = Some(peripheral.clone());
        let (Some(central), Some(delegate)) = (st.central.clone(), st.peripheral_delegate.clone())
        else {
            dial.fail(&addr);
            return;
        };
        let plan = dial.plan;
        if let Some(stale) = st.dials.insert(addr.clone(), dial) {
            // The transport only re-dials a peer once it has given up on the
            // last attempt, so this one is already abandoned.
            stale.fail(&addr);
        }
        debug!(addr = %addr, psm, "BLE: dialling");
        unsafe {
            peripheral.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
            if peripheral.state() == CBPeripheralState::Connected {
                st.step(&addr, plan.on_connected());
            } else {
                central.connectPeripheral_options(&peripheral, None);
            }
        }

        let weak = Arc::downgrade(this);
        let when = DispatchTime::try_from(DIAL_TIMEOUT).unwrap_or(DispatchTime::FOREVER);
        let _ = this.queue.after(when, move || {
            let Some(shared) = weak.upgrade() else { return };
            let mut st = shared.lock();
            if st
                .dials
                .get(&addr)
                .is_some_and(|d| d.connect_id == connect_id)
            {
                debug!(addr = %addr, "BLE: dial timed out");
                st.abandon_dial(&addr);
            }
        });
    }

    fn connected(&self, st: &mut QueueState, peripheral: &CBPeripheral) {
        let addr = addr_of(peripheral);
        match st.dials.get(&addr) {
            Some(dial) => {
                let step = dial.plan.on_connected();
                st.step(&addr, step);
            }
            // Connected after the dial was abandoned; let it go again.
            None => st.release_if_idle(&addr, peripheral),
        }
    }

    fn connect_failed(
        &self,
        st: &mut QueueState,
        peripheral: &CBPeripheral,
        error: Option<&NSError>,
    ) {
        let addr = addr_of(peripheral);
        if let Some(dial) = st.dials.remove(&addr) {
            debug!(addr = %addr, error = %ns_err("connect", error), "BLE: dial failed");
            dial.fail(&addr);
        }
    }

    fn services_discovered(
        &self,
        st: &mut QueueState,
        peripheral: &CBPeripheral,
        error: Option<&NSError>,
    ) {
        let addr = addr_of(peripheral);
        let Some(dial) = st.dials.get(&addr) else {
            return;
        };
        let found = error.is_none() && st.fips_service(peripheral).is_some();
        let step = dial.plan.on_service(found);
        st.step(&addr, step);
    }

    fn characteristics_discovered(
        &self,
        st: &mut QueueState,
        peripheral: &CBPeripheral,
        service: &CBService,
        error: Option<&NSError>,
    ) {
        let addr = addr_of(peripheral);
        let Some(dial) = st.dials.get(&addr) else {
            return;
        };
        let found = error.is_none() && st.psm_characteristic(service).is_some();
        let step = dial.plan.on_characteristic(found);
        st.step(&addr, step);
    }

    fn value_read(
        &self,
        st: &mut QueueState,
        peripheral: &CBPeripheral,
        characteristic: &CBCharacteristic,
        error: Option<&NSError>,
    ) {
        let addr = addr_of(peripheral);
        let Some(dial) = st.dials.get(&addr) else {
            return;
        };
        let value = match error {
            None => unsafe { characteristic.value() }.map(|d| d.to_vec()),
            Some(_) => None,
        };
        let step = dial.plan.on_psm_read(value.as_deref());
        debug!(addr = %addr, ?step, "BLE: read PSM over GATT");
        st.step(&addr, step);
    }

    fn outbound_opened(
        &self,
        st: &mut QueueState,
        peripheral: &CBPeripheral,
        channel: Option<&CBL2CAPChannel>,
        error: Option<&NSError>,
    ) {
        let addr = addr_of(peripheral);
        let Some(dial) = st.dials.remove(&addr) else {
            // Opened after the dial was abandoned: nobody wants it.
            if let Some(channel) = channel {
                close_channel_streams(channel);
            }
            st.release_if_idle(&addr, peripheral);
            return;
        };
        let channel = match (channel, error) {
            (Some(channel), None) => channel.retain(),
            (_, error) => {
                debug!(addr = %addr, error = %ns_err("open L2CAP", error), "BLE: dial failed");
                dial.fail(&addr);
                st.release_if_idle(&addr, peripheral);
                return;
            }
        };
        let mtu = self.mtu;
        let attached = st.attach(
            &dial.bridge,
            dial.generation,
            channel,
            Some(addr.clone()),
            mtu,
            |bridge| bridge.deliver_connect_result(dial.connect_id, true, addr.clone(), mtu, mtu),
        );
        if attached {
            debug!(addr = %addr, "BLE: outbound L2CAP channel open");
        } else {
            st.release_if_idle(&addr, peripheral);
        }
    }

    fn disconnected(
        &self,
        st: &mut QueueState,
        peripheral: &CBPeripheral,
        error: Option<&NSError>,
    ) {
        let addr = addr_of(peripheral);
        if let Some(dial) = st.dials.remove(&addr) {
            debug!(addr = %addr, error = %ns_err("disconnected", error), "BLE: dial failed");
            dial.fail(&addr);
        }
        // Open channels to this peer end on their own: their streams report
        // end of stream to the readers.
    }

    // --- listening -------------------------------------------------------

    fn inbound_opened(
        &self,
        st: &mut QueueState,
        channel: Option<&CBL2CAPChannel>,
        error: Option<&NSError>,
    ) {
        let channel = match (channel, error) {
            (Some(channel), None) => channel.retain(),
            (_, error) => {
                debug!(error = %ns_err("accept", error), "BLE: inbound L2CAP channel failed");
                return;
            }
        };
        let Some(bridge) = st.session.clone() else {
            close_channel_streams(&channel);
            return;
        };
        let Some(peer) = (unsafe { channel.peer() }) else {
            close_channel_streams(&channel);
            return;
        };
        let addr = addr_of(&peer);
        let mtu = self.mtu;
        let generation = st.generation;
        if st.attach(&bridge, generation, channel, None, mtu, |bridge| {
            bridge.deliver_inbound(addr.clone(), mtu, mtu)
        }) {
            debug!(addr = %addr, "BLE: inbound L2CAP channel open");
        }
    }

    // --- transport commands ----------------------------------------------

    fn start_advertising(&self, st: &mut QueueState) {
        let (Some(manager), Some(uuid)) = (&st.manager, &st.service_uuid) else {
            return;
        };
        unsafe {
            if manager.isAdvertising() {
                return;
            }
            // The legacy UUID-only advert: CoreBluetooth can carry no service
            // data, so the PSM is served over GATT instead (see `psm`).
            let uuids = NSArray::from_slice(&[&**uuid]);
            let uuids: &AnyObject = &uuids;
            let adv = NSDictionary::from_slices(&[CBAdvertisementDataServiceUUIDsKey], &[uuids]);
            manager.startAdvertising(Some(&adv));
        }
        debug!("BLE: advertising");
    }

    fn stop_advertising(&self, st: &mut QueueState) {
        if let Some(manager) = &st.manager {
            unsafe { manager.stopAdvertising() };
        }
    }

    fn start_scanning(&self, st: &mut QueueState) {
        let (Some(central), Some(uuid)) = (&st.central, &st.service_uuid) else {
            return;
        };
        unsafe {
            // Duplicates allowed, so a peer that restarts on a new PSM is
            // heard; `AdvertThrottle` keeps the rate down.
            let yes = NSNumber::new_bool(true);
            let yes: &AnyObject = &yes;
            let options =
                NSDictionary::from_slices(&[CBCentralManagerScanOptionAllowDuplicatesKey], &[yes]);
            let uuids = NSArray::from_slice(&[&**uuid]);
            central.scanForPeripheralsWithServices_options(Some(&uuids), Some(&options));
        }
        debug!("BLE: scanning");
    }

    fn stop_scanning(&self, st: &mut QueueState) {
        if let Some(central) = &st.central {
            unsafe { central.stopScan() };
        }
    }

    fn close_channel(&self, st: &mut QueueState, generation: u64, ch_id: i64) {
        let Some(channel) = st.channels.remove(&(generation, ch_id)) else {
            return;
        };
        channel.close();
        if let Some(addr) = &channel.outbound_to
            && let Some(peer) = st.peers.get(addr)
        {
            let peripheral = peer.peripheral.clone();
            st.release_if_idle(addr, &peripheral);
        }
    }
}

/// Log a manager state change, loudly when it keeps Bluetooth down.
///
/// The transport reports itself started either way and simply never peers,
/// so this line is the only place a node says why its BLE is idle.
fn report_state(manager: &str, state: CBManagerState) {
    match state {
        CBManagerState::PoweredOn => debug!(manager, "BLE: CoreBluetooth powered on"),
        CBManagerState::Unauthorized => warn!(
            manager,
            "BLE: CoreBluetooth access denied to this process. A launchd daemon \
             never gets it; the radio must come from the fips BLE agent in a \
             login session (or run fips from a terminal with Bluetooth permission)"
        ),
        CBManagerState::PoweredOff => info!(manager, "BLE: Bluetooth is off"),
        CBManagerState::Unsupported => warn!(manager, "BLE: Bluetooth LE unsupported on this Mac"),
        CBManagerState::Resetting => info!(manager, "BLE: Bluetooth resetting"),
        _ => debug!(manager, state = state.0, "BLE: CoreBluetooth state unknown"),
    }
}

/// The link address for a CoreBluetooth peer.
///
/// Goes through the identifier's string form: `NSUUID::as_bytes` in
/// objc2-foundation 0.3 sends `getUUIDBytes:` with an argument encoding the
/// runtime's debug check rejects, which panics inside a delegate callback and
/// aborts the process.
fn addr_of(peer: &CBPeer) -> BleAddr {
    let id = unsafe { peer.identifier() }.UUIDString().to_string();
    peer_addr(parse_uuid(&id).unwrap_or_else(|| {
        warn!(id, "BLE: unparseable peer identifier");
        [0; 16]
    }))
}

/// The PSM a scanned advert carries in its service data, if any.
fn advertised_psm(adv: &NSDictionary<NSString, AnyObject>) -> Option<u16> {
    let data = adv.objectForKey(unsafe { CBAdvertisementDataServiceDataKey })?;
    let data = data.downcast_ref::<NSDictionary>()?;
    data.allKeys().iter().find_map(|key| {
        let uuid = key.downcast_ref::<CBUUID>()?;
        if !is_psm_service_data_key(&unsafe { uuid.data() }.to_vec()) {
            return None;
        }
        let value = data.objectForKey(&key)?;
        psm::decode_psm(&value.downcast_ref::<NSData>()?.to_vec())
    })
}

/// Close both streams of a channel nobody is going to use.
fn close_channel_streams(channel: &CBL2CAPChannel) {
    unsafe {
        if let Some(input) = channel.inputStream() {
            input.close();
        }
        if let Some(output) = channel.outputStream() {
            output.close();
        }
    }
}

// ============================================================================
// Queue state
// ============================================================================

/// A peer seen in a scan.
struct Peer {
    peripheral: Retained<CBPeripheral>,
    advertised_psm: Option<u16>,
    seen: Instant,
}

/// A dial in progress.
struct PendingDial {
    connect_id: i64,
    plan: DialPlan,
    generation: u64,
    bridge: Arc<BleRadioBridge>,
    /// `None` only for a dial that failed before it started.
    peripheral: Option<Retained<CBPeripheral>>,
}

impl PendingDial {
    fn fail(self, addr: &BleAddr) {
        self.bridge
            .deliver_connect_result(self.connect_id, false, addr.clone(), 0, 0);
    }
}

/// An L2CAP channel handed to the transport.
struct OpenChannel {
    /// Held so the channel lives as long as the transport's stream does.
    _channel: Retained<CBL2CAPChannel>,
    input: Retained<NSInputStream>,
    output: Retained<NSOutputStream>,
    /// The peer, when this side dialled it and so owns the connection.
    outbound_to: Option<BleAddr>,
}

impl OpenChannel {
    fn close(&self) {
        // Closing from the queue is what wakes a reader blocked in `read`.
        self.input.close();
        self.output.close();
    }
}

/// Everything CoreBluetooth, touched only on the queue.
#[derive(Default)]
struct QueueState {
    central: Option<Retained<CBCentralManager>>,
    manager: Option<Retained<CBPeripheralManager>>,
    central_delegate: Option<Retained<CentralDelegate>>,
    manager_delegate: Option<Retained<ManagerDelegate>>,
    peripheral_delegate: Option<Retained<PeripheralDelegate>>,
    service_uuid: Option<Retained<CBUUID>>,
    psm_char_uuid: Option<Retained<CBUUID>>,
    central_on: bool,
    manager_on: bool,
    publishing: bool,
    /// `None` until the listener publish completes; `Some(0)` if it failed.
    published: Option<CBL2CAPPSM>,
    service: Option<Retained<CBMutableService>>,
    /// The live bridge, while Bluetooth is up.
    session: Option<Arc<BleRadioBridge>>,
    generation: u64,
    peers: HashMap<BleAddr, Peer>,
    throttle: Option<AdvertThrottle>,
    dials: HashMap<BleAddr, PendingDial>,
    channels: HashMap<(u64, i64), OpenChannel>,
}

// SAFETY: the CoreBluetooth objects in here are only ever used on the radio's
// serial queue. The `Send` is what lets the state sit behind the `Mutex` in
// `Shared` that the queue's closures and callbacks reach it through; the
// mutex is never contended, because the queue is serial.
unsafe impl Send for QueueState {}

impl QueueState {
    /// Create the managers and their delegates.
    ///
    /// # Safety
    /// Must run on the radio's queue.
    unsafe fn init(&mut self, shared: Weak<Shared>) {
        let Some(strong) = shared.upgrade() else {
            return;
        };
        let queue = &strong.queue;
        unsafe {
            self.service_uuid = Some(CBUUID::UUIDWithString(&NSString::from_str(
                FIPS_SERVICE_UUID,
            )));
            self.psm_char_uuid = Some(CBUUID::UUIDWithString(&NSString::from_str(
                psm::L2CAP_PSM_CHARACTERISTIC_UUID,
            )));
            let central_delegate = CentralDelegate::new(shared.clone());
            let manager_delegate = ManagerDelegate::new(shared.clone());
            self.peripheral_delegate = Some(PeripheralDelegate::new(shared.clone()));
            self.central = Some(CBCentralManager::initWithDelegate_queue(
                CBCentralManager::alloc(),
                Some(ProtocolObject::from_ref(&*central_delegate)),
                Some(queue),
            ));
            self.manager = Some(CBPeripheralManager::initWithDelegate_queue(
                CBPeripheralManager::alloc(),
                Some(ProtocolObject::from_ref(&*manager_delegate)),
                Some(queue),
            ));
            // The managers hold their delegates weakly.
            self.central_delegate = Some(central_delegate);
            self.manager_delegate = Some(manager_delegate);
        }
        debug!("BLE: CoreBluetooth managers created");
    }

    /// Serve `psm` from the GATT PSM characteristic, replacing any previous
    /// value. See the GATT section of [`super::super::psm`].
    ///
    /// # Safety
    /// Must run on the radio's queue.
    unsafe fn serve_psm(&mut self, psm: u16) {
        let (Some(manager), Some(service_uuid), Some(char_uuid)) =
            (&self.manager, &self.service_uuid, &self.psm_char_uuid)
        else {
            return;
        };
        unsafe {
            if let Some(old) = self.service.take() {
                manager.removeService(&old);
            }
            // A static value: CoreBluetooth answers reads itself, with no
            // read-request round trip through the delegate.
            let value = NSData::with_bytes(&psm::encode_psm(psm));
            let characteristic = CBMutableCharacteristic::initWithType_properties_value_permissions(
                CBMutableCharacteristic::alloc(),
                char_uuid,
                CBCharacteristicProperties::Read,
                Some(&value),
                CBAttributePermissions::Readable,
            );
            let service = CBMutableService::initWithType_primary(
                CBMutableService::alloc(),
                service_uuid,
                true,
            );
            let characteristic: Retained<CBCharacteristic> = Retained::into_super(characteristic);
            service.setCharacteristics(Some(&NSArray::from_retained_slice(&[characteristic])));
            manager.addService(&service);
            self.service = Some(service);
        }
    }

    /// The FIPS service among a peripheral's discovered services.
    fn fips_service(&self, peripheral: &CBPeripheral) -> Option<Retained<CBService>> {
        let wanted: &AnyObject = self.service_uuid.as_ref()?;
        unsafe { peripheral.services() }?
            .iter()
            .find(|s| unsafe { s.UUID() }.isEqual(Some(wanted)))
    }

    /// The PSM characteristic among a service's discovered characteristics.
    fn psm_characteristic(&self, service: &CBService) -> Option<Retained<CBCharacteristic>> {
        let wanted: &AnyObject = self.psm_char_uuid.as_ref()?;
        unsafe { service.characteristics() }?
            .iter()
            .find(|c| unsafe { c.UUID() }.isEqual(Some(wanted)))
    }

    /// Take the dial to `addr` one step further.
    fn step(&self, addr: &BleAddr, step: DialStep) {
        let Some(peripheral) = self.dials.get(addr).and_then(|d| d.peripheral.clone()) else {
            return;
        };
        let requested = self.dials[addr].plan.requested();
        trace!(addr = %addr, ?step, "BLE: dial step");
        unsafe {
            match step {
                DialStep::DiscoverService => {
                    let Some(uuid) = &self.service_uuid else {
                        return;
                    };
                    peripheral.discoverServices(Some(&NSArray::from_slice(&[&**uuid])));
                }
                DialStep::DiscoverCharacteristic => match self.fips_service(&peripheral) {
                    Some(service) => {
                        let Some(uuid) = &self.psm_char_uuid else {
                            return;
                        };
                        peripheral.discoverCharacteristics_forService(
                            Some(&NSArray::from_slice(&[&**uuid])),
                            &service,
                        );
                    }
                    None => peripheral.openL2CAPChannel(requested),
                },
                DialStep::ReadPsm => {
                    match self
                        .fips_service(&peripheral)
                        .and_then(|s| self.psm_characteristic(&s))
                    {
                        Some(characteristic) => {
                            peripheral.readValueForCharacteristic(&characteristic)
                        }
                        None => peripheral.openL2CAPChannel(requested),
                    }
                }
                DialStep::Open(psm) => peripheral.openL2CAPChannel(psm),
            }
        }
    }

    /// Give up on the dial to `addr` and drop its connection.
    fn abandon_dial(&mut self, addr: &BleAddr) {
        if let Some(dial) = self.dials.remove(addr) {
            if let Some(peripheral) = dial.peripheral.clone() {
                self.release_if_idle(addr, &peripheral);
            }
            dial.fail(addr);
        }
    }

    /// Drop this side's connection to `addr` unless a dial or an open
    /// outbound channel still needs it. Connections are a scarce controller
    /// resource, and CoreBluetooth keeps one up as long as anyone asked for
    /// it.
    fn release_if_idle(&self, addr: &BleAddr, peripheral: &CBPeripheral) {
        let in_use = self.dials.contains_key(addr)
            || self
                .channels
                .values()
                .any(|c| c.outbound_to.as_ref() == Some(addr));
        if !in_use && let Some(central) = &self.central {
            unsafe { central.cancelPeripheralConnection(peripheral) };
        }
    }

    /// Open `channel`'s streams, register it with `bridge` through
    /// `register`, and start its pumps. Returns whether it was taken.
    fn attach(
        &mut self,
        bridge: &Arc<BleRadioBridge>,
        generation: u64,
        channel: Retained<CBL2CAPChannel>,
        outbound_to: Option<BleAddr>,
        mtu: u16,
        register: impl FnOnce(&BleRadioBridge) -> i64,
    ) -> bool {
        let (Some(input), Some(output)) = (unsafe { channel.inputStream() }, unsafe {
            channel.outputStream()
        }) else {
            close_channel_streams(&channel);
            return false;
        };
        // Opened unscheduled: no run loop, so reads and writes are
        // synchronous and the pump threads block in them.
        input.open();
        output.open();
        let ch_id = register(bridge);
        let open = OpenChannel {
            _channel: channel,
            input: input.clone(),
            output: output.clone(),
            outbound_to,
        };
        if ch_id == 0 {
            // The transport is not accepting, or gave up on this dial.
            open.close();
            return false;
        }
        if let Err(e) = spawn_pumps(
            Arc::clone(bridge),
            ch_id,
            StreamReader(input),
            StreamWriter(output),
            mtu as usize,
        ) {
            warn!(error = %e, "BLE: could not start channel threads");
            open.close();
            bridge.channel_closed(ch_id);
            return false;
        }
        self.channels.insert((generation, ch_id), open);
        true
    }
}

// ============================================================================
// Session — the BleRadio a bridge drives
// ============================================================================

/// One power-on's worth of radio, as seen by the bridge built over it.
struct Session {
    shared: Weak<Shared>,
    generation: u64,
}

impl Session {
    fn on_queue(&self, f: impl FnOnce(&Arc<Shared>, &mut QueueState, u64) + Send + 'static) {
        let Some(shared) = self.shared.upgrade() else {
            return;
        };
        let generation = self.generation;
        let target = Arc::clone(&shared);
        shared.queue.exec_async(move || {
            let mut st = target.lock();
            f(&target, &mut st, generation);
        });
    }

    /// Like [`Self::on_queue`], but only while this session is the live one.
    fn on_live_queue(&self, f: impl FnOnce(&Shared, &mut QueueState) + Send + 'static) {
        self.on_queue(move |shared, st, generation| {
            if Shared::session(st, generation).is_some() {
                f(shared, st);
            }
        });
    }
}

impl BleRadio for Session {
    /// The listener is published before a session exists, so its PSM is
    /// already known; 0 if publishing failed.
    fn listen(&self) -> u16 {
        self.shared
            .upgrade()
            .map(|s| s.psm.load(Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn connect(&self, connect_id: i64, addr: &BleAddr, psm: u16) {
        let addr = addr.clone();
        self.on_queue(move |shared, st, generation| {
            Shared::dial(shared, st, generation, connect_id, addr, psm);
        });
    }

    /// `psm` is ignored: a Mac cannot advertise it, and serves its own over
    /// GATT instead.
    fn start_advertising(&self, _psm: u16) {
        self.on_live_queue(|shared, st| shared.start_advertising(st));
    }

    fn stop_advertising(&self) {
        self.on_live_queue(|shared, st| shared.stop_advertising(st));
    }

    fn start_scanning(&self) {
        self.on_live_queue(|shared, st| shared.start_scanning(st));
    }

    fn stop_scanning(&self) {
        self.on_live_queue(|shared, st| shared.stop_scanning(st));
    }

    fn close_channel(&self, ch_id: i64) {
        self.on_queue(move |shared, st, generation| shared.close_channel(st, generation, ch_id));
    }
}

// ============================================================================
// Streams
// ============================================================================

/// A channel's input stream, read on its pump thread.
struct StreamReader(Retained<NSInputStream>);

// SAFETY: after the queue opens it, the input stream is read only on its pump
// thread. The queue's one other use of it is `close`, which is what ends a
// blocked read.
unsafe impl Send for StreamReader {}

impl ChannelRead for StreamReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let ptr = NonNull::new(buf.as_mut_ptr()).ok_or_else(|| io::Error::other("empty buffer"))?;
        match unsafe { self.0.read_maxLength(ptr, buf.len()) } {
            n if n >= 0 => Ok(n as usize),
            _ => Err(ns_err("read", self.0.streamError().as_deref())),
        }
    }
}

/// A channel's output stream, written on its pump thread.
struct StreamWriter(Retained<NSOutputStream>);

// SAFETY: as for `StreamReader`, with the writer pump as the one user.
unsafe impl Send for StreamWriter {}

impl ChannelWrite for StreamWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let ptr = NonNull::new(data.as_ptr().cast_mut())
            .ok_or_else(|| io::Error::other("empty write"))?;
        match unsafe { self.0.write_maxLength(ptr, data.len()) } {
            n if n >= 0 => Ok(n as usize),
            _ => Err(ns_err("write", self.0.streamError().as_deref())),
        }
    }
}

// ============================================================================
// Delegates
// ============================================================================

/// Run `f` against the radio's state from a delegate callback, which
/// CoreBluetooth delivers on the radio's queue.
fn with_state(shared: &Weak<Shared>, f: impl FnOnce(&Arc<Shared>, &mut QueueState)) {
    if let Some(shared) = shared.upgrade() {
        let mut st = shared.lock();
        f(&shared, &mut st);
    }
}

define_class!(
    #[unsafe(super(NSObject))]
    #[ivars = Weak<Shared>]
    struct CentralDelegate;

    unsafe impl NSObjectProtocol for CentralDelegate {}

    unsafe impl CBCentralManagerDelegate for CentralDelegate {
        #[unsafe(method(centralManagerDidUpdateState:))]
        fn did_update_state(&self, central: &CBCentralManager) {
            let weak = self.ivars().clone();
            with_state(self.ivars(), |shared, st| {
                let state = unsafe { central.state() };
                st.central_on = state == CBManagerState::PoweredOn;
                report_state("central", state);
                if state == CBManagerState::Unauthorized {
                    shared.denied();
                }
                shared.power_changed(st, &weak);
            });
        }

        #[unsafe(method(centralManager:didDiscoverPeripheral:advertisementData:RSSI:))]
        fn did_discover(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            adv: &NSDictionary<NSString, AnyObject>,
            rssi: &NSNumber,
        ) {
            with_state(self.ivars(), |shared, st| shared.discovered(st, peripheral, adv, rssi));
        }

        #[unsafe(method(centralManager:didConnectPeripheral:))]
        fn did_connect(&self, _central: &CBCentralManager, peripheral: &CBPeripheral) {
            with_state(self.ivars(), |shared, st| shared.connected(st, peripheral));
        }

        #[unsafe(method(centralManager:didFailToConnectPeripheral:error:))]
        fn did_fail_to_connect(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            error: Option<&NSError>,
        ) {
            with_state(self.ivars(), |shared, st| shared.connect_failed(st, peripheral, error));
        }

        #[unsafe(method(centralManager:didDisconnectPeripheral:error:))]
        fn did_disconnect(
            &self,
            _central: &CBCentralManager,
            peripheral: &CBPeripheral,
            error: Option<&NSError>,
        ) {
            with_state(self.ivars(), |shared, st| shared.disconnected(st, peripheral, error));
        }
    }
);

impl CentralDelegate {
    fn new(shared: Weak<Shared>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(shared);
        unsafe { msg_send![super(this), init] }
    }
}

define_class!(
    #[unsafe(super(NSObject))]
    #[ivars = Weak<Shared>]
    struct ManagerDelegate;

    unsafe impl NSObjectProtocol for ManagerDelegate {}

    unsafe impl CBPeripheralManagerDelegate for ManagerDelegate {
        #[unsafe(method(peripheralManagerDidUpdateState:))]
        fn did_update_state(&self, manager: &CBPeripheralManager) {
            let weak = self.ivars().clone();
            with_state(self.ivars(), |shared, st| {
                let state = unsafe { manager.state() };
                st.manager_on = state == CBManagerState::PoweredOn;
                report_state("peripheral manager", state);
                if state == CBManagerState::Unauthorized {
                    shared.denied();
                }
                shared.power_changed(st, &weak);
            });
        }

        #[unsafe(method(peripheralManager:didPublishL2CAPChannel:error:))]
        fn did_publish(&self, _manager: &CBPeripheralManager, psm: CBL2CAPPSM, error: Option<&NSError>) {
            let weak = self.ivars().clone();
            with_state(self.ivars(), |shared, st| shared.published(st, &weak, psm, error));
        }

        #[unsafe(method(peripheralManager:didAddService:error:))]
        fn did_add_service(&self, _manager: &CBPeripheralManager, _service: &CBService, error: Option<&NSError>) {
            match error {
                Some(e) => warn!(error = %ns_err("add service", Some(e)), "BLE: GATT PSM not served"),
                None => debug!("BLE: GATT PSM served"),
            }
        }

        #[unsafe(method(peripheralManagerDidStartAdvertising:error:))]
        fn did_start_advertising(&self, _manager: &CBPeripheralManager, error: Option<&NSError>) {
            if let Some(e) = error {
                warn!(error = %ns_err("advertise", Some(e)), "BLE: advertising failed");
            }
        }

        #[unsafe(method(peripheralManager:didOpenL2CAPChannel:error:))]
        fn did_open(
            &self,
            _manager: &CBPeripheralManager,
            channel: Option<&CBL2CAPChannel>,
            error: Option<&NSError>,
        ) {
            with_state(self.ivars(), |shared, st| shared.inbound_opened(st, channel, error));
        }
    }
);

impl ManagerDelegate {
    fn new(shared: Weak<Shared>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(shared);
        unsafe { msg_send![super(this), init] }
    }
}

define_class!(
    #[unsafe(super(NSObject))]
    #[ivars = Weak<Shared>]
    struct PeripheralDelegate;

    unsafe impl NSObjectProtocol for PeripheralDelegate {}

    unsafe impl CBPeripheralDelegate for PeripheralDelegate {
        #[unsafe(method(peripheral:didDiscoverServices:))]
        fn did_discover_services(&self, peripheral: &CBPeripheral, error: Option<&NSError>) {
            with_state(self.ivars(), |shared, st| shared.services_discovered(st, peripheral, error));
        }

        #[unsafe(method(peripheral:didDiscoverCharacteristicsForService:error:))]
        fn did_discover_characteristics(
            &self,
            peripheral: &CBPeripheral,
            service: &CBService,
            error: Option<&NSError>,
        ) {
            with_state(self.ivars(), |shared, st| {
                shared.characteristics_discovered(st, peripheral, service, error)
            });
        }

        #[unsafe(method(peripheral:didUpdateValueForCharacteristic:error:))]
        fn did_update_value(
            &self,
            peripheral: &CBPeripheral,
            characteristic: &CBCharacteristic,
            error: Option<&NSError>,
        ) {
            with_state(self.ivars(), |shared, st| {
                shared.value_read(st, peripheral, characteristic, error)
            });
        }

        #[unsafe(method(peripheral:didOpenL2CAPChannel:error:))]
        fn did_open(
            &self,
            peripheral: &CBPeripheral,
            channel: Option<&CBL2CAPChannel>,
            error: Option<&NSError>,
        ) {
            with_state(self.ivars(), |shared, st| {
                shared.outbound_opened(st, peripheral, channel, error)
            });
        }
    }
);

impl PeripheralDelegate {
    fn new(shared: Weak<Shared>) -> Retained<Self> {
        let this = Self::alloc().set_ivars(shared);
        unsafe { msg_send![super(this), init] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The characteristic UUID `psm` specifies must be the one CoreBluetooth
    /// itself names, or a Mac would serve and look for its PSM somewhere no
    /// other Apple stack does.
    #[test]
    fn the_psm_characteristic_is_apples() {
        let apple = unsafe { objc2_core_bluetooth::CBUUIDL2CAPPSMCharacteristicString };
        assert_eq!(
            apple.to_string().to_uppercase(),
            psm::L2CAP_PSM_CHARACTERISTIC_UUID
        );
    }

    /// The service-data key CoreBluetooth would report for a BlueZ or
    /// Android advert is recognised in the form CoreBluetooth gives it.
    #[test]
    fn corebluetooth_reports_the_psm_key_in_a_recognised_form() {
        let key = unsafe { CBUUID::UUIDWithString(&NSString::from_str("9C90")) };
        assert!(is_psm_service_data_key(&unsafe { key.data() }.to_vec()));
    }

    #[test]
    fn an_advert_with_psm_service_data_yields_the_psm() {
        unsafe {
            let key = CBUUID::UUIDWithString(&NSString::from_str("9C90"));
            let value = NSData::with_bytes(&psm::encode_psm(0x00C1));
            let value: &AnyObject = &value;
            let key: &CBUUID = &key;
            let service_data = NSDictionary::<CBUUID, AnyObject>::from_slices(&[key], &[value]);
            let service_data: &AnyObject = &service_data;
            let adv =
                NSDictionary::from_slices(&[CBAdvertisementDataServiceDataKey], &[service_data]);
            assert_eq!(advertised_psm(&adv), Some(0x00C1));
        }
    }

    #[test]
    fn an_advert_without_service_data_yields_none() {
        let adv = NSDictionary::<NSString, AnyObject>::new();
        assert_eq!(advertised_psm(&adv), None);
    }

    /// Hardware smoke test: Bluetooth on, permission granted. The radio comes
    /// up, publishes a listener on an OS-assigned PSM, installs a bridge that
    /// reports it, and advertises and scans without error.
    ///
    /// `cargo test --lib corebluetooth -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "needs a Bluetooth adapter and Bluetooth permission"]
    async fn the_radio_comes_up_on_hardware() {
        use crate::transport::ble::io::BleIo;
        use crate::transport::ble::io_radio::RadioIo;

        let slot = Arc::new(BleRadioSlot::new());
        let radio = MacRadio::start(Arc::clone(&slot), 2048);
        let deadline = Instant::now() + Duration::from_secs(15);
        while !slot.is_installed() {
            assert!(Instant::now() < deadline, "Bluetooth never came up");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let io = RadioIo::with_owner(Arc::clone(&slot), radio);
        let (_acceptor, psm) = io.listen(0x0085).await.unwrap();
        println!("published L2CAP listener on PSM {psm:#06x}");
        assert_ne!(psm, 0, "a listener was published");
        io.start_advertising(psm).await.unwrap();
        let mut scanner = io.start_scanning().await.unwrap();
        // Report any FIPS peers in range; none is not a failure.
        let listen_until = tokio::time::Instant::now() + Duration::from_secs(5);
        while let Ok(Some(advert)) = tokio::time::timeout_at(
            listen_until,
            crate::transport::ble::io::BleScanner::next(&mut scanner),
        )
        .await
        {
            println!(
                "advert: {} psm={:?} rssi={:?}",
                advert.addr, advert.psm, advert.rssi
            );
        }
        io.stop_advertising().await.unwrap();
        io.stop_scanning().await.unwrap();
    }

    /// Hardware dial test: a FIPS peer in range. Dials the first one heard,
    /// at the PSM it advertised or, if it advertised none, at whatever GATT
    /// yields, and checks an L2CAP channel opens. The peer sees a connection
    /// that never completes its pubkey exchange, and drops it.
    ///
    /// `cargo test --lib corebluetooth -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "needs Bluetooth permission and a FIPS peer in range"]
    async fn dials_a_peer_on_hardware() {
        use crate::transport::ble::io::{BleIo, BleScanner, BleStream};
        use crate::transport::ble::io_radio::RadioIo;

        let slot = Arc::new(BleRadioSlot::new());
        let radio = MacRadio::start(Arc::clone(&slot), 2048);
        let deadline = Instant::now() + Duration::from_secs(15);
        while !slot.is_installed() {
            assert!(Instant::now() < deadline, "Bluetooth never came up");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let io = RadioIo::with_owner(Arc::clone(&slot), radio);
        let mut scanner = io.start_scanning().await.unwrap();
        let advert = tokio::time::timeout(Duration::from_secs(15), scanner.next())
            .await
            .expect("no FIPS peer in range")
            .unwrap();
        let psm = advert.psm.unwrap_or(crate::transport::ble::DEFAULT_PSM);
        println!("dialling {} at psm {psm:#06x}", advert.addr);
        let stream = tokio::time::timeout(Duration::from_secs(20), io.connect(&advert.addr, psm))
            .await
            .expect("dial timed out")
            .expect("dial failed");
        println!("L2CAP channel open to {}", stream.remote_addr());
        assert_eq!(stream.remote_addr(), &advert.addr);
        // Both ends open with their pubkey, so the peer's should arrive
        // through the reader pump.
        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(10), stream.recv(&mut buf))
            .await
            .expect("nothing received")
            .unwrap();
        println!("received {n} bytes: {}", hex::encode(&buf[..n]));
        assert!(n > 0, "the peer's opening message arrived");
        io.stop_scanning().await.unwrap();
    }
}
