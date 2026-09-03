//! Ethernet Transport Implementation
//!
//! Provides raw Ethernet transport for FIPS peer communication. On Linux,
//! uses AF_PACKET/SOCK_DGRAM sockets; on macOS, uses BPF devices (`/dev/bpf*`).
//! Works on wired Ethernet and WiFi interfaces (kernel mac80211 abstracts
//! 802.11 transparently on Linux).
//!
//! ## Dynamic interface binding
//!
//! The interface a transport names is not required to exist when the daemon
//! starts. `start_async` binds if it can and otherwise returns `Ok` with the
//! transport [`Absent`](presence::Presence::Absent); a binder task then waits
//! for the interface, binds when it appears, tears down when it goes away, and
//! rebinds when it returns. Start-time absence and runtime detach are the same
//! transition, so a node that boots before wifi and a node whose wifi reloads
//! at 03:00 take one code path. See [`presence`] for the state machine.

pub mod addr;
pub mod io;
pub mod neighbor;
pub mod presence;
pub mod stats;
mod watcher;

pub use addr::parse_mac_string;
pub use presence::{AbsencePolicy, Presence};

use super::{
    DiscoveredPeer, PacketTx, PresenceTx, ReceivedPacket, Transport, TransportAddr, TransportError,
    TransportId, TransportPresence, TransportState, TransportType,
};
use crate::config::EthernetConfig;
use io::{
    AsyncPacketSocket, ETHERNET_BROADCAST, PacketSocket, interface_present, interface_present_probe,
};
use neighbor::{FRAME_TYPE_BEACON, FRAME_TYPE_DATA, NeighborBuffer, build_beacon, parse_beacon};
use presence::{ABSENCE_ERROR_AFTER, ChurnGuard, PresenceState, bind_backoff};
use stats::EthernetStats;
use watcher::LinkWatcher;

use secp256k1::XOnlyPublicKey;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

/// Presence poll interval for the fallback watcher.
///
/// Deliberately small. `getifaddrs` plus a flags read is cheap, and letting
/// this drift to tens of seconds reintroduces exactly the boot-race latency
/// the mechanism exists to remove.
const WATCH_INTERVAL: Duration = Duration::from_secs(1);

/// Floor on how often the presence probe may run.
///
/// The Linux event source is bound to `RTNLGRP_LINK` and speaks only when a
/// link changes. `PF_ROUTE` has no group filter, so the macOS source delivers
/// every routing message on the box — route churn, ARP, DHCP renewals, a VPN
/// going up and down — and each one would otherwise wake the binder into a
/// full `getifaddrs` walk. Coalescing to ten probes a second keeps detection
/// sub-second while bounding the work an unrelated chatty network can cause.
const MIN_PROBE_INTERVAL: Duration = Duration::from_millis(100);

/// Consecutive receive errors tolerated before the receive loop gives up and
/// hands the transport back to the binder.
///
/// The loop used to `warn!` every iteration with no backoff, so a dead
/// descriptor was a hot log spin. Exiting is the correct response: a socket
/// that errors repeatedly is a socket to rebind, not one to keep reading.
const RECV_ERROR_EXIT_THRESHOLD: u32 = 5;

/// Consecutive beacon send failures tolerated before the beacon sender exits
/// and lets the binder rebind.
///
/// This replaces the ad-hoc ENXIO socket-reopen that used to live in
/// `beacon_sender_loop` — the only recovery logic in the tree, and in the
/// wrong layer. Recovery is the presence machine's job.
const BEACON_ERROR_EXIT_THRESHOLD: u32 = 3;

/// The mutable half of a bound interface: the socket and everything derived
/// from it.
///
/// Split out of [`EthernetTransport`] so the binder task can replace it
/// wholesale on a rebind while `send`, `mtu()` and the control plane keep
/// reading through a shared `Arc`. `None` in `socket` *is* absence.
struct Binding {
    /// The live socket, or `None` while absent.
    socket: RwLock<Option<Arc<AsyncPacketSocket>>>,
    /// Effective payload MTU of the current binding.
    mtu: AtomicU16,
    /// Local MAC of the current binding.
    local_mac: RwLock<Option<[u8; 6]>>,
    /// Kernel index of the device the current binding is attached to. `0` when
    /// unbound. Both backends bind by device, not by name, so this is the
    /// identity that has to keep matching — see [`io::interface_index`].
    bound_index: AtomicU32,
    /// Receive and beacon tasks belonging to the current binding.
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl Binding {
    fn new(default_mtu: u16) -> Self {
        Self {
            socket: RwLock::new(None),
            mtu: AtomicU16::new(default_mtu),
            local_mac: RwLock::new(None),
            bound_index: AtomicU32::new(0),
            tasks: Mutex::new(Vec::new()),
        }
    }

    fn socket(&self) -> Option<Arc<AsyncPacketSocket>> {
        self.socket
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }

    fn local_mac(&self) -> Option<[u8; 6]> {
        *self
            .local_mac
            .read()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `interface` still names the device this binding is attached to.
    ///
    /// A recreated netdev takes a new kernel index, so the old socket is bound
    /// to nothing while the name resolves fine. Nothing else notices: the
    /// receive loop on a stale `AF_PACKET` socket never becomes readable, so
    /// it never errors and never exits, and send failures are reported to the
    /// caller rather than to the binder. Without this check a listen-only node
    /// — one with `announce: false`, and so no beacon sender to fail — sits
    /// `present` and deaf indefinitely after a `wifi reload`.
    fn device_replaced(&self, interface: &str) -> bool {
        let bound = self.bound_index.load(Ordering::Relaxed);
        if bound == 0 {
            return false;
        }
        match io::interface_index(interface) {
            Some(current) => current != bound,
            // The name is gone; the caller's presence probe reports that more
            // precisely, so this is not the check that should claim it.
            None => false,
        }
    }

    /// Whether every task of the current binding is still running.
    ///
    /// A finished task means the socket underneath it died — a recreated veth
    /// handing out ENXIO, a BPF device torn away — even when the interface
    /// name is still present. The binder treats that as a detach.
    fn tasks_alive(&self) -> bool {
        let tasks = self.tasks.lock().unwrap_or_else(PoisonError::into_inner);
        !tasks.is_empty() && tasks.iter().all(|h| !h.is_finished())
    }

    /// Drop the socket and stop its loops. Idempotent.
    ///
    /// Every lock here ignores poisoning. Declining to abort a task because a
    /// mutex was poisoned would leak a receive loop per rebind while the
    /// binder, seeing no live tasks, rebound once a second forever — a stuck
    /// state strictly worse than touching data a panicking thread had
    /// written.
    fn tear_down(&self) {
        if let Some(socket) = self.socket() {
            // Wakes the macOS reader thread's `select()`; a no-op on Linux,
            // where `AsyncFd` cancellation is enough.
            socket.shutdown();
        }
        for task in self
            .tasks
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .drain(..)
        {
            task.abort();
        }
        *self.socket.write().unwrap_or_else(PoisonError::into_inner) = None;
        *self
            .local_mac
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
        // A stale index left here would make the next binding look replaced
        // the moment it came up.
        self.bound_index.store(0, Ordering::Relaxed);
    }
}

/// Everything the binder task needs to bind, run, and rebind.
///
/// The transport object survives detach: this context, the neighbor buffer,
/// the statistics and the `TransportId` all persist across an interface going
/// away and coming back. Only the file descriptor and its loops go.
struct BinderContext {
    /// Set when the transport is stopping or being dropped. The binder must
    /// not publish a new binding past this point.
    ///
    /// Teardown aborts the binder, but `bind_now` contains no await points, so
    /// a cancellation issued while it runs takes effect only at the *next*
    /// await — after the socket and task handles have been stored. Without
    /// this flag the sequence "tear_down clears an empty binding, binder
    /// stores a fresh one, binder is cancelled" leaves a live receive loop on
    /// a socket nothing owns. The flag is set before `tear_down`, and checked
    /// by the binder *after* it stores, so whichever order the two interleave
    /// exactly one of them cleans up.
    shutdown: Arc<AtomicBool>,
    transport_id: TransportId,
    name: Option<String>,
    interface: String,
    config: EthernetConfig,
    policy: AbsencePolicy,
    packet_tx: PacketTx,
    neighbor_buffer: Arc<NeighborBuffer>,
    stats: Arc<EthernetStats>,
    binding: Arc<Binding>,
    presence: Arc<PresenceState>,
    local_pubkey: Option<XOnlyPublicKey>,
    presence_tx: Option<PresenceTx>,
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
    /// The socket and its derived values, replaced wholesale on each rebind.
    binding: Arc<Binding>,
    /// Interface presence, published to the control plane and the supervisor.
    presence: Arc<PresenceState>,
    /// How absence of this interface is reported.
    policy: AbsencePolicy,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Binder task: binds, watches, and rebinds for the transport's lifetime.
    binder_task: Option<JoinHandle<()>>,
    /// Shared stop flag, honoured by the binder. See [`BinderContext`].
    shutdown: Arc<AtomicBool>,
    /// Interface name (from config).
    interface: String,
    /// Neighbor buffer for discovered peers.
    neighbor_buffer: Arc<NeighborBuffer>,
    /// Transport-level statistics.
    stats: Arc<EthernetStats>,
    /// Node's public key for beacon construction.
    local_pubkey: Option<XOnlyPublicKey>,
    /// Presence edges are published here so node health tracks absence in both
    /// directions.
    presence_tx: Option<PresenceTx>,
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
        let policy = AbsencePolicy::from_optional(config.optional());

        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            // 1499 = the common 1500-byte interface MTU minus the 3-byte frame
            // header; replaced by the real value at the first bind.
            binding: Arc::new(Binding::new(1499)),
            presence: Arc::new(PresenceState::new()),
            policy,
            packet_tx,
            binder_task: None,
            shutdown: Arc::new(AtomicBool::new(false)),
            interface,
            neighbor_buffer,
            stats,
            local_pubkey: None,
            presence_tx: None,
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

    /// Get the local MAC address (only valid while bound).
    pub fn local_mac(&self) -> Option<[u8; 6]> {
        self.binding.local_mac()
    }

    /// Current interface presence.
    pub fn presence(&self) -> Presence {
        self.presence.presence()
    }

    /// Whether the interface currently has carrier. Reported, never acted on —
    /// see [`io::interface_present`].
    pub fn has_carrier(&self) -> bool {
        io::interface_carrier(&self.interface)
    }

    /// Shared presence state, for the control plane and for tests.
    pub fn presence_state(&self) -> &Arc<PresenceState> {
        &self.presence
    }

    /// How absence of this interface is reported.
    pub fn absence_policy(&self) -> AbsencePolicy {
        self.policy
    }

    /// Set the node's public key for beacon construction.
    ///
    /// Must be called before start if announce is enabled.
    pub fn set_local_pubkey(&mut self, pubkey: XOnlyPublicKey) {
        self.local_pubkey = Some(pubkey);
    }

    /// Install the channel presence edges are published on.
    ///
    /// Must be called before start. Without it the transport still binds and
    /// rebinds; only the health reporting is lost.
    pub fn set_presence_tx(&mut self, tx: PresenceTx) {
        self.presence_tx = Some(tx);
    }

    /// Get a reference to the statistics.
    pub fn stats(&self) -> &Arc<EthernetStats> {
        &self.stats
    }

    /// Start the transport asynchronously.
    ///
    /// Binds the interface if it is present, then hands the transport to a
    /// binder task that owns every later bind and unbind. **Returns `Ok` when
    /// the interface is absent**: absence is a state the transport tracks, not
    /// a start failure. A node that boots before its wifi comes up is degraded
    /// (or, for an `optional` interface, unremarkable) — not permanently deaf.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }

        self.state = TransportState::Starting;

        // A restart reuses the transport object, so clear any stop from the
        // previous run before the binder can observe it.
        self.shutdown.store(false, Ordering::SeqCst);

        // The bring-up window is measured from here, not from whenever this
        // object happened to be constructed.
        self.presence.mark_starting();

        let ctx = Arc::new(BinderContext {
            shutdown: self.shutdown.clone(),
            transport_id: self.transport_id,
            name: self.name.clone(),
            interface: self.interface.clone(),
            config: self.config.clone(),
            policy: self.policy,
            packet_tx: self.packet_tx.clone(),
            neighbor_buffer: self.neighbor_buffer.clone(),
            stats: self.stats.clone(),
            binding: self.binding.clone(),
            presence: self.presence.clone(),
            local_pubkey: self.local_pubkey,
            presence_tx: self.presence_tx.clone(),
        });

        // First attempt inline, so the common case (interface already there)
        // keeps its ordering: the transport is bound and logged before
        // `start_async` returns, exactly as before this mechanism existed.
        // An edge the channel refused here is handed to the binder to retry,
        // rather than dropped: it is the only edge either consumer will ever
        // see for this transport until the interface next changes state.
        let mut initial_unpublished: Option<bool> = None;
        match bind_and_spawn(&ctx).await {
            Ok(()) => {
                if !publish_presence(&ctx, true) {
                    initial_unpublished = Some(true);
                }
            }
            Err(TransportError::InterfaceUnavailable { .. }) => {
                // Absence is a state, not a start failure. Come up and wait.
                log_initial_absence(&ctx);
                if !publish_presence(&ctx, false) {
                    initial_unpublished = Some(false);
                }
            }
            // Anything else — no CAP_NET_RAW, no free BPF device, a buffer
            // the kernel refused — is a fault, not a state, and it will not
            // resolve on its own. It fails the start exactly as it did before
            // this mechanism existed, so a node deployed without the
            // capability still dies loudly at boot instead of retrying
            // forever behind a `Degraded` nobody is watching.
            Err(e) => {
                self.state = TransportState::Configured;
                return Err(e);
            }
        }

        let watcher_ctx = ctx.clone();
        self.binder_task = Some(tokio::spawn(async move {
            binder_loop(watcher_ctx, initial_unpublished).await;
        }));

        self.state = TransportState::Up;
        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // The flag first, then the abort. The binder checks it after storing
        // a binding, so a bind that completes between here and `tear_down`
        // cleans up after itself instead of outliving the transport.
        self.shutdown.store(true, Ordering::SeqCst);

        if let Some(task) = self.binder_task.take() {
            task.abort();
            #[cfg(not(target_os = "macos"))]
            {
                let _ = task.await;
            }
        }

        // `tear_down` shuts the socket down and aborts the loops. On macOS the
        // aborted tasks are deliberately not awaited: on a current_thread
        // runtime an aborted task cannot be polled while we are blocked on its
        // `JoinHandle`, which deadlocks.
        let was_present = self.presence.is_present();
        self.binding.tear_down();
        self.presence.transition(Presence::Absent);

        // Retract the edge the binder left standing. Every other transition
        // pairs its edges; a transport stopped while `Present` would otherwise
        // leave health reading `present: true` for a socket that is gone.
        if was_present && let Some(tx) = &self.presence_tx {
            let _ = tx.try_send(TransportPresence {
                transport_id: self.transport_id,
                present: false,
                health_relevant: !self.policy.is_optional(),
            });
        }

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

        // Absence is reported as absence, not as "not started": the caller can
        // tell an interface that is away from a transport that was never
        // brought up.
        let socket = self
            .binding
            .socket()
            .ok_or_else(|| TransportError::InterfaceUnavailable {
                interface: self.interface.clone(),
            })?;

        let mtu = self.binding.mtu();
        if data.len() > mtu as usize {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu,
            });
        }

        let dest_mac = parse_mac_addr(addr)?;

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

/// Stop the binder and release the socket when the transport is dropped
/// without `stop_async`.
///
/// A `TransportHandle` can be dropped without ever being stopped — a pending
/// handle the supervisor never spawns, an unwind through `start()`. Without
/// this, the binder outlives the object that owns it: not merely a leaked
/// task, but one that goes on opening raw sockets on an interface nobody is
/// reading, once per attach, for the life of the process.
///
/// `Drop` cannot await, so this does what it can synchronously — raise the
/// stop flag, abort the binder, release the socket and its loops — which is
/// all `stop_async` does beyond awaiting the abort and logging.
impl Drop for EthernetTransport {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(task) = self.binder_task.take() {
            task.abort();
        }
        self.binding.tear_down();
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
        self.binding.mtu()
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
// Binder
// ============================================================================

/// Bind the interface and spawn the receive and beacon loops.
///
/// On success the binding's socket slot, MTU and MAC are published and the
/// presence state moves to [`Presence::Present`]. On failure nothing is
/// published and the presence state is left for the caller to classify.
async fn bind_and_spawn(ctx: &Arc<BinderContext>) -> Result<(), TransportError> {
    // Probe before opening anything. The socket is created before the
    // interface is named on both backends, so without this an unprivileged
    // process would report "permission denied" for an interface that is
    // simply not there — and absence would become indistinguishable from a
    // missing capability, which is exactly the distinction this mechanism
    // needs to make.
    //
    // Deliberately ahead of the `Binding` transition: absence is not an
    // attempt, and announcing one would put a permanently-missing interface
    // into `Binding` on every poll.
    if !interface_present(&ctx.interface) {
        return Err(TransportError::InterfaceUnavailable {
            interface: ctx.interface.clone(),
        });
    }

    // `Binding` is owned here, both edges of it. Leaving the revert to callers
    // meant a caller that returned early on failure — the fail-fast start
    // path — left the transport reporting `binding` for the rest of its life.
    ctx.presence.transition(Presence::Binding);
    let bound = bind_now(ctx);
    if bound.is_err() {
        ctx.presence.transition(Presence::Absent);
        return bound;
    }

    // Checked *after* the store, and set before teardown's own `tear_down`,
    // so a stop that lands anywhere inside `bind_now` is cleaned up by
    // exactly one of the two. Dropping this check is what leaves a receive
    // loop reading a socket belonging to a stopped transport.
    if ctx.shutdown.load(Ordering::SeqCst) {
        ctx.binding.tear_down();
        ctx.presence.transition(Presence::Absent);
        return Err(TransportError::NotStarted);
    }

    bound
}

/// Open the socket and start the loops. Every exit is an error the caller
/// converts back to [`Presence::Absent`]; nothing here is left half-published.
fn bind_now(ctx: &Arc<BinderContext>) -> Result<(), TransportError> {
    let raw_socket = PacketSocket::open(&ctx.interface, ctx.config.ethertype())?;
    let local_mac = raw_socket.local_mac()?;
    let if_mtu = raw_socket.interface_mtu()?;

    // Effective MTU: interface MTU minus 3 bytes for frame header
    // (1 byte frame type + 2 bytes LE payload length)
    let effective_mtu = if let Some(configured_mtu) = ctx.config.mtu {
        // Config MTU cannot exceed interface MTU - 3
        configured_mtu.min(if_mtu.saturating_sub(3))
    } else {
        if_mtu.saturating_sub(3)
    };

    raw_socket.set_recv_buffer_size(ctx.config.recv_buf_size())?;
    raw_socket.set_send_buffer_size(ctx.config.send_buf_size())?;

    // Captured before the socket is wrapped: this is the device identity the
    // binding is attached to, and the thing that has to keep matching.
    let bound_index = raw_socket.if_index() as u32;

    let socket = Arc::new(raw_socket.into_async()?);

    let mut tasks = Vec::new();

    let recv_task = {
        let socket = socket.clone();
        let transport_id = ctx.transport_id;
        let packet_tx = ctx.packet_tx.clone();
        let listen_enabled = ctx.config.listen();
        let neighbor_buffer = ctx.neighbor_buffer.clone();
        let stats = ctx.stats.clone();
        tokio::spawn(async move {
            ethernet_receive_loop(
                socket,
                transport_id,
                packet_tx,
                effective_mtu,
                listen_enabled,
                neighbor_buffer,
                stats,
            )
            .await;
        })
    };
    tasks.push(recv_task);

    if ctx.config.announce() {
        if let Some(pubkey) = ctx.local_pubkey {
            let socket = socket.clone();
            let interval_secs = ctx.config.beacon_interval_secs();
            let stats = ctx.stats.clone();
            let transport_id = ctx.transport_id;
            tasks.push(tokio::spawn(async move {
                beacon_sender_loop(socket, pubkey, interval_secs, stats, transport_id).await;
            }));
        } else {
            warn!(
                transport_id = %ctx.transport_id,
                "Announce enabled but no local pubkey set; beacons disabled"
            );
        }
    }

    *ctx.binding
        .socket
        .write()
        .unwrap_or_else(PoisonError::into_inner) = Some(socket);
    *ctx.binding
        .local_mac
        .write()
        .unwrap_or_else(PoisonError::into_inner) = Some(local_mac);
    ctx.binding.mtu.store(effective_mtu, Ordering::Relaxed);
    ctx.binding
        .bound_index
        .store(bound_index, Ordering::Relaxed);
    *ctx.binding
        .tasks
        .lock()
        .unwrap_or_else(PoisonError::into_inner) = tasks;

    // Only now does presence read `Present`. Flipping it before the socket
    // slot is filled would let a concurrent send see a bound transport and be
    // told its interface is unavailable.
    //
    // A name is not a device: if the interface reappeared with a MAC other
    // than the one last bound, this is different hardware wearing the same
    // name, so drop the cached neighbors rather than silently resuming onto
    // it.
    let hardware_changed = ctx.presence.record_bind(local_mac);
    if hardware_changed {
        ctx.neighbor_buffer.take();
        warn!(
            transport_id = %ctx.transport_id,
            interface = %ctx.interface,
            mac = %format_mac(&local_mac),
            "Interface reappeared with a different MAC; treating as new hardware \
             and dropping cached neighbors"
        );
    }

    let rebind = ctx.presence.binds() > 1;
    if let Some(ref name) = ctx.name {
        info!(
            name = %name,
            interface = %ctx.interface,
            mac = %format_mac(&local_mac),
            mtu = effective_mtu,
            if_mtu = if_mtu,
            rebind,
            "Ethernet transport started"
        );
    } else {
        info!(
            interface = %ctx.interface,
            mac = %format_mac(&local_mac),
            mtu = effective_mtu,
            if_mtu = if_mtu,
            rebind,
            "Ethernet transport started"
        );
    }

    Ok(())
}

/// Log the edge into a *start-time* absence, once.
///
/// At `info`, for both policies. An interface that is not there when the
/// daemon starts and binds a moment later is the ordinary case this whole
/// mechanism exists to absorb — on a router the daemon routinely wins the
/// race against the radio — so it is not an error yet. It becomes one by
/// outlasting the race: [`report_sustained_absence`] says so at `error`, once,
/// after [`ABSENCE_ERROR_AFTER`]. Node health does not wait for that; it reads
/// `Degraded` from the first edge.
///
/// A runtime detach is logged separately, at `warn`, and reaches the same
/// deadline by the same route — start-time absence and runtime detach are one
/// transition here as everywhere else in this module. Nothing reaches `error`
/// for merely happening, only for outlasting the window in which it could
/// still have been a race.
///
/// Never per retry attempt either way. A loop that logs per attempt
/// reproduces the hot log spin this mechanism removed, at 1–30 s intervals
/// forever on any router with an unplugged WAN — and operators learn to
/// filter it, which is how the next real failure gets missed.
fn log_initial_absence(ctx: &Arc<BinderContext>) {
    if ctx.policy.is_optional() {
        info!(
            transport_id = %ctx.transport_id,
            interface = %ctx.interface,
            "Ethernet interface absent; waiting for it to appear (optional)"
        );
    } else {
        info!(
            transport_id = %ctx.transport_id,
            interface = %ctx.interface,
            "Ethernet interface absent; waiting for it to appear"
        );
    }
}

/// Publish a presence edge to node health. Returns whether it went out.
///
/// **Never blocks.** This used to `await` the send, which handed a bounded
/// 16-slot channel the power to stop the machine reporting into it: a
/// receiver that is slow, not yet running, or gone leaves the binder parked
/// mid-publish, and an interface frozen in whatever state it happened to
/// hold. A health channel must not be able to deadlock the thing whose health
/// it carries. The caller retries a refused edge on its next tick, so a
/// momentarily full channel costs latency rather than correctness.
///
/// An `optional` interface publishes its edge with `health_relevant: false`.
/// That is the entire health half of the policy: absence of an interface
/// whose absence is normal must not move the node off `Full`.
///
/// It is deliberately *not* silence. The edge still goes out, because the
/// consumer derives two things from it and only one of them is about health:
/// the node's egress MTU floor is a function of the bound set, and an
/// `optional` interface binding or unbinding changes that set exactly as a
/// `required` one does. Filtering the edge here — which is what this used to
/// do — left the TUN MSS clamp stale for every `optional` transport, which on
/// the shipped OpenWrt config is five of seven.
fn publish_presence(ctx: &Arc<BinderContext>, present: bool) -> bool {
    let Some(tx) = &ctx.presence_tx else {
        return true;
    };
    match tx.try_send(TransportPresence {
        transport_id: ctx.transport_id,
        present,
        health_relevant: !ctx.policy.is_optional(),
    }) {
        Ok(()) => true,
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            // Nobody is listening and nobody will be. Reporting success stops
            // the caller retrying an edge that can never land.
            true
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => false,
    }
}

/// The binder: one task per interface-bound transport, alive for the
/// transport's whole lifetime.
///
/// Present → watch for detach; Absent → watch for attach. This is the polling
/// fallback; on platforms with a link-event source the same loop is driven by
/// events instead (see `docs`/the netlink watcher), and the interval below is
/// what "immediate" degrades to without one.
async fn binder_loop(ctx: Arc<BinderContext>, initial_unpublished: Option<bool>) {
    let watcher = LinkWatcher::new();
    let mut ticker = tokio::time::interval(WATCH_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Consume the immediate first tick: `start_async` has just probed.
    ticker.tick().await;

    debug!(
        transport_id = %ctx.transport_id,
        interface = %ctx.interface,
        event_driven = watcher.is_event_driven(),
        "Interface binder started"
    );

    // Whether this absence episode has already outlasted the bring-up window
    // and been reported. Reset on every entry into absence, so each outage is
    // judged on its own duration rather than inheriting the last one's.
    let mut absence_reported = false;
    // Damping for bindings that keep succeeding and then dying young.
    let mut churn = ChurnGuard::new();
    // `start_async` binds inline and publishes that edge itself, outside this
    // guard. Seed the guard from that bind, or the guard believes it has
    // announced nothing: `detached` takes `announced` to decide whether an
    // edge is owed, so the first detach after a clean start would retract
    // nothing and health would keep reading `Full` for as long as the
    // interface stayed away. `stabilized` cannot repair it either — it
    // early-returns while `bound_at` is `None`, which it is for a bind this
    // loop did not perform.
    if ctx.presence.is_present() {
        churn.bound(Instant::now());
    }
    // A presence edge the channel refused, to retry on the next tick. Health
    // is a level, so only the most recent value matters — an older pending
    // edge is superseded rather than queued. Seeded with the start edge if
    // that one was refused.
    let mut unpublished: Option<bool> = initial_unpublished;
    // When the presence probe last ran, for the coalescing floor.
    let mut last_probe = Instant::now();

    loop {
        // Whichever comes first. With an event source the tick is a backstop
        // and detection is sub-second; without one the watcher never fires and
        // the tick is the whole mechanism.
        tokio::select! {
            _ = ticker.tick() => {}
            _ = watcher.changed() => {}
        }

        // Coalesce wake-ups that arrive faster than the probe floor. The tick
        // never trips this; a firehose event source does.
        let since_probe = last_probe.elapsed();
        if since_probe < MIN_PROBE_INTERVAL {
            tokio::time::sleep(MIN_PROBE_INTERVAL - since_probe).await;
        }
        last_probe = Instant::now();

        if let Some(pending) = unpublished
            && publish_presence(&ctx, pending)
        {
            unpublished = None;
        }

        if ctx.presence.is_present() {
            // Detach is either the interface going away or the socket under it
            // dying while the name stays (a recreated veth, a reloaded phy).
            //
            // A probe that could not run is not an interface that went away.
            // Hold the binding and re-ask next tick, rather than tearing a
            // working socket down because `getifaddrs` hit `ENOBUFS` or the
            // process ran out of descriptors — the latter being a state the
            // rebind could not recover from anyway.
            let gone = match interface_present_probe(&ctx.interface) {
                Some(present) => !present,
                None => {
                    debug!(
                        transport_id = %ctx.transport_id,
                        interface = %ctx.interface,
                        "Interface presence probe failed; holding the binding"
                    );
                    false
                }
            };
            let replaced = !gone && ctx.binding.device_replaced(&ctx.interface);
            let dead = !ctx.binding.tasks_alive();
            let detach = classify_detach(gone, replaced, dead);
            if detach.is_none() {
                // Still bound. A binding held back during a churn streak is
                // announced here, once it has proved it will last.
                if churn.stabilized(Instant::now()) {
                    info!(
                        transport_id = %ctx.transport_id,
                        interface = %ctx.interface,
                        "Ethernet interface stable again"
                    );
                    if !publish_presence(&ctx, true) {
                        unpublished = Some(true);
                    }
                }
                continue;
            }

            ctx.binding.tear_down();
            ctx.presence.transition(Presence::Absent);
            absence_reported = false;

            let outcome = churn.detached(Instant::now());
            if outcome.log_edge {
                let reason = detach
                    .expect("classify_detach returned Some above")
                    .as_str();
                // `warn`, not `error`. A link coming and going is the weather
                // in a mesh daemon, and a cable unplugged for two seconds does
                // not need a human. If it stays away,
                // `report_sustained_absence` says so at `error` once the
                // bring-up window is out. Health is the immediate signal and
                // does not wait — `Degraded` publishes on this edge.
                match ctx.policy {
                    AbsencePolicy::Optional => info!(
                        transport_id = %ctx.transport_id,
                        interface = %ctx.interface,
                        reason,
                        "Ethernet interface detached (optional)"
                    ),
                    AbsencePolicy::Required => warn!(
                        transport_id = %ctx.transport_id,
                        interface = %ctx.interface,
                        reason,
                        "Ethernet interface detached"
                    ),
                }
            }
            if outcome.entered_churn {
                warn!(
                    transport_id = %ctx.transport_id,
                    interface = %ctx.interface,
                    consecutive = churn.streak(),
                    "Ethernet binding keeps dying immediately after binding; \
                     backing off and holding health until one lasts"
                );
            }
            if outcome.retract && !publish_presence(&ctx, false) {
                unpublished = Some(false);
            }
            if let Some(backoff) = outcome.backoff {
                tokio::time::sleep(backoff).await;
            }
            continue;
        }

        // Absent. Absence itself does not back off — there is nothing to poll
        // but the cheap presence probe. Only a *failed bind* backs off.
        //
        // The deadline check sits ahead of the presence probe so it covers
        // both shapes of absence: an interface that is not there, and one that
        // is there and refuses to bind. The second is the one that will not
        // fix itself, so it is the one that most needs saying out loud.
        if !absence_reported {
            absence_reported = report_sustained_absence(&ctx);
        }

        if !interface_present(&ctx.interface) {
            continue;
        }

        match bind_and_spawn(&ctx).await {
            Ok(()) => {
                if churn.bound(Instant::now()).announce {
                    info!(
                        transport_id = %ctx.transport_id,
                        interface = %ctx.interface,
                        "Ethernet interface recovered"
                    );
                    if !publish_presence(&ctx, true) {
                        unpublished = Some(true);
                    }
                }
            }
            Err(e) => {
                // `bind_and_spawn` has already reverted presence to Absent.
                if matches!(e, TransportError::InterfaceUnavailable { .. }) {
                    // Raced with a detach between the probe and the bind. No
                    // backoff and no log: the next tick re-probes.
                    //
                    // And no `record_attempt` either — the counter below gates
                    // the only log a genuine bind fault ever gets, on
                    // `attempts == 1`. Charging absence races to it means a
                    // flap followed by a real fault (CAP_NET_RAW dropped, no
                    // free BPF device) is never reported at all, and the
                    // operator gets `report_sustained_absence`'s "still
                    // missing" instead — for an interface that is present.
                    continue;
                }
                let attempts = ctx.presence.record_attempt();
                if attempts == 1 {
                    error!(
                        transport_id = %ctx.transport_id,
                        interface = %ctx.interface,
                        error = %e,
                        "Ethernet interface is present but will not bind; retrying"
                    );
                }
                tokio::time::sleep(bind_backoff(attempts)).await;
            }
        }
    }
}

/// Why a bound interface stopped being usable.
///
/// The three probes the binder runs while `Present` are independent, and the
/// operator-facing distinction between them is the whole diagnostic value of
/// the detach line: "the cable is out" and "your netdev was recreated under
/// you" want different responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DetachReason {
    /// The name no longer resolves, or resolves to an interface that is down.
    Gone,
    /// The name still resolves, but to a *different device* than the one bound
    /// — a recreated veth, a reloaded phy. The socket is attached to something
    /// that no longer exists while the name looks fine.
    Replaced,
    /// The socket's loops have exited, so the descriptor under them is dead
    /// even though the interface is present and unchanged.
    SocketDied,
}

impl DetachReason {
    /// The `reason=` field of the detach log line.
    ///
    /// These strings are load-bearing: `testing/iface-binding/test.sh` greps
    /// them, and an operator greps them. Changing one is a change to an
    /// interface, not a wording tweak.
    fn as_str(self) -> &'static str {
        match self {
            Self::Gone => "interface down",
            Self::Replaced => "interface replaced",
            Self::SocketDied => "socket died",
        }
    }
}

/// Classify a bound transport's liveness from the three probe answers, or
/// `None` while it is still bound and healthy.
///
/// Extracted from the binder loop so the decision is testable without a
/// privileged bind. Reaching `Replaced` or `SocketDied` in a live daemon
/// requires a successful bind and then a specific external event — a netdev
/// recreated under the same name, or five consecutive receive errors — which
/// no unit test can arrange and which the integration suite cannot arrange
/// deterministically either (the netlink event from a delete is acted on
/// within microseconds, so `Gone` wins that race in practice). The inputs are
/// each tested on their own; this makes the branch between them total and
/// exhaustively tested, which is the half that was reachable.
///
/// Precedence is `Gone` before `Replaced` before `SocketDied`, and it matters:
/// an interface that has gone away has also, trivially, been "replaced" and
/// its socket is also dead, so the most specific true statement about *why*
/// has to win. Callers pass `replaced` already masked by `!gone`, so the
/// first arm is belt-and-braces rather than load-bearing — but a total
/// function should not depend on its caller having masked correctly.
fn classify_detach(gone: bool, replaced: bool, dead: bool) -> Option<DetachReason> {
    if gone {
        Some(DetachReason::Gone)
    } else if replaced {
        Some(DetachReason::Replaced)
    } else if dead {
        Some(DetachReason::SocketDied)
    } else {
        None
    }
}

/// Report an absence that has outlasted [`ABSENCE_ERROR_AFTER`], once.
///
/// Returns `true` once the report has been made, so the caller stops asking.
///
/// A required interface still missing past the window is no longer a race
/// against a radio or a container: it is a fault an operator has to fix, and
/// it reads as one. Optional interfaces are silent here by definition —
/// `optional` is the statement that this interface's absence is normal.
///
/// Said **once**. This used to be a 1 m / 10 m / 1 h ladder that re-announced
/// the same fact at rising severity and then went permanently quiet, which
/// got both halves wrong: it used the log as a state store for something
/// `show_transports` and node health already publish continuously, and it
/// stopped mentioning a live fault after an hour. Duration belongs in
/// `interface.since_secs`; the log's job is to say the thing once, when it
/// becomes true.
fn report_sustained_absence(ctx: &Arc<BinderContext>) -> bool {
    let absent_for = ctx.presence.since();
    if absent_for < ABSENCE_ERROR_AFTER {
        return false;
    }
    if ctx.policy.is_optional() {
        // The window passed; there is simply nothing to say. Return `true` so
        // the caller stops re-checking the clock for the rest of the episode.
        return true;
    }
    // Deliberately not prefixed "Ethernet interface absent": that is the edge
    // line's opening, and sharing it makes the two indistinguishable to
    // anything grepping the log — an operator, or the suite that asserts the
    // edge is logged once.
    error!(
        transport_id = %ctx.transport_id,
        interface = %ctx.interface,
        absent_secs = absent_for.as_secs(),
        "Ethernet interface still missing past the bring-up window; \
         node is degraded until it returns"
    );
    true
}

// ============================================================================
// Receive Loop
// ============================================================================

/// Ethernet receive loop — runs as a spawned task.
///
/// Returns on a dead socket (see [`RECV_ERROR_EXIT_THRESHOLD`]); the binder
/// notices the finished task, tears the binding down, and rebinds.
async fn ethernet_receive_loop(
    socket: Arc<AsyncPacketSocket>,
    transport_id: TransportId,
    packet_tx: PacketTx,
    mtu: u16,
    listen_enabled: bool,
    neighbor_buffer: Arc<NeighborBuffer>,
    stats: Arc<EthernetStats>,
) {
    // Buffer with headroom: frame type prefix + MTU + some extra
    let mut buf = vec![0u8; mtu as usize + 100];
    let mut consecutive_errors: u32 = 0;

    debug!(transport_id = %transport_id, "Ethernet receive loop starting");

    loop {
        match socket.recv_from(&mut buf).await {
            Ok((len, src_mac)) => {
                consecutive_errors = 0;
                if len == 0 {
                    continue;
                }

                stats.record_recv(len);

                let frame_type = buf[0];
                match frame_type {
                    FRAME_TYPE_DATA => {
                        // Data frame: [type:1][length:2 LE][payload:N]
                        // Use the length field to trim Ethernet minimum-frame padding.
                        if len < 3 {
                            trace!("Data frame too short ({len} bytes), ignoring");
                            continue;
                        }
                        let payload_len = u16::from_le_bytes([buf[1], buf[2]]) as usize;
                        if payload_len > len - 3 {
                            trace!(
                                "Data frame length field ({payload_len}) exceeds \
                                 available bytes ({}), ignoring",
                                len - 3
                            );
                            continue;
                        }
                        let data = buf[3..3 + payload_len].to_vec();
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
                consecutive_errors += 1;
                // First of a streak only: the rest are the same fact repeated.
                if consecutive_errors == 1 {
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "Ethernet receive error"
                    );
                }
                if consecutive_errors >= RECV_ERROR_EXIT_THRESHOLD {
                    warn!(
                        transport_id = %transport_id,
                        errors = consecutive_errors,
                        "Ethernet receive loop giving up on this socket; \
                         handing back to the interface binder"
                    );
                    break;
                }
                tokio::time::sleep(Duration::from_millis(
                    100 * u64::from(consecutive_errors.min(10)),
                ))
                .await;
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
/// Exits after [`BEACON_ERROR_EXIT_THRESHOLD`] consecutive send failures. The
/// stale-socket reopen this loop used to perform itself (an ENXIO special case
/// for veth pairs destroyed and recreated under a live socket) now belongs to
/// the binder: the loop's exit is the detach signal, and the rebind is one
/// mechanism for every cause rather than one hack per symptom. Beacons pause
/// while the interface is absent because the task simply does not exist then.
async fn beacon_sender_loop(
    socket: Arc<AsyncPacketSocket>,
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

                // Log only the first error in a streak to avoid log spam
                if consecutive_errors == 1 {
                    warn!(
                        transport_id = %transport_id,
                        error = %e,
                        "Failed to send beacon"
                    );
                }

                if consecutive_errors >= BEACON_ERROR_EXIT_THRESHOLD {
                    info!(
                        transport_id = %transport_id,
                        consecutive_errors,
                        "Beacon socket looks dead; handing back to the interface binder"
                    );
                    break;
                }
            }
        }
    }

    debug!(transport_id = %transport_id, "Beacon sender stopped");
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

    #[test]
    fn test_data_frame_padding_trimmed() {
        // Simulate Ethernet minimum-frame padding: a 4-byte payload produces
        // a 7-byte frame (type + len + payload), padded to 46 bytes by NIC.
        let payload = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let payload_len = payload.len() as u16;

        // Build frame as sender would
        let mut frame = Vec::with_capacity(3 + payload.len());
        frame.push(FRAME_TYPE_DATA);
        frame.extend_from_slice(&payload_len.to_le_bytes());
        frame.extend_from_slice(&payload);

        // Simulate NIC padding to 46 bytes
        frame.resize(46, 0x00);

        // Receiver extracts using length field
        let recv_len = u16::from_le_bytes([frame[1], frame[2]]) as usize;
        let extracted = &frame[3..3 + recv_len];
        assert_eq!(extracted, &[0xAA, 0xBB, 0xCC, 0xDD]);
    }

    #[test]
    fn test_beacon_size() {
        assert_eq!(neighbor::BEACON_SIZE, 34);
    }

    // ── Dynamic interface binding ─────────────────────────────────────────

    fn absent_transport(optional: bool) -> (EthernetTransport, super::super::PacketRx) {
        // A name no host has. `fips` is not a valid netdev prefix anywhere and
        // the suffix keeps it clear of the test harness's own veth pairs.
        let config = EthernetConfig {
            interface: "fips-absent-x0".to_string(),
            ethertype: None,
            mtu: None,
            recv_buf_size: None,
            send_buf_size: None,
            listen: Some(true),
            announce: Some(false),
            auto_connect: None,
            accept_connections: None,
            beacon_interval_secs: None,
            optional: Some(optional),
        };
        let (tx, rx) = super::super::packet_channel(8);
        (
            EthernetTransport::new(TransportId::new(1), Some("lab".into()), config, tx),
            rx,
        )
    }

    #[tokio::test]
    async fn a_missing_interface_starts_absent_rather_than_failing() {
        // The boot race, at the mechanism level: `start_async` succeeds with
        // the transport absent. Failing here is what made an OpenWrt node that
        // booted before wifi stay deaf for the life of the process.
        let (mut eth, _rx) = absent_transport(false);
        assert_eq!(eth.presence(), Presence::Absent);

        eth.start_async()
            .await
            .expect("absence is not a start failure");

        assert_eq!(eth.state(), TransportState::Up);
        assert_eq!(eth.presence(), Presence::Absent);
        assert!(eth.local_mac().is_none());
        assert_eq!(eth.presence_state().binds(), 0);

        eth.stop_async().await.expect("stop");
    }

    #[tokio::test]
    async fn sending_while_absent_reports_absence_not_not_started() {
        // A caller must be able to tell an interface that is away from a
        // transport that was never brought up.
        let (mut eth, _rx) = absent_transport(false);
        eth.start_async().await.expect("start");

        let addr = TransportAddr::from_bytes(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let err = eth.send_async(&addr, b"hello").await.unwrap_err();
        assert!(
            matches!(err, TransportError::InterfaceUnavailable { ref interface }
                if interface == "fips-absent-x0"),
            "expected InterfaceUnavailable, got {err:?}"
        );

        eth.stop_async().await.expect("stop");
    }

    #[tokio::test]
    async fn the_absence_policy_comes_from_config() {
        let (required, _a) = absent_transport(false);
        assert_eq!(required.absence_policy(), AbsencePolicy::Required);
        let (optional, _b) = absent_transport(true);
        assert_eq!(optional.absence_policy(), AbsencePolicy::Optional);
    }

    #[tokio::test]
    async fn absence_is_published_to_node_health() {
        // The edge the supervisor turns into `Degraded`.
        let (mut eth, _rx) = absent_transport(false);
        let (tx, mut presence_rx) = tokio::sync::mpsc::channel(4);
        eth.set_presence_tx(tx);

        eth.start_async().await.expect("start");

        let edge = presence_rx
            .try_recv()
            .expect("an absence edge is published");
        assert_eq!(edge.transport_id, TransportId::new(1));
        assert!(!edge.present);

        eth.stop_async().await.expect("stop");
    }

    #[tokio::test]
    async fn an_optional_interface_publishes_an_edge_that_does_not_move_health() {
        // `optional: true` is a statement about presence, and its whole health
        // effect is this: a dock adapter that is not plugged in must not make
        // the node report Degraded.
        //
        // It is not a statement about the *edge*. The edge still goes out,
        // carrying `health_relevant: false`, because the consumer derives the
        // node's egress MTU floor from the same channel and an optional
        // interface changes the bound set exactly as a required one does.
        // Suppressing the edge here — which is what this used to do — left the
        // TUN MSS clamp stale for every optional transport.
        let (mut eth, _rx) = absent_transport(true);
        let (tx, mut presence_rx) = tokio::sync::mpsc::channel(4);
        eth.set_presence_tx(tx);

        eth.start_async().await.expect("start");

        let edge = presence_rx
            .try_recv()
            .expect("an optional interface still publishes its edge");
        assert_eq!(edge.transport_id, TransportId::new(1));
        assert!(!edge.present);
        assert!(
            !edge.health_relevant,
            "an optional interface must not report absence to node health"
        );

        eth.stop_async().await.expect("stop");
    }

    #[tokio::test]
    async fn a_required_interface_publishes_an_edge_that_moves_health() {
        // The other half of the policy, pinned alongside it so the pair cannot
        // drift into agreeing.
        let (mut eth, _rx) = absent_transport(false);
        let (tx, mut presence_rx) = tokio::sync::mpsc::channel(4);
        eth.set_presence_tx(tx);

        eth.start_async().await.expect("start");

        let edge = presence_rx
            .try_recv()
            .expect("an absence edge is published");
        assert!(!edge.present);
        assert!(edge.health_relevant);

        eth.stop_async().await.expect("stop");
    }

    #[tokio::test]
    async fn the_binder_stops_with_the_transport() {
        // Teardown must abort the binder first: a rebind racing a stop would
        // hand the node a socket nothing is going to read.
        let (mut eth, _rx) = absent_transport(true);
        eth.start_async().await.expect("start");
        eth.stop_async().await.expect("stop");
        assert_eq!(eth.state(), TransportState::Down);
        assert_eq!(eth.presence(), Presence::Absent);
        assert!(
            eth.stop_async().await.is_err(),
            "stopping twice is an error"
        );
    }

    #[tokio::test]
    async fn a_bind_fault_still_fails_the_start() {
        // Absence is a state the transport waits out; a fault is not. No
        // CAP_NET_RAW (Linux) or no readable /dev/bpf* (macOS) will not fix
        // itself, so it must fail the start exactly as it did before dynamic
        // binding existed — otherwise a node deployed without the capability
        // retries a socket it can never open, forever, behind a `Degraded`
        // nobody is watching.
        //
        // Loopback is the vehicle: it is present on every host, so the
        // presence probe passes and the *bind* is what fails.
        //
        // Whether it fails is a property of the host, not of the code: an
        // unprivileged CI runner is refused, while root — or a developer
        // machine whose /dev/bpf* is group-readable — is not. Establish that
        // as a precondition by opening the socket directly rather than
        // branching inside the assertion, so this test either exercises the
        // fail-fast path or declares itself inapplicable.
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        assert!(
            io::interface_present(loopback),
            "loopback must be present for this test to mean anything"
        );
        // Whether the socket opens splits the test into two halves, and both
        // assert. Returning early on the privileged host — which is what this
        // used to do — made the test vacuous as root and on any developer
        // machine with a group-readable /dev/bpf*, so the fail-fast path it is
        // named for went unchecked exactly where someone was most likely to be
        // running it.
        let can_open = PacketSocket::open(loopback, 0x2121).is_ok();

        let config = EthernetConfig {
            interface: loopback.to_string(),
            ethertype: None,
            mtu: None,
            recv_buf_size: None,
            send_buf_size: None,
            listen: Some(true),
            announce: Some(false),
            auto_connect: None,
            accept_connections: None,
            beacon_interval_secs: None,
            optional: None,
        };
        let (tx, _rx) = super::super::packet_channel(8);
        let mut eth = EthernetTransport::new(TransportId::new(9), None, config, tx);

        if can_open {
            // The privileged half. A present, bindable interface binds inline
            // and reports itself bound before `start_async` returns — which is
            // the ordinary case on a booted router, and which no other unit
            // test reaches: every other one here uses an interface that does
            // not exist, so the bind-success path has no unit coverage at all
            // without this branch.
            eth.start_async()
                .await
                .expect("a present, bindable interface must start");
            assert_eq!(
                eth.presence(),
                Presence::Present,
                "a bind that succeeded must leave the transport present"
            );
            assert!(
                eth.binding.socket().is_some(),
                "a present transport must hold its socket"
            );
            eth.stop_async().await.expect("stop");
            return;
        }

        let err = eth
            .start_async()
            .await
            .expect_err("an unprivileged raw socket must not start");
        assert!(
            !matches!(err, TransportError::InterfaceUnavailable { .. }),
            "a permission fault must not be reported as absence: {err:?}"
        );
        assert_eq!(
            eth.state(),
            TransportState::Configured,
            "a failed start must not leave the transport half-up"
        );
        assert_eq!(
            eth.presence(),
            Presence::Absent,
            "a failed bind must not leave presence parked in `binding`"
        );
    }

    #[tokio::test]
    async fn waiting_for_an_interface_never_looks_like_binding() {
        // `Binding` means an attempt is in flight. An interface that is simply
        // not there is not an attempt, so the probe sits ahead of the
        // transition and a permanently-absent transport must read `absent` on
        // every poll — never a `binding` that never resolves, and never a
        // climbing failed-attempt count for binds it never tried.
        let (mut eth, _rx) = absent_transport(false);
        eth.start_async().await.expect("start");

        // Long enough for the binder to have polled several times.
        tokio::time::sleep(Duration::from_millis(2500)).await;

        assert_eq!(eth.presence(), Presence::Absent);
        assert_eq!(eth.presence_state().binds(), 0);
        assert_eq!(
            eth.presence_state().attempts(),
            0,
            "absence is not a failed attempt"
        );

        eth.stop_async().await.expect("stop");
    }

    #[tokio::test]
    async fn a_poisoned_binding_does_not_strand_the_transport() {
        // The transport-side twin of the presence-state poisoning test:
        // `.ok()` on these locks would report the socket as gone and the
        // tasks as dead, which is the destructive direction — a binder that
        // tears down and rebinds every second while `tear_down` silently
        // declines to abort anything, leaking a receive loop per cycle.
        let (mut eth, _rx) = absent_transport(false);
        eth.start_async().await.expect("start");

        let binding = Arc::clone(&eth.binding);
        let panicked = std::thread::spawn(move || {
            let _guard = binding.tasks.lock().unwrap();
            panic!("poison the task list while holding it");
        })
        .join();
        assert!(panicked.is_err(), "the helper thread was supposed to panic");
        assert!(eth.binding.tasks.is_poisoned());

        // Still answerable, and — the part that matters — it answers the way
        // that keeps the transport recoverable. Discarding this, which the
        // test used to do, left the whole point unasserted: treating a
        // poisoned lock as "tasks are alive" would make the binder believe a
        // dead binding is healthy and never rebind it, and treating it as an
        // error would strand the transport instead. `false` is what routes it
        // back through detach and rebind.
        assert!(
            !eth.binding.tasks_alive(),
            "a poisoned task lock must read as a dead binding, so the binder \
             rebinds rather than either believing it healthy or giving up"
        );
        eth.stop_async().await.expect("stop");
        assert_eq!(eth.state(), TransportState::Down);
    }

    #[test]
    fn the_probe_floor_sits_under_the_poll_interval() {
        // The floor coalesces a firehose event source (`PF_ROUTE` on macOS has
        // no group filter, so it delivers every routing message on the box)
        // without becoming the thing that governs detection latency. If it
        // ever reached the poll interval it would be the cadence rather than a
        // bound on it.
        assert!(MIN_PROBE_INTERVAL < WATCH_INTERVAL);
        assert!(
            !MIN_PROBE_INTERVAL.is_zero(),
            "a zero floor coalesces nothing"
        );
    }

    #[test]
    fn a_present_probe_answers_for_loopback_and_refuses_a_fiction() {
        // `lo` is up on every host this test runs on, and the fictional name
        // is the negative control. Together they pin that the probe reads
        // flags rather than merely answering "the call worked".
        assert!(io::interface_present("lo") || io::interface_present("lo0"));
        assert!(!io::interface_present("fips-absent-x0"));
    }

    #[test]
    fn a_device_index_identifies_the_interface_a_binding_holds() {
        // A name is not a device. Both backends bind by index, so a netdev
        // deleted and recreated under the same name leaves the socket attached
        // to nothing while the name resolves perfectly well — and nothing else
        // notices: a stale AF_PACKET socket never becomes readable, so the
        // receive loop never errors and never exits, and send failures go to
        // the caller rather than to the binder. Comparing the index is the
        // only thing standing between a listen-only node and sitting
        // `present` and deaf after a `wifi reload`.
        let lo = if io::interface_present("lo") {
            "lo"
        } else {
            "lo0"
        };
        let index = io::interface_index(lo).expect("loopback has an index");
        assert!(index > 0);
        assert_eq!(io::interface_index("fips-absent-x0"), None);

        let binding = Binding::new(1499);
        // Nothing bound: there is no identity to have changed.
        assert!(!binding.device_replaced(lo));

        binding.bound_index.store(index, Ordering::Relaxed);
        assert!(!binding.device_replaced(lo), "same device, same index");

        binding.bound_index.store(index + 1000, Ordering::Relaxed);
        assert!(
            binding.device_replaced(lo),
            "a different index under the same name is different hardware"
        );

        // A name that has gone is absence, which the presence probe reports
        // more precisely; this check must not also claim it.
        assert!(!binding.device_replaced("fips-absent-x0"));
    }

    #[tokio::test]
    async fn teardown_forgets_the_device_it_was_bound_to() {
        // A stale index surviving teardown would make the next binding look
        // replaced the moment it came up.
        let (mut eth, _rx) = absent_transport(false);
        eth.binding.bound_index.store(12345, Ordering::Relaxed);
        eth.start_async().await.expect("start");
        eth.stop_async().await.expect("stop");
        assert_eq!(eth.binding.bound_index.load(Ordering::Relaxed), 0);
    }

    /// An interface with **no addresses at all** is still visible to the
    /// presence probe.
    ///
    /// This is the assumption the whole mechanism rests on and the one no
    /// other test reaches. `interface_present` walks `getifaddrs` and reads
    /// `ifa_flags`; neither the presence of a link-level entry for an
    /// address-less interface nor the flags on it are specified anywhere —
    /// `getifaddrs` is not in POSIX, glibc synthesizes an `AF_PACKET` entry
    /// per interface from netlink, and musl reimplements the whole call
    /// independently. Loopback cannot test this: it has `127.0.0.1`, so
    /// probing it asks "does `getifaddrs` work", which was never in doubt.
    ///
    /// And FIPS is squarely in that corner by design. `fips-mesh0` and
    /// `fips-ap0` on OpenWrt are deliberately unbridged with no IP
    /// configuration — the transport speaks raw frames and never wants an
    /// address — and OpenWrt is musl. If an address-less interface is
    /// invisible here, those transports never bind, and because they ship
    /// `optional: true` they never say so: the router reports `Running`, the
    /// 802.11s link forms anyway because that is mac80211 rather than the
    /// daemon, and the node reaches nothing. That is the original bug, whole,
    /// on the platform this was written for.
    ///
    /// Creating such an interface needs `CAP_NET_ADMIN`, so CI makes one and
    /// names it here rather than the test conjuring it. Absent the variable
    /// there is nothing to assert — which is why the CI step that provides it
    /// fails loudly rather than skipping, and why it checks that the interface
    /// really has no address: the kernel hands an IPv6 link-local to anything
    /// that comes up, and the first version of that fixture tested a
    /// perfectly well-addressed interface without anyone noticing.
    #[test]
    fn an_interface_with_no_addresses_is_still_present() {
        // A silent skip is how this test spent its life green without ever
        // running: no fixture, early return, pass. It still has to skip on a
        // developer machine that has no address-less interface, so the guard
        // is the runner declaring that it *does* — if the fixture step is
        // removed or renamed, this fails instead of quietly covering nothing.
        let Ok(iface) = std::env::var("FIPS_TEST_ADDRLESS_IFACE") else {
            assert!(
                std::env::var_os("FIPS_TEST_REQUIRE_FIXTURES").is_none(),
                "this runner sets FIPS_TEST_REQUIRE_FIXTURES but not \
                 FIPS_TEST_ADDRLESS_IFACE: the fixture step did not run, and \
                 the musl/glibc getifaddrs contract this pins went unchecked"
            );
            return;
        };
        assert!(
            io::interface_present(&iface),
            "interface {iface} has no addresses and must still be visible to \
             the presence probe; if this fails on musl, every address-less \
             interface on OpenWrt is invisible to interface binding"
        );
        // Carrier is asserted rather than discarded, but the expected answer
        // is `true`, not `false`: a Linux `dummy` brought up reports
        // `UP,LOWER_UP`, so `IFF_RUNNING` is set and it has carrier. The
        // comment this replaces claimed the opposite — "up but not running" —
        // which is why the result was discarded rather than checked.
        //
        // So this fixture pins address-less *presence*, and cannot demonstrate
        // the presence-vs-carrier split; an interface that is up with no
        // carrier is a bridge with nothing plugged in, which no fixture here
        // creates. `carrier_is_reported_separately_from_presence` pins that
        // split from the other side, on a missing interface having neither.
        //
        // Linux only, because the expected answer is a property of the fixture
        // device rather than of the code: a `dummy` that is up reports
        // `IFF_RUNNING`, and macOS's `feth` has its own semantics that are not
        // pinned here. What both platforms do assert is the part that matters
        // — an interface with no addresses is still *present*.
        #[cfg(target_os = "linux")]
        assert!(
            io::interface_carrier(&iface),
            "a dummy interface that is up reports IFF_RUNNING; if this fails, \
             the fixture is no longer a dummy and what it pins has changed"
        );
        // And it resolves to an index, which is what a bind would attach to.
        assert!(io::interface_index(&iface).is_some());
    }

    #[test]
    fn carrier_is_reported_separately_from_presence() {
        // Presence is `IFF_UP`; carrier is `IFF_RUNNING` and is reported, not
        // acted on. Loopback carries both, which pins that the two probes read
        // different flags rather than one calling the other. The negative
        // control pins that a missing interface has neither — "no carrier" and
        // "no interface" must not be confused, and presence is what tells them
        // apart.
        let lo = if io::interface_present("lo") {
            "lo"
        } else {
            "lo0"
        };
        assert!(io::interface_present(lo));
        assert!(io::interface_carrier(lo));
        assert!(!io::interface_carrier("fips-absent-x0"));
    }

    #[tokio::test]
    async fn an_absent_interface_does_not_clamp_the_node_mtu() {
        // `is_operational` means started, not bound. A transport whose
        // interface has never existed reports its configured MTU, so a caller
        // that filters on `is_operational` lets absent hardware set a value
        // for the whole node — `transport_mtu`, and with it the node's IPv6
        // MTU, was doing exactly that.
        let (mut eth, _rx) = absent_transport(false);
        eth.start_async().await.expect("start");

        let handle = super::super::TransportHandle::Ethernet(eth);
        assert!(
            handle.is_operational(),
            "an absent transport is still started"
        );
        assert!(
            !handle.is_bound(),
            "an absent transport must not count as usable"
        );
        assert!(
            handle.mtu() > 0,
            "it still reports an MTU, which is the trap"
        );
    }

    #[tokio::test]
    async fn a_dropped_transport_does_not_leave_its_binder_running() {
        // A handle can be dropped without ever being stopped — one the
        // supervisor never spawns, an unwind through start(). Without `Drop`
        // the binder outlives the object and goes on opening raw sockets on an
        // interface nobody reads, for the life of the process.
        let (mut eth, _rx) = absent_transport(false);
        eth.start_async().await.expect("start");

        let shutdown = Arc::clone(&eth.shutdown);
        let binder = eth
            .binder_task
            .as_ref()
            .expect("binder spawned")
            .abort_handle();
        assert!(!shutdown.load(Ordering::SeqCst));

        drop(eth);

        assert!(
            shutdown.load(Ordering::SeqCst),
            "drop must raise the stop flag"
        );
        // Give the aborted task a moment to be reaped by the runtime.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(binder.is_finished(), "drop must stop the binder");
    }

    #[tokio::test]
    async fn a_stop_racing_a_bind_leaves_nothing_behind() {
        // `bind_now` has no await points, so an abort issued while it runs
        // takes effect only afterwards — after the socket and tasks are
        // stored. The stop flag is what makes "teardown cleared an empty
        // binding, then the binder filled it" impossible to end in a live
        // receive loop on a socket nothing owns.
        let (mut eth, _rx) = absent_transport(false);
        eth.start_async().await.expect("start");
        eth.stop_async().await.expect("stop");

        assert!(eth.shutdown.load(Ordering::SeqCst));
        assert!(
            eth.binding.socket().is_none(),
            "no socket may survive teardown"
        );
        assert!(!eth.binding.tasks_alive(), "no loop may survive teardown");

        // And a bind attempted after the stop refuses rather than publishing.
        let ctx = Arc::new(BinderContext {
            shutdown: Arc::clone(&eth.shutdown),
            transport_id: eth.transport_id,
            name: None,
            interface: eth.interface.clone(),
            config: eth.config.clone(),
            policy: eth.policy,
            packet_tx: eth.packet_tx.clone(),
            neighbor_buffer: eth.neighbor_buffer.clone(),
            stats: eth.stats.clone(),
            binding: eth.binding.clone(),
            presence: eth.presence.clone(),
            local_pubkey: None,
            presence_tx: None,
        });
        // Assert the *reason*, not merely that it errored. This transport's
        // interface does not exist, so `bind_and_spawn` refuses at its
        // presence probe — before it ever reaches the post-store shutdown
        // check. Asserting `is_err()` alone therefore proved nothing about
        // the stop flag: the assertion passed on absence, and would still
        // pass with the shutdown check deleted outright.
        //
        // What is covered here is the observable half of the race — stop
        // raises the flag before tearing down, and teardown leaves no socket
        // and no loops. The post-store check itself needs a bind that
        // *succeeds*, which needs a real bindable interface and the privilege
        // to open a raw socket on it; that path is exercised only under the
        // docker suite, and no unit test can reach it unprivileged.
        let err = bind_and_spawn(&ctx)
            .await
            .expect_err("a bind must not complete for a stopped transport");
        assert!(
            matches!(err, TransportError::InterfaceUnavailable { .. }),
            "expected the absence refusal, got {err:?} — if this ever becomes \
             a shutdown refusal, this test has started covering the race it \
             is named for and the comment above is stale"
        );
        assert!(eth.binding.socket().is_none());
    }

    /// A stop that lands while a bind is in flight is cleaned up by the bind,
    /// not left running.
    ///
    /// `bind_now` has no await points, so an abort issued while it runs takes
    /// effect only afterwards — after the socket and tasks are stored. The
    /// post-store check is what makes "teardown cleared an empty binding, then
    /// the binder filled it" impossible to end in a live receive loop on a
    /// socket nothing owns.
    ///
    /// This needs a bind that *succeeds*, which needs privilege, so it is the
    /// one branch `a_stop_racing_a_bind_leaves_nothing_behind` cannot reach:
    /// that test's interface does not exist, so `bind_and_spawn` refuses at the
    /// presence probe long before this check.
    #[tokio::test]
    async fn a_bind_that_completes_after_a_stop_undoes_itself() {
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };

        if PacketSocket::open(loopback, 0x2121).is_err() {
            // Unprivileged: no bind can succeed, so there is no post-store
            // state to observe. Loud on a runner that claims otherwise, so
            // this cannot go quiet the way the fixture tests did.
            assert!(
                std::env::var_os("FIPS_TEST_PRIVILEGED").is_none(),
                "this runner declares FIPS_TEST_PRIVILEGED but cannot open a \
                 raw socket on {loopback}: the post-store shutdown check went \
                 unexercised"
            );
            return;
        }

        let (mut eth, _rx) = absent_transport(false);
        eth.interface = loopback.to_string();
        eth.shutdown.store(true, Ordering::SeqCst);

        let ctx = Arc::new(BinderContext {
            shutdown: Arc::clone(&eth.shutdown),
            transport_id: eth.transport_id,
            name: None,
            interface: eth.interface.clone(),
            config: eth.config.clone(),
            policy: eth.policy,
            packet_tx: eth.packet_tx.clone(),
            neighbor_buffer: eth.neighbor_buffer.clone(),
            stats: eth.stats.clone(),
            binding: eth.binding.clone(),
            presence: eth.presence.clone(),
            local_pubkey: None,
            presence_tx: None,
        });

        let err = bind_and_spawn(&ctx)
            .await
            .expect_err("a bind must not stand for a stopped transport");
        assert!(
            matches!(err, TransportError::NotStarted),
            "expected the shutdown refusal, got {err:?}"
        );
        assert!(
            eth.binding.socket().is_none(),
            "the bind must undo its own socket when it loses the stop race"
        );
        assert!(
            !eth.binding.tasks_alive(),
            "and its own loops, or a receive task outlives the transport"
        );
        assert_eq!(eth.presence.presence(), Presence::Absent);
    }

    #[test]
    fn every_detach_classification_is_total_and_ordered() {
        // All eight probe combinations, because the branch between them was
        // the untested part. `Replaced` and `SocketDied` are otherwise
        // unreachable from a test: both need a bind that succeeded and then a
        // specific external event, and the integration suite cannot arrange
        // the recreate deterministically either — the netlink event from a
        // delete is acted on within microseconds, so `Gone` wins that race.
        use DetachReason::{Gone, Replaced, SocketDied};

        // (gone, replaced, dead) -> expected
        let cases = [
            ((false, false, false), None),
            ((false, false, true), Some(SocketDied)),
            ((false, true, false), Some(Replaced)),
            ((false, true, true), Some(Replaced)),
            ((true, false, false), Some(Gone)),
            ((true, false, true), Some(Gone)),
            ((true, true, false), Some(Gone)),
            ((true, true, true), Some(Gone)),
        ];
        for ((gone, replaced, dead), expected) in cases {
            assert_eq!(
                classify_detach(gone, replaced, dead),
                expected,
                "classify_detach({gone}, {replaced}, {dead})"
            );
        }
    }

    #[test]
    fn a_healthy_binding_is_the_only_unclassified_state() {
        // The gate the loop actually uses: anything other than all-three-false
        // is a detach. Stated separately from the table so a future fourth
        // probe cannot be added and silently default to "still bound".
        assert!(classify_detach(false, false, false).is_none());
        for (gone, replaced, dead) in [
            (true, false, false),
            (false, true, false),
            (false, false, true),
        ] {
            assert!(
                classify_detach(gone, replaced, dead).is_some(),
                "a failing probe must detach"
            );
        }
    }

    #[test]
    fn detach_reason_labels_are_the_ones_greppers_expect() {
        // These strings are an interface. `testing/iface-binding/test.sh`
        // greps `reason="interface replaced"`, and operators grep the others.
        assert_eq!(DetachReason::Gone.as_str(), "interface down");
        assert_eq!(DetachReason::Replaced.as_str(), "interface replaced");
        assert_eq!(DetachReason::SocketDied.as_str(), "socket died");

        // And they are distinct, or a grep cannot tell two causes apart.
        let labels = std::collections::HashSet::from([
            DetachReason::Gone.as_str(),
            DetachReason::Replaced.as_str(),
            DetachReason::SocketDied.as_str(),
        ]);
        assert_eq!(labels.len(), 3);
    }

    #[tokio::test]
    async fn a_restarted_transport_starts_its_binder_again() {
        // `start_async` clears the stop flag so a restart is not immediately
        // undone by the previous run's shutdown. Nothing tested the second
        // start at all: `the_binder_stops_with_the_transport` only asserts a
        // second *stop* errors, so a transport that could never be restarted
        // would have passed everything here.
        let (mut eth, _rx) = absent_transport(false);

        eth.start_async().await.expect("first start");
        eth.stop_async().await.expect("stop");
        assert!(eth.shutdown.load(Ordering::SeqCst), "stop raises the flag");

        eth.start_async()
            .await
            .expect("a stopped transport restarts");
        assert!(
            !eth.shutdown.load(Ordering::SeqCst),
            "the restart must clear the previous run's stop, or the new binder \
             tears its own binding down on its first pass"
        );
        assert_eq!(eth.state(), TransportState::Up);

        eth.stop_async().await.expect("stop again");
    }

    #[tokio::test]
    async fn the_absence_deadline_is_measured_from_the_start() {
        // `PresenceState::new` stamps the episode clock at construction, but
        // construction and `start_async` need not be adjacent — config load and
        // supervisor staging sit between them. Without the restamp a transport
        // staged for longer than the window reports sustained absence on its
        // very first binder tick, having given the interface no bring-up window
        // at all, which is the one thing the window exists to provide.
        let (mut eth, _rx) = absent_transport(false);

        // Stand in for a slow bring-up by ageing the clock past the deadline.
        std::thread::sleep(Duration::from_millis(20));
        let staged_for = eth.presence.since();

        eth.start_async().await.expect("start");
        assert!(
            eth.presence.since() < staged_for,
            "the episode clock must restart at start, not run from whenever \
             the object happened to be constructed"
        );

        eth.stop_async().await.expect("stop");
    }

    #[tokio::test]
    async fn a_refused_presence_edge_is_delivered_once_there_is_room() {
        // The retry slot, which nothing followed through. The existing test
        // fills the channel and asserts the binder keeps running, then drops
        // the receiver — so a slot that captured the edge and never re-sent it
        // would pass, and health would sit on a stale level forever.
        let (mut eth, _rx) = absent_transport(false);
        let (tx, mut presence_rx) = tokio::sync::mpsc::channel(1);
        eth.set_presence_tx(tx.clone());

        // Occupy the only slot, so the start edge is refused on its way out.
        tx.try_send(TransportPresence {
            transport_id: TransportId::new(99),
            present: true,
            health_relevant: true,
        })
        .expect("the one slot");

        eth.start_async().await.expect("start");

        // Drain the squatter. The binder now has room on its next pass.
        let squatter = presence_rx.recv().await.expect("squatter");
        assert_eq!(squatter.transport_id, TransportId::new(99));

        let edge = tokio::time::timeout(Duration::from_secs(5), presence_rx.recv())
            .await
            .expect("the refused edge must be retried, not dropped")
            .expect("channel open");
        assert_eq!(edge.transport_id, TransportId::new(1));
        assert!(!edge.present, "the retried edge is the absence it refused");

        eth.stop_async().await.expect("stop");
    }

    #[tokio::test]
    async fn a_full_presence_channel_does_not_block_the_binder() {
        // The health channel must not be able to deadlock the machine whose
        // health it carries. `send().await` on a bounded channel could: a
        // receiver that is slow, not yet running, or gone parked the binder
        // mid-publish and froze the interface in whatever state it held.
        let (mut eth, _rx) = absent_transport(false);
        let (tx, presence_rx) = tokio::sync::mpsc::channel(1);
        eth.set_presence_tx(tx.clone());

        // Fill the channel, then never drain it.
        tx.try_send(TransportPresence {
            transport_id: TransportId::new(1),
            present: true,
            health_relevant: true,
        })
        .expect("first slot");

        // With a blocking publish this start would hang forever.
        let started = tokio::time::timeout(Duration::from_secs(5), eth.start_async())
            .await
            .expect("start must not block on a full presence channel");
        started.expect("start");

        // The binder keeps polling despite the refused edge.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(eth.presence(), Presence::Absent);

        drop(presence_rx);
        eth.stop_async().await.expect("stop");
    }
}
