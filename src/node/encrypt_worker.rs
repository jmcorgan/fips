//! Off-task FMP encrypt + UDP send worker.
//!
//! **Unix only** — the per-worker send loop issues direct
//! `sendmmsg(2)` / `sendmsg(2)+UDP_GSO` calls on raw file descriptors
//! via `AsRawFd`. On Windows the worker pool isn't spawned (see
//! `lifecycle.rs`) and the rx_loop's tokio-based send path remains
//! the canonical outbound route.
//!
//! The sender hot path of FIPS used to do every step of an outbound
//! packet — session lookup, FSP encrypt, datagram serialise, link
//! lookup, FMP encrypt, UDP `sendto` — sequentially on the single
//! `rx_loop` tokio task. At line rate that task pegs at 99.9% CPU on
//! one core while five other tokio workers sit at 6–40% each. The
//! send pipeline's measured cost breakdown (FIPS_PERF stats on AMD
//! Ryzen 7 7700, single-stream TCP at ~91 kpps):
//!
//! ```text
//! endpoint_send  ≈ 2170 ns/pkt   (whole handle_endpoint_data_command)
//!   fsp_encrypt  ≈  550 ns/pkt
//!   fmp_encrypt  ≈  550 ns/pkt
//!   udp_send     ≈  150 ns/pkt   (amortised sendmmsg)
//!   "other"      ≈  920 ns/pkt   (dispatch + state ops)
//! ```
//!
//! The two AEADs + the syscall are pure CPU work that can run on
//! another core; only the "other" 920 ns is genuinely serial because
//! it mutates per-session / per-peer state. Splitting the pipeline at
//! the FMP layer hands the rx_loop ~700 ns back per packet — at
//! 100 kpps that's ~70 ms/s of one core, which is exactly what we
//! need to unstick the single-task bottleneck.
//!
//! The worker takes a pre-cooked [`FmpSendJob`] (pre-reserved counter,
//! a fully-built wire buffer `[16-byte FMP header][inner plaintext]`
//! with TAG_SIZE trailing capacity, a cloned cipher, an `AsyncUdpSocket`
//! handle, and the destination `SocketAddr`) and does the AEAD
//! `seal_in_place_separate_tag` + a single `sendmsg(2) + UDP_SEGMENT`
//! (Linux GSO) or `sendmmsg(2)` fallback. It never touches `Node`
//! state, so any number of these can run in parallel against the same
//! peer.
//!
//! **UDP_GSO note** — the GSO path is verified end-to-end via a
//! loopback round-trip unit test (see `tests::gso_roundtrip_loopback`).
//! On a docker veth/bridge the perf gain from GSO is muted because the
//! kernel does software segmentation on egress and the veth peer-skb
//! cost dominates; on a real NIC (or `--network=host` benches) the
//! single skb walk through the TX stack lands the expected win.

// On Windows nothing inside this module is called (the pool isn't
// spawned in lifecycle::start). Silence the cascade of dead-code
// warnings rather than gate every function individually.
#![cfg_attr(not(unix), allow(dead_code))]

use crate::proto::fmp::wire::ESTABLISHED_HEADER_SIZE;
use crate::proto::fsp::wire::FSP_HEADER_SIZE;
use crate::transport::udp::io::AsyncUdpSocket;
#[cfg(not(target_os = "macos"))]
use crossbeam_channel::{Receiver, SendError, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
#[cfg(target_os = "macos")]
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::OnceLock;
#[cfg(target_os = "macos")]
use std::sync::{Condvar, Mutex};
use tracing::{debug, trace, warn};

/// A pre-cooked FMP-encrypt-and-send job. All state-touching work
/// (counter reservation, MMP/stats update) was already done on the
/// rx_loop before this was built; the worker only does the AEAD +
/// syscall.
///
/// **Wire-buf layout** — `wire_buf` is built on the rx_loop side as
/// the **final wire packet, minus the trailing AEAD tag**:
///
/// ```text
///   ┌──────────────────────────────┬────────────────────────────┐
///   │ FMP outer header (16 bytes)  │   inner plaintext (var)    │
///   └──────────────────────────────┴────────────────────────────┘
///   ^ wire_buf[0..16]                ^ wire_buf[16..]
///   used as AAD                      sealed in place
/// ```
///
/// Capacity is reserved for an additional 16-byte tag at the end so
/// the worker can `seal_in_place_separate_tag` on `wire_buf[16..]` and
/// then `wire_buf.extend_from_slice(&tag)` without re-growing. After
/// seal, `wire_buf` IS the wire packet — no second alloc / memcpy.
///
/// (Previous design used a separate `header: [u8; 16]` + `inner_plaintext:
/// Vec<u8>` and then memcpy'd header + ciphertext into a fresh `Vec`
/// inside the worker. That second alloc + ~1.5 KB memcpy per packet at
/// line rate cost ~150 MB/sec of memory bandwidth on the hot worker.)
pub(crate) struct FmpSendJob {
    /// Cloned FMP send cipher. `LessSafeKey` is `Clone` (`ring::aead`)
    /// — the clone is just a refcount bump on the inner key material.
    pub cipher: LessSafeKey,
    /// Pre-reserved monotonic counter (via `take_send_counter`).
    pub counter: u64,
    /// Pre-built wire buffer: `[16-byte FMP header][inner plaintext]`
    /// with TAG_SIZE bytes of trailing capacity reserved for the AEAD
    /// tag. The header bytes (`[0..16]`) double as both the AAD input
    /// and the prefix of the final wire packet — there is exactly one
    /// allocation per outbound packet (already incurred on the rx_loop
    /// path to build the inner header), reused end-to-end.
    pub wire_buf: Vec<u8>,
    /// Optional inner FSP AEAD operation to perform before the outer FMP seal.
    /// The rx_loop pre-reserves the FSP counter and lays out `wire_buf` so the
    /// FSP plaintext is the current tail. The worker seals that tail in place,
    /// appends the FSP tag, then seals the full FMP plaintext. This keeps both
    /// AEADs off the rx_loop while preserving FSP/FMP wire format.
    pub fsp_seal: Option<FspSealJob>,
    /// AsyncUdpSocket clone (internally `Arc<AsyncFd<UdpRawSocket>>`,
    /// so the clone is just a refcount bump). Used as the **fallback**
    /// send fd when no per-peer connected socket is available — i.e.
    /// the wildcard listen socket. Kernel serialises concurrent
    /// `sendto` calls so multiple workers sharing this handle is safe.
    pub socket: AsyncUdpSocket,
    /// Destination kernel `SocketAddr` — resolved on rx_loop side so
    /// the worker can skip the per-packet DNS / address parse. Used
    /// when sending via the listen socket (msg_name field of mmsghdr).
    /// Ignored when `connected_socket` is `Some` (the kernel knows
    /// the destination already).
    pub dest_addr: SocketAddr,
    /// **Unix connected-UDP fast path:** when set, the worker sends
    /// on this socket's fd without a destination sockaddr instead of
    /// the wildcard listen socket. The kernel skips per-packet
    /// sockaddr handling, route lookup, and neighbor resolution
    /// because they're cached from the `connect()` call. The `Arc`
    /// keeps the kernel fd alive for the lifetime of this job; once
    /// the job completes and the worker drops it, only the peer's
    /// strong ref remains.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub connected_socket: Option<std::sync::Arc<crate::peer::connected_udp::ConnectedPeerSocket>>,
    /// Bulk endpoint data may be dropped when the kernel reports UDP
    /// send-queue exhaustion. Control/rekey frames keep retrying so
    /// congestion cannot strand the session.
    pub drop_on_backpressure: bool,
    /// Monotonic timestamp captured before dispatch into the worker
    /// queue, used only when pipeline tracing is enabled.
    pub queued_at: Option<std::time::Instant>,
}

pub(crate) struct FspSealJob {
    pub cipher: LessSafeKey,
    pub counter: u64,
    pub aad_offset: usize,
    pub plaintext_offset: usize,
}

struct QueuedFmpSendJob {
    job: FmpSendJob,
    #[cfg(target_os = "macos")]
    macos_flow: Option<Arc<MacSequencedSendFlow>>,
    #[cfg(target_os = "macos")]
    macos_seq: u64,
}

impl QueuedFmpSendJob {
    #[allow(dead_code)] // used on non-macOS and by tests; macOS production uses sequenced flows.
    fn direct(job: FmpSendJob) -> Self {
        Self {
            job,
            #[cfg(target_os = "macos")]
            macos_flow: None,
            #[cfg(target_os = "macos")]
            macos_seq: 0,
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_sequenced(job: FmpSendJob, macos_flow: Arc<MacSequencedSendFlow>) -> Self {
        let macos_seq = macos_flow.reserve_seq();
        Self {
            job,
            macos_flow: Some(macos_flow),
            macos_seq,
        }
    }
}

/// Handle to the encrypt worker pool. Dispatches jobs **hash-by-
/// destination** across N worker tasks via per-worker bounded
/// crossbeam channels. The bounded queue intentionally backpressures
/// the rx_loop if encryption/sending falls behind, because these jobs
/// carry tunneled IP packets; silently dropping them here looks like
/// heavy loss to TCP-over-TUN and collapses throughput.
///
/// **Ordering: hash-by-destination, not round-robin.** Round-robin
/// across N workers causes UDP packet reordering on the wire, which
/// the receiving TCP layer reacts to with dup-ACK-triggered
/// fast-retransmits — measured in bench: 2 workers on a single-flow
/// TCP run dropped throughput 1308 → 1069 Mbps and pushed Retr count
/// from 0 to 8058. Hashing on the destination kernel `SocketAddr`
/// keeps all packets for one flow on one worker, preserving the FIFO
/// order TCP expects. Multi-peer / multi-flow benches still get the
/// parallelism since different destinations hash to different workers.
///
/// macOS defaults to the same hash-by-send-target shape unless explicitly
/// opted into the ordered sender. Live Wi-Fi sender tests showed the
/// worker-owned path beats the per-flow ordered sender handoff when the
/// Darwin UDP syscall/pacer path, not FMP AEAD, is the limiting stage.
/// Per-worker bounded queue cap. Keep this near
/// wireguard-go's outbound queue size: a much deeper queue hides a
/// saturated macOS UDP sender from TCP for tens of milliseconds,
/// inflating RTT/retransmits instead of pushing back to TUN promptly.
///
/// Linux uses crossbeam's bounded channel; macOS uses a tiny custom
/// bounded queue that wakes a worker only when the queue transitions
/// from empty to non-empty. `sample(1)` showed crossbeam's per-packet
/// Darwin `semaphore_signal_trap` dominating the rx_loop dispatch path
/// on saturated single-peer runs, even when the worker was already
/// active and about to drain the next packet. Bounded so the producer
/// back-pressures the rx_loop if the worker thread can't keep up —
/// same rationale as the bounded endpoint_commands channel upstream.
const WORKER_CHANNEL_CAP: usize = 1024;

#[cfg(target_os = "macos")]
struct MacWorkerSender {
    inner: Arc<MacWorkerQueueInner>,
}

#[cfg(target_os = "macos")]
struct MacWorkerReceiver {
    inner: Arc<MacWorkerQueueInner>,
}

#[cfg(target_os = "macos")]
struct MacWorkerQueueInner {
    state: Mutex<MacWorkerQueueState>,
    not_empty: Condvar,
    not_full: Condvar,
    cap: usize,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacWorkerQueueState {
    queue: VecDeque<QueuedFmpSendJob>,
    waiting: bool,
    closed: bool,
}

#[cfg(target_os = "macos")]
enum MacWorkerTryPushError {
    Full(Box<QueuedFmpSendJob>),
    Closed,
}

#[cfg(target_os = "macos")]
struct MacWorkerPushError;

#[cfg(target_os = "macos")]
fn mac_worker_channel(cap: usize) -> (MacWorkerSender, MacWorkerReceiver) {
    let inner = Arc::new(MacWorkerQueueInner {
        state: Mutex::new(MacWorkerQueueState {
            queue: VecDeque::with_capacity(cap),
            waiting: false,
            closed: false,
        }),
        not_empty: Condvar::new(),
        not_full: Condvar::new(),
        cap,
    });
    (
        MacWorkerSender {
            inner: Arc::clone(&inner),
        },
        MacWorkerReceiver { inner },
    )
}

#[cfg(target_os = "macos")]
impl MacWorkerSender {
    fn try_push(&self, job: QueuedFmpSendJob) -> Result<(), MacWorkerTryPushError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        if state.closed {
            drop(job);
            return Err(MacWorkerTryPushError::Closed);
        }
        if state.queue.len() >= self.inner.cap {
            return Err(MacWorkerTryPushError::Full(Box::new(job)));
        }
        let was_empty = state.queue.is_empty();
        let should_notify = was_empty && state.waiting;
        state.queue.push_back(job);
        drop(state);
        if should_notify {
            self.inner.not_empty.notify_one();
        }
        Ok(())
    }

    fn push_blocking(&self, job: QueuedFmpSendJob) -> Result<(), MacWorkerPushError> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        loop {
            if state.closed {
                drop(job);
                return Err(MacWorkerPushError);
            }
            if state.queue.len() < self.inner.cap {
                let was_empty = state.queue.is_empty();
                let should_notify = was_empty && state.waiting;
                state.queue.push_back(job);
                drop(state);
                if should_notify {
                    self.inner.not_empty.notify_one();
                }
                return Ok(());
            }
            state = self
                .inner
                .not_full
                .wait(state)
                .expect("encrypt worker queue poisoned");
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacWorkerSender {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        state.closed = true;
        drop(state);
        self.inner.not_empty.notify_all();
        self.inner.not_full.notify_all();
    }
}

#[cfg(target_os = "macos")]
impl MacWorkerReceiver {
    fn recv_batch(&self, batch: &mut Vec<QueuedFmpSendJob>, max: usize) -> bool {
        debug_assert!(batch.is_empty());
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        loop {
            while let Some(job) = state.queue.pop_front() {
                batch.push(job);
                if batch.len() >= max {
                    break;
                }
            }
            if !batch.is_empty() {
                self.inner.not_full.notify_one();
                return true;
            }
            if state.closed {
                return false;
            }
            state.waiting = true;
            state = self
                .inner
                .not_empty
                .wait(state)
                .expect("encrypt worker queue poisoned");
            state.waiting = false;
        }
    }
}

#[cfg(target_os = "macos")]
type WorkerSender = MacWorkerSender;

#[cfg(not(target_os = "macos"))]
type WorkerSender = Sender<QueuedFmpSendJob>;

/// Handle to the encrypt worker pool.
///
/// Workers are **dedicated `std::thread`s** with **`crossbeam_channel`**
/// between them and the rx_loop. The earlier tokio-task version of
/// this worker pool was the right shape, but every cross-runtime
/// wake (rx_loop's tokio task → tokio worker task) costs the tokio
/// scheduler an internal hop. Replacing the worker side with a sync
/// OS thread, and the channel with crossbeam (where both `.send()`
/// and `.recv()` are wait-free fast-paths and the blocking wake is a
/// single kernel futex), cuts the dispatch round-trip to the
/// platform minimum — same pattern boringtun uses for its main loop.
///
/// **Ordering: hash-by-destination** so single-flow TCP keeps its
/// FIFO ordering (round-robin caused 8000 retransmits in an earlier
/// experiment — see the git log for the 56e0ca8 fix). Multi-peer /
/// multi-flow benches still get parallelism since different
/// destinations hash to different workers.
#[derive(Clone)]
pub(crate) struct EncryptWorkerPool {
    senders: Arc<[WorkerSender]>,
    #[cfg(target_os = "macos")]
    macos_senders: Arc<MacSequencedSendFlows>,
    #[cfg(target_os = "macos")]
    next_worker: Arc<std::sync::atomic::AtomicUsize>,
}

impl EncryptWorkerPool {
    /// Spawn `n` worker **OS threads** and return a handle that
    /// dispatches jobs hash-by-destination to them. The workers exit
    /// when all senders for their channel are dropped (i.e. when the
    /// returned `EncryptWorkerPool` and all clones go away).
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            #[cfg(target_os = "macos")]
            {
                let (tx, rx) = mac_worker_channel(WORKER_CHANNEL_CAP);
                std::thread::Builder::new()
                    .name(format!("fips-encrypt-{i}"))
                    .spawn(move || run_worker_macos(i, rx))
                    .expect("failed to spawn fips-encrypt OS thread");
                senders.push(tx);
            }
            #[cfg(not(target_os = "macos"))]
            {
                let (tx, rx) = bounded::<QueuedFmpSendJob>(WORKER_CHANNEL_CAP);
                std::thread::Builder::new()
                    .name(format!("fips-encrypt-{i}"))
                    .spawn(move || run_worker(i, rx))
                    .expect("failed to spawn fips-encrypt OS thread");
                senders.push(tx);
            }
        }
        Self {
            senders: senders.into(),
            #[cfg(target_os = "macos")]
            macos_senders: Arc::new(MacSequencedSendFlows::default()),
            #[cfg(target_os = "macos")]
            next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Dispatch a job to the worker that owns its destination flow.
    /// The hash is over `dest_addr` so every packet for one peer's
    /// kernel `SocketAddr` lands on the same worker and stays in
    /// order — required for TCP's fast-retransmit logic above to
    /// behave on a single-flow run. Fire-and-forget — the worker
    /// handles send errors itself via stats counters.
    ///
    /// Uses `try_send` for the common uncontended case, then blocks
    /// only when the bounded worker channel is full. These jobs carry
    /// tunneled IP packets, not application UDP datagrams; dropping at
    /// this internal queue makes TCP-over-TUN collapse with avoidable
    /// retransmits. Blocking here pushes back toward the TUN reader
    /// and lets the kernel/app TCP stack pace the flow instead.
    pub fn dispatch(&self, job: FmpSendJob) {
        if self.senders.is_empty() {
            debug!("EncryptWorkerPool has no workers; dropping job");
            return;
        }
        let (idx, job) = self.prepare_dispatch(job);
        self.dispatch_to_worker(idx, job);
    }

    #[cfg(target_os = "macos")]
    fn prepare_dispatch(&self, job: FmpSendJob) -> (usize, QueuedFmpSendJob) {
        if !macos_ordered_sender_enabled() {
            use std::hash::{Hash, Hasher};

            let key = MacSendFlowKey {
                socket_fd: job.socket.as_raw_fd(),
                connected_fd: job.connected_socket.as_ref().map(|s| s.as_raw_fd()),
                dest_addr: job.dest_addr,
            };
            let mut h = std::collections::hash_map::DefaultHasher::new();
            key.hash(&mut h);
            let idx = (h.finish() as usize) % self.senders.len();
            return (idx, QueuedFmpSendJob::direct(job));
        }

        // Darwin has no sendmmsg/UDP_GSO equivalent in the standard UDP
        // path, and high-rate Wi-Fi sends regularly block in ENOBUFS. Keep
        // nonce assignment in rx_loop, spread FMP AEAD over the worker pool,
        // then serialize already-encrypted packets through one sender per
        // kernel 5-tuple. This mirrors wireguard-go's
        // route/nonce -> parallel encrypt -> sequential transmit shape.
        let flow = self.macos_senders.flow_for(&job);
        let ticket = self
            .next_worker
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            / macos_worker_stride();
        let idx = ticket % self.senders.len();
        (idx, QueuedFmpSendJob::macos_sequenced(job, flow))
    }

    #[cfg(not(target_os = "macos"))]
    fn prepare_dispatch(&self, job: FmpSendJob) -> (usize, QueuedFmpSendJob) {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        job.dest_addr.hash(&mut h);
        let idx = (h.finish() as usize) % self.senders.len();
        (idx, QueuedFmpSendJob::direct(job))
    }

    #[cfg(target_os = "macos")]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) {
        match self.senders[idx].try_push(job) {
            Ok(()) => {}
            Err(MacWorkerTryPushError::Full(job)) => {
                static FULL_COUNT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        full_events = n + 1,
                        "EncryptWorker channel full; applying outbound backpressure"
                    );
                }
                if let Err(MacWorkerPushError) = self.senders[idx].push_blocking(*job) {
                    debug!(worker = idx, "EncryptWorker thread gone; dropping job");
                }
            }
            Err(MacWorkerTryPushError::Closed) => {
                debug!(worker = idx, "EncryptWorker thread gone; dropping job");
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) {
        match self.senders[idx].try_send(job) {
            Ok(()) => {}
            Err(TrySendError::Full(job)) => {
                static FULL_COUNT: std::sync::atomic::AtomicU64 =
                    std::sync::atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        full_events = n + 1,
                        "EncryptWorker channel full; applying outbound backpressure"
                    );
                }
                if let Err(SendError(_)) = self.senders[idx].send(job) {
                    debug!(worker = idx, "EncryptWorker thread gone; dropping job");
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(worker = idx, "EncryptWorker thread gone; dropping job");
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct MacSendFlowKey {
    socket_fd: std::os::unix::io::RawFd,
    connected_fd: Option<std::os::unix::io::RawFd>,
    dest_addr: SocketAddr,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacSequencedSendFlows {
    flows: Mutex<HashMap<MacSendFlowKey, Arc<MacSequencedSendFlow>>>,
    last_prune_ms: std::sync::atomic::AtomicU64,
}

#[cfg(target_os = "macos")]
impl MacSequencedSendFlows {
    fn flow_for(&self, job: &FmpSendJob) -> Arc<MacSequencedSendFlow> {
        let now_ms = mac_now_ms();
        let key = MacSendFlowKey {
            socket_fd: job.socket.as_raw_fd(),
            connected_fd: job.connected_socket.as_ref().map(|s| s.as_raw_fd()),
            dest_addr: job.dest_addr,
        };

        let mut flows = self.flows.lock().expect("mac send flow map poisoned");
        self.prune_idle_locked(&mut flows, now_ms);
        if let Some(flow) = flows.get(&key) {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = MacSequencedSendFlow::spawn(
            key,
            job.socket.clone(),
            job.connected_socket.clone(),
            job.dest_addr,
            now_ms,
        );
        flows.insert(key, Arc::clone(&flow));
        flow
    }

    fn prune_idle_locked(
        &self,
        flows: &mut HashMap<MacSendFlowKey, Arc<MacSequencedSendFlow>>,
        now_ms: u64,
    ) {
        let last = self
            .last_prune_ms
            .load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last) < 10_000 {
            return;
        }
        if self
            .last_prune_ms
            .compare_exchange(
                last,
                now_ms,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        let idle_ms = mac_send_flow_idle_ms();
        flows.retain(|_, flow| {
            if flow.is_idle(now_ms, idle_ms) {
                flow.close();
                false
            } else {
                true
            }
        });
    }
}

#[cfg(target_os = "macos")]
fn macos_ordered_sender_enabled() -> bool {
    // Ordered mode parallelizes one peer's FMP AEAD while preserving UDP order,
    // but the extra flow map + sender-thread handoff regressed the measured
    // MacBook Wi-Fi -> Ethernet path. Keep it opt-in for AEAD-bound comparisons;
    // the default keeps packets on the worker selected by send target.
    static VALUE: OnceLock<bool> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_ORDERED_SENDER")
            .ok()
            .map(|raw| {
                !matches!(
                    raw.trim().to_ascii_lowercase().as_str(),
                    "0" | "false" | "no" | "off"
                )
            })
            .unwrap_or(false)
    })
}

#[cfg(target_os = "macos")]
fn macos_worker_stride() -> usize {
    // One-packet round-robin maximizes FMP AEAD parallelism but wakes an idle
    // worker for nearly every packet on Darwin. Short strides let a hot worker
    // drain a local queue batch before the next worker is signalled, while still
    // spreading sustained single-peer traffic across the full pool.
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_WORKER_STRIDE")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 64)
    })
}

#[cfg(target_os = "macos")]
fn macos_worker_batch_size() -> usize {
    // The direct Darwin sender has no sendmmsg/GSO equivalent, so a large
    // worker-drain batch becomes a tight burst of send/sendto calls. MacBook
    // Wi-Fi -> Ethernet tests showed the previous default of 32 could trigger
    // TCP collapse and long queue waits even when Darwin did not report
    // ENOBUFS. A smaller default keeps the kernel/radio pacer in the loop
    // without waking the worker for every datagram; keep this runtime-tunable
    // for LAN/NIC-specific A/B tests.
    static VALUE: OnceLock<usize> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_WORKER_BATCH")
            .ok()
            .and_then(|raw| raw.trim().parse::<usize>().ok())
            .unwrap_or(8)
            .clamp(1, 64)
    })
}

#[cfg(target_os = "macos")]
fn mac_send_flow_idle_ms() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_MACOS_SEND_FLOW_IDLE_MS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(120_000)
            .max(10_000)
    })
}

#[cfg(target_os = "macos")]
fn mac_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
struct MacSequencedSendFlow {
    key: MacSendFlowKey,
    socket: AsyncUdpSocket,
    connected_socket: Option<std::sync::Arc<crate::peer::connected_udp::ConnectedPeerSocket>>,
    dest_addr: SocketAddr,
    next_seq: std::sync::atomic::AtomicU64,
    last_used_ms: std::sync::atomic::AtomicU64,
    state: Mutex<MacSendFlowState>,
    ready_cv: Condvar,
    space_cv: Condvar,
}

#[cfg(target_os = "macos")]
#[derive(Default)]
struct MacSendFlowState {
    next_send_seq: u64,
    pending: BTreeMap<u64, MacSendItem>,
    closed: bool,
}

#[cfg(target_os = "macos")]
struct MacCompletionGroup {
    flow: Arc<MacSequencedSendFlow>,
    items: Vec<(u64, MacSendItem)>,
}

#[cfg(target_os = "macos")]
enum MacSendItem {
    Packet {
        packet: Vec<u8>,
        drop_on_backpressure: bool,
    },
    Skip,
}

#[cfg(target_os = "macos")]
impl MacSequencedSendFlow {
    fn spawn(
        key: MacSendFlowKey,
        socket: AsyncUdpSocket,
        connected_socket: Option<std::sync::Arc<crate::peer::connected_udp::ConnectedPeerSocket>>,
        dest_addr: SocketAddr,
        now_ms: u64,
    ) -> Arc<Self> {
        let flow = Arc::new(Self {
            key,
            socket,
            connected_socket,
            dest_addr,
            next_seq: std::sync::atomic::AtomicU64::new(0),
            last_used_ms: std::sync::atomic::AtomicU64::new(now_ms),
            state: Mutex::new(MacSendFlowState::default()),
            ready_cv: Condvar::new(),
            space_cv: Condvar::new(),
        });
        let thread_flow = Arc::clone(&flow);
        std::thread::Builder::new()
            .name(format!("fips-mac-send-{}", key.socket_fd))
            .spawn(move || thread_flow.run())
            .expect("failed to spawn fips macOS send thread");
        flow
    }

    fn reserve_seq(&self) -> u64 {
        self.next_seq
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    fn mark_used(&self, now_ms: u64) {
        self.last_used_ms
            .store(now_ms, std::sync::atomic::Ordering::Relaxed);
    }

    fn is_idle(&self, now_ms: u64, idle_ms: u64) -> bool {
        let last_used = self.last_used_ms.load(std::sync::atomic::Ordering::Relaxed);
        if now_ms.saturating_sub(last_used) < idle_ms {
            return false;
        }

        let state = self.state.lock().expect("mac send flow state poisoned");
        state.pending.is_empty()
            && state.next_send_seq == self.next_seq.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn close(&self) {
        let mut state = self.state.lock().expect("mac send flow state poisoned");
        state.closed = true;
        drop(state);
        self.ready_cv.notify_one();
        self.space_cv.notify_all();
    }

    fn complete_many(&self, items: Vec<(u64, MacSendItem)>) {
        const PENDING_CAP: usize = 4096;
        if items.is_empty() {
            return;
        }

        let mut state = self.state.lock().expect("mac send flow state poisoned");
        if state.closed {
            return;
        }
        let mut wakes_sender = false;
        for (seq, item) in items {
            while state.pending.len() >= PENDING_CAP && seq != state.next_send_seq && !wakes_sender
            {
                state = self
                    .space_cv
                    .wait(state)
                    .expect("mac send flow state poisoned");
            }
            if seq == state.next_send_seq {
                wakes_sender = true;
            }
            state.pending.insert(seq, item);
        }
        drop(state);
        if wakes_sender {
            self.ready_cv.notify_one();
        }
    }

    fn run(self: Arc<Self>) {
        trace!(
            socket_fd = self.key.socket_fd,
            connected_fd = ?self.key.connected_fd,
            dest = %self.dest_addr,
            "macOS ordered UDP sender starting"
        );
        let (fd, connected) = match self.connected_socket.as_ref() {
            Some(socket) => (socket.as_raw_fd(), true),
            None => (self.socket.as_raw_fd(), false),
        };
        let mut backpressure = SendBackpressurePacer::default();
        let mut rate_pacer = MacSendRatePacer::default();

        loop {
            let item = {
                let mut state = self.state.lock().expect("mac send flow state poisoned");
                loop {
                    let next = state.next_send_seq;
                    if let Some(item) = state.pending.remove(&next) {
                        state.next_send_seq = next.wrapping_add(1);
                        self.space_cv.notify_one();
                        break item;
                    }
                    if state.closed {
                        return;
                    }
                    state = self
                        .ready_cv
                        .wait(state)
                        .expect("mac send flow state poisoned");
                }
            };

            match item {
                MacSendItem::Packet {
                    packet,
                    drop_on_backpressure,
                } => {
                    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
                    rate_pacer.pace(packet.len());
                    if let Err(err) = send_one_with_backpressure(
                        fd,
                        connected,
                        &self.dest_addr,
                        &packet,
                        &mut backpressure,
                        drop_on_backpressure,
                    ) {
                        debug!(
                            socket_fd = self.key.socket_fd,
                            connected_fd = ?self.key.connected_fd,
                            dest = %self.dest_addr,
                            error = %err,
                            "macOS ordered UDP send failed"
                        );
                    }
                }
                MacSendItem::Skip => {}
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn push_mac_completion(
    groups: &mut Vec<MacCompletionGroup>,
    flow: Arc<MacSequencedSendFlow>,
    seq: u64,
    item: MacSendItem,
) {
    if let Some(group) = groups
        .iter_mut()
        .find(|group| Arc::ptr_eq(&group.flow, &flow))
    {
        group.items.push((seq, item));
    } else {
        groups.push(MacCompletionGroup {
            flow,
            items: vec![(seq, item)],
        });
    }
}

/// Sync OS-thread worker loop. Blocks on the crossbeam channel via
/// kernel futex (no tokio runtime involvement), drains follow-on
/// packets into a fixed-size local batch, then issues one
/// `sendmmsg(2)` per drain cycle.
#[cfg(not(target_os = "macos"))]
fn run_worker(idx: usize, rx: Receiver<QueuedFmpSendJob>) {
    trace!(worker = idx, "FMP encrypt worker thread starting");

    const BATCH_SIZE: usize = 32;
    let mut batch: Vec<QueuedFmpSendJob> = Vec::with_capacity(BATCH_SIZE);

    loop {
        // Blocking recv — parks the OS thread on the channel's
        // internal Condvar/futex until a job arrives or the channel
        // closes.
        let first = match rx.recv() {
            Ok(j) => j,
            Err(_) => break, // all senders dropped → graceful exit
        };
        batch.push(first);
        // Drain follow-on jobs without blocking, up to BATCH_SIZE.
        // Same drain pattern as the bounded mpsc one above — gives
        // sendmmsg something to amortise over.
        while batch.len() < BATCH_SIZE {
            match rx.try_recv() {
                Ok(j) => batch.push(j),
                Err(_) => break,
            }
        }
        if let Err(err) = flush_batch_sync(&mut batch) {
            debug!(worker = idx, error = %err, "FMP encrypt worker batch flush failed");
        }
    }
    trace!(worker = idx, "FMP encrypt worker thread exiting");
}

#[cfg(target_os = "macos")]
fn run_worker_macos(idx: usize, rx: MacWorkerReceiver) {
    trace!(worker = idx, "FMP encrypt worker thread starting");

    let batch_size = macos_worker_batch_size();
    let mut batch: Vec<QueuedFmpSendJob> = Vec::with_capacity(batch_size);

    while rx.recv_batch(&mut batch, batch_size) {
        if let Err(err) = flush_batch_sync(&mut batch) {
            debug!(worker = idx, error = %err, "FMP encrypt worker batch flush failed");
            batch.clear();
        }
    }
    trace!(worker = idx, "FMP encrypt worker thread exiting");
}

/// Encrypt every job in `batch` in place, then issue one or more
/// bulk-send syscalls grouped **by exact send target**. Clears
/// `batch` on return. Sync version — operates directly on the raw
/// nonblocking UDP fd with a retry-on-EAGAIN loop; no tokio reactor.
///
/// **Why grouping is required:** `EncryptWorkerPool::dispatch` hashes
/// `job.dest_addr` modulo the worker count to pick a worker — this
/// pins one peer's flow to one worker (FIFO order preserved for
/// TCP), but it does NOT mean every job in a worker's drained batch
/// shares a target. Two different peers can hash to the same
/// worker. The previous implementation cloned `batch[0].socket` /
/// `batch[0].connected_socket` and used them for the entire batch,
/// silently misdirecting packets:
///
/// - **Connected-socket path:** `sendmsg(.., msg_name=NULL)` delivers
///   to the peer cached at `connect(2)` time. Mixing jobs across
///   peers sent all of them to the first peer's connected socket.
/// - **UDP_GSO path:** the super-skb has one `msg_name` + one
///   `UDP_SEGMENT` cmsg. Mixing destinations sent the segmented
///   payload to `packets[0].dest_addr` regardless of each job's
///   intended target.
/// - **Plain `sendmmsg` path:** the kernel honours per-message
///   `msg_name`, so the non-connected fallback was actually safe —
///   but we group anyway for code symmetry and to keep GSO
///   eligibility checks simple.
///
/// **Order preservation:** within one target group the iteration
/// order is the channel-drain order, which is FIFO from the
/// rx_loop. TCP's fast-retransmit logic only cares about per-flow
/// ordering, and a single flow lives entirely inside one group.
fn flush_batch_sync(
    batch: &mut Vec<QueuedFmpSendJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if batch.is_empty() {
        return Ok(());
    }

    // FIPS_PERF: one AEAD timer span over the whole batch — average
    // per-packet falls out of the COUNT increment once per flush.
    let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpEncrypt);

    // Per-target encrypted-packet group. Vec layout (not HashMap)
    // because the typical batch has 1 target (hash-by-dest dispatch),
    // 2-3 worst-case under hash collisions — linear lookup beats
    // hashing for that range and keeps insertion order stable, so
    // the bursty peer's tail packets flush first.
    #[cfg(unix)]
    struct EncryptedGroup {
        socket: AsyncUdpSocket,
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        connected_socket: Option<std::sync::Arc<crate::peer::connected_udp::ConnectedPeerSocket>>,
        dest_addr: SocketAddr,
        wire_packets: Vec<Vec<u8>>,
        drop_on_backpressure: bool,
    }
    #[cfg(unix)]
    let mut groups: Vec<EncryptedGroup> = Vec::with_capacity(1);
    #[cfg(target_os = "macos")]
    let mut macos_completions: Vec<MacCompletionGroup> = Vec::with_capacity(1);

    for queued in batch.drain(..) {
        #[cfg(target_os = "macos")]
        let QueuedFmpSendJob {
            job,
            macos_flow,
            macos_seq,
        } = queued;
        #[cfg(not(target_os = "macos"))]
        let QueuedFmpSendJob { job } = queued;

        let FmpSendJob {
            cipher,
            counter,
            mut wire_buf,
            fsp_seal,
            socket,
            dest_addr,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket,
            drop_on_backpressure,
            queued_at,
        } = job;
        crate::perf_profile::record_since(
            crate::perf_profile::Stage::FmpWorkerQueueWait,
            queued_at,
        );
        if let Some(fsp) = fsp_seal {
            if fsp.aad_offset + FSP_HEADER_SIZE > fsp.plaintext_offset
                || fsp.plaintext_offset > wire_buf.len()
            {
                #[cfg(target_os = "macos")]
                if let Some(flow) = macos_flow.as_ref() {
                    push_mac_completion(
                        &mut macos_completions,
                        Arc::clone(flow),
                        macos_seq,
                        MacSendItem::Skip,
                    );
                }
                continue;
            }

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[4..12].copy_from_slice(&fsp.counter.to_le_bytes());
            let nonce = Nonce::assume_unique_for_key(nonce_bytes);
            let (prefix, plaintext_slice) = wire_buf.split_at_mut(fsp.plaintext_offset);
            let aad = &prefix[fsp.aad_offset..fsp.aad_offset + FSP_HEADER_SIZE];
            let tag =
                match fsp
                    .cipher
                    .seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext_slice)
                {
                    Ok(tag) => tag,
                    Err(_) => {
                        #[cfg(target_os = "macos")]
                        if let Some(flow) = macos_flow.as_ref() {
                            push_mac_completion(
                                &mut macos_completions,
                                Arc::clone(flow),
                                macos_seq,
                                MacSendItem::Skip,
                            );
                        }
                        continue;
                    }
                };
            wire_buf.extend_from_slice(tag.as_ref());
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        // Split-borrow: AAD reads from header bytes [0..16], seal writes
        // into the plaintext slice [16..]. ring::aead's `seal_in_place_
        // separate_tag` takes `&mut [u8]` so we can hand it the
        // post-header slice while AAD references the header slice.
        // `split_at_mut` is the standard way to do this safely.
        let (header_slice, plaintext_slice) = wire_buf.split_at_mut(ESTABLISHED_HEADER_SIZE);
        let tag = match cipher.seal_in_place_separate_tag(
            nonce,
            Aad::from(&*header_slice),
            plaintext_slice,
        ) {
            Ok(tag) => tag,
            Err(_) => {
                #[cfg(target_os = "macos")]
                if let Some(flow) = macos_flow {
                    push_mac_completion(&mut macos_completions, flow, macos_seq, MacSendItem::Skip);
                }
                continue;
            }
        };
        // wire_buf already has `+16` capacity reserved → no realloc.
        wire_buf.extend_from_slice(tag.as_ref());

        #[cfg(target_os = "macos")]
        if let Some(flow) = macos_flow {
            push_mac_completion(
                &mut macos_completions,
                flow,
                macos_seq,
                MacSendItem::Packet {
                    packet: wire_buf,
                    drop_on_backpressure,
                },
            );
            continue;
        }

        #[cfg(unix)]
        {
            // Compare by RawFd, not the `AsyncUdpSocket` / Arc identity —
            // identity comparison breaks if two jobs carry separately-
            // cloned handles to the same kernel fd, which happens
            // routinely on the rx_loop side. The kernel fd is the only
            // thing that matters for what `sendmsg(2)` actually does.
            let socket_fd = socket.as_raw_fd();
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let connected_fd = connected_socket.as_ref().map(|s| s.as_raw_fd());
            let matched = groups.iter_mut().position(|g| {
                if g.dest_addr != dest_addr {
                    return false;
                }
                if g.socket.as_raw_fd() != socket_fd {
                    return false;
                }
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                {
                    if g.connected_socket.as_ref().map(|s| s.as_raw_fd()) != connected_fd {
                        return false;
                    }
                }
                true
            });
            if let Some(idx) = matched {
                groups[idx].wire_packets.push(wire_buf);
                groups[idx].drop_on_backpressure &= drop_on_backpressure;
            } else {
                groups.push(EncryptedGroup {
                    socket,
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    connected_socket,
                    dest_addr,
                    wire_packets: vec![wire_buf],
                    drop_on_backpressure,
                });
            }
        }
        #[cfg(not(unix))]
        {
            // Windows: encrypt worker pool isn't spawned (see
            // lifecycle.rs); this function is unreachable. Drop
            // values explicitly so the compiler sees them as used.
            let _ = (socket, dest_addr, wire_buf);
        }
    }

    #[cfg(target_os = "macos")]
    for group in macos_completions {
        group.flow.complete_many(group.items);
    }

    drop(_t); // close the encrypt timer before we open the send timer

    // 2) Bulk send each group via its own raw FD.
    //
    // **Preferred (Linux only): UDP_GSO** — when every wire packet in
    // a group is the same size (last may be shorter, which the kernel
    // handles), one `sendmsg(2)` with the `UDP_SEGMENT` cmsg lets the
    // kernel split one "super-skb" into N on-the-wire UDP datagrams
    // in a single skb-walk. Profiling on AMD VM showed `sendmmsg(2)`
    // taking ~4.5 µs per packet at single-flow TCP rates — the kernel
    // TX path was the actual bottleneck, not the AEAD. UDP_GSO
    // collapses that to ~one walk per group. Same primitive WireGuard
    // kernel + boringtun use to hit 2.5-3.2 Gbps.
    //
    // **Fallback: sendmmsg(2)** — used when sizes differ in the
    // group (FIPS control frames + EndpointData mixed), and after a
    // one-shot EINVAL/EOPNOTSUPP from UDP_GSO sticks the
    // GSO_DISABLED flag. Same retry-on-EAGAIN loop as before.
    //
    // On EAGAIN we `yield_now()` — the kernel UDP socket is in
    // nonblocking mode (`UdpRawSocket::open`), and at line rate the
    // kernel send buffer (8 MiB by `DEFAULT_UDP_SEND_BUF`) is rarely
    // full so this is the cold path.
    let _t2 = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);

    #[cfg(target_os = "linux")]
    for group in groups {
        let mut backpressure = SendBackpressurePacer::default();
        let EncryptedGroup {
            socket,
            connected_socket,
            dest_addr,
            wire_packets,
            drop_on_backpressure: _,
        } = group;
        let (fd, connected) = match connected_socket.as_ref() {
            Some(s) => (s.as_raw_fd(), true),
            None => (socket.as_raw_fd(), false),
        };

        // Within a group, destination is uniform by construction —
        // GSO needs only the size check now.
        if !GSO_DISABLED.load(std::sync::atomic::Ordering::Relaxed)
            && gso_eligible_sizes(&wire_packets)
        {
            match send_batch_gso(fd, &wire_packets, dest_addr, connected) {
                Ok(()) => {
                    record_udp_send_path(connected, wire_packets.len() as u64);
                    continue;
                }
                Err(err)
                    if err.kind() == std::io::ErrorKind::InvalidInput
                        || err.raw_os_error() == Some(libc::EOPNOTSUPP)
                        || err.raw_os_error() == Some(libc::ENOPROTOOPT) =>
                {
                    GSO_DISABLED.store(true, std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        error = %err,
                        "UDP_GSO refused by kernel; falling back to sendmmsg for life of process"
                    );
                    // fall through to sendmmsg path for this group
                }
                Err(err) if is_send_backpressure(&err) => {
                    // Send buffer full mid-GSO — fall through to
                    // sendmmsg retry loop. No GSO_DISABLED toggle.
                }
                Err(err) => {
                    return Err(format!("sendmsg+UDP_GSO failed: {err}").into());
                }
            }
        }

        let mut sent = 0usize;
        while sent < wire_packets.len() {
            let n = match send_batch_raw(fd, &wire_packets[sent..], dest_addr, connected) {
                Ok(n) => n,
                Err(err) if is_send_backpressure(&err) => {
                    backpressure.pause(&err);
                    continue;
                }
                Err(err) => {
                    return Err(format!("sendmmsg(2) failed: {err}").into());
                }
            };
            if n == 0 {
                break;
            }
            sent += n;
            backpressure.record_success();
            record_udp_send_path(connected, n as u64);
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    for group in groups {
        let mut backpressure = SendBackpressurePacer::default();
        #[cfg(target_os = "macos")]
        let (fd, connected) = match group.connected_socket.as_ref() {
            Some(s) => (s.as_raw_fd(), true),
            None => (group.socket.as_raw_fd(), false),
        };
        #[cfg(not(target_os = "macos"))]
        let (fd, connected) = (group.socket.as_raw_fd(), false);
        for data in &group.wire_packets {
            if let Err(err) = send_one_with_backpressure(
                fd,
                connected,
                &group.dest_addr,
                data,
                &mut backpressure,
                group.drop_on_backpressure,
            ) {
                if group.drop_on_backpressure && is_send_backpressure(&err) {
                    continue;
                }
                return Err(format!("sendto failed: {err}").into());
            }
        }
    }
    // Windows: encrypt worker pool isn't spawned at all (see
    // lifecycle.rs), so this function is never reached. The
    // tokio-backed `AsyncUdpSocket::send_to` path on the rx_loop
    // remains the only outbound path on that platform.
    Ok(())
}

#[cfg(all(test, unix))]
fn flush_direct_batch_sync(
    batch: &mut Vec<FmpSendJob>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut queued: Vec<QueuedFmpSendJob> = batch.drain(..).map(QueuedFmpSendJob::direct).collect();
    flush_batch_sync(&mut queued)
}

fn record_udp_send_path(connected: bool, count: u64) {
    let event = if connected {
        crate::perf_profile::Event::UdpSendConnected
    } else {
        crate::perf_profile::Event::UdpSendWildcard
    };
    crate::perf_profile::record_event_count(event, count);
}

fn is_send_backpressure(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::WouldBlock
        || err.raw_os_error().is_some_and(raw_send_backpressure_code)
}

#[cfg(unix)]
fn raw_send_backpressure_code(code: i32) -> bool {
    code == libc::ENOBUFS || code == libc::ENOMEM
}

#[cfg(windows)]
fn raw_send_backpressure_code(code: i32) -> bool {
    const WSAENOBUFS: i32 = 10055;
    const ERROR_NOT_ENOUGH_MEMORY: i32 = 8;
    code == WSAENOBUFS || code == ERROR_NOT_ENOUGH_MEMORY
}

#[cfg(not(any(unix, windows)))]
fn raw_send_backpressure_code(_code: i32) -> bool {
    false
}

#[derive(Default)]
struct SendBackpressurePacer {
    /// Counts consecutive kernel send-queue failures since the last
    /// successful send. This drives the bounded-drop policy.
    consecutive_full: u32,
    /// Counts failures since the last sleep. This is separate from
    /// `consecutive_full` so sleeping does not make `drop_after`
    /// unreachable during a sustained ENOBUFS storm.
    full_since_sleep: u32,
}

impl SendBackpressurePacer {
    fn record_success(&mut self) {
        self.consecutive_full = 0;
        self.full_since_sleep = 0;
    }

    /// Returns true when a bulk-data caller should drop the current
    /// datagram instead of retrying indefinitely.
    fn pause(&mut self, err: &std::io::Error) -> bool {
        crate::perf_profile::record_event(crate::perf_profile::Event::UdpSendBackpressure);
        if err.kind() == std::io::ErrorKind::WouldBlock {
            self.consecutive_full = 0;
            self.full_since_sleep = 0;
            std::thread::yield_now();
            return false;
        }

        static SEND_BACKPRESSURE_COUNT: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(0);
        let n = SEND_BACKPRESSURE_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if n < 8 || n.is_multiple_of(100_000) {
            warn!(
                error = %err,
                events = n + 1,
                "UDP send queue full; applying kernel backpressure"
            );
        }

        self.consecutive_full = self.consecutive_full.saturating_add(1);
        self.full_since_sleep = self.full_since_sleep.saturating_add(1);
        let drop_after = send_backpressure_drop_after();
        if drop_after > 0 && self.consecutive_full >= drop_after {
            self.consecutive_full = 0;
            self.full_since_sleep = 0;
            return true;
        }

        let sleep_after = send_backpressure_sleep_after();
        if sleep_after > 0 && self.full_since_sleep >= sleep_after {
            self.full_since_sleep = 0;
            crate::perf_profile::record_event(crate::perf_profile::Event::UdpSendBackpressureSleep);
            std::thread::sleep(std::time::Duration::from_micros(
                send_backpressure_sleep_micros(),
            ));
        } else {
            std::thread::yield_now();
        }
        false
    }
}

fn send_backpressure_sleep_after() -> u32 {
    static VALUE: OnceLock<u32> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_SEND_BACKPRESSURE_SLEEP_AFTER")
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .unwrap_or(default_send_backpressure_sleep_after())
    })
}

fn send_backpressure_sleep_micros() -> u64 {
    static VALUE: OnceLock<u64> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_SEND_BACKPRESSURE_SLEEP_MICROS")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(default_send_backpressure_sleep_micros())
            .max(1)
    })
}

fn send_backpressure_drop_after() -> u32 {
    static VALUE: OnceLock<u32> = OnceLock::new();
    *VALUE.get_or_init(|| {
        std::env::var("FIPS_SEND_BACKPRESSURE_DROP_AFTER")
            .ok()
            .and_then(|raw| raw.trim().parse::<u32>().ok())
            .unwrap_or(default_send_backpressure_drop_after())
    })
}

#[cfg(target_os = "macos")]
fn default_send_backpressure_sleep_after() -> u32 {
    // Darwin returns ENOBUFS in tight bursts when Wi-Fi/UDP egress is full.
    // Pure yield/retry can spin tens of thousands of times per second, preserve
    // packets TCP should have treated as loss, and hide the bottleneck behind
    // worker-queue latency. Sleep only after a short burst; clean sends reset
    // the counter.
    4
}

#[cfg(not(target_os = "macos"))]
fn default_send_backpressure_sleep_after() -> u32 {
    0
}

#[cfg(target_os = "macos")]
fn default_send_backpressure_sleep_micros() -> u64 {
    100
}

#[cfg(not(target_os = "macos"))]
fn default_send_backpressure_sleep_micros() -> u64 {
    1
}

#[cfg(target_os = "macos")]
fn default_send_backpressure_drop_after() -> u32 {
    // WireGuard's Darwin UDP path returns ENOBUFS to the caller rather than
    // retrying one datagram forever. For bulk endpoint data, a bounded retry
    // budget avoids head-of-line stalls that can last seconds when Wi-Fi
    // egress is saturated, while still preserving short transient bursts.
    // Control frames pass `drop_on_backpressure = false` and keep retrying.
    256
}

#[cfg(not(target_os = "macos"))]
fn default_send_backpressure_drop_after() -> u32 {
    0
}

#[cfg(all(unix, not(target_os = "linux")))]
fn record_udp_send_backpressure_drop(err: &std::io::Error) {
    static SEND_BACKPRESSURE_DROP_COUNT: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
    let n = SEND_BACKPRESSURE_DROP_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if n < 8 || n.is_multiple_of(100_000) {
        warn!(
            error = %err,
            drops = n + 1,
            "UDP send queue full; dropping bulk data packet"
        );
    }
}

#[cfg(target_os = "macos")]
struct MacSendRatePacer {
    bytes_per_sec: f64,
    burst_bytes: f64,
    credit_bytes: f64,
    last: std::time::Instant,
}

#[cfg(target_os = "macos")]
impl Default for MacSendRatePacer {
    fn default() -> Self {
        let mbps = std::env::var("FIPS_MACOS_SEND_PACE_MBPS")
            .ok()
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .unwrap_or(0.0);
        let bytes_per_sec = if mbps.is_finite() && mbps > 0.0 {
            mbps * 1_000_000.0 / 8.0
        } else {
            0.0
        };
        let burst_bytes = std::env::var("FIPS_MACOS_SEND_PACE_BURST_BYTES")
            .ok()
            .and_then(|raw| raw.trim().parse::<f64>().ok())
            .filter(|value| value.is_finite() && *value > 0.0)
            .unwrap_or(64.0 * 1024.0);
        Self {
            bytes_per_sec,
            burst_bytes,
            credit_bytes: burst_bytes,
            last: std::time::Instant::now(),
        }
    }
}

#[cfg(target_os = "macos")]
impl MacSendRatePacer {
    fn pace(&mut self, bytes: usize) {
        if self.bytes_per_sec <= 0.0 || bytes == 0 {
            return;
        }

        let needed = bytes as f64;
        let now = std::time::Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.credit_bytes =
            (self.credit_bytes + elapsed * self.bytes_per_sec).min(self.burst_bytes);
        self.last = now;

        if self.credit_bytes >= needed {
            self.credit_bytes -= needed;
            return;
        }

        let wait_secs = (needed - self.credit_bytes) / self.bytes_per_sec;
        self.credit_bytes = 0.0;
        let deadline = now + std::time::Duration::from_secs_f64(wait_secs);
        let spin_window = std::time::Duration::from_micros(75);
        loop {
            let now = std::time::Instant::now();
            if now >= deadline {
                self.last = now;
                break;
            }
            let remaining = deadline - now;
            if remaining > spin_window {
                std::thread::sleep(remaining - spin_window);
            } else {
                std::hint::spin_loop();
            }
        }
    }
}

/// Process-wide flag: once the kernel returns EINVAL / EOPNOTSUPP from
/// a UDP_GSO send, we stop trying. Set lazily, never reset.
#[cfg(target_os = "linux")]
static GSO_DISABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Size-only GSO eligibility check. Callers MUST ensure all packets
/// share one destination + send target — `flush_batch_sync` does this
/// by grouping. A batch is GSO-eligible iff every packet is the same
/// size, except the last one may be shorter (UDP_GSO's documented
/// behaviour). Real-world TCP-over-FIPS traffic at line rate is
/// almost entirely MTU-sized packets, so this hits on >99% of groups.
#[cfg(target_os = "linux")]
fn gso_eligible_sizes(packets: &[Vec<u8>]) -> bool {
    if packets.len() < 2 {
        // Single-packet groups don't benefit from GSO (no segmentation
        // saving) and just add cmsg overhead.
        return false;
    }
    let seg = packets[0].len();
    if seg == 0 {
        return false;
    }
    for p in &packets[..packets.len() - 1] {
        if p.len() != seg {
            return false;
        }
    }
    // Last packet must be <= seg.
    packets[packets.len() - 1].len() <= seg
}

/// Issue a single `sendmsg(2)` with the `UDP_SEGMENT` cmsg, handing
/// the kernel a scatter-gather list of N same-size packets which it
/// emits as N on-the-wire UDP datagrams from one skb walk.
///
/// Scatter-gather: we pass each wire packet as its own iovec. With
/// UDP_GSO, the kernel concatenates iovecs into one logical payload
/// before segmenting, so we avoid a separate "memcpy all packets into
/// one big buffer" step.
#[cfg(target_os = "linux")]
fn send_batch_gso(
    fd: std::os::unix::io::RawFd,
    packets: &[Vec<u8>],
    dest: SocketAddr,
    connected: bool,
) -> std::io::Result<()> {
    debug_assert!(!packets.is_empty());
    const MAX_BATCH: usize = 64;
    let n = packets.len().min(MAX_BATCH);
    if n == 0 {
        return Ok(());
    }

    let seg_size = packets[0].len() as u16;
    let sa: socket2::SockAddr = dest.into();

    // Stack-allocated arrays sized for the worst case in this batch.
    let mut iovs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
    for (i, data) in packets[..n].iter().enumerate() {
        iovs[i].iov_base = data.as_ptr() as *mut libc::c_void;
        iovs[i].iov_len = data.len();
    }

    // Storage for the destination address. Only populated + linked
    // into `msghdr.msg_name` when sending via the wildcard listen
    // socket — the connected socket has the destination cached
    // kernel-side via `connect()`.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let sa_len = sa.len();
    if !connected {
        unsafe {
            std::ptr::copy_nonoverlapping(
                sa.as_ptr() as *const u8,
                &mut storage as *mut _ as *mut u8,
                sa_len as usize,
            );
        }
    }

    // Control message buffer: one cmsghdr + 2 bytes payload (u16
    // segment_size), padded to the cmsg alignment.
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) as usize };
    let mut cmsg_buf = [0u8; 64];
    debug_assert!(cmsg_space <= cmsg_buf.len());

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    if connected {
        // Connected socket: kernel rejects non-null msg_name with
        // EISCONN unless it matches the connect()'ed address. Safest
        // and fastest is to leave it null.
        msg.msg_name = std::ptr::null_mut();
        msg.msg_namelen = 0;
    } else {
        msg.msg_name = &mut storage as *mut _ as *mut libc::c_void;
        msg.msg_namelen = sa_len;
    }
    msg.msg_iov = iovs.as_mut_ptr();
    // `msg_iovlen` is `usize` on glibc and `i32` on musl — explicit `as _`
    // cast picks the right one for the target libc.
    msg.msg_iovlen = n as _;
    msg.msg_control = cmsg_buf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    // Fill the UDP_SEGMENT cmsg.
    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return Err(std::io::Error::other("CMSG_FIRSTHDR returned null"));
        }
        // `cmsg_level` / `cmsg_type` types differ between glibc and
        // musl; cast through `_` so the field's declared type wins.
        (*cmsg).cmsg_level = libc::IPPROTO_UDP as _;
        (*cmsg).cmsg_type = libc::UDP_SEGMENT as _;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        let data = libc::CMSG_DATA(cmsg) as *mut u16;
        *data = seg_size;
    }

    let r = unsafe { libc::sendmsg(fd, &msg, 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        // sendmsg+UDP_GSO either submits the whole super-skb or returns
        // -1; partial submission isn't a thing here.
        Ok(())
    }
}

/// Direct `sendmmsg(2)` wrapper for the sync worker. The
/// `transport::udp::io` module's existing `send_batch` is
/// pub(crate) on `UdpRawSocket`, but we don't have a handle to the
/// raw socket from here — we just have the FD. Re-implementing
/// inline is ~15 lines and avoids tunnelling the inner socket
/// through `AsyncUdpSocket` for the sync path.
#[cfg(target_os = "linux")]
fn send_batch_raw(
    fd: std::os::unix::io::RawFd,
    packets: &[Vec<u8>],
    dest: SocketAddr,
    connected: bool,
) -> std::io::Result<usize> {
    const MAX_BATCH: usize = 32;
    let n = packets.len().min(MAX_BATCH);
    if n == 0 {
        return Ok(0);
    }
    let mut iovs: [libc::iovec; MAX_BATCH] = unsafe { std::mem::zeroed() };
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut storage_len: libc::socklen_t = 0;
    let mut msgs: [libc::mmsghdr; MAX_BATCH] = unsafe { std::mem::zeroed() };

    // Within one group, every packet shares the destination — build
    // the sockaddr once and point every mmsghdr at it. (kernel copies
    // out of msg_name during the syscall, so a shared backing store
    // is safe.)
    if !connected {
        let sa: socket2::SockAddr = dest.into();
        let sa_len = sa.len();
        unsafe {
            std::ptr::copy_nonoverlapping(
                sa.as_ptr() as *const u8,
                &mut storage as *mut _ as *mut u8,
                sa_len as usize,
            );
        }
        storage_len = sa_len;
    }

    for i in 0..n {
        let data = &packets[i];
        iovs[i].iov_base = data.as_ptr() as *mut libc::c_void;
        iovs[i].iov_len = data.len();
        msgs[i].msg_hdr.msg_iov = &mut iovs[i];
        // `msg_iovlen` is `usize` on glibc / `i32` on musl.
        msgs[i].msg_hdr.msg_iovlen = 1 as _;
        if connected {
            // Connected socket: kernel has destination cached. Leaving
            // msg_name null skips the per-message sockaddr fixup +
            // route lookup; that's the whole point of the connected
            // fast path.
            msgs[i].msg_hdr.msg_name = std::ptr::null_mut();
            msgs[i].msg_hdr.msg_namelen = 0;
        } else {
            msgs[i].msg_hdr.msg_name = &mut storage as *mut _ as *mut libc::c_void;
            msgs[i].msg_hdr.msg_namelen = storage_len;
        }
    }

    let r = unsafe { libc::sendmmsg(fd, msgs.as_mut_ptr(), n as libc::c_uint, 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use crate::transport::udp::io::UdpRawSocket;
    use ring::aead::{LessSafeKey, UnboundKey};
    use std::net::UdpSocket;

    fn test_cipher(byte: u8) -> LessSafeKey {
        let key_bytes = [byte; 32];
        let unbound =
            UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).expect("build key");
        LessSafeKey::new(unbound)
    }

    #[test]
    fn fsp_preseal_runs_before_outer_fmp_seal() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
            recv.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .expect("set_read_timeout");
            let recv_addr = recv.local_addr().expect("recv local_addr");
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let send_sock = raw.into_async().expect("into_async");

            let fmp_cipher = test_cipher(1);
            let fsp_cipher = test_cipher(2);
            let fmp_counter = 11;
            let fsp_counter = 22;
            let fmp_header = [0xA5; ESTABLISHED_HEADER_SIZE];
            let fsp_header = [0x5A; FSP_HEADER_SIZE];
            let fsp_plaintext = b"inner payload";

            let mut wire_buf = Vec::with_capacity(
                ESTABLISHED_HEADER_SIZE
                    + FSP_HEADER_SIZE
                    + fsp_plaintext.len()
                    + crate::noise::TAG_SIZE
                    + crate::noise::TAG_SIZE,
            );
            wire_buf.extend_from_slice(&fmp_header);
            let fsp_aad_offset = wire_buf.len();
            wire_buf.extend_from_slice(&fsp_header);
            let fsp_plaintext_offset = wire_buf.len();
            wire_buf.extend_from_slice(fsp_plaintext);

            let expected_wire_len = ESTABLISHED_HEADER_SIZE
                + FSP_HEADER_SIZE
                + fsp_plaintext.len()
                + crate::noise::TAG_SIZE
                + crate::noise::TAG_SIZE;
            let mut batch = vec![FmpSendJob {
                cipher: fmp_cipher.clone(),
                counter: fmp_counter,
                wire_buf,
                fsp_seal: Some(FspSealJob {
                    cipher: fsp_cipher.clone(),
                    counter: fsp_counter,
                    aad_offset: fsp_aad_offset,
                    plaintext_offset: fsp_plaintext_offset,
                }),
                socket: send_sock,
                dest_addr: recv_addr,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                connected_socket: None,
                drop_on_backpressure: true,
                queued_at: None,
            }];

            flush_direct_batch_sync(&mut batch).expect("flush ok");
            assert!(batch.is_empty(), "flush must drain the batch");

            let mut buf = [0u8; 256];
            let (len, _) = recv.recv_from(&mut buf).expect("recv");
            assert_eq!(len, expected_wire_len);
            assert_eq!(&buf[..ESTABLISHED_HEADER_SIZE], &fmp_header);

            let outer_plaintext = crate::noise::open(
                Some(&fmp_cipher),
                fmp_counter,
                &fmp_header,
                &buf[ESTABLISHED_HEADER_SIZE..len],
            )
            .expect("outer open");
            assert_eq!(&outer_plaintext[..FSP_HEADER_SIZE], &fsp_header);
            let inner_plaintext = crate::noise::open(
                Some(&fsp_cipher),
                fsp_counter,
                &outer_plaintext[..FSP_HEADER_SIZE],
                &outer_plaintext[FSP_HEADER_SIZE..],
            )
            .expect("inner open");
            assert_eq!(inner_plaintext, fsp_plaintext);
        });
    }

    /// End-to-end round-trip for the pipelined FSP+FMP wire layout
    /// that `try_send_session_data_pipelined` builds.
    ///
    /// The pipelined send path hand-rolls the byte offsets for both
    /// AEAD seals: the inner FSP seal keys off `fsp_aad_offset` /
    /// `fsp_plaintext_offset` computed from cumulative `wire_buf.len()`
    /// during construction, and the outer FMP seal keys off the fixed
    /// `[0..16]` / `[16..]` split. A regression in any offset would
    /// only surface at receiver AEAD failure — the worst place to
    /// debug. The existing `fsp_preseal_runs_before_outer_fmp_seal`
    /// test catches the **seal ordering** invariant with synthetic
    /// `[0xA5;16]` / `[0x5A;12]` headers, but does not exercise the
    /// **wire-layout** invariant — that the encoder geometry matches
    /// what the canonical receive-side decoders
    /// (`EncryptedHeader::parse`, `SessionDatagramRef::decode`)
    /// expect.
    ///
    /// This test mirrors session.rs::try_send_session_data_pipelined
    /// (no coords, common established-session path), runs the worker's
    /// real seal + send via `flush_direct_batch_sync`, then decodes
    /// the resulting wire packet using only canonical decoders. Any
    /// divergence between encoder offsets and decoder expectations
    /// fails at one of the parse / open / decode steps before the
    /// inner-plaintext assertion fires.
    #[test]
    fn pipelined_send_wire_layout_roundtrips_canonical_decoders() {
        use crate::NodeAddr;
        use crate::noise::TAG_SIZE;
        use crate::proto::fmp::wire::{EncryptedHeader, FLAG_KEY_EPOCH, build_established_header};
        use crate::proto::fsp::wire::build_fsp_header;
        use crate::proto::link::{
            LinkMessageType, SESSION_DATAGRAM_HEADER_SIZE, SessionDatagramRef,
        };
        use crate::utils::index::SessionIndex;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
            recv.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .expect("set_read_timeout");
            let recv_addr = recv.local_addr().expect("recv local_addr");
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let send_sock = raw.into_async().expect("into_async");

            let fmp_cipher = test_cipher(0x11);
            let fsp_cipher = test_cipher(0x22);
            let fmp_counter: u64 = 0xCAFE_BABE;
            let fsp_counter: u64 = 0xDEAD_BEEF;
            let timestamp_ms: u32 = 1_234_567;
            let ttl: u8 = 32;
            let path_mtu: u16 = 1432;
            let src_addr = NodeAddr::from_bytes([0xAA; 16]);
            let dest_addr = NodeAddr::from_bytes([0xBB; 16]);
            let their_index = SessionIndex::new(42);
            let fmp_flags: u8 = FLAG_KEY_EPOCH;
            let fsp_flags: u8 = 0;
            let fsp_plaintext = b"pipelined-send wire-layout round-trip plaintext".to_vec();

            // Encoder geometry mirrors session.rs::try_send_session_data_pipelined
            // (no coords, the typical established-session path).
            let link_plaintext_len =
                SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + fsp_plaintext.len();
            let fmp_inner_len = 4 + link_plaintext_len + TAG_SIZE;
            let wire_capacity = ESTABLISHED_HEADER_SIZE + fmp_inner_len + TAG_SIZE;

            let fsp_header_bytes =
                build_fsp_header(fsp_counter, fsp_flags, fsp_plaintext.len() as u16);
            let fmp_header_bytes =
                build_established_header(their_index, fmp_counter, fmp_flags, fmp_inner_len as u16);

            let mut wire_buf = Vec::with_capacity(wire_capacity);
            wire_buf.extend_from_slice(&fmp_header_bytes);
            wire_buf.extend_from_slice(&timestamp_ms.to_le_bytes());
            wire_buf.push(LinkMessageType::SessionDatagram.to_byte());
            wire_buf.push(ttl);
            wire_buf.extend_from_slice(&path_mtu.to_le_bytes());
            wire_buf.extend_from_slice(src_addr.as_bytes());
            wire_buf.extend_from_slice(dest_addr.as_bytes());
            let fsp_aad_offset = wire_buf.len();
            wire_buf.extend_from_slice(&fsp_header_bytes);
            // No coords: established-session common path.
            let fsp_plaintext_offset = wire_buf.len();
            wire_buf.extend_from_slice(&fsp_plaintext);

            let mut batch = vec![FmpSendJob {
                cipher: fmp_cipher.clone(),
                counter: fmp_counter,
                wire_buf,
                fsp_seal: Some(FspSealJob {
                    cipher: fsp_cipher.clone(),
                    counter: fsp_counter,
                    aad_offset: fsp_aad_offset,
                    plaintext_offset: fsp_plaintext_offset,
                }),
                socket: send_sock,
                dest_addr: recv_addr,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                connected_socket: None,
                drop_on_backpressure: true,
                queued_at: None,
            }];
            flush_direct_batch_sync(&mut batch).expect("flush ok");
            assert!(batch.is_empty(), "flush must drain the batch");

            let mut buf = [0u8; 512];
            let (len, _) = recv.recv_from(&mut buf).expect("recv");
            assert_eq!(len, wire_capacity, "wire packet length matches geometry");

            // ---- Canonical receive-side decode ----

            // 1. Parse FMP outer header (canonical decoder).
            let parsed_fmp = EncryptedHeader::parse(&buf[..len])
                .expect("EncryptedHeader::parse must accept the wire packet");
            assert_eq!(parsed_fmp.counter, fmp_counter);
            assert_eq!(parsed_fmp.receiver_idx, their_index);
            assert_eq!(parsed_fmp.flags, fmp_flags);
            assert_eq!(parsed_fmp.payload_len, fmp_inner_len as u16);

            // 2. Open FMP outer using AAD from the parsed header.
            let fmp_plaintext = crate::noise::open(
                Some(&fmp_cipher),
                fmp_counter,
                &parsed_fmp.header_bytes,
                &buf[ESTABLISHED_HEADER_SIZE..len],
            )
            .expect("FMP outer open against EncryptedHeader AAD");

            // 3. FMP plaintext: [4-byte link-ts][1-byte msg_type][SessionDatagram body][FSP enc].
            assert!(
                fmp_plaintext.len() >= 5,
                "FMP plaintext must have link-ts + msg_type"
            );
            let recovered_ts = u32::from_le_bytes([
                fmp_plaintext[0],
                fmp_plaintext[1],
                fmp_plaintext[2],
                fmp_plaintext[3],
            ]);
            assert_eq!(recovered_ts, timestamp_ms);
            assert_eq!(fmp_plaintext[4], LinkMessageType::SessionDatagram.to_byte());

            // 4. Parse SessionDatagram body (canonical decoder).
            let datagram = SessionDatagramRef::decode(&fmp_plaintext[5..])
                .expect("SessionDatagramRef::decode must accept the FMP plaintext body");
            assert_eq!(datagram.ttl, ttl);
            assert_eq!(datagram.path_mtu, path_mtu);
            assert_eq!(datagram.src_addr, src_addr);
            assert_eq!(datagram.dest_addr, dest_addr);

            // 5. datagram.payload = [FSP header][FSP ciphertext + tag].
            //    The FSP header must round-trip byte-for-byte to what
            //    the encoder constructed via `build_fsp_header`.
            assert!(datagram.payload.len() >= FSP_HEADER_SIZE);
            assert_eq!(&datagram.payload[..FSP_HEADER_SIZE], &fsp_header_bytes);

            // 6. Open FSP inner using AAD = the parsed FSP header.
            let recovered_fsp_plaintext = crate::noise::open(
                Some(&fsp_cipher),
                fsp_counter,
                &datagram.payload[..FSP_HEADER_SIZE],
                &datagram.payload[FSP_HEADER_SIZE..],
            )
            .expect("FSP inner open against parsed FSP header AAD");
            assert_eq!(recovered_fsp_plaintext, fsp_plaintext);
        });
    }
}

/// Standalone tests for the GSO-eligibility predicate. The full
/// `send_batch_gso` is exercised in `tests::gso_roundtrip` below
/// (Linux only — UDP_GSO + connected-peer fast paths are Linux-only,
/// so the entire test module is gated to Linux to avoid dead-code
/// warnings on macOS / BSD builds).
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn pkt(bytes: usize) -> Vec<u8> {
        vec![0u8; bytes]
    }

    #[test]
    fn gso_eligible_rejects_single_packet() {
        assert!(!gso_eligible_sizes(&[pkt(1500)]));
    }

    #[test]
    fn gso_eligible_accepts_uniform_batch() {
        let batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        assert!(gso_eligible_sizes(&batch));
    }

    #[test]
    fn gso_eligible_accepts_short_trailer() {
        let mut batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        batch.push(pkt(900)); // last shorter — kernel handles this
        assert!(gso_eligible_sizes(&batch));
    }

    #[test]
    fn gso_eligible_rejects_mixed_sizes() {
        let mut batch: Vec<_> = (0..18).map(|_| pkt(1500)).collect();
        batch[3] = pkt(800); // mid-batch short packet
        batch.push(pkt(1500));
        assert!(!gso_eligible_sizes(&batch));
    }

    /// End-to-end: bind a real UDP socket pair on loopback, fire
    /// `send_batch_gso` from the sender, recv on the receiver, confirm
    /// we get N segmented datagrams back (one per logical packet).
    ///
    /// This validates the entire UDP_GSO codepath: cmsg setup,
    /// scatter-gather iov assembly, kernel segmentation. If the
    /// running kernel doesn't support UDP_SEGMENT the syscall returns
    /// EOPNOTSUPP and we skip the assertion (the prod path falls back
    /// to sendmmsg via the GSO_DISABLED flag).
    #[test]
    fn gso_roundtrip_loopback() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        // Sender + receiver on loopback.
        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let recv_addr = recv_sock.local_addr().expect("recv local_addr");
        recv_sock
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set_read_timeout");
        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send");

        // Build a uniform 18-packet batch addressed at recv_sock.
        const SEG: usize = 200;
        const N: usize = 18;
        let mut batch: Vec<Vec<u8>> = Vec::with_capacity(N);
        for i in 0..N {
            let mut buf = vec![0u8; SEG];
            // Stamp the packet index in the first byte so we can verify
            // ordering on the receive side.
            buf[0] = i as u8;
            batch.push(buf);
        }

        let r = send_batch_gso(
            send_sock.as_raw_fd(),
            &batch,
            recv_addr,
            /* connected */ false,
        );
        match r {
            Ok(()) => {} // proceed to recv
            Err(err)
                if err.raw_os_error() == Some(libc::EOPNOTSUPP)
                    || err.raw_os_error() == Some(libc::ENOPROTOOPT)
                    || err.kind() == std::io::ErrorKind::InvalidInput =>
            {
                eprintln!(
                    "gso_roundtrip_loopback: kernel doesn't support UDP_GSO ({err}); skipping"
                );
                return;
            }
            Err(err) => panic!("send_batch_gso failed: {err}"),
        }

        // Drain receive side — expect exactly N datagrams of SEG bytes
        // each, in order.
        let mut recv_buf = [0u8; SEG + 32];
        for i in 0..N {
            let (len, _from) = recv_sock
                .recv_from(&mut recv_buf)
                .unwrap_or_else(|e| panic!("recv {i}: {e}"));
            assert_eq!(len, SEG, "datagram {i} has wrong length");
            assert_eq!(
                recv_buf[0], i as u8,
                "datagram {i} arrived out of order or with wrong stamp"
            );
        }
    }

    /// `send_batch_raw` (the sendmmsg fallback) must deliver every
    /// packet to the shared dest passed alongside the slice. Two
    /// receivers + one mixed batch would be the wrong shape (the
    /// shared sockaddr means one receiver per call); this test
    /// validates the per-call contract: N packets in, N packets out
    /// at one address.
    #[test]
    fn sendmmsg_uniform_dest_roundtrip() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;

        let recv_sock = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let recv_addr = recv_sock.local_addr().unwrap();
        recv_sock
            .set_read_timeout(Some(std::time::Duration::from_millis(500)))
            .expect("set_read_timeout");
        let send_sock = UdpSocket::bind("127.0.0.1:0").expect("bind send");
        send_sock.set_nonblocking(true).unwrap();

        let packets: Vec<Vec<u8>> = (0..4)
            .map(|i| {
                let mut v = vec![0u8; 16];
                v[0] = i as u8;
                v
            })
            .collect();
        let n =
            send_batch_raw(send_sock.as_raw_fd(), &packets, recv_addr, false).expect("sendmmsg ok");
        assert_eq!(n, 4);

        let mut buf = [0u8; 64];
        let mut stamps: Vec<u8> = Vec::new();
        for _ in 0..4 {
            let (len, _) = recv_sock.recv_from(&mut buf).expect("recv");
            assert_eq!(len, 16);
            stamps.push(buf[0]);
        }
        stamps.sort();
        assert_eq!(stamps, vec![0, 1, 2, 3]);
    }

    /// Mixed-destination batch dispatched to a single worker. The
    /// pre-fix bug used `batch[0].socket` / `batch[0].connected_socket`
    /// / `packets[0].dest_addr` for the whole drained batch, so a
    /// hash-collision (two peers hashing to the same worker) silently
    /// misdirected the second peer's packets to the first peer's
    /// destination. The fix groups jobs by `(socket_fd, connected_fd,
    /// dest_addr)` before flushing.
    ///
    /// This test goes through `flush_batch_sync` directly: it constructs
    /// three `FmpSendJob`s split across two distinct receiver sockaddrs
    /// (A, B, A) on a shared send socket with no connected socket, then
    /// asserts that recv_a gets the two A-stamped packets and recv_b
    /// gets exactly the one B-stamped packet.
    ///
    /// We have to spin a tokio runtime because `AsyncUdpSocket` wraps a
    /// `tokio::io::unix::AsyncFd`, which requires a registered reactor
    /// at construction time. The actual `flush_batch_sync` work is sync
    /// (raw-fd `sendmmsg`); we just need the AsyncFd alive for the
    /// AsRawFd impl.
    #[test]
    fn flush_batch_routes_each_target_separately() {
        use crate::transport::udp::io::UdpRawSocket;
        use ring::aead::{LessSafeKey, UnboundKey};
        use std::net::UdpSocket;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        rt.block_on(async {
            // Two receivers — distinct kernel sockaddrs.
            let recv_a = UdpSocket::bind("127.0.0.1:0").expect("bind recv_a");
            let recv_b = UdpSocket::bind("127.0.0.1:0").expect("bind recv_b");
            for s in [&recv_a, &recv_b] {
                s.set_read_timeout(Some(std::time::Duration::from_millis(500)))
                    .expect("set_read_timeout");
            }
            let addr_a = recv_a.local_addr().unwrap();
            let addr_b = recv_b.local_addr().unwrap();

            // One send socket shared by all jobs (the wildcard listen
            // socket in production). `UdpRawSocket::open` builds a
            // socket2 socket; `into_async` wraps it in tokio's AsyncFd
            // and hands back an AsyncUdpSocket.
            let raw = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket");
            let send_sock = raw.into_async().expect("into_async");

            // Throwaway AEAD cipher — content doesn't matter, we just
            // need encrypt to succeed so a wire packet lands.
            let key_bytes = [0u8; 32];
            let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes)
                .expect("build unbound key");
            let cipher = LessSafeKey::new(unbound);

            // Per-target plaintext sizes are distinct so we can
            // identify which receiver got which job by wire-packet
            // length alone — `seal_in_place_separate_tag` scrambles
            // the post-header bytes, so byte-level stamps don't
            // survive the AEAD. Final wire size is 16-byte header
            // + plaintext_size + 16-byte tag.
            const A_PLAINTEXT: usize = 32;
            const B_PLAINTEXT: usize = 64;
            const A_WIRE: usize = 16 + A_PLAINTEXT + 16; // 64
            const B_WIRE: usize = 16 + B_PLAINTEXT + 16; // 96

            fn make_job(
                socket: crate::transport::udp::io::AsyncUdpSocket,
                cipher: &LessSafeKey,
                counter: u64,
                dest: SocketAddr,
                plaintext_size: usize,
            ) -> FmpSendJob {
                // wire_buf: 16-byte header + plaintext + tag-room.
                let mut wire_buf = Vec::with_capacity(16 + plaintext_size + 16);
                wire_buf.extend_from_slice(&[0u8; 16]);
                wire_buf.extend_from_slice(&vec![0u8; plaintext_size]);
                FmpSendJob {
                    cipher: cipher.clone(),
                    counter,
                    wire_buf,
                    fsp_seal: None,
                    socket,
                    dest_addr: dest,
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    connected_socket: None,
                    drop_on_backpressure: true,
                    queued_at: None,
                }
            }

            let mut batch = vec![
                make_job(send_sock.clone(), &cipher, 1, addr_a, A_PLAINTEXT),
                make_job(send_sock.clone(), &cipher, 2, addr_b, B_PLAINTEXT),
                make_job(send_sock.clone(), &cipher, 3, addr_a, A_PLAINTEXT),
            ];
            flush_direct_batch_sync(&mut batch).expect("flush ok");
            assert!(batch.is_empty(), "flush must drain the batch");

            // recv_a expects exactly two packets, each A_WIRE bytes.
            let mut buf = [0u8; 256];
            for i in 0..2 {
                let (len, _) = recv_a.recv_from(&mut buf).expect("recv_a");
                assert_eq!(
                    len, A_WIRE,
                    "recv_a packet {i} has wrong length: got {len}, expected {A_WIRE}"
                );
            }

            // recv_b expects exactly one packet, B_WIRE bytes.
            let (len, _) = recv_b.recv_from(&mut buf).expect("recv_b");
            assert_eq!(
                len, B_WIRE,
                "recv_b packet has wrong length: got {len}, expected {B_WIRE}"
            );

            // Neither receiver may have leftovers. The pre-fix bug
            // would have either:
            //   (a) sent all 3 packets to addr_a (first-job dest
            //       used for the whole batch), causing recv_a to
            //       see a B_WIRE-sized packet and recv_b to see
            //       nothing, or
            //   (b) silently sent A's wire packets to addr_b's
            //       connected fd if any was installed.
            for (name, sock) in [("recv_a", &recv_a), ("recv_b", &recv_b)] {
                sock.set_read_timeout(Some(std::time::Duration::from_millis(50)))
                    .unwrap();
                let leftover = sock.recv_from(&mut buf);
                assert!(
                    leftover.is_err(),
                    "{name} got unexpected extra packet: {:?}",
                    leftover
                );
            }
        });
    }
}

/// Direct `sendto(2)` for non-Linux unix (macOS / BSD). Windows
/// doesn't reach this — encrypt_worker is gated to `unix` in
/// `lifecycle.rs` (the per-worker raw-fd send loop only applies on
/// unix; on Windows the rx_loop fallback path takes outbound packets
/// through tokio's `AsyncUdpSocket::send_to`).
#[cfg(all(unix, not(target_os = "linux")))]
fn send_connected_raw(fd: std::os::unix::io::RawFd, data: &[u8]) -> std::io::Result<usize> {
    let r = unsafe { libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn send_one_with_backpressure(
    fd: std::os::unix::io::RawFd,
    connected: bool,
    dest: &SocketAddr,
    data: &[u8],
    backpressure: &mut SendBackpressurePacer,
    drop_on_backpressure: bool,
) -> std::io::Result<()> {
    loop {
        let result = if connected {
            send_connected_raw(fd, data)
        } else {
            send_one_raw(fd, data, dest)
        };
        match result {
            Ok(_) => {
                backpressure.record_success();
                record_udp_send_path(connected, 1);
                return Ok(());
            }
            Err(err) if is_send_backpressure(&err) => {
                if backpressure.pause(&err) && drop_on_backpressure {
                    record_udp_send_backpressure_drop(&err);
                    return Err(err);
                }
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn send_one_raw(
    fd: std::os::unix::io::RawFd,
    data: &[u8],
    dest: &SocketAddr,
) -> std::io::Result<usize> {
    let sa: socket2::SockAddr = (*dest).into();
    let r = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            sa.as_ptr() as *const libc::sockaddr,
            sa.len(),
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}
