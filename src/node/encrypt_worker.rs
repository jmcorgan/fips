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

#[cfg(test)]
use crate::node::worker_set::{TestWorker, test_spawner};
use crate::node::worker_set::{WorkerLiveness, WorkerSet, worth_logging};
use crate::proto::fmp::wire::ESTABLISHED_HEADER_SIZE;
use crate::proto::fsp::wire::FSP_HEADER_SIZE;
use crate::transport::udp::UdpStats;
use crate::transport::udp::io::AsyncUdpSocket;
#[cfg(not(target_os = "macos"))]
use crossbeam_channel::{Receiver, SendError, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
#[cfg(any(target_os = "macos", test))]
use std::collections::VecDeque;
#[cfg(target_os = "macos")]
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::io::AsRawFd;
use std::sync::Arc;
use std::sync::OnceLock;
#[cfg(any(target_os = "macos", test))]
use std::sync::{Condvar, Mutex, PoisonError};
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
    /// Cloned FMP send cipher. `LessSafeKey` is `Clone` (`ring::aead`), but
    /// the clone is not a refcount bump: `ring` stores the ChaCha20 key
    /// inline as `[u32; 8]`, so cloning copies the key material outright and
    /// leaves a second copy that nothing outside `ring` can clear.
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
    pub connected_socket: Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>>,
    /// The sending UDP transport's counters. The worker's sends bypass
    /// `UdpTransport::send_async`, so the worker counts each datagram it
    /// hands the kernel, and each it gives up on, here; the transport's
    /// send counters then cover every datagram it sends, on the wildcard
    /// socket and on per-peer connected sockets alike.
    pub stats: Arc<UdpStats>,
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
    macos_ticket: Option<MacSeqTicket>,
}

impl QueuedFmpSendJob {
    #[allow(dead_code)] // used on non-macOS and by tests; macOS production uses sequenced flows.
    fn direct(job: FmpSendJob) -> Self {
        Self {
            job,
            #[cfg(target_os = "macos")]
            macos_ticket: None,
        }
    }

    #[cfg(target_os = "macos")]
    fn macos_sequenced(job: FmpSendJob, macos_flow: Arc<MacSequencedSendFlow>) -> Self {
        Self {
            job,
            macos_ticket: Some(MacSeqTicket::reserve(macos_flow)),
        }
    }
}

/// A queued job its worker refused because the worker has exited. Boxed so
/// the dispatch path's `Result` stays small; the allocation happens only on a
/// refusal.
struct Refused(Box<QueuedFmpSendJob>);

impl Refused {
    /// The job, with any macOS ordered-flow slot it held released as a skip.
    fn into_job(self) -> Box<FmpSendJob> {
        #[cfg(target_os = "macos")]
        let QueuedFmpSendJob { job, macos_ticket } = *self.0;
        #[cfg(not(target_os = "macos"))]
        let QueuedFmpSendJob { job } = *self.0;
        #[cfg(target_os = "macos")]
        drop(macos_ticket);
        Box::new(job)
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

#[cfg(any(target_os = "macos", test))]
struct MacWorkerSender<T> {
    inner: Arc<MacWorkerQueueInner<T>>,
}

#[cfg(any(target_os = "macos", test))]
struct MacWorkerReceiver<T> {
    inner: Arc<MacWorkerQueueInner<T>>,
}

#[cfg(any(target_os = "macos", test))]
struct MacWorkerQueueInner<T> {
    state: Mutex<MacWorkerQueueState<T>>,
    not_empty: Condvar,
    not_full: Condvar,
    cap: usize,
}

#[cfg(any(target_os = "macos", test))]
struct MacWorkerQueueState<T> {
    queue: VecDeque<T>,
    waiting: bool,
    closed: bool,
}

/// Why `try_push` did not queue a job. Both variants hand the job back.
#[cfg(any(target_os = "macos", test))]
enum MacWorkerTryPushError<T> {
    Full(Box<T>),
    /// The receiver is gone: the worker has exited.
    Closed(Box<T>),
}

/// `push_blocking` found the receiver gone; the job is handed back.
#[cfg(any(target_os = "macos", test))]
struct MacWorkerPushError<T>(Box<T>);

#[cfg(any(target_os = "macos", test))]
fn mac_worker_channel<T>(cap: usize) -> (MacWorkerSender<T>, MacWorkerReceiver<T>) {
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

#[cfg(any(target_os = "macos", test))]
impl<T> MacWorkerSender<T> {
    fn try_push(&self, job: T) -> Result<(), MacWorkerTryPushError<T>> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        if state.closed {
            // The caller drops or reuses the job, outside the lock: dropping a
            // sequenced job completes its slot.
            drop(state);
            return Err(MacWorkerTryPushError::Closed(Box::new(job)));
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

    fn push_blocking(&self, job: T) -> Result<(), MacWorkerPushError<T>> {
        let mut state = self
            .inner
            .state
            .lock()
            .expect("encrypt worker queue poisoned");
        loop {
            if state.closed {
                drop(state);
                return Err(MacWorkerPushError(Box::new(job)));
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

#[cfg(any(target_os = "macos", test))]
impl<T> Drop for MacWorkerSender<T> {
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

/// Closing from the receiver side matters because a sender waiting in
/// `push_blocking` on a full queue sleeps on `not_full`, and only the
/// receiver draining the queue wakes it. If the worker thread exits (a
/// panic unwinding included), nothing else would, and the rx_loop behind
/// that sender would block forever.
#[cfg(any(target_os = "macos", test))]
impl<T> Drop for MacWorkerReceiver<T> {
    fn drop(&mut self) {
        // This can run while the worker thread unwinds from a panic, where
        // a second panic would abort the process, so tolerate poisoning.
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.closed = true;
        let queued = std::mem::take(&mut state.queue);
        drop(state);
        // Queued jobs hold key copies and sockets; free them outside the lock.
        drop(queued);
        self.inner.not_full.notify_all();
        self.inner.not_empty.notify_all();
    }
}

#[cfg(any(target_os = "macos", test))]
impl<T> MacWorkerReceiver<T> {
    fn recv_batch(&self, batch: &mut Vec<T>, max: usize) -> bool {
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
type WorkerSender = MacWorkerSender<QueuedFmpSendJob>;

#[cfg(not(target_os = "macos"))]
type WorkerSender = Sender<QueuedFmpSendJob>;

#[cfg(target_os = "macos")]
type WorkerReceiver = MacWorkerReceiver<QueuedFmpSendJob>;

#[cfg(not(target_os = "macos"))]
type WorkerReceiver = Receiver<QueuedFmpSendJob>;

fn worker_channel() -> (WorkerSender, WorkerReceiver) {
    #[cfg(target_os = "macos")]
    {
        mac_worker_channel(WORKER_CHANNEL_CAP)
    }
    #[cfg(not(target_os = "macos"))]
    {
        bounded::<QueuedFmpSendJob>(WORKER_CHANNEL_CAP)
    }
}

/// Start the production worker loop on `rx` in a named OS thread.
fn spawn_worker(idx: usize, rx: WorkerReceiver) -> std::io::Result<std::thread::JoinHandle<()>> {
    let builder = std::thread::Builder::new().name(format!("fips-encrypt-{idx}"));
    #[cfg(target_os = "macos")]
    {
        builder.spawn(move || run_worker_macos(idx, rx))
    }
    #[cfg(not(target_os = "macos"))]
    {
        builder.spawn(move || run_worker(idx, rx))
    }
}

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
/// experiment, which is why dispatch hashes by destination). Multi-peer /
/// multi-flow benches still get parallelism since different
/// destinations hash to different workers.
#[derive(Clone)]
pub(crate) struct EncryptWorkerPool {
    workers: Arc<WorkerSet<WorkerSender>>,
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
    ///
    /// A worker thread that cannot be started is logged and left dead;
    /// the caller reads how many started from [`Self::liveness`].
    pub fn spawn(n: usize) -> Self {
        Self::start_with(n, spawn_worker)
    }

    /// Build the pool, starting each worker with `spawn`. Production passes
    /// [`spawn_worker`]; tests pass workers that fail to start or exit on cue.
    fn start_with(
        n: usize,
        spawn: impl FnMut(usize, WorkerReceiver) -> std::io::Result<std::thread::JoinHandle<()>>,
    ) -> Self {
        Self {
            workers: Arc::new(WorkerSet::start("encrypt", n, worker_channel, spawn)),
            #[cfg(target_os = "macos")]
            macos_senders: Arc::new(MacSequencedSendFlows::default()),
            #[cfg(target_os = "macos")]
            next_worker: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Whether each worker is still running, and how many dispatches a dead
    /// one refused.
    pub(crate) fn liveness(&self) -> &dyn WorkerLiveness {
        &*self.workers
    }

    /// Dispatch a job to the worker that owns its destination flow.
    /// The hash is over `dest_addr` so every packet for one peer's
    /// kernel `SocketAddr` lands on the same worker and stays in
    /// order — required for TCP's fast-retransmit logic above to
    /// behave on a single-flow run. The worker handles send errors
    /// itself via stats counters.
    ///
    /// A job whose worker has exited is never queued: it is counted,
    /// logged at WARN, and handed back as `Err` so the caller can seal
    /// and send it on its own path with the counters it already
    /// reserved. A job is handed back only when no worker has it, so
    /// each reserved counter is still used at most once. In the macOS
    /// ordered mode the job's place in its flow is released as a skip
    /// before it is handed back.
    ///
    /// Uses `try_send` for the common uncontended case, then blocks
    /// only when the bounded worker channel is full. These jobs carry
    /// tunneled IP packets, not application UDP datagrams; dropping at
    /// this internal queue makes TCP-over-TUN collapse with avoidable
    /// retransmits. Blocking here pushes back toward the TUN reader
    /// and lets the kernel/app TCP stack pace the flow instead.
    #[must_use = "a job handed back was not sent; the caller must send it another way"]
    pub fn dispatch(&self, job: FmpSendJob) -> Result<(), Box<FmpSendJob>> {
        let (idx, job) = self.prepare_dispatch(job);
        let Err(refused) = self.dispatch_to_worker(idx, job) else {
            return Ok(());
        };
        let n = self.workers.note_refused();
        if worth_logging(n) {
            warn!(
                pool = "encrypt",
                worker = idx,
                refused = n + 1,
                "Encrypt worker has exited; encrypting the packet on the main loop"
            );
        }
        Err(refused.into_job())
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
            let idx = (h.finish() as usize) % self.workers.len();
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
        let idx = ticket % self.workers.len();
        (idx, QueuedFmpSendJob::macos_sequenced(job, flow))
    }

    #[cfg(not(target_os = "macos"))]
    fn prepare_dispatch(&self, job: FmpSendJob) -> (usize, QueuedFmpSendJob) {
        let idx = self.worker_index_for(job.dest_addr);
        (idx, QueuedFmpSendJob::direct(job))
    }

    /// The worker that owns `dest`'s flow.
    #[cfg(not(target_os = "macos"))]
    fn worker_index_for(&self, dest: SocketAddr) -> usize {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        dest.hash(&mut h);
        (h.finish() as usize) % self.workers.len()
    }

    /// Queue `job` on worker `idx`, or hand it back when that worker has
    /// exited.
    #[cfg(target_os = "macos")]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) -> Result<(), Refused> {
        let sender = self.workers.sender(idx);
        match sender.try_push(job) {
            Ok(()) => Ok(()),
            Err(MacWorkerTryPushError::Full(job)) => {
                static FULL_COUNT: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if worth_logging(n) {
                    warn!(
                        worker = idx,
                        full_events = n + 1,
                        "EncryptWorker channel full; applying outbound backpressure"
                    );
                }
                sender
                    .push_blocking(*job)
                    .map_err(|MacWorkerPushError(job)| Refused(job))
            }
            Err(MacWorkerTryPushError::Closed(job)) => Err(Refused(job)),
        }
    }

    /// Queue `job` on worker `idx`, or hand it back when that worker has
    /// exited.
    #[cfg(not(target_os = "macos"))]
    fn dispatch_to_worker(&self, idx: usize, job: QueuedFmpSendJob) -> Result<(), Refused> {
        let sender = self.workers.sender(idx);
        match sender.try_send(job) {
            Ok(()) => Ok(()),
            Err(TrySendError::Full(job)) => {
                static FULL_COUNT: portable_atomic::AtomicU64 = portable_atomic::AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if worth_logging(n) {
                    warn!(
                        worker = idx,
                        full_events = n + 1,
                        "EncryptWorker channel full; applying outbound backpressure"
                    );
                }
                sender
                    .send(job)
                    .map_err(|SendError(job)| Refused(Box::new(job)))
            }
            Err(TrySendError::Disconnected(job)) => Err(Refused(Box::new(job))),
        }
    }
}

#[cfg(test)]
impl EncryptWorkerPool {
    /// A pool whose workers behave as `plan` says; `Run` workers are the
    /// production loop.
    pub(crate) fn for_test(plan: Vec<TestWorker>) -> Self {
        Self::start_with(plan.len(), test_spawner(plan, spawn_worker))
    }

    /// The worker a job to `dest` is dispatched to, where that depends on
    /// `dest` alone. On macOS it also depends on the sending sockets, or on a
    /// round-robin in the ordered mode, so there it is `None`.
    pub(crate) fn worker_index_for_dest(&self, dest: SocketAddr) -> Option<usize> {
        #[cfg(target_os = "macos")]
        {
            let _ = dest;
            None
        }
        #[cfg(not(target_os = "macos"))]
        {
            Some(self.worker_index_for(dest))
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
    last_prune_ms: portable_atomic::AtomicU64,
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
        // A closed flow's sender thread has exited and sends nothing more, so
        // it is replaced rather than handed further jobs.
        if let Some(flow) = flows.get(&key)
            && !flow.is_closed()
        {
            flow.mark_used(now_ms);
            return Arc::clone(flow);
        }

        let flow = MacSequencedSendFlow::spawn(
            key,
            job.socket.clone(),
            job.connected_socket.clone(),
            job.dest_addr,
            job.stats.clone(),
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
            if flow.is_closed() || flow.is_idle(now_ms, idle_ms) {
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
    connected_socket: Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>>,
    dest_addr: SocketAddr,
    /// The sending transport's counters, which this flow's sender thread
    /// counts each datagram into.
    stats: Arc<UdpStats>,
    next_seq: portable_atomic::AtomicU64,
    last_used_ms: portable_atomic::AtomicU64,
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
impl MacCompletionGroup {
    /// Hand every item to the flow's sender.
    fn deliver(mut self) {
        let items = std::mem::take(&mut self.items);
        self.flow.complete_many(items);
    }
}

/// A group dropped before delivery, when its worker unwinds, still completes
/// its slots, each as a skip, so the flow moves past them.
#[cfg(target_os = "macos")]
impl Drop for MacCompletionGroup {
    fn drop(&mut self) {
        for (seq, _) in self.items.drain(..) {
            self.flow.complete_skip(seq);
        }
    }
}

/// One reserved slot in a flow's send order, owed a completion.
///
/// Every slot the flow hands out must be completed, or its sender waits at
/// the gap for ever and every later packet for that destination piles up
/// behind it. A ticket dropped without being taken, because its job never
/// reached a worker or its worker died, completes its slot as a skip.
#[cfg(target_os = "macos")]
struct MacSeqTicket {
    flow: Option<Arc<MacSequencedSendFlow>>,
    seq: u64,
}

#[cfg(target_os = "macos")]
impl MacSeqTicket {
    fn reserve(flow: Arc<MacSequencedSendFlow>) -> Self {
        let seq = flow.reserve_seq();
        Self {
            flow: Some(flow),
            seq,
        }
    }

    /// Take the slot, leaving its completion to the caller.
    fn take(mut self) -> (Arc<MacSequencedSendFlow>, u64) {
        let flow = self.flow.take().expect("a ticket is taken once");
        (flow, self.seq)
    }
}

#[cfg(target_os = "macos")]
impl Drop for MacSeqTicket {
    fn drop(&mut self) {
        if let Some(flow) = self.flow.take() {
            flow.complete_skip(self.seq);
        }
    }
}

/// Closes its flow when the flow's sender thread leaves `run`, including by
/// a panic, so completions waiting for room are released instead of waiting
/// on a sender that will never drain.
#[cfg(target_os = "macos")]
struct MacSenderExit<'a>(&'a MacSequencedSendFlow);

#[cfg(target_os = "macos")]
impl Drop for MacSenderExit<'_> {
    fn drop(&mut self) {
        self.0.close();
    }
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
        connected_socket: Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>>,
        dest_addr: SocketAddr,
        stats: Arc<UdpStats>,
        now_ms: u64,
    ) -> Arc<Self> {
        let flow = Arc::new(Self {
            key,
            socket,
            connected_socket,
            dest_addr,
            stats,
            next_seq: portable_atomic::AtomicU64::new(0),
            last_used_ms: portable_atomic::AtomicU64::new(now_ms),
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

        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.pending.is_empty()
            && state.next_send_seq == self.next_seq.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.closed = true;
        drop(state);
        self.ready_cv.notify_one();
        self.space_cv.notify_all();
    }

    fn is_closed(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .closed
    }

    /// Complete one slot as a skip without waiting for room, so a caller on
    /// the rx_loop never blocks here.
    fn complete_skip(&self, seq: u64) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        if state.closed {
            return;
        }
        let wakes_sender = seq == state.next_send_seq;
        state.pending.insert(seq, MacSendItem::Skip);
        drop(state);
        if wakes_sender {
            self.ready_cv.notify_one();
        }
    }

    fn complete_many(&self, items: Vec<(u64, MacSendItem)>) {
        const PENDING_CAP: usize = 4096;
        if items.is_empty() {
            return;
        }

        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let mut wakes_sender = false;
        for (seq, item) in items {
            while !state.closed
                && state.pending.len() >= PENDING_CAP
                && seq != state.next_send_seq
                && !wakes_sender
            {
                state = self
                    .space_cv
                    .wait(state)
                    .unwrap_or_else(PoisonError::into_inner);
            }
            // The sender has exited; what is left of `items` is dropped.
            if state.closed {
                return;
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
        // Closes the flow however this returns, a panic included.
        let _exit = MacSenderExit(&self);
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
                        &self.stats,
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
    ticket: MacSeqTicket,
    item: MacSendItem,
) {
    let (flow, seq) = ticket.take();
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
fn run_worker_macos(idx: usize, rx: MacWorkerReceiver<QueuedFmpSendJob>) {
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

/// Why a job could not be sealed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum SealError {
    /// The offsets the job carries do not fit its buffer.
    #[error("job layout does not fit its buffer")]
    Layout,
    /// The AEAD refused to seal.
    #[error("AEAD seal failed")]
    Aead,
}

impl FmpSendJob {
    /// Seal this job on the calling thread, as its worker would have, and
    /// return the wire packet. For a job its worker refused: the counters it
    /// carries were reserved for it and are used here, once.
    pub(crate) fn seal_inline(self) -> Result<Vec<u8>, SealError> {
        let FmpSendJob {
            cipher,
            counter,
            mut wire_buf,
            fsp_seal,
            ..
        } = self;
        seal_wire(&cipher, counter, &mut wire_buf, fsp_seal)?;
        Ok(wire_buf)
    }
}

/// Seal one job's wire buffer in place: the inner FSP seal first when the job
/// carries one, then the outer FMP seal over `[16..]` with the header as AAD.
/// Each tag is appended into capacity the builder reserved, so the buffer
/// becomes the wire packet without reallocating.
///
/// A layout that does not fit the buffer is refused rather than indexed out of
/// bounds: this runs on a worker thread and, for a job that worker refused, on
/// the rx loop, where a panic would end the node rather than one worker.
fn seal_wire(
    cipher: &LessSafeKey,
    counter: u64,
    wire_buf: &mut Vec<u8>,
    fsp_seal: Option<FspSealJob>,
) -> Result<(), SealError> {
    if let Some(fsp) = fsp_seal {
        let aad_end = fsp
            .aad_offset
            .checked_add(FSP_HEADER_SIZE)
            .ok_or(SealError::Layout)?;
        if aad_end > fsp.plaintext_offset || fsp.plaintext_offset > wire_buf.len() {
            return Err(SealError::Layout);
        }

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&fsp.counter.to_le_bytes());
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let (prefix, plaintext_slice) = wire_buf.split_at_mut(fsp.plaintext_offset);
        let aad = &prefix[fsp.aad_offset..aad_end];
        let tag = fsp
            .cipher
            .seal_in_place_separate_tag(nonce, Aad::from(aad), plaintext_slice)
            .map_err(|_| SealError::Aead)?;
        wire_buf.extend_from_slice(tag.as_ref());
    }

    if wire_buf.len() < ESTABLISHED_HEADER_SIZE {
        return Err(SealError::Layout);
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
    let tag = cipher
        .seal_in_place_separate_tag(nonce, Aad::from(&*header_slice), plaintext_slice)
        .map_err(|_| SealError::Aead)?;
    // wire_buf already has `+16` capacity reserved → no realloc.
    wire_buf.extend_from_slice(tag.as_ref());
    Ok(())
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
        connected_socket: Option<std::sync::Arc<crate::transport::udp::ConnectedPeerSocket>>,
        dest_addr: SocketAddr,
        stats: Arc<UdpStats>,
        wire_packets: Vec<Vec<u8>>,
        drop_on_backpressure: bool,
    }
    #[cfg(unix)]
    let mut groups: Vec<EncryptedGroup> = Vec::with_capacity(1);
    #[cfg(target_os = "macos")]
    let mut macos_completions: Vec<MacCompletionGroup> = Vec::with_capacity(1);

    for queued in batch.drain(..) {
        #[cfg(target_os = "macos")]
        let QueuedFmpSendJob { job, macos_ticket } = queued;
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
            stats,
            drop_on_backpressure,
            queued_at,
        } = job;
        crate::perf_profile::record_since(
            crate::perf_profile::Stage::FmpWorkerQueueWait,
            queued_at,
        );
        if seal_wire(&cipher, counter, &mut wire_buf, fsp_seal).is_err() {
            #[cfg(target_os = "macos")]
            if let Some(ticket) = macos_ticket {
                push_mac_completion(&mut macos_completions, ticket, MacSendItem::Skip);
            }
            continue;
        }

        #[cfg(target_os = "macos")]
        if let Some(ticket) = macos_ticket {
            push_mac_completion(
                &mut macos_completions,
                ticket,
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
                if g.socket.as_raw_fd() != socket_fd || !Arc::ptr_eq(&g.stats, &stats) {
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
                    stats,
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
            let _ = (socket, dest_addr, stats, wire_buf);
        }
    }

    #[cfg(target_os = "macos")]
    for group in macos_completions {
        group.deliver();
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

    // Every datagram is counted once in its transport's stats: as sent
    // when the kernel takes it, as a send error when it is given up on.
    // A hard error ends the flush, so the groups after the failing one
    // are never tried; `abandon` counts their datagrams as send errors.
    #[cfg(unix)]
    let mut groups = groups.into_iter();
    #[cfg(unix)]
    let abandon = |rest: std::vec::IntoIter<EncryptedGroup>| {
        for group in rest {
            group.stats.record_unsent(group.wire_packets.len() as u64);
        }
    };

    #[cfg(target_os = "linux")]
    while let Some(group) = groups.next() {
        let mut backpressure = SendBackpressurePacer::default();
        let EncryptedGroup {
            socket,
            connected_socket,
            dest_addr,
            stats,
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
                    stats.record_sends(wire_packets.len() as u64, wire_bytes(&wire_packets));
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
                    stats.record_unsent(wire_packets.len() as u64);
                    abandon(groups);
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
                    stats.record_unsent((wire_packets.len() - sent) as u64);
                    abandon(groups);
                    return Err(format!("sendmmsg(2) failed: {err}").into());
                }
            };
            if n == 0 {
                stats.record_unsent((wire_packets.len() - sent) as u64);
                break;
            }
            stats.record_sends(n as u64, wire_bytes(&wire_packets[sent..sent + n]));
            sent += n;
            backpressure.record_success();
            record_udp_send_path(connected, n as u64);
        }
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    while let Some(group) = groups.next() {
        let mut backpressure = SendBackpressurePacer::default();
        #[cfg(target_os = "macos")]
        let (fd, connected) = match group.connected_socket.as_ref() {
            Some(s) => (s.as_raw_fd(), true),
            None => (group.socket.as_raw_fd(), false),
        };
        #[cfg(not(target_os = "macos"))]
        let (fd, connected) = (group.socket.as_raw_fd(), false);
        for (i, data) in group.wire_packets.iter().enumerate() {
            if let Err(err) = send_one_with_backpressure(
                fd,
                connected,
                &group.dest_addr,
                data,
                &mut backpressure,
                group.drop_on_backpressure,
                &group.stats,
            ) {
                if group.drop_on_backpressure && is_send_backpressure(&err) {
                    continue;
                }
                let rest = group.wire_packets.len() - i - 1;
                group.stats.record_unsent(rest as u64);
                abandon(groups);
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

/// Total bytes in `packets`: the UDP payload bytes one batched send
/// hands the kernel when it takes every packet in the slice.
#[cfg(target_os = "linux")]
fn wire_bytes(packets: &[Vec<u8>]) -> u64 {
    packets.iter().map(|p| p.len() as u64).sum()
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

        static SEND_BACKPRESSURE_COUNT: portable_atomic::AtomicU64 =
            portable_atomic::AtomicU64::new(0);
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
    static SEND_BACKPRESSURE_DROP_COUNT: portable_atomic::AtomicU64 =
        portable_atomic::AtomicU64::new(0);
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

/// The most packets one UDP GSO send carries, the kernel's segment limit
/// on older kernels. `send_batch_gso` reports a whole group as sent, so a
/// larger group must not reach it.
#[cfg(target_os = "linux")]
const GSO_SEGMENTS: usize = 64;

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
    if packets.len() > GSO_SEGMENTS {
        // More than one GSO send can carry; sendmmsg's loop sends them all.
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
    debug_assert!(packets.len() <= GSO_SEGMENTS);
    let n = packets.len().min(GSO_SEGMENTS);
    if n == 0 {
        return Ok(());
    }

    let seg_size = packets[0].len() as u16;
    let sa: socket2::SockAddr = dest.into();

    // Stack-allocated arrays sized for the worst case in this batch.
    let mut iovs: [libc::iovec; GSO_SEGMENTS] = unsafe { std::mem::zeroed() };
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
                stats: Arc::new(UdpStats::new()),
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
                stats: Arc::new(UdpStats::new()),
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

    /// The seal a refused job gets on the main loop produces a packet the
    /// canonical receive-side decoders accept, inner FSP layer included.
    #[test]
    fn an_inline_seal_matches_the_worker_wire_layout() {
        use crate::NodeAddr;
        use crate::noise::TAG_SIZE;
        use crate::proto::fmp::wire::{EncryptedHeader, build_established_header};
        use crate::proto::fsp::wire::build_fsp_header;
        use crate::proto::link::{
            LinkMessageType, SESSION_DATAGRAM_HEADER_SIZE, SessionDatagramRef,
        };
        use crate::utils::index::SessionIndex;

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        let _enter = rt.enter();
        let socket = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
            .expect("open send socket")
            .into_async()
            .expect("into_async");

        let fmp_cipher = test_cipher(0x31);
        let fsp_cipher = test_cipher(0x32);
        let (fmp_counter, fsp_counter) = (900u64, 77u64);
        let fsp_plaintext = b"sealed on the main loop".to_vec();
        let link_plaintext_len =
            SESSION_DATAGRAM_HEADER_SIZE + FSP_HEADER_SIZE + fsp_plaintext.len();
        let fmp_inner_len = 4 + link_plaintext_len + TAG_SIZE;
        let fsp_header = build_fsp_header(fsp_counter, 0, fsp_plaintext.len() as u16);
        let fmp_header =
            build_established_header(SessionIndex::new(5), fmp_counter, 0, fmp_inner_len as u16);

        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + fmp_inner_len + TAG_SIZE);
        wire_buf.extend_from_slice(&fmp_header);
        wire_buf.extend_from_slice(&7u32.to_le_bytes());
        wire_buf.push(LinkMessageType::SessionDatagram.to_byte());
        wire_buf.push(16);
        wire_buf.extend_from_slice(&1280u16.to_le_bytes());
        wire_buf.extend_from_slice(NodeAddr::from_bytes([0xAA; 16]).as_bytes());
        wire_buf.extend_from_slice(NodeAddr::from_bytes([0xBB; 16]).as_bytes());
        let aad_offset = wire_buf.len();
        wire_buf.extend_from_slice(&fsp_header);
        let plaintext_offset = wire_buf.len();
        wire_buf.extend_from_slice(&fsp_plaintext);

        let job = FmpSendJob {
            cipher: fmp_cipher.clone(),
            counter: fmp_counter,
            wire_buf,
            fsp_seal: Some(FspSealJob {
                cipher: fsp_cipher.clone(),
                counter: fsp_counter,
                aad_offset,
                plaintext_offset,
            }),
            socket: socket.clone(),
            dest_addr: "127.0.0.1:9".parse().unwrap(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            stats: Arc::new(UdpStats::new()),
            drop_on_backpressure: true,
            queued_at: None,
        };
        let wire = job.seal_inline().expect("inline seal");

        let parsed = EncryptedHeader::parse(&wire).expect("FMP header parses");
        assert_eq!(parsed.counter, fmp_counter);
        let fmp_plaintext = crate::noise::open(
            Some(&fmp_cipher),
            fmp_counter,
            &parsed.header_bytes,
            &wire[ESTABLISHED_HEADER_SIZE..],
        )
        .expect("FMP open");
        let datagram = SessionDatagramRef::decode(&fmp_plaintext[5..]).expect("datagram decodes");
        let inner = crate::noise::open(
            Some(&fsp_cipher),
            fsp_counter,
            &datagram.payload[..FSP_HEADER_SIZE],
            &datagram.payload[FSP_HEADER_SIZE..],
        )
        .expect("FSP open");
        assert_eq!(inner, fsp_plaintext);

        // FMP-only twin: a link message carries no inner seal.
        let link_plaintext = b"\x10link message".to_vec();
        let header = build_established_header(
            SessionIndex::new(5),
            fmp_counter + 1,
            0,
            (4 + link_plaintext.len()) as u16,
        );
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + 4 + 64);
        wire_buf.extend_from_slice(&header);
        wire_buf.extend_from_slice(&9u32.to_le_bytes());
        wire_buf.extend_from_slice(&link_plaintext);
        let job = FmpSendJob {
            cipher: fmp_cipher.clone(),
            counter: fmp_counter + 1,
            wire_buf,
            fsp_seal: None,
            socket,
            dest_addr: "127.0.0.1:9".parse().unwrap(),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            stats: Arc::new(UdpStats::new()),
            drop_on_backpressure: false,
            queued_at: None,
        };
        let wire = job.seal_inline().expect("inline seal");
        let opened = crate::noise::open(
            Some(&fmp_cipher),
            fmp_counter + 1,
            &wire[..ESTABLISHED_HEADER_SIZE],
            &wire[ESTABLISHED_HEADER_SIZE..],
        )
        .expect("FMP open");
        assert_eq!(&opened[4..], &link_plaintext[..]);
    }

    /// A job whose offsets do not fit its buffer is refused, not indexed out
    /// of bounds. On the main loop a panic here would end the node.
    #[test]
    fn a_job_whose_layout_does_not_fit_is_refused_not_a_panic() {
        let cipher = test_cipher(9);
        let mut short = vec![0u8; ESTABLISHED_HEADER_SIZE - 1];
        assert!(matches!(
            seal_wire(&cipher, 1, &mut short, None),
            Err(SealError::Layout)
        ));

        let mut buf = vec![0u8; 64];
        let overflowing = FspSealJob {
            cipher: test_cipher(8),
            counter: 1,
            aad_offset: usize::MAX - 2,
            plaintext_offset: 40,
        };
        assert!(matches!(
            seal_wire(&cipher, 1, &mut buf, Some(overflowing)),
            Err(SealError::Layout)
        ));
    }

    /// A job carrying `plaintext_len` bytes of plaintext for `dest`, sent
    /// on `socket` and counted in `stats`. Its wire packet is
    /// `ESTABLISHED_HEADER_SIZE + plaintext_len + TAG_SIZE` bytes.
    fn counted_job(
        socket: &AsyncUdpSocket,
        dest: SocketAddr,
        plaintext_len: usize,
        counter: u64,
        stats: &Arc<UdpStats>,
    ) -> FmpSendJob {
        let mut wire_buf =
            Vec::with_capacity(ESTABLISHED_HEADER_SIZE + plaintext_len + crate::noise::TAG_SIZE);
        wire_buf.extend_from_slice(&[0xA5; ESTABLISHED_HEADER_SIZE]);
        wire_buf.resize(ESTABLISHED_HEADER_SIZE + plaintext_len, 0);
        FmpSendJob {
            cipher: test_cipher(3),
            counter,
            wire_buf,
            fsp_seal: None,
            socket: socket.clone(),
            dest_addr: dest,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            connected_socket: None,
            stats: stats.clone(),
            drop_on_backpressure: false,
            queued_at: None,
        }
    }

    /// The wire length of a `counted_job` carrying `plaintext_len` bytes.
    fn wire_len(plaintext_len: usize) -> u64 {
        (ESTABLISHED_HEADER_SIZE + plaintext_len + crate::noise::TAG_SIZE) as u64
    }

    /// Receive datagrams on `sock` until it goes quiet, returning how many
    /// arrived.
    fn count_received(sock: &UdpSocket) -> u64 {
        sock.set_read_timeout(Some(std::time::Duration::from_millis(200)))
            .expect("set_read_timeout");
        let mut buf = [0u8; 2048];
        let mut n = 0;
        while sock.recv_from(&mut buf).is_ok() {
            n += 1;
        }
        n
    }

    /// A nonblocking loopback send socket registered with `rt`'s reactor.
    fn open_async(rt: &tokio::runtime::Runtime) -> AsyncUdpSocket {
        let _enter = rt.enter();
        UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
            .expect("open send socket")
            .into_async()
            .expect("into_async")
    }

    /// The worker's sends bypass `UdpTransport::send_async`, so the worker
    /// must count them itself: each datagram it hands the kernel counts
    /// once, in the stats of the transport whose job it was. The batch
    /// mixes a same-size run (the UDP GSO group on Linux), a lone packet
    /// to a second destination (plain `sendmmsg`), and a job from a second
    /// transport, whose datagram must land in that transport's stats only.
    #[test]
    fn each_datagram_a_flush_sends_counts_once_in_its_own_transports_stats() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        let recv_a = UdpSocket::bind("127.0.0.1:0").expect("bind recv_a");
        let recv_b = UdpSocket::bind("127.0.0.1:0").expect("bind recv_b");
        let addr_a = recv_a.local_addr().unwrap();
        let addr_b = recv_b.local_addr().unwrap();
        let first = open_async(&rt);
        let second = open_async(&rt);
        let stats = Arc::new(UdpStats::new());
        let other = Arc::new(UdpStats::new());

        const RUN: u64 = 6;
        const RUN_LEN: usize = 100;
        const LONE_LEN: usize = 40;
        const OTHER_LEN: usize = 60;
        let mut batch: Vec<FmpSendJob> = (0..RUN)
            .map(|i| counted_job(&first, addr_a, RUN_LEN, i, &stats))
            .collect();
        batch.push(counted_job(&first, addr_b, LONE_LEN, RUN, &stats));
        batch.push(counted_job(&second, addr_b, OTHER_LEN, RUN + 1, &other));
        flush_direct_batch_sync(&mut batch).expect("flush ok");

        assert_eq!(count_received(&recv_a), RUN);
        assert_eq!(count_received(&recv_b), 2);
        let counted = stats.snapshot();
        assert_eq!(
            counted.packets_sent,
            RUN + 1,
            "each datagram the worker sent must count once"
        );
        assert_eq!(
            counted.bytes_sent,
            RUN * wire_len(RUN_LEN) + wire_len(LONE_LEN)
        );
        assert_eq!(counted.send_errors, 0);
        let counted = other.snapshot();
        assert_eq!(
            counted.packets_sent, 1,
            "a datagram must count in the stats of the transport whose job it was"
        );
        assert_eq!(counted.bytes_sent, wire_len(OTHER_LEN));
    }

    /// Datagrams sent on a per-peer connected socket count in the stats
    /// of the transport the job came from, as wildcard sends do.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn datagrams_sent_on_a_connected_socket_count_once_in_the_transports_stats() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let peer = recv.local_addr().unwrap();
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let owned = crate::transport::udp::open_connected_fd(local, peer, 1 << 16, 1 << 16, None)
            .expect("open a connected UDP socket");
        let connected = Arc::new(crate::transport::udp::ConnectedPeerSocket::from_fd(
            owned, peer, local,
        ));
        let wildcard = open_async(&rt);
        let stats = Arc::new(UdpStats::new());

        const N: u64 = 4;
        const LEN: usize = 80;
        let mut batch: Vec<FmpSendJob> = (0..N)
            .map(|i| {
                let mut job = counted_job(&wildcard, peer, LEN, i, &stats);
                job.connected_socket = Some(connected.clone());
                job
            })
            .collect();
        flush_direct_batch_sync(&mut batch).expect("flush ok");

        assert_eq!(count_received(&recv), N);
        let counted = stats.snapshot();
        assert_eq!(counted.packets_sent, N);
        assert_eq!(counted.bytes_sent, N * wire_len(LEN));
        assert_eq!(counted.send_errors, 0);
    }

    /// A hard send error ends the flush. The failing datagram and every
    /// datagram the flush then never tries count as send errors, none as
    /// sent. The failing destination is an IPv6 address on an IPv4
    /// socket, which the kernel refuses outright; it is a single packet so
    /// the Linux GSO path, whose refusal would switch GSO off for the
    /// whole process, is not taken.
    #[test]
    fn datagrams_a_flush_abandons_on_a_send_error_count_as_send_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let good = recv.local_addr().unwrap();
        let bad: SocketAddr = "[::1]:9".parse().unwrap();
        let socket = open_async(&rt);
        let stats = Arc::new(UdpStats::new());

        let mut batch = vec![
            counted_job(&socket, bad, 40, 0, &stats),
            counted_job(&socket, good, 50, 1, &stats),
            counted_job(&socket, good, 70, 2, &stats),
        ];
        assert!(
            flush_direct_batch_sync(&mut batch).is_err(),
            "precondition: the kernel refuses the IPv6 destination"
        );

        assert_eq!(count_received(&recv), 0);
        let counted = stats.snapshot();
        assert_eq!(counted.packets_sent, 0);
        assert_eq!(counted.bytes_sent, 0);
        assert_eq!(
            counted.send_errors, 3,
            "the refused datagram and the two never tried must each count once"
        );
    }

    /// A hard error on the Linux UDP GSO path ends the flush as one on
    /// `sendmmsg` does: every datagram of the failing group and of the
    /// groups after it counts as a send error, none as sent. The error is
    /// the ECONNREFUSED a connected socket reports after an ICMP port
    /// unreachable; unlike EINVAL, it does not switch GSO off for the
    /// whole process. On a kernel without UDP GSO the group takes
    /// `sendmmsg` and the counts must hold the same.
    #[cfg(target_os = "linux")]
    #[test]
    fn datagrams_a_gso_send_error_abandons_count_as_send_errors() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("tokio rt");
        let closed = UdpSocket::bind("127.0.0.1:0").expect("bind closed");
        let peer = closed.local_addr().unwrap();
        drop(closed);
        let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
        let good = recv.local_addr().unwrap();
        let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let owned = crate::transport::udp::open_connected_fd(local, peer, 1 << 16, 1 << 16, None)
            .expect("open a connected UDP socket");
        let connected = Arc::new(crate::transport::udp::ConnectedPeerSocket::from_fd(
            owned, peer, local,
        ));
        let wildcard = open_async(&rt);
        let to_peer = |len: usize, counter: u64, stats: &Arc<UdpStats>| {
            let mut job = counted_job(&wildcard, peer, len, counter, stats);
            job.connected_socket = Some(connected.clone());
            job
        };

        // One datagram to the closed port draws the ICMP port unreachable
        // that the socket's next send reports as ECONNREFUSED.
        let mut prime = vec![to_peer(40, 0, &Arc::new(UdpStats::new()))];
        flush_direct_batch_sync(&mut prime).expect("priming send ok");
        std::thread::sleep(std::time::Duration::from_millis(50));

        const RUN: u64 = 4;
        const LEN: usize = 100;
        let stats = Arc::new(UdpStats::new());
        let mut batch: Vec<FmpSendJob> = (1..=RUN).map(|i| to_peer(LEN, i, &stats)).collect();
        batch.push(counted_job(&wildcard, good, 40, RUN + 1, &stats));
        let err = flush_direct_batch_sync(&mut batch)
            .expect_err("precondition: the connected socket reports the refused port");
        if !GSO_DISABLED.load(std::sync::atomic::Ordering::Relaxed) {
            assert!(
                err.to_string().contains("UDP_GSO"),
                "precondition: the same-size group must fail on the GSO path, got: {err}"
            );
        }

        assert_eq!(count_received(&recv), 0);
        let counted = stats.snapshot();
        assert_eq!(counted.packets_sent, 0);
        assert_eq!(counted.bytes_sent, 0);
        assert_eq!(
            counted.send_errors,
            RUN + 1,
            "the failing group's datagrams and the one never tried must each count once"
        );
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
    fn gso_eligible_rejects_a_group_larger_than_one_gso_send_carries() {
        let at_cap: Vec<_> = (0..GSO_SEGMENTS).map(|_| pkt(1500)).collect();
        assert!(gso_eligible_sizes(&at_cap));
        let over: Vec<_> = (0..=GSO_SEGMENTS).map(|_| pkt(1500)).collect();
        assert!(!gso_eligible_sizes(&over));
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
                    stats: Arc::new(UdpStats::new()),
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

/// Send one datagram, retrying while the kernel reports backpressure, and
/// count it once in `stats`: as sent, or as a send error when it is
/// dropped under backpressure or the send fails.
#[cfg(all(unix, not(target_os = "linux")))]
fn send_one_with_backpressure(
    fd: std::os::unix::io::RawFd,
    connected: bool,
    dest: &SocketAddr,
    data: &[u8],
    backpressure: &mut SendBackpressurePacer,
    drop_on_backpressure: bool,
    stats: &UdpStats,
) -> std::io::Result<()> {
    loop {
        let result = if connected {
            send_connected_raw(fd, data)
        } else {
            send_one_raw(fd, data, dest)
        };
        match result {
            Ok(bytes) => {
                backpressure.record_success();
                record_udp_send_path(connected, 1);
                stats.record_send(bytes);
                return Ok(());
            }
            Err(err) if is_send_backpressure(&err) => {
                if backpressure.pause(&err) && drop_on_backpressure {
                    record_udp_send_backpressure_drop(&err);
                    stats.record_send_error();
                    return Err(err);
                }
            }
            Err(err) => {
                stats.record_send_error();
                return Err(err);
            }
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

/// Tests for the bounded worker queue the macOS encrypt pool uses. The
/// queue is generic, so these run on every platform against small item
/// types. Every wait is bounded so a regression fails instead of hanging.
#[cfg(test)]
mod mac_queue_tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(5);

    /// Run `push_blocking(item)` on a helper thread and return a channel
    /// that yields its result.
    fn spawn_pusher<T: Send + 'static>(
        tx: MacWorkerSender<T>,
        item: T,
    ) -> mpsc::Receiver<Result<(), MacWorkerPushError<T>>> {
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            let result = tx.push_blocking(item);
            let _ = done_tx.send(result);
        });
        done_rx
    }

    #[test]
    fn push_blocking_returns_error_when_worker_thread_panics_with_full_queue() {
        let (tx, rx) = mac_worker_channel::<u32>(2);
        assert!(tx.try_push(1).is_ok());
        assert!(tx.try_push(2).is_ok());
        match tx.try_push(9) {
            Err(MacWorkerTryPushError::Full(job)) => assert_eq!(*job, 9),
            _ => panic!("try_push on a full queue should hand the job back"),
        }

        // The worker owns the receiver and dies without draining, once the
        // pusher below has had time to start waiting for space.
        let (die_tx, die_rx) = mpsc::channel::<()>();
        let worker = thread::spawn(move || {
            let _rx = rx;
            let _ = die_rx.recv();
            panic!("simulated encrypt worker panic");
        });
        let done = spawn_pusher(tx, 3);
        thread::sleep(Duration::from_millis(200));
        assert!(
            matches!(done.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "push_blocking returned while the queue was full and the worker alive"
        );
        die_tx
            .send(())
            .expect("worker thread gone before its signal");

        let result = done
            .recv_timeout(WAIT)
            .expect("push_blocking still blocked after the worker thread died");
        match result {
            Err(MacWorkerPushError(job)) => assert_eq!(*job, 3, "the refused job comes back"),
            Ok(()) => panic!("push_blocking queued onto a dead worker"),
        }
        assert!(worker.join().is_err(), "worker thread should have panicked");
    }

    #[test]
    fn try_push_returns_closed_after_receiver_dropped() {
        let (tx, rx) = mac_worker_channel::<u32>(2);
        drop(rx);
        match tx.try_push(1) {
            Err(MacWorkerTryPushError::Closed(job)) => assert_eq!(*job, 1),
            _ => panic!("try_push on a closed queue should hand the job back"),
        }
        let done = spawn_pusher(tx, 2);
        let result = done
            .recv_timeout(WAIT)
            .expect("push_blocking blocked on a queue whose receiver is gone");
        match result {
            Err(MacWorkerPushError(job)) => assert_eq!(*job, 2),
            Ok(()) => panic!("push_blocking queued onto a closed queue"),
        }
    }

    #[test]
    fn receiver_drop_releases_queued_items() {
        let marker = Arc::new(());
        let (tx, rx) = mac_worker_channel::<Arc<()>>(4);
        assert!(tx.try_push(Arc::clone(&marker)).is_ok());
        assert!(tx.try_push(Arc::clone(&marker)).is_ok());
        assert_eq!(Arc::strong_count(&marker), 3);
        drop(rx);
        assert_eq!(
            Arc::strong_count(&marker),
            1,
            "queued items must be freed when the receiver goes away"
        );
        drop(tx);
    }

    #[test]
    fn push_blocking_completes_when_worker_drains_full_queue() {
        let (tx, rx) = mac_worker_channel::<u32>(2);
        assert!(tx.try_push(1).is_ok());
        assert!(tx.try_push(2).is_ok());
        let done = spawn_pusher(tx, 3);
        thread::sleep(Duration::from_millis(100));
        assert!(
            matches!(done.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "push_blocking returned while the queue was still full"
        );

        let mut batch = Vec::new();
        assert!(rx.recv_batch(&mut batch, 16));
        assert_eq!(batch, vec![1, 2]);
        let result = done
            .recv_timeout(WAIT)
            .expect("push_blocking not woken after the worker drained");
        assert!(result.is_ok());

        batch.clear();
        assert!(rx.recv_batch(&mut batch, 16));
        assert_eq!(batch, vec![3]);
    }

    #[test]
    fn recv_batch_drains_then_reports_closed_after_sender_drop() {
        let (tx, rx) = mac_worker_channel::<u32>(4);
        for i in 1..=3 {
            assert!(tx.try_push(i).is_ok());
        }
        drop(tx);
        let mut batch = Vec::new();
        assert!(rx.recv_batch(&mut batch, 16));
        assert_eq!(batch, vec![1, 2, 3]);
        batch.clear();
        assert!(!rx.recv_batch(&mut batch, 16));
        assert!(batch.is_empty());
    }

    #[test]
    fn receiver_drop_does_not_panic_on_poisoned_lock() {
        let (tx, rx) = mac_worker_channel::<u32>(2);
        // The sender's own Drop still expects an unpoisoned lock, so it must
        // never run here: a panic there while a failed assertion unwinds
        // would abort the whole test binary.
        let _tx = std::mem::ManuallyDrop::new(tx);
        let inner = Arc::clone(&rx.inner);
        let poisoner = thread::spawn(move || {
            let _guard = inner.state.lock().unwrap();
            panic!("poison the queue lock");
        });
        assert!(poisoner.join().is_err());
        assert!(rx.inner.state.is_poisoned());

        let dropped = catch_unwind(AssertUnwindSafe(move || drop(rx)));
        assert!(dropped.is_ok(), "receiver drop panicked on a poisoned lock");
    }
}

/// The opt-in ordered sender's completion contract: every reserved slot is
/// completed, a dead sender releases its waiters, and nothing on the rx_loop
/// waits on either. Every wait is bounded so a regression fails, not hangs.
#[cfg(all(test, target_os = "macos"))]
mod mac_ordered_tests {
    use super::*;
    use crate::transport::udp::io::UdpRawSocket;
    use ring::aead::{LessSafeKey, UnboundKey};
    use std::net::UdpSocket;
    use std::sync::mpsc;
    use std::thread;
    use std::time::{Duration, Instant};

    const WAIT: Duration = Duration::from_secs(5);
    const PENDING_CAP: u64 = 4096;

    fn job(socket: &AsyncUdpSocket, dest: SocketAddr, counter: u64) -> FmpSendJob {
        let key = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[7u8; 32]).expect("key");
        let mut wire_buf = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + 4 + crate::noise::TAG_SIZE);
        wire_buf.extend_from_slice(&[0xA5; ESTABLISHED_HEADER_SIZE]);
        wire_buf.extend_from_slice(&counter.to_le_bytes()[..4]);
        FmpSendJob {
            cipher: LessSafeKey::new(key),
            counter,
            wire_buf,
            fsp_seal: None,
            socket: socket.clone(),
            dest_addr: dest,
            connected_socket: None,
            stats: Arc::new(UdpStats::new()),
            drop_on_backpressure: false,
            queued_at: None,
        }
    }

    /// Reserve `n` slots on `flow` and complete them as skips, which fills
    /// it to `n` pending items when an earlier slot is still open.
    fn skip_reserved(flow: &MacSequencedSendFlow, n: u64) {
        let skips = (0..n)
            .map(|_| (flow.reserve_seq(), MacSendItem::Skip))
            .collect();
        flow.complete_many(skips);
    }

    struct Rig {
        _rt: tokio::runtime::Runtime,
        recv: UdpSocket,
        dest: SocketAddr,
        socket: AsyncUdpSocket,
        flows: MacSequencedSendFlows,
    }

    impl Rig {
        fn new() -> Self {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("tokio rt");
            let enter = rt.enter();
            let recv = UdpSocket::bind("127.0.0.1:0").expect("bind recv");
            recv.set_read_timeout(Some(WAIT)).expect("read timeout");
            let dest = recv.local_addr().expect("recv addr");
            let socket = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket")
                .into_async()
                .expect("into_async");
            drop(enter);
            Self {
                _rt: rt,
                recv,
                dest,
                socket,
                flows: MacSequencedSendFlows::default(),
            }
        }

        fn job(&self, counter: u64) -> FmpSendJob {
            job(&self.socket, self.dest, counter)
        }

        fn flow(&self) -> Arc<MacSequencedSendFlow> {
            self.flows.flow_for(&self.job(0))
        }

        fn sequenced(&self, counter: u64) -> QueuedFmpSendJob {
            let job = self.job(counter);
            let flow = self.flows.flow_for(&job);
            QueuedFmpSendJob::macos_sequenced(job, flow)
        }

        fn received(&self) -> bool {
            let mut buf = [0u8; 256];
            self.recv.recv_from(&mut buf).is_ok()
        }
    }

    #[test]
    fn a_sequenced_job_dropped_unsent_lets_its_flow_send_what_follows() {
        let rig = Rig::new();
        drop(rig.sequenced(1));
        let mut batch = vec![rig.sequenced(2)];
        flush_batch_sync(&mut batch).expect("flush");
        assert!(rig.received(), "the flow stalled at the dropped job's slot");
    }

    #[test]
    fn a_dead_workers_queue_releases_the_slots_it_held() {
        let rig = Rig::new();
        let (tx, rx) = mac_worker_channel::<QueuedFmpSendJob>(4);
        assert!(tx.try_push(rig.sequenced(1)).is_ok());
        assert!(tx.try_push(rig.sequenced(2)).is_ok());
        drop(rx);
        // The refused job comes back and is dropped here, which releases its
        // slot as the dispatcher's caller would.
        assert!(matches!(
            tx.try_push(rig.sequenced(3)),
            Err(MacWorkerTryPushError::Closed(_))
        ));
        let mut batch = vec![rig.sequenced(4)];
        flush_batch_sync(&mut batch).expect("flush");
        assert!(
            rig.received(),
            "the flow stalled at a slot the dead queue held"
        );
    }

    #[test]
    fn a_completion_group_dropped_undelivered_lets_its_flow_send_what_follows() {
        let rig = Rig::new();
        let flow = rig.flow();
        let group = MacCompletionGroup {
            flow: Arc::clone(&flow),
            items: vec![(
                flow.reserve_seq(),
                MacSendItem::Packet {
                    packet: b"undelivered".to_vec(),
                    drop_on_backpressure: false,
                },
            )],
        };
        drop(group);
        let mut batch = vec![rig.sequenced(2)];
        flush_batch_sync(&mut batch).expect("flush");
        assert!(
            rig.received(),
            "the flow stalled at a slot an undelivered group held"
        );
    }

    #[test]
    fn a_completion_waiting_for_room_returns_when_its_flow_closes() {
        let rig = Rig::new();
        let flow = rig.flow();
        let gap = QueuedFmpSendJob::macos_sequenced(rig.job(0), Arc::clone(&flow));
        skip_reserved(&flow, PENDING_CAP);
        let late = flow.reserve_seq();
        let (done_tx, done_rx) = mpsc::channel();
        let waiter = Arc::clone(&flow);
        thread::spawn(move || {
            waiter.complete_many(vec![(late, MacSendItem::Skip)]);
            let _ = done_tx.send(());
        });
        thread::sleep(Duration::from_millis(200));
        assert!(
            done_rx.try_recv().is_err(),
            "a full flow took a completion without room"
        );
        flow.close();
        done_rx
            .recv_timeout(WAIT)
            .expect("the completion still waited after its flow closed");
        drop(gap);
    }

    #[test]
    fn a_sender_thread_that_panics_closes_its_flow() {
        let rig = Rig::new();
        let flow = rig.flow();
        // Poison the flow's state lock, then wake the sender: its own
        // `expect` on the lock panics inside `run`.
        let poisoner = Arc::clone(&flow);
        let poisoned = thread::spawn(move || {
            let _state = poisoner.state.lock().unwrap();
            panic!("poison the flow state lock");
        })
        .join();
        assert!(poisoned.is_err());
        flow.complete_skip(0);
        let deadline = Instant::now() + WAIT;
        while !flow.is_closed() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            flow.is_closed(),
            "a sender thread that panicked left its flow open"
        );
    }

    #[test]
    fn a_flow_whose_sender_has_exited_is_replaced() {
        let rig = Rig::new();
        let first = rig.flow();
        first.close();
        let second = rig.flow();
        assert!(
            !Arc::ptr_eq(&first, &second),
            "a closed flow was handed out again"
        );
        let mut batch = vec![QueuedFmpSendJob::macos_sequenced(rig.job(3), second)];
        flush_batch_sync(&mut batch).expect("flush");
        assert!(rig.received(), "the replacement flow sent nothing");
    }

    #[test]
    fn dropping_a_sequenced_job_never_waits_for_room() {
        let rig = Rig::new();
        let flow = rig.flow();
        let gap = QueuedFmpSendJob::macos_sequenced(rig.job(0), Arc::clone(&flow));
        skip_reserved(&flow, PENDING_CAP);
        let dropped = QueuedFmpSendJob::macos_sequenced(rig.job(1), Arc::clone(&flow));
        let (done_tx, done_rx) = mpsc::channel();
        thread::spawn(move || {
            drop(dropped);
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(WAIT)
            .expect("dropping a job waited for room in a full flow");
        drop(gap);
    }
}

/// The pool's view of its workers: which are live, what a dead one does to a
/// dispatch, and that a live but full queue still blocks. Every wait is
/// bounded so a regression fails instead of hanging.
#[cfg(test)]
mod pool_tests {
    use super::*;
    use crate::node::worker_set::wait_for;
    #[cfg(not(target_os = "macos"))]
    use crate::transport::udp::io::UdpRawSocket;
    #[cfg(not(target_os = "macos"))]
    use ring::aead::UnboundKey;
    #[cfg(not(target_os = "macos"))]
    use std::net::UdpSocket;
    use std::sync::mpsc;
    #[cfg(not(target_os = "macos"))]
    use std::time::Duration;

    #[cfg(not(target_os = "macos"))]
    struct Rig {
        _rt: tokio::runtime::Runtime,
        socket: AsyncUdpSocket,
    }

    #[cfg(not(target_os = "macos"))]
    impl Rig {
        fn new() -> Self {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .expect("tokio rt");
            let enter = rt.enter();
            let socket = UdpRawSocket::open("127.0.0.1:0".parse().unwrap(), 1 << 20, 1 << 20)
                .expect("open send socket")
                .into_async()
                .expect("into_async");
            drop(enter);
            Self { _rt: rt, socket }
        }

        fn job(&self, dest: SocketAddr, counter: u64) -> FmpSendJob {
            let key = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &[3u8; 32]).expect("key");
            let mut wire_buf =
                Vec::with_capacity(ESTABLISHED_HEADER_SIZE + 8 + crate::noise::TAG_SIZE);
            wire_buf.extend_from_slice(&[0x5A; ESTABLISHED_HEADER_SIZE]);
            wire_buf.extend_from_slice(&counter.to_le_bytes());
            FmpSendJob {
                cipher: LessSafeKey::new(key),
                counter,
                wire_buf,
                fsp_seal: None,
                socket: self.socket.clone(),
                dest_addr: dest,
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                connected_socket: None,
                stats: Arc::new(UdpStats::new()),
                drop_on_backpressure: false,
                queued_at: None,
            }
        }
    }

    /// A bound receiver whose address the pool dispatches to worker `idx`.
    #[cfg(not(target_os = "macos"))]
    fn receiver_on_worker(pool: &EncryptWorkerPool, idx: usize) -> UdpSocket {
        loop {
            let sock = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
            if pool.worker_index_for(sock.local_addr().unwrap()) == idx {
                sock.set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("read timeout");
                return sock;
            }
        }
    }

    #[test]
    fn an_encrypt_worker_that_panics_is_counted_dead() {
        let (die_tx, die_rx) = mpsc::channel::<()>();
        let mut die_rx = Some(die_rx);
        let pool = EncryptWorkerPool::start_with(2, |idx, rx| {
            if idx != 1 {
                return spawn_worker(idx, rx);
            }
            let die = die_rx.take().expect("worker 1 starts once");
            std::thread::Builder::new().spawn(move || {
                let _rx = rx;
                let _ = die.recv();
                panic!("simulated encrypt worker panic");
            })
        });
        assert_eq!(pool.liveness().live_workers(), 2);
        die_tx.send(()).expect("worker 1 gone before its signal");
        assert!(
            wait_for(|| pool.liveness().live_workers() == 1),
            "a worker that panicked is still counted live"
        );
        assert_eq!(pool.liveness().dead_workers(), vec![1]);
        assert_eq!(pool.liveness().worker_count(), 2);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_worker_that_fails_to_spawn_leaves_the_pool_serving_the_rest() {
        let rig = Rig::new();
        let pool = EncryptWorkerPool::for_test(vec![TestWorker::Run, TestWorker::FailSpawn]);
        assert_eq!(pool.liveness().worker_count(), 2);
        assert_eq!(pool.liveness().live_workers(), 1);

        let recv = receiver_on_worker(&pool, 0);
        assert!(
            pool.dispatch(rig.job(recv.local_addr().unwrap(), 1))
                .is_ok()
        );
        let mut buf = [0u8; 128];
        recv.recv_from(&mut buf)
            .expect("the live worker did not send the job dispatched to it");
        assert_eq!(pool.liveness().refused_dispatches(), 0);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn dispatch_to_an_exited_encrypt_worker_warns_and_counts() {
        let rig = Rig::new();
        let pool = EncryptWorkerPool::for_test(vec![TestWorker::Run, TestWorker::FailSpawn]);
        let recv = receiver_on_worker(&pool, 1);
        let (dispatched, logs) =
            crate::testutil::capture_logs(|| pool.dispatch(rig.job(recv.local_addr().unwrap(), 1)));
        assert!(dispatched.is_err(), "a dead worker's job must come back");
        let warnings = logs.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains(" worker=1"), "{warnings:?}");
        assert!(warnings[0].contains(" pool=\"encrypt\""), "{warnings:?}");
        assert_eq!(pool.liveness().refused_dispatches(), 1);
    }

    /// A live worker that has fallen behind must hold the rx loop back, not
    /// have its packets dropped: these are tunnelled packets, and a drop here
    /// reads as loss to TCP inside the tunnel.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn a_full_live_encrypt_queue_still_blocks_dispatch() {
        let rig = Rig::new();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let mut release_rx = Some(release_rx);
        let pool = EncryptWorkerPool::start_with(1, |idx, rx| {
            let release = release_rx.take().expect("one worker");
            std::thread::Builder::new().spawn(move || {
                let _ = release.recv();
                run_worker(idx, rx);
            })
        });
        let recv = UdpSocket::bind("127.0.0.1:0").expect("bind receiver");
        let dest = recv.local_addr().unwrap();
        for counter in 0..WORKER_CHANNEL_CAP as u64 {
            assert!(pool.dispatch(rig.job(dest, counter)).is_ok());
        }

        let (done_tx, done_rx) = mpsc::channel::<bool>();
        let blocked_pool = pool.clone();
        let last = rig.job(dest, WORKER_CHANNEL_CAP as u64);
        std::thread::spawn(move || {
            let _ = done_tx.send(blocked_pool.dispatch(last).is_ok());
        });
        std::thread::sleep(Duration::from_millis(200));
        assert!(
            matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "dispatch returned while the live worker's queue was full"
        );

        release_tx.send(()).expect("worker gone before release");
        let queued = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("dispatch still blocked after the worker drained");
        assert!(queued, "the blocked job was refused, not queued");
        assert_eq!(pool.liveness().refused_dispatches(), 0);
    }

    /// A job refused by a dead worker comes back whole, with the counter and
    /// buffer the caller reserved, whether the worker was already gone or
    /// died while the dispatch waited on its full queue.
    #[cfg(not(target_os = "macos"))]
    #[test]
    fn dispatch_to_an_exited_worker_hands_the_job_back() {
        let rig = Rig::new();
        let dest: SocketAddr = "127.0.0.1:9".parse().unwrap();

        let pool = EncryptWorkerPool::for_test(vec![TestWorker::FailSpawn]);
        let job = rig.job(dest, 41);
        let wire_buf = job.wire_buf.clone();
        let back = match pool.dispatch(job) {
            Err(back) => back,
            Ok(()) => panic!("a dead worker took the job"),
        };
        assert_eq!(back.counter, 41);
        assert_eq!(back.wire_buf, wire_buf);

        // Worker alive but not draining; it exits while a dispatch waits.
        let (exit_tx, exit_rx) = mpsc::channel::<()>();
        let pool = EncryptWorkerPool::for_test(vec![TestWorker::ExitOn(exit_rx)]);
        for counter in 0..WORKER_CHANNEL_CAP as u64 {
            assert!(pool.dispatch(rig.job(dest, counter)).is_ok());
        }
        let (done_tx, done_rx) = mpsc::channel::<Option<u64>>();
        let blocked_pool = pool.clone();
        let last = rig.job(dest, 7_000);
        std::thread::spawn(move || {
            let _ = done_tx.send(blocked_pool.dispatch(last).err().map(|job| job.counter));
        });
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            matches!(done_rx.try_recv(), Err(mpsc::TryRecvError::Empty)),
            "dispatch returned while the queue was full and the worker alive"
        );
        exit_tx.send(()).expect("worker gone before its signal");
        let back = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("dispatch still blocked after the worker exited");
        assert_eq!(
            back,
            Some(7_000),
            "the job blocked on a dying worker must come back"
        );
    }
}
