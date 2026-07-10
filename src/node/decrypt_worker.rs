//! Off-task FMP + FSP decrypt + delivery worker.
//!
//! First incremental step of the data-plane shard restructure (per the
//! architectural plan): each worker now **owns its session state
//! directly** in a local `HashMap`, with no `Arc<RwLock<HashMap>>`
//! cache on the Node side and no `Arc<Mutex<ReplayWindow>>` shared
//! with the rx_loop. The worker is the sole authority over the replay
//! window and the recv-side ciphers for every session it owns.
//!
//! Dispatch is **deterministic by session key**: rx_loop computes
//! `worker_idx = hash(cache_key) % N` and routes both
//! `RegisterSession` control messages and per-packet `Job` messages
//! through the same hash, so a session always lands on the same shard.
//!
//! Three message types travel through the per-worker `crossbeam_channel`:
//!
//! - **`RegisterSession`** — sent once on the first successful legacy
//!   decrypt for a session. Hands the worker an owned snapshot of the
//!   recv cipher + replay window for both FMP and FSP layers.
//! - **`Job`** — per-packet bulk decrypt + deliver. The worker looks
//!   up the session in its local HashMap; if absent (registration
//!   hasn't arrived yet, or session was unregistered), the packet is
//!   bounced back to rx_loop via the fallback channel.
//! - **`UnregisterSession`** — sent on rekey / peer drop so the worker
//!   releases the owned cipher + replay state.
//!
//! Only the **bulk-data** path (FMP DataPacket → FSP EndpointData) is
//! handled by the worker. Anything else (handshakes, MMP reports,
//! routing errors, IPv6-shim packets going to TUN) is bounced back to
//! the rx_loop via a fallback channel so the existing slow paths
//! continue to work.

// **Unix only at the call sites.** On Windows nothing constructs an
// `OwnedSessionState` or spawns the pool (see `lifecycle.rs`), so
// every field + function in here becomes dead. Silence the warnings
// rather than gate them individually.
#![cfg_attr(not(unix), allow(dead_code))]

use crate::NodeAddr;
use crate::transport::{TransportAddr, TransportId};
use crossbeam_channel::{Receiver, Sender, TrySendError, bounded};
use ring::aead::{Aad, LessSafeKey, Nonce};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc::UnboundedSender;
use tracing::{debug, trace, warn};

// `endpoint_event_tx` used to ride on every `DecryptJob` so the worker
// could deliver inbound EndpointData straight to the API layer,
// bypassing rx_loop. After the FMP-only refactor (correctness fix —
// see the long comment in `handle_job`'s phase-2 block) the worker
// bounces ALL link messages back to rx_loop, so the sender went
// unused. It's been removed: it bloated `DecryptJob` (an extra Arc
// clone per packet on the rx_loop hot path) and — worse — its
// presence was used as the production-path predicate in
// `handle_encrypted_frame`, which silently disabled the entire
// worker for TUN-only configurations that never call
// `endpoint_data_io()`.

use crate::noise::ReplayWindow;

const WORKER_CHANNEL_CAP: usize = 32768;

/// Owning recv-side state for one established FMP session. Lives
/// **inside the worker thread that owns this session** — never
/// shared, never behind a mutex.
///
/// **FMP only** — the worker exclusively handles the FMP layer
/// (decrypt + replay accept), then bounces the FMP plaintext back to
/// rx_loop for FSP-layer dispatch. This split is what makes
/// register-at-FMP-establishment correct: the worker doesn't need
/// the FSP cipher / replay window, and can therefore be the
/// authoritative recv path for a peer the moment FMP is up — well
/// before the FSP handshake completes.
///
/// Built at FMP-session establishment time (`promote_connection`)
/// and shipped to the assigned worker via `WorkerMsg::RegisterSession`.
pub(crate) struct OwnedSessionState {
    pub fmp_cipher: LessSafeKey,
    pub fmp_replay: ReplayWindow,
    pub source_npub: Option<String>,
}

/// Pre-cooked decrypt + dispatch job. Built on rx_loop after parsing
/// the FMP header; the worker pulls its session state from its own
/// local HashMap (keyed by `cache_key`) instead of receiving a
/// `WorkerSessionState` clone per packet.
pub(crate) struct DecryptJob {
    /// The raw packet bytes (incl. the 16-byte FMP outer header).
    /// Mutated in place during AEAD open — must reach the worker
    /// with the full ciphertext + tag intact.
    pub packet_data: Vec<u8>,
    /// Lookup key into the worker's owned session HashMap. Mirrors the
    /// `peers_by_index` key on the Node side: `(transport_id,
    /// receiver_idx)`.
    pub cache_key: (TransportId, u32),
    /// Source kernel transport. Forwarded into the bounced
    /// `DecryptFallback` so rx_loop can update per-peer last-seen +
    /// link stats (otherwise the MMP link-dead timer fires at 30s
    /// because the worker handles packets without ever calling
    /// `peer.touch()` / `record_recv()`).
    pub _transport_id: TransportId,
    pub _remote_addr: TransportAddr,
    pub timestamp_ms: u64,
    /// Source NodeAddr (looked up via `peers_by_index` on rx_loop).
    /// Needed to attach to the bounced `DecryptFallback` so rx_loop
    /// can dispatch its legacy link-message handler.
    pub source_node_addr: NodeAddr,
    /// Counter from the FMP outer header. Used both as nonce input
    /// and to update the replay window.
    pub fmp_counter: u64,
    /// Flag byte from the FMP outer header. Carried through the
    /// fallback so the rx_loop bounce arm can extract `CE` and `SP`
    /// for ECN propagation and MMP stats — these used to be dropped
    /// on the worker path
    /// because the bounce hardcoded `fmp_flags: 0`.
    pub fmp_flags: u8,
    /// 16-byte FMP outer header used as AAD during AEAD open.
    pub fmp_header: [u8; 16],
    /// Offset within `packet_data` where the FMP ciphertext+tag begins.
    pub fmp_ciphertext_offset: usize,

    /// Anything that's NOT bulk EndpointData gets bounced back to the
    /// rx_loop via this channel along with its now-decrypted plaintext.
    /// The rx_loop drains this in a select! arm and runs the legacy
    /// dispatch (handshakes, MMP reports, routing errors, IPv6-shim →
    /// TUN). Keeps the slow paths working unchanged.
    pub fallback_tx: UnboundedSender<DecryptWorkerEvent>,
}

/// Result of a successful FMP decrypt + replay accept, when the
/// worker has decided this packet isn't on the EndpointData fast
/// path and is bouncing it back to rx_loop for the legacy slow path.
#[allow(dead_code)] // fmp_counter / fmp_flags retained for future debug paths
pub(crate) struct DecryptFallback {
    pub source_node_addr: NodeAddr,
    /// Transport this packet arrived on — used by rx_loop's bounce
    /// arm to call `peer.set_current_addr()` so address rotation +
    /// MMP link-dead tracking continue to see updates for packets
    /// handled by the worker.
    pub transport_id: TransportId,
    /// Remote transport address — companion to `transport_id`.
    pub remote_addr: TransportAddr,
    pub timestamp_ms: u64,
    /// Length of the wire packet that produced this bounce. Used
    /// by rx_loop to call `peer.link_stats_mut().record_recv()` so
    /// per-peer stats + MMP last-seen + link-dead detection see
    /// progress for worker-handled packets. Without this update,
    /// MMP's 30-second link-dead timer fires even though packets
    /// are arriving fine.
    pub packet_len: usize,
    pub fmp_counter: u64,
    pub fmp_flags: u8,
    /// Original received wire buffer, mutated in place by the FMP
    /// AEAD open. Bytes `[fmp_plaintext_offset ..
    /// fmp_plaintext_offset+fmp_plaintext_len]` are the decrypted
    /// FMP plaintext: a 4-byte session timestamp followed by the
    /// link-layer message (FSP frame when
    /// `phase == FSP_PHASE_ESTABLISHED`). rx_loop slices into this
    /// Vec for FSP decrypt + dispatch and only allocates on the
    /// actual delivery hop.
    ///
    /// **Why packet_data + offset, not `Vec<u8>` of the plaintext:**
    /// the pre-fix bounce did `packet_data[a..b].to_vec()` per
    /// packet, which is one fresh ~1500-byte allocation on every
    /// inbound bulk frame. At 150k pps that's ~225 MB/sec of
    /// memory bandwidth on the worker + rx_loop hot path, and a
    /// per-packet allocator round-trip. Passing the original Vec
    /// through unmodified lets the consumer borrow a slice; zero
    /// alloc, zero memcpy.
    pub packet_data: Vec<u8>,
    pub fmp_plaintext_offset: usize,
    pub fmp_plaintext_len: usize,
}

/// Report from the decrypt worker when a registered FMP session fails
/// AEAD authentication. Routed back to rx_loop so peer/session recovery
/// decisions stay in one place instead of being silently dropped inside
/// the worker thread.
pub(crate) struct DecryptFailureReport {
    pub source_node_addr: NodeAddr,
    pub fmp_counter: u64,
    pub fmp_replay_highest: u64,
}

/// Event emitted by the decrypt worker to the rx_loop.
pub(crate) enum DecryptWorkerEvent {
    Plaintext(DecryptFallback),
    DecryptFailure(DecryptFailureReport),
}

/// Messages travelling through the per-worker crossbeam channel.
/// `Job` is the per-packet hot path; `RegisterSession` /
/// `UnregisterSession` are control plane events sent at session
/// establishment / teardown.
///
/// The `Job` variant is intentionally much larger than the control
/// variants (it carries the whole packet buffer + cipher clone). The
/// alternative — boxing `Job` — adds a per-packet alloc on the hot
/// path, which is the exact thing this module is designed to avoid.
#[allow(clippy::large_enum_variant)]
pub(crate) enum WorkerMsg {
    Job(DecryptJob),
    RegisterSession {
        cache_key: (TransportId, u32),
        state: OwnedSessionState,
    },
    UnregisterSession {
        cache_key: (TransportId, u32),
    },
}

/// Handle to the decrypt worker pool. Shard-style: each worker is one
/// OS thread that owns its sessions outright. Dispatch is
/// deterministic on `cache_key` so a session always reaches the same
/// shard.
#[derive(Clone)]
pub(crate) struct DecryptWorkerPool {
    senders: Arc<[Sender<WorkerMsg>]>,
}

impl DecryptWorkerPool {
    pub fn spawn(n: usize) -> Self {
        let n = n.max(1);
        let mut senders = Vec::with_capacity(n);
        for i in 0..n {
            let (tx, rx) = bounded::<WorkerMsg>(WORKER_CHANNEL_CAP);
            std::thread::Builder::new()
                .name(format!("fips-decrypt-{i}"))
                .spawn(move || run_worker(i, rx))
                .expect("failed to spawn fips-decrypt OS thread");
            senders.push(tx);
        }
        Self {
            senders: senders.into(),
        }
    }

    /// Stable hash from session key → worker index. Same hash is used
    /// for session registration and per-packet dispatch so packets and
    /// registration arrive at the same shard.
    fn worker_idx_for(&self, cache_key: (TransportId, u32)) -> usize {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        cache_key.hash(&mut h);
        (h.finish() as usize) % self.senders.len()
    }

    /// Dispatch a per-packet decrypt job. Drops if the per-worker
    /// channel is full (sustained rate overrun); the rx_loop's drain
    /// caps inbound at the same scale upstream so the cliff is
    /// bounded.
    pub fn dispatch_job(&self, job: DecryptJob) {
        if self.senders.is_empty() {
            return;
        }
        let idx = self.worker_idx_for(job.cache_key);
        match self.senders[idx].try_send(WorkerMsg::Job(job)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                static FULL_COUNT: AtomicU64 = AtomicU64::new(0);
                let n = FULL_COUNT.fetch_add(1, Ordering::Relaxed);
                if n < 8 || n.is_multiple_of(10000) {
                    warn!(
                        worker = idx,
                        drops = n + 1,
                        "DecryptWorker channel full; dropping inbound packet"
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(worker = idx, "DecryptWorker thread gone; dropping job");
            }
        }
    }

    /// Hand ownership of a session's recv-side state to its assigned
    /// worker. Called once per session, from the rx_loop, on the
    /// first authentic legacy-path decrypt — the worker thereafter is
    /// the sole authority over the replay window and the cipher
    /// clones for this session.
    ///
    /// Returns `true` iff the registration message was actually
    /// queued. Callers MUST gate any "this session is now worker-
    /// owned" state on the returned bool — the previous version
    /// fire-and-forget'd the `try_send` and the caller unconditionally
    /// marked the session as registered on its side, so under
    /// sustained queue pressure rx_loop believed the worker owned a
    /// session that had never received the cipher + replay state.
    /// Subsequent `dispatch_job` packets then arrived at a worker
    /// shard without that session in its local `HashMap` and were
    /// silently dropped (the "session unregistered mid-flight"
    /// fallback path in `handle_job`). The caller's normal retry —
    /// "re-register on a later event" — is documented at the only
    /// call site (`register_decrypt_worker_session`).
    #[must_use = "registration may have failed under queue pressure; caller must gate its own session-registered flag on the returned bool"]
    pub fn register_session(
        &self,
        cache_key: (TransportId, u32),
        state: OwnedSessionState,
    ) -> bool {
        if self.senders.is_empty() {
            return false;
        }
        let idx = self.worker_idx_for(cache_key);
        match self.senders[idx].try_send(WorkerMsg::RegisterSession { cache_key, state }) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                warn!(
                    worker = idx,
                    "DecryptWorker channel full at session registration; will retry on next packet"
                );
                false
            }
            Err(TrySendError::Disconnected(_)) => {
                debug!(
                    worker = idx,
                    "DecryptWorker thread gone; ignoring registration"
                );
                false
            }
        }
    }

    /// Drop a session from its worker (rekey, peer removed). Fire and
    /// forget — if the worker is gone we don't care.
    pub fn unregister_session(&self, cache_key: (TransportId, u32)) {
        if self.senders.is_empty() {
            return;
        }
        let idx = self.worker_idx_for(cache_key);
        let _ = self.senders[idx].try_send(WorkerMsg::UnregisterSession { cache_key });
    }
}

fn run_worker(idx: usize, rx: Receiver<WorkerMsg>) {
    trace!(worker = idx, "FMP+FSP decrypt worker thread starting");

    // The shard's owned session table. Lives entirely on this OS
    // thread — never observed by any other thread.
    let mut sessions: HashMap<(TransportId, u32), OwnedSessionState> = HashMap::new();

    while let Ok(msg) = rx.recv() {
        handle_msg(idx, &mut sessions, msg);
        // Drain follow-ons before parking again. Keeps the thread
        // on-core for a burst (typical recvmmsg batch is 5–30 packets
        // delivered very close together).
        while let Ok(m) = rx.try_recv() {
            handle_msg(idx, &mut sessions, m);
        }
    }
    trace!(worker = idx, "FMP+FSP decrypt worker thread exiting");
}

fn handle_msg(
    idx: usize,
    sessions: &mut HashMap<(TransportId, u32), OwnedSessionState>,
    msg: WorkerMsg,
) {
    match msg {
        WorkerMsg::Job(job) => {
            if let Err(err) = handle_job(sessions, job) {
                debug!(worker = idx, error = %err, "decrypt worker job failed");
            }
        }
        WorkerMsg::RegisterSession { cache_key, state } => {
            trace!(worker = idx, ?cache_key, "DecryptWorker: register session");
            sessions.insert(cache_key, state);
        }
        WorkerMsg::UnregisterSession { cache_key } => {
            trace!(
                worker = idx,
                ?cache_key,
                "DecryptWorker: unregister session"
            );
            sessions.remove(&cache_key);
        }
    }
}

fn handle_job(
    sessions: &mut HashMap<(TransportId, u32), OwnedSessionState>,
    job: DecryptJob,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let DecryptJob {
        mut packet_data,
        cache_key,
        _transport_id: transport_id,
        _remote_addr: remote_addr,
        timestamp_ms,
        source_node_addr,
        fmp_counter,
        fmp_flags,
        fmp_header,
        fmp_ciphertext_offset,
        fallback_tx,
    } = job;
    // Capture the wire packet length BEFORE decrypt mutates the
    // buffer — it'll be the same number either way (in-place AEAD
    // open doesn't change Vec::len), but documenting the intent.
    let packet_len = packet_data.len();

    // Look up the shard-owned session state. If absent (session not
    // yet registered, or unregistered mid-flight), bounce the raw
    // packet to rx_loop so it can run its legacy decrypt + populate
    // the session via RegisterSession on success.
    let state = match sessions.get_mut(&cache_key) {
        Some(s) => s,
        None => {
            // The legacy rx_loop already has the ciphertext bytes
            // (worker owns `packet_data` here), but it can re-do the
            // decrypt from scratch since this is the first-packet
            // path. Bounce by sending the **encrypted** FMP frame
            // back wrapped in a fallback — rx_loop's
            // `dispatch_link_message` won't recognise it though, so
            // we just drop instead. This is a transient state on a
            // brand-new session; subsequent packets land after
            // registration.
            let _ = fallback_tx; // explicitly ignore — drop path
            let _ = source_node_addr;
            let _ = packet_data;
            return Ok(());
        }
    };

    // === Phase 1: FMP decrypt ===
    let _t_fmp = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FmpDecrypt);

    // Replay-window check before AEAD work to avoid wasting CPU on
    // replays. **Direct &mut access** — no Arc<Mutex> lock acquire.
    let fmp_replay_highest = state.fmp_replay.highest();
    if !state.fmp_replay.check(fmp_counter) {
        return Ok(()); // replay; drop silently
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..12].copy_from_slice(&fmp_counter.to_le_bytes());
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let buf = &mut packet_data[fmp_ciphertext_offset..];
    let plaintext_len = match state
        .fmp_cipher
        .open_in_place(nonce, Aad::from(&fmp_header), buf)
    {
        Ok(p) => p.len(),
        Err(_) => {
            let _ = fallback_tx.send(DecryptWorkerEvent::DecryptFailure(DecryptFailureReport {
                source_node_addr,
                fmp_counter,
                fmp_replay_highest,
            }));
            return Ok(());
        }
    };

    // FMP decrypt succeeded — accept the counter into the replay window.
    state.fmp_replay.accept(fmp_counter);
    drop(_t_fmp);

    // The FMP plaintext lives in packet_data[fmp_ciphertext_offset..
    // fmp_ciphertext_offset + plaintext_len]. It carries a 4-byte
    // session-relative timestamp prefix, then the link-layer message.
    let fmp_plaintext_start = fmp_ciphertext_offset;
    let fmp_plaintext_end = fmp_ciphertext_offset + plaintext_len;
    const INNER_TIMESTAMP_LEN: usize = 4;
    if plaintext_len < INNER_TIMESTAMP_LEN + 1 {
        return Ok(());
    }
    let link_msg_start = fmp_plaintext_start + INNER_TIMESTAMP_LEN;
    let link_msg_end = fmp_plaintext_end;
    let link_msg = &packet_data[link_msg_start..link_msg_end];

    // === Phase 2: bounce ALL link messages back to rx_loop ===
    //
    // **Why no FSP fast path here:** previous design did FSP decrypt
    // + replay-accept for SessionDatagram (link msg_type 0x00), then
    // checked the inner FSP msg_type. If it was EndpointData (0x11),
    // delivered directly to the endpoint event channel. Otherwise
    // (heartbeats, MMP reports, IPv6-shim, etc.) bounced the
    // **decrypted-in-place** FMP plaintext back to rx_loop.
    //
    // Two problems with that path:
    //   1. After the shard-owned-sessions refactor (01f6c62), the FSP
    //      replay window is owned by **this worker thread**. Once we
    //      `state.fsp_replay.accept(fsp_counter)`, the rx_loop's
    //      `noise::Session::replay_window` is stale — it still has
    //      old counters. When rx_loop tries to FSP-decrypt the
    //      bounced control frame, its legacy path's replay check
    //      passes (the counter wasn't in its window) but the AEAD
    //      tag check fails because the FSP bytes in `packet_data`
    //      were already decrypted in place (now plaintext + 16
    //      garbage tag bytes).
    //   2. Even if we didn't accept the worker's replay window for
    //      non-EndpointData, the in-place mutation of `packet_data`
    //      means the legacy path can't re-decrypt — the ciphertext
    //      is gone.
    //
    // The bug manifests in benches as link death: heartbeats never
    // make it through the worker, the link-dead timer fires at 30s,
    // peer is removed and re-handshakes, repeating forever.
    //
    // **Fix:** worker handles only the FMP layer. ALL link messages
    // (SessionDatagram, heartbeats, control) bounce back to rx_loop
    // with the FMP plaintext intact. The legacy rx_loop path does
    // FSP-decrypt as usual. Net cost vs the broken fast path: we
    // give up the rx_loop bypass for EndpointData, but the worker
    // still offloads the FMP AEAD (~half the per-packet decrypt
    // CPU). Correctness over micro-optimisation.
    //
    // The DataShard end-state (per the architectural plan) re-
    // introduces the EndpointData fast path correctly by having the
    // shard worker also own the rx_loop side for its sessions — at
    // that point there's no "rx_loop legacy path" for the worker to
    // conflict with.
    // Pass the buffer through by ownership + offset/length. No
    // per-packet allocation; rx_loop slices into `packet_data`.
    let _ = link_msg; // sanity-check borrow before sending buffer onward
    let _ = fallback_tx.send(DecryptWorkerEvent::Plaintext(DecryptFallback {
        source_node_addr,
        transport_id,
        remote_addr,
        timestamp_ms,
        packet_len,
        fmp_counter,
        fmp_flags,
        packet_data,
        fmp_plaintext_offset: fmp_plaintext_start,
        fmp_plaintext_len: plaintext_len,
    }));
    // Suppress unused-variable warnings for the (now-removed) FSP
    // fast path. The `state` lookup is still needed for the FMP
    // cipher + replay window above.
    let _ = (link_msg_start, link_msg_end, &state.source_npub);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::ReplayWindow;
    use ring::aead::{LessSafeKey, UnboundKey};

    /// `DecryptJob.fmp_flags` must survive the worker bounce as
    /// `DecryptFallback.fmp_flags`. Pre-fix the worker hardcoded
    /// `fmp_flags: 0`, dropping CE / SP on every packet handled by
    /// the production worker path (i.e. every bulk-data packet).
    /// Loss of CE wrecks ECN propagation.
    ///
    /// Drives the worker's `handle_job` directly: build an FMP wire
    /// packet sealed with a known cipher, ship a `DecryptJob` with
    /// non-zero flags through, observe the resulting `DecryptFallback`.
    #[test]
    fn worker_preserves_fmp_flags_through_fallback() {
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        // Both the sealing cipher (for building the test packet) and
        // the worker's owning cipher are clones of the same key.
        let seal_cipher = LessSafeKey::new(unbound);
        let unbound2 = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let open_cipher = LessSafeKey::new(unbound2);

        let counter: u64 = 7;
        const HDR: usize = crate::proto::fmp::wire::ESTABLISHED_HEADER_SIZE;
        // Build a wire packet `[16-byte header][4-byte inner ts][1 byte link msg]`
        // with capacity for the trailing AEAD tag. Header bytes
        // double as AAD and as the on-wire prefix.
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        // Header: fill the flags byte (the second byte) with both
        // FLAG_CE and FLAG_KEY_EPOCH set; the rest is uninterpreted by
        // the worker (it just AADs the whole 16 bytes).
        let flags_byte = crate::proto::fmp::wire::FLAG_CE | crate::proto::fmp::wire::FLAG_KEY_EPOCH;
        let mut header = [0u8; HDR];
        header[1] = flags_byte;
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]); // inner ts placeholder
        wire.push(0xAB); // a single byte of "link message" payload

        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        let nonce = ring::aead::Nonce::assume_unique_for_key(nonce_bytes);
        let (hdr_slice, payload_slice) = wire.split_at_mut(HDR);
        let tag = seal_cipher
            .seal_in_place_separate_tag(nonce, ring::aead::Aad::from(&*hdr_slice), payload_slice)
            .unwrap();
        wire.extend_from_slice(tag.as_ref());

        // Owning state held by the worker for this session.
        let cache_key = (TransportId::new(1), 99u32);
        let mut sessions: HashMap<(TransportId, u32), OwnedSessionState> = HashMap::new();
        sessions.insert(
            cache_key,
            OwnedSessionState {
                fmp_cipher: open_cipher,
                fmp_replay: ReplayWindow::new(),
                source_npub: None,
            },
        );

        let (fallback_tx, mut fallback_rx) =
            tokio::sync::mpsc::unbounded_channel::<DecryptWorkerEvent>();

        let job = DecryptJob {
            packet_data: wire,
            cache_key,
            _transport_id: TransportId::new(1),
            _remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            timestamp_ms: 1_000,
            source_node_addr: crate::NodeAddr::from_bytes([0u8; 16]),
            fmp_counter: counter,
            fmp_flags: flags_byte,
            fmp_header: header,
            fmp_ciphertext_offset: HDR,
            fallback_tx,
        };

        handle_job(&mut sessions, job).expect("worker job handled");

        let event = fallback_rx.try_recv().expect("fallback delivered");
        let fallback = match event {
            DecryptWorkerEvent::Plaintext(fallback) => fallback,
            DecryptWorkerEvent::DecryptFailure(_) => panic!("expected plaintext fallback event"),
        };
        assert_eq!(
            fallback.fmp_flags, flags_byte,
            "fmp_flags must round-trip from DecryptJob to DecryptFallback"
        );
        assert!(
            fallback.fmp_flags & crate::proto::fmp::wire::FLAG_CE != 0,
            "FLAG_CE bit lost on worker path"
        );
        assert!(
            fallback.fmp_flags & crate::proto::fmp::wire::FLAG_KEY_EPOCH != 0,
            "FLAG_KEY_EPOCH bit lost on worker path"
        );
    }

    /// Build a minimal `OwnedSessionState` for tests that only need
    /// the worker's HashMap to contain *something* keyed on cache_key
    /// (e.g. unregister-removal tests). The cipher key is all-zero
    /// and the replay window is fresh; not suitable for any test
    /// that exercises an actual AEAD open.
    fn make_test_session_state() -> OwnedSessionState {
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        OwnedSessionState {
            fmp_cipher: LessSafeKey::new(unbound),
            fmp_replay: ReplayWindow::new(),
            source_npub: None,
        }
    }

    /// `WorkerMsg::UnregisterSession` must remove the session's entry
    /// from the worker-owned HashMap. Without this, every rekey
    /// cutover on a long-lived peer would leave a stale entry behind,
    /// growing the worker's `sessions` map unboundedly.
    #[test]
    fn handle_msg_unregister_session_removes_entry() {
        let mut sessions: HashMap<(TransportId, u32), OwnedSessionState> = HashMap::new();
        let cache_key = (TransportId::new(1), 42u32);
        sessions.insert(cache_key, make_test_session_state());
        assert!(
            sessions.contains_key(&cache_key),
            "precondition: session should be registered"
        );

        handle_msg(0, &mut sessions, WorkerMsg::UnregisterSession { cache_key });
        assert!(
            !sessions.contains_key(&cache_key),
            "UnregisterSession must drop the entry"
        );
    }

    /// `WorkerMsg::UnregisterSession` for a cache_key the worker has
    /// never seen must be a no-op (no panic, no effect on unrelated
    /// sessions). This is required for the unconditional unregister
    /// calls at all four index slots in `remove_active_peer`, where
    /// most slots are typically `None` and the registered ones may
    /// have moved between slots before removal.
    #[test]
    fn handle_msg_unregister_session_idempotent_on_unknown_key() {
        let mut sessions: HashMap<(TransportId, u32), OwnedSessionState> = HashMap::new();
        let key1 = (TransportId::new(1), 1u32);
        let key2 = (TransportId::new(1), 2u32);

        sessions.insert(key1, make_test_session_state());

        // Unregister never-seen key — must not panic, must not affect key1.
        handle_msg(
            0,
            &mut sessions,
            WorkerMsg::UnregisterSession { cache_key: key2 },
        );
        assert!(
            sessions.contains_key(&key1),
            "unrelated session must remain after unregistering an unknown key"
        );
        assert!(
            !sessions.contains_key(&key2),
            "unknown key must not have been inserted"
        );

        // First unregister of key1 — removes the entry.
        handle_msg(
            0,
            &mut sessions,
            WorkerMsg::UnregisterSession { cache_key: key1 },
        );
        assert!(!sessions.contains_key(&key1));

        // Double-unregister of key1 — also no-op, no panic.
        handle_msg(
            0,
            &mut sessions,
            WorkerMsg::UnregisterSession { cache_key: key1 },
        );
        assert!(!sessions.contains_key(&key1));
    }

    #[test]
    fn worker_reports_fmp_aead_failure_to_rx_loop() {
        let key_bytes = [0u8; 32];
        let unbound = UnboundKey::new(&ring::aead::CHACHA20_POLY1305, &key_bytes).unwrap();
        let open_cipher = LessSafeKey::new(unbound);

        let counter: u64 = 11;
        const HDR: usize = crate::proto::fmp::wire::ESTABLISHED_HEADER_SIZE;
        let header = [0u8; HDR];
        let mut wire = Vec::with_capacity(HDR + 4 + 1 + 16);
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&[0u8; 4]);
        wire.push(0xAB);
        wire.extend_from_slice(&[0u8; 16]); // invalid AEAD tag

        let cache_key = (TransportId::new(1), 77u32);
        let mut sessions: HashMap<(TransportId, u32), OwnedSessionState> = HashMap::new();
        sessions.insert(
            cache_key,
            OwnedSessionState {
                fmp_cipher: open_cipher,
                fmp_replay: ReplayWindow::new(),
                source_npub: None,
            },
        );

        let (fallback_tx, mut fallback_rx) =
            tokio::sync::mpsc::unbounded_channel::<DecryptWorkerEvent>();
        let source_node_addr = crate::NodeAddr::from_bytes([9u8; 16]);
        let job = DecryptJob {
            packet_data: wire,
            cache_key,
            _transport_id: TransportId::new(1),
            _remote_addr: crate::transport::TransportAddr::from_string("127.0.0.1:1234"),
            timestamp_ms: 1_000,
            source_node_addr,
            fmp_counter: counter,
            fmp_flags: 0,
            fmp_header: header,
            fmp_ciphertext_offset: HDR,
            fallback_tx,
        };

        handle_job(&mut sessions, job).expect("worker job handled");

        let event = fallback_rx.try_recv().expect("failure delivered");
        match event {
            DecryptWorkerEvent::DecryptFailure(report) => {
                assert_eq!(report.source_node_addr, source_node_addr);
                assert_eq!(report.fmp_counter, counter);
            }
            DecryptWorkerEvent::Plaintext(_) => panic!("expected decrypt failure report"),
        }
    }
}
