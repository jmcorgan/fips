//! Frames refused as replays, and the receive loop's hold on the runtime
//! thread that makes a late frame into one.
//!
//! A refusal must reach the peer's counts whichever path refused the frame,
//! and the count a run reads at its end must still hold what a rekey cutover
//! reset. The polling tests run the real receive loop on a `current_thread`
//! runtime, the daemon's shape, with an OS thread keeping one arm's channel
//! full, and count the frames fed between two polls of a spawned task. A
//! listen socket's reader is such a task, so a frame it has yet to read is
//! overtaken by every frame fed meanwhile, and past the replay window it is
//! refused. The bound they hold the loop to is [`HOLD_BOUND`], 2048 frames,
//! the window's width when they were written. The window is wider now, to
//! cover a full receive queue, and that width is not the loop's to use up,
//! so the tests keep the old bound and their names still say "one replay
//! window". The count is of frames, not time, so a slow host cannot turn a
//! run green, and a run ends after a set number of frames fed against a full
//! channel for the same reason: a host that starves the feeders only makes the
//! run longer.
//! One limit: with the feeders and the loop made to share a CPU, the loop can
//! empty the channel between the feeders' time slices, and then it goes back
//! to the scheduler for that reason, so the two cheapest arms can read under
//! the window with no yield at all. A failure means what it says.
//!
//! The count is of frames fed between two polls, so it also takes in frames
//! still queued at the second poll, up to the channel's 1024. It reads at or
//! above the frames that overtook one waiting at the first poll, never below.
//! A loop that yields after 512 items handled at most keeps it under 1536.
//!
//! The short-burst tests feed one arm in bursts that end short of the cap,
//! waiting for the channel to empty and a few microseconds more before each.
//! A burst then lands after the loop's drain reads empty and before its next
//! select, so no round stops at the cap. A loop that yields only after a
//! capped burst never yields there; the full-channel tests meet that pattern
//! only by chance.
//!
//! The overtake test hands the decrypt worker a frame that overtook as many
//! as a full default receive buffer and the sender's encrypt queue hold, the
//! reorder two sockets of one link produce under load, and checks that none
//! is refused.
//!
//! The tests print their measurements; run with `--nocapture` to see them.

use super::connected_udp::{PROMOTED_ADDR, promoted_peer_with_the_far_side_session};
#[cfg(unix)]
use super::decrypt_forged::forged_frame;
#[cfg(unix)]
use super::rekey_parity::deliver;
use super::rekey_parity::{
    age_link, cutover, heartbeat, linked_pair, rekey_config, rekey_to_pending, trigger_age,
};
#[cfg(unix)]
use super::spanning_tree::TestNode;
use super::spanning_tree::cleanup_nodes;
use super::*;
use crate::proto::fmp::wire::{build_encrypted, build_established_header};
use crate::transport::packet_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::sync::mpsc::error::TrySendError;

/// The most frames a spawned task may be overtaken by while the loop holds
/// the thread: the replay window's width before it was widened to cover a
/// full receive queue. A yield after 512 items keeps the gap under 1536.
const HOLD_BOUND: u64 = 2048;

/// Frames the loop can take in one cooperative budget: 128 rounds of a burst
/// of 257.
const BUDGET_FRAMES: u64 = 128 * 257;

/// Frames a polling run feeds against a full channel: past two whole budgets,
/// so a loop that holds the thread for a budget shows at least one whole gap
/// between two polls, however late the first poll comes.
const FRAMES: u64 = 2 * BUDGET_FRAMES + 4096;

/// How many times its frames a run may feed in all before it gives up on the
/// feed outrunning the loop.
const FEED_LIMIT: u64 = 16;

/// Threads feeding an arm. The loop drops these frames about as fast as one
/// thread makes them, and a run on a loaded host needs its feed well ahead
/// of the loop or the arm reads empty for reasons that are not the loop's.
const FEEDERS: usize = 2;

/// How long a polling run may take, far past any host's need.
const DEADLINE: Duration = Duration::from_secs(60);

/// The receive loop's channels an outside thread can keep ready.
#[derive(Clone, Copy, Debug)]
enum Arm {
    /// Fed by a connected socket's drain thread.
    Packet,
    /// Fed by the TUN reader thread, so by a bulk sender's own traffic.
    Datagram,
    /// Fed by an embedder's thread, when the app owns the TUN.
    AppTun,
}

/// What one attempt to feed an arm did.
enum Fed {
    Sent,
    Full,
    Closed,
}

impl Fed {
    /// What a `try_send` that returned `result` did.
    fn of<T>(result: Result<(), TrySendError<T>>) -> Self {
        match result {
            Ok(()) => Fed::Sent,
            Err(TrySendError::Full(_)) => Fed::Full,
            Err(TrySendError::Closed(_)) => Fed::Closed,
        }
    }
}

type Feed = Arc<dyn Fn() -> Fed + Send + Sync>;

/// Give `node` a new channel for `arm`, and return one attempt to feed it.
fn feed(node: &mut Node, arm: Arm) -> Feed {
    let (packet_tx, packet_rx) = packet_channel(1024);
    node.packet_rx = Some(packet_rx);
    match arm {
        Arm::Packet => Arc::new(move || {
            Fed::of(packet_tx.try_send(ReceivedPacket::new(
                TransportId::new(1),
                TransportAddr::from_string("feeder"),
                vec![0xffu8; 40],
            )))
        }),
        Arm::Datagram => {
            let (tx, rx) = tokio::sync::mpsc::channel(1024);
            node.supervisor.datagram_rx = Some(rx);
            let peer = crate::ipv6tun::link::any_key();
            Arc::new(move || {
                let _keep = &packet_tx;
                Fed::of(tx.try_send(crate::ipv6tun::link::Datagram {
                    peer,
                    payload: vec![0u8; 40],
                }))
            })
        }
        Arm::AppTun => {
            let (tx, rx) = tokio::sync::mpsc::channel(1024);
            node.supervisor.ipv6tun.install_outbound(rx);
            Arc::new(move || {
                let _keep = &packet_tx;
                Fed::of(tx.try_send(vec![0u8; 40]))
            })
        }
    }
}

/// How each feeder paces itself: after `burst` frames it sleeps `pause`.
#[derive(Clone, Copy)]
struct Pace {
    burst: u64,
    pause: Duration,
}

/// What a spawned task saw while the loop ran.
#[derive(Clone, Copy, Debug, Default)]
struct Polling {
    /// The most frames fed between two polls.
    largest: u64,
    /// Polls after the first.
    polls: u64,
    /// Frames fed between those polls.
    frames: u64,
    /// Those of the frames fed between polls with a feeder finding the
    /// channel full in between.
    outrun: u64,
}

impl Polling {
    /// Whether the feed outran the loop for `frames` frames. A feed below the
    /// loop's rate never finds the channel full, so a small gap from one says
    /// nothing about the loop. Counted in frames, since a spawned task spins
    /// through thousands of polls whenever the loop is idle, and the channel
    /// itself is not sampled, since a yielding loop has just emptied part of
    /// it at each poll.
    fn arm_stayed_ready(&self, frames: u64) -> bool {
        self.outrun >= frames
    }
}

/// Run the real receive loop on this `current_thread` runtime with OS threads
/// feeding `arm`, until `frames` have gone in against a full channel, or
/// [`FEED_LIMIT`] times that have gone in at all.
async fn polled(arm: Arm, pace: Option<Pace>, frames: u64) -> Polling {
    let mut node = make_node();
    let attempt = feed(&mut node, arm);
    let sent = Arc::new(AtomicU64::new(0));
    let full = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let feeders: Vec<_> = (0..FEEDERS)
        .map(|_| {
            let (attempt, sent) = (attempt.clone(), sent.clone());
            let (full, stop) = (full.clone(), stop.clone());
            std::thread::spawn(move || {
                let mut count = 0;
                while !stop.load(Ordering::Relaxed) {
                    match attempt() {
                        Fed::Sent => {
                            sent.fetch_add(1, Ordering::Relaxed);
                            count += 1;
                            if let Some(pace) = pace
                                && count % pace.burst == 0
                            {
                                std::thread::sleep(pace.pause);
                            }
                        }
                        Fed::Full => {
                            full.fetch_add(1, Ordering::Relaxed);
                            std::thread::yield_now();
                        }
                        Fed::Closed => break,
                    }
                }
            })
        })
        .collect();
    drop(attempt);
    let mut task = tokio::spawn(async move {
        let mut seen = Polling::default();
        let mut fed = sent.load(Ordering::Relaxed);
        let mut refused = full.load(Ordering::Relaxed);
        while seen.outrun < frames && seen.frames < frames * FEED_LIMIT {
            tokio::task::yield_now().await;
            let now = sent.load(Ordering::Relaxed);
            let gap = now - fed;
            fed = now;
            let now = full.load(Ordering::Relaxed);
            seen.polls += 1;
            seen.frames += gap;
            seen.largest = seen.largest.max(gap);
            if now > refused {
                seen.outrun += gap;
            }
            refused = now;
        }
        seen
    });
    let run = async {
        tokio::select! {
            biased;
            seen = &mut task => seen.expect("the polling task panicked"),
            _ = node.run_rx_loop_with_shutdown(std::future::pending()) => {
                panic!("precondition: the receive loop ended before the frames were fed")
            }
        }
    };
    let seen = tokio::time::timeout(DEADLINE, run)
        .await
        .expect("precondition: the feeder fed the run's frames in time");
    stop.store(true, Ordering::Relaxed);
    for feeder in feeders {
        feeder.join().expect("the feeder panicked");
    }
    eprintln!("{arm:?} {seen:?}");
    seen
}

/// A spawned task is polled within [`HOLD_BOUND`] frames while `arm` is kept
/// ready.
async fn polled_within_one_window(arm: Arm) {
    let seen = polled(arm, None, FRAMES).await;
    assert!(
        seen.arm_stayed_ready(FRAMES),
        "precondition: the feed outran the loop for {FRAMES} frames: {seen:?}"
    );
    assert!(
        seen.largest < HOLD_BOUND,
        "{} frames were fed to the {arm:?} arm between two polls of a spawned task, \
         against a bound of {HOLD_BOUND}",
        seen.largest
    );
}

#[tokio::test]
async fn a_spawned_task_is_polled_within_one_replay_window_while_the_packet_arm_stays_full() {
    polled_within_one_window(Arm::Packet).await;
}

#[tokio::test]
async fn a_spawned_task_is_polled_within_one_replay_window_while_the_datagram_arm_stays_full() {
    polled_within_one_window(Arm::Datagram).await;
}

#[tokio::test]
async fn a_spawned_task_is_polled_within_one_replay_window_while_the_app_tun_arm_stays_full() {
    polled_within_one_window(Arm::AppTun).await;
}

/// Pauses after the channel reads empty, in microseconds, before a short-burst
/// feeder's next burst. They cover the bands where a refill lands between the
/// loop's empty read and its next select: 0 to 5 on the packet and app-TUN
/// arms, 5 to 20 on the datagram arm, which costs more per frame.
const SHORT_PAUSES_US: [u64; 6] = [0, 1, 2, 5, 10, 20];

/// One feeder thread for `tx`: push `burst` frames, wait until the channel
/// reads empty, spin `pause` more, and again, until `stop` or a closed channel.
fn short_feeder<T: Send + 'static>(
    tx: tokio::sync::mpsc::Sender<T>,
    make: impl Fn() -> T + Send + 'static,
    burst: u64,
    pause: Duration,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        while !stop.load(Ordering::Relaxed) && !tx.is_closed() {
            for _ in 0..burst {
                if tx.try_send(make()).is_err() {
                    break;
                }
                sent.fetch_add(1, Ordering::Relaxed);
            }
            while tx.capacity() != tx.max_capacity() {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                std::hint::spin_loop();
            }
            let until = std::time::Instant::now() + pause;
            while std::time::Instant::now() < until {
                std::hint::spin_loop();
            }
        }
    })
}

/// Give `node` a new channel for `arm` and a short-burst feeder on it. The
/// returned sender keeps the packet channel open when another arm is fed.
fn short_feed(
    node: &mut Node,
    arm: Arm,
    burst: u64,
    pause: Duration,
    sent: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) -> (
    std::thread::JoinHandle<()>,
    Option<crate::transport::PacketTx>,
) {
    let (packet_tx, packet_rx) = packet_channel(1024);
    node.packet_rx = Some(packet_rx);
    match arm {
        Arm::Packet => {
            let packet = || {
                ReceivedPacket::new(
                    TransportId::new(1),
                    TransportAddr::from_string("feeder"),
                    vec![0xffu8; 40],
                )
            };
            (
                short_feeder(packet_tx, packet, burst, pause, sent, stop),
                None,
            )
        }
        Arm::Datagram => {
            let (tx, rx) = tokio::sync::mpsc::channel(1024);
            node.supervisor.datagram_rx = Some(rx);
            let peer = crate::ipv6tun::link::any_key();
            let datagram = move || crate::ipv6tun::link::Datagram {
                peer,
                payload: vec![0u8; 40],
            };
            let feeder = short_feeder(tx, datagram, burst, pause, sent, stop);
            (feeder, Some(packet_tx))
        }
        Arm::AppTun => {
            let (tx, rx) = tokio::sync::mpsc::channel(1024);
            node.supervisor.ipv6tun.install_outbound(rx);
            let feeder = short_feeder(tx, || vec![0u8; 40], burst, pause, sent, stop);
            (feeder, Some(packet_tx))
        }
    }
}

/// Run the real receive loop with one short-burst feeder on `arm` until
/// `frames` have been fed, and return what a spawned task saw.
async fn polled_short(arm: Arm, burst: u64, pause: Duration, frames: u64) -> Polling {
    let mut node = make_node();
    let sent = Arc::new(AtomicU64::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (feeder, keep) = short_feed(&mut node, arm, burst, pause, sent.clone(), stop.clone());
    let mut task = tokio::spawn(async move {
        let mut seen = Polling::default();
        let mut fed = sent.load(Ordering::Relaxed);
        while seen.frames < frames {
            tokio::task::yield_now().await;
            let now = sent.load(Ordering::Relaxed);
            let gap = now - fed;
            fed = now;
            seen.polls += 1;
            seen.frames += gap;
            seen.largest = seen.largest.max(gap);
        }
        seen
    });
    let run = async {
        tokio::select! {
            biased;
            seen = &mut task => seen.expect("the polling task panicked"),
            _ = node.run_rx_loop_with_shutdown(std::future::pending()) => {
                panic!("precondition: the receive loop ended before the frames were fed")
            }
        }
    };
    let seen = tokio::time::timeout(DEADLINE, run)
        .await
        .expect("precondition: the feeder fed the run's frames in time");
    stop.store(true, Ordering::Relaxed);
    feeder.join().expect("the feeder panicked");
    drop(keep);
    seen
}

/// A spawned task is polled within [`HOLD_BOUND`] frames while `arm` is fed in
/// bursts of `burst` and of 128, each landing short of the cap, at every pause
/// in [`SHORT_PAUSES_US`].
async fn polled_within_one_window_on_short_bursts(arm: Arm, burst: u64) {
    let mut past = Vec::new();
    for burst in [burst, 128] {
        for pause in SHORT_PAUSES_US {
            let seen = polled_short(arm, burst, Duration::from_micros(pause), FRAMES).await;
            eprintln!("{arm:?} burst {burst} pause {pause} us {seen:?}");
            if seen.largest >= HOLD_BOUND {
                past.push((burst, pause, seen.largest));
            }
        }
    }
    assert!(
        past.is_empty(),
        "frames fed to the {arm:?} arm between two polls of a spawned task, against a bound \
         of {HOLD_BOUND}, as (burst, pause in us, frames): {past:?}"
    );
}

#[tokio::test]
async fn a_spawned_task_is_polled_within_one_replay_window_while_short_bursts_keep_the_packet_arm_ready()
 {
    polled_within_one_window_on_short_bursts(Arm::Packet, 255).await;
}

#[tokio::test]
async fn a_spawned_task_is_polled_within_one_replay_window_while_short_bursts_keep_the_datagram_arm_ready()
 {
    polled_within_one_window_on_short_bursts(Arm::Datagram, 256).await;
}

#[tokio::test]
async fn a_spawned_task_is_polled_within_one_replay_window_while_short_bursts_keep_the_app_tun_arm_ready()
 {
    polled_within_one_window_on_short_bursts(Arm::AppTun, 256).await;
}

/// The polling tests' precondition has to fail on a feeder that holds nothing
/// ready, or a healthy result from one would pass for a full arm. At this pace
/// the channel takes half a second to fill, so a loop that a loaded host keeps
/// off the CPU for a while does not read as a feed outrunning it, and the run
/// still feeds more than the channel holds, so a loop that took nothing would.
#[tokio::test]
async fn a_feeder_below_the_loops_rate_does_not_count_as_keeping_the_arm_ready() {
    let pace = Pace {
        burst: 10,
        pause: Duration::from_millis(10),
    };
    let frames = 100;
    let seen = polled(Arm::Datagram, Some(pace), frames).await;
    assert!(seen.frames > 0, "the spawned task saw the feed: {seen:?}");
    assert!(!seen.arm_stayed_ready(frames), "{seen:?}");
}

/// The kernel's charge against a UDP receive buffer for each datagram of
/// `len` bytes on this host: a loopback socket's buffer over the number of
/// datagrams it held when full. The ratio does not depend on the buffer's
/// size, so a small buffer keeps the fill short.
#[cfg(target_os = "linux")]
fn charge_per_datagram(len: usize) -> usize {
    use std::net::UdpSocket;
    let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let rx_ref = socket2::SockRef::from(&rx);
    rx_ref.set_recv_buffer_size(64 * 1024).unwrap();
    let buf = rx_ref.recv_buffer_size().unwrap();
    rx.set_nonblocking(true).unwrap();
    let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
    let to = rx.local_addr().unwrap();
    let datagram = vec![0u8; len];
    // Twice what the buffer could hold at no charge above the payload, so it
    // is full at any real charge. The kernel drops the rest.
    for _ in 0..2 * buf / len {
        let _ = tx.send_to(&datagram, to);
    }
    let mut sink = [0u8; 2048];
    let mut queued = 0;
    while rx.recv(&mut sink).is_ok() {
        queued += 1;
    }
    assert!(
        queued > 0,
        "precondition: the loopback socket queued a datagram"
    );
    buf / queued
}

/// While a receiver is saturated, the socket carrying a link's bulk stream
/// fills to its buffer, and a path probe arriving on the link's other socket
/// is read ahead of all of it. The sender's encrypt queue for another
/// destination can put up to its capacity more between them. The decrypt
/// worker's window has to cover that reorder, or the queued frames are
/// refused once the probe moves it. The buffer is the default UDP one, sized
/// in the smallest frames by this host's kernel.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_frame_queued_behind_a_full_default_receive_buffer_is_not_refused_when_a_probe_overtakes_it()
 {
    use super::connected_udp::far_side_frame;
    use crate::config::UdpConfig;
    use crate::node::decrypt_worker::{DecryptWorkerEvent, DecryptWorkerPool};
    use crate::node::encrypt_worker::WORKER_CHANNEL_CAP;

    let charge = charge_per_datagram(60);
    let queue = 2 * UdpConfig::default().recv_buf_size() / charge;
    let held = (queue + WORKER_CHANNEL_CAP + 1) as u64;
    eprintln!("{charge} B charged per small datagram: {queue} queued, {held} overtaken");
    assert!(
        held > HOLD_BOUND,
        "precondition: the probe overtakes more frames than the window once covered"
    );

    let tid = TransportId::new(1);
    let (mut node, peer, index, mut far_side) = promoted_peer_with_the_far_side_session(tid);
    let original = TransportAddr::from_string(PROMOTED_ADDR);
    node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
    let offer = node.get_peer(&peer).unwrap().offer_to_workers();
    node.run_link_outputs(&peer, offer);
    assert!(
        node.decrypt_registered_sessions.contains(&index.as_u32()),
        "precondition: the session is registered with the worker"
    );
    let mut events = node.decrypt_fallback_rx.take().unwrap();

    // Sealed in counter order; the last is the probe, and it is read first.
    let mut frames: Vec<_> = (0..=held)
        .map(|_| far_side_frame(&mut far_side, index))
        .collect();
    let probe = frames.pop().unwrap();
    for frame in std::iter::once(probe).chain(frames) {
        node.process_packet(ReceivedPacket::new(tid, original.clone(), frame))
            .await;
    }
    node.process_packet(ReceivedPacket::new(
        tid,
        original,
        forged_frame(index, 1_000_000),
    ))
    .await;
    let mut plaintext = 0u64;
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("precondition: the marker's report arrived")
            .expect("precondition: the worker event channel is open");
        let done = matches!(event, DecryptWorkerEvent::DecryptFailure(_));
        if matches!(event, DecryptWorkerEvent::Plaintext(_)) {
            plaintext += 1;
        }
        node.process_decrypt_worker_event(event).await;
        if done {
            break;
        }
    }
    let refused = node.get_peer(&peer).unwrap().replay_suppressed_total();
    assert_eq!(
        refused,
        0,
        "{refused} of the {held} frames the probe overtook were refused as replays \
         ({plaintext} of {} delivered)",
        held + 1
    );
}

/// A peer promoted on `tid`, and one authentic frame from its far side.
fn peer_and_frame(tid: TransportId) -> (Node, NodeAddr, SessionIndex, Vec<u8>) {
    let (node, peer, index, mut far_side) = promoted_peer_with_the_far_side_session(tid);
    let inner = [0u8; 8];
    let counter = far_side.current_send_counter();
    let header = build_established_header(index, counter, 0, inner.len() as u16);
    let sealed = far_side.encrypt_with_aad(&inner, &header).unwrap();
    let frame = build_encrypted(&header, &sealed);
    (node, peer, index, frame)
}

#[tokio::test]
async fn a_replay_refused_on_the_inline_path_is_counted_on_the_peer() {
    let tid = TransportId::new(1);
    let (mut node, peer, _, frame) = peer_and_frame(tid);
    let original = TransportAddr::from_string(PROMOTED_ADDR);
    for _ in 0..2 {
        node.handle_encrypted_frame(ReceivedPacket::new(tid, original.clone(), frame.clone()))
            .await;
    }
    assert_eq!(node.get_peer(&peer).unwrap().replay_suppressed_count(), 1);
}

/// One authentic frame from the far side, handed to the decrypt worker twice,
/// then a forged frame as a marker that the worker has handled both.
#[cfg(unix)]
#[tokio::test]
async fn a_replay_the_decrypt_worker_refuses_is_counted_on_the_peer() {
    use crate::node::decrypt_worker::{DecryptWorkerEvent, DecryptWorkerPool};
    let tid = TransportId::new(1);
    let (mut node, peer, index, frame) = peer_and_frame(tid);
    let original = TransportAddr::from_string(PROMOTED_ADDR);
    node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
    let offer = node.get_peer(&peer).unwrap().offer_to_workers();
    node.run_link_outputs(&peer, offer);
    assert!(
        node.decrypt_registered_sessions.contains(&index.as_u32()),
        "precondition: the session is registered with the worker"
    );
    let mut events = node.decrypt_fallback_rx.take().unwrap();
    for _ in 0..2 {
        node.handle_encrypted_frame(ReceivedPacket::new(tid, original.clone(), frame.clone()))
            .await;
    }
    let forged = forged_frame(index, 1_000_000);
    node.handle_encrypted_frame(ReceivedPacket::new(tid, original.clone(), forged))
        .await;
    let mut plaintext = 0;
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("precondition: the marker's report arrived")
            .expect("precondition: the worker event channel is open");
        let done = matches!(event, DecryptWorkerEvent::DecryptFailure(_));
        if matches!(event, DecryptWorkerEvent::Plaintext(_)) {
            plaintext += 1;
        }
        node.process_decrypt_worker_event(event).await;
        if done {
            break;
        }
    }
    assert_eq!(plaintext, 1, "precondition: the first copy was authentic");
    assert_eq!(
        node.get_peer(&peer).unwrap().replay_suppressed_count(),
        1,
        "the worker's refusal reached the peer's count"
    );
}

/// A session offered at promotion reads the peer's total to hand the worker,
/// so the promotion has to run the machine's outputs once the peer is in the
/// table. With the pool up before the handshake, each side's session reaches
/// its worker, and a refusal there reaches the total its peer holds.
#[cfg(unix)]
#[tokio::test]
async fn a_promoted_session_reaches_the_decrypt_workers_with_the_peers_total() {
    use super::spanning_tree::{drain_all_packets, initiate_handshake, make_test_node_with_config};
    use crate::node::decrypt_worker::DecryptWorkerPool;
    let mut nodes = vec![
        make_test_node_with_config(rekey_config(60), 1280).await,
        make_test_node_with_config(rekey_config(60), 1280).await,
    ];
    nodes[0].node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
    nodes[1].node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    let index0 = nodes[0].node.get_peer(&addr1).unwrap().our_index().unwrap();
    let index1 = nodes[1].node.get_peer(&addr0).unwrap().our_index().unwrap();
    assert!(
        nodes[0]
            .node
            .decrypt_registered_sessions
            .contains(&index0.as_u32()),
        "defect: the initiator's promoted session did not reach its worker"
    );
    assert!(
        nodes[1]
            .node
            .decrypt_registered_sessions
            .contains(&index1.as_u32()),
        "defect: the responder's promoted session did not reach its worker"
    );

    let mut events = nodes[0].node.decrypt_fallback_rx.take().unwrap();
    heartbeat(&mut nodes[1], &addr0).await;
    let TestNode {
        node, packet_rx, ..
    } = &mut nodes[0];
    refuse_a_copy_in_the_worker(node, packet_rx, &mut events, index0).await;

    let total = nodes[0]
        .node
        .get_peer(&addr1)
        .unwrap()
        .replay_suppressed_total();
    nodes[0].node.decrypt_fallback_rx = Some(events);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        total, 1,
        "defect: the worker's refusal did not reach the peer's total"
    );
}

/// Node 0 refuses a copy of one of node 1's frames, then cuts over a rekey,
/// which resets the count of refusals; the total keeps it.
#[tokio::test]
async fn the_total_of_refused_replays_survives_a_rekey_cutover() {
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    heartbeat(&mut nodes[1], &addr0).await;
    let frame = nodes[0]
        .packet_rx
        .recv()
        .await
        .expect("precondition: node 1's heartbeat reaches node 0");
    for _ in 0..2 {
        let copy = ReceivedPacket::new(
            frame.transport_id,
            frame.remote_addr.clone(),
            frame.data.clone(),
        );
        nodes[0].node.process_packet(copy).await;
    }
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&addr1)
            .unwrap()
            .replay_suppressed_count(),
        1,
        "precondition: the second copy was refused"
    );

    age_link(&mut nodes, 0, 1, trigger_age());
    rekey_to_pending(&mut nodes, 0, 1).await;
    cutover(&mut nodes[0], &addr1).await;

    let peer = nodes[0].node.get_peer(&addr1).unwrap();
    let total = peer.replay_suppressed_total();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(total, 1, "the total kept the refusal across the cutover");
}

/// Hand node 0 whatever is queued for it, the last frame twice, then a forged
/// frame on `index` as a marker that the worker has handled the copy, and
/// handle the worker's reports until the marker's.
#[cfg(unix)]
async fn refuse_a_copy_in_the_worker(
    node: &mut Node,
    queued: &mut tokio::sync::mpsc::UnboundedReceiver<ReceivedPacket>,
    events: &mut tokio::sync::mpsc::UnboundedReceiver<
        crate::node::decrypt_worker::DecryptWorkerEvent,
    >,
    index: SessionIndex,
) {
    use crate::node::decrypt_worker::DecryptWorkerEvent;
    let mut last = None;
    while let Ok(packet) = queued.try_recv() {
        last = Some((
            packet.transport_id,
            packet.remote_addr.clone(),
            packet.data.clone(),
        ));
        node.process_packet(packet).await;
    }
    let (tid, addr, data) = last.expect("precondition: a frame is queued at node 0");
    node.process_packet(ReceivedPacket::new(tid, addr.clone(), data))
        .await;
    node.process_packet(ReceivedPacket::new(
        tid,
        addr,
        forged_frame(index, 1_000_000),
    ))
    .await;
    loop {
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("precondition: the marker's report arrived")
            .expect("precondition: the worker event channel is open");
        let done = matches!(event, DecryptWorkerEvent::DecryptFailure(_));
        node.process_decrypt_worker_event(event).await;
        if done {
            break;
        }
    }
}

/// The session a cutover hands the worker counts into the total the peer
/// already holds, which the inline test above cannot see.
#[cfg(unix)]
#[tokio::test]
async fn a_worker_refusal_after_a_rekey_cutover_reaches_the_same_total() {
    use crate::node::decrypt_worker::DecryptWorkerPool;
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    nodes[0].node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
    let offer = nodes[0].node.get_peer(&addr1).unwrap().offer_to_workers();
    nodes[0].node.run_link_outputs(&addr1, offer);
    let mut events = nodes[0].node.decrypt_fallback_rx.take().unwrap();
    let first = nodes[0].node.get_peer(&addr1).unwrap().our_index().unwrap();
    assert!(
        nodes[0]
            .node
            .decrypt_registered_sessions
            .contains(&first.as_u32()),
        "precondition: the first session is registered with the worker"
    );

    heartbeat(&mut nodes[1], &addr0).await;
    let TestNode {
        node, packet_rx, ..
    } = &mut nodes[0];
    refuse_a_copy_in_the_worker(node, packet_rx, &mut events, first).await;
    let peer = nodes[0].node.get_peer(&addr1).unwrap();
    assert_eq!(
        peer.replay_suppressed_total(),
        1,
        "precondition: the first session's refusal is counted"
    );

    age_link(&mut nodes, 0, 1, trigger_age());
    rekey_to_pending(&mut nodes, 0, 1).await;
    cutover(&mut nodes[0], &addr1).await;
    let second = nodes[0].node.get_peer(&addr1).unwrap().our_index().unwrap();
    assert_ne!(second, first, "precondition: the cutover moved the session");
    assert!(
        nodes[0]
            .node
            .decrypt_registered_sessions
            .contains(&second.as_u32()),
        "precondition: the new session is registered with the worker"
    );

    // Node 1 moves to the new session on node 0's first frame under it.
    heartbeat(&mut nodes[0], &addr1).await;
    deliver(&mut nodes[1]).await;
    heartbeat(&mut nodes[1], &addr0).await;
    let TestNode {
        node, packet_rx, ..
    } = &mut nodes[0];
    refuse_a_copy_in_the_worker(node, packet_rx, &mut events, second).await;

    let peer = nodes[0].node.get_peer(&addr1).unwrap();
    let total = peer.replay_suppressed_total();
    nodes[0].node.decrypt_fallback_rx = Some(events);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(total, 2, "the new session's refusal reached the total");
}

/// A move hands the worker a new session, which counts into the total the
/// peer already holds: a worker of the old session may still be counting into
/// it, so the move keeps the same one and moves the base.
#[cfg(unix)]
#[tokio::test]
async fn a_worker_refusal_after_a_move_reaches_the_same_total() {
    use super::settle::readings::own_dial;
    use crate::node::decrypt_worker::DecryptWorkerPool;
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    nodes[0].node.supervisor.decrypt_workers = Some(DecryptWorkerPool::spawn(1));
    let offer = nodes[0].node.get_peer(&addr1).unwrap().offer_to_workers();
    nodes[0].node.run_link_outputs(&addr1, offer);
    let mut events = nodes[0].node.decrypt_fallback_rx.take().unwrap();
    let first = nodes[0].node.get_peer(&addr1).unwrap().our_index().unwrap();
    assert!(
        nodes[0]
            .node
            .decrypt_registered_sessions
            .contains(&first.as_u32()),
        "precondition: the first session is registered with the worker"
    );

    heartbeat(&mut nodes[1], &addr0).await;
    let TestNode {
        node, packet_rx, ..
    } = &mut nodes[0];
    refuse_a_copy_in_the_worker(node, packet_rx, &mut events, first).await;
    let peer = nodes[0].node.get_peer(&addr1).unwrap();
    assert_eq!(
        peer.replay_suppressed_total(),
        1,
        "precondition: the first session's refusal is counted"
    );

    own_dial(&mut nodes).await;
    let second = nodes[0].node.get_peer(&addr1).unwrap().our_index().unwrap();
    assert_ne!(second, first, "precondition: the move changed the session");
    assert!(
        nodes[0]
            .node
            .decrypt_registered_sessions
            .contains(&second.as_u32()),
        "precondition: the new session is registered with the worker"
    );

    // Node 1 moves to the new session on node 0's first frame under it.
    heartbeat(&mut nodes[0], &addr1).await;
    deliver(&mut nodes[1]).await;
    heartbeat(&mut nodes[1], &addr0).await;
    let TestNode {
        node, packet_rx, ..
    } = &mut nodes[0];
    refuse_a_copy_in_the_worker(node, packet_rx, &mut events, second).await;

    let peer = nodes[0].node.get_peer(&addr1).unwrap();
    let total = peer.replay_suppressed_total();
    nodes[0].node.decrypt_fallback_rx = Some(events);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(total, 2, "the new session's refusal reached the total");
}

/// A restart replaces the peer, and the new peer's total of refusals starts
/// at nothing: what was refused belonged to the peering that has gone.
#[tokio::test]
async fn a_replaced_peer_starts_a_new_total() {
    use super::settle::readings::restart_dial;
    let mut nodes = linked_pair(rekey_config(60), rekey_config(60)).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    heartbeat(&mut nodes[1], &addr0).await;
    let frame = nodes[0]
        .packet_rx
        .recv()
        .await
        .expect("precondition: node 1's heartbeat reaches node 0");
    for _ in 0..2 {
        let copy = ReceivedPacket::new(
            frame.transport_id,
            frame.remote_addr.clone(),
            frame.data.clone(),
        );
        nodes[0].node.process_packet(copy).await;
    }
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&addr1)
            .unwrap()
            .replay_suppressed_total(),
        1,
        "precondition: the second copy was refused"
    );

    restart_dial(&mut nodes, rekey_config(60)).await;

    let total = nodes[0]
        .node
        .get_peer(&addr1)
        .unwrap()
        .replay_suppressed_total();
    cleanup_nodes(&mut nodes).await;
    assert_eq!(total, 0, "the new peer's total starts at nothing");
}
