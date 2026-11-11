//! A pinned BLE path loaded beyond its rate.
//!
//! Two loopback nodes, each with a second transport: BLE over the mock
//! backend, its far ends joined by a pacer that carries the frames at a
//! set rate, so the BLE transport's own outbound queue is the only queue
//! in front of the link. Both ends pin the link to BLE, then A sends more
//! than the link carries. Simulated time throughout (`crate::time::freeze`),
//! advanced in fixed steps, so the run does not depend on the host's load.

use super::ble::ble_addr;
use super::paths::enabled;
use super::rekey_parity::linked_pair;
use super::spanning_tree::{LOOPBACK_REGISTRY, TestNode, cleanup_nodes, process_available_packets};
use super::*;
use crate::config::BleConfig;
use crate::peer::PathState;
use crate::proto::link::LinkMessageType;
use crate::transport::ble::BleTransport;
use crate::transport::ble::io::{BleStream, MockBleIo, MockBleStream};
use crate::transport::{TransportHandle, TransportId, packet_channel};
use futures::FutureExt;

/// The id of the BLE transport each node is given.
const BLE_ID: u32 = 2;

/// The BLE transport each node is given.
fn ble_id() -> TransportId {
    TransportId::new(BLE_ID)
}

/// The BLE link's rate in each direction, bits per second: what a macOS
/// to BlueZ link carried in a field test.
const LINK_BPS: u64 = 250_000;

/// What A offers the link while loaded, bits per second.
const LOAD_BPS: u64 = 500_000;

/// The plaintext of each frame of load: a heartbeat padded to this size,
/// which the peer reads and ignores.
const LOAD_LEN: usize = 1_000;

/// The simulated step.
const STEP: Duration = Duration::from_millis(5);

/// The node's path tick, every this many steps (50 ms, as the daemon).
const TICK_EVERY: u32 = 10;

/// One direction of the paced link: the frame on the link now, and the
/// credit toward it in bit-milliseconds.
#[derive(Default)]
struct Lane {
    held: Option<Vec<u8>>,
    credit: u64,
}

impl Lane {
    /// Carry what one step of [`STEP`] carries from `from` to `to`, at
    /// [`LINK_BPS`], one frame at a time.
    async fn step(&mut self, from: &MockBleStream, to: &MockBleStream) {
        self.credit += LINK_BPS * STEP.as_millis() as u64;
        loop {
            if self.held.is_none() {
                let mut buf = vec![0u8; 4096];
                match from.recv(&mut buf).now_or_never() {
                    Some(Ok(n)) if n > 0 => {
                        buf.truncate(n);
                        self.held = Some(buf);
                    }
                    _ => {
                        // An idle link banks no credit.
                        self.credit = 0;
                        return;
                    }
                }
            }
            let need = self.held.as_ref().map_or(0, |f| f.len() as u64) * 8 * 1000;
            if self.credit < need {
                return;
            }
            self.credit -= need;
            let frame = self.held.take().unwrap();
            to.send(&frame)
                .await
                .expect("the receiver's stream is open");
        }
    }
}

/// The BLE link between A and B: the far end of each node's stream and a
/// lane each way.
struct Link {
    /// The far end of A's stream: what A sends comes out here, and what is
    /// sent here reaches A.
    a_far: MockBleStream,
    /// The far end of B's stream.
    b_far: MockBleStream,
    ab: Lane,
    ba: Lane,
}

impl Link {
    /// Carry one step's worth each way.
    async fn step(&mut self) {
        self.ab.step(&self.a_far, &self.b_far).await;
        self.ba.step(&self.b_far, &self.a_far).await;
    }
}

/// Give `tn` the BLE transport [`BLE`] at `ble_addr(n)`, delivering what it
/// receives into `tn`'s own receive channel, and return its address.
async fn add_ble(tn: &mut TestNode, n: u8) -> TransportAddr {
    let addr = ble_addr(n);
    let config = BleConfig {
        adapter: Some("hci0".to_string()),
        mtu: Some(2048),
        accept_connections: Some(true),
        scan: Some(false),
        advertise: Some(false),
        auto_connect: Some(false),
        ..Default::default()
    };
    let io = MockBleIo::new("hci0", addr.clone());
    let (packet_tx, mut packet_rx) = packet_channel(256);
    let mut transport = BleTransport::new(ble_id(), None, config, io, packet_tx);
    transport.start_async().await.unwrap();
    let (_, inbox) = LOOPBACK_REGISTRY
        .lock()
        .unwrap()
        .get(&tn.addr)
        .expect("the node's loopback address is registered")
        .clone();
    tokio::spawn(async move {
        while let Some(packet) = packet_rx.recv().await {
            if inbox.send(packet).is_err() {
                break;
            }
        }
    });
    tn.node
        .transports
        .insert(ble_id(), TransportHandle::Ble(transport));
    addr.to_transport_addr()
}

/// `tn`'s BLE transport.
fn ble(tn: &TestNode) -> &crate::transport::ble::DefaultBleTransport {
    match tn.node.transports.get(&ble_id()) {
        Some(TransportHandle::Ble(t)) => t,
        _ => panic!("transport 2 is BLE"),
    }
}

/// What one sample of A's link shows.
#[derive(Clone, Debug, PartialEq)]
struct Seen {
    /// The transport of A's active path.
    active: TransportId,
    /// The state of A's BLE path.
    ble: Option<PathState>,
    /// Whether A's pin is in force.
    pinned: bool,
}

/// The two nodes, the pacers between their BLE transports, and the
/// simulated clock's position.
struct Rig {
    nodes: Vec<TestNode>,
    link: Link,
    a_ble: TransportAddr,
    b_ble: TransportAddr,
    steps: u32,
    /// A's credit toward the next frame of load, in bit-milliseconds.
    load_credit: u64,
    /// Frames of load A's sends refused.
    load_refused: u64,
    /// Frames of load A sent.
    load_sent: u64,
}

impl Rig {
    /// The time since the rig started.
    fn at(&self) -> Duration {
        STEP * self.steps
    }

    /// Run one step: the clock moves, the pacers carry what the link
    /// carries, the path tick runs on its cadence, then `load` frames of
    /// load go, then every frame that arrived is handled. The tick runs
    /// before the load, so a probe meets a slot the pacer has just freed
    /// before the load can take it.
    async fn step(&mut self, load: bool) {
        crate::time::advance(STEP);
        self.steps += 1;
        self.settle().await;
        self.link.step().await;
        self.settle().await;
        if self.steps.is_multiple_of(TICK_EVERY) {
            self.nodes[0].node.path_tick().await;
            self.nodes[1].node.path_tick().await;
        }
        if load {
            let b = *self.nodes[1].node.node_addr();
            self.load_credit += LOAD_BPS * STEP.as_millis() as u64;
            let need = (LOAD_LEN as u64) * 8 * 1000;
            while self.load_credit >= need {
                self.load_credit -= need;
                let mut frame = vec![0u8; LOAD_LEN];
                frame[0] = LinkMessageType::Heartbeat.to_byte();
                match self.nodes[0]
                    .node
                    .send_encrypted_link_message(&b, &frame)
                    .await
                {
                    Ok(()) => self.load_sent += 1,
                    Err(_) => self.load_refused += 1,
                }
            }
        }
        self.settle().await;
        let mut passes = 0;
        while process_available_packets(&mut self.nodes).await > 0 {
            passes += 1;
            assert!(passes < 64, "the frames do not settle");
            self.settle().await;
        }
    }

    /// Let the transports' tasks run: the writers, the receive loops and
    /// the forwarders into each node's channel.
    async fn settle(&self) {
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
    }

    /// What A's link to B shows now.
    fn seen(&self) -> Seen {
        let b = *self.nodes[1].node.node_addr();
        let peer = self.nodes[0].node.get_peer(&b).expect("A holds B");
        let paths = peer.bundle().expect("A's link has a bundle").paths();
        let active = paths
            .get(paths.active_index().expect("an active path"))
            .unwrap()
            .transport_id();
        let ble = paths
            .find(ble_id(), &self.b_ble)
            .map(|i| paths.get(i).unwrap().state());
        let npub = self.nodes[1].node.npub();
        let shown = self.nodes[0].node.show_paths(&npub).expect("path_show");
        Seen {
            active,
            ble,
            pinned: shown["pin"]["in_force"] == true,
        }
    }

    /// The latest round trip of A's BLE path.
    fn ble_rtt(&self) -> Option<Duration> {
        let b = *self.nodes[1].node.node_addr();
        let paths = self.nodes[0].node.get_peer(&b)?.bundle()?.paths();
        let i = paths.find(ble_id(), &self.b_ble)?;
        paths.get(i).unwrap().live().rtt()
    }

    /// The state of B's BLE path to A.
    fn b_side(&self) -> Option<PathState> {
        let a = *self.nodes[0].node.node_addr();
        let paths = self.nodes[1].node.get_peer(&a)?.bundle()?.paths();
        let i = paths.find(ble_id(), &self.a_ble)?;
        Some(paths.get(i).unwrap().state())
    }
}

/// Build the rig: two linked loopback nodes, multipath on, each with a BLE
/// transport, A's BLE path to B and B's to A both Live.
async fn rig() -> Rig {
    crate::time::freeze();
    // Loopback addresses are no IP addresses, so the loopback link's kind
    // is internet and BLE's is local; let the link hold both.
    let mut config = enabled();
    config.node.path.mix_kinds = true;
    let mut nodes = linked_pair(config.clone(), config).await;
    let a_ble = add_ble(&mut nodes[0], 1).await;
    let b_ble = add_ble(&mut nodes[1], 2).await;

    // A's stream to B and B's to A, each joined at its far end to a pacer.
    // A writer's channel holds one frame, so its send waits on the pacer
    // as a radio's waits on the link; what arrives is not held back.
    let (a_end, a_far) = MockBleStream::pair_with_depths(ble_addr(1), ble_addr(2), 2048, 1, 64);
    let (b_end, b_far) = MockBleStream::pair_with_depths(ble_addr(2), ble_addr(1), 2048, 1, 64);
    let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(a_end)));
    ble(&nodes[0]).io().set_connect_handler(move |_, _| {
        slot.lock()
            .unwrap()
            .take()
            .ok_or(crate::transport::TransportError::ConnectionRefused)
    });
    ble(&nodes[1]).io().inject_inbound(b_end).await;

    let mut rig = Rig {
        nodes,
        link: Link {
            a_far,
            b_far,
            ab: Lane::default(),
            ba: Lane::default(),
        },
        a_ble,
        b_ble,
        steps: 0,
        load_credit: 0,
        load_refused: 0,
        load_sent: 0,
    };

    // A offers B's BLE address; the machine has the connection opened,
    // proves the path, and B learns its own path to A from A's probes.
    let b = *rig.nodes[1].node.node_addr();
    let to = rig.b_ble.clone();
    rig.nodes[0].node.offer_path(&b, ble_id(), to).await;
    let mut waited = 0;
    while !(rig.seen().ble == Some(PathState::Live) && rig.b_side() == Some(PathState::Live)) {
        waited += 1;
        assert!(
            waited < 6_000,
            "setup bound: the BLE paths are not Live after 30 s"
        );
        rig.step(false).await;
    }
    rig
}

/// Pin both ends of the link to BLE, idle for 3 s, then load A's side with
/// twice what BLE carries for 20 s. The pin holds through both: the link
/// stays on BLE and the BLE path stays Live, whatever the load, since the
/// path still answers, only late. Prints A's timeline: each change of
/// active path, BLE path state or pin, with the BLE path's latest round
/// trip.
#[tokio::test]
async fn a_pinned_ble_path_loaded_past_its_rate_keeps_the_pin_and_stays_live() {
    let (logs, _guard) = crate::testutil::capture_logs_scoped();
    let mut rig = rig().await;
    let a_npub = rig.nodes[0].node.npub();
    let b_npub = rig.nodes[1].node.npub();
    rig.nodes[0]
        .node
        .pin_path(&b_npub, "2", None)
        .await
        .expect("A pins BLE");
    rig.nodes[1]
        .node
        .pin_path(&a_npub, "2", None)
        .await
        .expect("B pins BLE");
    rig.step(false).await;
    let pinned = Seen {
        active: ble_id(),
        ble: Some(PathState::Live),
        pinned: true,
    };
    assert_eq!(rig.seen(), pinned, "precondition: A on BLE, pinned");

    let mut timeline = Vec::new();
    let mut last = rig.seen();
    let mut changes = [0u32; 2];
    let mut rtt_max = Duration::ZERO;
    let start = rig.at();
    let refused_before = ble(&rig.nodes[0]).stats().snapshot().send_errors;
    for (phase, load, secs) in [(0, false, 3u32), (1, true, 20)] {
        for _ in 0..(secs * 1000 / STEP.as_millis() as u32) {
            rig.step(load).await;
            let now = rig.seen();
            if let Some(rtt) = rig.ble_rtt() {
                rtt_max = rtt_max.max(rtt);
            }
            if now != last {
                changes[phase] += 1;
                timeline.push(format!(
                    "t={:>6.2}s {} active={} ble={:?} pin_in_force={} ble_rtt={:?}",
                    (rig.at() - start).as_secs_f64(),
                    if load { "load" } else { "idle" },
                    now.active,
                    now.ble,
                    now.pinned,
                    rig.ble_rtt(),
                ));
                last = now;
            }
        }
        timeline.push(format!(
            "t={:>6.2}s end of {} phase",
            (rig.at() - start).as_secs_f64(),
            if load { "load" } else { "idle" }
        ));
    }
    let refused = ble(&rig.nodes[0]).stats().snapshot().send_errors - refused_before;
    println!("--- A's link to B, pinned to BLE ({LINK_BPS} bit/s), load {LOAD_BPS} bit/s ---");
    for line in &timeline {
        println!("{line}");
    }
    println!(
        "changes idle={} load={}; load frames sent={} refused={}; \
         A's BLE sends refused in all={}; path messages refused={}; max BLE rtt={:?}",
        changes[0],
        changes[1],
        rig.load_sent,
        rig.load_refused,
        refused,
        refused.saturating_sub(rig.load_refused),
        rtt_max,
    );

    let ble_field = format!("transport_id={}", ble_id());
    let suspect: Vec<String> = logs
        .lines_with("Path state changed")
        .into_iter()
        .filter(|l| l.contains(&ble_field) && l.contains("next=Some(Suspect)"))
        .map(|l| {
            crate::testutil::log_field(&l, "why")
                .unwrap_or("?")
                .to_string()
        })
        .collect();
    let unsent = logs
        .lines_with("Path message not sent")
        .into_iter()
        .filter(|l| l.contains(&ble_field))
        .count();
    println!(
        "BLE paths turned Suspect {} times, why: {:?}; path messages not sent on BLE: {}",
        suspect.len(),
        suspect,
        unsent
    );

    assert_eq!(changes[0], 0, "idle, the pin holds the link on BLE");
    assert!(
        rig.load_refused > 0,
        "the load must overrun the BLE queue, or the run shows nothing"
    );
    assert_eq!(
        changes[1], 0,
        "defect: loaded, the pin must still hold the link on BLE, Live; it flapped {} times",
        changes[1]
    );
    cleanup_nodes(&mut rig.nodes).await;
}
