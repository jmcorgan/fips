//! Claims of an already connected peer made at `max_peers` must not fill
//! the outbound handshake slots and hold back an honest redial.
//!
//! Ethernet beacons each claim a key from a fresh source MAC. While
//! admission is closed, a claim of a connected peer is still dialled, so a
//! beacon flood naming one connected peer can keep every handshake slot
//! busy; a peer that drops then finds no slot for its redial.
//!
//! Needs a real AF_PACKET socket, so every test here is `#[ignore]` and is
//! run as root inside a network namespace holding a veth pair: `CLAIM_NODE_IF`
//! (default `r17a`, the node's interface) and `CLAIM_ATTACK_IF` (default
//! `r17b`, its far end, where the beacons are sent):
//!
//! ```sh
//! sudo ip netns add r0517ns
//! sudo ip netns exec r0517ns ip link add r17a type veth peer name r17b
//! for i in lo r17a r17b; do sudo ip netns exec r0517ns ip link set "$i" up; done
//! sudo ip netns exec r0517ns <test binary> --ignored --test-threads=1 node::tests::claim_slots::
//! sudo ip netns del r0517ns
//! ```
//!
//! The timeline runs in real time at the node's 1 s tick, with the default
//! limits (256 handshake slots, 16 discovery dials per tick, 30 s handshake
//! timeout, 5 s retry base); the four tests take about four minutes.

use super::*;
use crate::config::{EthernetConfig, PeerConfig, UdpConfig};
use crate::peer::ActivePeer;
use crate::transport::ethernet::EthernetTransport;
use crate::transport::udp::UdpTransport;
use crate::transport::{TransportHandle, TransportId, packet_channel};
use std::time::Instant;

const ETHERTYPE: u16 = 0x2121;

/// Where the dropped honest peer Q is configured; inside the namespace
/// nothing answers there, so the redial is observed as its handshake leg.
const Q_ADDR: &str = "127.0.0.1:9";

/// The environment variable `name`, or `default` when unset.
fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

/// A raw AF_PACKET socket on the attacker's end of the veth, sending
/// beacons from spoofed source MACs.
struct Attacker {
    fd: i32,
    ifindex: i32,
    next: u32,
}

impl Attacker {
    /// Open the raw socket on `ifname`.
    fn open(ifname: &str) -> Self {
        let name = std::ffi::CString::new(ifname).unwrap();
        // SAFETY: plain libc socket calls with checked results.
        unsafe {
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW,
                i32::from(ETHERTYPE.to_be()),
            );
            assert!(fd >= 0, "raw socket (needs root)");
            let ifindex = libc::if_nametoindex(name.as_ptr()) as i32;
            assert!(ifindex > 0, "no interface {ifname}");
            Self {
                fd,
                ifindex,
                next: 0,
            }
        }
    }

    /// Send `count` beacons claiming `key`, each from a MAC never used before.
    fn beacons(&mut self, key: &secp256k1::XOnlyPublicKey, count: usize) {
        for _ in 0..count {
            self.next += 1;
            let n = self.next.to_be_bytes();
            let src = [0x02, 0x17, n[0], n[1], n[2], n[3]];
            let mut frame = Vec::with_capacity(64);
            frame.extend_from_slice(&[0xff; 6]);
            frame.extend_from_slice(&src);
            frame.extend_from_slice(&ETHERTYPE.to_be_bytes());
            frame.push(0x01); // beacon frame type
            frame.push(0x01); // beacon version
            frame.extend_from_slice(&key.serialize());
            frame.resize(64, 0);
            // SAFETY: sockaddr_ll is plain data; the frame outlives the call.
            unsafe {
                let mut sll: libc::sockaddr_ll = std::mem::zeroed();
                sll.sll_family = libc::AF_PACKET as u16;
                sll.sll_protocol = ETHERTYPE.to_be();
                sll.sll_ifindex = self.ifindex;
                sll.sll_halen = 6;
                sll.sll_addr[..6].copy_from_slice(&[0xff; 6]);
                let sent = libc::sendto(
                    self.fd,
                    frame.as_ptr().cast(),
                    frame.len(),
                    0,
                    (&sll as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of::<libc::sockaddr_ll>() as u32,
                );
                assert_eq!(sent, frame.len() as isize, "beacon send");
            }
        }
    }
}

impl Drop for Attacker {
    fn drop(&mut self) {
        // SAFETY: closing the fd this struct opened.
        unsafe {
            libc::close(self.fd);
        }
    }
}

/// The victim: max_peers 2, peered with P and with the configured peer Q,
/// an Ethernet transport (listen, auto_connect) and a loopback UDP transport
/// for Q's configured address.
struct Victim {
    node: Node,
    p: PeerIdentity,
    q: NodeAddr,
    udp: TransportId,
    _rx: crate::transport::PacketRx,
}

/// Build the [`Victim`] with admission closed at its peer limit.
async fn victim() -> Victim {
    let q_identity = Identity::generate();
    let q = PeerIdentity::from_pubkey(q_identity.pubkey());
    let p = PeerIdentity::from_pubkey(Identity::generate().pubkey());

    let mut config = Config::new();
    config.node.limits.max_peers = 2;
    config
        .peers
        .push(PeerConfig::new(q_identity.npub(), "udp", Q_ADDR));
    let mut node = Node::new(config).unwrap();
    let (packet_tx, packet_rx) = packet_channel(8192);
    node.supervisor.packet_tx = Some(packet_tx.clone());
    node.supervisor.state = NodeState::Running;

    let eth_id = TransportId::new(1);
    let mut eth = EthernetTransport::new(
        eth_id,
        None,
        EthernetConfig {
            interface: env_or("CLAIM_NODE_IF", "r17a"),
            listen: Some(true),
            announce: Some(false),
            auto_connect: Some(true),
            accept_connections: Some(true),
            ..Default::default()
        },
        packet_tx.clone(),
    );
    eth.start_async()
        .await
        .expect("ethernet start (needs root in the netns)");
    node.transports
        .insert(eth_id, TransportHandle::Ethernet(eth));

    let udp = TransportId::new(2);
    let mut transport = UdpTransport::new(
        udp,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1280),
            ..Default::default()
        },
        packet_tx,
    );
    transport.start_async().await.unwrap();
    node.transports.insert(udp, TransportHandle::Udp(transport));

    node.peers
        .raw()
        .insert(*p.node_addr(), ActivePeer::new(p, LinkId::new(900_001), 0));
    node.peers
        .raw()
        .insert(*q.node_addr(), ActivePeer::new(q, LinkId::new(900_002), 0));
    assert!(
        !node.outbound_admission_check(),
        "admission closed at max_peers"
    );

    Victim {
        node,
        p,
        q: *q.node_addr(),
        udp,
        _rx: packet_rx,
    }
}

impl Victim {
    /// Whether Q's redial leg to its configured address is in flight.
    fn q_dialled(&self) -> bool {
        let at = TransportAddr::from_string(Q_ADDR);
        self.node
            .is_connecting_to_peer_on_path(&self.q, self.udp, &at)
    }

    /// Outbound handshake slots still free.
    fn slots(&self) -> usize {
        self.node.build_peering_budget().handshake_slots
    }

    /// Dials in flight expecting P, claims and addressed dials alike.
    fn legs_for_p(&self) -> usize {
        let observed = self.node.observe_peering();
        let p = self.p.node_addr();
        observed.in_flight_by_peer.get(p).copied().unwrap_or(0)
            + observed
                .claims_in_flight_by_peer
                .get(p)
                .copied()
                .unwrap_or(0)
    }

    /// Q's retry count, while a retry is scheduled for it.
    fn q_retry_count(&self) -> Option<u32> {
        self.node
            .peering
            .reconciler
            .retry_pending
            .get(&self.q)
            .map(|state| state.retry_count)
    }

    /// One node tick in the rx loop's order (timeouts, timers, retries,
    /// then transport discovery), with the attacker's beacons for this tick
    /// sent before discovery drains them. Returns whether Q's redial leg
    /// exists after the retry step.
    async fn tick(&mut self, attacker: &mut Attacker, beacons: usize) -> bool {
        let start = Instant::now();
        let now = Node::interval_ms();
        self.node.check_timeouts().await;
        self.node.drive_peer_timers(now).await;
        self.node.process_pending_retries(Node::peering_now()).await;
        let q = self.q_dialled();
        if beacons > 0 {
            let key = self.p.pubkey();
            attacker.beacons(&key, beacons);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        self.node.poll_transport_discovery().await;
        let rest = std::time::Duration::from_secs(1).saturating_sub(start.elapsed());
        tokio::time::sleep(rest).await;
        q
    }

    /// Stop the victim's transports.
    async fn stop(mut self) {
        for transport in self.node.transports.values_mut() {
            transport.stop().await.ok();
        }
    }
}

/// When the claims run.
#[derive(Clone, Copy, PartialEq, Debug)]
enum Claims {
    /// None at all: the control.
    None,
    /// 16 a tick before Q drops, none after.
    StopAtDrop,
    /// 16 a tick throughout.
    Continue,
}

/// Fill phase, then drop Q and tick until its redial leg appears (or 90 s).
/// Returns the seconds from the drop to Q's redial.
async fn redial_delay(claims: Claims) -> Option<u64> {
    redial_delay_with(claims, 17, 90).await
}

/// [`redial_delay`] with the fill ticks before the drop and the post-drop
/// window chosen.
async fn redial_delay_with(claims: Claims, pre: usize, window: usize) -> Option<u64> {
    let mut v = victim().await;
    let mut attacker = Attacker::open(&env_or("CLAIM_ATTACK_IF", "r17b"));
    let per_tick = |phase_on: bool| if phase_on { 16 } else { 0 };

    for t in 0..pre {
        v.tick(&mut attacker, per_tick(claims != Claims::None))
            .await;
        println!(
            "CLAIM-SLOTS {claims:?} pre-drop tick {t:2}: handshake_slots={} legs_claiming_P={}",
            v.slots(),
            v.legs_for_p()
        );
    }

    // Q drops as a Disconnect does: removed, then the reconnect reflex.
    v.node.remove_active_peer(&v.q.clone());
    v.node.note_link_dead(v.q, Node::peering_now());
    let dropped = Instant::now();
    println!(
        "CLAIM-SLOTS {claims:?} Q dropped: handshake_slots={} legs_claiming_P={} admission_ok={}",
        v.slots(),
        v.legs_for_p(),
        v.node.outbound_admission_check()
    );

    let mut delay = None;
    for t in 0..window {
        let on = claims == Claims::Continue;
        // The retry step runs at the start of the tick.
        let at = dropped.elapsed().as_secs();
        let q = v.tick(&mut attacker, per_tick(on)).await;
        println!(
            "CLAIM-SLOTS {claims:?} post-drop tick {t:2} (retry step at +{at:>2}s): Q_redial_leg={q} handshake_slots={} legs_claiming_P={} Q_retry_count={:?}",
            v.slots(),
            v.legs_for_p(),
            v.q_retry_count()
        );
        if q {
            delay = Some(at);
            break;
        }
    }
    println!("CLAIM-SLOTS {claims:?} RESULT redial_after_drop_s={delay:?}");
    v.stop().await;
    delay
}

/// Control: with no claims, Q is redialled on its first due retry (the 5 s
/// base backoff).
#[tokio::test]
#[ignore = "needs root in a netns with a veth pair; see the module comment"]
async fn a_dropped_peer_is_redialled_on_its_first_retry_when_no_claims_are_made() {
    let delay = redial_delay(Claims::None).await;
    assert!(
        matches!(delay, Some(d) if d <= 6),
        "control redial at {delay:?}"
    );
}

/// Claims of connected peer P made while admission is closed must not hold
/// back Q's redial: it is due on its first retry, as in the control.
#[tokio::test]
#[ignore = "needs root in a netns with a veth pair; see the module comment"]
async fn a_dropped_peer_is_redialled_on_its_first_retry_after_claims_of_a_connected_peer_stop_at_the_drop()
 {
    let delay = redial_delay(Claims::StopAtDrop).await;
    assert!(
        matches!(delay, Some(d) if d <= 6),
        "claims of a connected peer made at max_peers delay the redial of a dropped \
         peer to {delay:?} s after the drop"
    );
}

/// As above, with the claims continuing after the drop.
#[tokio::test]
#[ignore = "needs root in a netns with a veth pair; see the module comment"]
async fn a_dropped_peer_is_redialled_on_its_first_retry_while_claims_of_a_connected_peer_continue()
{
    let delay = redial_delay(Claims::Continue).await;
    assert!(
        matches!(delay, Some(d) if d <= 6),
        "claims of a connected peer made at max_peers delay the redial of a dropped \
         peer to {delay:?} s after the drop"
    );
}

/// Claims continue and Q drops after 11 fill ticks, so without a per-key
/// bound its first retry (+5 s) meets full slots and its second (+15 s)
/// falls in the gap before the first claims time out (about +19 s).
#[tokio::test]
#[ignore = "needs root in a netns with a veth pair; see the module comment"]
async fn a_dropped_peer_is_redialled_on_its_first_retry_when_its_retries_fall_between_slot_releases()
 {
    let delay = redial_delay_with(Claims::Continue, 11, 300).await;
    assert!(
        matches!(delay, Some(d) if d <= 6),
        "claims of a connected peer made at max_peers delay the redial of a dropped \
         peer to {delay:?} s after the drop"
    );
}
