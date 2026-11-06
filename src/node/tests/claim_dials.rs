//! Dials made because a transport neighbour claimed a key, beside the other
//! paths to the same node.
//!
//! A BLE or Ethernet neighbour's key claim is unproven until its handshake
//! completes, so a leg dialled on one must not hold back the node's
//! configured address or its LAN advert. The claim links use MockBleIo; a
//! LAN advert is dialled over a loopback UDP transport.

use super::ble::{
    base_config, ble_addr, inject_claim, larger_second, make_test_node_ble_with, pooled_at, until,
};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::config::BleConfig;
use crate::transport::ble::io::MockBleStream;
use crate::transport::{TransportHandle, TransportId, packet_channel};

/// Node 1 (BLE `auto_connect`) and node 0, ordered so node 1 holds the larger
/// key and admits inbound links claiming node 0. Node 1 is running, so its
/// opportunistic layer dials.
async fn claim_pair() -> Vec<TestNode> {
    let auto = BleConfig {
        auto_connect: Some(true),
        ..base_config()
    };
    let mut nodes = vec![
        make_test_node_ble_with(1, auto.clone()).await,
        make_test_node_ble_with(2, auto).await,
    ];
    larger_second(&mut nodes);
    nodes[1].node.supervisor.state = NodeState::Running;
    nodes
}

/// Hand node 1 `claims` unanswered BLE links claiming node 0 and let the
/// opportunistic layer dial them. With `as_legs`, the next tick's
/// `poll_pending_connects` is run so each dial is a handshake leg rather
/// than a pending BLE connect. The remote ends are returned and must be
/// kept alive, or the links close.
async fn dial_claims(nodes: &mut [TestNode], claims: u8, as_legs: bool) -> Vec<MockBleStream> {
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let n0 = *nodes[0].node.node_addr();
    let ble_tid = nodes[1].transport_id;
    let mut held = Vec::new();
    for n in 20..20 + claims {
        let at = ble_addr(n).to_transport_addr();
        held.push(inject_claim(nodes, 1, &ble_addr(n), key_0).await);
        assert!(
            until(|| pooled_at(&nodes[1], &at)).await,
            "claim {n} pooled"
        );
    }
    if claims == 0 {
        return held;
    }
    nodes[1].node.poll_transport_discovery().await;
    if as_legs {
        assert!(until(|| !nodes[1].node.peering.pending_connects.is_empty()).await);
        for _ in 0..50 {
            nodes[1].node.poll_pending_connects().await;
            if nodes[1].node.peering.pending_connects.is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            nodes[1].node.peering.pending_connects.is_empty(),
            "every claim dial became a handshake leg"
        );
    }
    for n in 20..20 + claims {
        let at = ble_addr(n).to_transport_addr();
        assert!(
            nodes[1]
                .node
                .is_connecting_to_peer_on_path(&n0, ble_tid, &at),
            "node 1 dials claim link {n} for node 0"
        );
    }
    held
}

// ============================================================================
// What the reconciler observes
// ============================================================================

/// A handshake leg dialled on a claim of node 0 is not one of node 0's
/// in-flight dials as the reconciler's other-path gates see them.
#[tokio::test]
async fn a_claim_leg_is_left_out_of_the_in_flight_dials_other_paths_wait_for() {
    let mut nodes = claim_pair().await;
    let n0 = *nodes[0].node.node_addr();
    let held = dial_claims(&mut nodes, 1, true).await;
    let observed = nodes[1].node.observe_peering();
    drop(held);
    cleanup_nodes(&mut nodes).await;
    assert!(
        !observed.connecting.contains(&n0),
        "a claim leg marks node 0 as connecting"
    );
    assert_eq!(
        observed.in_flight_by_peer.get(&n0),
        None,
        "a claim leg counts against node 0's per-peer cap"
    );
    assert_eq!(
        observed.claims_in_flight_by_peer.get(&n0),
        Some(&1),
        "the claim leg is counted among node 0's claims"
    );
}

// ============================================================================
// The configured address
// ============================================================================

/// Node 1 with node 0 configured at node 0's genuine BLE address, and
/// `claims` unanswered links claiming node 0 dialled by the opportunistic
/// layer first (as handshake legs when `as_legs`). Returns whether node 1
/// dials node 0's configured address.
async fn configured_peer_dialled_beside(claims: u8, as_legs: bool) -> bool {
    use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
    let mut nodes = claim_pair().await;
    let n0 = *nodes[0].node.node_addr();
    let tid = nodes[1].transport_id;
    let held = dial_claims(&mut nodes, claims, as_legs).await;

    let genuine = nodes[0].addr.clone();
    let config = PeerConfig {
        npub: nodes[0].node.identity().npub(),
        alias: None,
        addresses: vec![PeerAddress::new("ble", genuine.as_str().unwrap())],
        connect_policy: ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    let _ = nodes[1].node.initiate_peer_connection(&config).await;
    let dialled = nodes[1]
        .node
        .is_connecting_to_peer_on_path(&n0, tid, &genuine);
    drop(held);
    cleanup_nodes(&mut nodes).await;
    dialled
}

#[tokio::test]
async fn a_configured_peer_is_dialled_at_its_configured_address_when_no_claim_is_in_flight() {
    assert!(configured_peer_dialled_beside(0, false).await);
}

#[tokio::test]
async fn a_configured_peer_is_dialled_while_one_link_claiming_it_is_connecting() {
    assert!(
        configured_peer_dialled_beside(1, false).await,
        "one unanswered link claiming the configured peer stops node 1 dialling \
         the peer's configured address"
    );
}

#[tokio::test]
async fn a_configured_peer_is_dialled_while_four_links_claiming_it_are_connecting() {
    assert!(
        configured_peer_dialled_beside(4, false).await,
        "four unanswered links claiming the configured peer stop node 1 dialling \
         the peer's configured address"
    );
}

#[tokio::test]
async fn a_configured_peer_is_dialled_while_a_handshake_claiming_it_is_unanswered() {
    assert!(
        configured_peer_dialled_beside(1, true).await,
        "one unanswered handshake on a link claiming the configured peer stops \
         node 1 dialling the peer's configured address"
    );
}

// ============================================================================
// The LAN advert
// ============================================================================

/// The interface index the LAN tests' prefix and advert use.
const LAN_IF: u32 = 1;

/// The LAN address node 0 is advertised at.
const LAN_ADDR: &str = "127.0.0.1:9";

/// 127.0.0.1/32 on [`LAN_IF`].
fn loopback_prefix() -> crate::utils::onlink::OnLinkPrefixes {
    crate::utils::onlink::OnLinkPrefixes::from_indexed([(
        "127.0.0.1".parse().unwrap(),
        32,
        Some(LAN_IF),
    )])
}

/// What a LAN test holds: the nodes, node 0's address, node 1's UDP
/// transport, the held claim streams and the UDP packet receiver.
struct LanSetup {
    nodes: Vec<TestNode>,
    n0: NodeAddr,
    udp: TransportId,
    held: Vec<MockBleStream>,
    _udp_rx: crate::transport::PacketRx,
}

/// Node 1 runs BLE with `auto_connect` and a loopback UDP transport. It is
/// handed `claims` unanswered BLE links claiming node 0, dials them from the
/// opportunistic layer and turns them into handshake legs, then receives one
/// honest mDNS advert for node 0 at [`LAN_ADDR`].
async fn lan_setup(claims: u8) -> LanSetup {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;
    let mut nodes = claim_pair().await;
    let n0 = *nodes[0].node.node_addr();

    let udp = TransportId::new(2);
    let (udp_tx, udp_rx) = packet_channel(1024);
    let mut transport = UdpTransport::new(
        udp,
        None,
        UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1280),
            ..Default::default()
        },
        udp_tx,
    );
    transport.start_async().await.unwrap();
    nodes[1]
        .node
        .transports
        .insert(udp, TransportHandle::Udp(transport));

    let held = dial_claims(&mut nodes, claims, true).await;

    let advert = crate::mdns::LanEvent::Discovered(crate::mdns::LanDiscoveredPeer {
        npub: nodes[0].node.identity().npub(),
        scope: None,
        addr: LAN_ADDR.parse().unwrap(),
        interfaces: vec![LAN_IF],
        observed_at: std::time::Instant::now(),
    });
    nodes[1]
        .node
        .handle_lan_events(vec![advert], &loopback_prefix())
        .await;
    LanSetup {
        nodes,
        n0,
        udp,
        held,
        _udp_rx: udp_rx,
    }
}

impl LanSetup {
    /// Whether node 1 is dialling node 0 at its advertised LAN address.
    fn lan_dialled(&self) -> bool {
        let at = crate::transport::TransportAddr::from_string(LAN_ADDR);
        self.nodes[1]
            .node
            .is_connecting_to_peer_on_path(&self.n0, self.udp, &at)
    }

    /// Reap node 1's outbound handshake legs as their 30 s timeout does.
    async fn time_out_claims(&mut self) {
        let later = Node::interval_ms() + 31_000;
        self.nodes[1].node.drive_peer_timers(later).await;
    }

    async fn finish(mut self) {
        drop(std::mem::take(&mut self.held));
        for transport in self.nodes[1].node.transports.values_mut() {
            transport.stop().await.ok();
        }
        cleanup_nodes(&mut self.nodes).await;
    }
}

/// Control: with no claim in flight the honest advert is dialled at once.
#[tokio::test]
async fn a_lan_candidate_is_dialled_when_no_claim_is_in_flight() {
    let lan = lan_setup(0).await;
    let dialled = lan.lan_dialled();
    lan.finish().await;
    assert!(dialled);
}

/// One unanswered handshake on a BLE link claiming node 0 must not stop
/// node 1 dialling node 0's honest LAN advert.
#[tokio::test]
async fn a_lan_candidate_is_dialled_while_a_handshake_claiming_its_node_is_unanswered() {
    let lan = lan_setup(1).await;
    let dialled = lan.lan_dialled();
    lan.finish().await;
    assert!(
        dialled,
        "one unanswered link claiming node 0 stops node 1 dialling node 0's LAN advert"
    );
}

/// However the first pass goes, the held candidate is dialled at the latest
/// on the first LAN pass after the claim's handshake times out.
#[tokio::test]
async fn a_lan_candidate_is_dialled_at_the_latest_once_the_claim_times_out() {
    let mut lan = lan_setup(1).await;
    let before = lan.lan_dialled();
    lan.time_out_claims().await;
    lan.nodes[1].node.dial_pending_lan(&loopback_prefix()).await;
    let after = lan.lan_dialled();
    lan.finish().await;
    assert!(
        before || after,
        "the held candidate is dialled at the latest on the first LAN pass after the claim is gone"
    );
}

/// A claim of node 0 kept in flight for the candidate's whole 600 s life
/// (one leg held here; an attacker would re-arm a fresh one every 30 s)
/// must not lose node 0's honest LAN advert, which mDNS does not deliver
/// again.
#[tokio::test]
async fn a_lan_candidate_is_dialled_before_it_expires_while_a_claim_is_kept_in_flight() {
    let mut lan = lan_setup(1).await;
    let mut ever_dialled = lan.lan_dialled();
    let start = lan.nodes[1].node.uptime().as_millis() as u64;
    // One LAN tick a minute for ten minutes, the claim kept in flight.
    for minute in 1..=10u64 {
        lan.nodes[1]
            .node
            .lan_tick(Vec::new(), start + minute * 60_000 + 1)
            .await;
        ever_dialled |= lan.lan_dialled();
    }
    lan.time_out_claims().await;
    lan.nodes[1].node.dial_pending_lan(&loopback_prefix()).await;
    ever_dialled |= lan.lan_dialled();
    lan.finish().await;
    assert!(
        ever_dialled,
        "a claim kept in flight for 600 s expires node 0's LAN candidate undialled"
    );
}

// ============================================================================
// Where a dial came from
// ============================================================================

/// The origin of node 1's single dial to node 0, as its pending connect and
/// then its handshake leg record it.
async fn origins_across_the_hand_off(
    nodes: &mut [TestNode],
) -> (
    crate::peer::machine::DialOrigin,
    crate::peer::machine::DialOrigin,
) {
    let n0 = *nodes[0].node.node_addr();
    assert!(until(|| !nodes[1].node.peering.pending_connects.is_empty()).await);
    let pending = &nodes[1].node.peering.pending_connects;
    assert_eq!(pending.len(), 1, "one dial to node 0");
    let at_connect = pending[0].origin;
    assert_eq!(
        nodes[1].node.peer_machines[&pending[0].link_id].dial_origin(),
        at_connect,
        "the pending connect carries its machine's origin"
    );
    for _ in 0..50 {
        nodes[1].node.poll_pending_connects().await;
        if nodes[1].node.peering.pending_connects.is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let legs: Vec<_> = nodes[1]
        .node
        .connections()
        .filter(|(_, machine)| {
            machine
                .conn_expected_identity()
                .is_some_and(|id| *id.node_addr() == n0)
        })
        .map(|(_, machine)| machine.dial_origin())
        .collect();
    assert_eq!(legs.len(), 1, "the dial became one handshake leg");
    (at_connect, legs[0])
}

/// A dial made on a transport neighbour's claim is marked as one from its
/// pending BLE connect through to its handshake leg.
#[tokio::test]
async fn a_claim_dial_keeps_its_origin_from_pending_connect_to_handshake_leg() {
    use crate::peer::machine::DialOrigin;
    let mut nodes = claim_pair().await;
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let at = ble_addr(20).to_transport_addr();
    let held = inject_claim(&nodes, 1, &ble_addr(20), key_0).await;
    assert!(until(|| pooled_at(&nodes[1], &at)).await);
    nodes[1].node.poll_transport_discovery().await;
    let origins = origins_across_the_hand_off(&mut nodes).await;
    drop(held);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(
        origins,
        (DialOrigin::NeighbourClaim, DialOrigin::NeighbourClaim)
    );
}

/// A configured dial over the same transport, to an address where a link
/// is already open, is not marked as a claim.
#[tokio::test]
async fn a_configured_dial_is_not_marked_as_a_claim() {
    use crate::config::{ConnectPolicy, PeerAddress, PeerConfig};
    use crate::peer::machine::DialOrigin;
    let mut nodes = claim_pair().await;
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let at = ble_addr(20).to_transport_addr();
    let held = inject_claim(&nodes, 1, &ble_addr(20), key_0).await;
    assert!(until(|| pooled_at(&nodes[1], &at)).await);
    let config = PeerConfig {
        npub: nodes[0].node.identity().npub(),
        alias: None,
        addresses: vec![PeerAddress::new("ble", at.as_str().unwrap())],
        connect_policy: ConnectPolicy::AutoConnect,
        auto_reconnect: true,
        via_nostr: false,
    };
    nodes[1]
        .node
        .initiate_peer_connection(&config)
        .await
        .unwrap();
    let origins = origins_across_the_hand_off(&mut nodes).await;
    drop(held);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(origins, (DialOrigin::Addressed, DialOrigin::Addressed));
}

// ============================================================================
// An honest node reached by a claim leg and an addressed leg at once
// ============================================================================

/// Both legs to an honest node, one dialled as a neighbour claim and one to
/// an address held for it, on two paths to the same node, leave it as one
/// peer. Whichever leg loses is left to its handshake timeout, as with two
/// addressed legs today, and reaping it keeps the peer.
#[tokio::test]
async fn an_honest_peer_reached_by_a_claim_leg_and_an_addressed_leg_ends_as_one_peer() {
    use super::spanning_tree::{add_loopback_alias, drain_all_packets, make_test_node};
    use crate::peer::machine::DialOrigin;
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    let tid = nodes[1].transport_id;
    let n0 = *nodes[0].node.node_addr();
    let n1 = *nodes[1].node.node_addr();
    let id0 = PeerIdentity::from_pubkey_full(nodes[0].node.identity().pubkey_full());
    let claimed_at = nodes[0].addr.clone();
    let addressed_at = add_loopback_alias(&nodes[0].addr, nodes[0].transport_id);

    nodes[1]
        .node
        .initiate_connection_from(tid, claimed_at, id0, DialOrigin::NeighbourClaim)
        .await
        .unwrap();
    nodes[1]
        .node
        .initiate_connection(tid, addressed_at, id0)
        .await
        .unwrap();
    assert_eq!(
        nodes[1].node.connections().count(),
        2,
        "both legs are in flight at once"
    );

    drain_all_packets(&mut nodes, false).await;
    let peers_1: Vec<NodeAddr> = nodes[1].node.peers.keys().copied().collect();
    let peers_0: Vec<NodeAddr> = nodes[0].node.peers.keys().copied().collect();
    let later = Node::interval_ms() + 31_000;
    nodes[1].node.drive_peer_timers(later).await;
    let legs_after_timeout = nodes[1].node.connections().count();
    let still_peered = nodes[1].node.peers.contains_key(&n0);
    cleanup_nodes(&mut nodes).await;
    assert_eq!(peers_1, vec![n0], "node 1 holds node 0 as its one peer");
    assert_eq!(peers_0, vec![n1], "node 0 holds node 1 as its one peer");
    assert_eq!(
        legs_after_timeout, 0,
        "a leg outlives its handshake timeout"
    );
    assert!(still_peered, "reaping the losing leg drops the peer");
}
