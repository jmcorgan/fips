//! BLE transport integration tests.
//!
//! Tests that the BLE transport works end-to-end at the node level:
//! handshake, spanning tree convergence, mixed-transport routing.
//! All tests use MockBleIo (in-memory channels, no hardware needed).

use super::*;
use crate::config::BleConfig;
use crate::transport::ble::BleTransport;
use crate::transport::ble::addr::BleAddr;
use crate::transport::ble::io::{MockBleIo, MockBleStream};
use crate::transport::{Transport, TransportHandle, TransportId, packet_channel};
use spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, initiate_handshake, verify_tree_convergence,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

/// Generate a deterministic BLE address for test node `n`.
fn ble_addr(n: u8) -> BleAddr {
    BleAddr {
        adapter: "hci0".to_string(),
        device: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, n],
    }
}

/// A pre-connected stream bank for MockBleIo connect handlers.
///
/// When a connect handler fires, it looks up the target address in this
/// bank and returns the pre-created stream. The peer end should be
/// injected into the target node's acceptor separately.
type StreamBank = Arc<StdMutex<HashMap<String, MockBleStream>>>;

/// Create a test node with a BLE transport backed by MockBleIo.
///
/// Returns the TestNode and its MockBleIo (via Arc inside the transport)
/// for test injection of connections and scan results.
async fn make_test_node_ble(node_num: u8) -> TestNode {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let addr = ble_addr(node_num);

    let config = BleConfig {
        adapter: Some("hci0".to_string()),
        mtu: Some(2048),
        accept_connections: Some(true),
        scan: Some(false),      // no auto-scan in tests
        advertise: Some(false), // no advertising in tests
        auto_connect: Some(false),
        ..Default::default()
    };

    let io = MockBleIo::new("hci0", addr.clone());
    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = BleTransport::new(transport_id, None, config, io, packet_tx);
    transport.start_async().await.unwrap();

    let ta = addr.to_transport_addr();

    node.transports
        .insert(transport_id, TransportHandle::Ble(transport));

    TestNode {
        node,
        transport_id,
        packet_rx: spanning_tree::bridge_to_unbounded(packet_rx),
        addr: ta,
    }
}

/// Extract the BleAddr from a TestNode's TransportAddr.
fn node_ble_addr(node: &TestNode) -> BleAddr {
    BleAddr::parse(node.addr.as_str().unwrap()).unwrap()
}

/// Wire a unidirectional BLE connection from node `i` to node `j`.
///
/// Creates a MockBleStream pair, deposits one end in a stream bank for
/// node i's connect handler, and injects the other end into node j's
/// accept loop. Must be called after `make_test_node_ble()` and before
/// `initiate_handshake()`.
async fn wire_ble_connection(nodes: &[TestNode], i: usize, j: usize, bank: &StreamBank) {
    let addr_i = node_ble_addr(&nodes[i]);
    let addr_j = node_ble_addr(&nodes[j]);

    let (stream_i, stream_j) = MockBleStream::pair(addr_j.clone(), addr_i.clone(), 2048);

    // Store stream_i in the bank keyed by node j's address string.
    // When node i connects to node j, the handler returns this stream.
    let key = nodes[j].addr.to_string();
    bank.lock().unwrap().insert(key, stream_i);

    // Inject stream_j into node j's accept loop so it sees the inbound.
    let transport_j = nodes[j]
        .node
        .transports
        .get(&nodes[j].transport_id)
        .unwrap();
    match transport_j {
        TransportHandle::Ble(t) => {
            t.io().inject_inbound(stream_j).await;
        }
        _ => panic!("expected BLE transport"),
    }
}

/// Install a connect handler on node `i` that draws from the stream bank.
fn install_connect_handler(nodes: &[TestNode], i: usize, bank: &StreamBank) {
    let bank = Arc::clone(bank);
    let transport_i = nodes[i]
        .node
        .transports
        .get(&nodes[i].transport_id)
        .unwrap();
    match transport_i {
        TransportHandle::Ble(t) => {
            t.io().set_connect_handler(move |addr, _psm| {
                let key = addr.to_transport_addr().to_string();
                let mut map = bank.lock().unwrap();
                match map.remove(&key) {
                    Some(stream) => Ok(stream),
                    None => Err(crate::transport::TransportError::ConnectionRefused),
                }
            });
        }
        _ => panic!("expected BLE transport"),
    }
}

/// Establish a BLE connection from node `i` to node `j` via connect_async.
///
/// Must be called after `wire_ble_connection` and `install_connect_handler`.
/// BLE send_async fails fast if no connection exists, so connections must
/// be pre-established before initiating handshakes.
async fn establish_ble_connection(nodes: &[TestNode], i: usize, j: usize) {
    let transport = nodes[i]
        .node
        .transports
        .get(&nodes[i].transport_id)
        .unwrap();
    transport.connect(&nodes[j].addr).await.unwrap();
    // Let the background connect task complete
    tokio::task::yield_now().await;
}

/// Two BLE nodes complete a Noise handshake and establish bidirectional peering.
#[tokio::test]
async fn test_ble_two_node_handshake() {
    let mut nodes = vec![make_test_node_ble(1).await, make_test_node_ble(2).await];

    // Wire connection: node 0 → node 1
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    wire_ble_connection(&nodes, 0, 1, &bank).await;
    install_connect_handler(&nodes, 0, &bank);
    establish_ble_connection(&nodes, 0, 1).await;

    // Initiate handshake
    initiate_handshake(&mut nodes, 0, 1).await;

    // Drain all packets (handshake + TreeAnnounce exchange)
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "should have processed packets");

    // Verify bidirectional peering
    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "node 0 should have node 1 as peer"
    );
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 should have node 0 as peer"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Three BLE nodes in a chain converge to a consistent spanning tree.
#[tokio::test]
async fn test_ble_three_node_chain() {
    let mut nodes = vec![
        make_test_node_ble(1).await,
        make_test_node_ble(2).await,
        make_test_node_ble(3).await,
    ];

    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));

    // Wire: 0 -- 1 -- 2
    wire_ble_connection(&nodes, 0, 1, &bank).await;
    wire_ble_connection(&nodes, 1, 2, &bank).await;
    install_connect_handler(&nodes, 0, &bank);
    install_connect_handler(&nodes, 1, &bank);
    establish_ble_connection(&nodes, 0, 1).await;
    establish_ble_connection(&nodes, 1, 2).await;

    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 2).await;

    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "should have processed packets");

    // Verify spanning tree convergence
    verify_tree_convergence(&nodes);

    // Verify correct root
    let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
    for tn in &nodes {
        assert_eq!(*tn.node.tree_state().root(), expected_root);
    }

    // Verify peer counts
    assert_eq!(nodes[0].node.peer_count(), 1);
    assert_eq!(nodes[1].node.peer_count(), 2);
    assert_eq!(nodes[2].node.peer_count(), 1);

    // Verify bloom filter reachability: node 0 → node 2
    let addr_2 = *nodes[2].node.node_addr();
    let reaches = nodes[0].node.peers().any(|p| p.may_reach(&addr_2));
    assert!(reaches, "node 0 should see node 2 as reachable");

    cleanup_nodes(&mut nodes).await;
}

/// Mixed transport: UDP and BLE nodes coexist in independent components.
#[tokio::test]
async fn test_ble_mixed_transport() {
    use spanning_tree::{make_test_node, verify_tree_convergence_components};

    let udp_0 = make_test_node().await;
    let udp_1 = make_test_node().await;
    let ble_0 = make_test_node_ble(1).await;
    let ble_1 = make_test_node_ble(2).await;

    let mut nodes = vec![udp_0, udp_1, ble_0, ble_1];

    // Wire BLE pair
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    wire_ble_connection(&nodes, 2, 3, &bank).await;
    install_connect_handler(&nodes, 2, &bank);
    establish_ble_connection(&nodes, 2, 3).await;

    // Handshake within each component
    initiate_handshake(&mut nodes, 0, 1).await; // UDP pair
    initiate_handshake(&mut nodes, 2, 3).await; // BLE pair

    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    // Verify each component converges independently
    verify_tree_convergence_components(&nodes, &[vec![0, 1], vec![2, 3]]);

    // BLE component has its own root
    let ble_root = std::cmp::min(*nodes[2].node.node_addr(), *nodes[3].node.node_addr());
    assert_eq!(*nodes[2].node.tree_state().root(), ble_root);
    assert_eq!(*nodes[3].node.tree_state().root(), ble_root);

    cleanup_nodes(&mut nodes).await;
}

/// BLE scan+probe loop discovers peers via adapter scan events.
#[tokio::test(start_paused = true)]
async fn test_ble_discovery() {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let addr = ble_addr(1);

    // Enable scanning so the scan+probe loop runs
    let config = BleConfig {
        adapter: Some("hci0".to_string()),
        mtu: Some(2048),
        accept_connections: Some(true),
        scan: Some(true),
        advertise: Some(false),
        auto_connect: Some(false),
        ..Default::default()
    };

    let io = MockBleIo::new("hci0", addr.clone());
    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = BleTransport::new(transport_id, None, config, io, packet_tx);
    transport.start_async().await.unwrap();

    // Inject scan results via the I/O mock
    transport.io().inject_scan_result(ble_addr(2)).await;
    transport.io().inject_scan_result(ble_addr(3)).await;

    // Let scan_probe_loop pick up results and schedule jitter
    tokio::task::yield_now().await;
    // Advance past max jitter so probes fire
    tokio::time::advance(std::time::Duration::from_secs(6)).await;
    tokio::task::yield_now().await;

    // Without pubkey set, peers appear as bare MACs in discovery buffer
    let peers = transport.discover().unwrap();
    assert_eq!(peers.len(), 2);

    let ta = addr.to_transport_addr();
    node.transports
        .insert(transport_id, TransportHandle::Ble(transport));

    let mut nodes = vec![TestNode {
        node,
        transport_id,
        packet_rx: spanning_tree::bridge_to_unbounded(packet_rx),
        addr: ta,
    }];
    cleanup_nodes(&mut nodes).await;
}

/// A stale outbound handshake leg whose connection is also an active peer's
/// must not take that peer's link down when it is reaped.
///
/// BLE pools one L2CAP link per peer address, so a handshake leg that crossed
/// an established peer's — both nodes dialling at once — sits on the very
/// connection that peer runs on. Reaping the leg by address closed it, and
/// the peer with it.
#[tokio::test]
async fn reaping_a_handshake_leg_keeps_the_peer_link_it_shares() {
    let mut nodes = vec![make_test_node_ble(1).await, make_test_node_ble(2).await];
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    wire_ble_connection(&nodes, 0, 1, &bank).await;
    install_connect_handler(&nodes, 0, &bank);
    establish_ble_connection(&nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;

    let peer_1 = *nodes[1].node.node_addr();
    let transport_id = nodes[0].transport_id;
    let peer_addr = nodes[1].addr.clone();
    assert!(nodes[0].node.get_peer(&peer_1).is_some(), "peered");
    let connected = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .transports
            .get(&transport_id)
            .unwrap()
            .connection_state(&peer_addr)
            == crate::transport::ConnectionState::Connected
    };
    assert!(connected(&nodes), "the peer's BLE link is up");

    // A second, outbound handshake leg to the same peer, on the same address,
    // as a crossed dial leaves behind.
    let peer_identity = PeerIdentity::from_pubkey_full(nodes[1].node.identity().pubkey_full());
    let node = &mut nodes[0].node;
    let leg = node.allocate_link_id();
    let our_index = node.index_allocator.allocate().unwrap();
    node.seed_handshake_machine(
        HandshakeSeed::outbound(leg, peer_identity, 1000)
            .with_our_index(our_index)
            .with_transport_id(transport_id)
            .with_source_addr(peer_addr.clone()),
    )
    .unwrap();
    node.links.insert(
        leg,
        Link::connectionless(
            leg,
            transport_id,
            peer_addr.clone(),
            LinkDirection::Outbound,
            std::time::Duration::from_millis(100),
        ),
    );

    node.cleanup_stale_connection(leg, 2000).await;

    assert!(!nodes[0].node.links.contains_key(&leg), "the leg is reaped");
    assert!(
        connected(&nodes),
        "the peer's link survives the leg it shared a connection with"
    );
    assert!(nodes[0].node.get_peer(&peer_1).is_some(), "still peered");

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Claimed keys versus verified links
// ============================================================================

/// The BLE configuration every node-level test node starts from.
fn base_config() -> BleConfig {
    BleConfig {
        adapter: Some("hci0".to_string()),
        mtu: Some(2048),
        accept_connections: Some(true),
        scan: Some(false),
        advertise: Some(false),
        auto_connect: Some(false),
        ..Default::default()
    }
}

/// A BLE test node whose transport runs the pre-handshake key exchange with
/// the node's own key, as the daemon's transport does, under `config`.
async fn make_test_node_ble_with(node_num: u8, config: BleConfig) -> TestNode {
    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let addr = ble_addr(node_num);
    let io = MockBleIo::new("hci0", addr.clone());
    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = BleTransport::new(transport_id, None, config, io, packet_tx);
    transport.set_local_pubkey(node.identity().pubkey().serialize());
    transport.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Ble(transport));
    TestNode {
        node,
        transport_id,
        packet_rx: spanning_tree::bridge_to_unbounded(packet_rx),
        addr: addr.to_transport_addr(),
    }
}

/// [`make_test_node_ble_with`] under the default test configuration.
async fn make_test_node_ble_identified(node_num: u8) -> TestNode {
    make_test_node_ble_with(node_num, base_config()).await
}

/// Order two nodes so that node 1 holds the larger node address: the
/// accepting side's inbound tie-break admits only a smaller claimed key.
fn larger_second(nodes: &mut [TestNode]) {
    if nodes[0].node.node_addr() > nodes[1].node.node_addr() {
        nodes.swap(0, 1);
    }
}

/// The BLE transport of a test node.
fn ble_of(node: &TestNode) -> &BleTransport<MockBleIo> {
    match node.node.transports.get(&node.transport_id).unwrap() {
        TransportHandle::Ble(t) => t,
        _ => panic!("expected BLE transport"),
    }
}

/// Whether the node's link at `addr` is verified; `None` when none is pooled.
async fn verified_at(node: &TestNode, addr: &crate::transport::TransportAddr) -> Option<bool> {
    ble_of(node).is_verified(addr).await
}

/// Whether the node pools a link at `addr`. False while the pool lock is
/// held, so only a wait for presence may use it.
fn pooled_at(node: &TestNode, addr: &crate::transport::TransportAddr) -> bool {
    ble_of(node).connection_state_sync(addr) == crate::transport::ConnectionState::Connected
}

/// Let background tasks run until node `node` pools no link at `addr`, for at
/// most about a second. The pool lock is awaited, so a held lock cannot pass
/// for an absent link.
async fn until_unpooled(node: &TestNode, addr: &crate::transport::TransportAddr) -> bool {
    for _ in 0..200 {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        if verified_at(node, addr).await.is_none() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    false
}

/// Let background tasks run until `cond` holds, for at most about a second.
async fn until(mut cond: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        if cond() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    false
}

/// Run the remote half of the pre-handshake key exchange, claiming `pubkey`.
///
/// The exchange is `[0x00][key:32]` each way; the prefix is private to the
/// BLE transport, so it is written out here.
async fn claim_key(stream: &MockBleStream, pubkey: [u8; 32]) {
    use crate::transport::ble::io::BleStream;
    let mut msg = [0u8; 33];
    msg[1..].copy_from_slice(&pubkey);
    stream.send(&msg).await.unwrap();
    let mut buf = [0u8; 33];
    let n = stream.recv(&mut buf).await.unwrap();
    assert_eq!(n, 33);
}

/// Open an inbound link to node `i` from `from` that claims `pubkey`. The
/// remote end is returned and must be kept alive, or the link closes.
async fn inject_claim(
    nodes: &[TestNode],
    i: usize,
    from: &BleAddr,
    pubkey: [u8; 32],
) -> MockBleStream {
    let (remote, injected) = MockBleStream::pair(from.clone(), node_ble_addr(&nodes[i]), 2048);
    ble_of(&nodes[i]).io().inject_inbound(injected).await;
    claim_key(&remote, pubkey).await;
    remote
}

/// Node 0's genuine link to node 1, dialled by node 0. Node 1 keys its end by
/// its own address (see [`wire_ble_connection`]).
async fn link_genuinely(nodes: &[TestNode]) -> StreamBank {
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    wire_ble_connection(nodes, 0, 1, &bank).await;
    install_connect_handler(nodes, 0, &bank);
    establish_ble_connection(nodes, 0, 1).await;
    bank
}

/// A real msg1 from `initiator` to `responder`, built on a detached machine,
/// as a device that captured it over the air would hold it.
fn genuine_msg1(initiator: &Node, responder: &Node) -> Vec<u8> {
    use crate::proto::fmp::wire::build_msg1;
    let responder_identity = PeerIdentity::from_pubkey_full(responder.identity().pubkey_full());
    let mut machine = outbound_leg(LinkId::new(9_999), responder_identity, 1_000);
    let noise_msg1 = machine
        .start_handshake(
            initiator.identity().keypair(),
            initiator.startup_epoch(),
            1_000,
        )
        .expect("the initiator side of a real msg1 must build");
    build_msg1(SessionIndex::new(7), &noise_msg1)
}

/// A device that connects first and claims a node's key must not stop that
/// node's genuine link from being admitted and carrying the handshake.
#[tokio::test]
async fn a_ble_channel_claiming_a_peers_key_does_not_stop_that_peer_linking() {
    let mut nodes = vec![
        make_test_node_ble_identified(1).await,
        make_test_node_ble_identified(2).await,
    ];
    larger_second(&mut nodes);

    let impostor_ta = ble_addr(9).to_transport_addr();
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let _impostor = inject_claim(&nodes, 1, &ble_addr(9), key_0).await;
    assert!(
        until(|| pooled_at(&nodes[1], &impostor_ta)).await,
        "node 1 holds the impostor's link"
    );

    let _bank = link_genuinely(&nodes).await;
    let genuine_ta = nodes[1].addr.clone();
    until(|| pooled_at(&nodes[1], &genuine_ta)).await;
    assert!(
        pooled_at(&nodes[1], &genuine_ta),
        "node 1 admitted node 0's genuine link beside the impostor's"
    );

    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;

    let addr_0 = *nodes[0].node.node_addr();
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[1].node.get_peer(&addr_0).is_some(),
        "node 1 peers with node 0"
    );
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "node 0 peers with node 1"
    );
    assert_eq!(
        verified_at(&nodes[1], &impostor_ta).await,
        Some(false),
        "the impostor's link stays pooled and unverified"
    );
    assert_eq!(
        verified_at(&nodes[1], &genuine_ta).await,
        Some(true),
        "the responder's link is verified by the initiator's frames"
    );
    let dialled = nodes[1].addr.clone();
    assert_eq!(
        verified_at(&nodes[0], &dialled).await,
        Some(true),
        "the initiator's link is verified at its promotion"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A captured msg1 replayed on a link claiming its sender promotes the sender
/// there, but must not verify that link: the responder has seen nothing an
/// eavesdropper could not replay.
#[tokio::test]
async fn a_replayed_handshake_on_a_link_claiming_a_peer_does_not_verify_it() {
    let mut nodes = vec![
        make_test_node_ble_identified(1).await,
        make_test_node_ble_identified(2).await,
    ];
    larger_second(&mut nodes);
    let impostor_ta = ble_addr(9).to_transport_addr();
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let _impostor = inject_claim(&nodes, 1, &ble_addr(9), key_0).await;
    assert!(
        until(|| pooled_at(&nodes[1], &impostor_ta)).await,
        "node 1 holds the impostor's link"
    );

    let msg1 = genuine_msg1(&nodes[0].node, &nodes[1].node);
    let tid = nodes[1].transport_id;
    nodes[1]
        .node
        .handle_msg1(ReceivedPacket::with_timestamp(
            tid,
            impostor_ta.clone(),
            msg1,
            2_000,
        ))
        .await;
    let addr_0 = *nodes[0].node.node_addr();
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&addr_0)
            .and_then(|p| p.current_addr().cloned()),
        Some(impostor_ta.clone()),
        "the replay promotes node 0 on the impostor's link"
    );
    assert_eq!(
        verified_at(&nodes[1], &impostor_ta).await,
        Some(false),
        "a replayed msg1 does not verify the link it arrived on"
    );

    let _bank = link_genuinely(&nodes).await;
    let genuine_ta = nodes[1].addr.clone();
    until(|| pooled_at(&nodes[1], &genuine_ta)).await;
    assert!(
        pooled_at(&nodes[1], &genuine_ta),
        "node 1 admits node 0's genuine link beside the replayer's"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Two links between one pair, both handshakes started on the first before
/// either is processed: the pair peers, the link carrying the session is
/// verified at both ends, and the spare stays pooled and unverified.
#[tokio::test]
async fn crossed_handshakes_on_one_of_two_links_keep_the_pair_peered() {
    let mut nodes = vec![
        make_test_node_ble_identified(1).await,
        make_test_node_ble_identified(2).await,
    ];
    // Node 0 is the smaller: both links are its dials, the direction both
    // tie-breaks admit.
    larger_second(&mut nodes);
    let (a0, a1, a0x, a1x) = two_links(&nodes).await;

    // Both msg1s go out on L1 before either is processed.
    initiate_handshake(&mut nodes, 0, 1).await;
    initiate_handshake(&mut nodes, 1, 0).await;
    drain_all_packets(&mut nodes, false).await;

    let n0 = *nodes[0].node.node_addr();
    let n1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0].node.get_peer(&n1).is_some(),
        "node 0 peers with node 1"
    );
    assert!(
        nodes[1].node.get_peer(&n0).is_some(),
        "node 1 peers with node 0"
    );
    for (i, a) in [(0, &a1), (0, &a1x), (1, &a0), (1, &a0x)] {
        assert!(
            pooled_at(&nodes[i], &a.to_transport_addr()),
            "node {i} still holds {a} after the handshakes"
        );
    }
    assert_eq!(
        verified_at(&nodes[0], &a1.to_transport_addr()).await,
        Some(true)
    );
    assert_eq!(
        verified_at(&nodes[1], &a0.to_transport_addr()).await,
        Some(true)
    );
    assert_eq!(
        verified_at(&nodes[0], &a1x.to_transport_addr()).await,
        Some(false)
    );
    assert_eq!(
        verified_at(&nodes[1], &a0x.to_transport_addr()).await,
        Some(false)
    );
    cleanup_nodes(&mut nodes).await;
}

/// Two identified nodes, node 1 the larger, peered over one link node 0
/// dialled, with the link verified at node 1 by node 0's frames.
async fn peered_pair() -> Vec<TestNode> {
    let mut nodes = vec![
        make_test_node_ble_identified(1).await,
        make_test_node_ble_identified(2).await,
    ];
    larger_second(&mut nodes);
    let _bank = link_genuinely(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let n0 = *nodes[0].node.node_addr();
    assert!(
        nodes[1].node.get_peer(&n0).is_some(),
        "node 1 peers with node 0"
    );
    let link = nodes[1].addr.clone();
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        Some(true),
        "verified once node 0's frames arrive"
    );
    nodes
}

/// Hand node 1 an authenticated Heartbeat from node 0 arriving on `link`, as
/// the decrypt worker's bounce does once it has checked the frame.
async fn worker_heartbeat(
    nodes: &mut [TestNode],
    slot: crate::node::dataplane::LinkSlot,
    link: &crate::transport::TransportAddr,
    counter: u64,
) {
    let tid = nodes[1].transport_id;
    let n0 = *nodes[0].node.node_addr();
    // A 4-byte inner timestamp, then the Heartbeat message type.
    let plaintext = [0u8, 0, 0, 0, 0x51];
    nodes[1]
        .node
        .process_authentic_fmp_plaintext(
            &n0,
            slot,
            tid,
            link,
            Node::now_ms(),
            64,
            counter,
            false,
            false,
            &plaintext,
        )
        .await;
}

/// A link's protection ends when its peer leaves: after an FMP Disconnect
/// the link stays pooled but no longer verified.
#[tokio::test]
async fn a_verified_link_stops_being_protected_when_its_peer_disconnects() {
    let mut nodes = peered_pair().await;
    let n0 = *nodes[0].node.node_addr();
    let link = nodes[1].addr.clone();
    let bye = crate::proto::fmp::wire::Disconnect::new(
        crate::proto::fmp::wire::DisconnectReason::Shutdown,
    )
    .encode();
    nodes[1].node.dispatch_link_message(&n0, &bye, false).await;
    assert!(
        nodes[1].node.get_peer(&n0).is_none(),
        "node 1 dropped the peer"
    );
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        Some(false),
        "the link is still pooled but no longer verified"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The same when the peer is reaped for silence.
#[tokio::test]
async fn a_verified_link_stops_being_protected_when_its_peer_is_reaped() {
    let mut nodes = peered_pair().await;
    let n0 = *nodes[0].node.node_addr();
    let link = nodes[1].addr.clone();
    nodes[1].node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.node.link_dead_timeout_secs = 0;
        ctx.config = std::sync::Arc::new(cfg);
    });
    nodes[1].node.check_link_heartbeats().await;
    assert!(
        nodes[1].node.get_peer(&n0).is_none(),
        "node 1 reaped the peer"
    );
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        Some(false),
        "the link is still pooled but no longer verified"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Node 1's view of two links from node 0, both dialled by node 0: L1 at
/// node 1's address (seen from node 0's) and L2 at an alias (seen from
/// node 0's alias). Returns `(a0, a1, a0x, a1x)`.
async fn two_links(nodes: &[TestNode]) -> (BleAddr, BleAddr, BleAddr, BleAddr) {
    let a0 = node_ble_addr(&nodes[0]);
    let a1 = node_ble_addr(&nodes[1]);
    let a0x = ble_addr(100);
    let a1x = ble_addr(101);
    let (l1_0, l1_1) = MockBleStream::pair(a0.clone(), a1.clone(), 2048);
    let (l2_0, l2_1) = MockBleStream::pair(a0x.clone(), a1x.clone(), 2048);
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    bank.lock()
        .unwrap()
        .insert(a1.to_transport_addr().to_string(), l1_0);
    bank.lock()
        .unwrap()
        .insert(a1x.to_transport_addr().to_string(), l2_0);
    install_connect_handler(nodes, 0, &bank);
    ble_of(&nodes[1]).io().inject_inbound(l1_1).await;
    ble_of(&nodes[0])
        .connect_async(&a1.to_transport_addr())
        .await
        .unwrap();
    until(|| pooled_at(&nodes[1], &a0.to_transport_addr())).await;
    ble_of(&nodes[1]).io().inject_inbound(l2_1).await;
    ble_of(&nodes[0])
        .connect_async(&a1x.to_transport_addr())
        .await
        .unwrap();
    until(|| {
        pooled_at(&nodes[0], &a1.to_transport_addr())
            && pooled_at(&nodes[0], &a1x.to_transport_addr())
            && pooled_at(&nodes[1], &a0.to_transport_addr())
            && pooled_at(&nodes[1], &a0x.to_transport_addr())
    })
    .await;
    for (i, a) in [(0, &a1), (0, &a1x), (1, &a0), (1, &a0x)] {
        assert!(
            pooled_at(&nodes[i], &a.to_transport_addr()),
            "node {i} holds both links before any handshake ({a})"
        );
    }
    (a0, a1, a0x, a1x)
}

/// A peer that moves its traffic to another link takes its verification with
/// it: the link it left is no longer the node's.
#[tokio::test]
async fn a_peer_roaming_onto_a_second_link_moves_the_verification_with_it() {
    let mut nodes = vec![
        make_test_node_ble_identified(1).await,
        make_test_node_ble_identified(2).await,
    ];
    larger_second(&mut nodes);
    let (a0, _a1, a0x, a1x) = two_links(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let n0 = *nodes[0].node.node_addr();
    let n1 = *nodes[1].node.node_addr();
    assert_eq!(
        verified_at(&nodes[1], &a0.to_transport_addr()).await,
        Some(true)
    );

    // Node 0 moves its traffic to L2, as after a reconnect at a new address.
    let tid0 = nodes[0].transport_id;
    nodes[0]
        .node
        .get_peer_mut(&n1)
        .unwrap()
        .set_current_addr(tid0, a1x.to_transport_addr());
    nodes[0].node.send_tree_announce_to_peer(&n1).await.unwrap();
    drain_all_packets(&mut nodes, false).await;

    assert_eq!(
        nodes[1]
            .node
            .get_peer(&n0)
            .and_then(|p| p.current_addr().cloned()),
        Some(a0x.to_transport_addr()),
        "node 1 follows node 0 onto L2"
    );
    assert_eq!(
        verified_at(&nodes[1], &a0x.to_transport_addr()).await,
        Some(true),
        "the link the peer roamed onto is verified"
    );
    assert_eq!(
        verified_at(&nodes[1], &a0.to_transport_addr()).await,
        Some(false),
        "the link it left is not"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The decrypt worker's path moves the verification the same way, and marks
/// a link again when a frame arrives at an unchanged address.
#[tokio::test]
async fn an_authenticated_frame_from_the_decrypt_worker_moves_the_verification_to_its_link() {
    let mut nodes = vec![
        make_test_node_ble_identified(1).await,
        make_test_node_ble_identified(2).await,
    ];
    larger_second(&mut nodes);
    // A second link claiming node 0, admitted before anything verifies.
    let l2 = ble_addr(77).to_transport_addr();
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let _second = inject_claim(&nodes, 1, &ble_addr(77), key_0).await;
    assert!(until(|| pooled_at(&nodes[1], &l2)).await, "L2 is pooled");

    let _bank = link_genuinely(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let n0 = *nodes[0].node.node_addr();
    let l1 = nodes[1].addr.clone();
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&n0)
            .and_then(|p| p.current_addr().cloned()),
        Some(l1.clone())
    );
    assert_eq!(verified_at(&nodes[1], &l1).await, Some(true));
    assert_eq!(verified_at(&nodes[1], &l2).await, Some(false));

    use crate::node::dataplane::LinkSlot;
    worker_heartbeat(&mut nodes, LinkSlot::Current, &l2, 1_000_000).await;
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&n0)
            .and_then(|p| p.current_addr().cloned()),
        Some(l2.clone()),
        "node 1 follows node 0 onto L2"
    );
    assert_eq!(verified_at(&nodes[1], &l2).await, Some(true));
    assert_eq!(verified_at(&nodes[1], &l1).await, Some(false));

    // Withdrawn while the peer stays on L2, as when the link drops and comes
    // back at the same address: the next frame there marks it again.
    let handle = nodes[1]
        .node
        .transports
        .get(&nodes[1].transport_id)
        .unwrap();
    handle.clear_verified(&l2, &n0, true).await;
    assert_eq!(verified_at(&nodes[1], &l2).await, Some(false));
    worker_heartbeat(&mut nodes, LinkSlot::Current, &l2, 1_000_001).await;
    assert_eq!(
        verified_at(&nodes[1], &l2).await,
        Some(true),
        "a frame at an unchanged address marks the link again"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A restart over the same link withdraws the verification; the responder's
/// promotion does not set it again, the initiator's first frame does.
#[tokio::test]
async fn a_restart_over_the_same_ble_link_is_verified_by_the_initiators_first_frame() {
    let mut nodes = peered_pair().await;
    let n0 = *nodes[0].node.node_addr();
    let link = nodes[1].addr.clone();
    let before = nodes[1].node.get_peer(&n0).unwrap().link_id();
    {
        let peer = nodes[1].node.get_peer_mut(&n0).unwrap();
        // An epoch other than the one node 0's msg1 carries, and quiet long
        // enough to pass the liveness gate, so the msg1 reads as a restart.
        peer.set_remote_epoch(Some([0xAA; 8]));
        peer.touch(Node::now_ms().saturating_sub(60_000));
    }

    let msg1 = genuine_msg1(&nodes[0].node, &nodes[1].node);
    let tid = nodes[1].transport_id;
    nodes[1]
        .node
        .handle_msg1(ReceivedPacket::with_timestamp(
            tid,
            link.clone(),
            msg1,
            2_000,
        ))
        .await;
    let after = nodes[1].node.get_peer(&n0).map(|p| p.link_id());
    assert!(
        after.is_some_and(|l| l != before),
        "node 1 re-peered with node 0 (a restart, not a decline)"
    );
    assert!(pooled_at(&nodes[1], &link), "the link is still pooled");
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        Some(false),
        "the teardown withdrew the flag and the responder's promotion did not set it"
    );

    use crate::node::dataplane::LinkSlot;
    worker_heartbeat(&mut nodes, LinkSlot::Current, &link, 1_000_000).await;
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        Some(true),
        "the initiator's first frame verifies the link"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A Disconnect the node cannot decode keeps the peer, and so must keep the
/// peer's link verified.
#[tokio::test]
async fn a_malformed_disconnect_keeps_its_link_verified() {
    let mut nodes = peered_pair().await;
    let n0 = *nodes[0].node.node_addr();
    let link = nodes[1].addr.clone();
    // The message type alone: no reason byte.
    let bad = [0x50u8];
    assert!(
        crate::proto::fmp::Disconnect::decode(&bad[1..]).is_err(),
        "the payload really is malformed"
    );
    nodes[1].node.dispatch_link_message(&n0, &bad, false).await;
    assert!(
        nodes[1].node.get_peer(&n0).is_some(),
        "node 1 keeps the peer"
    );
    assert_eq!(verified_at(&nodes[1], &link).await, Some(true));
    cleanup_nodes(&mut nodes).await;
}

/// A frame the decrypt worker bounces after its peer was removed must not
/// verify the link: no later removal would withdraw it.
#[tokio::test]
async fn a_frame_processed_after_its_peer_left_does_not_verify_the_link() {
    let mut nodes = peered_pair().await;
    let n0 = *nodes[0].node.node_addr();
    let link = nodes[1].addr.clone();
    let bye = crate::proto::fmp::wire::Disconnect::new(
        crate::proto::fmp::wire::DisconnectReason::Shutdown,
    )
    .encode();
    nodes[1].node.dispatch_link_message(&n0, &bye, false).await;
    assert!(nodes[1].node.get_peer(&n0).is_none());
    assert_eq!(verified_at(&nodes[1], &link).await, Some(false));

    use crate::node::dataplane::LinkSlot;
    worker_heartbeat(&mut nodes, LinkSlot::Previous, &link, 1_000_000).await;
    assert!(nodes[1].node.get_peer(&n0).is_none(), "still no peer");
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        Some(false),
        "a late frame for a removed peer verifies nothing"
    );
    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Links carrying a session survive a flood of newcomers
// ============================================================================

/// `n` fresh public keys whose node addresses sort below `node`, so the
/// inbound tie-break at `node` admits a link claiming any of them.
fn smaller_keys(node: &NodeAddr, n: usize) -> Vec<[u8; 32]> {
    let mut keys = Vec::new();
    while keys.len() < n {
        let id = crate::Identity::generate();
        if id.node_addr() < node {
            keys.push(id.pubkey().serialize());
        }
    }
    keys
}

/// Node 1's BLE pool refusals plus evictions: each newcomer offered to a full
/// pool raises exactly one of them, whichever rule the pool follows.
fn pool_outcomes(node: &TestNode) -> u64 {
    let snap = ble_of(node).stats().snapshot();
    snap.connections_rejected + snap.pool_evictions
}

/// Two identified nodes, node 1 the larger, pooling at most three links at
/// node 1, peered over one link that node 0 dialled.
async fn small_pair() -> Vec<TestNode> {
    let small = BleConfig {
        max_connections: Some(3),
        ..base_config()
    };
    let mut nodes = vec![
        make_test_node_ble_with(1, small.clone()).await,
        make_test_node_ble_with(2, small).await,
    ];
    larger_second(&mut nodes);
    let _bank = link_genuinely(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let n0 = *nodes[0].node.node_addr();
    assert!(
        nodes[1].node.get_peer(&n0).is_some(),
        "node 1 peers with node 0"
    );
    let link = nodes[1].addr.clone();
    assert!(pooled_at(&nodes[1], &link), "node 1 holds node 0's link");
    nodes
}

/// Advance past the grace, then offer node 1 three newcomers from new
/// addresses claiming fresh keys. The remote ends are returned.
async fn flood_pool(nodes: &[TestNode]) -> Vec<MockBleStream> {
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    let keys = smaller_keys(nodes[1].node.node_addr(), 3);
    let mut remotes = Vec::new();
    for (k, key) in keys.iter().enumerate() {
        let before = pool_outcomes(&nodes[1]);
        let from = ble_addr(50 + k as u8);
        remotes.push(inject_claim(nodes, 1, &from, *key).await);
        if k < 2 {
            assert!(
                until(|| pooled_at(&nodes[1], &from.to_transport_addr())).await,
                "newcomer {k} is admitted while the pool has room"
            );
        } else {
            assert!(
                until(|| pool_outcomes(&nodes[1]) == before + 1).await,
                "the third newcomer meets a full pool"
            );
        }
    }
    remotes
}

/// An established peer's link survives newcomers that fill the pool.
#[tokio::test]
async fn an_active_peers_link_survives_a_flood_of_unverified_newcomers() {
    let mut nodes = small_pair().await;
    let link = nodes[1].addr.clone();
    let _remotes = flood_pool(&nodes).await;
    let n0 = *nodes[0].node.node_addr();
    assert!(
        pooled_at(&nodes[1], &link),
        "node 0's link survives the flood"
    );
    assert!(
        nodes[1].node.get_peer(&n0).is_some(),
        "node 1 still peers with node 0"
    );
    assert_eq!(verified_at(&nodes[1], &link).await, Some(true));
    cleanup_nodes(&mut nodes).await;
}

/// A link that drops and comes back at the same address while the session
/// continues, with no new handshake, is verified by the first authenticated
/// frame on it and survives a flood like any other link carrying a session.
#[tokio::test]
async fn an_active_peers_link_reestablished_at_the_same_address_is_verified_and_survives_a_flood() {
    let mut nodes = small_pair().await;
    let link = nodes[1].addr.clone();
    let n0 = *nodes[0].node.node_addr();
    let n1 = *nodes[1].node.node_addr();

    // Node 0 ends the link; node 1's receive loop drops its entry.
    ble_of(&nodes[0]).close_connection_async(&link).await;
    assert!(
        until_unpooled(&nodes[1], &link).await,
        "node 1 notices the link ended"
    );

    // A new link at the same two addresses. Node 0's next send finds no
    // entry and re-dials; the session carries on over it.
    let bank: StreamBank = Arc::new(StdMutex::new(HashMap::new()));
    wire_ble_connection(&nodes, 0, 1, &bank).await;
    install_connect_handler(&nodes, 0, &bank);
    let _ = nodes[0].node.send_tree_announce_to_peer(&n1).await;
    assert!(
        until(|| pooled_at(&nodes[0], &link) && pooled_at(&nodes[1], &link)).await,
        "the link is re-established at the same address"
    );
    nodes[0]
        .node
        .send_tree_announce_to_peer(&n1)
        .await
        .expect("a frame over the re-established link");
    drain_all_packets(&mut nodes, false).await;
    assert!(
        nodes[1].node.get_peer(&n0).is_some(),
        "node 1 still peers with node 0"
    );

    let _remotes = flood_pool(&nodes).await;
    assert!(
        pooled_at(&nodes[1], &link),
        "the re-established link survives the flood"
    );
    assert!(
        nodes[1].node.get_peer(&n0).is_some(),
        "node 1 still peers with node 0"
    );
    assert_eq!(verified_at(&nodes[1], &link).await, Some(true));
    cleanup_nodes(&mut nodes).await;
}

/// Node 1's BLE pool evictions so far.
fn pool_evictions(node: &TestNode) -> u64 {
    ble_of(node).stats().snapshot().pool_evictions
}

/// A peer that moves its frames from link to link among its own links gives
/// each link it leaves no new protection: once the first link's grace has
/// passed, a newcomer to the full pool evicts one of the links it left.
#[tokio::test]
async fn a_peer_rotating_its_frames_across_its_links_keeps_only_the_current_one_protected() {
    let small = BleConfig {
        max_connections: Some(3),
        ..base_config()
    };
    let mut nodes = vec![
        make_test_node_ble_with(1, small.clone()).await,
        make_test_node_ble_with(2, small).await,
    ];
    larger_second(&mut nodes);
    // Two more links claiming node 0, admitted before anything verifies,
    // then node 0's own link: the pool is full.
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let mut others = Vec::new();
    let mut remotes = Vec::new();
    for n in [77, 78] {
        let at = ble_addr(n).to_transport_addr();
        remotes.push(inject_claim(&nodes, 1, &ble_addr(n), key_0).await);
        assert!(until(|| pooled_at(&nodes[1], &at)).await, "{at} is pooled");
        others.push(at);
    }
    let _bank = link_genuinely(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let n0 = *nodes[0].node.node_addr();
    let l1 = nodes[1].addr.clone();
    assert_eq!(verified_at(&nodes[1], &l1).await, Some(true));

    // Past every link's grace, node 0's frames move to L2, then to L3.
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    use crate::node::dataplane::LinkSlot;
    for (k, link) in others.iter().enumerate() {
        worker_heartbeat(&mut nodes, LinkSlot::Current, link, 1_000_000 + k as u64).await;
        assert_eq!(verified_at(&nodes[1], link).await, Some(true));
    }
    let (l2, l3) = (&others[0], &others[1]);
    assert_eq!(verified_at(&nodes[1], &l1).await, Some(false));
    assert_eq!(verified_at(&nodes[1], l2).await, Some(false));

    let before = pool_outcomes(&nodes[1]);
    let evictions = pool_evictions(&nodes[1]);
    let key = smaller_keys(nodes[1].node.node_addr(), 1)[0];
    let from = ble_addr(50).to_transport_addr();
    let _newcomer = inject_claim(&nodes, 1, &ble_addr(50), key).await;
    assert!(
        until(|| pool_outcomes(&nodes[1]) == before + 1).await,
        "the newcomer meets a full pool"
    );
    assert_eq!(
        pool_evictions(&nodes[1]),
        evictions + 1,
        "the newcomer evicts a link node 0 left rather than being refused"
    );
    assert!(
        verified_at(&nodes[1], &from).await.is_some(),
        "the newcomer is pooled"
    );
    assert!(
        verified_at(&nodes[1], &l1).await.is_none() || verified_at(&nodes[1], l2).await.is_none(),
        "the evicted link is one node 0 left"
    );
    assert_eq!(
        verified_at(&nodes[1], l3).await,
        Some(true),
        "the current link stays"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&n0)
            .and_then(|p| p.current_addr().cloned()),
        Some(l3.clone())
    );
    cleanup_nodes(&mut nodes).await;
}

/// Advance past the grace, then offer node 1 newcomers from new addresses
/// claiming fresh keys until one meets a full pool. The remote ends are
/// returned.
async fn fill_aged(nodes: &[TestNode]) -> Vec<MockBleStream> {
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    fill_pool(nodes).await
}

/// Offer node 1 newcomers from new addresses claiming fresh keys until one
/// meets a full pool. The remote ends are returned.
async fn fill_pool(nodes: &[TestNode]) -> Vec<MockBleStream> {
    let mut remotes = Vec::new();
    for k in 0..3u8 {
        let before = pool_outcomes(&nodes[1]);
        let key = smaller_keys(nodes[1].node.node_addr(), 1)[0];
        let from = ble_addr(50 + k);
        remotes.push(inject_claim(nodes, 1, &from, key).await);
        let decided = until(|| {
            pooled_at(&nodes[1], &from.to_transport_addr()) || pool_outcomes(&nodes[1]) > before
        })
        .await;
        assert!(decided, "newcomer {k} is admitted or meets a full pool");
        if pool_outcomes(&nodes[1]) > before {
            return remotes;
        }
    }
    panic!("no newcomer met a full pool");
}

/// After node 0's frames have moved off node 1's link to it: that link is no
/// longer verified, and a newcomer to node 1's full pool evicts it.
async fn left_unprotected(nodes: &[TestNode], moved_to: &TransportAddr) {
    let n0 = *nodes[0].node.node_addr();
    let link = nodes[1].addr.clone();
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&n0)
            .and_then(|p| p.current_addr().cloned()),
        Some(moved_to.clone()),
        "node 1 follows node 0's frames"
    );
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        Some(false),
        "the link node 0 left is no longer verified"
    );
    let _remotes = fill_aged(nodes).await;
    assert_eq!(pool_evictions(&nodes[1]), 1, "the newcomer evicts");
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        None,
        "the link node 0 left is the one evicted"
    );
}

/// A peer whose frame arrives from a link the pool no longer holds, as when
/// that link closed after the frame was read, has still left its old link:
/// the old link is cleared even though no link is verified in its place.
#[tokio::test]
async fn a_frame_from_an_unpooled_link_still_clears_the_link_its_peer_left() {
    let mut nodes = small_pair().await;
    let n1 = *nodes[1].node.node_addr();
    assert_eq!(verified_at(&nodes[1], &nodes[1].addr).await, Some(true));

    nodes[0]
        .node
        .send_tree_announce_to_peer(&n1)
        .await
        .expect("a frame to node 1");
    assert!(
        until(|| !nodes[1].packet_rx.is_empty()).await,
        "node 1 reads the frame"
    );
    let mut frame = nodes[1].packet_rx.try_recv().unwrap();
    let gone = ble_addr(90).to_transport_addr();
    assert_eq!(
        verified_at(&nodes[1], &gone).await,
        None,
        "nothing is pooled there"
    );
    frame.remote_addr = gone.clone();
    nodes[1].node.handle_encrypted_frame(frame).await;

    left_unprotected(&nodes, &gone).await;
    cleanup_nodes(&mut nodes).await;
}

/// The same through the decrypt worker, for a frame arriving on a link that
/// claimed a different node, which therefore cannot become node 0's.
#[tokio::test]
async fn a_frame_on_a_link_claiming_another_node_still_clears_the_link_its_peer_left() {
    let mut nodes = small_pair().await;
    assert_eq!(verified_at(&nodes[1], &nodes[1].addr).await, Some(true));
    let other = ble_addr(91).to_transport_addr();
    let key = smaller_keys(nodes[1].node.node_addr(), 1)[0];
    let _remote = inject_claim(&nodes, 1, &ble_addr(91), key).await;
    assert!(
        until(|| pooled_at(&nodes[1], &other)).await,
        "the link is pooled"
    );

    use crate::node::dataplane::LinkSlot;
    worker_heartbeat(&mut nodes, LinkSlot::Current, &other, 1_000_000).await;
    assert_eq!(
        verified_at(&nodes[1], &other).await,
        Some(false),
        "a link claiming another node is not verified for node 0"
    );
    left_unprotected(&nodes, &other).await;
    cleanup_nodes(&mut nodes).await;
}

/// A peer removed from a link long past its grace gives the link a new grace,
/// so a session restarting over it is not evicted before its first frame.
#[tokio::test]
async fn a_link_whose_peer_disconnected_gets_its_grace_again() {
    let mut nodes = small_pair().await;
    let n0 = *nodes[0].node.node_addr();
    let link = nodes[1].addr.clone();
    tokio::time::pause();
    tokio::time::advance(std::time::Duration::from_secs(11)).await;
    let bye = crate::proto::fmp::wire::Disconnect::new(
        crate::proto::fmp::wire::DisconnectReason::Shutdown,
    )
    .encode();
    nodes[1].node.dispatch_link_message(&n0, &bye, false).await;
    assert!(
        nodes[1].node.get_peer(&n0).is_none(),
        "node 1 dropped the peer"
    );
    assert_eq!(verified_at(&nodes[1], &link).await, Some(false));

    let _remotes = fill_pool(&nodes).await;
    assert_eq!(pool_evictions(&nodes[1]), 0, "nothing is evicted");
    assert_eq!(
        verified_at(&nodes[1], &link).await,
        Some(false),
        "the link its peer left is inside its new grace"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A peer moving its frames from one link to another is never left without a
/// verified link while the move is under way: an inbound claiming the peer
/// whose duplicate check waits on the pool lock behind the move is declined,
/// as it would be before or after it.
#[tokio::test]
async fn an_inbound_claim_checked_while_its_peer_moves_links_is_still_declined() {
    use crate::transport::ble::io::BleStream;
    let mut nodes = vec![
        make_test_node_ble_identified(1).await,
        make_test_node_ble_identified(2).await,
    ];
    larger_second(&mut nodes);
    // L2 claims node 0 and is admitted before anything verifies; then node
    // 0's own link L1 verifies.
    let key_0 = nodes[0].node.identity().pubkey().serialize();
    let l2 = ble_addr(77).to_transport_addr();
    let _l2_remote = inject_claim(&nodes, 1, &ble_addr(77), key_0).await;
    assert!(until(|| pooled_at(&nodes[1], &l2)).await, "L2 is pooled");
    let _bank = link_genuinely(&nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let n0 = *nodes[0].node.node_addr();
    let tid = nodes[1].transport_id;
    let l1 = nodes[1].addr.clone();
    assert_eq!(verified_at(&nodes[1], &l1).await, Some(true));
    assert_eq!(verified_at(&nodes[1], &l2).await, Some(false));

    // A newcomer claiming node 0 has node 1's key and has not sent its own.
    let from = ble_addr(50);
    let (remote, injected) = MockBleStream::pair(from.clone(), node_ble_addr(&nodes[1]), 2048);
    ble_of(&nodes[1]).io().inject_inbound(injected).await;
    let mut reply = [0u8; 33];
    assert_eq!(remote.recv(&mut reply).await.unwrap(), 33);
    let declines = ble_of(&nodes[1]).stats().snapshot().duplicate_node_declines;

    // Node 0's frames move from L1 to L2. The move queues on the held pool
    // lock first, the newcomer's duplicate check second.
    {
        let held = ble_of(&nodes[1]).hold_pool().await;
        let relink = nodes[1]
            .node
            .relink(&n0, Some((tid, l1.clone())), Some((tid, l2.clone())));
        tokio::pin!(relink);
        assert!(
            futures::poll!(&mut relink).is_pending(),
            "the move waits on the pool lock"
        );
        let mut claim = [0u8; 33];
        claim[1..].copy_from_slice(&key_0);
        remote.send(&claim).await.unwrap();
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        drop(held);
        relink.await;
    }

    let newcomer = from.to_transport_addr();
    let declined = || ble_of(&nodes[1]).stats().snapshot().duplicate_node_declines > declines;
    assert!(
        until(|| declined() || pooled_at(&nodes[1], &newcomer)).await,
        "the newcomer is decided"
    );
    assert!(
        declined(),
        "the newcomer claiming node 0 is declined as a duplicate"
    );
    assert_eq!(
        verified_at(&nodes[1], &newcomer).await,
        None,
        "and not pooled"
    );
    assert_eq!(
        verified_at(&nodes[1], &l2).await,
        Some(true),
        "L2 is verified"
    );
    assert_eq!(verified_at(&nodes[1], &l1).await, Some(false), "L1 is not");
    cleanup_nodes(&mut nodes).await;
}
