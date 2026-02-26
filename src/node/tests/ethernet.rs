//! Ethernet transport integration tests.
//!
//! Tests that the Ethernet transport works end-to-end using veth pairs.
//! All tests require root or CAP_NET_RAW and are marked `#[ignore]`.

use super::*;
use crate::config::EthernetConfig;
use crate::transport::ethernet::EthernetTransport;
use crate::transport::{packet_channel, TransportAddr, TransportHandle, TransportId};
use spanning_tree::{cleanup_nodes, drain_all_packets, initiate_handshake, TestNode};

use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

/// Atomic counter for unique veth names across tests.
static VETH_COUNTER: AtomicU32 = AtomicU32::new(0);

/// RAII wrapper for a veth pair.
///
/// Creates a pair of connected virtual Ethernet interfaces. Destroying
/// one end automatically destroys the other.
struct VethPair {
    name_a: String,
    name_b: String,
}

impl VethPair {
    /// Create a new veth pair with unique interface names.
    ///
    /// Names are kept under 15 chars (IFNAMSIZ limit). Format: `ftXXa`/`ftXXb`
    /// where XX is an atomic counter combined with PID for cross-process uniqueness.
    fn create() -> Self {
        let id = VETH_COUNTER.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id() % 10000;
        let name_a = format!("ft{}{}a", pid, id);
        let name_b = format!("ft{}{}b", pid, id);

        assert!(name_a.len() <= 15, "veth name too long: {}", name_a);
        assert!(name_b.len() <= 15, "veth name too long: {}", name_b);

        // Create veth pair
        let status = Command::new("ip")
            .args(["link", "add", &name_a, "type", "veth", "peer", "name", &name_b])
            .status()
            .expect("failed to run 'ip link add'");
        assert!(status.success(), "failed to create veth pair");

        // Bring both ends up
        let status = Command::new("ip")
            .args(["link", "set", &name_a, "up"])
            .status()
            .expect("failed to run 'ip link set up'");
        assert!(status.success(), "failed to bring up {}", name_a);

        let status = Command::new("ip")
            .args(["link", "set", &name_b, "up"])
            .status()
            .expect("failed to run 'ip link set up'");
        assert!(status.success(), "failed to bring up {}", name_b);

        VethPair { name_a, name_b }
    }
}

impl Drop for VethPair {
    fn drop(&mut self) {
        // Deleting one end destroys both
        let _ = Command::new("ip")
            .args(["link", "delete", &self.name_a])
            .status();
    }
}

/// Create a test node with a live Ethernet transport on the given interface.
///
/// Parallel to `make_test_node()` in spanning_tree.rs but uses
/// EthernetTransport instead of UDP.
async fn make_test_node_ethernet(interface: &str) -> TestNode {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let config = EthernetConfig {
        interface: interface.to_string(),
        discovery: Some(false),
        announce: Some(false),
        accept_connections: Some(true),
        ..Default::default()
    };

    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = EthernetTransport::new(transport_id, None, config, packet_tx);
    transport.start_async().await.unwrap();

    let mac = transport.local_mac().expect("transport should have MAC after start");
    let addr = TransportAddr::from_bytes(&mac);

    node.transports
        .insert(transport_id, TransportHandle::Ethernet(transport));

    TestNode {
        node,
        transport_id,
        packet_rx,
        addr,
    }
}

/// Two nodes on a veth pair complete a Noise handshake and establish peering.
#[tokio::test]
#[ignore] // Requires root or CAP_NET_RAW
async fn test_ethernet_two_node_handshake() {
    let veth = VethPair::create();

    let mut nodes = vec![
        make_test_node_ethernet(&veth.name_a).await,
        make_test_node_ethernet(&veth.name_b).await,
    ];

    // Initiate handshake from node 0 to node 1
    initiate_handshake(&mut nodes, 0, 1).await;

    // Drain all packets (handshake + tree announce)
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

/// Two Ethernet nodes converge to a correct spanning tree (2-node tree).
#[tokio::test]
#[ignore] // Requires root or CAP_NET_RAW
async fn test_ethernet_data_exchange() {
    use spanning_tree::verify_tree_convergence;

    let veth = VethPair::create();

    let mut nodes = vec![
        make_test_node_ethernet(&veth.name_a).await,
        make_test_node_ethernet(&veth.name_b).await,
    ];

    initiate_handshake(&mut nodes, 0, 1).await;
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    // Verify spanning tree convergence
    verify_tree_convergence(&nodes);

    // The root should be the node with the smallest NodeAddr
    let expected_root = std::cmp::min(*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    assert_eq!(*nodes[0].node.tree_state().root(), expected_root);
    assert_eq!(*nodes[1].node.tree_state().root(), expected_root);

    cleanup_nodes(&mut nodes).await;
}

/// Mixed transport: 2 Ethernet nodes + 2 UDP nodes coexist.
///
/// Each transport forms its own connected component. Validates that
/// `process_available_packets()` handles heterogeneous transport types.
#[tokio::test]
#[ignore] // Requires root or CAP_NET_RAW
async fn test_mixed_transport_coexistence() {
    use spanning_tree::{make_test_node, verify_tree_convergence_components};

    let veth = VethPair::create();

    // Create 2 Ethernet nodes and 2 UDP nodes
    let eth_0 = make_test_node_ethernet(&veth.name_a).await;
    let eth_1 = make_test_node_ethernet(&veth.name_b).await;
    let udp_0 = make_test_node().await;
    let udp_1 = make_test_node().await;

    let mut nodes = vec![eth_0, eth_1, udp_0, udp_1];

    // Handshake within each component
    initiate_handshake(&mut nodes, 0, 1).await; // Ethernet pair
    initiate_handshake(&mut nodes, 2, 3).await; // UDP pair

    // Drain all packets across both transports
    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0);

    // Verify each component converges independently
    verify_tree_convergence_components(&nodes, &[vec![0, 1], vec![2, 3]]);

    // Ethernet component has its own root
    let eth_root = std::cmp::min(*nodes[0].node.node_addr(), *nodes[1].node.node_addr());
    assert_eq!(*nodes[0].node.tree_state().root(), eth_root);
    assert_eq!(*nodes[1].node.tree_state().root(), eth_root);

    // UDP component has its own root
    let udp_root = std::cmp::min(*nodes[2].node.node_addr(), *nodes[3].node.node_addr());
    assert_eq!(*nodes[2].node.tree_state().root(), udp_root);
    assert_eq!(*nodes[3].node.tree_state().root(), udp_root);

    cleanup_nodes(&mut nodes).await;
}
