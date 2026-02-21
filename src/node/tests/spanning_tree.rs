//! Spanning tree convergence integration tests.
//!
//! Tests that multi-node networks converge to a consistent spanning tree
//! with the correct root (smallest NodeAddr). Includes helper infrastructure
//! reused by bloom filter tests.

use super::*;

/// A test node bundling a Node with its transport and packet channel.
pub(super) struct TestNode {
    pub(super) node: Node,
    pub(super) transport_id: TransportId,
    pub(super) packet_rx: PacketRx,
    pub(super) addr: TransportAddr,
}

/// Create a test node with a live UDP transport on localhost.
pub(super) async fn make_test_node() -> TestNode {
    use crate::config::UdpConfig;
    use crate::transport::udp::UdpTransport;

    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let udp_config = UdpConfig {
        bind_addr: Some("127.0.0.1:0".to_string()),
        mtu: Some(1280),
        ..Default::default()
    };

    let (packet_tx, packet_rx) = packet_channel(256);
    let mut transport = UdpTransport::new(transport_id, None, udp_config, packet_tx);
    transport.start_async().await.unwrap();

    let addr = TransportAddr::from_string(&transport.local_addr().unwrap().to_string());
    node.transports
        .insert(transport_id, TransportHandle::Udp(transport));

    TestNode {
        node,
        transport_id,
        packet_rx,
        addr,
    }
}

/// Initiate a Noise handshake from nodes[i] to nodes[j].
///
/// Sends msg1 over UDP. The drain loop will handle msg1 processing,
/// msg2 response, and subsequent TreeAnnounce exchange.
pub(super) async fn initiate_handshake(nodes: &mut [TestNode], i: usize, j: usize) {
    use crate::node::wire::build_msg1;

    // Extract responder info before mutably borrowing initiator
    let responder_addr = nodes[j].addr.clone();
    let responder_pubkey_full = nodes[j].node.identity().pubkey_full();
    let peer_identity = PeerIdentity::from_pubkey_full(responder_pubkey_full);

    let initiator = &mut nodes[i];
    let transport_id = initiator.transport_id;

    let link_id = initiator.node.allocate_link_id();
    let mut conn = PeerConnection::outbound(link_id, peer_identity, 1000);

    let our_index = initiator.node.index_allocator.allocate().unwrap();
    let our_keypair = initiator.node.identity().keypair();
    let noise_msg1 = conn.start_handshake(our_keypair, 1000).unwrap();
    conn.set_our_index(our_index);
    conn.set_transport_id(transport_id);
    conn.set_source_addr(responder_addr.clone());

    let wire_msg1 = build_msg1(our_index, &noise_msg1);

    let link = Link::connectionless(
        link_id,
        transport_id,
        responder_addr.clone(),
        LinkDirection::Outbound,
        Duration::from_millis(100),
    );
    initiator.node.links.insert(link_id, link);
    initiator
        .node
        .addr_to_link
        .insert((transport_id, responder_addr.clone()), link_id);
    initiator.node.connections.insert(link_id, conn);
    initiator
        .node
        .pending_outbound
        .insert((transport_id, our_index.as_u32()), link_id);

    let transport = initiator.node.transports.get(&transport_id).unwrap();
    transport
        .send(&responder_addr, &wire_msg1)
        .await
        .expect("Failed to send msg1");
}

/// Print a snapshot of each node's tree state.
///
/// For small networks (≤20 nodes) prints per-node detail.
/// For larger networks prints a compact summary with depth histogram.
pub(super) fn print_tree_snapshot(label: &str, nodes: &[TestNode]) {
    eprintln!("\n  --- {} ---", label);

    // Find expected root for reference
    let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
    let expected_root_idx = nodes
        .iter()
        .position(|tn| *tn.node.node_addr() == expected_root)
        .unwrap();

    // Count how many nodes agree on the correct root
    let correct_root_count = nodes
        .iter()
        .filter(|tn| *tn.node.tree_state().root() == expected_root)
        .count();
    let total_pending: usize = nodes
        .iter()
        .map(|tn| {
            tn.node
                .peers
                .values()
                .filter(|p| p.has_pending_tree_announce())
                .count()
        })
        .sum();

    // Build depth histogram
    let mut depth_counts = std::collections::BTreeMap::new();
    for tn in nodes {
        *depth_counts
            .entry(tn.node.tree_state().my_coords().depth())
            .or_insert(0usize) += 1;
    }
    let depth_str: Vec<String> = depth_counts
        .iter()
        .map(|(d, c)| format!("d{}={}", d, c))
        .collect();

    // Count distinct roots
    let mut roots = std::collections::BTreeSet::new();
    for tn in nodes {
        roots.insert(*tn.node.tree_state().root());
    }

    eprintln!(
        "  converged={}/{} roots={} depths=[{}] pending={}",
        correct_root_count,
        nodes.len(),
        roots.len(),
        depth_str.join(" "),
        total_pending,
    );

    // Per-node detail for small networks
    if nodes.len() <= 20 {
        for (i, tn) in nodes.iter().enumerate() {
            let ts = tn.node.tree_state();
            let parent_idx = if ts.is_root() {
                "self".to_string()
            } else {
                nodes
                    .iter()
                    .position(|n| n.node.node_addr() == ts.my_declaration().parent_id())
                    .map(|p| format!("{}", p))
                    .unwrap_or_else(|| format!("?{}", ts.my_declaration().parent_id()))
            };
            let root_idx = nodes
                .iter()
                .position(|n| n.node.node_addr() == ts.root())
                .map(|r| format!("{}", r))
                .unwrap_or_else(|| format!("?{}", ts.root()));
            let pending = tn
                .node
                .peers
                .values()
                .filter(|p| p.has_pending_tree_announce())
                .count();
            eprintln!(
                "  node[{}] root=node[{}] depth={} parent=node[{}] peers={} pending={}",
                i, root_idx, ts.my_coords().depth(), parent_idx, tn.node.peer_count(), pending,
            );
        }
    } else if correct_root_count < nodes.len() {
        // For large networks that haven't converged, show which nodes are wrong
        let wrong: Vec<usize> = nodes
            .iter()
            .enumerate()
            .filter(|(_, tn)| *tn.node.tree_state().root() != expected_root)
            .map(|(i, _)| i)
            .collect();
        if wrong.len() <= 20 {
            eprintln!("  unconverged nodes: {:?}", wrong);
        } else {
            eprintln!("  unconverged nodes: {} remaining", wrong.len());
        }
    }

    let _ = expected_root_idx; // suppress unused
}

/// Process all currently available packets across all nodes.
///
/// Returns the number of packets processed.
pub(super) async fn process_available_packets(nodes: &mut [TestNode]) -> usize {
    use crate::node::wire::{CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2, COMMON_PREFIX_SIZE};

    let mut count = 0;
    for node in nodes.iter_mut() {
        while let Ok(packet) = node.packet_rx.try_recv() {
            if packet.data.len() < COMMON_PREFIX_SIZE {
                continue;
            }
            if let Some(prefix) = CommonPrefix::parse(&packet.data) {
                if prefix.version != FMP_VERSION {
                    continue;
                }
                match prefix.phase {
                    PHASE_MSG1 => node.node.handle_msg1(packet).await,
                    PHASE_MSG2 => node.node.handle_msg2(packet).await,
                    PHASE_ESTABLISHED => {
                        node.node.handle_encrypted_frame(packet).await
                    }
                    _ => {}
                }
                count += 1;
            }
        }
    }
    count
}

/// Drain all packet channels across all nodes until quiescence.
///
/// Processes msg1, msg2, and encrypted frames (including TreeAnnounce)
/// through the appropriate handlers. Handles rate-limited TreeAnnounce
/// messages by waiting for the rate limit window to expire and then
/// flushing pending announces. Returns total packets processed.
///
/// If `verbose` is true, prints tree state snapshots after each phase.
pub(super) async fn drain_all_packets(nodes: &mut [TestNode], verbose: bool) -> usize {
    let mut total = 0;

    // Phase 1: Fast drain — process packets as fast as they arrive.
    // This handles handshakes (msg1/msg2) and the first wave of TreeAnnounce.
    for _round in 0..200 {
        tokio::time::sleep(Duration::from_millis(10)).await;

        let count = process_available_packets(nodes).await;
        total += count;
        if count == 0 {
            break;
        }
    }

    if verbose {
        print_tree_snapshot(
            &format!("After handshakes + initial announces ({} packets)", total),
            nodes,
        );
    }

    // Phase 2: Rate-limit flush cycles. Each cycle waits for rate limits
    // to expire, flushes pending announces, processes resulting packets,
    // and repeats. Each cycle propagates the tree one hop further through
    // rate-limited paths. For a chain of depth D, we need D cycles.
    for flush in 0..20 {
        // Wait for rate limit window (500ms) to fully expire
        tokio::time::sleep(Duration::from_millis(550)).await;

        // Flush pending rate-limited tree and filter announces on all nodes
        for tn in nodes.iter_mut() {
            tn.node.send_pending_tree_announces().await;
            tn.node.send_pending_filter_announces().await;
        }

        // Allow flushed packets to arrive
        tokio::time::sleep(Duration::from_millis(20)).await;

        // Process the resulting packets. Processing may trigger new
        // parent switches → new announces, but those to the same peer
        // will be rate-limited again and caught by the next flush cycle.
        let mut flush_total = process_available_packets(nodes).await;

        // Do a few more quick rounds in case packet processing above
        // triggered non-rate-limited sends (to different peers)
        for _sub in 0..20 {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let count = process_available_packets(nodes).await;
            flush_total += count;
            if count == 0 {
                break;
            }
        }

        total += flush_total;
        if flush_total == 0 {
            break;
        }

        if verbose {
            print_tree_snapshot(
                &format!("After flush cycle {} ({} packets)", flush + 1, flush_total),
                nodes,
            );
        }
    }

    total
}

/// Generate a connected random graph with deterministic topology.
///
/// First builds a random spanning tree to ensure connectivity,
/// then adds extra edges up to the target count.
pub(super) fn generate_random_edges(n: usize, target_edges: usize, seed: u64) -> Vec<(usize, usize)> {
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    let mut rng = StdRng::seed_from_u64(seed);
    let mut edges = Vec::new();
    let mut adj = vec![vec![false; n]; n];

    // Build a random spanning tree (ensures connectivity)
    let mut connected = vec![false; n];
    connected[0] = true;
    let mut connected_count = 1;

    while connected_count < n {
        let from = rng.gen_range(0..n);
        if !connected[from] {
            continue;
        }
        let to = rng.gen_range(0..n);
        if connected[to] || from == to {
            continue;
        }

        edges.push((from, to));
        adj[from][to] = true;
        adj[to][from] = true;
        connected[to] = true;
        connected_count += 1;
    }

    // Add random extra edges up to target
    let mut attempts = 0;
    while edges.len() < target_edges && attempts < target_edges * 10 {
        let a = rng.gen_range(0..n);
        let b = rng.gen_range(0..n);
        attempts += 1;
        if a == b || adj[a][b] {
            continue;
        }
        edges.push((a, b));
        adj[a][b] = true;
        adj[b][a] = true;
    }

    edges
}

/// Verify that all nodes in a connected component have converged to a
/// consistent spanning tree.
pub(super) fn verify_tree_convergence(nodes: &[TestNode]) {
    let n = nodes.len();
    assert!(n > 0);

    // Find the expected root (smallest NodeAddr across all nodes)
    let expected_root = nodes
        .iter()
        .map(|tn| *tn.node.node_addr())
        .min()
        .unwrap();

    // All nodes should agree on the root
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        assert_eq!(
            *ts.root(),
            expected_root,
            "Node {} (addr={}) has root {} but expected {}",
            i,
            tn.node.node_addr(),
            ts.root(),
            expected_root
        );
    }

    // Root node should have is_root() == true and depth 0
    let root_node = nodes
        .iter()
        .find(|tn| *tn.node.node_addr() == expected_root)
        .unwrap();
    assert!(
        root_node.node.tree_state().is_root(),
        "Expected root node should have is_root = true"
    );
    assert_eq!(
        root_node.node.tree_state().my_coords().depth(),
        0,
        "Root node should have depth 0"
    );

    // Non-root nodes should have depth > 0
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if *tn.node.node_addr() != expected_root {
            assert!(
                ts.my_coords().depth() > 0,
                "Non-root node {} should have depth > 0, got {}",
                i,
                ts.my_coords().depth()
            );
        }
    }

    // Each non-root node's parent should be one of its peers
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if ts.is_root() {
            continue;
        }

        let parent_id = ts.my_declaration().parent_id();
        assert!(
            tn.node.get_peer(parent_id).is_some(),
            "Node {}'s parent {} should be in its peer list",
            i,
            parent_id
        );
    }

    // Each node's coordinate root should match expected root
    for (i, tn) in nodes.iter().enumerate() {
        let coords = tn.node.tree_state().my_coords();
        assert_eq!(
            *coords.root_id(),
            expected_root,
            "Node {}'s coordinate root {} should match expected root {}",
            i,
            coords.root_id(),
            expected_root
        );
    }

    // Depth consistency: child's depth = parent's depth + 1
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if ts.is_root() {
            continue;
        }

        let my_depth = ts.my_coords().depth();
        let parent_id = ts.my_declaration().parent_id();

        // Find the parent node in our array
        if let Some(parent_node) = nodes.iter().find(|pn| pn.node.node_addr() == parent_id) {
            let parent_depth = parent_node.node.tree_state().my_coords().depth();
            assert_eq!(
                my_depth,
                parent_depth + 1,
                "Node {}'s depth ({}) should be parent's depth ({}) + 1",
                i,
                my_depth,
                parent_depth
            );
        }
    }
}

/// Verify tree convergence for disconnected components.
///
/// Each connected component should converge to its own root (smallest
/// NodeAddr in that component).
pub(super) fn verify_tree_convergence_components(nodes: &[TestNode], components: &[Vec<usize>]) {
    for component in components {
        let component_nodes: Vec<&TestNode> = component.iter().map(|&i| &nodes[i]).collect();

        let expected_root = component_nodes
            .iter()
            .map(|tn| *tn.node.node_addr())
            .min()
            .unwrap();

        for &idx in component {
            let ts = nodes[idx].node.tree_state();
            assert_eq!(
                *ts.root(),
                expected_root,
                "Node {} in component should have root {}",
                idx,
                expected_root
            );
        }
    }
}

/// Run a spanning tree test for a given set of edges.
///
/// Creates nodes, initiates handshakes, drains packets, and verifies convergence.
/// If `verbose` is true, prints topology and convergence progress.
pub(super) async fn run_tree_test(
    num_nodes: usize,
    edges: &[(usize, usize)],
    verbose: bool,
) -> Vec<TestNode> {
    // Create nodes
    let mut nodes = Vec::new();
    for _ in 0..num_nodes {
        nodes.push(make_test_node().await);
    }

    if verbose {
        eprintln!(
            "\n  === Spanning Tree Convergence ({} nodes, {} edges) ===",
            num_nodes,
            edges.len()
        );
        let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();
        let root_idx = nodes
            .iter()
            .position(|tn| *tn.node.node_addr() == expected_root)
            .unwrap();
        eprintln!("  Expected root: node[{}] = {}", root_idx, expected_root);

        // Compute average degree
        let mut degree = vec![0usize; num_nodes];
        for &(i, j) in edges {
            degree[i] += 1;
            degree[j] += 1;
        }
        let avg_degree = degree.iter().sum::<usize>() as f64 / num_nodes as f64;
        let max_degree = degree.iter().max().copied().unwrap_or(0);
        let min_degree = degree.iter().min().copied().unwrap_or(0);
        eprintln!(
            "  Degree: min={} max={} avg={:.1}",
            min_degree, max_degree, avg_degree
        );

        // Per-node/edge detail only for small networks
        if num_nodes <= 20 {
            let mut sorted: Vec<(usize, NodeAddr)> = nodes
                .iter()
                .enumerate()
                .map(|(i, tn)| (i, *tn.node.node_addr()))
                .collect();
            sorted.sort_by_key(|(_, addr)| *addr);
            eprintln!("  Node addresses (sorted, smallest = expected root):");
            for (i, addr) in &sorted {
                let marker = if *i == sorted[0].0 { " <-- root" } else { "" };
                eprintln!("    node[{}] = {}{}", i, addr, marker);
            }
            eprintln!("  Edges:");
            for (idx, &(i, j)) in edges.iter().enumerate() {
                eprintln!("    edge[{}]: node[{}] -- node[{}]", idx, i, j);
            }
        }
    }

    // Initiate all handshakes
    for &(i, j) in edges {
        initiate_handshake(&mut nodes, i, j).await;
    }

    // Drain packets until convergence (handles rate-limited announces)
    let total = drain_all_packets(&mut nodes, verbose).await;
    assert!(total > 0, "Should have processed at least some packets");

    if verbose {
        eprintln!("\n  Total packets processed: {}", total);
    }

    // Verify all edges established bidirectional peers
    for &(i, j) in edges {
        let j_addr = *nodes[j].node.node_addr();
        let i_addr = *nodes[i].node.node_addr();

        assert!(
            nodes[i].node.get_peer(&j_addr).is_some(),
            "Node {} should have peer {} (node {})",
            i,
            j_addr,
            j
        );
        assert!(
            nodes[j].node.get_peer(&i_addr).is_some(),
            "Node {} should have peer {} (node {})",
            j,
            i_addr,
            i
        );
    }

    nodes
}

/// Clean up transports for all test nodes.
pub(super) async fn cleanup_nodes(nodes: &mut [TestNode]) {
    for tn in nodes.iter_mut() {
        for (_, t) in tn.node.transports.iter_mut() {
            t.stop().await.ok();
        }
    }
}

// ===== Main Convergence Test =====

/// Integration test: 100 nodes with random connectivity converge to a
/// consistent spanning tree with the correct root.
#[tokio::test]
async fn test_spanning_tree_convergence_100_nodes() {
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, true).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

// ===== Topology Variant Tests =====

/// Ring topology: 5 nodes in a cycle.
#[tokio::test]
async fn test_spanning_tree_ring() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Star topology: node 0 connected to all others.
#[tokio::test]
async fn test_spanning_tree_star() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (0, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Linear chain: 0-1-2-3-4.
#[tokio::test]
async fn test_spanning_tree_chain() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// Two disconnected components: nodes 0-2 and nodes 3-5.
#[tokio::test]
async fn test_spanning_tree_disconnected() {
    let edges: Vec<(usize, usize)> = vec![
        (0, 1),
        (1, 2), // component 1
        (3, 4),
        (4, 5), // component 2
    ];
    let mut nodes = run_tree_test(6, &edges, false).await;
    verify_tree_convergence_components(&nodes, &[vec![0, 1, 2], vec![3, 4, 5]]);
    cleanup_nodes(&mut nodes).await;
}
