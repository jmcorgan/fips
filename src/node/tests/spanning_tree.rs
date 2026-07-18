//! Spanning tree convergence integration tests.
//!
//! Tests that multi-node networks converge to a consistent spanning tree
//! with the correct root (smallest NodeAddr). Includes helper infrastructure
//! reused by bloom filter tests.

use super::*;
use crate::node::tree::sign_declaration;
use crate::proto::stp::TreeAnnounce;
use crate::proto::stp::{CoordEntry, ParentDeclaration, TreeCoordinate};
use crate::transport::loopback::{LoopbackRegistry, LoopbackTransport, new_registry};

static LARGE_NETWORK_TEST_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

/// Process-wide shared loopback registry for node-level mesh tests.
///
/// All loopback test nodes register here so they can locate each other by
/// address. Each node gets a unique synthetic address (`loopback:{n}`) from
/// `LOOPBACK_ADDR_COUNTER`, so addresses never collide across concurrently
/// running tests and stale entries from finished tests are harmless.
static LOOPBACK_REGISTRY: std::sync::LazyLock<LoopbackRegistry> =
    std::sync::LazyLock::new(new_registry);

static LOOPBACK_ADDR_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Allocate the next globally-unique loopback address.
fn next_loopback_addr() -> TransportAddr {
    let n = LOOPBACK_ADDR_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    TransportAddr::from_string(&format!("loopback:{}", n))
}

/// Bridge a transport's bounded receive channel into the unbounded channel
/// that `TestNode` holds.
///
/// Real transports (TCP, Ethernet, BLE) drain their kernel socket into a
/// bounded `PacketRx` via a background receive task, so a bounded channel
/// does not deadlock for them. `TestNode.packet_rx` is unbounded (required
/// by the loopback path, which has no background reader); this spawns a
/// forwarding task so non-loopback factories can still produce a `TestNode`.
pub(super) fn bridge_to_unbounded(
    mut bounded_rx: PacketRx,
) -> tokio::sync::mpsc::UnboundedReceiver<ReceivedPacket> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Some(packet) = bounded_rx.recv().await {
            if tx.send(packet).is_err() {
                break;
            }
        }
    });
    rx
}

pub(super) async fn lock_large_network_test() -> tokio::sync::MutexGuard<'static, ()> {
    LARGE_NETWORK_TEST_LOCK.lock().await
}

/// A test node bundling a Node with its transport and packet channel.
pub(super) struct TestNode {
    pub(super) node: Node,
    pub(super) transport_id: TransportId,
    pub(super) packet_rx: tokio::sync::mpsc::UnboundedReceiver<ReceivedPacket>,
    pub(super) addr: TransportAddr,
}

/// Create a test node with an in-process loopback transport.
pub(super) async fn make_test_node() -> TestNode {
    make_test_node_with_mtu(1280).await
}

/// Create a test node with a specific transport MTU.
///
/// Uses the in-process loopback transport (not real UDP): packets are
/// delivered directly to the destination node's unbounded receive channel
/// via the shared registry. This avoids the kernel UDP receive-buffer
/// overflow that drops handshake packets when many tests run in parallel
/// under CPU contention. The `mtu` is enforced on send (MtuExceeded),
/// mirroring UDP, so heterogeneous-MTU / PMTUD tests still exercise the
/// forward-path bottleneck.
pub(super) async fn make_test_node_with_mtu(mtu: u16) -> TestNode {
    let mut node = make_node();
    let transport_id = TransportId::new(1);

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<ReceivedPacket>();
    let addr = next_loopback_addr();

    LOOPBACK_REGISTRY.lock().unwrap().insert(addr.clone(), tx);

    let loopback =
        LoopbackTransport::with_mtu(transport_id, addr.clone(), mtu, LOOPBACK_REGISTRY.clone());
    node.transports
        .insert(transport_id, TransportHandle::Loopback(loopback));

    TestNode {
        node,
        transport_id,
        packet_rx: rx,
        addr,
    }
}

/// Initiate a Noise handshake from nodes[i] to nodes[j].
///
/// Sends msg1 over UDP. The drain loop will handle msg1 processing,
/// msg2 response, and subsequent TreeAnnounce exchange.
pub(super) async fn initiate_handshake(nodes: &mut [TestNode], i: usize, j: usize) {
    use crate::proto::fmp::wire::build_msg1;

    // Extract responder info before mutably borrowing initiator
    let responder_addr = nodes[j].addr.clone();
    let responder_pubkey_full = nodes[j].node.identity().pubkey_full();
    let peer_identity = PeerIdentity::from_pubkey_full(responder_pubkey_full);

    let initiator = &mut nodes[i];
    let transport_id = initiator.transport_id;

    let link_id = initiator.node.allocate_link_id();

    let our_index = initiator.node.index_allocator.allocate().unwrap();
    initiator
        .node
        .seed_handshake_machine(
            HandshakeSeed::outbound(link_id, peer_identity, 1000)
                .with_our_index(our_index)
                .with_transport_id(transport_id)
                .with_source_addr(responder_addr.clone()),
        )
        .unwrap();
    let our_keypair = initiator.node.identity().keypair();
    let startup_epoch = initiator.node.startup_epoch();
    let noise_msg1 = initiator
        .node
        .get_connection_mut(&link_id)
        .unwrap()
        .start_handshake(our_keypair, startup_epoch, 1000)
        .unwrap();

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
                i,
                root_idx,
                ts.my_coords().depth(),
                parent_idx,
                tn.node.peer_count(),
                pending,
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
    use crate::proto::fmp::wire::{
        COMMON_PREFIX_SIZE, CommonPrefix, FMP_VERSION, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2,
    };

    // Snapshot the number of packets queued at every node at the start of the
    // pass, before processing any node. Loopback delivery is synchronous, so a
    // packet sent during this pass would otherwise land in another node's
    // channel and be drained in the *same* pass. Real UDP defers such packets
    // to the next pass (socket round-trip + recv task), and several tests
    // depend on that one-hop-per-pass cadence. Bounding each node's drain to
    // its start-of-pass count preserves it regardless of iteration order.
    let queued: Vec<usize> = nodes.iter().map(|n| n.packet_rx.len()).collect();

    let mut count = 0;
    for (node, &queued) in nodes.iter_mut().zip(queued.iter()) {
        for _ in 0..queued {
            let Ok(packet) = node.packet_rx.try_recv() else {
                break;
            };
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
                    PHASE_ESTABLISHED => node.node.handle_encrypted_frame(packet).await,
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

/// Repair synthetic test edges whose one-shot UDP handshake packet was dropped.
///
/// The large topology tests create 250 links by sending exactly one msg1 per
/// edge, bypassing the normal node reconnect timers. On slower CI runners that
/// burst can still drop a localhost UDP datagram, so retry only edges that did
/// not produce bidirectional peers before asserting tree/session behavior. The
/// retry path drains after each edge instead of sending a second burst, since
/// the repair is meant to remove harness pressure rather than recreate it.
async fn repair_missing_edge_handshakes(
    nodes: &mut [TestNode],
    edges: &[(usize, usize)],
    verbose: bool,
) -> usize {
    let mut retries = 0;

    for attempt in 0..5 {
        let mut missing = Vec::new();
        for &(i, j) in edges {
            let j_addr = *nodes[j].node.node_addr();
            let i_addr = *nodes[i].node.node_addr();
            let i_has_j = nodes[i].node.get_peer(&j_addr).is_some();
            let j_has_i = nodes[j].node.get_peer(&i_addr).is_some();
            if !i_has_j || !j_has_i {
                missing.push((i, j, i_has_j, j_has_i));
            }
        }

        if missing.is_empty() {
            break;
        }

        if verbose {
            eprintln!(
                "  Repairing {} missing synthetic edge handshake(s), attempt {}",
                missing.len(),
                attempt + 1
            );
        }

        for (i, j, i_has_j, j_has_i) in missing {
            if !i_has_j {
                initiate_handshake(nodes, i, j).await;
                retries += 1;
                let _ = drain_all_packets(nodes, false).await;
            }

            let j_addr = *nodes[j].node.node_addr();
            let i_addr = *nodes[i].node.node_addr();
            let j_still_missing_i = nodes[j].node.get_peer(&i_addr).is_none();
            let i_still_missing_j = nodes[i].node.get_peer(&j_addr).is_none();

            if !j_has_i && j_still_missing_i {
                initiate_handshake(nodes, j, i).await;
                retries += 1;
                let _ = drain_all_packets(nodes, false).await;
            } else if i_still_missing_j {
                initiate_handshake(nodes, i, j).await;
                retries += 1;
                let _ = drain_all_packets(nodes, false).await;
            }
        }
    }

    retries
}

/// Generate a connected random graph with deterministic topology.
///
/// First builds a random spanning tree to ensure connectivity,
/// then adds extra edges up to the target count.
pub(super) fn generate_random_edges(
    n: usize,
    target_edges: usize,
    seed: u64,
) -> Vec<(usize, usize)> {
    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};

    let mut rng = StdRng::seed_from_u64(seed);
    let mut edges = Vec::new();
    let mut adj = vec![vec![false; n]; n];

    // Build a random spanning tree (ensures connectivity)
    let mut connected = vec![false; n];
    connected[0] = true;
    let mut connected_count = 1;

    while connected_count < n {
        let from = rng.random_range(0..n);
        if !connected[from] {
            continue;
        }
        let to = rng.random_range(0..n);
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
        let a = rng.random_range(0..n);
        let b = rng.random_range(0..n);
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
    let expected_root = nodes.iter().map(|tn| *tn.node.node_addr()).min().unwrap();

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
    let repaired = repair_missing_edge_handshakes(&mut nodes, edges, verbose).await;

    if verbose {
        eprintln!("\n  Total packets processed: {}", total);
        if repaired > 0 {
            eprintln!("  Synthetic handshake retries: {}", repaired);
            print_tree_snapshot("After synthetic handshake repair", &nodes);
        }
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

/// Like `run_tree_test` but with per-node transport MTUs.
///
/// `mtus` must have one entry per node. Used for heterogeneous-MTU tests
/// where different hops have different link-layer capacities.
pub(super) async fn run_tree_test_with_mtus(
    mtus: &[u16],
    edges: &[(usize, usize)],
) -> Vec<TestNode> {
    let mut nodes = Vec::new();
    for &mtu in mtus {
        nodes.push(make_test_node_with_mtu(mtu).await);
    }

    for &(i, j) in edges {
        initiate_handshake(&mut nodes, i, j).await;
    }

    let total = drain_all_packets(&mut nodes, false).await;
    assert!(total > 0, "Should have processed at least some packets");
    let _ = repair_missing_edge_handshakes(&mut nodes, edges, false).await;

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
    let _guard = lock_large_network_test().await;

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

/// Tests that a node ignores a signed TreeAnnounce whose advertised root is not the smallest node_addr in the ancestry.
#[tokio::test]
async fn test_rejects_tree_announce_with_inconsistent_root() {
    // Start from a healthy 2-node tree so node B already has a normal, trusted
    // view of node A's coordinates.
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let a_addr = *nodes[0].node.node_addr();
    let current_root = *nodes[1].node.tree_state().root();
    let current_depth = nodes[1].node.tree_state().my_coords().depth();
    let peer_coords_before = nodes[1]
        .node
        .get_peer(&a_addr)
        .unwrap()
        .coords()
        .unwrap()
        .clone();
    let accepted_before = nodes[1].node.metrics().tree.accepted.get();

    // Use two fixed synthetic ancestors so the forged path is explicit:
    // - fake_parent = 00000000000000000000000000000000
    // - fake_root   = 00000000000000000000000000000001
    //
    // The forged ancestry is therefore:
    //   [A, 000...000, 000...001]
    //
    // That makes 000...001 the advertised root because it is the final entry,
    // even though 000...000 is smaller and appears earlier in the path.
    let fake_parent = NodeAddr::from_bytes([0u8; 16]);
    let mut fake_root_bytes = [0u8; 16];
    fake_root_bytes[15] = 1;
    let fake_root = NodeAddr::from_bytes(fake_root_bytes);

    // Sign a fresh declaration from A. The 99/12345 values are just a newer
    // sequence/timestamp so the announce would be acceptable on freshness
    // grounds if its ancestry semantics were valid.
    let mut declaration = ParentDeclaration::new(a_addr, fake_parent, 99, 12345);
    sign_declaration(&mut declaration, nodes[0].node.identity()).unwrap();

    let announce = TreeAnnounce::new(
        declaration,
        TreeCoordinate::new(vec![
            CoordEntry::new(a_addr, 99, 12345),
            CoordEntry::new(fake_parent, 98, 12344),
            CoordEntry::new(fake_root, 97, 12343),
        ])
        .unwrap(),
    );
    let encoded = announce.encode().unwrap();

    nodes[1]
        .node
        .handle_tree_announce(&a_addr, &encoded[1..])
        .await;

    // B should reject the malformed ancestry before mutating either its local
    // tree state or its cached view of peer A.
    assert_eq!(*nodes[1].node.tree_state().root(), current_root);
    assert_eq!(
        nodes[1].node.tree_state().my_coords().depth(),
        current_depth
    );
    assert_eq!(nodes[1].node.metrics().tree.accepted.get(), accepted_before);
    assert_eq!(
        nodes[1].node.get_peer(&a_addr).unwrap().coords().unwrap(),
        &peer_coords_before
    );

    cleanup_nodes(&mut nodes).await;
}

/// A peer whose TreeAnnounce advertises a root worse (higher NodeAddr) than
/// ours must be answered with our own current TreeAnnounce, so a node that has
/// fallen back to self-root (e.g. because its parent's attaching announce was
/// lost) can re-attach without waiting for the parent's slow periodic
/// re-broadcast.
///
/// This reproduces, at the unit level, the single-uplink-leaf convergence
/// wedge: a node with exactly one peer has its periodic parent re-evaluation
/// disabled, so if it misses its parent's attaching announce it is stranded as
/// a self-root until the parent's next periodic re-broadcast. The receive-path
/// re-push makes recovery event-driven: the stranded node's self-root announce
/// provokes its better-rooted parent to echo its real position straight back.
#[tokio::test]
async fn test_tree_announce_repushed_on_root_disagreement() {
    // Converge a 2-node tree: one node is root, the other its child.
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    // Identify which index is the root (smallest NodeAddr) and which is the
    // attached child — the topology is address-order dependent.
    let root_idx = if nodes[0].node.tree_state().is_root() {
        0
    } else {
        1
    };
    let child_idx = 1 - root_idx;

    let root_addr = *nodes[root_idx].node.node_addr();
    let child_addr = *nodes[child_idx].node.node_addr();

    // Sanity: before the disturbance the child is attached to the root.
    assert_eq!(
        nodes[child_idx].node.tree_state().root(),
        &root_addr,
        "child should start attached to the root"
    );
    assert!(
        !nodes[child_idx].node.tree_state().is_root(),
        "child should not start as its own root"
    );

    // Simulate the lost attaching announce: force the child back to self-root
    // AND drop its cached view of the root's tree position, as it would be if
    // it had never processed the root's attaching announce. The child's
    // advertised root is now itself, disagreeing with the root's view, and its
    // own periodic re-evaluation cannot recover it (single peer).
    nodes[child_idx].node.tree_state_mut().become_root(1000);
    nodes[child_idx]
        .node
        .tree_state_mut()
        .remove_peer(&root_addr);
    {
        let identity = nodes[child_idx].node.identity().clone();
        let decl_mut = nodes[child_idx].node.tree_state_mut().my_declaration_mut();
        sign_declaration(decl_mut, &identity).unwrap();
    }
    assert!(nodes[child_idx].node.tree_state().is_root());

    // Drain any packets the disturbance may have queued so the counters below
    // isolate the re-push.
    let _ = drain_all_packets(&mut nodes, false).await;

    // The stranded child announces its (self-root) position to its only peer,
    // the root. The root's advertised root differs from the child's, so the
    // root must re-push its current announce back.
    let root_sent_before = nodes[root_idx].node.metrics().tree.sent.get();
    nodes[child_idx]
        .node
        .send_tree_announce_to_peer(&root_addr)
        .await
        .unwrap();

    // Deliver the child's announce to the root and let the resulting re-push
    // (and the child's processing of it) settle.
    let _ = drain_all_packets(&mut nodes, false).await;

    // The root emitted at least one TreeAnnounce in response to the child's
    // root-disagreeing announce (the receive-path re-push).
    let root_sent_after = nodes[root_idx].node.metrics().tree.sent.get();
    assert!(
        root_sent_after > root_sent_before,
        "root should re-push its TreeAnnounce when a peer advertises a worse root \
         (sent before={}, after={})",
        root_sent_before,
        root_sent_after
    );

    // End state: the child has re-attached to the root rather than remaining a
    // stranded self-root.
    assert!(
        !nodes[child_idx].node.tree_state().is_root(),
        "child should have re-attached, not remained a self-root"
    );
    assert_eq!(
        nodes[child_idx].node.tree_state().root(),
        &root_addr,
        "child should have re-converged to the root"
    );
    let _ = child_addr;

    cleanup_nodes(&mut nodes).await;
}

// ===== Direct handler characterization tests =====
//
// These drive `handle_tree_announce` directly to pin the individual
// classification and validation arms that the aggregate convergence suite
// only exercises indirectly: the four validation rejects (addr-mismatch,
// sig-fail, stale, unknown-peer) and the self-root / loop-drop /
// same-parent ancestry-update transitions. `run_tree_test(2, ..)` supplies
// two handshaked peers (so the sender's pubkey is known); the transition
// tests then force the receiver's local tree state into the precise shape
// each arm requires — the same `tree_state_mut()` seam
// `test_tree_announce_repushed_on_root_disagreement` uses above.
//
// `make_node_addr(0)` is the all-zero address, strictly smaller than every
// randomly-generated real node address, so it is used as a synthetic global
// root that keeps forced ancestries valid (advertised root = path minimum).

/// A TreeAnnounce whose declared `node_addr` does not match the sending peer
/// must be rejected (addr-mismatch) before any state mutation. The addr-match
/// gate precedes signature verification, so a harvested-but-unrelated
/// signature is enough to reach it.
#[tokio::test]
async fn test_tree_announce_rejects_addr_mismatch() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let a_addr = *nodes[0].node.node_addr();

    let sig = nodes[0].node.identity().sign(&[0u8; 48]).to_byte_array();
    let bogus = make_node_addr(200);
    let declaration = ParentDeclaration::with_signature(bogus, bogus, 5, 2000, sig);
    let announce = TreeAnnounce::new(
        declaration,
        TreeCoordinate::from_addrs(vec![bogus]).unwrap(),
    );
    let encoded = announce.encode().unwrap();

    let mismatch_before = nodes[1].node.metrics().tree.addr_mismatch.get();
    let accepted_before = nodes[1].node.metrics().tree.accepted.get();
    let root_before = *nodes[1].node.tree_state().root();

    // Sender is the known peer a_addr, but the declaration claims `bogus`.
    nodes[1]
        .node
        .handle_tree_announce(&a_addr, &encoded[1..])
        .await;

    assert_eq!(
        nodes[1].node.metrics().tree.addr_mismatch.get(),
        mismatch_before + 1
    );
    assert_eq!(nodes[1].node.metrics().tree.accepted.get(), accepted_before);
    assert_eq!(*nodes[1].node.tree_state().root(), root_before);

    cleanup_nodes(&mut nodes).await;
}

/// A TreeAnnounce whose declared node_addr matches the sender but whose
/// signature does not verify under the sender's pubkey must be rejected
/// (sig-fail) without mutating tree state.
#[tokio::test]
async fn test_tree_announce_rejects_bad_signature() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let a_addr = *nodes[0].node.node_addr();

    // A valid A-signature, but over a *different* declaration, so verifying it
    // against the forged declaration's signing bytes fails.
    let mut signed_other = ParentDeclaration::new(a_addr, a_addr, 99, 88);
    sign_declaration(&mut signed_other, nodes[0].node.identity()).unwrap();
    let sig = *signed_other.signature().unwrap();
    let forged = ParentDeclaration::with_signature(a_addr, a_addr, 5, 2000, sig);
    let announce = TreeAnnounce::new(forged, TreeCoordinate::from_addrs(vec![a_addr]).unwrap());
    let encoded = announce.encode().unwrap();

    let sig_failed_before = nodes[1].node.metrics().tree.sig_failed.get();
    let accepted_before = nodes[1].node.metrics().tree.accepted.get();

    nodes[1]
        .node
        .handle_tree_announce(&a_addr, &encoded[1..])
        .await;

    assert_eq!(
        nodes[1].node.metrics().tree.sig_failed.get(),
        sig_failed_before + 1
    );
    assert_eq!(nodes[1].node.metrics().tree.accepted.get(), accepted_before);

    cleanup_nodes(&mut nodes).await;
}

/// Replaying a peer's already-known declaration verbatim (same sequence) is
/// not fresher, so `update_peer` reports no change and the announce is counted
/// stale and ignored rather than accepted.
#[tokio::test]
async fn test_tree_announce_stale_ignored() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let a_addr = *nodes[0].node.node_addr();

    let stored_decl = nodes[1]
        .node
        .tree_state()
        .peer_declaration(&a_addr)
        .expect("node 1 should hold A's declaration after convergence")
        .clone();
    let stored_coords = nodes[1]
        .node
        .tree_state()
        .peer_coords(&a_addr)
        .expect("node 1 should hold A's coordinates after convergence")
        .clone();
    let announce = TreeAnnounce::new(stored_decl, stored_coords);
    let encoded = announce.encode().unwrap();

    let stale_before = nodes[1].node.metrics().tree.stale.get();
    let accepted_before = nodes[1].node.metrics().tree.accepted.get();

    nodes[1]
        .node
        .handle_tree_announce(&a_addr, &encoded[1..])
        .await;

    assert_eq!(nodes[1].node.metrics().tree.stale.get(), stale_before + 1);
    assert_eq!(nodes[1].node.metrics().tree.accepted.get(), accepted_before);

    cleanup_nodes(&mut nodes).await;
}

/// A TreeAnnounce from a node that is not a known peer must be rejected
/// (unknown-peer) at the pubkey-lookup gate.
#[tokio::test]
async fn test_tree_announce_rejects_unknown_peer() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let unknown = make_node_addr(201);
    let sig = nodes[0].node.identity().sign(&[0u8; 48]).to_byte_array();
    let declaration = ParentDeclaration::with_signature(unknown, unknown, 1, 1000, sig);
    let announce = TreeAnnounce::new(
        declaration,
        TreeCoordinate::from_addrs(vec![unknown]).unwrap(),
    );
    let encoded = announce.encode().unwrap();

    let unknown_before = nodes[1].node.metrics().tree.unknown_peer.get();

    nodes[1]
        .node
        .handle_tree_announce(&unknown, &encoded[1..])
        .await;

    assert_eq!(
        nodes[1].node.metrics().tree.unknown_peer.get(),
        unknown_before + 1
    );

    cleanup_nodes(&mut nodes).await;
}

/// A non-root node whose only visible root is larger than its own address must
/// self-promote to root. P (the smaller-addr node) is forced into a child of
/// its larger peer L rooted at a synthetic smaller root; when L then announces
/// itself as its own (larger) root, P's smallest visible root becomes L, so P
/// promotes itself.
#[tokio::test]
async fn test_tree_announce_self_root_promotion() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    // P must be the smaller-addr node (the one that should win root); L larger.
    let (p_idx, l_idx) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let p_addr = *nodes[p_idx].node.node_addr();
    let l_addr = *nodes[l_idx].node.node_addr();
    let fake_root = make_node_addr(0);

    // Force P into a non-root child of L rooted at fake_root: coords
    // [P, L, fake_root]. P > fake_root, so recompute keeps it attached.
    {
        let ts = nodes[p_idx].node.tree_state_mut();
        ts.remove_peer(&l_addr);
        ts.update_peer(
            ParentDeclaration::new(l_addr, fake_root, 1, 1000),
            TreeCoordinate::from_addrs(vec![l_addr, fake_root]).unwrap(),
        );
        ts.set_parent(l_addr, 1, 1000, 1000);
        ts.recompute_coords();
    }
    {
        let identity = nodes[p_idx].node.identity().clone();
        let decl_mut = nodes[p_idx].node.tree_state_mut().my_declaration_mut();
        sign_declaration(decl_mut, &identity).unwrap();
    }
    assert!(!nodes[p_idx].node.tree_state().is_root());
    assert_eq!(*nodes[p_idx].node.tree_state().root(), fake_root);

    // L announces a fresh self-root (root = L > P).
    let mut decl = ParentDeclaration::self_root(l_addr, 5, 2000);
    sign_declaration(&mut decl, nodes[l_idx].node.identity()).unwrap();
    let announce = TreeAnnounce::new(decl, TreeCoordinate::from_addrs(vec![l_addr]).unwrap());
    let encoded = announce.encode().unwrap();

    let switched_before = nodes[p_idx].node.metrics().tree.parent_switches.get();
    nodes[p_idx]
        .node
        .handle_tree_announce(&l_addr, &encoded[1..])
        .await;

    assert!(
        nodes[p_idx].node.tree_state().is_root(),
        "P should self-promote to root when its only visible root is larger"
    );
    assert_eq!(*nodes[p_idx].node.tree_state().root(), p_addr);
    assert_eq!(
        nodes[p_idx].node.metrics().tree.parent_switches.get(),
        switched_before + 1
    );

    cleanup_nodes(&mut nodes).await;
}

/// When our current parent's freshly announced ancestry comes to contain us, a
/// loop has formed and the parent must be dropped. P is forced into a child of
/// Q rooted at a synthetic root; Q then announces an ancestry [Q, P, root] that
/// runs back through P, so P detects the loop and (having no alternative) falls
/// back to self-root.
#[tokio::test]
async fn test_tree_announce_loop_detection_drops_parent() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let (p_idx, q_idx) = (0, 1);
    let p_addr = *nodes[p_idx].node.node_addr();
    let q_addr = *nodes[q_idx].node.node_addr();
    let root = make_node_addr(0);

    // Force P into a child of Q rooted at `root`: coords [P, Q, root].
    {
        let ts = nodes[p_idx].node.tree_state_mut();
        ts.remove_peer(&q_addr);
        ts.update_peer(
            ParentDeclaration::new(q_addr, root, 1, 1000),
            TreeCoordinate::from_addrs(vec![q_addr, root]).unwrap(),
        );
        ts.set_parent(q_addr, 1, 1000, 1000);
        ts.recompute_coords();
    }
    {
        let identity = nodes[p_idx].node.identity().clone();
        let decl_mut = nodes[p_idx].node.tree_state_mut().my_declaration_mut();
        sign_declaration(decl_mut, &identity).unwrap();
    }
    assert!(!nodes[p_idx].node.tree_state().is_root());
    assert_eq!(
        nodes[p_idx].node.tree_state().my_declaration().parent_id(),
        &q_addr
    );

    // Q announces an ancestry that now runs through P (declaring P as its own
    // parent): [Q, P, root]. Adopting it would form a loop.
    let mut decl = ParentDeclaration::new(q_addr, p_addr, 5, 2000);
    sign_declaration(&mut decl, nodes[q_idx].node.identity()).unwrap();
    let announce = TreeAnnounce::new(
        decl,
        TreeCoordinate::from_addrs(vec![q_addr, p_addr, root]).unwrap(),
    );
    let encoded = announce.encode().unwrap();

    let loop_before = nodes[p_idx].node.metrics().tree.loop_detected.get();
    nodes[p_idx]
        .node
        .handle_tree_announce(&q_addr, &encoded[1..])
        .await;

    assert_eq!(
        nodes[p_idx].node.metrics().tree.loop_detected.get(),
        loop_before + 1
    );
    // No alternative parent remains, so P falls back to self-root.
    assert!(nodes[p_idx].node.tree_state().is_root());
    assert_eq!(*nodes[p_idx].node.tree_state().root(), p_addr);

    cleanup_nodes(&mut nodes).await;
}

/// When our parent keeps the same root and depth but swaps a mid-chain
/// ancestor, we keep the parent yet must recompute our coordinates and
/// re-announce (the `old_addrs != new_addrs` gate). P is forced into
/// [P, Q, mid, root]; Q re-announces [Q, new_mid, root], leaving root and depth
/// unchanged while replacing the interior ancestor.
#[tokio::test]
async fn test_tree_announce_same_parent_ancestry_update() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;

    let (p_idx, q_idx) = (0, 1);
    let q_addr = *nodes[q_idx].node.node_addr();
    let root = make_node_addr(0);
    let mid = make_node_addr(1);
    let new_mid = make_node_addr(2);

    // Force P into a child of Q rooted at `root` via `mid`: [P, Q, mid, root].
    {
        let ts = nodes[p_idx].node.tree_state_mut();
        ts.remove_peer(&q_addr);
        ts.update_peer(
            ParentDeclaration::new(q_addr, mid, 1, 1000),
            TreeCoordinate::from_addrs(vec![q_addr, mid, root]).unwrap(),
        );
        ts.set_parent(q_addr, 1, 1000, 1000);
        ts.recompute_coords();
    }
    {
        let identity = nodes[p_idx].node.identity().clone();
        let decl_mut = nodes[p_idx].node.tree_state_mut().my_declaration_mut();
        sign_declaration(decl_mut, &identity).unwrap();
    }
    let depth_before = nodes[p_idx].node.tree_state().my_coords().depth();
    assert_eq!(
        nodes[p_idx].node.tree_state().my_declaration().parent_id(),
        &q_addr
    );

    // Q keeps root and depth but swaps its mid-chain ancestor mid -> new_mid.
    let mut decl = ParentDeclaration::new(q_addr, new_mid, 5, 2000);
    sign_declaration(&mut decl, nodes[q_idx].node.identity()).unwrap();
    let announce = TreeAnnounce::new(
        decl,
        TreeCoordinate::from_addrs(vec![q_addr, new_mid, root]).unwrap(),
    );
    let encoded = announce.encode().unwrap();

    let ancestry_before = nodes[p_idx].node.metrics().tree.ancestry_changed.get();
    nodes[p_idx]
        .node
        .handle_tree_announce(&q_addr, &encoded[1..])
        .await;

    assert_eq!(
        nodes[p_idx].node.metrics().tree.ancestry_changed.get(),
        ancestry_before + 1
    );
    // Same parent, same depth, but the recomputed path now runs through new_mid.
    assert_eq!(
        nodes[p_idx].node.tree_state().my_declaration().parent_id(),
        &q_addr
    );
    assert_eq!(
        nodes[p_idx].node.tree_state().my_coords().depth(),
        depth_before
    );
    let path: Vec<NodeAddr> = nodes[p_idx]
        .node
        .tree_state()
        .my_coords()
        .node_addrs()
        .copied()
        .collect();
    assert!(
        path.contains(&new_mid),
        "recomputed path should include the swapped-in ancestor"
    );
    assert!(
        !path.contains(&mid),
        "old mid-chain ancestor should be gone from the recomputed path"
    );

    cleanup_nodes(&mut nodes).await;
}
