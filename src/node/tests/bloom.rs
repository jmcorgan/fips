//! Bloom filter integration tests.
//!
//! Verifies that bloom filters are exchanged between peers and that
//! filter propagation works correctly across multi-hop networks.

use super::spanning_tree::*;
use super::*;

/// Verify that all peer pairs have exchanged bloom filters and each
/// peer's inbound filter contains the peer's own node_addr.
///
/// Also verifies propagation: for each node, check that destinations
/// reachable through a peer's filter include the peer's direct neighbors.
fn verify_bloom_filter_exchange(nodes: &[TestNode], edges: &[(usize, usize)]) {
    // Build adjacency for hop distance computation
    let n = nodes.len();
    let mut adj = vec![vec![]; n];
    for &(i, j) in edges {
        adj[i].push(j);
        adj[j].push(i);
    }

    // Every peer pair must have exchanged filters
    for &(i, j) in edges {
        let j_addr = *nodes[j].node.node_addr();
        let i_addr = *nodes[i].node.node_addr();

        // Node i should have a filter from node j
        let peer_j = nodes[i]
            .node
            .get_peer(&j_addr)
            .unwrap_or_else(|| panic!("Node {} should have peer {}", i, j));
        let filter_from_j = peer_j.inbound_filter().unwrap_or_else(|| {
            panic!(
                "Node {} should have inbound filter from node {} (addr={})",
                i, j, j_addr
            )
        });

        // The filter from j must contain j's own node_addr
        assert!(
            filter_from_j.contains(&j_addr),
            "Node {}'s filter from node {} should contain node {}'s addr",
            i,
            j,
            j
        );

        // Node j should have a filter from node i
        let peer_i = nodes[j]
            .node
            .get_peer(&i_addr)
            .unwrap_or_else(|| panic!("Node {} should have peer {}", j, i));
        let filter_from_i = peer_i.inbound_filter().unwrap_or_else(|| {
            panic!(
                "Node {} should have inbound filter from node {} (addr={})",
                j, i, i_addr
            )
        });

        // The filter from i must contain i's own node_addr
        assert!(
            filter_from_i.contains(&i_addr),
            "Node {}'s filter from node {} should contain node {}'s addr",
            j,
            i,
            i
        );
    }

    // Verify propagation: each node's filter from a peer should
    // contain addresses of the peer's direct neighbors (which were
    // merged into the peer's outgoing filter).
    for &(i, j) in edges {
        let j_addr = *nodes[j].node.node_addr();
        let peer_j = nodes[i].node.get_peer(&j_addr).unwrap();
        let filter = peer_j.inbound_filter().unwrap();

        // All of j's direct neighbors (except i) should be in j's filter to i
        for &neighbor_idx in &adj[j] {
            if neighbor_idx == i {
                continue; // j excludes i's direction from i's filter
            }
            let neighbor_addr = *nodes[neighbor_idx].node.node_addr();
            assert!(
                filter.contains(&neighbor_addr),
                "Node {}'s filter from node {} should contain node {}'s neighbor {} (addr={})",
                i,
                j,
                j,
                neighbor_idx,
                neighbor_addr
            );
        }
    }
}

/// 10-node random graph: tree + bloom filter convergence.
#[tokio::test]
async fn test_bloom_filter_10_nodes() {
    let edges = generate_random_edges(10, 20, 123);
    let mut nodes = run_tree_test(10, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_bloom_filter_exchange(&nodes, &edges);
    cleanup_nodes(&mut nodes).await;
}

/// 5-node star: hub node's filter should contain all spokes.
#[tokio::test]
async fn test_bloom_filter_star() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (0, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_bloom_filter_exchange(&nodes, &edges);

    // Hub (node 0) sends each spoke a filter containing the other spokes
    let hub_addr = *nodes[0].node.node_addr();
    for spoke in 1..5 {
        let peer = nodes[spoke].node.get_peer(&hub_addr).unwrap();
        let filter = peer.inbound_filter().unwrap();

        // Filter from hub should contain all OTHER spokes
        for (other, other_node) in nodes[1..5].iter().enumerate() {
            let other = other + 1; // adjust for slice offset
            if other == spoke {
                continue;
            }
            let other_addr = *other_node.node.node_addr();
            assert!(
                filter.contains(&other_addr),
                "Spoke {}'s filter from hub should contain spoke {} (addr={})",
                spoke,
                other,
                other_addr
            );
        }
    }

    cleanup_nodes(&mut nodes).await;
}

/// 8-node chain: verify full propagation.
///
/// Chain: 0-1-2-3-4-5-6-7. Each node's outgoing filter is the merge
/// of its own address plus all peer inbound filters (excluding the
/// destination peer). This means entries propagate through the entire
/// chain: node 1 merges node 2's filter, which contains node 3's
/// entries, and so on. Both endpoints should see all other nodes.
#[tokio::test]
async fn test_bloom_filter_chain_propagation() {
    let edges: Vec<(usize, usize)> =
        vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)];
    let mut nodes = run_tree_test(8, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_bloom_filter_exchange(&nodes, &edges);

    let addrs: Vec<NodeAddr> = nodes.iter().map(|tn| *tn.node.node_addr()).collect();

    // Node 0's filter from node 1 should contain node 1 and its
    // immediate neighbor node 2 (node 1 directly merges node 2's filter).
    let peer_1 = nodes[0].node.get_peer(&addrs[1]).unwrap();
    let filter = peer_1.inbound_filter().unwrap();
    assert!(filter.contains(&addrs[1]), "Should contain node 1 (self)");
    assert!(
        filter.contains(&addrs[2]),
        "Should contain node 2 (1-hop neighbor of node 1)"
    );

    // Entries propagate through the full chain because each
    // intermediate node merges its peer's filter into its outgoing
    // filter. Verify all nodes are reachable from the endpoints.
    for (i, addr) in addrs[2..8].iter().enumerate() {
        assert!(
            filter.contains(addr),
            "Node 0's filter from node 1 should contain node {} \
             (chain merge propagation)",
            i + 2
        );
    }

    // Verify symmetric: node 7's filter from node 6 should contain all
    for i in 0..6 {
        let peer_6 = nodes[7].node.get_peer(&addrs[6]).unwrap();
        let filter_6 = peer_6.inbound_filter().unwrap();
        assert!(
            filter_6.contains(&addrs[i]),
            "Node 7's filter from node 6 should contain node {} \
             (chain merge propagation)",
            i
        );
    }

    cleanup_nodes(&mut nodes).await;
}

/// 5-node ring: every node should see all others (all within 2-hop reach).
#[tokio::test]
async fn test_bloom_filter_ring() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_bloom_filter_exchange(&nodes, &edges);

    // In a 5-node ring, each node has 2 peers. Through each peer,
    // the other 3 nodes are at most 2 hops away. So every node should
    // be reachable via at least one peer's filter.
    for i in 0..5 {
        for j in 0..5 {
            if i == j {
                continue;
            }
            let target_addr = *nodes[j].node.node_addr();
            let reachable = nodes[i]
                .node
                .peers()
                .any(|peer| peer.may_reach(&target_addr));
            assert!(
                reachable,
                "Node {} should see node {} as reachable via at least one peer's filter",
                i, j
            );
        }
    }

    cleanup_nodes(&mut nodes).await;
}

/// 100-node random graph: bloom filter exchange at scale.
#[tokio::test]
async fn test_bloom_filter_convergence_100_nodes() {
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_bloom_filter_exchange(&nodes, &edges);
    cleanup_nodes(&mut nodes).await;
}
