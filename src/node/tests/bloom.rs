//! Bloom filter integration tests.
//!
//! Verifies that bloom filters are exchanged between all peers and that
//! filter content propagates only through tree edges (tree-only propagation).

use super::spanning_tree::*;
use super::*;

/// Derive the tree edges from the converged spanning tree state.
///
/// For each non-root node, finds the parent relationship and returns
/// the corresponding edge as (child_index, parent_index).
fn get_tree_edges(nodes: &[TestNode]) -> Vec<(usize, usize)> {
    let mut edges = Vec::new();
    for (i, tn) in nodes.iter().enumerate() {
        let ts = tn.node.tree_state();
        if !ts.is_root() {
            let parent_addr = ts.my_declaration().parent_id();
            if let Some(j) = nodes
                .iter()
                .position(|n| n.node.node_addr() == parent_addr)
            {
                edges.push((i, j));
            }
        }
    }
    edges
}

/// Verify that all peer pairs on the given edges have exchanged bloom
/// filters and each peer's inbound filter contains the peer's own
/// node_addr.
fn verify_filter_exchange(nodes: &[TestNode], edges: &[(usize, usize)]) {
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
}

/// Verify propagation along tree edges: each node's filter from a tree
/// peer should contain addresses of the peer's tree neighbors (which
/// were merged into the peer's outgoing filter via tree-only propagation).
fn verify_tree_propagation(nodes: &[TestNode], tree_edges: &[(usize, usize)]) {
    let n = nodes.len();
    let mut tree_adj = vec![vec![]; n];
    for &(i, j) in tree_edges {
        tree_adj[i].push(j);
        tree_adj[j].push(i);
    }

    for &(i, j) in tree_edges {
        let j_addr = *nodes[j].node.node_addr();
        let peer_j = nodes[i].node.get_peer(&j_addr).unwrap();
        let filter = peer_j.inbound_filter().unwrap();

        // All of j's tree neighbors (except i) should be in j's filter to i
        for &neighbor_idx in &tree_adj[j] {
            if neighbor_idx == i {
                continue; // j excludes i's direction from i's filter
            }
            let neighbor_addr = *nodes[neighbor_idx].node.node_addr();
            assert!(
                filter.contains(&neighbor_addr),
                "Node {}'s filter from node {} should contain node {}'s tree neighbor {} (addr={})",
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
    // All peers exchange filters
    verify_filter_exchange(&nodes, &edges);
    // Content propagation only along tree edges
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);
    print_filter_cardinality(&nodes);
    cleanup_nodes(&mut nodes).await;
}

/// 5-node star: hub node's filter should contain all spokes.
#[tokio::test]
async fn test_bloom_filter_star() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (0, 3), (0, 4)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);

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
/// of its own address plus all tree peer inbound filters (excluding the
/// destination peer). This means entries propagate through the entire
/// chain: node 1 merges node 2's filter, which contains node 3's
/// entries, and so on. Both endpoints should see all other nodes.
#[tokio::test]
async fn test_bloom_filter_chain_propagation() {
    let edges: Vec<(usize, usize)> =
        vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)];
    let mut nodes = run_tree_test(8, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);

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

/// 5-node ring: every node should see all others via peer filters.
///
/// All peers receive filters. Content propagates through the tree
/// (N-1=4 tree edges). Every node is reachable through at least one
/// peer's filter.
#[tokio::test]
async fn test_bloom_filter_ring() {
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 0)];
    let mut nodes = run_tree_test(5, &edges, false).await;
    verify_tree_convergence(&nodes);
    // All peers (including the non-tree edge) receive filters
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);

    // Every node should be reachable via at least one peer's filter
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

/// Print filter cardinality for all peer relationships (diagnostic helper).
///
/// Useful with `--nocapture` to inspect filter sizes and tree/mesh distinction.
fn print_filter_cardinality(nodes: &[TestNode]) {
    println!("\n  === Filter Cardinality ===");
    for (i, tn) in nodes.iter().enumerate() {
        for (j, other) in nodes.iter().enumerate() {
            if i == j {
                continue;
            }
            let addr = *other.node.node_addr();
            if let Some(peer) = tn.node.get_peer(&addr)
                && let Some(filter) = peer.inbound_filter()
            {
                let is_tree = tn.node.is_tree_peer(&addr);
                println!(
                    "  n{} <- n{}: est={:.1} set_bits={} fill={:.1}% tree={}",
                    i,
                    j,
                    filter.estimated_count(),
                    filter.count_ones(),
                    filter.fill_ratio() * 100.0,
                    is_tree,
                );
            }
        }
    }
}

/// Compute the set of node indices in a subtree rooted at `subtree_root`,
/// given a tree adjacency list and the actual root of the whole tree.
fn collect_subtree(
    subtree_root: usize,
    parent: Option<usize>,
    tree_adj: &[Vec<usize>],
) -> Vec<usize> {
    let mut result = vec![subtree_root];
    for &neighbor in &tree_adj[subtree_root] {
        if Some(neighbor) != parent {
            result.extend(collect_subtree(neighbor, Some(subtree_root), tree_adj));
        }
    }
    result
}

/// 7-node tree: verify split-horizon asymmetry between upward and downward filters.
///
/// Creates a pure tree topology and verifies that:
/// - Upward filters (child→parent) contain only the child's subtree
/// - Downward filters (parent→child) contain only the complement
/// - Cardinality estimates match expected subtree sizes
///
/// The tree structure formed depends on which node gets the lowest NodeAddr
/// (becomes root), but the split-horizon property holds regardless.
#[tokio::test]
async fn test_bloom_filter_split_horizon() {
    // Pure tree: 7 nodes, 6 edges
    let edges: Vec<(usize, usize)> =
        vec![(0, 1), (0, 2), (1, 3), (1, 4), (2, 5), (5, 6)];
    let mut nodes = run_tree_test(7, &edges, false).await;
    verify_tree_convergence(&nodes);
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);

    let addrs: Vec<NodeAddr> = nodes.iter().map(|tn| *tn.node.node_addr()).collect();

    // Build the actual tree adjacency from converged state
    let n = nodes.len();
    let mut tree_adj = vec![vec![]; n];
    for &(child, parent) in &tree_edges {
        tree_adj[child].push(parent);
        tree_adj[parent].push(child);
    }

    print_filter_cardinality(&nodes);

    // For each tree edge (child, parent), verify split-horizon:
    // - child's filter to parent contains child's subtree only
    // - parent's filter to child contains the complement only
    for &(child_idx, parent_idx) in &tree_edges {
        let child_subtree = collect_subtree(child_idx, Some(parent_idx), &tree_adj);
        let complement: Vec<usize> = (0..n)
            .filter(|i| !child_subtree.contains(i))
            .collect();

        // --- Upward filter: child → parent ---
        // This is stored as parent's inbound filter from child
        let filter_up = nodes[parent_idx]
            .node
            .get_peer(&addrs[child_idx])
            .unwrap()
            .inbound_filter()
            .unwrap();

        // Should contain all nodes in child's subtree
        for &idx in &child_subtree {
            assert!(
                filter_up.contains(&addrs[idx]),
                "Upward filter (n{}→n{}): should contain subtree member n{} but doesn't",
                child_idx, parent_idx, idx
            );
        }

        // Should NOT contain nodes in the complement
        for &idx in &complement {
            assert!(
                !filter_up.contains(&addrs[idx]),
                "Upward filter (n{}→n{}): should NOT contain complement member n{} but does",
                child_idx, parent_idx, idx
            );
        }

        // Cardinality should match subtree size
        let up_est = filter_up.estimated_count();
        assert!(
            (up_est - child_subtree.len() as f64).abs() < 1.5,
            "Upward filter (n{}→n{}): expected ~{} entries, got {:.1}",
            child_idx, parent_idx, child_subtree.len(), up_est
        );

        // --- Downward filter: parent → child ---
        // This is stored as child's inbound filter from parent
        let filter_down = nodes[child_idx]
            .node
            .get_peer(&addrs[parent_idx])
            .unwrap()
            .inbound_filter()
            .unwrap();

        // Should contain all nodes in the complement
        for &idx in &complement {
            assert!(
                filter_down.contains(&addrs[idx]),
                "Downward filter (n{}→n{}): should contain complement member n{} but doesn't",
                parent_idx, child_idx, idx
            );
        }

        // Should NOT contain nodes in child's subtree (except: split-horizon
        // excludes the child's direction, but child itself is NOT in parent's
        // outgoing filter to child — parent merges child's filter into filters
        // for OTHER peers, not back to child)
        for &idx in &child_subtree {
            assert!(
                !filter_down.contains(&addrs[idx]),
                "Downward filter (n{}→n{}): should NOT contain subtree member n{} but does",
                parent_idx, child_idx, idx
            );
        }

        // Cardinality should match complement size
        let down_est = filter_down.estimated_count();
        assert!(
            (down_est - complement.len() as f64).abs() < 1.5,
            "Downward filter (n{}→n{}): expected ~{} entries, got {:.1}",
            parent_idx, child_idx, complement.len(), down_est
        );

        // Together, subtree + complement = all nodes
        assert_eq!(
            child_subtree.len() + complement.len(),
            n,
            "Subtree + complement should cover all {} nodes",
            n
        );
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
    verify_filter_exchange(&nodes, &edges);
    let tree_edges = get_tree_edges(&nodes);
    verify_tree_propagation(&nodes, &tree_edges);
    print_filter_cardinality(&nodes);
    cleanup_nodes(&mut nodes).await;
}
