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
            if let Some(j) = nodes.iter().position(|n| n.node.node_addr() == parent_addr) {
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
    let edges: Vec<(usize, usize)> = vec![(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7)];
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
                    "  n{} <- n{}: est={} set_bits={} fill={:.1}% tree={}",
                    i,
                    j,
                    match filter.estimated_count(f64::INFINITY) {
                        Some(n) => format!("{:.1}", n),
                        None => "saturated".to_string(),
                    },
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
    let edges: Vec<(usize, usize)> = vec![(0, 1), (0, 2), (1, 3), (1, 4), (2, 5), (5, 6)];
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
        let complement: Vec<usize> = (0..n).filter(|i| !child_subtree.contains(i)).collect();

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
                child_idx,
                parent_idx,
                idx
            );
        }

        // Should NOT contain nodes in the complement
        for &idx in &complement {
            assert!(
                !filter_up.contains(&addrs[idx]),
                "Upward filter (n{}→n{}): should NOT contain complement member n{} but does",
                child_idx,
                parent_idx,
                idx
            );
        }

        // Cardinality should match subtree size
        let up_est = filter_up
            .estimated_count(f64::INFINITY)
            .expect("upward filter should not be saturated in tree convergence test");
        assert!(
            (up_est - child_subtree.len() as f64).abs() < 1.5,
            "Upward filter (n{}→n{}): expected ~{} entries, got {:.1}",
            child_idx,
            parent_idx,
            child_subtree.len(),
            up_est
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
                parent_idx,
                child_idx,
                idx
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
                parent_idx,
                child_idx,
                idx
            );
        }

        // Cardinality should match complement size
        let down_est = filter_down
            .estimated_count(f64::INFINITY)
            .expect("downward filter should not be saturated in tree convergence test");
        assert!(
            (down_est - complement.len() as f64).abs() < 1.5,
            "Downward filter (n{}→n{}): expected ~{} entries, got {:.1}",
            parent_idx,
            child_idx,
            complement.len(),
            down_est
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

/// Each peer's inbound filter contributes exactly once, independent of
/// tree-declaration state.
///
/// Under all-peers union semantics there is no parent/child gating and no
/// `peer_declaration` lookup, so a stale or contradictory declaration
/// cache cannot cause a peer's bloom cardinality to be folded twice. This
/// retains the spirit of the old parent-double-count regression: we set up
/// the same stale-cache scenario (the cached `peer_declaration(P)` still
/// names US as P's parent) and assert the estimate reflects each filter
/// counted once, not the double-count fingerprint.
#[test]
fn compute_mesh_size_counts_each_peer_filter_once() {
    use crate::peer::ActivePeer;
    use crate::proto::bloom::BloomFilter;
    use crate::proto::stp::ParentDeclaration;

    let mut node = make_node();
    let my_addr = *node.tree_state().my_node_addr();

    // Generate a parent identity strictly less than my_addr so the
    // tree_state defensive check (my_node_addr > parent_root) accepts
    // the extension; otherwise recompute_coords would demote us back
    // to self-root and is_root() would stay true.
    let (parent_identity, parent_addr) = loop {
        let candidate = make_peer_identity();
        let addr = *candidate.node_addr();
        if addr < my_addr {
            break (candidate, addr);
        }
    };
    let mut parent_peer = ActivePeer::new(parent_identity, LinkId::new(1), 0);
    let mut parent_filter = BloomFilter::new();
    for i in 0..5u8 {
        let mut bytes = [0u8; 16];
        bytes[0] = 0x80 | i; // distinct namespace
        parent_filter.insert(&NodeAddr::from_bytes(bytes));
    }
    parent_peer.update_filter(parent_filter, 1, 0);
    node.peers.insert(parent_addr, parent_peer);

    // Inject legitimate child Q with a 3-entry inbound filter.
    let child_identity = make_peer_identity();
    let child_addr = *child_identity.node_addr();
    let mut child_peer = ActivePeer::new(child_identity, LinkId::new(2), 0);
    let mut child_filter = BloomFilter::new();
    for i in 0..3u8 {
        let mut bytes = [0u8; 16];
        bytes[0] = 0xC0 | i;
        child_filter.insert(&NodeAddr::from_bytes(bytes));
    }
    child_peer.update_filter(child_filter, 1, 0);
    node.peers.insert(child_addr, child_peer);

    // Seed parent ancestry first so recompute_coords can extend it and
    // flip is_root() to false; child ancestry is for completeness.
    let parent_ancestry = crate::proto::stp::TreeCoordinate::root_with_meta(parent_addr, 1, 1);
    let child_ancestry = crate::proto::stp::TreeCoordinate::root_with_meta(child_addr, 1, 1);
    // Inject the stale-cache scenario: peer_declaration(P) still names
    // US (M) as P's parent (the pre-switch advert that the cache hasn't
    // refreshed yet). Q is a legitimate child also naming M as parent.
    // Under all-peers semantics these declarations no longer affect the
    // estimate at all.
    let parent_decl_stale = ParentDeclaration::new(parent_addr, my_addr, 1, 1);
    let child_decl = ParentDeclaration::new(child_addr, my_addr, 1, 1);
    node.tree_state_mut()
        .update_peer(parent_decl_stale, parent_ancestry);
    node.tree_state_mut()
        .update_peer(child_decl, child_ancestry);

    // Switch our parent to P and recompute coords so root flips off self.
    node.tree_state_mut().set_parent(parent_addr, 2, 1, 1);
    node.tree_state_mut().recompute_coords();
    assert!(
        !node.tree_state().is_root(),
        "test setup broken: node should not be its own root after parent switch"
    );

    node.compute_mesh_size();

    let estimate = node
        .estimated_mesh_size()
        .expect("estimator should produce a value with filter data present");

    // Each filter counted once: 1 (self) + 5 (P) + 3 (Q) = 9.
    // A double-count of P (the old declaration-cache bug fingerprint)
    // would land near 1 + 2*5 + 3 = 14.
    // The estimator's log-based math rounds, so allow +/-1 tolerance.
    let diff = (estimate as i64 - 9).abs();
    assert!(
        diff <= 1,
        "expected mesh-size estimate ~9 (1+5+3), got {} (double-count fingerprint is ~14)",
        estimate
    );
}

/// Overlapping peer inbound filters must be OR-unioned, not summed.
///
/// Two connected peers share several NodeAddrs (plus a few distinct ones
/// each). The naive sum of per-filter cardinalities would over-count the
/// shared entries; the union estimate must instead approximate the number
/// of *distinct* addresses across both filters (plus self). Under all-peers
/// semantics the union folds in every connected peer regardless of tree
/// role, so no parent/child wiring is needed — this asserts the
/// overlap-dedup property directly on the union result that
/// `estimated_mesh_size` carries.
#[test]
fn compute_mesh_size_unions_overlapping_filters() {
    use crate::peer::ActivePeer;
    use crate::proto::bloom::BloomFilter;

    let mut node = make_node();

    // Build the set of addresses. SHARED appear in both filters; the
    // distinct sets appear in only one each.
    let mk = |hi: u8, lo: u8| {
        let mut bytes = [0u8; 16];
        bytes[0] = hi;
        bytes[1] = lo;
        NodeAddr::from_bytes(bytes)
    };
    let shared: Vec<NodeAddr> = (0..6u8).map(|i| mk(0x10, i)).collect();
    let peer_a_only: Vec<NodeAddr> = (0..3u8).map(|i| mk(0x20, i)).collect();
    let peer_b_only: Vec<NodeAddr> = (0..3u8).map(|i| mk(0x30, i)).collect();

    // Distinct addresses across the union: shared + peer_a_only +
    // peer_b_only + self = 6 + 3 + 3 + 1 = 13. The naive sum of the two
    // filters' cardinalities would be (6+3) + (6+3) + 1 = 19.
    let distinct = shared.len() + peer_a_only.len() + peer_b_only.len() + 1; // 13
    let naive_sum = (shared.len() + peer_a_only.len()) + (shared.len() + peer_b_only.len()) + 1; // 19

    // Peer A with shared + peer_a_only.
    let peer_a_identity = make_peer_identity();
    let peer_a_addr = *peer_a_identity.node_addr();
    let mut peer_a = ActivePeer::new(peer_a_identity, LinkId::new(1), 0);
    let mut filter_a = BloomFilter::new();
    for addr in shared.iter().chain(peer_a_only.iter()) {
        filter_a.insert(addr);
    }
    peer_a.update_filter(filter_a, 1, 0);
    node.peers.insert(peer_a_addr, peer_a);

    // Peer B with a filter that overlaps A's on `shared`.
    let peer_b_identity = make_peer_identity();
    let peer_b_addr = *peer_b_identity.node_addr();
    let mut peer_b = ActivePeer::new(peer_b_identity, LinkId::new(2), 0);
    let mut filter_b = BloomFilter::new();
    for addr in shared.iter().chain(peer_b_only.iter()) {
        filter_b.insert(addr);
    }
    peer_b.update_filter(filter_b, 1, 0);
    node.peers.insert(peer_b_addr, peer_b);

    node.compute_mesh_size();

    let estimate =
        node.estimated_mesh_size()
            .expect("estimator should produce a value with filter data present") as i64;

    // The union estimate should approximate the distinct count (13), not
    // the naive sum (19). Bloom cardinality estimation rounds, so allow a
    // small absolute tolerance, and require we are clearly below the sum.
    let diff = (estimate - distinct as i64).abs();
    assert!(
        diff <= 2,
        "expected union mesh-size estimate ~{} (distinct addrs), got {}",
        distinct,
        estimate
    );
    assert!(
        estimate < naive_sum as i64,
        "estimate {} must be below the naive sum {} (overlap should be deduplicated)",
        estimate,
        naive_sum
    );
}

/// Flap-damping: the estimate survives a parent switch when a healthy
/// cross-link carries the upward coverage.
///
/// Under the old tree-only union, the upward leg of the estimate hinged
/// entirely on the current parent's filter; dropping the parent (a parent
/// switch transient, before the new parent's filter converges) collapsed
/// the estimate to self + children. Under all-peers semantics a cross-link
/// peer whose split-horizon `inbound_filter` carries the same upward
/// coverage keeps the union nearly intact across the drop. This builds a
/// node with a parent and one healthy cross-link, records the estimate,
/// removes the parent, and asserts the estimate does not collapse.
#[test]
fn compute_mesh_size_stable_across_parent_drop_with_cross_link() {
    use crate::peer::ActivePeer;
    use crate::proto::bloom::BloomFilter;

    let mut node = make_node();

    let mk = |hi: u8, lo: u8| {
        let mut bytes = [0u8; 16];
        bytes[0] = hi;
        bytes[1] = lo;
        NodeAddr::from_bytes(bytes)
    };

    // Upward coverage: the set of addresses reachable through the rest of
    // the mesh (everything outside our local subtree). Both the parent and
    // a healthy cross-link advertise this under split-horizon propagation.
    let upward: Vec<NodeAddr> = (0..12u8).map(|i| mk(0x40, i)).collect();
    // The cross-link additionally knows a couple of addresses of its own.
    let cross_extra: Vec<NodeAddr> = (0..2u8).map(|i| mk(0x50, i)).collect();

    // Parent P: carries the upward coverage.
    let parent_identity = make_peer_identity();
    let parent_addr = *parent_identity.node_addr();
    let mut parent_peer = ActivePeer::new(parent_identity, LinkId::new(1), 0);
    let mut parent_filter = BloomFilter::new();
    for addr in &upward {
        parent_filter.insert(addr);
    }
    parent_peer.update_filter(parent_filter, 1, 0);
    node.peers.insert(parent_addr, parent_peer);

    // Cross-link X: a non-tree peer whose split-horizon filter also carries
    // the upward coverage (plus a little of its own).
    let cross_identity = make_peer_identity();
    let cross_addr = *cross_identity.node_addr();
    let mut cross_peer = ActivePeer::new(cross_identity, LinkId::new(2), 0);
    let mut cross_filter = BloomFilter::new();
    for addr in upward.iter().chain(cross_extra.iter()) {
        cross_filter.insert(addr);
    }
    cross_peer.update_filter(cross_filter, 1, 0);
    node.peers.insert(cross_addr, cross_peer);

    // Baseline estimate with both peers present.
    node.compute_mesh_size();
    let before =
        node.estimated_mesh_size()
            .expect("estimator should produce a value with filter data present") as i64;

    // Simulate a parent switch transient: the old parent is dropped before
    // the new parent's filter has converged. The cross-link remains.
    node.peers.remove(&parent_addr);
    node.compute_mesh_size();
    let after = node
        .estimated_mesh_size()
        .expect("estimator should still produce a value via the cross-link") as i64;

    // The estimate must not collapse: the cross-link still holds the upward
    // coverage. Old tree-only behavior would have lost the entire upward
    // leg (~12 addrs) and dropped to roughly self alone. Allow a small
    // tolerance for bloom rounding and the cross-link's couple extra bits.
    let diff = (before - after).abs();
    assert!(
        diff <= 2,
        "mesh-size estimate collapsed across parent drop: before={before}, after={after} \
         (cross-link should preserve upward coverage)"
    );
}

/// 100-node random graph: bloom filter exchange at scale.
#[tokio::test]
async fn test_bloom_filter_convergence_100_nodes() {
    let _guard = lock_large_network_test().await;

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

// ===== Outgoing filter re-announce on a tree-peer flip =====
//
// These tests read only what M actually sent (`last_sent_filter`, written
// after a successful send) or what M has marked (`needs_update`). Recomputing
// an outgoing filter would read live peer state and bypass the marking under
// test, so none of them does.

use crate::node::tree::sign_declaration;
use crate::proto::bloom::{BloomFilter, FilterAnnounce};
use crate::proto::stp::{ParentDeclaration, TreeAnnounce, TreeCoordinate};

/// Three loopback nodes, P -- M -- C, with M's tree view forced so that P is
/// M's parent and C either names M as parent (a child) or names an unrelated
/// node (not a tree peer).
struct FlipFixture {
    nodes: Vec<TestNode>,
    m: NodeAddr,
    p: NodeAddr,
    c: NodeAddr,
    root: NodeAddr,
    fake: NodeAddr,
}

/// Index of M in `FlipFixture::nodes`.
const M: usize = 1;
/// Index of C in `FlipFixture::nodes`.
const C: usize = 2;

/// Synthetic address carried in C's filter and in no real one.
fn marker() -> NodeAddr {
    make_node_addr(0xab)
}

/// Build the fixture and flush whatever convergence left pending at M.
///
/// With `child_start`, C's stored declaration names M as parent; otherwise it
/// names `fake`. Every stored declaration uses sequence 1, so the sequence-5
/// announces from `deliver_tree_announce` are fresher.
async fn flip_fixture(child_start: bool) -> FlipFixture {
    let nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    let p = *nodes[0].node.node_addr();
    let m = *nodes[M].node.node_addr();
    let c = *nodes[C].node.node_addr();
    // All zero bytes: smaller than any real address, so it stays root.
    let root = make_node_addr(0);
    let fake = make_node_addr(1);
    let mut fx = FlipFixture {
        nodes,
        m,
        p,
        c,
        root,
        fake,
    };

    {
        let ts = fx.nodes[M].node.tree_state_mut();
        ts.remove_peer(&p);
        ts.update_peer(
            ParentDeclaration::new(p, root, 1, 1000),
            TreeCoordinate::from_addrs(vec![p, root]).unwrap(),
        );
        ts.set_parent(p, 1, 1000, 1000);
        ts.recompute_coords();
        ts.remove_peer(&c);
        let (parent, coords) = if child_start {
            (m, vec![c, m, p, root])
        } else {
            (fake, vec![c, fake, root])
        };
        ts.update_peer(
            ParentDeclaration::new(c, parent, 1, 1000),
            TreeCoordinate::from_addrs(coords).unwrap(),
        );
    }
    {
        let identity = fx.nodes[M].node.identity().clone();
        let decl_mut = fx.nodes[M].node.tree_state_mut().my_declaration_mut();
        sign_declaration(decl_mut, &identity).unwrap();
    }

    // Debounce is a brake, not the mechanism under test: send on every drain.
    fx.nodes[M].node.bloom_state.set_update_debounce_ms(0);
    fx.nodes[M].node.send_pending_filter_announces().await;

    let node = &fx.nodes[M].node;
    assert_eq!(
        node.is_tree_peer(&c),
        child_start,
        "setup: C's starting tree-peer state"
    );
    assert_eq!(
        node.tree_state().my_declaration().parent_id(),
        &p,
        "setup: M's parent must be P"
    );
    fx
}

/// Deliver a FilterAnnounce from C to M holding exactly `addrs`, and check M
/// stored it, so a rejected announce cannot decide a later assertion.
async fn deliver_filter(fx: &mut FlipFixture, addrs: &[NodeAddr]) {
    let c = fx.c;
    let mut filter = BloomFilter::new();
    for addr in addrs {
        filter.insert(addr);
    }
    let seq = fx.nodes[M].node.get_peer(&c).unwrap().filter_sequence() + 1;
    let mut payload = FilterAnnounce::new(filter.clone(), seq).encode().unwrap();
    payload.remove(0); // strip msg_type byte
    fx.nodes[M].node.handle_filter_announce(&c, &payload).await;

    let stored = fx.nodes[M].node.get_peer(&c).unwrap().inbound_filter();
    assert_eq!(
        stored,
        Some(&filter),
        "setup: M must store C's delivered filter"
    );
}

/// Deliver a signed sequence-5 TreeAnnounce from C to M through the real
/// handler, declaring `parent` with ancestry `coords`. Checks the announce was
/// accepted and that M did not switch parent, since a switch marks every peer
/// and would pass the tests for a reason unrelated to the flip.
async fn deliver_tree_announce(fx: &mut FlipFixture, parent: NodeAddr, coords: Vec<NodeAddr>) {
    let c = fx.c;
    let mut decl = ParentDeclaration::new(c, parent, 5, 2000);
    sign_declaration(&mut decl, fx.nodes[C].node.identity()).unwrap();
    let announce = TreeAnnounce::new(decl, TreeCoordinate::from_addrs(coords).unwrap());
    let encoded = announce.encode().unwrap();

    let node = &mut fx.nodes[M].node;
    let accepted_before = node.metrics().tree.accepted.get();
    let switches_before = node.metrics().tree.parent_switches.get();
    node.handle_tree_announce(&c, &encoded[1..]).await;

    assert_eq!(
        node.metrics().tree.accepted.get(),
        accepted_before + 1,
        "setup: C's tree announce must be accepted"
    );
    assert_eq!(
        node.tree_state().my_declaration().parent_id(),
        &fx.p,
        "setup: M's parent must still be P"
    );
    assert_eq!(
        node.metrics().tree.parent_switches.get(),
        switches_before,
        "setup: M must not switch parent"
    );
}

/// The filter M last sent to P, which must exist.
fn sent_to_parent(fx: &FlipFixture) -> &BloomFilter {
    fx.nodes[M]
        .node
        .bloom_state
        .last_sent_filter(&fx.p)
        .expect("M has sent a filter to P")
}

/// When C starts naming M as parent, M must re-announce to P a filter that
/// now includes C's contribution.
#[tokio::test]
async fn test_bloom_outgoing_filter_to_parent_reannounced_when_peer_becomes_child() {
    let mut fx = flip_fixture(false).await;
    let (m, c, p, root) = (fx.m, fx.c, fx.p, fx.root);

    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    assert!(
        !sent_to_parent(&fx).contains(&marker()),
        "control: a non-tree peer's filter must not reach P"
    );

    deliver_tree_announce(&mut fx, m, vec![c, m, p, root]).await;
    assert!(fx.nodes[M].node.is_tree_peer(&c));
    fx.nodes[M].node.send_pending_filter_announces().await;

    assert!(
        sent_to_parent(&fx).contains(&marker()),
        "P must be sent C's filter once C becomes M's child"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// When C stops naming M as parent, M must re-announce to P a filter that no
/// longer includes C's contribution.
#[tokio::test]
async fn test_bloom_outgoing_filter_to_parent_reannounced_when_child_leaves() {
    let mut fx = flip_fixture(true).await;
    let (c, root, fake) = (fx.c, fx.root, fx.fake);

    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    assert!(
        sent_to_parent(&fx).contains(&marker()),
        "control: a child's filter must reach P"
    );

    deliver_tree_announce(&mut fx, fake, vec![c, fake, root]).await;
    assert!(!fx.nodes[M].node.is_tree_peer(&c));
    fx.nodes[M].node.send_pending_filter_announces().await;

    assert!(
        !sent_to_parent(&fx).contains(&marker()),
        "P must stop being sent C's filter once C leaves"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// A child's filter that arrives after its tree announce reaches the parent
/// through the ordinary filter-announce marking.
#[tokio::test]
async fn test_bloom_child_filter_after_tree_announce_reaches_parent() {
    let mut fx = flip_fixture(false).await;
    let (m, c, p, root) = (fx.m, fx.c, fx.p, fx.root);

    deliver_tree_announce(&mut fx, m, vec![c, m, p, root]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;

    assert!(
        sent_to_parent(&fx).contains(&marker()),
        "P must be sent a child's filter delivered after its tree announce"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// A tree-peer flip that changes no outgoing filter marks no peer: C's filter
/// holds only M's own address, which M's base filter already carries.
#[tokio::test]
async fn test_bloom_tree_peer_flip_without_filter_change_marks_no_peer() {
    let mut fx = flip_fixture(false).await;
    let (m, c, p, root) = (fx.m, fx.c, fx.p, fx.root);

    deliver_filter(&mut fx, &[m]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p) && !bloom.needs_update(&c));

    deliver_tree_announce(&mut fx, m, vec![c, m, p, root]).await;
    assert!(fx.nodes[M].node.is_tree_peer(&c));
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p), "P must not be marked");
    assert!(!bloom.needs_update(&c), "C must not be marked");
    cleanup_nodes(&mut fx.nodes).await;
}

/// A fresher tree announce that leaves C a child of M marks no peer.
#[tokio::test]
async fn test_bloom_tree_announce_without_tree_peer_flip_marks_no_peer() {
    let mut fx = flip_fixture(true).await;
    let (m, c, p, root) = (fx.m, fx.c, fx.p, fx.root);

    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p) && !bloom.needs_update(&c));

    deliver_tree_announce(&mut fx, m, vec![c, m, p, root]).await;
    assert!(fx.nodes[M].node.is_tree_peer(&c));
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p), "P must not be marked");
    assert!(!bloom.needs_update(&c), "C must not be marked");
    cleanup_nodes(&mut fx.nodes).await;
}

// ===== Resend of a filter announce the peer did not receive =====
//
// A lost datagram is made by taking M's frame out of P's receive channel
// without processing it: the transport returned `Ok` and the receiver never
// saw the frame, which is the shape of a real loss on UDP or Ethernet. Final
// assertions read the filter P stores for M, never what M believes it sent.

/// Index of P in `FlipFixture::nodes`.
const P: usize = 0;

/// Set every link report interval on `node` to zero, so the next
/// `check_mmp_reports` sends each report that has interval data.
///
/// Processing a ReceiverReport re-derives the intervals from SRTT, so callers
/// re-apply this before every `check_mmp_reports`.
fn zero_intervals(node: &mut Node) {
    for peer in node.peers.values_mut() {
        if let Some(mmp) = peer.mmp_mut() {
            mmp.sender.update_report_interval_with_bounds(1_000, 0, 0);
            mmp.receiver.update_report_interval_with_bounds(1_000, 0, 0);
        }
    }
}

/// One MMP exchange between nodes `a` and `b`: `a` reports, everyone
/// processes, `b` reports, everyone processes. No other node is asked to
/// report.
async fn mmp_between(nodes: &mut [TestNode], a: usize, b: usize) {
    zero_intervals(&mut nodes[a].node);
    zero_intervals(&mut nodes[b].node);
    nodes[a].node.check_mmp_reports().await;
    process_available_packets(nodes).await;
    zero_intervals(&mut nodes[a].node);
    zero_intervals(&mut nodes[b].node);
    nodes[b].node.check_mmp_reports().await;
    process_available_packets(nodes).await;
}

/// One MMP exchange between M and P: M reports, P processes, P reports, M
/// processes. C is never asked to report.
async fn mmp_round(nodes: &mut [TestNode]) {
    mmp_between(nodes, M, P).await;
}

/// Process packets on every node until a pass handles none, at most 50 passes.
pub(super) async fn drain_quiet(nodes: &mut [TestNode]) {
    for _ in 0..50 {
        if process_available_packets(nodes).await == 0 {
            return;
        }
    }
    panic!("setup: packets still flowing after 50 passes");
}

/// Wait at most 1 s for `tn` to hold a queued frame, then take every queued
/// frame without processing it. Returns how many were taken.
pub(super) async fn drop_queued(tn: &mut TestNode) -> usize {
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while tn.packet_rx.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut dropped = 0;
    while tn.packet_rx.try_recv().is_ok() {
        dropped += 1;
    }
    dropped
}

/// ReceiverReports node `a` has seen from node `b`, including stale and
/// duplicate ones.
fn seen_by(nodes: &[TestNode], a: usize, b: usize) -> u64 {
    let remote = *nodes[b].node.node_addr();
    nodes[a]
        .node
        .get_peer(&remote)
        .and_then(|peer| peer.mmp())
        .map_or(0, |mmp| mmp.metrics.reports_seen())
}

/// ReceiverReports M has seen from P, including stale and duplicate ones.
fn reports_seen(fx: &FlipFixture) -> u64 {
    seen_by(&fx.nodes, M, P)
}

/// Whether the filter P stores for M contains the marker.
fn holds_marker(fx: &FlipFixture) -> bool {
    fx.nodes[P]
        .node
        .get_peer(&fx.m)
        .and_then(|peer| peer.inbound_filter())
        .is_some_and(|filter| filter.contains(&marker()))
}

/// Parent-switch counts at the two ends of a link before a run of MMP
/// rounds.
///
/// A first RTT sample can re-evaluate the parent, and a switch marks every
/// peer, which would pass a resend test for a reason unrelated to the resend.
struct SwitchGuard {
    a: u64,
    b: u64,
}

/// Snapshot the parent-switch counters of nodes `a` and `b`.
fn guard_of(nodes: &[TestNode], a: usize, b: usize) -> SwitchGuard {
    SwitchGuard {
        a: nodes[a].node.metrics().tree.parent_switches.get(),
        b: nodes[b].node.metrics().tree.parent_switches.get(),
    }
}

/// Assert neither node `a` nor node `b` switched parent since `guard`, and
/// `a`'s parent is still `parent`.
fn assert_steady(nodes: &[TestNode], a: usize, b: usize, guard: &SwitchGuard, parent: &NodeAddr) {
    assert_eq!(
        nodes[a].node.metrics().tree.parent_switches.get(),
        guard.a,
        "setup: node {a} must not switch parent during the MMP rounds"
    );
    assert_eq!(
        nodes[b].node.metrics().tree.parent_switches.get(),
        guard.b,
        "setup: node {b} must not switch parent during the MMP rounds"
    );
    assert_eq!(
        nodes[a].node.tree_state().my_declaration().parent_id(),
        parent,
        "setup: node {a}'s parent must not change"
    );
}

/// Snapshot M's and P's parent-switch counters.
fn switch_guard(fx: &FlipFixture) -> SwitchGuard {
    guard_of(&fx.nodes, M, P)
}

/// Assert neither M nor P switched parent since `guard`, and M's parent is P.
fn assert_unswitched(fx: &FlipFixture, guard: &SwitchGuard) {
    assert_steady(&fx.nodes, M, P, guard, &fx.p);
}

/// FilterAnnounces M has sent.
fn sent_count(fx: &FlipFixture) -> u64 {
    fx.nodes[M].node.metrics().bloom.sent.get()
}

/// Drain `nodes`, then run MMP exchanges between nodes `a` and `b` until `a`
/// has seen a report from `b`.
async fn await_report(nodes: &mut [TestNode], a: usize, b: usize) {
    drain_quiet(nodes).await;
    for _ in 0..10 {
        if seen_by(nodes, a, b) >= 1 {
            break;
        }
        mmp_between(nodes, a, b).await;
    }
    assert!(
        seen_by(nodes, a, b) >= 1,
        "setup: node {b} must report to node {a}"
    );
}

/// Drain the fixture, then run MMP rounds until M has seen a report from P.
async fn start_reports(fx: &mut FlipFixture) {
    await_report(&mut fx.nodes, M, P).await;
}

/// Deliver C's filter carrying the marker and send M's announce of it to P.
/// Returns M's sent count after the send.
async fn send_marker(fx: &mut FlipFixture) -> u64 {
    let c = fx.c;
    deliver_filter(fx, &[c, marker()]).await;
    let before = sent_count(fx);
    fx.nodes[M].node.send_pending_filter_announces().await;
    let after = sent_count(fx);
    assert_eq!(after, before + 1, "setup: M must send exactly one announce");
    after
}

/// Lose the announce just sent to P, and check the loss took.
async fn lose_announce(fx: &mut FlipFixture) {
    assert_eq!(
        drop_queued(&mut fx.nodes[P]).await,
        1,
        "setup: exactly the one announce frame must be lost"
    );
    assert!(
        !holds_marker(fx),
        "control: P must not hold the lost announce's content"
    );
    assert!(
        sent_to_parent(fx).contains(&marker()),
        "control: M must record the lost announce as sent"
    );
}

/// Get reports flowing from P to M, then send M's announce carrying the
/// marker and lose it on the way to P. Returns M's sent count after the send.
async fn lose_marker(fx: &mut FlipFixture) -> u64 {
    start_reports(fx).await;
    let sent = send_marker(fx).await;
    lose_announce(fx).await;
    sent
}

/// The first eight bytes of the handshake hash of node `a`'s current session
/// with node `b`.
fn epoch_of(nodes: &[TestNode], a: usize, b: usize) -> [u8; 8] {
    let remote = *nodes[b].node.node_addr();
    let hash = nodes[a]
        .node
        .get_peer(&remote)
        .and_then(|peer| peer.noise_session())
        .expect("setup: the link has a session")
        .handshake_hash();
    let mut epoch = [0u8; 8];
    epoch.copy_from_slice(&hash[..8]);
    epoch
}

/// The first eight bytes of the handshake hash of M's current session with P.
fn link_epoch(fx: &FlipFixture) -> [u8; 8] {
    epoch_of(&fx.nodes, M, P)
}

/// A FilterAnnounce lost in transit is resent once a receiver report shows
/// the loss, so the peer ends up holding the filter.
#[tokio::test]
async fn test_bloom_filter_announce_lost_in_transit_reaches_the_peer_after_a_receiver_report() {
    let mut fx = flip_fixture(true).await;
    lose_marker(&mut fx).await;

    let seen = reports_seen(&fx);
    let guard = switch_guard(&fx);
    for _ in 0..3 {
        mmp_round(&mut fx.nodes).await;
        fx.nodes[M].node.check_bloom_state().await;
        process_available_packets(&mut fx.nodes).await;
    }
    assert!(
        reports_seen(&fx) > seen,
        "setup: a receiver report must arrive after the loss"
    );
    assert_unswitched(&fx, &guard);

    assert!(
        holds_marker(&fx),
        "P must hold the filter whose announce was lost"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// Receiving the same filter again under a newer sequence changes no outgoing
/// filter, so it marks no peer and cannot cascade.
#[tokio::test]
async fn test_bloom_unchanged_filter_with_newer_sequence_marks_no_peer() {
    let mut fx = flip_fixture(true).await;
    let (c, p) = (fx.c, fx.p);

    deliver_filter(&mut fx, &[c, marker()]).await;
    fx.nodes[M].node.send_pending_filter_announces().await;
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(
        !bloom.needs_update(&p) && !bloom.needs_update(&c),
        "control: the first delivery must be fully sent"
    );

    deliver_filter(&mut fx, &[c, marker()]).await;
    let bloom = &fx.nodes[M].node.bloom_state;
    assert!(!bloom.needs_update(&p), "P must not be marked");
    assert!(!bloom.needs_update(&c), "C must not be marked");
    cleanup_nodes(&mut fx.nodes).await;
}

/// Make node `a` rekey each of its links on its next check, with both ends
/// of each link aged past the responder's rekey-acceptance gate: node `a`'s
/// side past its time trigger, the peer's side past the 30 s link age.
fn arm_rekeys(nodes: &mut [TestNode], a: usize) {
    let local = *nodes[a].node.node_addr();
    let remotes: Vec<NodeAddr> = nodes[a].node.peers.keys().copied().collect();
    let due = Duration::from_secs(
        nodes[a].node.config().node.rekey.after_secs + crate::node::REKEY_JITTER_SECS as u64 + 1,
    );
    let aged = Duration::from_secs(31);
    for remote in remotes {
        let b = nodes
            .iter()
            .position(|tn| *tn.node.node_addr() == remote)
            .expect("setup: every peer is a test node");
        for (i, addr, age) in [(a, remote, due), (b, local, aged)] {
            nodes[i]
                .node
                .get_peer_mut(&addr)
                .expect("setup: link peer present")
                .test_backdate_session_established(age);
        }
    }
}

/// Make M rekey on its next check, with both ends of both of M's links aged
/// past the responder's rekey-acceptance gate.
fn arm_rekey(fx: &mut FlipFixture) {
    arm_rekeys(&mut fx.nodes, M);
}

/// Drive the real rekey handshake until node `a`'s session with node `b` is
/// cut over.
async fn cutover(nodes: &mut [TestNode], a: usize, b: usize) {
    let before = epoch_of(nodes, a, b);
    let addr_b = *nodes[b].node.node_addr();
    for _ in 0..6 {
        // An initiator holding the pending its msg2 completed cuts over at
        // its first poll after the cutover delay.
        if nodes[a]
            .node
            .get_peer(&addr_b)
            .is_some_and(|p| p.pending_new_session().is_some())
        {
            super::rekey_parity::pass_cutover_delay();
        }
        nodes[a].node.poll_link_rekeys().await;
        nodes[b].node.poll_link_rekeys().await;
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            process_available_packets(nodes).await;
        }
        if epoch_of(nodes, a, b) != before {
            break;
        }
    }
    assert_ne!(
        epoch_of(nodes, a, b),
        before,
        "setup: node {a}'s link to node {b} must rekey"
    );
    let (addr_a, addr_b) = (*nodes[a].node.node_addr(), *nodes[b].node.node_addr());
    assert!(
        !nodes[a].node.get_peer(&addr_b).unwrap().rekey_in_progress(),
        "setup: node {a}'s rekey with node {b} must be complete"
    );
    assert!(
        !nodes[b].node.get_peer(&addr_a).unwrap().rekey_in_progress(),
        "setup: node {b}'s rekey with node {a} must be complete"
    );
}

/// Drive the real rekey handshake until M's session with P is cut over.
async fn rekey_cutover(fx: &mut FlipFixture) {
    cutover(&mut fx.nodes, M, P).await;
}

/// An announce lost just before a link rekey is resent on the new session.
#[tokio::test]
async fn test_bloom_announce_lost_before_a_link_rekey_reaches_the_peer_after_the_cutover() {
    let mut fx = flip_fixture(true).await;
    let sent = lose_marker(&mut fx).await;

    arm_rekey(&mut fx);
    rekey_cutover(&mut fx).await;

    let guard = switch_guard(&fx);
    for _ in 0..5 {
        mmp_round(&mut fx.nodes).await;
        fx.nodes[M].node.check_bloom_state().await;
        process_available_packets(&mut fx.nodes).await;
    }
    assert_unswitched(&fx, &guard);

    assert_eq!(
        sent_count(&fx),
        sent + 1,
        "M must resend to P exactly once after the loss"
    );
    assert!(
        holds_marker(&fx),
        "P must hold the filter whose announce was lost before the rekey"
    );
    assert!(
        !fx.nodes[M].node.bloom_state.announce_outstanding(&fx.p),
        "M's resend on the new session must be confirmed"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// An announce that arrives is confirmed from the receiver reports and never
/// resent.
#[tokio::test]
async fn test_bloom_delivered_announce_is_confirmed_without_a_resend() {
    let mut fx = flip_fixture(true).await;
    let p = fx.p;
    start_reports(&mut fx).await;
    let sent = send_marker(&mut fx).await;
    process_available_packets(&mut fx.nodes).await;
    assert!(holds_marker(&fx), "control: P must hold the announce");

    let guard = switch_guard(&fx);
    for _ in 0..3 {
        mmp_round(&mut fx.nodes).await;
        fx.nodes[M].node.check_bloom_state().await;
        process_available_packets(&mut fx.nodes).await;
    }
    assert_unswitched(&fx, &guard);

    let bloom = &fx.nodes[M].node.bloom_state;
    assert_eq!(
        sent_count(&fx),
        sent,
        "M must not resend a delivered announce"
    );
    assert!(!bloom.needs_update(&p), "P must not be marked");
    assert!(
        !bloom.announce_outstanding(&p),
        "the delivered announce must be confirmed"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// On a converged mesh with clean links, every announce is confirmed from the
/// receiver reports and none is resent. The convergence announces go out
/// before any report, so this checks the zero baseline on real counters.
#[tokio::test]
async fn test_bloom_clean_links_confirm_every_announce_without_a_resend() {
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    drain_quiet(&mut nodes).await;
    let snapshot = |nodes: &[TestNode]| -> Vec<(u64, u64, NodeAddr)> {
        nodes
            .iter()
            .map(|tn| {
                (
                    tn.node.metrics().bloom.sent.get(),
                    tn.node.metrics().tree.parent_switches.get(),
                    *tn.node.tree_state().my_declaration().parent_id(),
                )
            })
            .collect()
    };
    let before = snapshot(&nodes);

    for _ in 0..5 {
        for i in 0..nodes.len() {
            zero_intervals(&mut nodes[i].node);
            nodes[i].node.check_mmp_reports().await;
            process_available_packets(&mut nodes).await;
        }
        for tn in nodes.iter_mut() {
            tn.node.check_bloom_state().await;
        }
        process_available_packets(&mut nodes).await;
    }

    assert_eq!(
        snapshot(&nodes),
        before,
        "no node may send an announce, switch parent or change parent"
    );
    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers.keys() {
            assert!(
                !tn.node.bloom_state.announce_outstanding(peer),
                "node {i} must have confirmed its announce to every peer"
            );
        }
    }
    cleanup_nodes(&mut nodes).await;
}

/// With no receiver report at all, a lost announce is still resent once the
/// fallback interval passes.
#[tokio::test]
async fn test_bloom_lost_announce_is_resent_after_the_fallback_when_no_receiver_report_arrives() {
    let mut fx = flip_fixture(true).await;
    drain_quiet(&mut fx.nodes).await;
    fx.nodes[M].node.bloom_state.set_fallback(0);
    let seen = reports_seen(&fx);
    send_marker(&mut fx).await;
    lose_announce(&mut fx).await;

    fx.nodes[M].node.check_bloom_state().await;
    process_available_packets(&mut fx.nodes).await;

    assert_eq!(reports_seen(&fx), seen, "setup: P must send no report");
    assert!(
        holds_marker(&fx),
        "P must hold the filter once the fallback resends it"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// The cumulative counters of the last report `node` accepted from `peer`.
fn rr_counters(node: &Node, peer: &NodeAddr) -> Option<(u64, u64, u32)> {
    node.get_peer(peer)?.mmp()?.metrics.rr_counters()
}

/// The next send counter of `node`'s current session with `peer`.
fn next_counter(node: &Node, peer: &NodeAddr) -> u64 {
    node.get_peer(peer)
        .and_then(|p| p.noise_session())
        .expect("setup: session present")
        .current_send_counter()
}

/// Around a rekey, frames the responder sent on the old session reach the
/// initiator after it cut over: a report about the initiator's old-session
/// traffic, and data frames carrying the responder's old-session counters.
/// Neither may feed the new session's MMP state, so the reports either end
/// holds after the cutover describe the new session, an announce sent after
/// it is confirmed by them, and nothing is resent.
#[tokio::test]
async fn test_bloom_reports_from_the_previous_session_do_not_trigger_resends() {
    let mut fx = flip_fixture(true).await;
    let (m, p) = (fx.m, fx.p);
    fx.nodes[P].node.bloom_state.set_update_debounce_ms(0);
    start_reports(&mut fx).await;
    arm_rekey(&mut fx);

    // A session reaching its rekey has carried many frames. Reserve counters
    // on both old sessions so their counters stay above the new sessions'
    // for the whole test, as they do in the field; with a short history the
    // new counters pass them within a few rounds, the reports become usable,
    // and each announce spends its one unchecked resend.
    for (i, remote) in [(M, p), (P, m)] {
        let peer = fx.nodes[i]
            .node
            .get_peer_mut(&remote)
            .expect("setup: session present");
        for _ in 0..1000 {
            peer.seal(crate::peer::peer_now())
                .expect("setup: counter available");
        }
    }

    // Reports both ways, then M reports alone so P holds interval data.
    mmp_round(&mut fx.nodes).await;
    zero_intervals(&mut fx.nodes[M].node);
    zero_intervals(&mut fx.nodes[P].node);
    fx.nodes[M].node.check_mmp_reports().await;
    process_available_packets(&mut fx.nodes).await;

    // M starts the rekey and holds the new session, not yet cut over.
    let before = link_epoch(&fx);
    fx.nodes[M].node.poll_link_rekeys().await;
    for _ in 0..10 {
        if fx.nodes[M]
            .node
            .get_peer(&p)
            .is_some_and(|peer| peer.pending_new_session().is_some())
        {
            break;
        }
        process_available_packets(&mut fx.nodes).await;
    }
    assert!(
        fx.nodes[M]
            .node
            .get_peer(&p)
            .is_some_and(|peer| peer.pending_new_session().is_some()),
        "setup: M must hold P's new session"
    );
    assert_eq!(link_epoch(&fx), before, "setup: M must not have cut over");

    // P reports on the old session; hold its frames back from M.
    assert!(
        fx.nodes[M].packet_rx.is_empty(),
        "setup: M's queue is empty"
    );
    zero_intervals(&mut fx.nodes[P].node);
    fx.nodes[P].node.check_mmp_reports().await;
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while fx.nodes[M].packet_rx.is_empty() && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let mut held = Vec::new();
    while let Ok(packet) = fx.nodes[M].packet_rx.try_recv() {
        held.push(packet);
    }
    assert!(!held.is_empty(), "setup: P must queue its reports for M");

    // M cuts over after the cutover delay, then receives P's old-session
    // frames.
    super::rekey_parity::pass_cutover_delay();
    fx.nodes[M].node.poll_link_rekeys().await;
    assert_ne!(link_epoch(&fx), before, "setup: M must cut over");
    for packet in held {
        fx.nodes[M].node.handle_encrypted_frame(packet).await;
    }
    assert_eq!(
        rr_counters(&fx.nodes[M].node, &p),
        None,
        "M must not take P's report about M's previous session"
    );
    mmp_round(&mut fx.nodes).await;
    let describes_new = |rr: Option<(u64, u64, u32)>, next: u64| rr.is_none_or(|rr| rr.0 < next);
    assert!(
        describes_new(
            rr_counters(&fx.nodes[M].node, &p),
            next_counter(&fx.nodes[M].node, &p)
        ),
        "M's report must describe M's new session"
    );
    assert!(
        describes_new(
            rr_counters(&fx.nodes[P].node, &m),
            next_counter(&fx.nodes[P].node, &m)
        ),
        "P's report must not carry P's previous-session counter"
    );

    // Both ends come to hold a usable report on the new session, which an
    // announce sent next is measured from. Under the old behaviour the
    // previous-session reports kept both ends from ever holding one here.
    let usable = |fx: &FlipFixture| {
        [(M, p), (P, m)].into_iter().all(|(i, remote)| {
            rr_counters(&fx.nodes[i].node, &remote)
                .is_some_and(|rr| rr.0 < next_counter(&fx.nodes[i].node, &remote))
        })
    };
    for _ in 0..5 {
        if usable(&fx) {
            break;
        }
        mmp_round(&mut fx.nodes).await;
    }
    assert!(
        usable(&fx),
        "both ends must hold a usable new-session report"
    );

    fx.nodes[M].node.bloom_state.mark_update_needed(p);
    fx.nodes[P].node.bloom_state.mark_update_needed(m);
    fx.nodes[M].node.send_pending_filter_announces().await;
    fx.nodes[P].node.send_pending_filter_announces().await;
    process_available_packets(&mut fx.nodes).await;
    assert!(
        fx.nodes[M].node.bloom_state.announce_outstanding(&p)
            && fx.nodes[P].node.bloom_state.announce_outstanding(&m),
        "setup: both ends must have an announce outstanding"
    );

    let sent_m = fx.nodes[M].node.metrics().bloom.sent.get();
    let sent_p = fx.nodes[P].node.metrics().bloom.sent.get();
    let guard = switch_guard(&fx);
    for _ in 0..5 {
        mmp_round(&mut fx.nodes).await;
        fx.nodes[M].node.check_bloom_state().await;
        fx.nodes[P].node.check_bloom_state().await;
        process_available_packets(&mut fx.nodes).await;
    }
    assert_unswitched(&fx, &guard);

    assert_eq!(
        fx.nodes[M].node.metrics().bloom.sent.get(),
        sent_m,
        "M must not resend a delivered announce after the rekey"
    );
    assert_eq!(
        fx.nodes[P].node.metrics().bloom.sent.get(),
        sent_p,
        "P must not resend a delivered announce after the rekey"
    );
    assert!(
        !fx.nodes[M].node.bloom_state.announce_outstanding(&p),
        "M's announce must be confirmed by a new-session report"
    );
    assert!(
        !fx.nodes[P].node.bloom_state.announce_outstanding(&m),
        "P's announce must be confirmed by a new-session report"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

// ===== Resend of a tree announce the peer did not receive =====
//
// Tree announces are confirmed and resent by the same receiver-report check
// as filter announces, so their node tests share this file's MMP, rekey and
// loss helpers. They run on real converged state only: every role is read
// from the converged tree, and nothing in any node's tree state is forged.
// Final assertions read the sequence the receiver stores for the sender,
// never what the sender believes it sent.

/// A converged line of loopback nodes with a sender S that is not root and
/// its parent R.
///
/// In a line every neighbour of S other than its parent is its child, whose
/// ancestry contains S, so S has no alternative parent and cannot switch.
struct TreeLine {
    nodes: Vec<TestNode>,
    /// Index of the sender.
    s: usize,
    /// Index of the sender's parent.
    r: usize,
}

/// Index of the node whose address is `addr`.
fn index_of(nodes: &[TestNode], addr: &NodeAddr) -> usize {
    nodes
        .iter()
        .position(|tn| tn.node.node_addr() == addr)
        .expect("setup: address belongs to a test node")
}

/// Converge a line of `n` nodes (2 or 4) and pick S and R from the result.
///
/// With 4 nodes, S is the first of indices 1 and 2 that is not root; with 2,
/// S is the node that is not root. R is S's parent. Every node's per-peer
/// tree announce rate limit is set to 0 and whatever convergence left
/// pending is flushed, so a resend is never held back by the rate limit.
async fn tree_line(n: usize) -> TreeLine {
    let edges: Vec<(usize, usize)> = (1..n).map(|i| (i - 1, i)).collect();
    let mut nodes = run_tree_test(n, &edges, false).await;

    let root = (0..n)
        .find(|&i| nodes[i].node.tree_state().is_root())
        .expect("setup: the line must have a root");
    let candidates: &[usize] = if n == 2 { &[0, 1] } else { &[1, 2] };
    let s = *candidates
        .iter()
        .find(|&&i| !nodes[i].node.tree_state().is_root())
        .expect("setup: one candidate sender is not root");
    let s_addr = *nodes[s].node.node_addr();
    let r = index_of(
        &nodes,
        nodes[s].node.tree_state().my_declaration().parent_id(),
    );
    let neighbours: Vec<usize> = [s.checked_sub(1), Some(s + 1)]
        .into_iter()
        .flatten()
        .filter(|&i| i < n)
        .collect();
    eprintln!(
        "tree_line({n}): root index {root}, S {s}, R {r}, shape: {}",
        if r == root {
            "R is root"
        } else {
            "R is not root"
        }
    );

    assert!(
        !nodes[s].node.tree_state().is_root(),
        "setup: S is not root"
    );
    assert_eq!(
        nodes[s].node.peers.len(),
        neighbours.len(),
        "setup: S has exactly its line neighbours as peers"
    );
    assert!(neighbours.contains(&r), "setup: R is S's neighbour");
    for &c in neighbours.iter().filter(|&&i| i != r) {
        assert_eq!(
            nodes[c].node.tree_state().my_declaration().parent_id(),
            &s_addr,
            "setup: S's other neighbour declares S as its parent"
        );
    }

    for tn in nodes.iter_mut() {
        for peer in tn.node.peers.values_mut() {
            peer.set_tree_announce_min_interval_ms(0);
        }
        tn.node.send_pending_tree_announces().await;
    }
    drain_quiet(&mut nodes).await;
    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers.values() {
            assert!(
                !peer.has_pending_tree_announce(),
                "setup: node {i} must have no pending tree announce"
            );
        }
    }
    TreeLine { nodes, s, r }
}

/// Turn off the periodic parent re-evaluation on `node`, so its periodic
/// re-broadcast cannot be what delivers a lost announce.
fn no_reeval(node: &mut Node) {
    node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.node.tree.reeval_interval_secs = 0;
        ctx.config = std::sync::Arc::new(cfg);
    });
}

/// Hold off S's fallback resend. S's announces to a child that never
/// reports stay outstanding, and on a loaded host a test running past the
/// fallback would add an unchecked resend to the child and break the exact
/// send counts.
fn hold_fallback(line: &mut TreeLine) {
    line.nodes[line.s]
        .node
        .tree_state_mut()
        .set_fallback(u64::MAX);
}

/// Whether S's announce to R still awaits confirmation.
fn parent_outstanding(line: &TreeLine) -> bool {
    let parent = *line.nodes[line.r].node.node_addr();
    line.nodes[line.s]
        .node
        .tree_state()
        .announce_outstanding(&parent)
}

/// TreeAnnounces node `i` has sent.
fn tree_sent(nodes: &[TestNode], i: usize) -> u64 {
    nodes[i].node.metrics().tree.sent.get()
}

/// The declaration sequence node `r` stores for node `s`.
fn held_seq(nodes: &[TestNode], r: usize, s: usize) -> Option<u64> {
    let sender = *nodes[s].node.node_addr();
    nodes[r]
        .node
        .tree_state()
        .peer_declaration(&sender)
        .map(|decl| decl.sequence())
}

/// Give S a new declaration sequence with the same parent, signed, as a
/// position change would. Returns the new sequence.
fn bump(line: &mut TreeLine) -> u64 {
    let (s, r) = (line.s, line.r);
    let parent = *line.nodes[r].node.node_addr();
    let identity = line.nodes[s].node.identity().clone();
    let ts = line.nodes[s].node.tree_state_mut();
    let seq = ts.my_declaration().sequence() + 1;
    let timestamp = ts.my_declaration().timestamp() + 1;
    ts.set_parent(parent, seq, timestamp, crate::time::mono_ms());
    ts.recompute_coords();
    sign_declaration(ts.my_declaration_mut(), &identity).unwrap();

    let ts = line.nodes[s].node.tree_state();
    assert!(!ts.is_root(), "setup: S is still not root after the bump");
    assert_eq!(
        ts.my_declaration().parent_id(),
        &parent,
        "setup: S's parent is still R after the bump"
    );
    assert!(
        held_seq(&line.nodes, r, s).is_some_and(|held| seq > held),
        "setup: the new sequence is fresher than the one R holds for S"
    );
    seq
}

/// Send S's current announce to R and check exactly one was sent. Returns
/// S's sent count after the send.
async fn send_up(line: &mut TreeLine) -> u64 {
    let (s, r) = (line.s, line.r);
    let parent = *line.nodes[r].node.node_addr();
    let before = tree_sent(&line.nodes, s);
    line.nodes[s]
        .node
        .send_tree_announce_to_peer(&parent)
        .await
        .expect("setup: the send must succeed");
    let after = tree_sent(&line.nodes, s);
    assert_eq!(after, before + 1, "setup: S must send exactly one announce");
    after
}

/// Lose the announce just sent to R, and check the loss took.
async fn lose_up(line: &mut TreeLine, old: Option<u64>) {
    let (s, r) = (line.s, line.r);
    assert_eq!(
        drop_queued(&mut line.nodes[r]).await,
        1,
        "setup: exactly the one announce frame must be lost"
    );
    assert_eq!(
        held_seq(&line.nodes, r, s),
        old,
        "control: R must still hold S's old sequence"
    );
}

/// Bump S's declaration, send it to R and lose it on the way. Returns the new
/// sequence and S's sent count after the send.
async fn lose_bump(line: &mut TreeLine) -> (u64, u64) {
    let old = held_seq(&line.nodes, line.r, line.s);
    let seq = bump(line);
    let sent = send_up(line).await;
    lose_up(line, old).await;
    (seq, sent)
}

/// `rounds` rounds of an MMP exchange between S and R followed by S's tree
/// tick, with checks that a report arrived and nothing switched parent.
async fn tree_rounds(line: &mut TreeLine, rounds: usize) {
    let (s, r) = (line.s, line.r);
    let parent = *line.nodes[r].node.node_addr();
    let seen = seen_by(&line.nodes, s, r);
    let guard = guard_of(&line.nodes, s, r);
    for _ in 0..rounds {
        mmp_between(&mut line.nodes, s, r).await;
        line.nodes[s].node.check_tree_state().await;
        process_available_packets(&mut line.nodes).await;
    }
    assert!(
        seen_by(&line.nodes, s, r) > seen,
        "setup: a receiver report must arrive after the send"
    );
    assert_steady(&line.nodes, s, r, &guard, &parent);
}

/// Whether S has a tree announce pending for R.
fn parent_pending(line: &TreeLine) -> bool {
    let parent = *line.nodes[line.r].node.node_addr();
    line.nodes[line.s]
        .node
        .get_peer(&parent)
        .expect("setup: R is S's peer")
        .has_pending_tree_announce()
}

/// A TreeAnnounce lost in transit is resent once a receiver report shows the
/// loss, so the parent ends up holding the new declaration.
#[tokio::test]
async fn test_tree_announce_lost_in_transit_reaches_the_peer_after_a_receiver_report() {
    let mut line = tree_line(4).await;
    let (s, r) = (line.s, line.r);
    await_report(&mut line.nodes, s, r).await;
    no_reeval(&mut line.nodes[s].node);
    hold_fallback(&mut line);

    let (seq, sent) = lose_bump(&mut line).await;
    tree_rounds(&mut line, 3).await;

    assert_eq!(
        tree_sent(&line.nodes, s),
        sent + 1,
        "S must resend to R exactly once after the loss"
    );
    assert!(
        !parent_pending(&line),
        "the rate limit must not be holding the resend"
    );
    assert_eq!(
        held_seq(&line.nodes, r, s),
        Some(seq),
        "R must hold the declaration whose announce was lost"
    );
    cleanup_nodes(&mut line.nodes).await;
}

/// A node with a single peer has no periodic re-broadcast, so without a
/// resend a lost announce is never recovered.
#[tokio::test]
async fn test_tree_announce_lost_by_a_node_with_one_peer_reaches_the_peer_after_a_receiver_report()
{
    let mut line = tree_line(2).await;
    let (s, r) = (line.s, line.r);
    await_report(&mut line.nodes, s, r).await;

    let (seq, _) = lose_bump(&mut line).await;
    tree_rounds(&mut line, 3).await;

    assert_eq!(
        held_seq(&line.nodes, r, s),
        Some(seq),
        "R must hold the declaration whose announce was lost"
    );
    cleanup_nodes(&mut line.nodes).await;
}

/// An announce lost just before a link rekey is resent on the new session.
#[tokio::test]
async fn test_tree_announce_lost_before_a_link_rekey_reaches_the_peer_after_the_cutover() {
    let mut line = tree_line(4).await;
    let (s, r) = (line.s, line.r);
    await_report(&mut line.nodes, s, r).await;
    no_reeval(&mut line.nodes[s].node);
    hold_fallback(&mut line);

    let (seq, sent) = lose_bump(&mut line).await;
    arm_rekeys(&mut line.nodes, s);
    cutover(&mut line.nodes, s, r).await;
    tree_rounds(&mut line, 5).await;

    assert_eq!(
        tree_sent(&line.nodes, s),
        sent + 1,
        "S must resend to R exactly once after the loss"
    );
    assert_eq!(
        held_seq(&line.nodes, r, s),
        Some(seq),
        "R must hold the declaration whose announce was lost before the rekey"
    );
    assert!(
        !parent_outstanding(&line),
        "S's resend on the new session must be confirmed"
    );
    cleanup_nodes(&mut line.nodes).await;
}

/// An announce that arrives is confirmed from the receiver reports and never
/// resent.
#[tokio::test]
async fn test_tree_delivered_announce_is_confirmed_without_a_resend() {
    let mut line = tree_line(4).await;
    let (s, r) = (line.s, line.r);
    await_report(&mut line.nodes, s, r).await;
    no_reeval(&mut line.nodes[s].node);
    hold_fallback(&mut line);

    let seq = bump(&mut line);
    let sent = send_up(&mut line).await;
    assert!(
        parent_outstanding(&line),
        "control: the tracker must hold the announce straight after the send"
    );
    process_available_packets(&mut line.nodes).await;
    assert_eq!(
        held_seq(&line.nodes, r, s),
        Some(seq),
        "control: R must hold the announce"
    );
    tree_rounds(&mut line, 3).await;

    assert_eq!(
        tree_sent(&line.nodes, s),
        sent,
        "S must not resend a delivered announce"
    );
    assert!(!parent_pending(&line), "R must not be marked");
    assert!(
        !parent_outstanding(&line),
        "the delivered announce must be confirmed"
    );
    cleanup_nodes(&mut line.nodes).await;
}

/// On a converged mesh with clean links, every tree announce is confirmed
/// from the receiver reports and none is resent. The convergence announces
/// go out before any report, so this checks the zero baseline on real
/// counters.
#[tokio::test]
async fn test_tree_clean_links_confirm_every_announce_without_a_resend() {
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    for tn in nodes.iter_mut() {
        for peer in tn.node.peers.values_mut() {
            peer.set_tree_announce_min_interval_ms(0);
        }
        tn.node.send_pending_tree_announces().await;
        no_reeval(&mut tn.node);
    }
    drain_quiet(&mut nodes).await;
    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers.values() {
            assert!(
                !peer.has_pending_tree_announce(),
                "setup: node {i} must have no pending tree announce"
            );
        }
    }
    let snapshot = |nodes: &[TestNode]| -> Vec<(u64, u64, NodeAddr)> {
        nodes
            .iter()
            .map(|tn| {
                (
                    tn.node.metrics().tree.sent.get(),
                    tn.node.metrics().tree.parent_switches.get(),
                    *tn.node.tree_state().my_declaration().parent_id(),
                )
            })
            .collect()
    };
    let before = snapshot(&nodes);
    assert!(
        (0..nodes.len()).all(|i| tree_sent(&nodes, i) > 0),
        "setup: every node must have sent tree announces while converging"
    );

    for _ in 0..5 {
        for i in 0..nodes.len() {
            zero_intervals(&mut nodes[i].node);
            nodes[i].node.check_mmp_reports().await;
            process_available_packets(&mut nodes).await;
        }
        for tn in nodes.iter_mut() {
            tn.node.check_tree_state().await;
        }
        process_available_packets(&mut nodes).await;
    }

    assert_eq!(
        snapshot(&nodes),
        before,
        "no node may send a tree announce, switch parent or change parent"
    );
    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers.keys() {
            assert!(
                !tn.node.tree_state().announce_outstanding(peer),
                "node {i} must have confirmed its tree announce to every peer"
            );
        }
    }
    cleanup_nodes(&mut nodes).await;
}

/// With no receiver report at all, a lost tree announce is still resent once
/// the fallback interval passes.
#[tokio::test]
async fn test_tree_lost_announce_is_resent_after_the_fallback_when_no_receiver_report_arrives() {
    let mut line = tree_line(4).await;
    let (s, r) = (line.s, line.r);
    drain_quiet(&mut line.nodes).await;
    no_reeval(&mut line.nodes[s].node);
    line.nodes[s].node.tree_state_mut().set_fallback(0);
    let seen = seen_by(&line.nodes, s, r);

    let (seq, _) = lose_bump(&mut line).await;
    line.nodes[s].node.check_tree_state().await;
    process_available_packets(&mut line.nodes).await;

    assert_eq!(
        seen_by(&line.nodes, s, r),
        seen,
        "setup: R must send no report"
    );
    assert_eq!(
        held_seq(&line.nodes, r, s),
        Some(seq),
        "R must hold the declaration once the fallback resends it"
    );
    cleanup_nodes(&mut line.nodes).await;
}

/// The filter-announce debounce is stamped on the monotonic clock, so a step
/// back of the wall clock cannot hold announces for the size of the step.
#[tokio::test]
async fn filter_announce_debounce_stamps_the_monotonic_clock() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let peer = *nodes[1].node.node_addr();
    let node = &mut nodes[0].node;

    node.bloom_state.set_update_debounce_ms(0);
    node.bloom_state.mark_update_needed(peer);
    let sent = node.metrics().bloom.sent.get();
    let before = crate::time::mono_ms();
    node.send_pending_filter_announces().await;
    let after = crate::time::mono_ms();

    assert_eq!(
        node.metrics().bloom.sent.get(),
        sent + 1,
        "setup: the pending announce must be sent"
    );
    let stamp = node.bloom_state.last_update_sent(&peer);
    assert!(
        stamp.is_some_and(|t| before <= t && t <= after),
        "stamp {stamp:?} not in [{before}, {after}]"
    );

    // Regression guard for the ready-set read: with the debounce window
    // still open, the peer must not even reach the send path, where the
    // re-check would count it as suppressed.
    node.bloom_state.set_update_debounce_ms(60_000);
    node.bloom_state.mark_update_needed(peer);
    let suppressed = node.metrics().bloom.debounce_suppressed.get();
    node.send_pending_filter_announces().await;
    assert_eq!(
        node.metrics().bloom.debounce_suppressed.get(),
        suppressed,
        "a peer inside the debounce window must not enter the ready set"
    );

    cleanup_nodes(&mut nodes).await;
}
