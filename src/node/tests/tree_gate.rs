//! TreeAnnounce handling that must sit behind the handler's gates.
//!
//! A stale announce must leave the peer's stored position alone, and a parent
//! update that leaves this node's address path unchanged must not drop the
//! cached coordinates of this node's descendants or clear lookup backoff.
//! Both are driven through `handle_tree_announce` on a converged two-node
//! tree, with declarations rooted at a synthetic all-zero root that is smaller
//! than any generated node address.

use super::spanning_tree::*;
use super::*;
use crate::node::tree::sign_declaration;
use crate::proto::stp::{ParentDeclaration, TreeAnnounce, TreeCoordinate};

/// Encode a TreeAnnounce from node `s` with the given parent, sequence and
/// ancestry above `s`, signed with `s`'s identity. The returned payload has
/// the message-type byte stripped, as `handle_tree_announce` expects.
fn signed_announce(
    nodes: &[TestNode],
    s: usize,
    parent: NodeAddr,
    seq: u64,
    above: &[NodeAddr],
) -> Vec<u8> {
    let sender = *nodes[s].node.node_addr();
    let mut decl = ParentDeclaration::new(sender, parent, seq, 1000 + seq);
    sign_declaration(&mut decl, nodes[s].node.identity()).unwrap();
    let mut addrs = vec![sender];
    addrs.extend_from_slice(above);
    let announce = TreeAnnounce::new(decl, TreeCoordinate::from_addrs(addrs).unwrap());
    announce.encode().unwrap()[1..].to_vec()
}

/// The ancestry node `r` holds for node `s` in its `ActivePeer`, the copy the
/// show-peers and snapshot paths read.
fn active_peer_path(nodes: &[TestNode], r: usize, s: usize) -> Vec<NodeAddr> {
    let sender = *nodes[s].node.node_addr();
    nodes[r]
        .node
        .get_peer(&sender)
        .expect("setup: peer exists")
        .coords()
        .expect("peer has a tree position")
        .node_addrs()
        .copied()
        .collect()
}

#[tokio::test]
async fn a_stale_tree_announce_leaves_the_active_peer_position_unchanged() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    let (s, r) = (0, 1);
    let sender = *nodes[s].node.node_addr();
    let root = make_node_addr(0);
    let (mid_new, mid_old, mid_next) = (make_node_addr(1), make_node_addr(2), make_node_addr(3));

    let held = nodes[r]
        .node
        .tree_state()
        .peer_declaration(&sender)
        .expect("setup: receiver holds the sender's declaration")
        .sequence();
    let n = held + 10;

    let fresh = signed_announce(&nodes, s, mid_new, n + 1, &[mid_new, root]);
    let stale = signed_announce(&nodes, s, mid_old, n, &[mid_old, root]);

    nodes[r].node.handle_tree_announce(&sender, &fresh).await;
    assert_eq!(
        active_peer_path(&nodes, r, s),
        vec![sender, mid_new, root],
        "setup: the fresher announce is stored"
    );

    let stale_before = nodes[r].node.metrics().tree.stale.get();
    nodes[r].node.handle_tree_announce(&sender, &stale).await;
    assert_eq!(nodes[r].node.metrics().tree.stale.get(), stale_before + 1);
    assert_eq!(
        active_peer_path(&nodes, r, s),
        vec![sender, mid_new, root],
        "a stale announce overwrote the peer's position shown to the operator"
    );
    let tree_path: Vec<NodeAddr> = nodes[r]
        .node
        .tree_state()
        .peer_coords(&sender)
        .unwrap()
        .node_addrs()
        .copied()
        .collect();
    assert_eq!(tree_path, active_peer_path(&nodes, r, s));

    // Control: a fresher announce still moves the stored position.
    let next = signed_announce(&nodes, s, mid_next, n + 2, &[mid_next, root]);
    nodes[r].node.handle_tree_announce(&sender, &next).await;
    assert_eq!(active_peer_path(&nodes, r, s), vec![sender, mid_next, root]);

    cleanup_nodes(&mut nodes).await;
}

/// A converged two-node tree in which node P (index 0) is forced under node Q
/// (index 1) at the synthetic root, `[P, Q, mid, root]`, with a signed
/// declaration. Lookup backoff is enabled so a backoff entry can be planted.
/// Returns the nodes and the descendant D whose cached coordinates run
/// through P.
async fn p_under_q_with_cached_descendant() -> (Vec<TestNode>, NodeAddr) {
    let configs = (0..2)
        .map(|_| {
            let mut config = crate::config::Config::new();
            config.node.lookup.backoff_base_secs = 30;
            config.node.lookup.backoff_max_secs = 300;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    let (p, q) = (0, 1);
    let p_addr = *nodes[p].node.node_addr();
    let q_addr = *nodes[q].node.node_addr();
    let (root, mid) = (make_node_addr(0), make_node_addr(1));

    {
        let ts = nodes[p].node.tree_state_mut();
        ts.remove_peer(&q_addr);
        ts.update_peer(
            ParentDeclaration::new(q_addr, mid, 1, 1000),
            TreeCoordinate::from_addrs(vec![q_addr, mid, root]).unwrap(),
        );
        ts.set_parent(q_addr, 1, 1000, 1000);
        ts.recompute_coords();
    }
    let identity = nodes[p].node.identity().clone();
    sign_declaration(
        nodes[p].node.tree_state_mut().my_declaration_mut(),
        &identity,
    )
    .unwrap();

    let descendant = make_node_addr(9);
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let _ = nodes[p].node.coord_cache_mut().insert(
        descendant,
        TreeCoordinate::from_addrs(vec![descendant, p_addr, q_addr, mid, root]).unwrap(),
        now_ms,
    );
    assert!(cached(&nodes, p, &descendant), "setup: descendant cached");
    nodes[p]
        .node
        .lookup
        .backoff
        .record_failure(&make_node_addr(7), crate::time::mono_ms());
    assert_eq!(
        nodes[p].node.lookup.backoff.entry_count(),
        1,
        "setup: backoff entry planted"
    );

    (nodes, descendant)
}

fn cached(nodes: &[TestNode], i: usize, addr: &NodeAddr) -> bool {
    nodes[i].node.coord_cache().get_entry(addr).is_some()
}

#[tokio::test]
async fn a_sequence_only_parent_update_keeps_cached_descendants_and_lookup_backoff() {
    let (mut nodes, descendant) = p_under_q_with_cached_descendant().await;
    let (p, q) = (0, 1);
    let q_addr = *nodes[q].node.node_addr();
    let (root, mid) = (make_node_addr(0), make_node_addr(1));

    // Q re-declares the same parent and ancestry at a fresher sequence.
    let announce = signed_announce(&nodes, q, mid, 5, &[mid, root]);
    let ancestry_before = nodes[p].node.metrics().tree.ancestry_changed.get();
    let accepted_before = nodes[p].node.metrics().tree.accepted.get();
    nodes[p].node.handle_tree_announce(&q_addr, &announce).await;

    assert_eq!(
        nodes[p].node.metrics().tree.accepted.get(),
        accepted_before + 1,
        "setup: the announce is accepted"
    );
    assert_eq!(
        nodes[p].node.metrics().tree.ancestry_changed.get(),
        ancestry_before
    );
    assert!(
        cached(&nodes, p, &descendant),
        "a parent update that left our path unchanged dropped a cached descendant"
    );
    assert_eq!(
        nodes[p].node.lookup.backoff.entry_count(),
        1,
        "a parent update that left our path unchanged cleared lookup backoff"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_parent_path_change_drops_cached_descendants_and_lookup_backoff() {
    let (mut nodes, descendant) = p_under_q_with_cached_descendant().await;
    let (p, q) = (0, 1);
    let q_addr = *nodes[q].node.node_addr();
    let (root, new_mid) = (make_node_addr(0), make_node_addr(2));

    // Q swaps its mid-chain ancestor, which changes P's address path.
    let announce = signed_announce(&nodes, q, new_mid, 5, &[new_mid, root]);
    let ancestry_before = nodes[p].node.metrics().tree.ancestry_changed.get();
    nodes[p].node.handle_tree_announce(&q_addr, &announce).await;

    assert_eq!(
        nodes[p].node.metrics().tree.ancestry_changed.get(),
        ancestry_before + 1
    );
    assert!(!cached(&nodes, p, &descendant));
    assert_eq!(nodes[p].node.lookup.backoff.entry_count(), 0);

    cleanup_nodes(&mut nodes).await;
}
