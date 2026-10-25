//! End-to-end session establishment tests.

use super::link_session_diag::{HeldMsg2Pair, node0_cut_over};
use super::*;
use crate::node::session::{session_after, session_at};
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, delay_loopback_delivery, drain_all_packets, generate_random_edges,
    initiate_handshake, lock_large_network_test, make_test_node_with_config, pinned_tree,
    populate_all_coord_caches, process_available_packets, run_tree_test,
    run_tree_test_with_configs, run_tree_test_with_mtus, run_tree_test_with_profiles,
    run_tree_test_with_profiles_leaf_smallest, verify_tree_convergence,
};
use crate::proto::fsp::{SessionAck, SessionMessageType, SessionMsg3};
use crate::proto::link::SessionDatagram;
use fips_core::proto::rekey::EpochTag;

/// A stand-in for the authenticated FMP link peer a datagram arrived over.
///
/// Tests that call `handle_session_payload` directly have no link underneath
/// them. The setup limiter keys on this address, so a test wanting to drain a
/// bucket has to drive `handle_session_datagram` instead.
fn stub_link_peer() -> NodeAddr {
    make_node_addr(0xFE)
}

/// Render each node's address and elected tree root.
///
/// Attached to mixed-profile failure messages: the failures worth diagnosing
/// there are root-election partitions, which are keyed on the random per-node
/// address ordering and so are invisible without the addresses that produced
/// them.
fn mesh_state(nodes: &[TestNode]) -> String {
    nodes
        .iter()
        .enumerate()
        .map(|(i, tn)| {
            format!(
                "node[{i}] addr={} root={} self_rooted={}",
                tn.node.node_addr(),
                tn.node.tree_state().root(),
                tn.node.tree_state().is_root()
            )
        })
        .collect::<Vec<_>>()
        .join("; ")
}

// ============================================================================
// Unit tests: SessionEntry data structure
// ============================================================================

#[test]
fn test_session_entry_new_initiating() {
    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let entry = crate::node::session::SessionEntry::opened_for_test(
        &identity_b.pubkey_full(),
        identity_a.keypair(),
        session_at(1000),
    );

    assert!(entry.is_initiating());
    assert!(!entry.is_established());
    assert!(!entry.is_awaiting_msg3());
    assert_eq!(entry.created_at(), session_at(1000));
    assert_eq!(entry.last_activity(), session_at(1000));
}

#[test]
fn test_session_entry_rekey_jitter_in_range() {
    use crate::node::REKEY_JITTER_SECS;

    // Every newly constructed SessionEntry's jitter must lie in the
    // symmetric range [-REKEY_JITTER_SECS, +REKEY_JITTER_SECS].
    for _ in 0..100 {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let entry = crate::node::session::SessionEntry::opened_for_test(
            &identity_b.pubkey_full(),
            identity_a.keypair(),
            session_at(1000),
        );
        let j = entry.rekey_jitter_secs();
        assert!(
            (-REKEY_JITTER_SECS..=REKEY_JITTER_SECS).contains(&j),
            "jitter {} outside [-{}, +{}]",
            j,
            REKEY_JITTER_SECS,
            REKEY_JITTER_SECS
        );
    }
}

#[test]
fn test_session_entry_rekey_jitter_mean_near_zero() {
    // Sanity check that the distribution is roughly symmetric and not
    // stuck at one extreme. With N=200 draws from a uniform ~30-second
    // range, the empirical mean should be well under 5 in absolute value.
    let mut sum: i64 = 0;
    let n: i64 = 200;
    for _ in 0..n {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let entry = crate::node::session::SessionEntry::opened_for_test(
            &identity_b.pubkey_full(),
            identity_a.keypair(),
            session_at(1000),
        );
        sum += entry.rekey_jitter_secs();
    }
    let mean = sum / n;
    assert!(
        mean.abs() < 5,
        "empirical mean {} not within 5 of 0 over {} samples",
        mean,
        n
    );
}

#[test]
fn test_session_entry_touch() {
    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let mut entry = crate::node::session::SessionEntry::opened_for_test(
        &identity_b.pubkey_full(),
        identity_a.keypair(),
        session_at(1000),
    );

    entry.touch(session_at(2000));
    assert_eq!(entry.last_activity(), session_at(2000));
    assert_eq!(entry.created_at(), session_at(1000));
}

/// A clock step back past the session's start must not wrap the inner
/// header's timestamp to near 2^32, which the peer reads as an RTT sample of
/// about 49 days.
#[test]
fn session_timestamp_is_zero_when_now_precedes_the_session_start() {
    let identity_a = Identity::generate();
    let identity_b = Identity::generate();
    let session = make_noise_session(&identity_a, &identity_b);
    let entry = crate::node::session::SessionEntry::keyed(
        *identity_b.node_addr(),
        session,
        session_at(10_000),
        true,
    );

    assert_eq!(entry.session_timestamp(session_at(11_500)), 1_500);
    assert_eq!(entry.session_timestamp(session_at(9_000)), 0);
}

#[test]
fn test_session_table_operations() {
    let mut node = make_node();
    let identity_b = Identity::generate();

    let dest_addr = *identity_b.node_addr();
    let entry = crate::node::session::SessionEntry::opened_for_test(
        &identity_b.pubkey_full(),
        node.identity().keypair(),
        session_at(1000),
    );

    node.sessions.insert(dest_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&dest_addr).is_some());
    assert!(node.get_session(&make_node_addr(0xFF)).is_none());

    let removed = node.remove_session(&dest_addr);
    assert!(removed.is_some());
    assert_eq!(node.session_count(), 0);
}

// ============================================================================
// Integration tests: 2-node direct session establishment
// ============================================================================

#[tokio::test]
async fn test_session_direct_peer_handshake() {
    // Two directly connected nodes: A initiates a session with B
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Node 0 initiates session with Node 1
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");

    // Node 0 should have a session in Initiating state
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_initiating()
    );

    // Process packets: SessionSetup arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionSetup packet to arrive");

    // Node 1 should now have a session in AwaitingMsg3 state (XX: identity not yet known)
    assert_eq!(nodes[1].node.session_count(), 1);
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_awaiting_msg3()
    );

    // Process packets: SessionAck arrives at Node 0, Node 0 sends SessionMsg3
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionAck packet to arrive");

    // Node 0 should now be Established (transitions after sending msg3)
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );

    // Process packets: SessionMsg3 arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected SessionMsg3 packet to arrive");

    // Node 1 should now be Established (transitions after processing msg3)
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_established()
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_direct_peer_data_transfer() {
    // Two nodes: establish session, then send data
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Establish session (XX: 3 messages — Setup, Ack, Msg3)
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Setup → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Ack → Node 0, Node 0 sends Msg3
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Msg3 → Node 1

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_established()
    );

    // Send data from Node 0 to Node 1
    let test_data = b"Hello, FIPS session!";
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, test_data)
        .await
        .expect("send_session_data failed");

    // Process packets: encrypted data arrives at Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    let count = process_available_packets(&mut nodes).await;
    assert!(count > 0, "Expected encrypted data to arrive");

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: 3-node forwarded session
// ============================================================================

#[tokio::test]
async fn test_session_3node_forwarded_handshake() {
    // A—B—C: Node A initiates session with Node C through transit node B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Node 0 initiates session with Node 2
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .expect("initiate_session failed");

    // Process: SessionSetup: 0→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionSetup: 1→2 (arrives at destination C)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 2 should have an AwaitingMsg3 session (XX: identity not yet known)
    assert!(
        nodes[2].node.get_session(&node0_addr).is_some(),
        "Node 2 should have a session entry for Node 0"
    );
    assert!(
        nodes[2]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_awaiting_msg3()
    );

    // Process: SessionAck: 2→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionAck: 1→0 (arrives at initiator A, sends SessionMsg3)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should now be Established (transitions after sending msg3)
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .unwrap()
            .is_established()
    );

    // Process: SessionMsg3: 0→1 (forwarded by transit B)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Process: SessionMsg3: 1→2 (arrives at responder C)
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 2 should now be Established (transitions after processing msg3)
    assert!(
        nodes[2]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_established()
    );

    // Transit node B should NOT have a session
    assert_eq!(
        nodes[1].node.session_count(),
        0,
        "Transit node should have no sessions"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_3node_forwarded_data() {
    // A—B—C: Establish session, send data end-to-end
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();

    // Establish session (needs more hops)
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .unwrap();

    // Drain packets until handshake completes (multi-hop needs several rounds)
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .map(|s| s.is_established())
            .unwrap_or(false),
        "Session should be established after handshake rounds"
    );

    // Send data
    let test_data = b"End-to-end through transit node B";
    nodes[0]
        .node
        .send_session_data(&node2_addr, 0, 0, test_data)
        .await
        .expect("send_session_data failed");

    // Drain data packet through transit node
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    // Node 2 should be Established (transitioned during XX handshake msg3)
    assert!(
        nodes[2]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .is_established()
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Edge cases
// ============================================================================

#[tokio::test]
async fn test_session_initiate_idempotent() {
    // Calling initiate_session twice should be idempotent
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // First call
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    assert_eq!(nodes[0].node.session_count(), 1);

    // Second call should be a no-op
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    assert_eq!(nodes[0].node.session_count(), 1);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_send_data_no_session_fails() {
    let mut node = make_node();
    let fake_addr = make_node_addr(0xAA);

    let result = node.send_session_data(&fake_addr, 0, 0, b"test").await;
    assert!(result.is_err(), "Should fail with no session");
}

#[tokio::test]
async fn test_session_ack_for_unknown_session() {
    // Receiving a SessionAck when we have no Initiating session should be dropped
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // Fabricate a SessionAck and deliver directly
    let src_coords = nodes[1].node.tree_state().my_coords().clone();
    let dest_coords = nodes[0].node.tree_state().my_coords().clone();
    let ack = SessionAck::new(src_coords, dest_coords).with_handshake(vec![0u8; 57]);
    let datagram = SessionDatagram::new(node1_addr, node0_addr, ack.encode());

    // Send through link layer
    let encoded = datagram.encode();
    nodes[1]
        .node
        .send_encrypted_link_message(&node0_addr, &encoded)
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Node 0 should have no sessions (ack was for unknown session)
    assert_eq!(nodes[0].node.session_count(), 0);

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Large-scale test: 100-node session establishment + bidirectional data
// ============================================================================

/// Drain packets until quiescent (2 consecutive idle rounds).
async fn drain_to_quiescence(nodes: &mut [TestNode]) {
    let mut idle_rounds = 0;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        let count = process_available_packets(nodes).await;
        if count == 0 {
            idle_rounds += 1;
            if idle_rounds >= 2 {
                break;
            }
        } else {
            idle_rounds = 0;
        }
    }
}

/// Mixed-profile lifecycle over loopback: a Full / Full / NonRouting / Leaf
/// mesh comes up, each node peers to the degree its role and topology
/// dictate, and end-to-end data reaches every reachable pair — including the
/// one multi-hop path, a Leaf node reaching a non-adjacent Full node through
/// the Full router between them. This is the in-process replacement for the
/// Docker `mixed-profile` suite: the node roles are the subject, and none of
/// it needs a real transport.
///
/// Topology (matching the retired Docker suite):
///
/// ```text
///   A (Full) ── B (Full)
///   │  \          │
///   │    \        │
///   D (Leaf)   C (NonRouting)
/// ```
#[tokio::test]
async fn mixed_profile_nodes_converge_and_forward() {
    use crate::proto::fmp::NodeProfile;

    // 0=A Full, 1=B Full, 2=C NonRouting, 3=D Leaf.
    let profiles = [
        NodeProfile::Full,
        NodeProfile::Full,
        NodeProfile::NonRouting,
        NodeProfile::Leaf,
    ];
    // A-B, A-C, A-D, B-C.
    let edges = [(0, 1), (0, 2), (0, 3), (1, 2)];
    let mut nodes = run_tree_test_with_profiles(&profiles, &edges, false).await;

    // Peer degree per role + topology: A=3 (B,C,D), B=2 (A,C), C=2 (A,B), D=1 (A).
    let peer_counts: Vec<usize> = nodes.iter().map(|n| n.node.peers().count()).collect();
    assert_eq!(
        peer_counts,
        vec![3, 2, 2, 1],
        "mixed-profile peer degrees (A=3, B=2, C=2, D=1)"
    );

    populate_all_coord_caches(&mut nodes);

    // TUN receiver on every node so delivered plaintext can be observed.
    let mut tun_rx = Vec::with_capacity(nodes.len());
    for tn in nodes.iter_mut() {
        let (tx, rx) = std::sync::mpsc::channel();
        tn.node.install_tun(tx);
        tun_rx.push(rx);
    }

    let info: Vec<(NodeAddr, secp256k1::PublicKey)> = nodes
        .iter()
        .map(|tn| (*tn.node.node_addr(), tn.node.identity().pubkey_full()))
        .collect();

    // Reachability the Docker suite asserted: F<->F, F<->N and F<->L between
    // adjacent nodes, plus the Leaf<->Full multi-hop pair D<->B routed through
    // the Full node A between them. Each is checked end to end.
    //
    // Unlike `leaf_smallest_addr_does_not_partition_multihop`, which pins the
    // Leaf to the smallest NodeAddr to make one partition mode deterministic,
    // this mesh draws its identities at random, so the multi-hop pair here is
    // exercised against whatever root election the address ordering produces.
    let reach: &[(usize, usize)] = &[
        (0, 1), // A -> B  Full <-> Full
        (1, 0), // B -> A
        (0, 2), // A -> C  Full <-> NonRouting
        (2, 0), // C -> A
        (1, 2), // B -> C
        (2, 1), // C -> B
        (0, 3), // A -> D  Full <-> Leaf
        (3, 0), // D -> A
        (3, 1), // D -> B  Leaf -> Full, two hops via A
        (1, 3), // B -> D  Full -> Leaf, two hops via A
    ];

    for &(src, dst) in reach {
        let (dst_addr, dst_pubkey) = info[dst];
        let src_addr = info[src].0;
        let initiated = nodes[src].node.initiate_session(dst_addr, dst_pubkey).await;
        if let Err(e) = initiated {
            panic!(
                "initiate_session {src}->{dst} failed: {e:?}; {}",
                mesh_state(&nodes)
            );
        }
        drain_to_quiescence(&mut nodes).await;

        let payload = format!("mp-{src}-{dst}").into_bytes();
        let src_fips = crate::Ipv6Address::from_node_addr(&src_addr);
        let dst_fips = crate::Ipv6Address::from_node_addr(&dst_addr);
        let ipv6 = build_ipv6_packet(&src_fips, &dst_fips, &payload);
        let sent = nodes[src].node.send_ipv6_packet(&dst_addr, &ipv6).await;
        if let Err(e) = sent {
            panic!("send {src}->{dst} failed: {e:?}; {}", mesh_state(&nodes));
        }
        drain_to_quiescence(&mut nodes).await;

        // TUN receives the decompressed IPv6 packet; match the upper-layer
        // payload after the 40-byte header, as the other forwarding tests do.
        let found = std::iter::from_fn(|| tun_rx[dst].try_recv().ok())
            .any(|pkt| pkt.len() >= 40 && pkt[40..] == payload[..]);
        if !found {
            panic!(
                "datagram {src}->{dst} must be delivered to node {dst}'s TUN; {}",
                mesh_state(&nodes)
            );
        }
    }

    cleanup_nodes(&mut nodes).await;
}

/// Regression: a Leaf holding the smallest NodeAddr must not self-elect as root
/// and partition the mesh, so a multi-hop session from the Leaf to a
/// non-adjacent Full node still establishes and delivers.
///
/// Topology A(Full) — B(Full), with D(Leaf) hanging off A. D is pinned to the
/// strictly smallest NodeAddr — the condition that made D self-elect as a second
/// root, partitioning A/B's tree from D's and leaving B unable to route its
/// handshake reply back to D. The multi-hop pair D->B (routed through A) is the
/// one the Docker `mixed-profile` suite covered.
///
/// Only Full and Leaf profiles appear here so the elected root is always the
/// smaller of the two Full nodes: the separate global-min-NonRouting partition
/// (a distinct open problem for the leaf/non-routing tree-participation model) is
/// deliberately kept out so this test isolates the Leaf fix.
///
/// Without the leaf gate D self-roots every run and D->B fails; with it, D
/// attaches under A and the session establishes.
#[tokio::test]
async fn leaf_smallest_addr_does_not_partition_multihop() {
    use crate::proto::fmp::NodeProfile;

    // 0=A Full, 1=B Full, 2=D Leaf (pinned smallest).
    let profiles = [NodeProfile::Full, NodeProfile::Full, NodeProfile::Leaf];
    // A-B, A-D (D is a single-upstream leaf hanging off A).
    let edges = [(0, 1), (0, 2)];
    let mut nodes = run_tree_test_with_profiles_leaf_smallest(&profiles, 2, &edges).await;

    // The mesh must be a single tree rooted at a Full node: D (the smallest
    // addr) must NOT be its own root. A partition shows up as D self-rooted.
    assert!(
        !nodes[2].node.tree_state().is_root(),
        "the Leaf (smallest addr) must not self-elect as root"
    );
    let roots: Vec<_> = nodes.iter().map(|n| *n.node.tree_state().root()).collect();
    assert!(
        roots.iter().all(|r| *r == roots[0]),
        "all nodes must share one root (no partition); got {roots:?}"
    );

    populate_all_coord_caches(&mut nodes);

    // TUN receiver on B so delivered plaintext can be observed.
    let (tx, b_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tx);

    let d_addr = *nodes[2].node.node_addr();
    let (b_addr, b_pubkey) = (
        *nodes[1].node.node_addr(),
        nodes[1].node.identity().pubkey_full(),
    );

    // D -> B: the multi-hop pair routed through A.
    nodes[2]
        .node
        .initiate_session(b_addr, b_pubkey)
        .await
        .expect("D->B initiate_session must succeed (no partition)");
    drain_to_quiescence(&mut nodes).await;

    let payload = b"leaf-multihop".to_vec();
    let d_fips = crate::Ipv6Address::from_node_addr(&d_addr);
    let b_fips = crate::Ipv6Address::from_node_addr(&b_addr);
    let ipv6 = build_ipv6_packet(&d_fips, &b_fips, &payload);
    nodes[2]
        .node
        .send_ipv6_packet(&b_addr, &ipv6)
        .await
        .expect("D->B send must succeed");
    drain_to_quiescence(&mut nodes).await;

    let found = std::iter::from_fn(|| b_rx.try_recv().ok())
        .any(|pkt| pkt.len() >= 40 && pkt[40..] == payload[..]);
    assert!(
        found,
        "D->B multi-hop datagram must be delivered to B's TUN"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_session_100_nodes() {
    let _guard = lock_large_network_test().await;

    use rand::rngs::StdRng;
    use rand::{RngExt, SeedableRng};
    use std::sync::mpsc;
    use std::time::Instant;

    // Same random topology as other 100-node tests
    const NUM_NODES: usize = 100;
    const TARGET_EDGES: usize = 250;
    const SEED: u64 = 42;

    let start = Instant::now();

    let edges = generate_random_edges(NUM_NODES, TARGET_EDGES, SEED);
    let mut nodes = run_tree_test(NUM_NODES, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let setup_time = start.elapsed();

    // Collect identities: (node_addr, pubkey) for all nodes
    let all_info: Vec<(NodeAddr, secp256k1::PublicKey)> = nodes
        .iter()
        .map(|tn| (*tn.node.node_addr(), tn.node.identity().pubkey_full()))
        .collect();

    // Each node picks one random target for its outbound session.
    // Use deterministic RNG so failures are reproducible.
    let mut rng = StdRng::seed_from_u64(SEED + 1);
    let mut session_pairs: Vec<(usize, usize)> = Vec::with_capacity(NUM_NODES);
    for src in 0..NUM_NODES {
        let mut dst = rng.random_range(0..NUM_NODES);
        while dst == src {
            dst = rng.random_range(0..NUM_NODES);
        }
        session_pairs.push((src, dst));
    }

    // === Phase 1: Establish all sessions ===

    let session_start = Instant::now();

    for &(src, dst) in &session_pairs {
        let (dest_addr, dest_pubkey) = all_info[dst];

        nodes[src]
            .node
            .initiate_session(dest_addr, dest_pubkey)
            .await
            .expect("initiate_session failed");

        drain_to_quiescence(&mut nodes).await;
    }

    drain_to_quiescence(&mut nodes).await;
    let session_time = session_start.elapsed();

    // Verify all initiator sessions reached Established before data phase
    let mut handshake_failures: Vec<(usize, usize)> = Vec::new();
    for &(src, dst) in &session_pairs {
        let dest_addr = all_info[dst].0;
        let ok = nodes[src]
            .node
            .get_session(&dest_addr)
            .map(|e| e.is_established())
            .unwrap_or(false);
        if !ok {
            handshake_failures.push((src, dst));
        }
    }
    assert!(
        handshake_failures.is_empty(),
        "Handshake failed for {} pairs (first: {:?})",
        handshake_failures.len(),
        handshake_failures.first()
    );

    // === Phase 2: Inject TUN receivers and snapshot link stats ===

    // Install a tun_tx on every node so delivered datagrams can be counted.
    let mut tun_receivers: Vec<mpsc::Receiver<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for tn in nodes.iter_mut() {
        let (tx, rx) = mpsc::channel();
        tn.node.install_tun(tx);
        tun_receivers.push(rx);
    }

    // Snapshot per-peer link stats before data phase
    let link_pkts_sent_before: Vec<Vec<(NodeAddr, u64)>> = nodes
        .iter()
        .map(|tn| {
            tn.node
                .peers()
                .map(|p| (*p.node_addr(), p.link_stats().packets_sent))
                .collect()
        })
        .collect();

    // === Phase 3: Bidirectional data transfer ===
    //
    // For each session pair:
    //   1. Initiator sends one datagram to responder
    //   2. Responder sends one datagram back to initiator
    //
    // Batched per pair with draining between each.

    let data_start = Instant::now();
    let mut send_forward_ok = 0usize;
    let mut send_forward_err = 0usize;
    let mut send_reverse_ok = 0usize;
    let mut send_reverse_err = 0usize;

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let dest_addr = all_info[dst].0;
        let src_addr = all_info[src].0;

        // Build IPv6 packets with pair index as payload
        let src_fips = crate::Ipv6Address::from_node_addr(&src_addr);
        let dst_fips = crate::Ipv6Address::from_node_addr(&dest_addr);

        // Forward: initiator → responder
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let fwd_ipv6 = build_ipv6_packet(&src_fips, &dst_fips, &fwd_payload);
        match nodes[src]
            .node
            .send_ipv6_packet(&dest_addr, &fwd_ipv6)
            .await
        {
            Ok(()) => send_forward_ok += 1,
            Err(_) => send_forward_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;

        // Reverse: responder → initiator
        // (Responder should already be Established after XX msg3)
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();
        let rev_ipv6 = build_ipv6_packet(&dst_fips, &src_fips, &rev_payload);
        match nodes[dst].node.send_ipv6_packet(&src_addr, &rev_ipv6).await {
            Ok(()) => send_reverse_ok += 1,
            Err(_) => send_reverse_err += 1,
        }

        drain_to_quiescence(&mut nodes).await;
    }

    let data_time = data_start.elapsed();

    // === Phase 4: Collect delivered datagrams from TUN receivers ===

    let mut delivered_per_node: Vec<Vec<Vec<u8>>> = Vec::with_capacity(NUM_NODES);
    for rx in tun_receivers.iter_mut() {
        let mut packets = Vec::new();
        while let Ok(pkt) = rx.try_recv() {
            packets.push(pkt);
        }
        delivered_per_node.push(packets);
    }

    let total_delivered: usize = delivered_per_node.iter().map(|v| v.len()).sum();

    // Verify each pair's forward and reverse datagrams arrived
    let mut fwd_delivered = 0usize;
    let mut rev_delivered = 0usize;
    let mut fwd_missing: Vec<(usize, usize)> = Vec::new();
    let mut rev_missing: Vec<(usize, usize)> = Vec::new();

    for (pair_idx, &(src, dst)) in session_pairs.iter().enumerate() {
        let fwd_payload = format!("fwd-{}", pair_idx).into_bytes();
        let rev_payload = format!("rev-{}", pair_idx).into_bytes();

        // After decompression, TUN receives full IPv6 packets.
        // Check that delivered packet's upper-layer payload matches.
        let fwd_found = delivered_per_node[dst]
            .iter()
            .any(|pkt| pkt.len() >= 40 && pkt[40..] == fwd_payload);
        if fwd_found {
            fwd_delivered += 1;
        } else if fwd_missing.len() < 20 {
            fwd_missing.push((src, dst));
        }

        let rev_found = delivered_per_node[src]
            .iter()
            .any(|pkt| pkt.len() >= 40 && pkt[40..] == rev_payload);
        if rev_found {
            rev_delivered += 1;
        } else if rev_missing.len() < 20 {
            rev_missing.push((src, dst));
        }
    }

    // === Phase 5: Final session state ===

    let mut total_established = 0usize;
    let mut total_responding = 0usize;
    let mut total_initiating = 0usize;
    let mut fully_established_nodes = 0usize;

    for tn in &nodes {
        let mut all_est = true;
        for (_, entry) in tn.node.sessions.iter() {
            if entry.is_established() {
                total_established += 1;
            } else if entry.is_awaiting_msg3() {
                total_responding += 1;
                all_est = false;
            } else {
                total_initiating += 1;
                all_est = false;
            }
        }
        if tn.node.session_count() > 0 && all_est {
            fully_established_nodes += 1;
        }
    }

    let session_counts: Vec<usize> = nodes.iter().map(|tn| tn.node.session_count()).collect();
    let total_sessions: usize = session_counts.iter().sum();
    let min_sessions = *session_counts.iter().min().unwrap();
    let max_sessions = *session_counts.iter().max().unwrap();

    // === Phase 6: Link and routing statistics ===

    // Link stats delta: packets sent during data phase
    let mut data_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_sent: u64 = 0;
    let mut total_link_pkts_recv: u64 = 0;
    let mut total_link_bytes_sent: u64 = 0;
    let mut total_link_bytes_recv: u64 = 0;

    for (i, tn) in nodes.iter().enumerate() {
        for peer in tn.node.peers() {
            let stats = peer.link_stats();
            // Delta for this peer since before data phase
            let before = link_pkts_sent_before[i]
                .iter()
                .find(|(addr, _)| addr == peer.node_addr())
                .map(|(_, pkts)| *pkts)
                .unwrap_or(0);
            data_link_pkts_sent += stats.packets_sent.saturating_sub(before);

            // Totals (cumulative since node creation)
            total_link_pkts_sent += stats.packets_sent;
            total_link_pkts_recv += stats.packets_recv;
            total_link_bytes_sent += stats.bytes_sent;
            total_link_bytes_recv += stats.bytes_recv;
        }
    }

    // Estimate average hop count from link packet overhead.
    // Each data datagram traverses N link hops, each producing 1 link send.
    // We sent 200 datagrams total (100 forward + 100 reverse).
    let total_data_datagrams = (send_forward_ok + send_reverse_ok) as u64;
    let avg_hops = if total_data_datagrams > 0 {
        data_link_pkts_sent as f64 / total_data_datagrams as f64
    } else {
        0.0
    };

    // Coord cache stats
    let coord_cache_sizes: Vec<usize> =
        nodes.iter().map(|tn| tn.node.coord_cache().len()).collect();
    let total_coord_entries: usize = coord_cache_sizes.iter().sum();
    let min_coord = *coord_cache_sizes.iter().min().unwrap();
    let max_coord = *coord_cache_sizes.iter().max().unwrap();

    // === Report ===

    eprintln!("\n  === Session 100-Node Test ===");
    eprintln!(
        "  Topology: {} nodes, {} edges (seed {})",
        NUM_NODES,
        edges.len(),
        SEED
    );
    eprintln!(
        "  Session pairs: {} (1 outbound per node, random target)",
        session_pairs.len()
    );

    eprintln!("\n  --- Handshake ---");
    eprintln!(
        "  Initiator established: {}/{}",
        session_pairs.len(),
        session_pairs.len()
    );

    eprintln!("\n  --- Data Transfer ---");
    eprintln!(
        "  Forward (initiator->responder): {} sent, {} errors",
        send_forward_ok, send_forward_err
    );
    eprintln!(
        "  Reverse (responder->initiator): {} sent, {} errors",
        send_reverse_ok, send_reverse_err
    );
    eprintln!(
        "  TUN delivery: {} total ({} expected)",
        total_delivered,
        send_forward_ok + send_reverse_ok
    );
    eprintln!(
        "  Forward delivered: {}/{} | Reverse delivered: {}/{}",
        fwd_delivered, send_forward_ok, rev_delivered, send_reverse_ok
    );

    eprintln!("\n  --- Final Session State ---");
    eprintln!(
        "  Entries: {} total ({} established, {} responding, {} initiating)",
        total_sessions, total_established, total_responding, total_initiating
    );
    eprintln!(
        "  Per node: min={} max={} avg={:.1}",
        min_sessions,
        max_sessions,
        total_sessions as f64 / NUM_NODES as f64
    );
    eprintln!(
        "  All-established nodes: {}/{}",
        fully_established_nodes, NUM_NODES
    );

    eprintln!("\n  --- Routing ---");
    eprintln!(
        "  Data-phase link hops: {} ({:.1} avg hops/datagram over {} datagrams)",
        data_link_pkts_sent, avg_hops, total_data_datagrams
    );
    eprintln!(
        "  Lifetime link totals: {} pkts sent, {} pkts recv, {:.1} KB sent, {:.1} KB recv",
        total_link_pkts_sent,
        total_link_pkts_recv,
        total_link_bytes_sent as f64 / 1024.0,
        total_link_bytes_recv as f64 / 1024.0
    );
    eprintln!(
        "  Coord cache: total={} min={} max={} avg={:.1}",
        total_coord_entries,
        min_coord,
        max_coord,
        total_coord_entries as f64 / NUM_NODES as f64
    );

    eprintln!("\n  --- Timing ---");
    eprintln!(
        "  Setup: {:.1}s | Handshake: {:.1}s | Data: {:.1}s | Total: {:.1}s",
        setup_time.as_secs_f64(),
        session_time.as_secs_f64(),
        data_time.as_secs_f64(),
        start.elapsed().as_secs_f64()
    );

    if !fwd_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered forward datagrams:",
            fwd_missing.len()
        );
        for &(src, dst) in &fwd_missing {
            eprintln!("    node {} -> node {}", src, dst);
        }
    }
    if !rev_missing.is_empty() {
        eprintln!(
            "\n  First {} undelivered reverse datagrams:",
            rev_missing.len()
        );
        for &(src, dst) in &rev_missing {
            eprintln!("    node {} <- node {}", src, dst);
        }
    }

    // === Assertions ===

    assert_eq!(send_forward_err, 0, "All forward sends should succeed");
    assert_eq!(
        send_reverse_err, 0,
        "All reverse sends should succeed (responder Established after XX msg3)"
    );
    assert_eq!(
        fwd_delivered, send_forward_ok,
        "All forward datagrams should be delivered to responder TUN"
    );
    assert_eq!(
        rev_delivered, send_reverse_ok,
        "All reverse datagrams should be delivered to initiator TUN"
    );
    assert_eq!(
        total_established, total_sessions,
        "All {} session entries should be Established, \
         but {} responding, {} initiating",
        total_sessions, total_responding, total_initiating
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Data plane integration tests: TUN → session → link → TUN
// ============================================================================

/// Build a minimal valid IPv6 packet with given source and destination addresses.
fn build_ipv6_packet(
    src: &crate::Ipv6Address,
    dst: &crate::Ipv6Address,
    payload: &[u8],
) -> Vec<u8> {
    let payload_len = payload.len() as u16;
    let mut packet = vec![0u8; 40 + payload.len()];
    // Version (6) + traffic class high nibble
    packet[0] = 0x60;
    // Payload length (u16 BE)
    packet[4] = (payload_len >> 8) as u8;
    packet[5] = (payload_len & 0xff) as u8;
    // Next header: 59 = No Next Header
    packet[6] = 59;
    // Hop limit
    packet[7] = 64;
    // Source address (bytes 8-23)
    packet[8..24].copy_from_slice(src.as_bytes());
    // Destination address (bytes 24-39)
    packet[24..40].copy_from_slice(dst.as_bytes());
    // Payload
    packet[40..].copy_from_slice(payload);
    packet
}

#[test]
fn test_identity_cache_populated_on_promote() {
    use crate::proto::fmp::PromotionResult;

    let mut node = make_node();
    let transport_id = TransportId::new(1);
    let link_id = LinkId::new(1);

    let peer_identity = seed_completed_connection(&mut node, link_id, transport_id, 1000);

    // Promote
    let result = node
        .promote_connection(link_id, peer_identity, 2000)
        .unwrap();
    assert!(matches!(result, PromotionResult::Promoted(_)));

    // Identity cache should contain the peer
    let peer_addr = *peer_identity.node_addr();
    let prefix = peer_addr.prefix();
    let cached = node.lookup_by_fips_prefix(&prefix);
    assert!(
        cached.is_some(),
        "Identity cache should contain promoted peer"
    );
    let (cached_addr, cached_pk) = cached.unwrap();
    assert_eq!(cached_addr, peer_addr);
    assert_eq!(cached_pk, peer_identity.pubkey_full());
}

#[tokio::test]
async fn test_tun_outbound_established_session() {
    // Two directly connected nodes, session established.
    // Inject IPv6 packet via handle_tun_outbound on Node 0,
    // verify plaintext arrives at Node 1's tun_tx.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node1_addr);

    // Establish session (XX: 3 messages — Setup, Ack, Msg3)
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Setup → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Ack → Node 0, Node 0 sends Msg3
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await; // Msg3 → Node 1

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun_tx);

    // Build and inject an IPv6 packet
    let test_payload = b"data-plane-test-12345";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Process packets: encrypted data → Node 1
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // Verify plaintext arrived at Node 1's TUN
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Exactly one packet should be delivered");
    assert_eq!(
        delivered[0], ipv6_packet,
        "Delivered packet should match original"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A—B—C with an established A→C session, then the route to C lost the way
/// a link change loses it: A's coordinates for C are flushed while both ends
/// keep the session. With `evict_identity`, A's identity entry for C goes
/// too, as a bounded cache can drop it on a long-lived session; a lookup's
/// answer is verified against it, so the relookup has to restore it from the
/// session. Returns the nodes and C's address.
async fn session_with_its_route_lost(evict_identity: bool) -> (Vec<TestNode>, NodeAddr) {
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node2_addr = *nodes[2].node.node_addr();
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .unwrap();
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .is_some_and(|s| s.is_established()),
        "session established before the route is lost"
    );

    nodes[0].node.coord_cache.remove(&node2_addr);
    if evict_identity {
        let prefix = node2_addr.prefix();
        nodes[0].node.identity_cache.remove(&prefix);
        assert!(!nodes[0].node.has_cached_identity(&node2_addr));
    }
    assert!(
        nodes[0].node.find_next_hop(&node2_addr).is_none(),
        "no route to C without its coordinates"
    );
    (nodes, node2_addr)
}

/// A TUN packet on a session that lost its route starts a lookup instead of
/// failing until the session idles out, and the session carries the next
/// packet once the route is back.
#[tokio::test]
async fn a_tun_send_on_a_session_that_lost_its_route_looks_the_route_up_again() {
    // The TUN path maps the packet's address to C through the identity
    // cache before it reaches the session, so the entry stays.
    let (mut nodes, node2_addr) = session_with_its_route_lost(false).await;
    let node0_addr = *nodes[0].node.node_addr();
    let (_tun_outbound, tun_rx) = nodes[2].node.enable_app_owned_tun();
    let src = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst = crate::Ipv6Address::from_node_addr(&node2_addr);

    // This packet finds no route and is lost, but it starts the lookup.
    nodes[0]
        .node
        .handle_tun_outbound(build_ipv6_packet(&src, &dst, b"lost"))
        .await;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[0].node.find_next_hop(&node2_addr).is_some(),
        "the lookup restored a route to C"
    );

    let packet = build_ipv6_packet(&src, &dst, b"after the route returned");
    nodes[0].node.handle_tun_outbound(packet.clone()).await;
    for _ in 0..5 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert!(
        delivered.contains(&packet),
        "the packet after the lookup reaches C on the existing session"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The native datagram API's send on a session that lost its route starts a
/// lookup the same way, and restores C's evicted identity from the session so
/// the lookup's answer can be verified.
#[tokio::test]
async fn a_native_send_on_a_session_that_lost_its_route_looks_the_route_up_again() {
    let (mut nodes, node2_addr) = session_with_its_route_lost(true).await;
    let key = crate::native::registry::FlowKey {
        peer: node2_addr,
        remote: 7000,
        local: 7001,
    };
    let node2_xonly = nodes[2].node.identity().pubkey();

    nodes[0]
        .node
        .handle_native_outbound(key, node2_xonly, b"lost".to_vec())
        .await;
    for _ in 0..10 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[0].node.find_next_hop(&node2_addr).is_some(),
        "the lookup restored a route to C"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .is_some_and(|s| s.is_established()),
        "the existing session is still the one in place"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A completed rekey cutover must not break the data plane: an encrypted
/// datagram sent after the K-bit cutover decodes on the new session, and the
/// peer is not spuriously torn down.
///
/// This is the wire-continuity half of the rekey property the Docker `rekey`
/// suites exercised. The rekey timing and choreography decision itself lives in
/// the sans-IO cores and is covered exhaustively there
/// (`proto/fsp/tests/core.rs`, `proto/fmp/tests/core.rs`); this drives a real
/// XX rekey handshake over the loopback transport so the AEAD continuity across
/// the cutover is asserted end to end.
///
/// Deterministic, no wall-clock wait and no clock read on the responder:
/// `rekey.after_messages = 1` makes the first sent datagram cross the
/// initiator's trigger, and the responder classifies the arrival from the rekey
/// marker the initiator declares in its msg3 negotiation TLV.
///
/// The message-count arm is what carries this test's value. It is the arm the
/// retired age-based discriminator got wrong, and suppressing the marker so the
/// responder falls back to the cross-connection path reds the post-cutover
/// assertion, which is what shows the test discriminates the two arms rather
/// than merely observing a session index change.
#[tokio::test]
async fn rekey_cutover_preserves_data_plane() {
    // node 0 rekeys on the message counter; time never triggers it.
    let mut cfg0 = crate::config::Config::new();
    cfg0.node.rekey.after_messages = 1;
    cfg0.node.rekey.after_secs = u64::MAX;
    let cfg1 = crate::config::Config::new();

    let mut nodes = vec![
        make_test_node_with_config(cfg0, 1280).await,
        make_test_node_with_config(cfg1, 1280).await,
    ];

    // FMP peering + FSP session between the two loopback nodes.
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&node1_addr).is_some());
    assert!(nodes[1].node.get_peer(&node0_addr).is_some());
    populate_all_coord_caches(&mut nodes);

    let node1_pubkey = nodes[1].node.identity().pubkey_full();
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established(),
        "session established"
    );

    // node 1's TUN receiver observes decoded plaintext.
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun_tx);
    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node1_addr);

    // Baseline: data decodes on the original session, and this send bumps the
    // counter across the rekey trigger.
    let pre = build_ipv6_packet(&src_fips, &dst_fips, b"pre-rekey-payload");
    nodes[0].node.handle_tun_outbound(pre.clone()).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    process_available_packets(&mut nodes).await;
    let pre_delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        pre_delivered,
        vec![pre.clone()],
        "baseline datagram must decode before the rekey"
    );

    let idx_before = nodes[0].node.get_peer(&node1_addr).unwrap().our_index();

    // Only the initiator is aged, past the 31 s link and session floors below
    // which its link rekey machine starts nothing. The responder's session
    // stays young: it classifies the arrival from the sender's msg3
    // declaration and reads no clock, so its age gates nothing.
    nodes[0]
        .node
        .get_peer_mut(&node1_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(32));

    // Drive the real rekey handshake (msg1/msg2/msg3 over loopback) to
    // cutover, which the initiator takes after the cutover delay.
    for _ in 0..6 {
        if nodes[0]
            .node
            .get_peer(&node1_addr)
            .is_some_and(|p| p.pending_new_session().is_some())
        {
            super::rekey_parity::pass_cutover_delay();
        }
        nodes[0].node.poll_link_rekeys().await;
        nodes[1].node.poll_link_rekeys().await;
        for _ in 0..3 {
            tokio::time::sleep(Duration::from_millis(5)).await;
            process_available_packets(&mut nodes).await;
        }
    }

    // The cutover actually happened: node 0's live session index changed and no
    // rekey is left dangling. Guards against a vacuous pass where the rekey
    // never fired.
    let idx_after = nodes[0].node.get_peer(&node1_addr).unwrap().our_index();
    assert_ne!(
        idx_after, idx_before,
        "rekey must cut the live session over to a new index"
    );
    assert!(
        !nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .rekey_in_progress(),
        "rekey must have completed, not left in progress"
    );

    // Continuity: a datagram sent after the cutover decodes on the NEW session.
    let post = build_ipv6_packet(&src_fips, &dst_fips, b"post-rekey-payload");
    nodes[0].node.handle_tun_outbound(post.clone()).await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    process_available_packets(&mut nodes).await;
    let post_delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        post_delivered,
        vec![post.clone()],
        "datagram sent after the cutover must decode on the new session"
    );

    // No spurious teardown across the rekey.
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_some(),
        "peer must survive the rekey"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established(),
        "session must remain established after the rekey"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A two-node pair with an FSP session over an FMP link whose link sessions
/// have been aged. Built by [`aged_link_pair`].
pub(super) struct AgedLinkPair {
    pub(super) nodes: Vec<TestNode>,
    pub(super) node0_addr: NodeAddr,
    pub(super) node1_addr: NodeAddr,
}

/// Build a two-node pair from `cfg0` and `cfg1`, peer node 0 to node 1 over
/// FMP, open an FSP session from node 0, show that both directions decode,
/// then backdate both link sessions by `age`.
pub(super) async fn aged_link_pair(
    cfg0: crate::config::Config,
    cfg1: crate::config::Config,
    age: Duration,
) -> AgedLinkPair {
    let mut nodes = vec![
        make_test_node_with_config(cfg0, 1280).await,
        make_test_node_with_config(cfg1, 1280).await,
    ];

    // FMP peering + FSP session between the two loopback nodes.
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&node1_addr).is_some());
    assert!(nodes[1].node.get_peer(&node0_addr).is_some());
    populate_all_coord_caches(&mut nodes);

    let node1_pubkey = nodes[1].node.identity().pubkey_full();
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes).await;
    }
    for (i, remote) in [(0, node1_addr), (1, node0_addr)] {
        assert!(
            nodes[i]
                .node
                .get_session(&remote)
                .is_some_and(|s| s.is_established()),
            "node {i} session established"
        );
    }

    // Each node's TUN receiver observes the plaintext the other one sent.
    let (tun0_tx, tun0_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun0_tx);
    let (tun1_tx, tun1_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun1_tx);
    let fips0 = crate::Ipv6Address::from_node_addr(&node0_addr);
    let fips1 = crate::Ipv6Address::from_node_addr(&node1_addr);

    // Baseline: both directions decode before the caller's scenario, so a
    // later failure is the scenario's and not the harness's.
    let pre_fwd = build_ipv6_packet(&fips0, &fips1, b"pre-rekey 0 to 1");
    let pre_rev = build_ipv6_packet(&fips1, &fips0, b"pre-rekey 1 to 0");
    nodes[0].node.handle_tun_outbound(pre_fwd.clone()).await;
    nodes[1].node.handle_tun_outbound(pre_rev.clone()).await;
    pump_until_quiet(&mut nodes).await;
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![pre_fwd], "baseline node 0 to node 1 must decode");
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![pre_rev], "baseline node 1 to node 0 must decode");

    // Age both link sessions.
    nodes[0]
        .node
        .get_peer_mut(&node1_addr)
        .unwrap()
        .test_backdate_session_established(age);
    nodes[1]
        .node
        .get_peer_mut(&node0_addr)
        .unwrap()
        .test_backdate_session_established(age);

    AgedLinkPair {
        nodes,
        node0_addr,
        node1_addr,
    }
}

/// Deliver queued packets between the nodes until a round moves none, for at
/// most 50 rounds of 10 ms.
pub(super) async fn pump_until_quiet(nodes: &mut [TestNode]) {
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        if process_available_packets(nodes).await == 0 {
            break;
        }
    }
}

/// A ReceiverReport claiming `highest` frames received with nothing lost.
fn receiver_report(highest: u64) -> crate::proto::mmp::ReceiverReport {
    crate::proto::mmp::ReceiverReport {
        highest_counter: highest,
        cumulative_packets_recv: highest,
        cumulative_bytes_recv: highest * 100,
        timestamp_echo: 0,
        dwell_time: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
    }
}

/// A ReceiverReport, encoded as a link message, claiming `highest` frames
/// received with nothing lost.
fn receiver_report_message(highest: u64) -> Vec<u8> {
    receiver_report(highest).encode()
}

/// A link rekey initiator that has cut over keeps its new session's MMP state
/// free of frames the responder sealed on the old session.
///
/// node 0 cuts over after the cutover delay and resets its MMP receiver and
/// metrics. node 1 has not yet read node 0's msg3, so it still sends on the
/// old session, and node 0 decrypts those frames against its previous
/// session during the drain. Their payload is still delivered, but they
/// describe the old session: a data frame's counter must not become the new
/// session's highest counter, which would make every new-session frame count
/// as a reorder, and a ReceiverReport about node 0's old-session traffic must
/// not become the baseline later reports are judged against, which would
/// reject every new-session report as regressed. Once node 1 reads the msg3
/// and promotes, its frames and reports on the new session are counted and
/// accepted.
#[tokio::test]
async fn frames_on_the_previous_link_session_do_not_feed_the_new_sessions_mmp() {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        node1_idx_before,
        ..
    } = node0_cut_over().await;
    let (tun0_tx, tun0_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun0_tx);
    let (tun1_tx, tun1_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun1_tx);
    let fips0 = crate::Ipv6Address::from_node_addr(&node0_addr);
    let fips1 = crate::Ipv6Address::from_node_addr(&node1_addr);

    let mmp = nodes[0]
        .node
        .get_peer(&node1_addr)
        .unwrap()
        .mmp()
        .expect("node 0 must run link MMP");
    assert_eq!(mmp.receiver.highest_counter(), 0, "the cutover resets MMP");
    assert_eq!(mmp.metrics.rr_counters(), None, "the cutover resets MMP");
    let reports_before = mmp.metrics.reports_seen();

    // node 1, still on the old session, sends data and then a report about
    // node 0's old-session traffic. Only node 0's queue is delivered.
    let old_rev = build_ipv6_packet(&fips1, &fips0, b"old session 1 to 0");
    nodes[1].node.handle_tun_outbound(old_rev.clone()).await;
    nodes[1]
        .node
        .send_encrypted_link_message(&node0_addr, &receiver_report_message(1_000))
        .await
        .unwrap();
    assert_eq!(
        nodes[1].node.get_peer(&node0_addr).unwrap().our_index(),
        node1_idx_before,
        "node 1 must still be on the old session"
    );
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes[..1]).await;
    }

    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![old_rev],
        "an old-session frame's payload must still be delivered"
    );
    let mmp = nodes[0].node.get_peer(&node1_addr).unwrap().mmp().unwrap();
    assert_eq!(
        mmp.metrics.reports_seen(),
        reports_before,
        "an old-session ReceiverReport must not reach the new session's metrics"
    );
    assert_eq!(mmp.metrics.rr_counters(), None);
    assert_eq!(
        mmp.receiver.highest_counter(),
        0,
        "an old-session frame's counter must not become the new session's highest"
    );

    // node 1 reads the msg3 still queued for it, and node 0's first
    // new-epoch frame promotes it; node 1's frames and reports on the new
    // session then feed node 0's MMP.
    let new_fwd = build_ipv6_packet(&fips0, &fips1, b"new session 0 to 1");
    nodes[0].node.handle_tun_outbound(new_fwd.clone()).await;
    pump_until_quiet(&mut nodes).await;
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![new_fwd]);
    assert_ne!(
        nodes[1].node.get_peer(&node0_addr).unwrap().our_index(),
        node1_idx_before,
        "node 1 must promote on node 0's first new-epoch frame"
    );
    let new_rev = build_ipv6_packet(&fips1, &fips0, b"new session 1 to 0");
    nodes[1].node.handle_tun_outbound(new_rev.clone()).await;
    nodes[1]
        .node
        .send_encrypted_link_message(&node0_addr, &receiver_report_message(5))
        .await
        .unwrap();
    pump_until_quiet(&mut nodes).await;
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![new_rev]);
    let mmp = nodes[0].node.get_peer(&node1_addr).unwrap().mmp().unwrap();
    assert!(
        mmp.receiver.highest_counter() > 0,
        "new-session frames must be counted"
    );
    assert_eq!(
        mmp.metrics.rr_counters().map(|(highest, _, _)| highest),
        Some(5),
        "a new-session ReceiverReport must be accepted"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The decrypt-worker path tells the sessions apart too. A frame the worker
/// decrypted under the previous session's index, bounced back after the
/// cutover, does not feed the new session's MMP; the same frame under the
/// current session's index does.
#[cfg(unix)]
#[tokio::test]
async fn a_worker_decrypted_frame_on_the_previous_link_session_does_not_feed_mmp() {
    use crate::node::decrypt_worker::DecryptFallback;
    use crate::proto::fmp::wire::FLAG_KEY_EPOCH;

    let HeldMsg2Pair {
        mut nodes,
        node1_addr,
        node0_idx_before,
        ..
    } = node0_cut_over().await;
    let peer = nodes[0].node.get_peer(&node1_addr).unwrap();
    let previous_idx = peer.previous_our_index().expect("node 0 must be draining");
    assert_eq!(Some(previous_idx), node0_idx_before);
    let current_idx = peer.our_index().expect("node 0 must have cut over");
    let current_flags = if peer.current_k_bit() {
        FLAG_KEY_EPOCH
    } else {
        0
    };
    let previous_flags = current_flags ^ FLAG_KEY_EPOCH;

    // A bounced worker plaintext: the 4-byte session timestamp, then a
    // ReceiverReport about 1000 frames.
    let (transport_id, remote_addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    let bounce = |receiver_idx: u32, counter: u64, fmp_flags: u8| {
        let mut data = 0u32.to_le_bytes().to_vec();
        data.extend(receiver_report_message(1_000));
        DecryptFallback {
            source_node_addr: node1_addr,
            transport_id,
            remote_addr: remote_addr.clone(),
            timestamp_ms: Node::now_ms(),
            packet_len: data.len() + 32,
            receiver_idx,
            fmp_counter: counter,
            fmp_flags,
            fmp_plaintext_len: data.len(),
            packet_data: data,
            fmp_plaintext_offset: 0,
        }
    };

    let previous = bounce(previous_idx.as_u32(), 900, previous_flags);
    nodes[0].node.process_decrypt_fallback(previous).await;
    let mmp = nodes[0].node.get_peer(&node1_addr).unwrap().mmp().unwrap();
    assert_eq!(
        mmp.receiver.highest_counter(),
        0,
        "a previous-session frame's counter must not be counted"
    );
    assert_eq!(
        mmp.metrics.rr_counters(),
        None,
        "a previous-session ReceiverReport must not be processed"
    );

    let current = bounce(current_idx.as_u32(), 1, current_flags);
    nodes[0].node.process_decrypt_fallback(current).await;
    let mmp = nodes[0].node.get_peer(&node1_addr).unwrap().mmp().unwrap();
    assert_eq!(mmp.receiver.highest_counter(), 1);
    assert_eq!(mmp.metrics.rr_counters().map(|(h, _, _)| h), Some(1_000));

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_triggers_session_initiation() {
    // Two connected nodes, no session yet.
    // Inject a TUN packet — should trigger session initiation,
    // queue the packet, and deliver after handshake completes.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node1_addr);

    // No session yet
    assert_eq!(nodes[0].node.session_count(), 0);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun_tx);

    // Build and inject an IPv6 packet (identity cache populated at peer promotion)
    let test_payload = b"trigger-session-test";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Session should now be initiating
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_initiating()
    );

    // Drain packets until session established and queued packet delivered
    drain_to_quiescence(&mut nodes).await;

    // Session should be established on Node 0
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );

    // Verify the queued packet was delivered to Node 1
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        1,
        "Queued packet should be delivered after handshake"
    );
    assert_eq!(delivered[0], ipv6_packet);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_unknown_destination() {
    // Inject a packet for an unknown destination — should get ICMPv6 back
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);

    // Install TUN receiver on Node 0 (for ICMPv6 response)
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun_tx);

    let src_fips = crate::Ipv6Address::from_node_addr(nodes[0].node.node_addr());

    // Build a packet to an unknown IPv6 address (not in identity cache)
    let unknown_addr = NodeAddr::from_bytes([0xAA; 16]);
    let unknown_fips = crate::Ipv6Address::from_node_addr(&unknown_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &unknown_fips, b"unknown");

    nodes[0].node.handle_tun_outbound(ipv6_packet).await;

    // Should receive ICMPv6 Destination Unreachable back on TUN
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        1,
        "Should receive ICMPv6 Destination Unreachable"
    );
    // Verify it's an ICMPv6 Destination Unreachable (type 1, code 0)
    // ICMPv6 header starts at byte 40, type at byte 40, code at byte 41
    assert!(delivered[0].len() >= 48, "ICMPv6 response too short");
    assert_eq!(delivered[0][6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(
        delivered[0][40], 1,
        "ICMPv6 type should be Destination Unreachable (1)"
    );
    assert_eq!(delivered[0][41], 0, "ICMPv6 code should be No Route (0)");

    cleanup_nodes(&mut nodes).await;
}

/// Pins what `Node::enable_app_owned_tun` documents for an embedder: a packet
/// pushed to an off-mesh destination is not filtered out, but answered with
/// ICMPv6 Destination Unreachable on `app_inbound_rx`, sourced from the node's
/// own mesh address, and a multicast destination gets no answer.
///
/// It calls `handle_tun_outbound` directly, so it pins the handler and not the
/// `run_rx_loop` hop that carries `app_outbound_tx` to it.
#[tokio::test]
async fn an_app_owned_tun_answers_an_off_mesh_unicast_destination_with_destination_unreachable_on_app_inbound_rx()
 {
    let mut node = make_node();
    let (_app_outbound_tx, app_inbound_rx) = node.enable_app_owned_tun();
    let our_fips = crate::Ipv6Address::from_node_addr(node.node_addr());

    let mut packet = vec![0u8; 48];
    packet[0] = 0x60;
    packet[5] = 8; // payload length
    packet[6] = 59; // No Next Header
    packet[7] = 64;
    packet[8..24].copy_from_slice(our_fips.as_bytes());
    let off_mesh: std::net::Ipv6Addr = "2001:db8::1".parse().unwrap();
    packet[24..40].copy_from_slice(&off_mesh.octets());
    assert_ne!(packet[24], crate::identity::IPV6_ADDRESS_PREFIX);

    node.handle_tun_outbound(packet).await;

    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| app_inbound_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        1,
        "an off-mesh destination must be answered on app_inbound_rx, not dropped"
    );
    let reply = &delivered[0];
    assert!(reply.len() >= 48, "ICMPv6 reply too short");
    assert_eq!(reply[6], 58, "next header must be ICMPv6");
    assert_eq!(reply[40], 1, "ICMPv6 type must be Destination Unreachable");
    assert_eq!(reply[41], 0, "ICMPv6 code must be No Route");
    assert_eq!(
        &reply[8..24],
        our_fips.as_bytes(),
        "the reply must come from the node's own mesh address"
    );

    let mut multicast = vec![0u8; 40];
    multicast[0] = 0x60;
    multicast[6] = 59;
    multicast[7] = 64;
    multicast[8..24].copy_from_slice(our_fips.as_bytes());
    let all_nodes: std::net::Ipv6Addr = "ff02::1".parse().unwrap();
    multicast[24..40].copy_from_slice(&all_nodes.octets());

    node.handle_tun_outbound(multicast).await;

    assert!(
        app_inbound_rx.try_recv().is_err(),
        "a multicast destination must get no ICMPv6 answer"
    );
}

#[tokio::test]
async fn test_tun_outbound_3node_forwarded() {
    // A—B—C: TUN packet from A destined for C, forwarded through B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node2_addr);

    // Register Node 2's identity in Node 0's cache
    // (In production, this would come from the discovery protocol or DNS priming)
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Install TUN receiver on Node 2
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[2].node.install_tun(tun_tx);

    // Build and inject an IPv6 packet (triggers session initiation to Node 2)
    let test_payload = b"forwarded-data-plane";
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, test_payload);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    // Drain packets: handshake + queued data delivery
    drain_to_quiescence(&mut nodes).await;

    // Session should be established
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .unwrap()
            .is_established()
    );

    // Verify packet delivered to Node 2
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered.len(), 1, "Packet should be delivered to Node 2");
    assert_eq!(delivered[0], ipv6_packet);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_tun_outbound_pending_queue_flush() {
    // Send multiple packets before session exists — all should be delivered
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node1_addr);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun_tx);

    // Send 5 packets before any session exists
    let mut packets = Vec::new();
    for i in 0..5u8 {
        let payload = format!("queued-pkt-{}", i).into_bytes();
        let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &payload);
        packets.push(ipv6_packet.clone());
        nodes[0].node.handle_tun_outbound(ipv6_packet).await;
    }

    // First packet triggers session initiation, rest are queued
    assert_eq!(nodes[0].node.session_count(), 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_initiating()
    );

    // The setup reaches node 1 and its ack node 0: node 0 sends its msg3
    // and, behind it at once, every packet it queued, before anything else
    // arrives from node 1.
    assert_eq!(process_available_packets(&mut nodes[1..]).await, 1);
    assert_eq!(process_available_packets(&mut nodes[..1]).await, 1);
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );
    assert_eq!(
        nodes[1].packet_rx.len(),
        6,
        "the msg3 and the five queued packets must leave together"
    );
    drain_to_quiescence(&mut nodes).await;

    // All 5 packets should have been delivered
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered.len(),
        5,
        "All 5 queued packets should be delivered"
    );
    for (i, pkt) in delivered.iter().enumerate() {
        assert_eq!(*pkt, packets[i], "Packet {} should match", i);
    }

    cleanup_nodes(&mut nodes).await;
}

/// A three-node line A - B - C, converged, with C's identity registered on A
/// but no coordinates for C cached there, and TUN channels on A and C.
async fn line_of_three_without_cached_coords() -> (
    Vec<TestNode>,
    std::sync::mpsc::Receiver<Vec<u8>>,
    std::sync::mpsc::Receiver<Vec<u8>>,
) {
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    verify_tree_convergence(&nodes);
    let c = *nodes[2].node.node_addr();
    let c_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(c, c_pubkey);
    assert!(
        nodes[0].node.coord_cache().get_entry(&c).is_none(),
        "precondition: A has no coordinates for C"
    );
    let (a_tx, a_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(a_tx);
    let (c_tx, c_rx) = std::sync::mpsc::channel();
    nodes[2].node.install_tun(c_tx);
    (nodes, a_rx, c_rx)
}

#[tokio::test]
async fn inside_the_hold_a_bloom_miss_packet_is_held_and_a_retransmit_after_the_target_enters_a_filter_establishes_the_session_and_flushes_both_packets()
 {
    let (mut nodes, a_rx, c_rx) = line_of_three_without_cached_coords().await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let c = *nodes[2].node.node_addr();
    let src = crate::Ipv6Address::from_node_addr(&a);
    let dst = crate::Ipv6Address::from_node_addr(&c);

    // B's filter on A, kept so it can arrive again later; meanwhile A sees an
    // empty one, as before B's filter reached it.
    let (b_filter, b_seq) = {
        let peer = nodes[0].node.peers.get(&b).unwrap();
        (
            peer.inbound_filter().unwrap().clone(),
            peer.filter_sequence(),
        )
    };
    assert!(b_filter.contains(&c), "precondition: B's filter reaches C");
    nodes[0].node.peers.get_mut(&b).unwrap().update_filter(
        crate::proto::bloom::BloomFilter::new(),
        b_seq + 1,
        Node::now_ms(),
    );
    assert!(
        nodes[0].node.routing_hold_active(std::time::Instant::now()),
        "precondition: A is inside the routing hold"
    );

    let lookup = &nodes[0].node.metrics().lookup;
    let (misses, initiated) = (lookup.req_bloom_miss.get(), lookup.req_initiated.get());
    let syn = build_ipv6_packet(&src, &dst, b"syn");
    nodes[0].node.handle_tun_outbound(syn.clone()).await;
    assert_eq!(
        nodes[0].node.metrics().lookup.req_bloom_miss.get(),
        misses + 1
    );
    assert_eq!(nodes[0].node.pending_tun_total_packets(), 1, "held");
    assert!(a_rx.try_recv().is_err(), "not answered inside the hold");

    // B's filter arrives, and the retransmit starts a lookup.
    nodes[0]
        .node
        .peers
        .get_mut(&b)
        .unwrap()
        .update_filter(b_filter, b_seq + 2, Node::now_ms());
    let retransmit = build_ipv6_packet(&src, &dst, b"syn-retransmit");
    nodes[0].node.handle_tun_outbound(retransmit.clone()).await;
    assert_eq!(
        nodes[0].node.metrics().lookup.req_initiated.get(),
        initiated + 1
    );
    assert_eq!(nodes[0].node.pending_tun_total_packets(), 2, "both held");
    assert!(a_rx.try_recv().is_err());

    // The hold ends with the lookup still in flight: nothing is released.
    nodes[0]
        .node
        .backdate_hold_for_test(std::time::Duration::from_secs(60));
    nodes[0].node.check_timeouts().await;
    assert_eq!(nodes[0].node.pending_tun_total_packets(), 2);
    assert!(a_rx.try_recv().is_err());
    assert!(nodes[0].node.lookup.pending_lookups.contains_key(&c));

    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&c)
            .is_some_and(|s| s.is_established()),
        "the lookup's answer must start a session that establishes"
    );
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| c_rx.try_recv().ok()).collect();
    assert_eq!(delivered, vec![syn, retransmit], "both packets, in order");
    assert!(a_rx.try_recv().is_err(), "A never answered");

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn outside_the_hold_a_packet_to_a_destination_a_tree_peer_filter_reaches_is_held_without_an_answer_and_flushed_once_the_session_establishes()
 {
    let (mut nodes, a_rx, c_rx) = line_of_three_without_cached_coords().await;
    let a = *nodes[0].node.node_addr();
    let c = *nodes[2].node.node_addr();
    nodes[0]
        .node
        .backdate_hold_for_test(std::time::Duration::from_secs(60));
    assert!(
        !nodes[0].node.routing_hold_active(std::time::Instant::now()),
        "precondition: A is outside the routing hold"
    );
    let initiated = nodes[0].node.metrics().lookup.req_initiated.get();

    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&a),
        &crate::Ipv6Address::from_node_addr(&c),
        b"first",
    );
    nodes[0].node.handle_tun_outbound(packet.clone()).await;
    assert_eq!(
        nodes[0].node.metrics().lookup.req_initiated.get(),
        initiated + 1,
        "precondition: a lookup was sent"
    );
    assert_eq!(nodes[0].node.pending_tun_total_packets(), 1, "held");
    assert!(a_rx.try_recv().is_err(), "a pending lookup is not answered");

    drain_to_quiescence(&mut nodes).await;
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| c_rx.try_recv().ok()).collect();
    assert_eq!(delivered, vec![packet]);
    assert!(a_rx.try_recv().is_err());

    cleanup_nodes(&mut nodes).await;
}

/// On the line of three, hold a packet from A to C inside the routing hold
/// as a bloom miss, then move its stamp back `by`, as if it was held that long
/// ago. Returns the backdated stamp.
async fn hold_a_bloom_miss_for_c_and_backdate_it(
    nodes: &mut [TestNode],
    by: std::time::Duration,
) -> std::time::Instant {
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    let c = *nodes[2].node.node_addr();
    let b_seq = nodes[0].node.peers.get(&b).unwrap().filter_sequence();
    nodes[0].node.peers.get_mut(&b).unwrap().update_filter(
        crate::proto::bloom::BloomFilter::new(),
        b_seq + 1,
        Node::now_ms(),
    );
    assert!(
        nodes[0].node.routing_hold_active(std::time::Instant::now()),
        "precondition: A is inside the routing hold"
    );
    let misses = nodes[0].node.metrics().lookup.req_bloom_miss.get();
    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&a),
        &crate::Ipv6Address::from_node_addr(&c),
        b"syn",
    );
    nodes[0].node.handle_tun_outbound(packet).await;
    assert_eq!(
        nodes[0].node.metrics().lookup.req_bloom_miss.get(),
        misses + 1,
        "precondition: held as a bloom miss"
    );
    assert_eq!(nodes[0].node.pending_tun_total_packets(), 1);
    assert!(nodes[0].node.get_session(&c).is_none());
    nodes[0].node.backdate_held_for_test(&c, by);
    nodes[0].node.pending_tun_since[&c].since
}

#[tokio::test]
async fn a_destination_held_inside_the_hold_whose_session_starts_on_a_retransmit_is_aged_from_the_session_start()
 {
    let (mut nodes, a_rx, _c_rx) = line_of_three_without_cached_coords().await;
    let a = *nodes[0].node.node_addr();
    let c = *nodes[2].node.node_addr();
    let backdate = std::time::Duration::from_secs(30);
    let second = std::time::Duration::from_secs(1);
    let first = hold_a_bloom_miss_for_c_and_backdate_it(&mut nodes, backdate).await;

    // C's coordinates arrive, as a hint or cache warming leaves them, so the
    // retransmit starts a session itself rather than a lookup.
    populate_all_coord_caches(&mut nodes);
    let initiated = nodes[0].node.metrics().lookup.req_initiated.get();
    let retransmit = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&a),
        &crate::Ipv6Address::from_node_addr(&c),
        b"syn-retransmit",
    );
    nodes[0].node.handle_tun_outbound(retransmit).await;
    assert!(
        nodes[0]
            .node
            .get_session(&c)
            .is_some_and(|s| s.is_initiating()),
        "precondition: the retransmit started a session"
    );
    assert_eq!(
        nodes[0].node.metrics().lookup.req_initiated.get(),
        initiated,
        "precondition: no lookup was sent, so only the session start can restamp"
    );

    let stamp = nodes[0].node.pending_tun_since[&c].since;
    assert!(
        stamp >= first + backdate - second,
        "the session start must restamp the destination"
    );
    let max_age = nodes[0].node.pending_tun_max_age();
    nodes[0]
        .node
        .release_stranded_tun_packets(stamp + max_age - second);
    assert_eq!(
        nodes[0].node.pending_tun_total_packets(),
        2,
        "both packets kept while the handshake may still complete"
    );
    assert!(a_rx.try_recv().is_err());

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_destination_held_inside_the_hold_whose_session_starts_after_its_lookup_answers_is_aged_from_the_session_start()
 {
    let (mut nodes, a_rx, _c_rx) = line_of_three_without_cached_coords().await;
    let c = *nodes[2].node.node_addr();
    let backdate = std::time::Duration::from_secs(30);
    let second = std::time::Duration::from_secs(1);
    let first = hold_a_bloom_miss_for_c_and_backdate_it(&mut nodes, backdate).await;

    // The lookup's answer caches C's coordinates and retries the session.
    populate_all_coord_caches(&mut nodes);
    nodes[0].node.retry_session_after_discovery(c).await;
    assert!(
        nodes[0]
            .node
            .get_session(&c)
            .is_some_and(|s| s.is_initiating()),
        "precondition: the retry started a session"
    );

    let stamp = nodes[0].node.pending_tun_since[&c].since;
    assert!(
        stamp >= first + backdate - second,
        "the session start must restamp the destination"
    );
    let max_age = nodes[0].node.pending_tun_max_age();
    nodes[0]
        .node
        .release_stranded_tun_packets(stamp + max_age - second);
    assert_eq!(
        nodes[0].node.pending_tun_total_packets(),
        1,
        "the held packet is kept while the handshake may still complete"
    );
    assert!(a_rx.try_recv().is_err());

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn with_the_held_table_full_a_destination_with_an_initiating_session_gets_no_answer_and_its_retransmit_flushes_after_establishment()
 {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    let node0 = *nodes[0].node.node_addr();
    let node1 = *nodes[1].node.node_addr();
    let (tx0, rx0) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tx0);
    let (tx1, rx1) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tx1);

    let cap = nodes[0].node.config().node.session.pending_max_destinations;
    for i in 0..cap as u32 {
        let mut bytes = [0xEEu8; 16];
        bytes[..4].copy_from_slice(&i.to_be_bytes());
        nodes[0].node.test_hold(
            NodeAddr::from_bytes(bytes),
            crate::ipv6tun::link::any_key(),
            vec![0x60; 40],
        );
    }
    assert_eq!(nodes[0].node.pending_tun_destinations(), cap);

    let src = crate::Ipv6Address::from_node_addr(&node0);
    let dst = crate::Ipv6Address::from_node_addr(&node1);
    nodes[0]
        .node
        .handle_tun_outbound(build_ipv6_packet(&src, &dst, b"first"))
        .await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1)
            .is_some_and(|s| s.is_initiating()),
        "precondition: a session started"
    );
    assert!(rx0.try_recv().is_err(), "a refused packet is not answered");

    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1)
            .is_some_and(|s| s.is_established())
    );

    let retransmit = build_ipv6_packet(&src, &dst, b"retransmit");
    nodes[0].node.handle_tun_outbound(retransmit.clone()).await;
    drain_to_quiescence(&mut nodes).await;
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| rx1.try_recv().ok()).collect();
    assert_eq!(delivered, vec![retransmit]);
    assert!(rx0.try_recv().is_err());

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Unit tests: Session idle timeout
// ============================================================================

/// Helper: complete a Noise XX handshake and return the initiator's NoiseSession.
pub(super) fn make_noise_session(
    our_identity: &Identity,
    remote_identity: &Identity,
) -> crate::noise::NoiseSession {
    use crate::noise::HandshakeState;

    let mut initiator = HandshakeState::new_initiator(our_identity.keypair());
    let mut responder = HandshakeState::new_responder(remote_identity.keypair());

    // Set epochs for both sides (required for handshake message encryption)
    let mut init_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut init_epoch);
    initiator.set_local_epoch(init_epoch);
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    responder.set_local_epoch(resp_epoch);

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    let msg3 = initiator.write_message_3().unwrap();
    responder.read_message_3(&msg3).unwrap();

    initiator.into_session().unwrap()
}

#[test]
fn test_purge_idle_sessions_removes_expired() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);

    node.sessions.insert(remote_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&remote_addr).unwrap().is_established());

    // Purge at t=92s — should exceed default 90s idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(session_at(now_ms));

    assert_eq!(node.session_count(), 0, "Idle session should be purged");
}

#[test]
fn test_purge_idle_sessions_keeps_active() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);

    // Touch at t=80s — recent activity
    entry.touch(session_at(81_000));

    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — only 11s since last activity, well within 90s timeout
    let now_ms = 92_000;
    node.purge_idle_sessions(session_at(now_ms));

    assert_eq!(
        node.session_count(),
        1,
        "Active session should survive purge"
    );
}

#[test]
fn test_purge_idle_sessions_ignores_initiating() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let entry = crate::node::session::SessionEntry::opened_for_test(
        &remote.pubkey_full(),
        node.identity().keypair(),
        session_at(1000),
    );

    node.sessions.insert(remote_addr, entry);

    // Purge well past the idle timeout — Initiating sessions should not be touched
    let now_ms = 1000 + 200_000;
    node.purge_idle_sessions(session_at(now_ms));

    assert_eq!(
        node.session_count(),
        1,
        "Initiating session should not be purged by idle timeout"
    );
}

#[test]
fn test_purge_idle_sessions_cleans_pending_packets() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);

    node.sessions.insert(remote_addr, entry);

    // Insert some pending packets for this destination
    node.test_hold(
        remote_addr,
        crate::ipv6tun::link::PeerKey::from_xonly(&remote.pubkey()),
        vec![1, 2, 3],
    );
    assert!(node.pending_tun_packets.contains_key(&remote_addr));

    // Purge after idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(session_at(now_ms));

    assert_eq!(node.session_count(), 0);
    assert!(
        !node.pending_tun_packets.contains_key(&remote_addr),
        "Pending packets should be cleaned up with idle session"
    );
}

#[test]
fn test_purge_idle_sessions_disabled_when_zero() {
    let mut config = Config::new();
    config.node.session.idle_timeout_secs = 0;
    let mut node = make_node_with(config);

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);

    node.sessions.insert(remote_addr, entry);

    // Even way past any timeout, sessions should survive when disabled
    let now_ms = 1000 + 1_000_000;
    node.purge_idle_sessions(session_at(now_ms));

    assert_eq!(
        node.session_count(),
        1,
        "Sessions should not be purged when idle timeout is disabled"
    );
}

#[test]
fn test_purge_idle_sessions_mmp_activity_does_not_prevent_purge() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);

    // Do NOT call entry.touch() — simulates a session where only MMP
    // reports have flowed (MMP no longer calls touch). last_activity
    // remains at creation time (1000ms).
    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — 91s since creation, exceeds 90s idle timeout.
    // Even though MMP reports would have been flowing, they no longer
    // reset the idle timer.
    let now_ms = 92_000;
    node.purge_idle_sessions(session_at(now_ms));

    assert_eq!(
        node.session_count(),
        0,
        "Session with MMP-only activity should be purged"
    );
}

// ============================================================================
// Unit tests: COORDS_PRESENT warmup counter
// ============================================================================

#[test]
fn test_coords_warmup_counter_default_zero_on_new() {
    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let entry = crate::node::session::SessionEntry::opened_for_test(
        &identity_b.pubkey_full(),
        identity_a.keypair(),
        session_at(1000),
    );

    assert_eq!(
        entry.coords_warmup_remaining(),
        0,
        "Counter should be 0 for non-Established sessions"
    );
}

#[test]
fn test_coords_warmup_counter_set_and_get() {
    let node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);

    assert_eq!(entry.coords_warmup_remaining(), 0);

    entry.set_coords_warmup_remaining(5);
    assert_eq!(entry.coords_warmup_remaining(), 5);

    entry.set_coords_warmup_remaining(0);
    assert_eq!(entry.coords_warmup_remaining(), 0);
}

#[test]
fn test_coords_warmup_counter_decrement() {
    let node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);

    entry.set_coords_warmup_remaining(3);

    // Simulate the decrement pattern used in send_session_data
    for expected in (0..3).rev() {
        assert!(entry.coords_warmup_remaining() > 0);
        entry.set_coords_warmup_remaining(entry.coords_warmup_remaining() - 1);
        assert_eq!(entry.coords_warmup_remaining(), expected);
    }

    assert_eq!(
        entry.coords_warmup_remaining(),
        0,
        "Counter should reach 0 after N decrements"
    );
}

#[test]
fn test_coords_warmup_config_default() {
    let config = crate::config::Config::new();
    assert_eq!(
        config.node.session.coords_warmup_packets, 5,
        "Default coords_warmup_packets should be 5"
    );
}

// ============================================================================
// Unit tests: Identity cache
// ============================================================================

#[test]
fn test_identity_cache_lru_eviction() {
    let mut config = crate::Config::new();
    config.node.cache.identity_size = 2;
    let mut node = make_node_with(config);

    let id1 = Identity::generate();
    let id2 = Identity::generate();
    let id3 = Identity::generate();

    // Insert first two with explicit timestamps to ensure deterministic ordering
    let prefix1 = id1.node_addr().prefix();
    node.identity_cache
        .insert(prefix1, (*id1.node_addr(), id1.pubkey_full(), 1000));

    let prefix2 = id2.node_addr().prefix();
    node.identity_cache
        .insert(prefix2, (*id2.node_addr(), id2.pubkey_full(), 2000));

    assert_eq!(node.identity_cache_len(), 2);

    // Adding a third should evict the oldest (id1, timestamp 1000)
    node.register_identity(*id3.node_addr(), id3.pubkey_full());
    assert_eq!(node.identity_cache_len(), 2);

    assert!(
        node.lookup_by_fips_prefix(&prefix1).is_none(),
        "Oldest entry should have been evicted"
    );

    let prefix3 = id3.node_addr().prefix();
    assert!(
        node.lookup_by_fips_prefix(&prefix3).is_some(),
        "Newest entry should be present"
    );
}

#[test]
fn test_identity_cache_lookup() {
    let mut node = make_node();

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    node.register_identity(remote_addr, remote.pubkey_full());

    let prefix = remote_addr.prefix();

    let result = node.lookup_by_fips_prefix(&prefix);
    assert!(result.is_some(), "Registered identity should be available");

    let (addr, pk) = result.unwrap();
    assert_eq!(addr, remote_addr);
    assert_eq!(pk, remote.pubkey_full());
}

// ============================================================================
// Session-layer handshake resend tests
// ============================================================================

/// A session this node opened whose setup nobody answered is removed at
/// its attempt's deadline, the handshake timeout from its first setup, when
/// no candidate of the peer's is held beside it.
#[tokio::test]
async fn test_session_handshake_timeout() {
    let mut node = make_node();

    let identity_b = Identity::generate();
    let dest_addr = *identity_b.node_addr();

    // The session opens at 1 s, its first setup sent then.
    let entry = crate::node::session::SessionEntry::opened_for_test(
        &identity_b.pubkey_full(),
        node.identity().keypair(),
        session_at(1000),
    );
    node.sessions.insert(dest_addr, entry);

    let timeout_secs = node.config().node.rate_limit.handshake_timeout_secs;
    let deadline = 1000 + timeout_secs * 1000;
    node.poll_session_rekeys(session_at(deadline - 1)).await;
    assert!(
        node.sessions.contains_key(&dest_addr),
        "the session survives until its attempt's deadline"
    );
    node.poll_session_rekeys(session_at(deadline)).await;
    assert!(
        !node.sessions.contains_key(&dest_addr),
        "an unanswered first attempt with no candidate beside it ends the session at its deadline"
    );
}

/// A session one setup opened is removed when that setup's candidate
/// expires, 40 s after it arrived, with no msg3 and no attempt of this
/// node's: a forged setup holds a half-open session that long and no longer.
#[tokio::test]
async fn test_session_awaiting_msg3_timeout() {
    let mut node = make_node();
    let identity_a = Identity::generate();
    let src_addr = *identity_a.node_addr();

    let entry = crate::node::session::SessionEntry::answering_for_test(
        src_addr,
        node.identity().keypair(),
        session_at(1000),
    );
    node.sessions.insert(src_addr, entry);

    node.poll_session_rekeys(session_at(1000 + 40_000 - 1))
        .await;
    assert!(
        node.sessions.contains_key(&src_addr),
        "the candidate lives 40 s from its setup"
    );
    node.poll_session_rekeys(session_at(1000 + 40_000)).await;
    assert!(
        !node.sessions.contains_key(&src_addr),
        "the session ends with its last candidate"
    );
}

#[tokio::test]
async fn test_tun_outbound_path_mtu_generates_ptb() {
    // When a session's PathMtuState reports a lower MTU than the local
    // transport (simulating a bottleneck learned via MtuExceeded signals),
    // handle_tun_outbound should generate ICMPv6 Packet Too Big for
    // oversized packets instead of forwarding them.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node1_addr);

    // Establish session (XX: 3 messages — Setup, Ack, Msg3)
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );

    // Simulate receipt of MtuExceeded by reducing PathMtuState to a value
    // lower than the local transport MTU.
    let local_transport_mtu = nodes[0].node.transport_mtu();
    let reduced_mtu = local_transport_mtu - 200;
    {
        let entry = nodes[0].node.get_session_mut(&node1_addr).unwrap();
        let mmp = entry.mmp_mut().unwrap();
        mmp.path_mtu
            .apply_notification(reduced_mtu, crate::time::mono_ms());
        assert_eq!(mmp.path_mtu.current_mtu(), reduced_mtu);
    }

    // Install TUN receiver on source node to capture ICMPv6 PTB
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun_tx);

    // Build an IPv6 packet that fits local MTU but exceeds path MTU
    let reduced_ipv6_mtu = crate::ipv6tun::icmp::effective_ipv6_mtu(reduced_mtu) as usize;
    let local_ipv6_mtu = nodes[0].node.effective_ipv6_mtu() as usize;
    let oversized_payload = vec![0u8; reduced_ipv6_mtu - 39]; // 40-byte hdr + payload > reduced MTU
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &oversized_payload);
    assert!(
        ipv6_packet.len() > reduced_ipv6_mtu,
        "packet must exceed path MTU"
    );
    assert!(
        ipv6_packet.len() <= local_ipv6_mtu,
        "packet must fit local MTU"
    );

    nodes[0].node.handle_tun_outbound(ipv6_packet).await;

    // Verify ICMPv6 Packet Too Big was generated
    let ptb_messages: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages.len(),
        1,
        "Should generate exactly one ICMPv6 PTB"
    );

    let ptb = &ptb_messages[0];
    assert_eq!(ptb[0] >> 4, 6, "Should be IPv6");
    assert_eq!(ptb[6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(ptb[40], 2, "ICMPv6 type should be Packet Too Big (2)");
    assert_eq!(ptb[41], 0, "ICMPv6 code should be 0");

    // Verify PTB source is the *remote peer* (original packet's destination),
    // NOT the local node. Linux ignores PTBs whose source matches a local
    // address, causing a PMTUD blackhole.
    let ptb_src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[8..24]).unwrap());
    let ptb_dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[24..40]).unwrap());
    assert_eq!(
        ptb_src,
        dst_fips.to_ipv6(),
        "PTB source must be remote peer (original dst), not local node"
    );
    assert_eq!(
        ptb_dst,
        src_fips.to_ipv6(),
        "PTB destination must be local node (original src)"
    );

    // Verify reported MTU (32-bit field at ICMPv6 header bytes 4-7)
    let reported_mtu = u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]);
    assert_eq!(
        reported_mtu, reduced_ipv6_mtu as u32,
        "Reported MTU should match path IPv6 MTU"
    );

    // Verify a packet that fits within path MTU passes through (no PTB)
    let (tun_tx2, tun_rx2) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun_tx2);
    let fitting_payload = vec![0u8; reduced_ipv6_mtu - 41]; // fits within path MTU
    let fitting_packet = build_ipv6_packet(&src_fips, &dst_fips, &fitting_payload);
    assert!(fitting_packet.len() <= reduced_ipv6_mtu);

    nodes[0].node.handle_tun_outbound(fitting_packet).await;

    // No PTB should be generated for a fitting packet
    let ptb_messages2: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx2.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages2.len(),
        0,
        "Should not generate PTB for fitting packet"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration test: Multi-hop PMTUD with heterogeneous MTUs
// ============================================================================

#[tokio::test]
async fn test_multihop_pmtud_heterogeneous_mtu() {
    // Three-node chain: A(1400)—B(800)—C(800)
    //
    // Node B has a smaller transport MTU than A. When A sends an IPv6
    // packet that fits A's local MTU (1294) but whose wire size after
    // FIPS encapsulation exceeds B's transport MTU (800), B's forwarding
    // path fails with MtuExceeded and sends an MtuExceeded signal back
    // to A. A updates PathMtuState, and the next oversized packet
    // generates ICMPv6 Packet Too Big on TUN.
    //
    // This exercises the full PMTUD loop:
    //   1. Oversized packet forwarded A→B
    //   2. B→C forward fails (B's transport MTU 800 exceeded)
    //   3. B sends MtuExceeded signal back to A
    //   4. A receives signal, updates PathMtuState for C
    //   5. Next oversized packet → ICMPv6 PTB on TUN
    let mtus = [1400, 800, 800];
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test_with_mtus(&mtus, &edges).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node2_addr);

    // Register Node 2's identity in Node 0's cache
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Establish session A→C via B (triggers routing through tree)
    nodes[0]
        .node
        .initiate_session(node2_addr, node2_pubkey)
        .await
        .unwrap();
    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node2_addr)
            .unwrap()
            .is_established(),
        "Session A→C should be established"
    );

    // Exhaust coord warmup by sending small packets first.
    // Without piggybacked coords, the wire packet is ~106 + IPv6 bytes,
    // which fits B's receive buffer (mtu+100=900) for reasonable sizes.
    // With coords (~66 extra), the wire could exceed B's recv buffer.
    for _ in 0..5 {
        let small = build_ipv6_packet(&src_fips, &dst_fips, &[0u8; 10]);
        nodes[0]
            .node
            .send_ipv6_packet(&node2_addr, &small)
            .await
            .unwrap();
    }
    drain_to_quiescence(&mut nodes).await;

    // Build an IPv6 packet that fits A's local MTU (1294) but whose wire
    // size (~750 + 106 = ~856 bytes) exceeds B's transport MTU (800).
    // effective_ipv6_mtu(1400) = 1294, effective_ipv6_mtu(800) = 694
    let oversized_payload = vec![0xABu8; 750 - 40]; // 710 bytes payload → 750-byte IPv6 packet
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &oversized_payload);
    assert_eq!(ipv6_packet.len(), 750);
    let local_effective_mtu = crate::ipv6tun::icmp::effective_ipv6_mtu(1400) as usize;
    assert!(
        ipv6_packet.len() <= local_effective_mtu,
        "packet ({}) must fit A's local MTU ({})",
        ipv6_packet.len(),
        local_effective_mtu
    );

    // Send the oversized packet — B should fail to forward and send
    // MtuExceeded signal back.
    nodes[0]
        .node
        .send_ipv6_packet(&node2_addr, &ipv6_packet)
        .await
        .unwrap();
    drain_to_quiescence(&mut nodes).await;

    // Verify PathMtuState was updated on A
    let path_mtu = {
        let entry = nodes[0].node.get_session(&node2_addr).unwrap();
        let mmp = entry.mmp().expect("session should have MMP state");
        mmp.path_mtu.current_mtu()
    };
    assert!(
        path_mtu < 1400,
        "PathMtuState should have decreased from MtuExceeded signal, got {}",
        path_mtu
    );

    // Verify path_mtu_lookup (consulted by the TUN reader/writer at TCP MSS
    // clamp time) also reflects the tightened bottleneck. The reactive
    // MtuExceeded handler writes here so subsequent SYN clamps see the
    // forward-path budget rather than the discovery reverse-path value.
    let lookup_mtu = nodes[0]
        .node
        .path_mtu_lookup_get(&dst_fips)
        .expect("path_mtu_lookup should have entry for C after MtuExceeded");
    assert!(
        lookup_mtu < 1400,
        "path_mtu_lookup should have tightened from MtuExceeded signal, got {}",
        lookup_mtu
    );

    // Now send ANOTHER oversized packet — this time handle_tun_outbound
    // should check PathMtuState and generate ICMPv6 PTB on TUN instead
    // of forwarding.
    let (tun_tx2, tun_rx2) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun_tx2);

    nodes[0].node.handle_tun_outbound(ipv6_packet.clone()).await;

    let ptb_messages: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx2.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages.len(),
        1,
        "Should generate ICMPv6 PTB for oversized packet after PathMtuState update"
    );

    let ptb = &ptb_messages[0];
    assert_eq!(ptb[0] >> 4, 6, "Should be IPv6");
    assert_eq!(ptb[6], 58, "Next header should be ICMPv6 (58)");
    assert_eq!(ptb[40], 2, "ICMPv6 type should be Packet Too Big (2)");
    assert_eq!(ptb[41], 0, "ICMPv6 code should be 0");

    // Verify PTB source is the *remote peer* (original packet's destination),
    // NOT the local node. Linux ignores PTBs whose source matches a local
    // address, causing a PMTUD blackhole.
    let ptb_src = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[8..24]).unwrap());
    let ptb_dst = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&ptb[24..40]).unwrap());
    assert_eq!(
        ptb_src,
        dst_fips.to_ipv6(),
        "PTB source must be remote peer (original dst), not local node"
    );
    assert_eq!(
        ptb_dst,
        src_fips.to_ipv6(),
        "PTB destination must be local node (original src)"
    );

    // Verify reported MTU is the path MTU (not local MTU)
    let reported_mtu = u32::from_be_bytes([ptb[44], ptb[45], ptb[46], ptb[47]]);
    let expected_ipv6_mtu = crate::ipv6tun::icmp::effective_ipv6_mtu(path_mtu) as u32;
    assert_eq!(
        reported_mtu, expected_ipv6_mtu,
        "ICMPv6 PTB MTU should match path IPv6 MTU (transport MTU {} - overhead)",
        path_mtu
    );

    // Verify a fitting packet still passes through without PTB
    let (tun_tx3, tun_rx3) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun_tx3);

    let fitting_payload = vec![0xCDu8; 600 - 40]; // 600-byte IPv6 packet, well within 694
    let fitting_packet = build_ipv6_packet(&src_fips, &dst_fips, &fitting_payload);
    assert!(fitting_packet.len() <= expected_ipv6_mtu as usize);

    nodes[0].node.handle_tun_outbound(fitting_packet).await;

    let ptb_messages3: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx3.try_recv().ok()).collect();
    assert_eq!(
        ptb_messages3.len(),
        0,
        "Should not generate PTB for packet fitting within path MTU"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Reactive MtuExceeded → path_mtu_lookup focused unit tests
//
// These exercise the receive-side write path that mirrors the bottleneck
// MTU into `path_mtu_lookup` (consulted by the TUN reader/writer at
// SYN-clamp time). Discovery's reverse-path response and the FMP-promotion
// seed populate the same lookup; the reactive channel keeps it
// authoritative under forward-path-asymmetry conditions.
// ============================================================================

/// Build an MtuExceeded inner payload (35 bytes: flags + dest + reporter + mtu LE).
///
/// `handle_mtu_exceeded` receives the payload after the dispatcher strips
/// the FSP prefix and msg_type byte, so the test wire is just the body.
fn build_mtu_exceeded_inner(dest: &NodeAddr, reporter: &NodeAddr, mtu: u16) -> Vec<u8> {
    let mut buf = Vec::with_capacity(35);
    buf.push(0x00); // flags (reserved)
    buf.extend_from_slice(dest.as_bytes());
    buf.extend_from_slice(reporter.as_bytes());
    buf.extend_from_slice(&mtu.to_le_bytes());
    buf
}

/// Install the half-open entry an inbound SessionSetup creates: keyed on an
/// address the sender merely claimed, awaiting msg3, not initiated by us.
///
/// This is the shape an attacker manufactures with one forged handshake
/// opening, so a routing signal naming `claimed` must not be admitted by it.
fn install_halfopen(node: &mut Node, claimed: NodeAddr) {
    let entry = crate::node::session::SessionEntry::answering_for_test(
        claimed,
        node.identity().keypair(),
        session_at(1000),
    );
    node.sessions.insert(claimed, entry);
}

/// Record that this node put a frame of `wire_len` bytes on the wire toward
/// `dest`, which is what corroborates a reactive `MtuExceeded` reporting a
/// smaller bottleneck. Honest path-MTU discovery produces this by sending;
/// a handler test that installs a session without sending has to state it.
fn note_sent_wire_len(node: &mut Node, dest: &NodeAddr, wire_len: usize) {
    node.sessions
        .get_mut(dest)
        .expect("session must exist to corroborate a report")
        .record_sent_wire_len(wire_len);
}

/// Install the entry `initiate_session` creates: an address this node chose
/// itself, with the handshake still in flight and MMP not yet initialized.
fn install_initiating(node: &mut Node, remote: &Identity) {
    let remote_addr = *remote.node_addr();
    let entry = crate::node::session::SessionEntry::opened_for_test(
        &remote.pubkey_full(),
        node.identity().keypair(),
        session_at(1000),
    );
    node.sessions.insert(remote_addr, entry);
}

#[tokio::test]
async fn test_handle_mtu_exceeded_writes_path_mtu_lookup_when_empty() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut tn.node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    assert!(
        tn.node.path_mtu_lookup_get(&dest_fips).is_none(),
        "lookup should start empty for this destination"
    );

    note_sent_wire_len(&mut tn.node, &dest, 1400);
    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded should populate path_mtu_lookup with the bottleneck MTU"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_tightens_existing_path_mtu_lookup() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut tn.node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    // Pre-seed with a generous value (e.g., from a discovery reverse-path
    // response that didn't reflect the forward-path bottleneck).
    tn.node.path_mtu_lookup_insert(dest_fips, 1500);

    note_sent_wire_len(&mut tn.node, &dest, 1400);
    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded with smaller bottleneck must tighten the lookup"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_keeps_tighter_existing_path_mtu_lookup() {
    use crate::node::tests::spanning_tree::make_test_node;

    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut tn.node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    // Pre-seed with a tighter value than the incoming signal (e.g., from
    // a prior reactive event on a narrower hop). The clamp must never
    // loosen — keep the existing value.
    tn.node.path_mtu_lookup_insert(dest_fips, 1280);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1500);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "MtuExceeded with looser bottleneck must not loosen a tighter existing value"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_below_floor_leaves_path_mtu_lookup_untouched() {
    use crate::node::tests::spanning_tree::make_test_node;

    // MtuExceeded is an unencrypted signal that any admitted member can send
    // for any destination this node has bound. A bottleneck this small cannot
    // describe a real path; storing it would drive the SYN-time MSS clamp to a
    // single-digit or zero segment size. The session is installed so the
    // admission gate lets the signal through and the floor is what refuses it;
    // without one this would pass whether or not the floor exists.
    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    install_initiating(&mut tn.node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 100);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        None,
        "a sub-floor MtuExceeded must leave no path_mtu_lookup entry behind"
    );
}

#[tokio::test]
async fn test_sub_floor_mtu_exceeded_is_counted_separately_from_all_mtu_exceeded() {
    use crate::node::tests::spanning_tree::make_test_node;

    // `mtu_exceeded` counts every MtuExceeded regardless of value, so the
    // sub-floor subset is not separable from it. The signal is unencrypted,
    // unauthenticated and unmetered, so that subset climbing on its own is
    // the forged-signal signature and needs its own counter.
    let mut tn = make_test_node().await;

    // Bound the destination so the admission gate admits the signal and the
    // floor is what classifies it.
    let remote = Identity::generate();
    install_initiating(&mut tn.node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);

    assert_eq!(
        tn.node.metrics().errors.mtu_exceeded_below_floor.get(),
        0,
        "counter starts at zero on a fresh node"
    );

    let inner = build_mtu_exceeded_inner(
        &dest,
        &reporter,
        crate::proto::mmp::MIN_ACTIONABLE_PATH_MTU - 1,
    );
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.metrics().errors.mtu_exceeded_below_floor.get(),
        1,
        "a sub-floor MtuExceeded must bump the below-floor counter"
    );

    // The counter must discriminate: an actionable bottleneck is stored and
    // must bump only the all-signals counter.
    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.metrics().errors.mtu_exceeded_below_floor.get(),
        1,
        "an actionable MtuExceeded must not bump the below-floor counter"
    );
    assert_eq!(
        tn.node.metrics().errors.mtu_exceeded.get(),
        2,
        "the all-signals counter must count both, sub-floor and actionable"
    );
}

#[tokio::test]
async fn test_handle_mtu_exceeded_at_the_floor_still_writes_path_mtu_lookup() {
    use crate::node::tests::spanning_tree::make_test_node;

    // The guard must reject only what is below the floor. Without this the
    // floor could be widened arbitrarily and the test above would not notice.
    let mut tn = make_test_node().await;

    let remote = Identity::generate();
    install_initiating(&mut tn.node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);
    let floor = crate::proto::mmp::MIN_REACTIVE_PATH_MTU;

    note_sent_wire_len(&mut tn.node, &dest, 1400);
    let inner = build_mtu_exceeded_inner(&dest, &reporter, floor);
    tn.node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        Some(floor),
        "a bottleneck exactly at the floor is actionable and must be stored"
    );
}

#[tokio::test]
async fn test_forged_mtu_exceeded_of_zero_does_not_blackhole_the_session() {
    // The security property itself. MtuExceeded arrives unencrypted with no
    // sender check, so anyone who can reach this node can inject one. Applied
    // unfiltered, a reported MTU of zero drives the session's path MTU to
    // zero, and from then on the TUN send gate answers every packet with an
    // ICMPv6 Packet Too Big instead of sending it: a total blackhole for that
    // destination that survives until the daemon restarts.
    let edges = vec![(0, 1)];
    let mut nodes = run_tree_test(2, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node1_addr);

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .unwrap();
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .is_established()
    );

    // Forge the signal: an MtuExceeded claiming the path to node 1 carries
    // nothing at all, reported by a node that is not on the path.
    let reporter = NodeAddr::from_bytes([0xEE; 16]);
    let inner = build_mtu_exceeded_inner(&node1_addr, &reporter, 0);
    nodes[0].node.handle_mtu_exceeded(&reporter, &inner).await;

    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun_tx);

    let payload = vec![0u8; 560];
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, &payload);
    assert_eq!(ipv6_packet.len(), 600);
    assert!(
        ipv6_packet.len() <= nodes[0].node.effective_ipv6_mtu() as usize,
        "the packet must fit the local MTU, so any PTB comes from the forged signal"
    );

    nodes[0].node.handle_tun_outbound(ipv6_packet).await;

    let tun_messages: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert!(
        tun_messages.is_empty(),
        "a forged MtuExceeded of zero must not turn ordinary packets into \
         ICMPv6 Packet Too Big; got {} message(s)",
        tun_messages.len()
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_path_broken_releases_path_mtu_lookup_entry() {
    use crate::node::tests::spanning_tree::make_test_node;
    use crate::proto::routing::PathBroken;

    // A PathBroken report declares the path to a destination gone. The stored
    // path MTU described that path, so it must not be carried onto whatever
    // path replaces it — otherwise a value learned once (or injected once)
    // outlives every route change until the daemon restarts.
    let mut tn = make_test_node().await;

    // The signal is only acted on for a destination this node has itself
    // bound, so the release is reachable only behind an installed session.
    // Without one the admission gate refuses the signal and this test would
    // observe the entry surviving for the wrong reason.
    let remote = Identity::generate();
    install_initiating(&mut tn.node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    tn.node.path_mtu_lookup_insert(dest_fips, 700);
    assert_eq!(tn.node.path_mtu_lookup_get(&dest_fips), Some(700));

    // Build the body the dispatcher would hand the handler: encode() prepends
    // a 4-byte FSP prefix and a msg_type byte, both already consumed there.
    let encoded = PathBroken::new(dest, reporter).encode();
    let inner = &encoded[5..];
    assert!(
        PathBroken::decode(inner).is_ok(),
        "the test body must decode, or the handler returns early and the \
         assertion below observes nothing"
    );

    tn.node
        .handle_path_broken(&reporter, &reporter, inner)
        .await;

    assert_eq!(
        tn.node.path_mtu_lookup_get(&dest_fips),
        None,
        "PathBroken must release the stored path MTU for the dead path"
    );
}

#[tokio::test]
async fn test_path_broken_resets_the_session_source_path_mtu() {
    use crate::node::tests::spanning_tree::make_test_node;
    use crate::proto::routing::PathBroken;

    // The other half of the same release. The map the SYN clamp reads is not
    // the only store describing the dead path: the session's own source-side
    // estimate gates every outbound packet, and the increase ladder is the
    // only thing that would ever raise it again — three matching higher
    // notifications spanning two notification intervals, which arrive only
    // while the peer is still receiving our datagrams.
    let mut tn = make_test_node().await;

    // An Established session, not an Initiating one: an Initiating entry
    // carries no MMP state at all, which would make the assertion vacuous.
    let remote = Identity::generate();
    install_established_session_with_mmp(&mut tn.node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);

    tn.node
        .get_session_mut(&dest)
        .expect("the session was just installed")
        .mmp_mut()
        .expect("install_established_session_with_mmp initialises MMP state")
        .path_mtu
        .apply_notification(800, 1_000);
    assert_eq!(
        tn.node
            .get_session(&dest)
            .and_then(|e| e.mmp())
            .map(|m| m.path_mtu.current_mtu()),
        Some(800),
        "precondition: the source-side estimate is tightened before the path dies"
    );

    // Same construction as the sibling test: encode() prepends a 4-byte FSP
    // prefix and a msg_type byte, both already consumed by the dispatcher.
    let encoded = PathBroken::new(dest, reporter).encode();
    let inner = &encoded[5..];
    assert!(
        PathBroken::decode(inner).is_ok(),
        "the test body must decode, or the handler returns early and the \
         assertion below observes nothing"
    );

    tn.node
        .handle_path_broken(&reporter, &reporter, inner)
        .await;

    assert_eq!(
        tn.node
            .get_session(&dest)
            .and_then(|e| e.mmp())
            .map(|m| m.path_mtu.current_mtu()),
        Some(u16::MAX),
        "PathBroken must return the source-side estimate to the no-measurement \
         state, so the next send re-seeds it from the outbound transport"
    );
}

/// A node with one UDP transport at `mtu`, and `path_mtu_lookup` seeded from
/// that transport's link MTU for a remote address. The remote is deliberately
/// *not* registered in `node.peers`: a test that wants the expiry pass to
/// reseed it must add the `ActivePeer` itself, so that the two tests below
/// can tell "restored by the reseed" apart from "never a candidate". The
/// remote's identity comes back too, for the `ActivePeer` such a test adds.
async fn node_with_link_seed(
    mtu: u16,
) -> (
    Node,
    Identity,
    crate::NodeAddr,
    crate::Ipv6Address,
    TransportId,
    TransportAddr,
) {
    use crate::transport::udp::UdpTransport;
    use crate::transport::{TransportHandle, packet_channel};

    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let (transport_packet_tx, _transport_packet_rx) = packet_channel(64);
    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("udp1".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(mtu),
            ..Default::default()
        },
        transport_packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);
    let transport_addr = TransportAddr::from_string("127.0.0.1:2121");

    node.seed_path_mtu_for_link_peer(
        &remote_addr,
        crate::ipv6tun::link::PeerKey::from_xonly(&remote.pubkey()),
        transport_id,
        &transport_addr,
    );

    (
        node,
        remote,
        remote_addr,
        remote_fips,
        transport_id,
        transport_addr,
    )
}

#[tokio::test]
async fn test_expired_path_mtu_keeps_the_link_peer_seed() {
    use crate::peer::ActivePeer;

    // The same regression the release helper's reseed half exists to
    // prevent, reproduced on the expiry path. A tighter discovery value
    // overwrites a direct peer's link MTU under keep-tighter, so expiring it
    // with a bare removal would silently drop that peer to the conservative
    // ceiling until its link re-handshakes.
    let (mut node, remote, remote_addr, remote_fips, transport_id, transport_addr) =
        node_with_link_seed(1452).await;

    let peer_identity = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let mut peer = ActivePeer::new(peer_identity, LinkId::new(7), 0);
    peer.set_current_addr(transport_id, transport_addr);
    node.peers.insert(remote_addr, peer);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1452),
        "precondition: the direct-link seed is in place"
    );

    let t0 = 5_000_000u64;
    node.path_mtu_lookup_learn(remote_fips, 800, t0);
    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(800),
        "precondition: a tighter remote-learned value is sitting on the seed"
    );

    let ttl_ms = node.config().node.cache.coord_ttl_secs * 1000;
    node.purge_expired_path_mtu(t0 + ttl_ms + 1);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1452),
        "expiring a remote value must restore the local link seed, not leave the \
         destination with no entry at all"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_local_path_mtu_seed_never_expires() {
    // Discriminating half of the test above, which on its own cannot tell
    // "the seed was restored by the reseed sweep" from "the seed was never a
    // candidate for expiry". Here the remote is not in `node.peers`, so there
    // is no reseed to mask the difference: a seed that carried a deadline
    // would be removed and stay removed.
    let (mut node, _remote, _remote_addr, remote_fips, _tid, _taddr) =
        node_with_link_seed(1452).await;
    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1452),
        "precondition: the direct-link seed is in place"
    );
    assert_eq!(
        node.path_mtu_lookup_entry(&remote_fips)
            .and_then(|e| e.learned_ms),
        None,
        "precondition: a locally derived seed carries no deadline"
    );

    let ttl_ms = node.config().node.cache.coord_ttl_secs * 1000;
    node.purge_expired_path_mtu(10 * ttl_ms);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1452),
        "a locally derived link MTU describes a link this node can still see, \
         so no amount of elapsed time may expire it"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

#[tokio::test]
async fn test_mirrored_notification_path_mtu_survives_a_purge() {
    // The proactive mirror exists because a peer repeating an identical value
    // on a stable path never rewrites the entry: the handler returns early
    // when the session-side MTU is unchanged. An entry from that carrier must
    // therefore carry no deadline, or expiring it would permanently reopen
    // the gap the mirror closed, for every long-lived multi-hop destination.
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);
    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "precondition: the mirror wrote the notified value"
    );

    let ttl_ms = node.config().node.cache.coord_ttl_secs * 1000;
    node.purge_expired_path_mtu(10 * ttl_ms);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "a value learned inside a session is released by the session, not by a \
         timer, and must survive any number of expiry passes"
    );
}

// ============================================================================
// Routing-signal admission: the named destination must be an address this
// node bound itself, either by initiating toward it or by completing the
// handshake that binds an address to a peer's static key. These signals carry
// no end-to-end authentication, so without that gate any mesh member can name
// any address and have the effects applied.
// ============================================================================

#[tokio::test]
async fn test_mtu_exceeded_naming_a_dest_with_no_session_does_not_touch_path_mtu_lookup() {
    let mut node = make_node();

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    assert!(
        node.path_mtu_lookup_get(&dest_fips).is_none(),
        "lookup should start empty for this destination"
    );

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        None,
        "a signal naming an address with no session must not write the clamp"
    );
    assert_eq!(node.stats().session.unknown_session, 1);

    let errors = &node.metrics().errors;
    assert_eq!(
        errors.unbound.mtu.get(),
        1,
        "the refusal must be counted against the MtuExceeded counter"
    );
    assert_eq!(
        errors.unbound.coords.get(),
        0,
        "an MtuExceeded refusal must not bump the CoordsRequired counter"
    );
    assert_eq!(
        errors.unbound.broken.get(),
        0,
        "an MtuExceeded refusal must not bump the PathBroken counter"
    );
    assert_eq!(
        errors.unbound.forged.get(),
        0,
        "an absent session is an unbound refusal, not a forged pairing"
    );
    assert_eq!(
        errors.mtu_exceeded.get(),
        1,
        "the arrival counter is the denominator and counts refused arrivals too"
    );
}

#[tokio::test]
async fn test_mtu_exceeded_naming_a_dest_whose_entry_is_an_unauthenticated_responder_handshake_is_dropped()
 {
    let mut node = make_node();

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    // One forged SessionSetup naming `dest` would leave exactly this entry.
    install_halfopen(&mut node, dest);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        None,
        "a half-open entry keyed on a claimed address must not admit the signal"
    );
    assert_eq!(node.stats().session.unknown_session, 1);

    let errors = &node.metrics().errors;
    assert_eq!(
        errors.unbound.mtu.get(),
        1,
        "a half-open entry is an unbound refusal for MtuExceeded"
    );
    assert_eq!(
        errors.unbound.forged.get(),
        0,
        "a half-open entry is a plausible pairing, not a forged one"
    );
}

#[tokio::test]
async fn test_mtu_exceeded_for_a_session_we_initiated_seeds_path_mtu_lookup_before_establishment() {
    let mut node = make_node();

    let remote = Identity::generate();
    install_initiating(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    note_sent_wire_len(&mut node, &dest, 1400);
    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "an address we chose ourselves must still seed the clamp during handshake"
    );
    assert_eq!(
        node.metrics().errors.unbound.mtu.get(),
        0,
        "an admitted signal must not be counted as refused"
    );
}

#[tokio::test]
async fn test_mtu_exceeded_from_a_third_party_forwarder_still_tightens_an_active_session() {
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();
    // A real transit reporter is neither us nor the destination.
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    note_sent_wire_len(&mut node, &dest, 1400);
    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1280);
    node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        Some(1280),
        "an on-path forwarder's report must still tighten the clamp"
    );
    assert_eq!(
        node.sessions
            .get(&dest)
            .and_then(|e| e.mmp())
            .map(|m| m.path_mtu.current_mtu()),
        Some(1280),
        "the session-side path MTU must also decrease"
    );
}

#[tokio::test]
async fn test_path_broken_naming_a_dest_with_no_session_does_not_flush_cached_coords() {
    use crate::proto::routing::PathBroken;

    let mut node = make_node();

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let coords = node.tree_state().my_coords().clone();
    let _ = node.coord_cache_mut().insert(dest, coords, 1000);

    let encoded = PathBroken::new(dest, reporter).encode();
    node.handle_path_broken(&reporter, &reporter, &encoded[5..])
        .await;

    assert!(
        node.coord_cache().get(&dest, 1000).is_some(),
        "a signal naming an address with no session must not flush its coords"
    );
    assert_eq!(node.stats().session.unknown_session, 1);

    let errors = &node.metrics().errors;
    assert_eq!(
        errors.unbound.broken.get(),
        1,
        "the refusal must be counted against the PathBroken counter"
    );
    assert_eq!(
        errors.unbound.mtu.get(),
        0,
        "a PathBroken refusal must not bump the MtuExceeded counter"
    );
    assert_eq!(
        errors.unbound.coords.get(),
        0,
        "a PathBroken refusal must not bump the CoordsRequired counter"
    );
    assert_eq!(
        errors.unbound.forged.get(),
        0,
        "an absent session is an unbound refusal, not a forged pairing"
    );
}

/// A session one setup opened has proven no key: it knows only the address
/// the setup claimed, where an entry once held this node's own key as a
/// placeholder for the peer's, which the identity-cache fill that runs
/// before the signal's lookup would have filed under the claimed address
/// had the signal been admitted. With no cached identity for the address
/// beforehand, none may follow.
#[tokio::test]
async fn test_path_broken_naming_a_dest_whose_entry_is_an_unauthenticated_responder_handshake_does_not_flush_cached_coords_or_cache_its_placeholder_key()
 {
    use crate::proto::routing::PathBroken;

    let mut node = make_node();

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let coords = node.tree_state().my_coords().clone();
    let _ = node.coord_cache_mut().insert(dest, coords, 1000);

    // One forged SessionSetup naming `dest` would leave exactly this entry.
    install_halfopen(&mut node, dest);
    assert!(!node.has_cached_identity(&dest), "precondition");

    let encoded = PathBroken::new(dest, reporter).encode();
    node.handle_path_broken(&reporter, &reporter, &encoded[5..])
        .await;

    assert!(
        node.coord_cache().get(&dest, 1000).is_some(),
        "a half-open entry keyed on a claimed address must not admit the signal"
    );
    assert!(
        !node.has_cached_identity(&dest),
        "the placeholder key of a half-open entry must not be cached for the address it claims"
    );
    assert_eq!(node.stats().session.unknown_session, 1);

    let errors = &node.metrics().errors;
    assert_eq!(
        errors.unbound.broken.get(),
        1,
        "a half-open entry is an unbound refusal for PathBroken"
    );
    assert_eq!(
        errors.unbound.forged.get(),
        0,
        "a half-open entry is a plausible pairing, not a forged one"
    );
}

#[tokio::test]
async fn test_path_broken_for_a_session_we_initiated_still_flushes_cached_coords() {
    use crate::proto::routing::PathBroken;

    let mut node = make_node();

    let remote = Identity::generate();
    install_initiating(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let coords = node.tree_state().my_coords().clone();
    let _ = node.coord_cache_mut().insert(dest, coords, 1000);

    let encoded = PathBroken::new(dest, reporter).encode();
    node.handle_path_broken(&reporter, &reporter, &encoded[5..])
        .await;

    assert!(
        node.coord_cache().get(&dest, 1000).is_none(),
        "handshake-time recovery must still flush coords for an address we chose"
    );
}

#[tokio::test]
async fn test_coords_required_naming_a_dest_with_no_session_is_counted_as_an_unknown_session_reject()
 {
    use crate::proto::routing::CoordsRequired;

    let mut node = make_node();

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);

    let encoded = CoordsRequired::new(dest, reporter).encode();
    node.handle_coords_required(&reporter, &encoded[5..]).await;
    assert_eq!(node.stats().session.unknown_session, 1);

    // A second identical signal is refused the same way. This does not pin
    // the gate's position relative to the response rate limiter: should_send
    // returning false would not short-circuit the handler, so this counter
    // reaches 2 either way. The ordering is pinned by
    // test_coords_required_for_an_unbound_dest_never_reaches_the_response_rate_limiter.
    node.handle_coords_required(&reporter, &encoded[5..]).await;
    assert_eq!(node.stats().session.unknown_session, 2);

    let errors = &node.metrics().errors;
    assert_eq!(
        errors.unbound.coords.get(),
        2,
        "both refusals must be counted against the CoordsRequired counter"
    );
    assert_eq!(
        errors.unbound.broken.get(),
        0,
        "a CoordsRequired refusal must not bump the PathBroken counter"
    );
    assert_eq!(
        errors.unbound.mtu.get(),
        0,
        "a CoordsRequired refusal must not bump the MtuExceeded counter"
    );
    assert_eq!(
        errors.unbound.forged.get(),
        0,
        "an absent session is an unbound refusal, not a forged pairing"
    );
    assert_eq!(
        errors.coords_required.get(),
        2,
        "the arrival counter is the denominator and counts refused arrivals too"
    );
}

#[tokio::test]
async fn test_coords_required_for_an_unbound_dest_never_reaches_the_response_rate_limiter() {
    use crate::proto::routing::CoordsRequired;

    let mut node = make_node();

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);

    assert_eq!(
        node.coords_response_rate_limiter.len(),
        0,
        "precondition: the response rate limiter holds nothing before the signal"
    );

    let encoded = CoordsRequired::new(dest, reporter).encode();
    node.handle_coords_required(&reporter, &encoded[5..]).await;

    assert_eq!(node.stats().session.unknown_session, 1);
    assert_eq!(
        node.coords_response_rate_limiter.len(),
        0,
        "an inadmissible signal must be refused before should_send can insert \
         the attacker-chosen address into last_sent"
    );
}

#[tokio::test]
async fn test_coords_required_for_a_bound_dest_does_reach_the_response_rate_limiter() {
    use crate::proto::routing::CoordsRequired;

    let mut node = make_node();

    let remote = Identity::generate();
    install_initiating(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);

    let encoded = CoordsRequired::new(dest, reporter).encode();
    node.handle_coords_required(&reporter, &encoded[5..]).await;

    assert_eq!(node.stats().session.unknown_session, 0);
    assert_eq!(
        node.coords_response_rate_limiter.len(),
        1,
        "an admitted signal must still consult the response rate limiter"
    );
}

#[tokio::test]
async fn test_mtu_exceeded_whose_claimed_source_is_the_destination_it_names_is_dropped() {
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    // The emitter of a routing signal is by construction a transit node for
    // the datagram it is reporting on, so it is never that datagram's own
    // destination. A signal claiming otherwise is malformed.
    let inner = build_mtu_exceeded_inner(&dest, &dest, 1280);
    node.handle_mtu_exceeded(&dest, &inner).await;

    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        None,
        "a signal whose claimed source is the destination it names must be dropped"
    );
    assert_eq!(node.stats().session.unknown_session, 1);

    let errors = &node.metrics().errors;
    assert_eq!(
        errors.unbound.mtu.get(),
        1,
        "the refusal must still be counted against the MtuExceeded counter"
    );
    assert_eq!(
        errors.unbound.forged.get(),
        1,
        "a src equal to the dest it names is a structurally impossible pairing"
    );
}

#[tokio::test]
async fn test_coords_required_naming_this_node_as_the_destination_counts_a_forged_pairing() {
    use crate::proto::routing::CoordsRequired;

    let mut node = make_node();

    // A datagram addressed to this node is delivered locally before any
    // forwarding, so no honest transit router ever emits a signal naming
    // us as the destination. This clause can only be reached by fabrication.
    let dest = *node.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);

    let encoded = CoordsRequired::new(dest, reporter).encode();
    node.handle_coords_required(&reporter, &encoded[5..]).await;

    assert_eq!(node.stats().session.unknown_session, 1);
    let errors = &node.metrics().errors;
    assert_eq!(
        errors.unbound.coords.get(),
        1,
        "the refusal must be counted against the CoordsRequired counter"
    );
    assert_eq!(
        errors.unbound.forged.get(),
        1,
        "a signal naming this node as the destination is a forged pairing"
    );
    assert_eq!(
        errors.unbound.broken.get(),
        0,
        "a CoordsRequired refusal must not bump the PathBroken counter"
    );
    assert_eq!(
        errors.unbound.mtu.get(),
        0,
        "a CoordsRequired refusal must not bump the MtuExceeded counter"
    );
}

// ============================================================================
// Proactive PathMtuNotification → path_mtu_lookup focused unit tests
//
// These exercise the receive-side write path that mirrors the proactive
// end-to-end echo into `path_mtu_lookup`. Without this mirror, new TCP
// flows opened on a path the proactive notification has tightened keep
// getting clamped by the staler discovery-time value until a reactive
// MtuExceeded fires for those flows — long-lived stable paths can sit
// in the gap indefinitely.
// ============================================================================

/// Build a PathMtuNotification body (2 bytes: path_mtu LE).
fn build_path_mtu_notification_body(mtu: u16) -> Vec<u8> {
    mtu.to_le_bytes().to_vec()
}

/// Insert an Established session with MMP initialized so the proactive
/// PathMtuNotification handler can apply notifications.
fn install_established_session_with_mmp(node: &mut Node, remote: &Identity) {
    let session = make_noise_session(node.identity(), remote);
    let remote_addr = *remote.node_addr();
    let mut entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);
    entry.init_mmp(&node.config().node.session_mmp);
    node.sessions.insert(remote_addr, entry);
}

#[test]
fn test_handle_path_mtu_notification_writes_path_mtu_lookup_when_empty() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    assert!(
        node.path_mtu_lookup_get(&remote_fips).is_none(),
        "lookup should start empty for this destination"
    );

    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "PathMtuNotification should populate path_mtu_lookup with the reported MTU"
    );
}

#[test]
fn test_handle_path_mtu_notification_tightens_existing_path_mtu_lookup() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    // Pre-seed with a generous value (e.g., from the discovery seed at link
    // promotion time, before the destination's proactive echo arrived).
    node.path_mtu_lookup_insert(remote_fips, 1500);

    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "PathMtuNotification with smaller MTU must tighten the lookup"
    );
}

#[test]
fn test_handle_path_mtu_notification_keeps_tighter_existing_path_mtu_lookup() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    // Pre-seed with a tighter value than what the proactive notification
    // reports (e.g., from a prior reactive MtuExceeded on a narrower hop).
    // The mirror must never loosen the clamp.
    node.path_mtu_lookup_insert(remote_fips, 1200);

    let body = build_path_mtu_notification_body(1400);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1200),
        "PathMtuNotification with looser MTU must not loosen a tighter existing value"
    );
}

#[test]
fn test_handle_path_mtu_notification_no_session_no_op() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);

    // No session installed. The handler should drop the notification entirely.
    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert!(
        node.path_mtu_lookup_get(&remote_fips).is_none(),
        "PathMtuNotification with no session must not touch path_mtu_lookup"
    );
}

#[test]
fn test_sub_floor_path_mtu_notification_is_ignored_and_counted() {
    // The state machine returns the same `false` for a sub-floor refusal as
    // for an ordinary no-change, so without a counter at the caller the
    // refusal is indistinguishable from the common case. This arrives on the
    // decrypted path, so a rising count means an authenticated peer is
    // sending unusable values.
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    assert_eq!(
        node.metrics().errors.path_mtu_notif_below_floor.get(),
        0,
        "counter starts at zero on a fresh node"
    );

    let body = build_path_mtu_notification_body(crate::proto::mmp::MIN_ACTIONABLE_PATH_MTU - 1);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.metrics().errors.path_mtu_notif_below_floor.get(),
        1,
        "a sub-floor PathMtuNotification must bump the below-floor counter"
    );
    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        None,
        "a sub-floor PathMtuNotification must leave no path_mtu_lookup entry"
    );

    // The counter must discriminate: an actionable value is applied and must
    // not bump it.
    let body = build_path_mtu_notification_body(1280);
    node.handle_session_path_mtu_notification(&remote_addr, &body);

    assert_eq!(
        node.metrics().errors.path_mtu_notif_below_floor.get(),
        1,
        "an actionable PathMtuNotification must not bump the below-floor counter"
    );
    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1280),
        "the actionable value must still be applied after a refused one"
    );
}

#[tokio::test]
async fn test_idle_session_purge_keeps_link_peer_path_mtu_seed() {
    use crate::peer::ActivePeer;
    use crate::transport::udp::UdpTransport;
    use crate::transport::{TransportHandle, packet_channel};

    // Releasing on idle expiry must not throw away what local configuration
    // knows. Idle expiry removes an end-to-end session; the FMP link to a
    // directly connected peer stays up, and its link MTU is seeded only on
    // link promotion. A blanket removal here would drop that peer to the
    // conservative ceiling for every later flow until the link re-handshakes.
    let mut node = make_node();
    let (packet_tx, packet_rx) = packet_channel(64);
    node.supervisor.packet_tx = Some(packet_tx);
    node.packet_rx = Some(packet_rx);

    let (transport_packet_tx, _transport_packet_rx) = packet_channel(64);
    let transport_id = TransportId::new(1);
    let mut udp = UdpTransport::new(
        transport_id,
        Some("udp1".to_string()),
        crate::config::UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1452),
            ..Default::default()
        },
        transport_packet_tx,
    );
    udp.start_async().await.unwrap();
    node.transports
        .insert(transport_id, TransportHandle::Udp(udp));

    // A directly connected peer, seeded from its link MTU the way FMP
    // promotion seeds it, with an end-to-end session on top.
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::Ipv6Address::from_node_addr(&remote_addr);
    let transport_addr = TransportAddr::from_string("127.0.0.1:2121");

    let peer_identity = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let mut peer = ActivePeer::new(peer_identity, LinkId::new(7), 0);
    peer.set_current_addr(transport_id, transport_addr.clone());
    node.peers.insert(remote_addr, peer);

    node.seed_path_mtu_for_link_peer(
        &remote_addr,
        crate::ipv6tun::link::PeerKey::from_xonly(&remote.pubkey()),
        transport_id,
        &transport_addr,
    );
    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1452),
        "precondition: the direct-link seed is in place"
    );

    let session = make_noise_session(node.identity(), &remote);
    let entry =
        crate::node::session::SessionEntry::keyed(remote_addr, session, session_at(1000), true);
    node.sessions.insert(remote_addr, entry);

    node.purge_idle_sessions(session_at(1000 + 92_000));
    assert_eq!(node.session_count(), 0, "precondition: the session expired");

    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1452),
        "idle expiry must leave the locally derived link MTU in place"
    );

    for transport in node.transports.values_mut() {
        transport.stop().await.ok();
    }
}

// ============================================================================
// Session identity binding: XX msg3 source address / static key
// ============================================================================

/// Helper: read the XX ack `ack` on the initiator handshake `hs`, its
/// negotiation payload included when it carries one, and write the msg3 that
/// answers it, carrying the negotiation payload a session's first handshake
/// carries when `opening`, as a node of this line writes it.
fn xx_msg3(hs: &crate::noise::HandshakeState, ack: &[u8], opening: bool) -> Vec<u8> {
    let (mut hs, _) = hs.fork_msg2(ack).expect("the ack reads");
    let mut msg3 = hs.write_message_3().expect("msg3 builds");
    if opening {
        let payload = crate::proto::fmp::NegotiationPayload::new(0, 0, 0).encode();
        msg3.extend(hs.encrypt_payload(&payload).expect("the payload seals"));
    }
    msg3
}

/// Helper: open a session on `node` for a setup `initiator_identity` writes
/// under the claimed address `claimed`, at `now`, and return the session with
/// its candidate held, plus the msg3 the initiator writes on the ack.
///
/// The msg3 is cryptographically valid for the candidate and carries
/// `initiator_identity`'s static key, which is exactly the shape of the
/// defect when `claimed` is not that key's address: a peer that completes a
/// real handshake while the datagram claims somebody else's source address.
fn drive_xx_to_msg3(
    node: &Node,
    claimed: NodeAddr,
    initiator_identity: &Identity,
    now: crate::node::session::SessionInstant,
) -> (crate::node::session::SessionEntry, Vec<u8>) {
    use crate::noise::HandshakeState;

    let mut initiator = HandshakeState::new_initiator(initiator_identity.keypair());
    let mut init_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut init_epoch);
    initiator.set_local_epoch(init_epoch);

    let msg1 = initiator.write_message_1().unwrap();
    let carrier = stub_link_peer();
    let (entry, out) = crate::node::session::SessionEntry::answering(
        claimed,
        &msg1,
        carrier,
        crate::proto::stp::TreeCoordinate::root(carrier),
        node.session_params(),
        &node.session_node_keys(),
        *node.node_addr(),
        now,
    );
    let msg2 = out
        .into_iter()
        .find_map(|o| match o {
            fips_core::proto::rekey::Output::Send { msg, .. } => Some(msg),
            _ => None,
        })
        .expect("the setup is held and acknowledged");
    let msg3 = xx_msg3(&initiator, &msg2, true);

    (entry, msg3)
}

/// Helper: generate an identity whose full public key has odd parity.
fn generate_odd_parity_identity() -> Identity {
    loop {
        let id = Identity::generate();
        if id.pubkey_full().serialize()[0] == 0x03 {
            return id;
        }
    }
}

#[tokio::test]
async fn test_session_msg3_rejects_spoofed_source_address() {
    let mut node = make_node();
    let attacker = Identity::generate();
    let victim = Identity::generate();
    let victim_addr = *victim.node_addr();

    // Half-open session recorded under the victim's address, as the setup
    // handler opens it from the claimed source. Its only candidate goes with
    // the msg3, and the session with it.
    let (entry, msg3) = drive_xx_to_msg3(&node, victim_addr, &attacker, Node::session_now());
    node.sessions.insert(victim_addr, entry);

    node.handle_session_payload(
        &victim_addr,
        &stub_link_peer(),
        &SessionMsg3::new(msg3).encode(),
        1280,
        false,
    )
    .await;

    assert_eq!(
        node.session_count(),
        0,
        "session must not be installed under an address the peer's key does not derive"
    );
    assert_eq!(
        node.identity_cache_len(),
        0,
        "identity cache must not be poisoned with the spoofed address"
    );
    assert_eq!(node.stats().session.addr_mismatch, 1);
}

#[tokio::test]
async fn test_session_msg3_accepts_matching_source_address() {
    let mut node = make_node();
    let peer = Identity::generate();
    let peer_addr = *peer.node_addr();

    let (entry, msg3) = drive_xx_to_msg3(&node, peer_addr, &peer, Node::session_now());
    assert_eq!(
        (entry.identity(), entry.peer_key()),
        (fips_core::proto::rekey::Identity::Claimed(peer_addr), None),
        "before its msg3 the session knows only the address the setup claimed"
    );
    node.sessions.insert(peer_addr, entry);

    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(msg3).encode(),
        1280,
        false,
    )
    .await;

    assert!(
        node.sessions
            .get(&peer_addr)
            .is_some_and(|e| e.is_established()),
        "an honest initiator using its own address must still establish"
    );
    assert_eq!(
        node.get_session(&peer_addr).and_then(|e| e.peer_key()),
        Some(peer.pubkey()),
        "the completion bonds the key its msg3 authenticated"
    );
    assert_eq!(node.identity_cache_len(), 1);
    assert_eq!(node.stats().session.addr_mismatch, 0);
}

#[tokio::test]
async fn test_rekey_msg3_rejects_different_static_key() {
    let mut node = make_node();
    let legit = Identity::generate();
    let attacker = Identity::generate();
    let peer_addr = *legit.node_addr();

    let session = make_noise_session(node.identity(), &legit);
    let entry =
        crate::node::session::SessionEntry::keyed(peer_addr, session, session_at(1000), true);

    // A rekey setup held beside the session, but written by a different
    // identity.
    node.sessions.insert(peer_addr, entry);
    let msg3 = hold_rekey_setup(&mut node, &peer_addr, &attacker);

    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(msg3).encode(),
        1280,
        false,
    )
    .await;

    let entry = node
        .sessions
        .get(&peer_addr)
        .expect("existing session must survive a spoofed rekey");
    assert!(entry.is_established());
    assert!(
        entry.pending_new_session().is_none() && !entry.is_draining(),
        "a rekey from a different static key must not become the session's keys"
    );
    assert_eq!(
        entry.candidate_count(),
        0,
        "the candidate it completed goes"
    );
    assert_eq!(node.stats().session.rekey_key_mismatch, 1);
}

#[tokio::test]
async fn test_rekey_msg3_accepts_established_peer_key() {
    let mut node = make_node();
    let legit = Identity::generate();
    let peer_addr = *legit.node_addr();

    let session = make_noise_session(node.identity(), &legit);
    let entry =
        crate::node::session::SessionEntry::keyed(peer_addr, session, session_at(1000), true);

    node.sessions.insert(peer_addr, entry);
    let msg3 = hold_rekey_setup(&mut node, &peer_addr, &legit);

    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(msg3).encode(),
        1280,
        false,
    )
    .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(
        entry.is_draining(),
        "the responder must cut over to the peer's rekey at its msg3"
    );
    assert_eq!(node.stats().session.rekey_key_mismatch, 0);
}

#[tokio::test]
async fn test_rekey_msg3_accepts_odd_parity_peer_stored_as_even() {
    let mut node = make_node();
    let legit = generate_odd_parity_identity();
    let peer_addr = *legit.node_addr();

    // The stored key is the even-parity synthesis an npub-sourced peer
    // identity produces; the peer's real key has odd parity. This must
    // still be accepted, or every peer-initiated rekey against roughly
    // half of all peers would be rejected.
    let stored_pubkey = crate::identity::PeerIdentity::from_pubkey(legit.pubkey()).pubkey_full();
    assert_ne!(
        stored_pubkey,
        legit.pubkey_full(),
        "test fixture must actually differ in parity"
    );

    let session = make_noise_session(node.identity(), &legit);
    let entry =
        crate::node::session::SessionEntry::keyed(peer_addr, session, session_at(1000), true);

    node.sessions.insert(peer_addr, entry);
    let msg3 = hold_rekey_setup(&mut node, &peer_addr, &legit);

    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(msg3).encode(),
        1280,
        false,
    )
    .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(
        entry.is_draining(),
        "a parity-normalized stored key must not reject a legitimate rekey"
    );
    assert_eq!(node.stats().session.rekey_key_mismatch, 0);
}

/// Install an established entry with a handshake armed beside it by a
/// stranger's setup, the shape a forged setup leaves behind.
///
/// Returns the node, the peer's address and the cryptographically valid msg3
/// the stranger would send to finish the handshake it armed.
fn install_a_stranger_armed_handshake(
    peer: &Identity,
    stranger: &Identity,
) -> (Node, crate::NodeAddr, Vec<u8>) {
    let (mut node, peer_addr) = make_node_with_established_peer(peer);
    let msg3 = arm_stranger_handshake(&mut node, &peer_addr, stranger);
    (node, peer_addr, msg3)
}

/// Hold a rekey setup from a stranger beside a session that is already
/// established, as the setup handler does, and return the msg3 that
/// completes it.
fn arm_stranger_handshake(
    node: &mut Node,
    peer_addr: &crate::NodeAddr,
    stranger: &Identity,
) -> Vec<u8> {
    hold_rekey_setup(node, peer_addr, stranger)
}

/// Hold a rekey setup written by `initiator`, under the startup epoch the
/// test fixtures record for a peer, beside `node`'s established session
/// with `peer_addr`, through its rekey machine as the setup handler does,
/// and return the msg3 that completes it.
fn hold_rekey_setup(node: &mut Node, peer_addr: &crate::NodeAddr, initiator: &Identity) -> Vec<u8> {
    use crate::noise::HandshakeState;
    use fips_core::proto::rekey::{MsgKind, Output};

    let mut hs = HandshakeState::new_initiator(initiator.keypair());
    hs.set_local_epoch(crate::node::session::TEST_PEER_EPOCH);
    let msg1 = hs.write_message_1().expect("msg1 builds");
    let local = node.session_node_keys();
    let route = node.tree_state().my_coords().clone();
    let out = node
        .sessions
        .get_mut(peer_addr)
        .expect("an established session")
        .step_setup(&msg1, *peer_addr, route, Node::session_now(), &local);
    let ack = out
        .into_iter()
        .find_map(|o| match o {
            Output::Send {
                msg,
                kind: MsgKind::Ack,
                ..
            } => Some(msg),
            _ => None,
        })
        .expect("the setup is held and acknowledged");
    xx_msg3(&hs, &ack, false)
}

#[tokio::test]
async fn test_forged_msg3_against_a_peer_armed_handshake_leaves_the_session_keys_intact() {
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr, valid_msg3) = install_a_stranger_armed_handshake(&peer, &stranger);

    // Garbage of the right length: `read_message_3` fails on the AEAD.
    let forged = SessionMsg3::new(vec![0u8; crate::noise::HANDSHAKE_MSG3_SIZE]).encode();
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(
        entry.is_established() && !entry.is_draining(),
        "an unauthenticated msg3 must leave the running session's keys as \
         they were"
    );
    assert_eq!(
        entry.candidate_count(),
        1,
        "an unreadable msg3 must not discard the candidate it failed against"
    );

    // The candidate's handshake is as it was: the msg3 that genuinely
    // finishes it still reads, and the bond to the peer's key, not the read,
    // refuses it.
    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(valid_msg3).encode(),
        1280,
        false,
    )
    .await;
    assert_eq!(
        node.stats().session.rekey_key_mismatch,
        1,
        "the kept handshake must still read the msg3 that finishes it"
    );
    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(
        !entry.is_draining(),
        "a stranger's msg3 must not cut the session over"
    );
    assert_eq!(entry.candidate_count(), 0);
}

#[tokio::test]
async fn test_rekey_msg3_from_a_different_static_key_leaves_the_session_keys_intact() {
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr, valid_msg3) = install_a_stranger_armed_handshake(&peer, &stranger);

    // Cryptographically valid for the handshake the stranger armed, so
    // `read_message_3` succeeds and the key-mismatch branch decides.
    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(valid_msg3).encode(),
        1280,
        false,
    )
    .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(
        entry.is_established() && !entry.is_draining(),
        "a msg3 whose static key is not this session's peer must not cut the \
         session over"
    );
    assert_eq!(
        node.stats().session.rekey_key_mismatch,
        1,
        "the key mismatch must still be counted, so this test also pins that \
         the refusal itself did not move"
    );
}

/// A rekey msg3 whose base message reads but whose negotiation payload does
/// not decrypt completes nothing: the session keys stay as they were, and the
/// candidate it was written for keeps its handshake, which still reads the
/// msg3 that genuinely finishes it.
///
/// XX msg3 can carry a negotiation payload behind the base message, so the
/// base read succeeding and the trailer's decrypt failing is a failure path
/// of its own, and nothing about the sender is established at that point.
#[tokio::test]
async fn test_rekey_msg3_with_an_unreadable_negotiation_payload_leaves_the_completed_epoch_intact()
{
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr, valid_msg3) = install_a_stranger_armed_handshake(&peer, &stranger);

    let mut payload = valid_msg3.clone();
    let base_len = payload.len();
    payload.resize(base_len + crate::noise::TAG_SIZE + 8, 0);
    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(payload).encode(),
        1280,
        false,
    )
    .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(
        entry.is_established() && !entry.is_draining(),
        "a msg3 whose negotiation payload will not decrypt must leave the \
         session keys as they were"
    );
    assert_eq!(
        entry.candidate_count(),
        1,
        "the candidate the payload failed against must be kept"
    );
    assert_eq!(node.stats().session.rekey_key_mismatch, 0);

    // The candidate's handshake was not spoiled: the msg3 that finishes it
    // still reads, and the key mismatch, not the read, refuses it.
    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(valid_msg3).encode(),
        1280,
        false,
    )
    .await;
    assert_eq!(
        node.stats().session.rekey_key_mismatch,
        1,
        "the kept handshake must still read the msg3 that finishes it"
    );
}

// ============================================================================
// Integration tests: a setup message naming an established peer
// ============================================================================

/// Build a two-node routable mesh with default configs and every node's
/// coordinate cache populated.
async fn make_routable_pair() -> Vec<TestNode> {
    let configs = (0..2).map(|_| Config::new()).collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    nodes
}

/// How long the session tests' setup waits for both sides to be established.
///
/// Sized for a loaded host, the same figure the bootstrap tests give peering.
/// Measured on the wall clock, because one caller pauses tokio time and a
/// paused clock would run out a tokio bound at once.
const SESSION_SETUP_BOUND: Duration = Duration::from_secs(10);

/// Establish an FSP session from nodes[0] to nodes[1] and assert both sides
/// reached Established.
async fn establish_pair_session(nodes: &mut [TestNode]) {
    establish_pair_session_within(nodes, SESSION_SETUP_BOUND).await;
}

/// Establish an FSP session from nodes[0] to nodes[1], waiting up to `bound`
/// of wall time, and assert both sides reached Established.
async fn establish_pair_session_within(nodes: &mut [TestNode], bound: Duration) {
    let node1_pubkey = nodes[1].node.identity().pubkey_full();
    establish_under(nodes, node1_pubkey, bound).await;
}

/// Establish an FSP session from nodes[0] to nodes[1], dialling nodes[1]
/// under `key`, waiting up to `bound` of wall time, and assert both sides
/// reached Established.
///
/// `key` is what nodes[0] stores as the session's peer key, so a caller can
/// pin a key that differs from nodes[1]'s own in parity.
///
/// The three 20 ms drain passes come first, unconditionally: on loopback they
/// carry the three-message handshake one hop per pass, so a setup that
/// completes in them returns exactly as it always has. Only a setup still
/// short of Established after them keeps draining, until the bound.
async fn establish_under(nodes: &mut [TestNode], key: secp256k1::PublicKey, bound: Duration) {
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let deadline = std::time::Instant::now() + bound;

    nodes[0]
        .node
        .initiate_session(node1_addr, key)
        .await
        .expect("initiate_session failed");

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(nodes).await;
    }

    let established = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established())
            && nodes[1]
                .node
                .get_session(&node0_addr)
                .is_some_and(|e| e.is_established())
    };
    while !established(nodes) && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(nodes).await;
    }

    assert!(
        established(nodes),
        "the pair's session must be established before the test body: after {:?} \
         initiator {}, responder {}",
        bound,
        setup_state(&nodes[0].node, &node1_addr),
        setup_state(&nodes[1].node, &node0_addr),
    );
}

/// Name the state of `node`'s session entry for `peer`, for a setup failure.
fn setup_state(node: &Node, peer: &NodeAddr) -> &'static str {
    match node.get_session(peer) {
        None => "absent",
        Some(e) if e.is_established() => "established",
        Some(e) if e.is_initiating() => "initiating",
        Some(e) if e.is_awaiting_msg3() => "awaiting msg3",
        Some(_) => "no state",
    }
}

#[tokio::test]
async fn a_session_setup_whose_packets_arrive_late_is_still_established_before_the_test_body() {
    let mut nodes = make_routable_pair().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // Each of the handshake's three hops now takes 100 ms, longer than the
    // whole of a fixed 60 ms setup window.
    for node in &nodes {
        delay_loopback_delivery(node, Some(Duration::from_millis(100)));
    }
    establish_pair_session(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established()),
        "the initiator must be established once the setup returns"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.is_established()),
        "the responder must be established once the setup returns"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
#[should_panic(expected = "must be established before the test body")]
async fn a_session_setup_that_never_completes_fails_at_the_bound() {
    let mut nodes = make_routable_pair().await;

    // The responder never hears the setup, so the wait has to give up at its
    // bound rather than hide a handshake that cannot finish.
    delay_loopback_delivery(&nodes[1], None);
    establish_pair_session_within(&mut nodes, Duration::from_millis(300)).await;
}

/// Forge a SessionSetup carrying an unrelated ephemeral but claiming
/// `nodes[0]`'s coordinates, as an attacker able to reach `nodes[1]` would.
///
/// XX msg1 is a bare ephemeral: unlike XK it needs no knowledge of the
/// responder's static key, so the forgery is even cheaper on this branch.
fn forge_setup_from_stranger(nodes: &[TestNode]) -> Vec<u8> {
    use crate::noise::HandshakeState;
    use crate::proto::fsp::SessionSetup;

    let attacker = Identity::generate();
    let mut handshake = HandshakeState::new_initiator(attacker.keypair());
    handshake.set_local_epoch([0xA5; 8]);
    let msg1 = handshake
        .write_message_1()
        .expect("attacker msg1 must build");

    SessionSetup::new(
        nodes[0].node.tree_state().my_coords().clone(),
        nodes[1].node.tree_state().my_coords().clone(),
    )
    .with_handshake(msg1)
    .encode()
}

#[tokio::test]
async fn test_forged_setup_naming_established_peer_leaves_session_carrying_traffic() {
    let mut nodes = make_routable_pair().await;
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let recv_before = nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .traffic_counters()
        .1;

    let forged = forge_setup_from_stranger(&nodes);
    nodes[1]
        .node
        .handle_session_payload(&node0_addr, &node0_addr, &forged, 1280, false)
        .await;

    let entry = nodes[1]
        .node
        .get_session(&node0_addr)
        .expect("the established entry must survive an unauthenticated setup");
    assert!(
        entry.is_established(),
        "an unauthenticated setup must not replace the established session"
    );
    assert_eq!(
        entry.candidate_count(),
        1,
        "the forged setup must have been held as a candidate, not dropped \
         for an unrelated reason"
    );
    assert_eq!(
        nodes[1].node.stats().session.rekey_armed,
        1,
        "answering an unauthenticated setup must be counted, since the DEBUG \
         line at that site is invisible at the default level"
    );

    // The session must still decrypt the real peer's next frame.
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"after the forgery")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    let recv_after = nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .traffic_counters()
        .1;
    assert!(
        recv_after > recv_before,
        "the real peer's frame must still decrypt: received {} packets before, {} after",
        recv_before,
        recv_after
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_genuine_peer_restart_reestablishes_session() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0].node.remove_session(&node1_addr);
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("re-initiate_session failed");

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder entry present")
            .is_draining(),
        "the restarted peer's msg3 must have cut node 1 over to its keys"
    );

    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"after the restart")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    let entry = nodes[1].node.get_session(&node0_addr).unwrap();
    assert!(
        entry.traffic_counters().1 > 0,
        "node 1 must have decrypted the restarted peer's frame"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: the per-link-peer session-setup limiter
// ============================================================================

/// Build a two-node routable mesh with the setup limiter sized for a test.
async fn make_setup_limited_pair(burst: u32, rate: f64) -> Vec<TestNode> {
    let configs = (0..2)
        .map(|_| {
            let mut config = Config::new();
            config.node.rate_limit.session_setup_burst = burst;
            config.node.rate_limit.session_setup_rate = rate;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    nodes
}

/// Deliver one forged SessionSetup to `nodes[1]` over the link from
/// `nodes[0]`, naming a fresh source address nobody has seen.
///
/// Driven through `handle_session_datagram` rather than
/// `handle_session_payload` for two reasons: it is the only path that binds
/// the link peer the limiter keys on, and its coordinate-cache warming is
/// what gives the forged address a route, without which the ack send fails
/// and the entry is never inserted even in unlimited code.
async fn deliver_forged_setup_over_link(nodes: &mut [TestNode]) {
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let forged_src = *Identity::generate().node_addr();

    let setup = forge_setup_from_stranger(nodes);
    let datagram = SessionDatagram::new(forged_src, node1_addr, setup).with_ttl(64);
    let encoded = datagram.encode();

    nodes[1]
        .node
        .handle_session_datagram(&node0_addr, &encoded[1..], false)
        .await;
}

#[tokio::test]
async fn test_forged_setups_from_one_link_peer_stop_creating_session_entries_once_the_bucket_is_drained()
 {
    const BURST: u32 = 4;
    // Slow enough that nothing refills during the test.
    let mut nodes = make_setup_limited_pair(BURST, 0.5).await;

    let before = nodes[1].node.sessions.len();
    for _ in 0..BURST {
        deliver_forged_setup_over_link(&mut nodes).await;
    }
    assert_eq!(
        nodes[1].node.sessions.len(),
        before + BURST as usize,
        "the burst must be admitted, or this test would pass for the wrong reason"
    );
    assert_eq!(nodes[1].node.stats().session.setup_rate_limited, 0);

    // Every SessionAck the handler emits goes out through
    // `send_session_datagram`, which is the only thing that bumps this
    // counter on a node with no transit traffic. A refused setup must not
    // move it: that is the ack amplification bound, measured rather than
    // argued from where the check sits.
    let originated = nodes[1].node.metrics().forwarding.originated_packets.get();

    for _ in 0..3 {
        deliver_forged_setup_over_link(&mut nodes).await;
    }

    assert_eq!(
        nodes[1].node.sessions.len(),
        before + BURST as usize,
        "a drained bucket must stop the session table growing"
    );
    assert_eq!(
        nodes[1].node.stats().session.setup_rate_limited,
        3,
        "each refusal must be counted; the DEBUG line is invisible by default"
    );
    assert_eq!(
        nodes[1].node.metrics().forwarding.originated_packets.get(),
        originated,
        "a refused setup must emit nothing at all, so it buys the sender no \
         packet to an address it chose"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The limiter's clock for the refill test: tokio's paused clock, which the
/// test moves with `tokio::time::advance` and nothing else moves.
fn paused_now() -> crate::time::HostInstant {
    crate::time::HostInstant::from(tokio::time::Instant::now().into_std())
}

#[tokio::test]
async fn test_a_drained_setup_bucket_refills_and_admits_the_next_legitimate_setup() {
    const BURST: u32 = 2;
    const RATE: f64 = 2.0;
    let mut nodes = make_setup_limited_pair(BURST, RATE).await;

    // From here the limiter reads a clock only the test moves, so the drain
    // cannot race a refill however slowly each delivery runs, and the refill
    // below is exactly the one the test grants.
    tokio::time::pause();
    nodes[1].node.setup_clock = Some(paused_now);

    let before = nodes[1].node.stats().session.setup_rate_limited;
    for _ in 0..=BURST {
        deliver_forged_setup_over_link(&mut nodes).await;
    }
    assert_eq!(
        nodes[1].node.stats().session.setup_rate_limited,
        before + 1,
        "the burst must be admitted and the one setup past it refused"
    );

    // A full burst back from empty at the configured rate, so the legitimate
    // setup below meets a bucket the refill alone has restored. The denial
    // is transient and clears on its own; how long it lasts is a function of
    // the configured rate.
    tokio::time::advance(Duration::from_secs_f64(f64::from(BURST) / RATE)).await;
    establish_pair_session(&mut nodes).await;

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_a_drained_stranger_bucket_still_admits_a_setup_naming_an_established_peer() {
    // Burst 2: one token for the genuine msg1 that establishes the pair, one
    // for a forged stranger setup, and the third stranger setup is refused.
    let mut nodes = make_setup_limited_pair(2, 0.5).await;
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    deliver_forged_setup_over_link(&mut nodes).await;
    deliver_forged_setup_over_link(&mut nodes).await;
    assert!(
        nodes[1].node.stats().session.setup_rate_limited > 0,
        "the stranger bucket must be drained before the established class is tested"
    );

    // The same message, but naming the established peer: this is the shape an
    // inbound rekey arrives in. It creates no new table entry, so it draws on
    // its own bucket rather than competing with stranger admission.
    let setup = forge_setup_from_stranger(&nodes);
    let datagram = SessionDatagram::new(node0_addr, node1_addr, setup).with_ttl(64);
    let encoded = datagram.encode();
    nodes[1]
        .node
        .handle_session_datagram(&node0_addr, &encoded[1..], false)
        .await;

    assert_eq!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("the established session must still be there")
            .candidate_count(),
        1,
        "a drained stranger bucket must not stop an established peer's rekey \
         setup being answered: suppressed rotation is silent, and the \
         operator's only signal would be a flat rekey_armed"
    );
    assert_eq!(nodes[1].node.stats().session.rekey_armed, 1);

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: the session-table population cap
// ============================================================================

/// Build a two-node routable mesh with the session table capped for a test
/// and the setup limiter opened wide, so the cap is the only thing refusing.
async fn make_session_capped_pair(max_sessions: usize) -> Vec<TestNode> {
    let configs = (0..2)
        .map(|_| {
            let mut config = Config::new();
            config.node.limits.max_sessions = max_sessions;
            config.node.rate_limit.session_setup_burst = 10_000;
            config.node.rate_limit.session_setup_rate = 10_000.0;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    nodes
}

#[tokio::test]
async fn test_forged_setups_stop_growing_the_session_table_once_the_cap_is_reached() {
    // The table was the one remotely-grown map with no bound: each setup from
    // an address nobody has seen inserted an entry, and neither existing limit
    // reached it, the setup limiter governing arrival rate rather than
    // population and the idle purge only reaching entries a peer stops using.
    const MAX: usize = 8;
    let share = MAX / 2;
    let mut nodes = make_session_capped_pair(MAX).await;

    for _ in 0..share {
        deliver_forged_setup_over_link(&mut nodes).await;
    }
    assert_eq!(
        nodes[1].node.sessions.len(),
        share,
        "the admissible entries must be admitted, or this test would pass for \
         the wrong reason"
    );
    assert_eq!(nodes[1].node.stats().session.half_open_full, 0);

    // Every SessionAck goes out through `send_session_datagram`, the only
    // thing bumping this counter on a node with no transit traffic. A refused
    // setup must not move it.
    let originated = nodes[1].node.metrics().forwarding.originated_packets.get();

    for _ in 0..4 {
        deliver_forged_setup_over_link(&mut nodes).await;
    }

    assert_eq!(
        nodes[1].node.sessions.len(),
        share,
        "a table at its bound must stop growing"
    );
    assert_eq!(
        nodes[1].node.stats().session.half_open_full,
        4,
        "each refusal must be counted; the DEBUG line is invisible by default"
    );
    assert_eq!(
        nodes[1].node.metrics().forwarding.originated_packets.get(),
        originated,
        "a refused setup must emit nothing at all"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_a_setup_that_would_grow_a_full_table_is_refused_and_counted() {
    // The table-full arm specifically: one established entry against a cap of
    // one, so the half-open share is not what refuses.
    let mut nodes = make_session_capped_pair(1).await;
    establish_pair_session(&mut nodes).await;
    assert_eq!(
        nodes[1].node.sessions.len(),
        1,
        "precondition: the table is full with the established peer"
    );

    let originated = nodes[1].node.metrics().forwarding.originated_packets.get();
    deliver_forged_setup_over_link(&mut nodes).await;

    assert_eq!(
        nodes[1].node.sessions.len(),
        1,
        "a full table must not grow for a stranger"
    );
    assert_eq!(nodes[1].node.stats().session.table_full, 1);
    assert_eq!(
        nodes[1].node.metrics().forwarding.originated_packets.get(),
        originated,
        "a refused setup must cost no ack"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_a_full_session_table_still_serves_a_setup_naming_an_existing_entry() {
    // The guard against writing the cap as "refuse strangers". A setup for an
    // entry already present cannot grow the table, and refusing it would break
    // the duplicate-ack resend an initiator depends on.
    let mut nodes = make_session_capped_pair(1).await;
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let refused_before = nodes[1].node.stats().session.table_full;
    let originated = nodes[1].node.metrics().forwarding.originated_packets.get();

    // A setup naming the established peer: the shape an inbound rekey has.
    let setup = forge_setup_from_stranger(&nodes);
    let datagram = SessionDatagram::new(node0_addr, node1_addr, setup).with_ttl(64);
    let encoded = datagram.encode();
    nodes[1]
        .node
        .handle_session_datagram(&node0_addr, &encoded[1..], false)
        .await;

    assert_eq!(
        nodes[1].node.stats().session.table_full,
        refused_before,
        "a setup that cannot grow the table must not be refused by the cap"
    );
    assert!(
        nodes[1].node.metrics().forwarding.originated_packets.get() > originated,
        "and it must still be answered"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_a_full_session_table_does_not_evict_an_established_session() {
    // Pins refuse-not-evict. The setup that triggers the decision is
    // unauthenticated at that point, so evicting would hand a stranger a way
    // to tear down a session it has nothing to do with.
    let mut nodes = make_session_capped_pair(1).await;
    establish_pair_session(&mut nodes).await;
    let node0_addr = *nodes[0].node.node_addr();

    for _ in 0..4 {
        deliver_forged_setup_over_link(&mut nodes).await;
    }

    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("the established session must survive a flood at the cap")
            .is_established(),
        "a stranger's setup must never cost an established peer its session"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_the_session_table_admits_again_after_the_handshake_reaper_drains_it() {
    // The cap is a ceiling, not a latch: a half-open entry ends with its last
    // candidate, 40 s after its setup, and the room it frees must be usable.
    const MAX: usize = 8;
    let share = MAX / 2;
    let mut nodes = make_session_capped_pair(MAX).await;

    for _ in 0..(share + 2) {
        deliver_forged_setup_over_link(&mut nodes).await;
    }
    assert!(
        nodes[1].node.stats().session.half_open_full > 0,
        "precondition: the table is refusing before the reaper runs"
    );

    let now = Node::session_now();
    nodes[1]
        .node
        .poll_session_rekeys(session_after(now, 40_001))
        .await;
    assert_eq!(
        nodes[1].node.sessions.len(),
        0,
        "precondition: the reaper freed the half-open entries"
    );

    deliver_forged_setup_over_link(&mut nodes).await;
    assert_eq!(
        nodes[1].node.sessions.len(),
        1,
        "room freed by the reaper must be usable, or the cap is a latch"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_half_open_setups_cannot_consume_more_than_their_share_of_the_table() {
    // Half-open entries are unauthenticated and cheap to create, so they are
    // held to a share of the table rather than being allowed to fill it and
    // deny it to every peer that would complete a handshake.
    const MAX: usize = 16;
    let share = MAX / 2;
    let mut nodes = make_session_capped_pair(MAX).await;

    for _ in 0..(share + 2) {
        deliver_forged_setup_over_link(&mut nodes).await;
    }

    assert_eq!(
        nodes[1].node.sessions.len(),
        share,
        "half-open entries must stop at their share, well below the table cap"
    );
    assert_eq!(nodes[1].node.stats().session.half_open_full, 2);
    assert_eq!(
        nodes[1].node.stats().session.table_full,
        0,
        "the table itself is not full, so the refusals must be attributed to \
         the share rather than to the cap"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn test_session_entry_size_stays_within_the_budget_the_cap_is_derived_from() {
    // The default `max_sessions` is derived from what one entry costs.
    // Measured at 6608 bytes of inline state when the cap was written, plus
    // heap for the MMP window and handshake payloads, so 1024 sessions is
    // roughly 7 MB. This is what fires if a large field is added later and
    // the arithmetic behind that default stops holding.
    const BUDGET: usize = 8192;
    assert!(
        std::mem::size_of::<SessionEntry>() <= BUDGET,
        "SessionEntry is {} bytes, over the {} the max_sessions default \
         assumes; re-derive the default or shrink the entry",
        std::mem::size_of::<SessionEntry>(),
        BUDGET
    );
}

// ============================================================================
// Integration tests: a forged SessionAck against an in-flight initiation
// ============================================================================

/// A forged SessionAck of exactly the right length, carrying `from`'s tree
/// coordinates.
///
/// The leading 33 bytes of its handshake payload are a valid compressed
/// point, which is what makes it discriminate a rollback: random bytes
/// usually fail `PublicKey::from_slice` before anything has been mixed into
/// the symmetric state. The bytes after it are zeroed, so the read fails only
/// once the point has been mixed in.
fn forged_session_ack(from: &TestNode) -> Vec<u8> {
    let mut payload = Identity::generate().pubkey_full().serialize().to_vec();
    payload.resize(crate::noise::HANDSHAKE_MSG2_SIZE, 0);
    assert_eq!(payload.len(), crate::noise::HANDSHAKE_MSG2_SIZE);
    let coords = from.node.tree_state().my_coords().clone();
    SessionAck::new(coords.clone(), coords)
        .with_handshake(payload)
        .encode()
}

#[tokio::test]
async fn test_forged_session_ack_leaves_the_initiation_able_to_complete_on_the_genuine_ack() {
    let mut nodes = make_routable_pair().await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Initiate but do not pump: node 0 sits in Initiating with its msg1 in
    // flight, which is the state the forgery targets.
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");
    let activity_before = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("initiating entry present")
        .last_activity();

    let forged = forged_session_ack(&nodes[1]);

    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;

    let entry = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("an unauthenticated ack must not destroy the initiation");
    assert!(
        entry.is_initiating(),
        "the entry must still be the initiation it was, not a broken one"
    );
    assert_eq!(
        entry.last_activity(),
        activity_before,
        "the reinsert must not push the handshake sweep's deadline out, or a \
         spray would keep a dead entry alive"
    );
    assert_eq!(
        nodes[0].node.stats().session.ack_handshake_failed,
        1,
        "the refusal must be counted; its DEBUG line is invisible at the \
         default log level"
    );

    // The genuine exchange now runs to completion over the same handshake.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .expect("initiator session present")
            .is_established(),
        "the initiation must still complete when the genuine ack arrives"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder session present")
            .is_established(),
        "and the responder must reach Established too"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Answer `msg1`, the Noise msg1 of a setup `node` has in flight, with a
/// cryptographically well-formed XX msg2 under `responder`'s static key, as
/// a SessionAck carrying `node`'s coordinates.
///
/// This is the shape the two exits below the msg2 read have to survive, and
/// the shape a bare garbage buffer cannot produce: nothing in XX binds msg2 to
/// the identity the initiator dialled, so any keypair at all answers a msg1
/// with a msg2 that reads cleanly. The msg1 is the one the setup carried, so
/// the ephemeral is the real one and the read genuinely succeeds.
///
/// `good_negotiation` chooses between the encrypted negotiation payload a real
/// responder appends and a same-length run of zeroes, which reaches the
/// decrypt failure with everything before it intact.
fn answer_in_flight_msg1(
    node: &Node,
    msg1: &[u8],
    responder: &Identity,
    good_negotiation: bool,
) -> Vec<u8> {
    use crate::proto::fmp::NegotiationPayload;

    let mut handshake = crate::noise::HandshakeState::new_responder(responder.keypair());
    handshake.set_local_epoch([0x77; 8]);
    handshake
        .read_message_1(msg1)
        .expect("the in-flight msg1 must read");
    let mut msg2 = handshake.write_message_2().expect("msg2 must build");

    let encrypted = handshake
        .encrypt_payload(&NegotiationPayload::new(0, 0, 0).encode())
        .expect("negotiation payload must encrypt");
    if good_negotiation {
        msg2.extend_from_slice(&encrypted);
    } else {
        msg2.resize(msg2.len() + encrypted.len(), 0);
    }

    let coords = node.tree_state().my_coords().clone();
    SessionAck::new(coords.clone(), coords)
        .with_handshake(msg2)
        .encode()
}

#[tokio::test]
async fn test_a_session_ack_whose_negotiation_payload_fails_leaves_the_initiation_alive() {
    let mut nodes = make_routable_pair().await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");
    let activity_before = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("initiating entry present")
        .last_activity();

    // Built under a stranger's key rather than node 1's, to pin the ordering:
    // if the negotiation payload were checked after the identity comparison
    // this would be counted as an identity mismatch instead.
    let stranger = Identity::generate();
    // node 1 answers the genuine setup; its ack waits in node 0's queue
    // while the forgery is delivered first.
    let setups = deliver_keeping_setups(&mut nodes, 1, &node0_addr).await;
    assert_eq!(setups.len(), 1, "node 0's SessionSetup must reach node 1");
    let forged = answer_in_flight_msg1(&nodes[0].node, &setup_msg1(&setups[0]), &stranger, false);

    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;

    let entry = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("a bad negotiation payload must not destroy the initiation");
    assert!(
        entry.is_initiating(),
        "the entry must still be the initiation it was, not a broken one"
    );
    assert_eq!(
        entry.last_activity(),
        activity_before,
        "the reinsert must not push the handshake sweep's deadline out"
    );
    assert_eq!(
        nodes[0].node.stats().session.ack_handshake_failed,
        1,
        "a failed negotiation payload is a failed ack, counted with the read"
    );
    assert_eq!(
        nodes[0].node.stats().session.ack_identity_mismatch,
        0,
        "and it must not be attributed to the identity check it never reached"
    );

    // The fork is the half that matters: the msg2 read succeeded here, so a
    // read on the attempt's own handshake would have left it holding the
    // stranger's material.
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .expect("initiator session present")
            .is_established(),
        "the initiation must still complete when the genuine ack arrives"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder session present")
            .is_established(),
        "and the responder must reach Established too"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_a_session_ack_under_the_wrong_static_key_leaves_the_initiation_alive() {
    let mut nodes = make_routable_pair().await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");
    let activity_before = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("initiating entry present")
        .last_activity();

    // Everything about this ack is valid except whose key it is under, which
    // is the whole attack: the source address it claims is an envelope field,
    // so a stranger answering our msg1 is indistinguishable from the peer we
    // dialled having a different key.
    let stranger = Identity::generate();
    // node 1 answers the genuine setup; its ack waits in node 0's queue
    // while the forgery is delivered first.
    let setups = deliver_keeping_setups(&mut nodes, 1, &node0_addr).await;
    assert_eq!(setups.len(), 1, "node 0's SessionSetup must reach node 1");
    let forged = answer_in_flight_msg1(&nodes[0].node, &setup_msg1(&setups[0]), &stranger, true);

    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;

    let entry = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("an ack under the wrong key must not destroy the initiation");
    assert!(
        entry.is_initiating(),
        "the entry must still be the initiation it was, not a broken one"
    );
    assert_eq!(
        entry.last_activity(),
        activity_before,
        "the reinsert must not push the handshake sweep's deadline out"
    );
    assert_eq!(
        nodes[0].node.stats().session.ack_identity_mismatch,
        1,
        "the mismatch was a silent return before; it must be counted, and \
         counted separately, since it means something a failed read does not"
    );
    assert_eq!(
        nodes[0].node.stats().session.ack_handshake_failed,
        0,
        "and it must not be summed into the failed-read counter, which would \
         hide both"
    );

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .expect("initiator session present")
            .is_established(),
        "the initiation must still complete when the genuine ack arrives"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder session present")
            .is_established(),
        "and the responder must reach Established too"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A garbage msg3 that reaches the responder of an initial handshake after
/// the initiator has sent its genuine msg3 must not cost the genuine one the
/// half-open entry it completes.
#[tokio::test]
async fn test_forged_initial_msg3_leaves_the_responder_able_to_complete_on_the_genuine_msg3() {
    let mut nodes = make_routable_pair().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..]).await;
    let activity_before = nodes[1]
        .node
        .get_session(&node0_addr)
        .filter(|e| e.is_awaiting_msg3())
        .expect("node 1 must be awaiting msg3 after answering the setup")
        .last_activity();
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[..1]).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.is_established()),
        "node 0 must be established once it has sent msg3"
    );

    // Hold node 0's genuine msg3 and deliver the forgery first.
    tokio::time::sleep(Duration::from_millis(20)).await;
    let held: Vec<_> = std::iter::from_fn(|| nodes[1].packet_rx.try_recv().ok()).collect();
    assert!(!held.is_empty(), "node 0's msg3 must be queued at node 1");
    let forged = SessionMsg3::new(vec![0u8; crate::noise::HANDSHAKE_MSG3_SIZE]).encode();
    nodes[1]
        .node
        .handle_session_payload(&node0_addr, &node0_addr, &forged, 1280, false)
        .await;
    let entry = nodes[1]
        .node
        .get_session(&node0_addr)
        .expect("an unauthenticated msg3 must not destroy the half-open entry");
    assert!(entry.is_awaiting_msg3());
    assert_eq!(
        entry.last_activity(),
        activity_before,
        "the reinsert must not push the handshake sweep's deadline out, or a \
         spray would keep a dead entry alive"
    );

    for packet in held {
        nodes[1].node.handle_encrypted_frame(packet).await;
    }
    pump_until_quiet(&mut nodes).await;
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.is_established()),
        "the genuine msg3 must still complete the session at node 1"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: a lost initial msg3
// ============================================================================

/// Build a two-node pair where node 0's initial msg3 was sent and dropped, so
/// node 0 is established and node 1 is still waiting for msg3.
///
/// The session is seconds old, far short of the rekey trigger, so no rekey
/// offers a second way to recover and the rekey drivers stay out of the
/// picture. Every step asserts its packet count, so a harness surprise fails loudly instead
/// of being read as the defect.
async fn pair_with_lost_initial_msg3() -> Vec<TestNode> {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_ESTABLISHED};

    let mut nodes = make_routable_pair().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");

    assert_eq!(
        process_available_packets(&mut nodes[1..]).await,
        1,
        "node 1 must have exactly node 0's SessionSetup queued"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder entry present")
            .is_awaiting_msg3(),
        "node 1 must be awaiting msg3 after answering the SessionSetup"
    );

    assert_eq!(
        process_available_packets(&mut nodes[..1]).await,
        1,
        "node 0 must have exactly node 1's SessionAck queued"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .expect("initiator entry present")
            .is_established(),
        "node 0 must be established once it has sent msg3"
    );

    // Drop msg3: take it out of node 1's queue instead of processing it.
    let dropped: Vec<_> = std::iter::from_fn(|| nodes[1].packet_rx.try_recv().ok()).collect();
    assert_eq!(
        dropped.len(),
        1,
        "node 1 must have only node 0's msg3 queued"
    );
    assert_eq!(
        CommonPrefix::parse(&dropped[0].data).map(|p| p.phase),
        Some(PHASE_ESTABLISHED),
        "the dropped packet must be a link data frame carrying the msg3"
    );

    pump_until_quiet(&mut nodes).await;
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder entry present")
            .is_awaiting_msg3(),
        "node 1 must still be awaiting msg3 after the drop"
    );
    assert_eq!(
        nodes[1].packet_rx.len(),
        0,
        "nothing may be left queued at node 1"
    );

    nodes
}

/// The initiator keeps its first msg3 and resends it on its ladder until a
/// frame from the responder authenticates: one lost msg3 costs one resend,
/// not the session, and the recovery does not depend on a rekey. Once the
/// responder completes, its prompt alone, with no application data, is that
/// frame, so the later rungs send nothing.
#[tokio::test]
async fn lost_first_handshake_msg3_is_resent_until_heard() {
    let mut nodes = pair_with_lost_initial_msg3().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let t0 = Node::session_now();

    let (tun0_tx, tun0_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun0_tx);
    let (tun1_tx, tun1_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun1_tx);
    let fips0 = crate::Ipv6Address::from_node_addr(&node0_addr);
    let fips1 = crate::Ipv6Address::from_node_addr(&node1_addr);

    // The ladder's first rung, 1 s after the install.
    nodes[0]
        .node
        .poll_session_rekeys(session_after(t0, 1_001))
        .await;
    assert_eq!(
        nodes[1].packet_rx.len(),
        1,
        "node 0 must resend its msg3 at the first rung"
    );
    pump_until_quiet(&mut nodes).await;
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder entry present")
            .is_established(),
        "node 1 must complete the session once node 0 resends its msg3"
    );

    // The later rungs: node 1's prompt has been heard, so nothing is resent.
    for at in [3_001, 7_001, 15_001, 31_001] {
        nodes[0]
            .node
            .poll_session_rekeys(session_after(t0, at))
            .await;
        assert_eq!(
            nodes[1].packet_rx.len(),
            0,
            "a msg3 the responder has answered must not be resent ({at} ms)"
        );
    }

    let fwd = build_ipv6_packet(&fips0, &fips1, b"after msg3 resend 0 to 1");
    let rev = build_ipv6_packet(&fips1, &fips0, b"after msg3 resend 1 to 0");
    nodes[0].node.handle_tun_outbound(fwd.clone()).await;
    nodes[1].node.handle_tun_outbound(rev.clone()).await;
    pump_until_quiet(&mut nodes).await;
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![fwd], "node 0 to node 1 must decode");
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![rev], "node 1 to node 0 must decode");

    cleanup_nodes(&mut nodes).await;
}

/// Drain and count the packets queued at `node` without processing them.
fn drain_queued(node: &mut TestNode) -> usize {
    std::iter::from_fn(|| node.packet_rx.try_recv().ok()).count()
}

/// The resend is harmless to a responder that already completed: when the
/// responder's prompt is lost, the initiator resends its msg3, the
/// responder refuses it as a bad-state reject, and both directions keep
/// decoding. This is the wire-neutrality claim, observed rather than argued.
#[tokio::test]
async fn a_resent_msg3_reaching_an_established_responder_is_refused_and_the_session_keeps_working()
{
    let mut nodes = make_routable_pair().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Setup, ack and msg3 delivered; node 1's prompt under the new keys lost.
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");
    assert_eq!(process_available_packets(&mut nodes[1..]).await, 1);
    assert_eq!(process_available_packets(&mut nodes[..1]).await, 1);
    assert_eq!(process_available_packets(&mut nodes[1..]).await, 1);
    assert!(
        drain_queued(&mut nodes[0]) > 0,
        "precondition: node 1 prompted node 0 under the new keys"
    );
    let t0 = Node::session_now();

    let (tun0_tx, tun0_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun0_tx);
    let (tun1_tx, tun1_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun1_tx);
    let fips0 = crate::Ipv6Address::from_node_addr(&node0_addr);
    let fips1 = crate::Ipv6Address::from_node_addr(&node1_addr);
    let before = nodes[1].node.stats().session.bad_state;

    nodes[0]
        .node
        .poll_session_rekeys(session_after(t0, 1_001))
        .await;
    assert_eq!(
        nodes[1].packet_rx.len(),
        1,
        "precondition: node 0 must have resent its msg3 to node 1"
    );
    pump_until_quiet(&mut nodes).await;

    assert_eq!(
        nodes[1].node.stats().session.bad_state,
        before + 1,
        "the duplicate msg3 must be refused as a bad-state reject"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder session present")
            .is_established(),
        "the duplicate msg3 must not disturb the responder's session"
    );

    let fwd = build_ipv6_packet(&fips0, &fips1, b"after duplicate msg3 0 to 1");
    let rev = build_ipv6_packet(&fips1, &fips0, b"after duplicate msg3 1 to 0");
    nodes[0].node.handle_tun_outbound(fwd.clone()).await;
    nodes[1].node.handle_tun_outbound(rev.clone()).await;
    pump_until_quiet(&mut nodes).await;
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![fwd], "node 0 to node 1 must decode");
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![rev], "node 1 to node 0 must decode");

    cleanup_nodes(&mut nodes).await;
}

/// A setup that reaches a node while its first msg3 waits for the peer is
/// never answered with that msg3: the smaller node refuses it, sending
/// nothing, and the larger holds it as a candidate and answers it with its
/// own ack. Either way the pair then converges on one session.
#[tokio::test]
async fn a_setup_while_the_first_msg3_is_unconfirmed_is_never_answered_with_that_msg3() {
    for smaller in [true, false] {
        let mut nodes = make_routable_pair().await;
        let (small, large) = by_address(&nodes);
        let (x, y) = if smaller {
            (small, large)
        } else {
            (large, small)
        };
        let x_addr = *nodes[x].node.node_addr();
        let y_addr = *nodes[y].node.node_addr();
        let x_pubkey = nodes[x].node.identity().pubkey_full();
        let y_pubkey = nodes[y].node.identity().pubkey_full();

        // X opens; its setup and Y's ack are delivered; X's msg3 is lost.
        nodes[x]
            .node
            .initiate_session(y_addr, y_pubkey)
            .await
            .expect("initiation must start");
        assert_eq!(process_available_packets(&mut nodes[y..=y]).await, 1);
        assert_eq!(process_available_packets(&mut nodes[x..=x]).await, 1);
        assert_eq!(
            drain_queued(&mut nodes[y]),
            1,
            "precondition: X's msg3 was sent"
        );

        // Y, still holding X's setup, opens its own attempt; its setup
        // reaches X, whose msg3 is unconfirmed.
        nodes[y]
            .node
            .initiate_session(x_addr, x_pubkey)
            .await
            .expect("initiation must start");
        let pending_before = nodes[x].node.stats().session.rekey_pending;
        assert_eq!(process_available_packets(&mut nodes[x..=x]).await, 1);

        if smaller {
            assert_eq!(
                nodes[y].packet_rx.len(),
                0,
                "the smaller node must answer the setup with nothing at all"
            );
            assert_eq!(
                nodes[x].node.stats().session.rekey_pending - pending_before,
                1,
                "the refusal must be counted"
            );
        } else {
            assert_eq!(
                nodes[x]
                    .node
                    .get_session(&y_addr)
                    .map(|e| e.candidate_count()),
                Some(1),
                "the larger node must hold the setup as a candidate"
            );
            assert_eq!(process_available_packets(&mut nodes[y..=y]).await, 1);
            assert!(
                nodes[y]
                    .node
                    .get_session(&x_addr)
                    .is_some_and(|e| e.is_established() && e.is_initiator()),
                "the larger node must answer with an ack that completes Y's own \
                 attempt, not with its retained msg3"
            );
        }

        drain_to_quiescence(&mut nodes).await;
        nodes[x]
            .node
            .poll_session_rekeys(session_after(Node::session_now(), 1_001))
            .await;
        drain_to_quiescence(&mut nodes).await;
        assert!(
            session_frame_decodes(&mut nodes, x, y).await
                && session_frame_decodes(&mut nodes, y, x).await,
            "the pair must converge on one session (X smaller: {smaller})"
        );
        cleanup_nodes(&mut nodes).await;
    }
}

/// The first msg3's ladder is bounded: with every copy lost, it is resent
/// at 1, 3, 7, 15 and 31 s after the install (`handshake_max_resends` at
/// its default of five) and never otherwise, and after its last copy the
/// session, whose peer has not been heard under it, starts a repair rekey
/// at once, while staying established.
#[tokio::test]
async fn first_msg3_resends_end_at_their_fifth_copy_and_start_a_repair() {
    let mut nodes = pair_with_lost_initial_msg3().await;
    let node1_addr = *nodes[1].node.node_addr();
    let t0 = Node::session_now();

    let mut sent = Vec::new();
    for secs in 1..=31u64 {
        nodes[0]
            .node
            .poll_session_rekeys(session_after(t0, secs * 1_000 + 1))
            .await;
        let n = drain_queued(&mut nodes[1]);
        if n > 0 {
            sent.push((secs, n));
        }
    }
    assert_eq!(
        sent,
        vec![(1, 1), (3, 1), (7, 1), (15, 1), (31, 2)],
        "one msg3 copy per rung, and at the last the repair's setup beside it"
    );

    let entry = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("the ladder's end must not tear the session down");
    assert!(
        entry.is_established() && entry.rekey_attempt(),
        "node 0 must stay established with the repair rekey in flight"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A lost initial msg3 must be kept and resent with its negotiation payload,
/// not as the bare handshake message.
///
/// A bare msg3 would still establish the responder: it treats the
/// negotiation payload as optional, and the transport keys come from the
/// chaining key alone. What a bare msg3 changes is the responder's
/// handshake hash, which the negotiation ciphertext is mixed into. So the
/// resent msg3 is pinned by length, and after it both ends must hold the
/// same handshake hash; the session completing cannot tell the two apart.
#[tokio::test]
async fn a_lost_initial_msg3_is_retained_and_resent_with_its_negotiation_payload() {
    use crate::proto::fsp::wire::{FSP_COMMON_PREFIX_SIZE, FSP_PHASE_MSG3};

    let mut nodes = pair_with_lost_initial_msg3().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let t0 = Node::session_now();

    // The retained msg3's first rung, 1 s after the install.
    nodes[0]
        .node
        .poll_session_rekeys(session_after(t0, 1_001))
        .await;
    let resent = deliver_keeping_phase(&mut nodes, 1, &node0_addr, FSP_PHASE_MSG3).await;
    assert_eq!(
        resent.len(),
        1,
        "node 0 must resend its msg3 at the first rung"
    );
    let msg3 = SessionMsg3::decode(&resent[0][FSP_COMMON_PREFIX_SIZE..])
        .expect("the resent SessionMsg3 must decode");
    // What the initiator appends: the encrypted negotiation payload, that is
    // its plaintext plus the AEAD tag.
    let negotiation_len = crate::proto::fmp::NegotiationPayload::new(0, 0, 0)
        .encode()
        .len()
        + crate::noise::TAG_SIZE;
    assert_eq!(
        msg3.handshake_payload.len(),
        crate::noise::HANDSHAKE_MSG3_SIZE + negotiation_len,
        "the resent msg3 must carry the encrypted negotiation payload"
    );
    pump_until_quiet(&mut nodes).await;

    let hash = |node: &TestNode, peer: &NodeAddr| {
        *node
            .node
            .get_session(peer)
            .and_then(|e| e.current_session())
            .expect("an established session")
            .handshake_hash()
    };
    assert_eq!(
        hash(&nodes[0], &node1_addr),
        hash(&nodes[1], &node0_addr),
        "the responder must have read the negotiation payload the initiator sent"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A SessionAck that fails to read must not end an FSP rekey the node
/// initiated.
///
/// Nothing authenticates a SessionAck before its msg2 is read: the only tie
/// to the rekey is the datagram's source address, which the sender chooses.
/// So the rekey-initiator arm has to put its handshake back, rolled back to
/// its pre-read state, and let the genuine ack complete the cycle, as the
/// primary arm does for an initiation.
#[tokio::test]
async fn test_forged_session_ack_leaves_the_rekey_able_to_complete_on_the_genuine_ack() {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_ESTABLISHED};
    use crate::transport::ReceivedPacket;

    // node 0 rekeys after one message; node 1 never initiates.
    let mut cfg0 = Config::new();
    cfg0.node.rekey.after_messages = 1;
    let mut cfg1 = Config::new();
    cfg1.node.rekey.after_messages = u64::MAX;
    cfg1.node.rekey.after_secs = u64::MAX;
    let mut nodes = run_tree_test_with_configs(vec![cfg0, cfg1], &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // One frame crosses node 0's rekey trigger.
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"before the rekey")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    // node 0 sends its rekey SessionSetup; only node 1 is pumped, so node 1
    // arms and its SessionAck waits in node 0's queue.
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.rekey_attempt()),
        "node 0 must have initiated a rekey"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..]).await;
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.candidate_count() > 0),
        "node 1 must have armed as the rekey responder"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    let held: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert!(
        !held.is_empty(),
        "node 1's SessionAck must be queued at node 0"
    );
    for packet in &held {
        assert_eq!(
            CommonPrefix::parse(&packet.data).map(|p| p.phase),
            Some(PHASE_ESTABLISHED),
            "every held packet must be a link frame"
        );
    }

    // The forgery arrives first, under node 1's address.
    let forged = forged_session_ack(&nodes[1]);
    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;
    let entry = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("an unreadable ack must not remove the session");
    assert!(
        entry.rekey_attempt(),
        "the rekey must still be in flight after an ack that did not read"
    );
    assert_eq!(
        nodes[0].node.stats().session.ack_handshake_failed,
        1,
        "the refusal must be counted"
    );

    // Release the genuine ack. This is the assertion that tells the outcomes
    // apart: an initiator that abandoned on the forgery meets the genuine ack
    // with no rekey in flight and completes nothing.
    for packet in held {
        nodes[0].node.handle_encrypted_frame(packet).await;
    }
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        cut_over(&nodes[1], &node0_addr),
        "node 1 must cut over to the new session at the genuine ack's msg3"
    );
    assert!(
        cut_over(&nodes[0], &node1_addr),
        "node 0 must complete the rekey on the genuine ack and cut over on \
         node 1's prompt under the new keys"
    );

    let recv1_before = nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .traffic_counters()
        .1;
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"after the rekey 0 to 1")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    let entry1 = nodes[1].node.get_session(&node0_addr).unwrap();
    assert_eq!(
        entry1.traffic_counters().1,
        recv1_before + 1,
        "node 0 to node 1 must decode on the new epoch"
    );
    assert!(
        entry1.pending_new_session().is_none(),
        "node 1 holds no pending session after its cutover"
    );

    let recv0_before = nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .traffic_counters()
        .1;
    nodes[1]
        .node
        .send_session_data(&node0_addr, 0, 0, b"after the rekey 1 to 0")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    assert_eq!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .traffic_counters()
            .1,
        recv0_before + 1,
        "node 1 to node 0 must decode on the new epoch"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: a rekey SessionAck under a key other than the peer's
// ============================================================================

/// Start node 0's own rekey of its session with node 1 through its machine,
/// and return the XX msg1 of the SessionSetup it sends, taken off node 1's
/// queue undelivered so the test decides what node 1 sees.
async fn arm_rekey(nodes: &mut [TestNode]) -> Vec<u8> {
    let node0_addr = *nodes[0].node.node_addr();
    start_rekey(nodes, 0).await;
    take_queued_setup_msg1(nodes, 1, &node0_addr).await
}

/// Encode the rekey SessionSetup `from` would send `to`, carrying `msg1`.
fn rekey_setup(from: &Node, to: &Node, msg1: &[u8]) -> Vec<u8> {
    crate::proto::fsp::SessionSetup::new(
        from.tree_state().my_coords().clone(),
        to.tree_state().my_coords().clone(),
    )
    .with_handshake(msg1.to_vec())
    .encode()
}

/// Answer `msg1` as a rekey responder holding `responder`'s static key, and
/// encode the msg2 as a SessionAck carrying `from`'s coordinates.
///
/// No negotiation payload is appended, as a node of this line answers a
/// rekey setup.
fn rekey_ack(msg1: &[u8], responder: &Identity, from: &Node) -> Vec<u8> {
    let mut handshake = crate::noise::HandshakeState::new_responder(responder.keypair());
    handshake.set_local_epoch([0x5a; 8]);
    handshake.read_message_1(msg1).expect("stranger reads msg1");
    let msg2 = handshake.write_message_2().expect("stranger writes msg2");
    let coords = from.tree_state().my_coords().clone();
    SessionAck::new(coords.clone(), coords)
        .with_handshake(msg2)
        .encode()
}

/// A SessionAck whose msg2 reads under a stranger's static key must be
/// refused before msg3 is written: nothing reaches the wire, nothing is
/// installed, the rekey stays in flight as ours, and the refusal is counted
/// as a rekey key mismatch.
///
/// Under XX a msg2 that reads proves only that its sender holds some key.
/// The ack's source address is an envelope field, so anyone who saw our
/// rekey msg1 can answer it under their own key.
#[tokio::test]
async fn test_a_rekey_ack_under_a_strangers_static_key_sends_no_msg3_installs_nothing_and_keeps_the_rekey()
 {
    let mut nodes = rekey_pair([true, false], None).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let msg1 = arm_rekey(&mut nodes).await;
    let stranger = Identity::generate();
    let forged = rekey_ack(&msg1, &stranger, &nodes[1].node);

    // Sibling control: node 0 originated its SessionSetup and msg3 through
    // this counter while establishing, so it is live on this node.
    let originated_before = nodes[0].node.metrics().forwarding.originated_packets.get();
    assert!(
        originated_before > 0,
        "the originated-packets counter must be live on node 0"
    );

    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;

    assert_eq!(
        nodes[0].node.stats().session.ack_handshake_failed,
        0,
        "the stranger's msg2 must read, or this test measures a failed read"
    );
    assert_eq!(
        nodes[0].node.metrics().forwarding.originated_packets.get(),
        originated_before,
        "no msg3 may reach a key the session was not opened with"
    );
    let entry = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("a refused ack must not remove the session");
    assert!(
        entry.pending_new_session().is_none(),
        "a session keyed with the stranger must not be installed"
    );
    assert!(
        entry.rekey_attempt(),
        "the rekey must still be in flight as ours"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_key_mismatch,
        1,
        "the refusal must be counted as a rekey key mismatch"
    );
    assert!(entry.is_established(), "the session must stay established");

    // The current session still carries data.
    let recv1_before = nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .traffic_counters()
        .1;
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"after the refused ack")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    assert_eq!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .traffic_counters()
            .1,
        recv1_before + 1,
        "the current session must still decode"
    );

    cleanup_nodes(&mut nodes).await;
}

/// An ack under a stranger's static key leaves the rekey's timers exactly
/// where its start set them: the machine's next wake does not move, so the
/// ack cannot push out the rekey's resends or its deadline.
#[tokio::test]
async fn a_rekey_ack_under_a_strangers_key_does_not_push_out_the_rekey_deadline() {
    let mut nodes = rekey_pair([true, false], None).await;
    let node1_addr = *nodes[1].node.node_addr();

    let msg1 = arm_rekey(&mut nodes).await;
    let wake = nodes[0].node.get_session(&node1_addr).unwrap().next_wake();
    assert_ne!(wake, None, "the rekey must have a deadline");

    crate::time::advance(Duration::from_millis(500));
    let forged = rekey_ack(&msg1, &Identity::generate(), &nodes[1].node);
    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;
    assert_eq!(
        nodes[0].node.stats().session.rekey_key_mismatch,
        1,
        "the stranger's ack must be refused as a key mismatch"
    );
    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "the refused ack must leave the rekey in flight"
    );
    assert_eq!(
        nodes[0].node.get_session(&node1_addr).unwrap().next_wake(),
        wake,
        "the refused ack must not move the rekey's timers"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A SessionAck under a stranger's static key arriving midway through an
/// unanswered rekey does not restart its deadline: the rekey ends 30 s after
/// it started, counted once.
#[tokio::test]
async fn stranger_keyed_rekey_acks_do_not_hold_an_unanswered_rekey_open_past_its_deadline() {
    let mut nodes = rekey_pair([true, false], None).await;
    let node1_addr = *nodes[1].node.node_addr();

    let msg1 = arm_rekey(&mut nodes).await;

    crate::time::advance(Duration::from_secs(15));
    let forged = rekey_ack(&msg1, &Identity::generate(), &nodes[1].node);
    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;
    assert_eq!(
        nodes[0].node.stats().session.rekey_key_mismatch,
        1,
        "the stranger's ack must be refused as a key mismatch"
    );
    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "the refused ack must leave the rekey in flight"
    );

    crate::time::advance(Duration::from_secs(15));
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    assert!(
        !rekey_initiated(&nodes[0], &node1_addr),
        "an ack under a stranger's key must not restart the deadline of the \
         rekey this node initiated"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_unanswered,
        1,
        "the given-up rekey must be counted once"
    );

    cleanup_nodes(&mut nodes).await;
}

/// After refusing a SessionAck under a stranger's static key, the initiator
/// must still complete the rekey on the peer's genuine ack and cut over to a
/// working session.
///
/// This is what proves the ack was read on a fork of the handshake: read on
/// the handshake itself, it would hold the stranger's material and could not
/// read the genuine msg2.
#[tokio::test]
async fn test_a_rekey_ack_under_a_strangers_static_key_leaves_the_rekey_able_to_complete_on_the_genuine_ack()
 {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_ESTABLISHED};
    use crate::transport::ReceivedPacket;

    let mut nodes = rekey_pair([true, false], None).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let msg1 = arm_rekey(&mut nodes).await;

    // node 1 answers the genuine msg1; its SessionAck waits in node 0's queue.
    let setup = rekey_setup(&nodes[0].node, &nodes[1].node, &msg1);
    nodes[1]
        .node
        .handle_session_payload(&node0_addr, &node0_addr, &setup, 1280, false)
        .await;
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.candidate_count() == 1),
        "node 1 must hold node 0's setup as a rekey candidate"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    let held: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert!(
        !held.is_empty(),
        "node 1's SessionAck must be queued at node 0"
    );
    for packet in &held {
        assert_eq!(
            CommonPrefix::parse(&packet.data).map(|p| p.phase),
            Some(PHASE_ESTABLISHED),
            "every held packet must be a link frame"
        );
    }

    // The stranger's ack arrives first, under node 1's address.
    let stranger = Identity::generate();
    let forged = rekey_ack(&msg1, &stranger, &nodes[1].node);
    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;
    let entry = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("a refused ack must not remove the session");
    assert!(
        entry.rekey_attempt(),
        "the rekey must still be in flight after an ack under a stranger's key"
    );
    assert!(
        entry.pending_new_session().is_none(),
        "a session keyed with the stranger must not be installed"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_key_mismatch,
        1,
        "the refusal must be counted"
    );
    let tag0 = entry.current_tag();

    // Release the genuine ack: node 0 completes, its msg3 completes node 1,
    // and node 1's prompt under the new keys moves node 0 onto them.
    for packet in held {
        nodes[0].node.handle_encrypted_frame(packet).await;
    }
    pump_until_quiet(&mut nodes).await;
    assert_eq!(
        nodes[0].node.stats().session.ack_handshake_failed,
        0,
        "the genuine msg2 must read against the untouched handshake"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_key_mismatch,
        1,
        "the genuine ack must not be counted as a mismatch"
    );
    assert!(
        cut_over(&nodes[0], &node1_addr) && cut_over(&nodes[1], &node0_addr),
        "both nodes must complete the rekey and cut over"
    );
    assert_ne!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .current_tag(),
        tag0,
        "node 0 must be on the new keys"
    );

    // Data decodes both ways on the new epoch.
    for (from, to) in [(0, 1), (1, 0)] {
        let to_addr = *nodes[to].node.node_addr();
        let from_addr = *nodes[from].node.node_addr();
        let recv_before = nodes[to]
            .node
            .get_session(&from_addr)
            .unwrap()
            .traffic_counters()
            .1;
        nodes[from]
            .node
            .send_session_data(&to_addr, 0, 0, b"after the rekey")
            .await
            .expect("send_session_data failed");
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
        assert_eq!(
            nodes[to]
                .node
                .get_session(&from_addr)
                .unwrap()
                .traffic_counters()
                .1,
            recv_before + 1,
            "node {from} to node {to} must decode on the new epoch"
        );
    }

    cleanup_nodes(&mut nodes).await;
}

/// A rekey with a peer whose key has odd parity, dialled by the even-parity
/// key an npub gives, must complete on the peer's genuine ack.
///
/// The stored key and the key msg2 proves differ as full keys and agree as
/// x-only keys, so this is the pair that tells an x-only comparison from a
/// full-key one.
#[tokio::test]
async fn test_a_rekey_ack_from_an_odd_parity_peer_dialled_by_its_even_parity_key_completes_the_rekey()
 {
    // node 0 rekeys after one message; node 1 never starts one.
    let mut cfg0 = Config::new();
    cfg0.node.rekey.after_messages = 1;
    let mut cfg1 = Config::new();
    cfg1.node.rekey.after_messages = u64::MAX;
    cfg1.node.rekey.after_secs = u64::MAX;
    let mut nodes = pinned_tree(
        vec![
            (cfg0, Identity::generate()),
            (cfg1, generate_odd_parity_identity()),
        ],
        &[(0, 1)],
    )
    .await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let stored =
        crate::identity::PeerIdentity::from_pubkey(nodes[1].node.identity().pubkey()).pubkey_full();
    assert_ne!(
        stored,
        nodes[1].node.identity().pubkey_full(),
        "test fixture must actually differ in parity"
    );
    establish_under(&mut nodes, stored, SESSION_SETUP_BOUND).await;
    assert_eq!(
        nodes[0].node.get_session(&node1_addr).unwrap().peer_key(),
        Some(stored.x_only_public_key().0),
        "node 0 must hold the dialled key as the session's peer key"
    );
    // Past the dampening node 1's completion of the first handshake opened.
    crate::time::advance(Duration::from_secs(31));

    let msg1 = arm_rekey(&mut nodes).await;
    let setup = rekey_setup(&nodes[0].node, &nodes[1].node, &msg1);
    nodes[1]
        .node
        .handle_session_payload(&node0_addr, &node0_addr, &setup, 1280, false)
        .await;
    pump_until_quiet(&mut nodes).await;

    assert!(
        holds_new_keys(&nodes[0], &node1_addr),
        "node 0 must complete the rekey with an odd-parity peer"
    );
    assert!(
        holds_new_keys(&nodes[1], &node0_addr),
        "node 1 must hold the new session after msg3"
    );
    assert_eq!(nodes[0].node.stats().session.rekey_key_mismatch, 0);
    assert_eq!(nodes[0].node.stats().session.ack_handshake_failed, 0);

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: a destination with no cached coordinates
// ============================================================================

/// Build a two-node routable mesh with an established FSP session from node 0
/// to node 1, with node 0's coordinate warmup budget set to `warmup`.
///
/// node 1's budget is 0, so none of its frames carry coordinates: each one
/// that did would re-warm node 0's entry for node 1, and these tests need
/// that entry to stay gone once they remove it.
async fn make_warmup_pair(warmup: u8) -> Vec<TestNode> {
    let configs = (0..2)
        .map(|i| {
            let mut config = Config::new();
            config.node.session.coords_warmup_packets = if i == 0 { warmup } else { 0 };
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;
    pump_until_quiet(&mut nodes).await;
    nodes
}

/// The address path `node` has cached for `addr`, if any.
///
/// Compared by address because coordinates carried in a session frame arrive
/// without the declaration metadata a node's own copy holds.
fn cached_path(node: &TestNode, addr: &NodeAddr) -> Option<Vec<NodeAddr>> {
    node.node
        .coord_cache()
        .get(addr, wall_clock_ms())
        .map(addr_path)
}

/// The address path of a coordinate, self to root.
fn addr_path(coords: &crate::proto::stp::TreeCoordinate) -> Vec<NodeAddr> {
    coords.node_addrs().copied().collect()
}

/// Deliver a PathBroken naming `dest` to `nodes[at]`, reported by `reporter`.
/// The reporter must not be `dest`, or the signal is refused as forged before
/// it removes anything.
///
/// Nothing is pumped afterwards: the handler starts a lookup, and in a small
/// mesh its answer would refill the entry the signal removed before the test
/// could send into the miss.
async fn deliver_path_broken(
    nodes: &mut [TestNode],
    at: usize,
    dest: NodeAddr,
    reporter: NodeAddr,
) {
    use crate::proto::routing::PathBroken;
    let encoded = PathBroken::new(dest, reporter).encode();
    nodes[at]
        .node
        .handle_path_broken(&reporter, &reporter, &encoded[5..])
        .await;
}

/// A data frame to a destination whose coordinates this node does not have
/// cached must not carry this node's own coordinates in their place.
///
/// The shape reached in practice: a direct peer whose cache entry is gone,
/// here removed by a PathBroken from a third address. The destination warms
/// its cache from every coordinate-bearing frame, so a frame carrying the
/// sender's coordinates as the destination's leaves the destination holding
/// its own address under the sender's coordinates. Once the coordinates are
/// known again, the warmup budget the miss did not spend is spent on frames
/// that carry them.
#[tokio::test]
async fn test_a_data_frame_to_a_destination_with_no_cached_coordinates_carries_none_and_keeps_the_warmup()
 {
    let mut nodes = make_warmup_pair(1).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node0_coords = nodes[0].node.tree_state().my_coords().clone();
    let node1_coords = nodes[1].node.tree_state().my_coords().clone();

    // A transit router reports the path to node 1 broken. It is a third
    // address: a report "from" node 1 about node 1 is refused as forged.
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    deliver_path_broken(&mut nodes, 0, node1_addr, reporter).await;
    assert!(
        nodes[0]
            .node
            .coord_cache()
            .get(&node1_addr, wall_clock_ms())
            .is_none(),
        "precondition: the PathBroken must have removed node 0's entry for node 1"
    );
    let warmup = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .coords_warmup_remaining()
    };
    assert_eq!(warmup(&nodes), 1, "PathBroken resets the warmup budget");

    let mismatch_before = nodes[1]
        .node
        .metrics()
        .forwarding
        .coord_warm_key_mismatch
        .get();
    let recv_before = nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .traffic_counters()
        .1;
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"after the cache miss")
        .await
        .expect("send_session_data failed");
    // node 1 takes the frame, and node 0 then drops everything node 1 sent
    // back. That includes the answer to the lookup the PathBroken started,
    // which would both refill the cache and reset the warmup budget, and so
    // hide whether the miss spent it.
    process_available_packets(&mut nodes[1..]).await;
    while nodes[0].packet_rx.try_recv().is_ok() {}

    assert_eq!(
        nodes[1]
            .node
            .metrics()
            .forwarding
            .coord_warm_key_mismatch
            .get(),
        mismatch_before,
        "node 1 must not be sent node 0's coordinates as its own"
    );
    assert_ne!(
        cached_path(&nodes[1], &node1_addr),
        Some(addr_path(&node0_coords)),
        "node 1 must not hold its own address under node 0's coordinates"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .traffic_counters()
            .1,
        recv_before + 1,
        "the frame must still be delivered"
    );
    assert_eq!(
        warmup(&nodes),
        1,
        "a frame sent without coordinates must not spend the warmup budget"
    );

    // Node 0's cache is refilled without a discovery answer, so the only
    // budget left to spend is the one the miss preserved. node 1's entry for
    // node 0 is removed first, so the only way node 1 can learn node 0's
    // coordinates again is from a frame that carries them.
    let now_ms = wall_clock_ms();
    let _ = nodes[0].node.insert_coord_hint(
        node1_addr,
        node1_coords,
        now_ms,
        crate::cache::Funding::Uncharged,
    );
    nodes[1].node.coord_cache.remove(&node0_addr);
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"after the refill")
        .await
        .expect("send_session_data failed");
    pump_until_quiet(&mut nodes).await;

    assert_eq!(
        cached_path(&nodes[1], &node0_addr),
        Some(addr_path(&node0_coords)),
        "the first frame after the refill must carry node 0's coordinates"
    );
    assert_eq!(
        warmup(&nodes),
        0,
        "and it spends the warmup budget the miss preserved"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A standalone CoordsWarmup to a destination with no cached coordinates
/// sends nothing: its only content would be this node's coordinates standing
/// in for the destination's.
#[tokio::test]
async fn test_a_coords_warmup_to_a_destination_with_no_cached_coordinates_sends_nothing() {
    let mut nodes = make_warmup_pair(5).await;
    let node1_addr = *nodes[1].node.node_addr();

    nodes[0].node.coord_cache.remove(&node1_addr);
    let warmup_before = nodes[0]
        .node
        .get_session(&node1_addr)
        .unwrap()
        .coords_warmup_remaining();
    assert_eq!(
        nodes[1].packet_rx.len(),
        0,
        "precondition: node 1's queue is empty"
    );

    nodes[0]
        .node
        .send_coords_warmup(&node1_addr)
        .await
        .expect("a skipped warmup is not an error");

    assert_eq!(
        nodes[1].packet_rx.len(),
        0,
        "no CoordsWarmup may be sent without the destination's coordinates"
    );
    assert_eq!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .coords_warmup_remaining(),
        warmup_before,
        "the warmup budget must not move"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A rekey SessionSetup to a direct peer whose cache entry is gone carries
/// the peer's own announced coordinates, not this node's.
#[tokio::test]
async fn test_a_rekey_setup_to_a_peer_with_no_cached_coordinates_carries_the_peers_announced_ones()
{
    // node 0 rekeys after one message; node 1 never initiates.
    let mut cfg0 = Config::new();
    cfg0.node.rekey.after_messages = 1;
    let mut cfg1 = Config::new();
    cfg1.node.rekey.after_messages = u64::MAX;
    cfg1.node.rekey.after_secs = u64::MAX;
    let mut nodes = run_tree_test_with_configs(vec![cfg0, cfg1], &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_coords = nodes[1].node.tree_state().my_coords().clone();
    assert_eq!(
        nodes[0].node.tree_state().peer_coords(&node1_addr),
        Some(&node1_coords),
        "precondition: node 0 knows node 1's announced coordinates"
    );

    // One frame crosses node 0's rekey trigger, sent while the cache still
    // holds node 1, so only the rekey setup can meet the miss.
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"before the rekey")
        .await
        .expect("send_session_data failed");
    pump_until_quiet(&mut nodes).await;

    // node 1's entry for its own address goes too, so what it holds after
    // the rekey can only have come from the setup.
    nodes[0].node.coord_cache.remove(&node1_addr);
    nodes[1].node.coord_cache.remove(&node1_addr);
    let mismatch_before = nodes[1]
        .node
        .metrics()
        .forwarding
        .coord_warm_key_mismatch
        .get();

    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    assert_eq!(
        nodes[1]
            .node
            .metrics()
            .forwarding
            .coord_warm_key_mismatch
            .get(),
        mismatch_before,
        "the rekey setup must not name node 0's coordinates as node 1's"
    );
    assert_eq!(
        cached_path(&nodes[1], &node1_addr),
        Some(addr_path(&node1_coords)),
        "the setup's destination coordinates must be node 1's own"
    );
    assert!(
        holds_new_keys(&nodes[0], &node1_addr),
        "the rekey must complete at node 0"
    );
    assert!(holds_new_keys(&nodes[1], &node0_addr), "and at node 1");

    cleanup_nodes(&mut nodes).await;
}

/// A transit router must not end up holding the destination under the
/// source's coordinates after the source's cache entry for it is gone.
///
/// Not a red-first test: a source routes to a destination that is not a
/// direct peer only through its coordinate cache, so on a miss there is no
/// next hop and no frame reaches the transit router at all. This constructs
/// that rather than leaving it to a reading of the routing code.
#[tokio::test]
async fn test_a_transit_router_does_not_learn_the_source_coordinates_as_the_destinations() {
    // Only A sends coordinates, so nothing but a frame from A can re-warm
    // A's entry for B once it is removed.
    let configs = (0..3)
        .map(|i| {
            let mut config = Config::new();
            if i != 0 {
                config.node.session.coords_warmup_packets = 0;
            }
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1), (1, 2)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let a_addr = *nodes[0].node.node_addr();
    let t_addr = *nodes[1].node.node_addr();
    let b_addr = *nodes[2].node.node_addr();
    let a_coords = nodes[0].node.tree_state().my_coords().clone();
    let b_pubkey = nodes[2].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(b_addr, b_pubkey)
        .await
        .expect("initiate_session failed");
    pump_until_quiet(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&b_addr)
            .is_some_and(|e| e.is_established()),
        "precondition: A and B must hold an established session"
    );
    assert!(
        nodes[2]
            .node
            .get_session(&a_addr)
            .is_some_and(|e| e.is_established()),
        "precondition: B must hold the session too"
    );

    // T reports the path to B broken, and A's entry for B goes.
    deliver_path_broken(&mut nodes, 0, b_addr, t_addr).await;
    assert!(
        nodes[0]
            .node
            .coord_cache()
            .get(&b_addr, wall_clock_ms())
            .is_none(),
        "precondition: A's entry for B must be gone"
    );

    let mismatch_before = nodes[1]
        .node
        .metrics()
        .forwarding
        .coord_warm_key_mismatch
        .get();
    let sent = nodes[0]
        .node
        .send_session_data(&b_addr, 0, 0, b"after the cache miss")
        .await;
    pump_until_quiet(&mut nodes).await;

    assert_ne!(
        cached_path(&nodes[1], &b_addr),
        Some(addr_path(&a_coords)),
        "T must not hold B under A's coordinates"
    );
    assert_eq!(
        nodes[1]
            .node
            .metrics()
            .forwarding
            .coord_warm_key_mismatch
            .get(),
        mismatch_before,
        "T must not be sent a coordinate filed under the wrong address"
    );
    assert!(
        sent.is_err(),
        "with no coordinates cached for B, A has no route to it, which is why \
         no transit router can see the frame"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Tick-loop maintenance of an established session
// ============================================================================

/// Build a node holding one established session with `peer`, returning the
/// node and the peer's address.
fn make_node_with_established_peer(peer: &Identity) -> (Node, crate::NodeAddr) {
    let mut node = make_node_with(Config::new());
    let peer_addr = install_established_peer(&mut node, peer);
    (node, peer_addr)
}

/// Install one established session with `peer` on an existing node.
///
/// Split out of `make_node_with_established_peer` for the tests that must
/// choose the peer identity relative to the node's own address, which needs
/// the node to exist first.
fn install_established_peer(node: &mut Node, peer: &Identity) -> crate::NodeAddr {
    let peer_addr = *peer.node_addr();

    let session = make_noise_session(node.identity(), peer);
    let entry = crate::node::session::SessionEntry::keyed_as(
        peer_addr,
        session,
        node.session_params(),
        &node.session_node_keys(),
        *node.node_addr(),
        session_at(1000),
        true,
    );
    node.sessions.insert(peer_addr, entry);
    peer_addr
}

/// Generate an identity whose address sorts strictly above `node_addr`.
///
/// The dual-initiation tie-break compares the two addresses directly, so a
/// test that wants a specific side of it has to pick the peer to match.
/// Roughly two draws on average, as with `generate_odd_parity_identity`.
fn peer_identity_sorting_above(node_addr: &crate::NodeAddr) -> Identity {
    loop {
        let id = Identity::generate();
        if id.node_addr() > node_addr {
            return id;
        }
    }
}

/// Wall-clock milliseconds, matching the clock the tick loop reads.
fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[tokio::test]
async fn test_superseded_key_epoch_is_drained_by_the_tick_loop() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

    // The peer's rekey completes here: its msg3 cuts this node over, and
    // the old keys drain.
    let msg3 = hold_rekey_setup(&mut node, &peer_addr, &peer);
    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(msg3).encode(),
        1280,
        false,
    )
    .await;
    assert!(node.sessions.get(&peer_addr).unwrap().is_draining());

    // Nothing shows the peer moved, so the drain runs to its ceiling; the
    // session clock is moved well past it.
    crate::time::advance(std::time::Duration::from_secs(3_600));
    node.poll_session_rekeys(Node::session_now()).await;

    assert!(
        !node.sessions.get(&peer_addr).unwrap().is_draining(),
        "a drain window that expired long ago must be completed"
    );
}

/// A rekey setup answered for the peer whose msg3 never comes is dropped at
/// the end of its candidate lifetime, 40 s after it arrived, leaving the
/// session as it was, and the expiry is counted.
#[tokio::test]
async fn test_an_answered_rekey_setup_with_no_msg3_expires_at_its_candidate_lifetime_and_is_counted()
 {
    let peer = Identity::generate();
    let attacker = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

    let _msg3 = hold_rekey_setup(&mut node, &peer_addr, &attacker);
    crate::time::advance(Duration::from_secs(39));
    node.poll_session_rekeys(Node::session_now()).await;
    assert_eq!(
        node.sessions.get(&peer_addr).unwrap().candidate_count(),
        1,
        "a candidate inside its lifetime is kept for its msg3"
    );

    crate::time::advance(Duration::from_secs(2));
    node.poll_session_rekeys(Node::session_now()).await;
    let entry = node.sessions.get(&peer_addr).unwrap();
    assert_eq!(
        entry.candidate_count(),
        0,
        "a setup answered for a peer that never sent msg3 must not persist \
         for the life of the session"
    );
    assert!(
        entry.is_established() && !entry.is_draining(),
        "expiring the candidate must leave the session intact"
    );
    assert_eq!(
        node.stats().session.rekey_expired,
        1,
        "the expired candidate must be counted"
    );
    assert_eq!(node.stats().session.pending_replaced, 0);
}

/// Forge a SessionSetup addressed to `node` from an unrelated identity,
/// as an off-path sender naming an established peer would send it.
fn forge_setup_for(node: &Node) -> Vec<u8> {
    use crate::noise::HandshakeState;
    use crate::proto::fsp::SessionSetup;

    let stranger = Identity::generate();
    let mut handshake = HandshakeState::new_initiator(stranger.keypair());
    handshake.set_local_epoch([0x5A; 8]);
    let msg1 = handshake
        .write_message_1()
        .expect("stranger msg1 must build");

    let coords = node.tree_state().my_coords().clone();
    SessionSetup::new(coords.clone(), coords)
        .with_handshake(msg1)
        .encode()
}

/// Complete a rekey of `node`'s own toward `peer` through the session
/// entry's machine: its trigger starts the rekey once the session is past
/// the time trigger at any jitter, and the peer's ack completes it, so the
/// new keys wait for the peer to be heard under them. The machine's sends
/// (the setup, the msg3 and the probes) are not delivered; `node` has no
/// route to the peer.
fn complete_own_rekey(node: &mut Node, peer_addr: &crate::NodeAddr, peer: &Identity) {
    use crate::noise::HandshakeState;
    use fips_core::proto::rekey::{MsgKind, Output};

    crate::time::advance(Duration::from_secs(140));
    let local = node.session_node_keys();
    let route = node.tree_state().my_coords().clone();
    let entry = node.sessions.get_mut(peer_addr).unwrap();
    let setup = entry
        .poll_rekey(Node::session_now(), true, &local)
        .into_iter()
        .find_map(|o| match o {
            Output::Send {
                msg,
                kind: MsgKind::Setup,
                ..
            } => Some(msg),
            _ => None,
        })
        .expect("the trigger starts a rekey");
    let mut responder = HandshakeState::new_responder(peer.keypair());
    responder.set_local_epoch(crate::node::session::TEST_PEER_EPOCH);
    responder.read_message_1(&setup).expect("the setup reads");
    let ack = responder.write_message_2().expect("the ack builds");
    let _ = entry.step_reply(&ack, route, Node::session_now(), &local);
    assert!(
        entry.pending_new_session().is_some(),
        "the ack completes the rekey into keys waiting for the peer"
    );
}

/// At the smaller address, a setup that arrives while this node's own
/// completed rekey waits for the peer is refused, not answered, and the
/// refusal is counted: a deployed peer commits on an ack.
#[tokio::test]
async fn test_setup_naming_peer_with_pending_session_is_dropped_and_counted() {
    let mut node = make_node_with(Config::new());
    let peer = peer_identity_sorting_above(node.node_addr());
    let peer_addr = install_established_peer(&mut node, &peer);

    // A rekey this node initiated completed and waits to hear the peer
    // under its new keys.
    complete_own_rekey(&mut node, &peer_addr, &peer);

    let forged = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).unwrap();
    assert_eq!(
        entry.candidate_count(),
        0,
        "a setup must not be answered while this node's completed rekey \
         waits for its cutover"
    );
    assert!(
        entry.pending_new_session().is_some(),
        "the pending session must survive the refused setup"
    );
    assert_eq!(
        node.stats().session.rekey_pending,
        1,
        "the refused setup must be counted, since its DEBUG line is \
         invisible at the default log level"
    );
    assert_eq!(
        node.stats().session.rekey_armed,
        0,
        "nothing was answered, so the answer counter must not move"
    );
}

/// At the larger address, a setup that arrives while this node's own
/// completed rekey waits for the peer never discards that rekey's keys: they
/// may be the keys the peer has already moved to. The setup is held as a
/// candidate beside them, and only an authenticated msg3 could complete it,
/// so no tie-break is lost and nothing is yielded.
#[tokio::test]
async fn test_setup_never_discards_a_pending_session_when_our_address_loses_the_tiebreak() {
    let mut node = make_node_with(Config::new());
    let peer = loop {
        let id = Identity::generate();
        if id.node_addr() < node.node_addr() {
            break id;
        }
    };
    let peer_addr = install_established_peer(&mut node, &peer);
    complete_own_rekey(&mut node, &peer_addr, &peer);

    let forged = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).unwrap();
    assert!(
        entry.pending_new_session().is_some(),
        "losing the address tie-break must not let an unauthenticated setup \
         discard the keys the peer may already have cut over to"
    );
    assert_eq!(
        entry.candidate_count(),
        1,
        "the larger node holds the setup as a candidate beside its keys"
    );
    assert_eq!(
        node.stats().session.rekey_yielded,
        0,
        "no completed rekey yields to a setup"
    );
}

/// At the smaller address, a setup that arrives after this node's completed
/// rekey has passed its confirmation deadline, before the tick has polled
/// the machine, is judged after that deadline: the rekey is assumed, and the
/// setup is answered as it would be at any later instant. A deployed peer
/// whose re-armed handshake dropped this node's msg3 starts its own rekey at
/// about that deadline and sends its setup once, so refusing it there would
/// leave this node's frames lost until its silence rule repairs the session.
#[tokio::test]
async fn test_setup_after_the_confirmation_deadline_is_answered_before_the_tick_polls() {
    let mut node = make_node_with(Config::new());
    let peer = peer_identity_sorting_above(node.node_addr());
    let peer_addr = install_established_peer(&mut node, &peer);
    complete_own_rekey(&mut node, &peer_addr, &peer);

    // Past the 31 s confirmation window, with no poll since the rekey
    // completed.
    crate::time::advance(Duration::from_secs(32));
    let setup = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &setup, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).unwrap();
    assert!(
        entry.pending_new_session().is_none() && entry.is_draining(),
        "the confirmation deadline must be processed before the setup: the \
         rekey is assumed and the old keys drain"
    );
    assert_eq!(
        entry.candidate_count(),
        1,
        "a setup arriving after the confirmation deadline must be answered"
    );
    assert_eq!(
        (
            node.stats().session.rekey_pending,
            node.stats().session.rekey_armed
        ),
        (0, 1),
        "the setup must be counted as answered, not refused"
    );
}

/// A setup naming a session whose deadline has passed, unpolled, is admitted
/// against the table as the poll before it leaves it. Here the poll ends the
/// session (its first attempt unanswered at the handshake timeout), so the
/// setup would open a new half-open entry, and the half-open share, which a
/// forged session already fills, must refuse it as it refuses any other
/// setup opening an entry.
#[tokio::test]
async fn test_setup_naming_a_session_its_overdue_poll_ends_is_admitted_against_the_table_after_the_poll()
 {
    let mut config = Config::new();
    // A half-open share of one.
    config.node.limits.max_sessions = 2;
    let mut node = make_node_with(config);

    let target = Identity::generate();
    let target_addr = *target.node_addr();
    let opened = crate::node::session::SessionEntry::opened_for_test(
        &target.pubkey_full(),
        node.identity().keypair(),
        Node::session_now(),
    );
    node.sessions.insert(target_addr, opened);
    let timeout_secs = node.config().node.rate_limit.handshake_timeout_secs;
    crate::time::advance(Duration::from_secs(timeout_secs + 1));

    // A young forged session fills the half-open share.
    let forger = *Identity::generate().node_addr();
    let forged = crate::node::session::SessionEntry::answering_for_test(
        forger,
        node.identity().keypair(),
        Node::session_now(),
    );
    node.sessions.insert(forger, forged);
    let refused_before = node.stats().session.half_open_full;

    let setup = forge_setup_for(&node);
    node.handle_session_payload(&target_addr, &stub_link_peer(), &setup, 1280, false)
        .await;

    assert!(
        !node.sessions.contains_key(&target_addr),
        "a setup reopening a session its poll ended must not bypass the half-open share"
    );
    assert_eq!(
        node.stats().session.half_open_full - refused_before,
        1,
        "the refusal must be counted"
    );
}

// ============================================================================
// Integration tests: a rekey this node initiated that is never answered
// ============================================================================

/// Build an established two-node pair, with the handshake timeout set to
/// `timeout_secs` on both nodes when given and left at its default otherwise.
///
/// `rekeys[i]` says whether node `i` rekeys after a single sent message;
/// otherwise it never starts a rekey of its own. The session is opened from
/// node 0, which says nothing about which node later initiates a rekey.
async fn rekey_pair(rekeys: [bool; 2], timeout_secs: Option<u64>) -> Vec<TestNode> {
    let configs = rekeys
        .iter()
        .map(|&rekeys| {
            let mut config = Config::new();
            if let Some(secs) = timeout_secs {
                config.node.rate_limit.handshake_timeout_secs = secs;
            }
            if rekeys {
                config.node.rekey.after_messages = 1;
            } else {
                config.node.rekey.after_messages = u64::MAX;
                config.node.rekey.after_secs = u64::MAX;
            }
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;
    // Past the 30 s dampening node 1's completion of the first handshake
    // opened, so either end can start the next rekey.
    crate::time::advance(Duration::from_secs(31));
    nodes
}

/// Send one data frame from `nodes[from]` across its rekey trigger, deliver
/// it, then poll `nodes[from]`'s session rekey machines so its trigger sends
/// a rekey SessionSetup, and assert it now holds an initiated rekey.
async fn start_rekey(nodes: &mut [TestNode], from: usize) {
    let peer = *nodes[1 - from].node.node_addr();
    nodes[from]
        .node
        .send_session_data(&peer, 0, 0, b"crosses the rekey trigger")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(nodes).await;

    nodes[from]
        .node
        .poll_session_rekeys(Node::session_now())
        .await;
    assert!(
        rekey_initiated(&nodes[from], &peer),
        "node {from} must have initiated a rekey"
    );
}

/// Whether `node` holds a rekey handshake toward `peer` that it initiated.
fn rekey_initiated(node: &TestNode, peer: &NodeAddr) -> bool {
    node.node
        .get_session(peer)
        .is_some_and(|e| e.rekey_attempt())
}

/// Whether `node`'s session with `peer` holds the keys of a completed
/// rekey: as an initiator still waiting to hear the peer under them, or
/// already current with the old keys draining.
fn holds_new_keys(node: &TestNode, peer: &NodeAddr) -> bool {
    node.node
        .get_session(peer)
        .is_some_and(|e| e.pending_new_session().is_some() || e.is_draining())
}

/// Whether `node`'s session with `peer` has cut over to a completed rekey:
/// nothing pending, nothing in flight, the old keys draining.
fn cut_over(node: &TestNode, peer: &NodeAddr) -> bool {
    node.node
        .get_session(peer)
        .is_some_and(|e| e.pending_new_session().is_none() && !e.rekey_attempt() && e.is_draining())
}

/// Discard every packet queued at `node` without processing it, as a lossy
/// link would, and return how many were dropped.
fn drop_queued(node: &mut TestNode) -> usize {
    std::iter::from_fn(|| node.packet_rx.try_recv().ok()).count()
}

/// Run three delivery passes over every node.
async fn pump_all(nodes: &mut [TestNode]) {
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(nodes).await;
    }
}

/// Poll `nodes[at]`'s session rekey machines once a second for up to `secs`
/// seconds until it holds a rekey of its own toward `peer`; true when it
/// does. A retry waits out the abandon backoff, one tick plus a random part
/// of up to the rekey jitter.
async fn retried(nodes: &mut [TestNode], at: usize, peer: &NodeAddr, secs: u64) -> bool {
    for _ in 0..secs {
        crate::time::advance(Duration::from_secs(1));
        nodes[at]
            .node
            .poll_session_rekeys(Node::session_now())
            .await;
        if rekey_initiated(&nodes[at], peer) {
            return true;
        }
    }
    false
}

/// A rekey whose every SessionAck was lost resends its setup at 1, 3, 7 and
/// 15 s, each copy answered from the responder's one candidate with the ack
/// it stored; the rekey ends at its 30 s deadline, counted, and the retry,
/// after the abandon backoff, completes beside that candidate, which holds
/// nothing back.
#[tokio::test]
async fn test_a_rekey_whose_session_acks_were_all_lost_resends_its_setup_until_its_deadline_and_is_retried()
 {
    let mut nodes = rekey_pair([true, false], None).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    // Up to the last rung inside the deadline; the next would fall at 31 s.
    let mut copies = Vec::new();
    for second in 0..=16u64 {
        if second > 0 {
            crate::time::advance(Duration::from_secs(1));
            nodes[0].node.poll_session_rekeys(Node::session_now()).await;
        }
        let setups = deliver_keeping_setups(&mut nodes, 1, &node0_addr).await;
        copies.extend(setups.iter().map(|_| second));
        tokio::time::sleep(Duration::from_millis(20)).await;
        drop_queued(&mut nodes[0]);
    }
    assert_eq!(
        copies,
        [0, 1, 3, 7, 15],
        "the setup must be resent on its ladder, from a 1 s first rung"
    );
    assert_eq!(
        nodes[1].node.stats().session.rekey_armed,
        1,
        "each copy is answered from the candidate it matches, not held again"
    );
    assert!(rekey_initiated(&nodes[0], &node1_addr));

    crate::time::advance(Duration::from_secs(14));
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    assert!(
        !rekey_initiated(&nodes[0], &node1_addr),
        "an unanswered rekey this node initiated must end at its deadline, or \
         the trigger stays vetoed for good"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_unanswered,
        1,
        "the abandoned rekey must be counted once"
    );

    assert!(
        retried(&mut nodes, 0, &node1_addr, 17).await,
        "the trigger must start a fresh rekey once the old one has ended"
    );
    pump_all(&mut nodes).await;
    assert_eq!(
        nodes[1].node.stats().session.rekey_armed,
        2,
        "the retried setup must reach node 1 and be answered"
    );
    assert!(
        holds_new_keys(&nodes[0], &node1_addr) && holds_new_keys(&nodes[1], &node0_addr),
        "the retried rekey must complete on both nodes"
    );
    assert_eq!(nodes[1].node.stats().session.rekey_unanswered, 0);

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: forged setups naming an established peer
// ============================================================================
//
// A SessionSetup carries an ephemeral-only msg1 and names its source in the
// envelope, so anyone who can reach a node can name the node's established
// peer. These record what such setups must not be able to do to the pair's
// key rotation.

/// Deliver to `nodes[victim]` a setup naming `nodes[claimed]`, written by a
/// stranger, and return whether the victim answered it.
async fn forge_rekey_setup(nodes: &mut [TestNode], claimed: usize, victim: usize) -> bool {
    let claimed_addr = *nodes[claimed].node.node_addr();
    let forged = forge_setup_naming(&nodes[claimed], &nodes[victim]);
    let answered = nodes[victim].node.stats().session.rekey_armed;
    nodes[victim]
        .node
        .handle_session_payload(&claimed_addr, &claimed_addr, &forged, 1280, false)
        .await;
    nodes[victim].node.stats().session.rekey_armed > answered
}

/// Forged setups naming each end of an established pair, delivered to the
/// other end once per handshake timeout, must not stop the pair's scheduled
/// rotation: each end's own rekey trigger fires, and each end completes a
/// rekey with the other. A forged setup is held as a candidate beside the
/// session and answered, and holds nothing back: not the trigger, not the
/// dampening, not the peer's genuine setup.
#[tokio::test]
async fn forged_setups_at_both_ends_once_per_handshake_timeout_do_not_stop_the_pairs_rotation() {
    let mut nodes = rekey_pair([true, true], None).await;
    let addrs = [*nodes[0].node.node_addr(), *nodes[1].node.node_addr()];
    for from in 0..2 {
        nodes[from]
            .node
            .send_session_data(&addrs[1 - from], 0, 0, b"crosses the rekey trigger")
            .await
            .expect("send_session_data failed");
    }
    pump_all(&mut nodes).await;
    let timeout = Duration::from_secs(
        nodes[0]
            .node
            .config()
            .node
            .rate_limit
            .handshake_timeout_secs
            + 1,
    );

    let mut initiated = [false; 2];
    let mut completed = [false; 2];
    for window in 1..=3u64 {
        for victim in 0..2 {
            let answered = forge_rekey_setup(&mut nodes, 1 - victim, victim).await;
            assert!(
                answered || window > 1,
                "precondition: the first forged setup must reach node {victim} and be answered"
            );
        }
        for i in 0..2 {
            nodes[i].node.poll_session_rekeys(Node::session_now()).await;
            initiated[i] |= rekey_initiated(&nodes[i], &addrs[1 - i]);
        }
        pump_all(&mut nodes).await;
        for i in 0..2 {
            completed[i] |= holds_new_keys(&nodes[i], &addrs[1 - i]);
        }
        crate::time::advance(timeout);
        for end in nodes.iter_mut() {
            end.node.poll_session_rekeys(Node::session_now()).await;
        }
        pump_all(&mut nodes).await;
    }

    assert_eq!(
        initiated,
        [true, true],
        "each end's scheduled rekey must fire while forged setups name its peer"
    );
    assert_eq!(
        completed,
        [true, true],
        "each end must complete a rekey with its peer while forged setups name it"
    );
    cleanup_nodes(&mut nodes).await;
}

/// At the larger address, with this node's own rekey in flight, a forged
/// setup naming its peer must leave that rekey in flight, and the rekey then
/// completes with the peer: no tie-break runs at a setup, which proves
/// nothing about who sent it.
#[tokio::test]
async fn a_forged_setup_at_the_larger_address_leaves_its_own_rekey_in_flight_to_complete() {
    let mut nodes = rekey_pair([true, true], None).await;
    let (small, large) = by_address(&nodes);
    let small_addr = *nodes[small].node.node_addr();
    let large_addr = *nodes[large].node.node_addr();
    // A frame from the smaller node first, so that whichever node opened the
    // session has heard its peer on it and no longer holds its msg3.
    nodes[small]
        .node
        .send_session_data(&large_addr, 0, 0, b"heard on the session")
        .await
        .expect("send_session_data failed");
    pump_all(&mut nodes).await;

    start_rekey(&mut nodes, large).await;
    assert!(
        forge_rekey_setup(&mut nodes, small, large).await,
        "precondition: the forged setup must reach the larger node and be answered"
    );
    assert!(
        rekey_initiated(&nodes[large], &small_addr),
        "the larger node's own rekey must survive a forged setup naming its peer"
    );

    pump_all(&mut nodes).await;
    assert!(
        holds_new_keys(&nodes[large], &small_addr) && holds_new_keys(&nodes[small], &large_addr),
        "the larger node's own rekey must then complete with its peer"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The session payload of `packet`, a link frame `node` holds from `from`,
/// when it carries a session message in `phase`. The frame is opened under
/// `node`'s link session with `from` without moving its replay window, so
/// delivering it afterwards is unaffected.
fn session_message_in(
    node: &TestNode,
    from: &NodeAddr,
    packet: &crate::transport::ReceivedPacket,
    phase: u8,
) -> Option<Vec<u8>> {
    use crate::proto::fmp::wire::{EncryptedHeader, strip_inner_header};
    use crate::proto::fsp::wire::FspCommonPrefix;
    use crate::proto::link::LinkMessageType;

    let header = EncryptedHeader::parse(&packet.data)?;
    let plaintext = node
        .node
        .get_peer(from)?
        .noise_session()?
        .open_unmarked(
            &packet.data[header.ciphertext_offset()..],
            header.counter,
            &header.header_bytes,
        )
        .ok()?;
    let (_, message) = strip_inner_header(&plaintext)?;
    if message.first() != Some(&LinkMessageType::SessionDatagram.to_byte()) {
        return None;
    }
    let datagram = SessionDatagram::decode(&message[1..]).ok()?;
    FspCommonPrefix::parse(&datagram.payload)
        .is_some_and(|prefix| prefix.phase == phase)
        .then_some(datagram.payload)
}

/// Deliver every frame queued at `nodes[to]` from `from`, and return the
/// session payload of each session message in `phase` among them.
async fn deliver_keeping_phase(
    nodes: &mut [TestNode],
    to: usize,
    from: &NodeAddr,
    phase: u8,
) -> Vec<Vec<u8>> {
    use crate::transport::ReceivedPacket;

    tokio::time::sleep(Duration::from_millis(20)).await;
    let packets: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[to].packet_rx.try_recv().ok()).collect();
    let mut kept = Vec::new();
    for packet in packets {
        if let Some(payload) = session_message_in(&nodes[to], from, &packet, phase) {
            kept.push(payload);
        }
        nodes[to].node.handle_encrypted_frame(packet).await;
    }
    kept
}

/// Deliver every frame queued at `nodes[to]` from `from`, and return the
/// session payload of each SessionSetup among them.
async fn deliver_keeping_setups(
    nodes: &mut [TestNode],
    to: usize,
    from: &NodeAddr,
) -> Vec<Vec<u8>> {
    use crate::proto::fsp::wire::FSP_PHASE_MSG1;
    deliver_keeping_phase(nodes, to, from, FSP_PHASE_MSG1).await
}

/// The Noise msg1 a SessionSetup's session payload `payload` carries.
fn setup_msg1(payload: &[u8]) -> Vec<u8> {
    use crate::proto::fsp::SessionSetup;
    use crate::proto::fsp::wire::FSP_COMMON_PREFIX_SIZE;
    SessionSetup::decode(&payload[FSP_COMMON_PREFIX_SIZE..])
        .expect("a SessionSetup")
        .handshake_payload
}

/// Take every frame queued at `nodes[to]` from `from` off the queue without
/// delivering it, as a lossy link would, and return the Noise msg1 of the one
/// SessionSetup among them.
async fn take_queued_setup_msg1(nodes: &mut [TestNode], to: usize, from: &NodeAddr) -> Vec<u8> {
    use crate::proto::fsp::wire::FSP_PHASE_MSG1;
    use crate::transport::ReceivedPacket;

    tokio::time::sleep(Duration::from_millis(20)).await;
    let packets: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[to].packet_rx.try_recv().ok()).collect();
    let setups: Vec<Vec<u8>> = packets
        .iter()
        .filter_map(|packet| session_message_in(&nodes[to], from, packet, FSP_PHASE_MSG1))
        .collect();
    assert_eq!(setups.len(), 1, "exactly one SessionSetup must be queued");
    setup_msg1(&setups[0])
}

/// A rekey whose SessionAck was lost completes on its setup's first resend,
/// a second later. The resend carries the same Noise msg1 in a SessionSetup
/// built afresh with the destination coordinates cached when it is sent,
/// and the responder answers it from the candidate it matches with the ack
/// it stored, holding one candidate for both.
#[tokio::test]
async fn a_rekey_whose_session_ack_was_lost_completes_on_the_stored_ack_its_resent_setup_draws() {
    use crate::proto::fsp::SessionSetup;
    use crate::proto::fsp::wire::FSP_COMMON_PREFIX_SIZE;

    let mut nodes = rekey_pair([true, false], None).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    let first = deliver_keeping_setups(&mut nodes, 1, &node0_addr).await;
    assert_eq!(first.len(), 1, "node 0's setup must reach node 1");
    assert_eq!(nodes[1].node.stats().session.rekey_armed, 1);
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[0]) > 0,
        "node 1's SessionAck must have been queued at node 0 to be lost"
    );

    // Coordinates for node 1 that differ from those the first copy carried,
    // so the resend shows which it was built with.
    let moved = nodes[0].node.tree_state().my_coords().clone();
    let _ = nodes[0]
        .node
        .coord_cache_mut()
        .insert(node1_addr, moved.clone(), Node::now_ms());

    crate::time::advance(Duration::from_secs(1));
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    let resent = deliver_keeping_setups(&mut nodes, 1, &node0_addr).await;
    assert_eq!(resent.len(), 1, "the setup must be resent at its 1 s rung");
    let decode = |payload: &[u8]| {
        SessionSetup::decode(&payload[FSP_COMMON_PREFIX_SIZE..]).expect("a SessionSetup")
    };
    let (first, resent) = (decode(&first[0]), decode(&resent[0]));
    assert_eq!(
        resent.handshake_payload, first.handshake_payload,
        "the resend must carry the same Noise msg1"
    );
    assert_ne!(
        addr_path(&first.dest_coords),
        addr_path(&moved),
        "precondition: the coordinates moved"
    );
    assert_eq!(
        addr_path(&resent.dest_coords),
        addr_path(&moved),
        "the resend must be wrapped with the coordinates of the moment"
    );
    assert_eq!(
        nodes[1].node.stats().session.rekey_armed,
        1,
        "the copy is answered from the candidate it matches, not held again"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .candidate_count(),
        1
    );
    pump_all(&mut nodes).await;
    assert!(
        cut_over(&nodes[0], &node1_addr) && cut_over(&nodes[1], &node0_addr),
        "the stored ack must complete node 0's rekey, and both ends cut over"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A rekey whose msg3 was lost is completed at the responder by the
/// initiator's msg3 resend: nothing else delivers that msg3, since the
/// responder never resends its SessionAck.
#[tokio::test]
async fn a_rekey_whose_msg3_was_lost_is_completed_at_the_responder_by_the_initiators_msg3_resend() {
    let mut nodes = rekey_pair([true, false], None).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // The setup reaches node 1, which arms and answers; the SessionAck
    // reaches node 0, which derives the new session and sends msg3.
    start_rekey(&mut nodes, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..=1]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[0..=0]).await;
    assert!(
        holds_new_keys(&nodes[0], &node1_addr) && !rekey_initiated(&nodes[0], &node1_addr),
        "precondition: node 0 read the SessionAck and holds the new session"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        drop_queued(&mut nodes[1]),
        3,
        "precondition: the msg3, its probe under the new keys and a keepalive \
         under the old ones are the packets lost"
    );
    assert!(
        !holds_new_keys(&nodes[1], &node0_addr),
        "precondition: node 1 has not completed the rekey"
    );

    // The machine's first msg3 rung, a second after completion.
    crate::time::advance(Duration::from_secs(1));
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    pump_all(&mut nodes).await;

    assert!(
        cut_over(&nodes[1], &node0_addr),
        "the resent msg3 must complete the rekey at node 1"
    );
    assert!(
        cut_over(&nodes[0], &node1_addr),
        "node 1's prompt under the new keys must cut node 0 over"
    );
    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: a forgery inside a rekey responder's msg2-to-msg3 window
// ============================================================================

/// An unauthenticated message delivered to a rekey responder after the
/// initiator has read its SessionAck and before the initiator's msg3 arrives.
#[derive(Clone, Copy, Debug)]
enum WindowForgery {
    /// Nothing is forged: the control the other two are measured against.
    Nothing,
    /// A SessionMsg3 of the right size whose first AEAD cannot open.
    Msg3,
    /// A SessionSetup carrying a stranger's ephemeral under the initiator's
    /// address, delivered at the larger address, where a tie-break at the
    /// setup would yield to it.
    Setup,
}

/// What a rekey left behind once a forgery may have reached its window.
#[derive(Debug, PartialEq, Eq)]
struct WindowOutcome {
    /// The responder completed the handshake on the initiator's genuine msg3
    /// and cut over.
    responder_completed: bool,
    /// The initiator cut over on the responder's prompt under the new keys.
    initiator_cut_over: bool,
    /// A frame the initiator sent after its cutover, and after its
    /// confirmation window, decoded at the responder.
    initiator_to_responder: bool,
    /// A frame the responder sent decoded at the initiator.
    responder_to_initiator: bool,
    /// After the responder's own next rekey, frames decode both ways.
    next_cycle_carries_both_ways: bool,
}

/// The outcome of a rekey nothing interfered with.
const WINDOW_HEALTHY: WindowOutcome = WindowOutcome {
    responder_completed: true,
    initiator_cut_over: true,
    initiator_to_responder: true,
    responder_to_initiator: true,
    next_cycle_carries_both_ways: true,
};

/// Send one data frame from `nodes[from]` to `nodes[to]`, deliver it, and
/// report whether it decoded at `nodes[to]`.
async fn session_frame_decodes(nodes: &mut [TestNode], from: usize, to: usize) -> bool {
    let from_addr = *nodes[from].node.node_addr();
    let to_addr = *nodes[to].node.node_addr();
    let received = |nodes: &[TestNode]| {
        nodes[to]
            .node
            .get_session(&from_addr)
            .expect("the session must survive")
            .traffic_counters()
            .1
    };
    let before = received(nodes);
    nodes[from]
        .node
        .send_session_data(&to_addr, 0, 0, b"window forgery probe")
        .await
        .expect("send_session_data failed");
    pump_all(nodes).await;
    received(nodes) == before + 1
}

/// The current epoch of `node`'s session with `peer`.
fn current_epoch(node: &TestNode, peer: &NodeAddr) -> Option<EpochTag> {
    node.node.get_session(peer).and_then(|e| e.current_tag())
}

/// Drive a genuine FSP rekey to the point where the initiator has read the
/// SessionAck and derived the new session, deliver `forgery` to the
/// responder, then release the initiator's genuine msg3 and follow the cycle
/// through the responder's cutover and prompt, the initiator's cutover, its
/// confirmation window, and one data frame each way. Then let the responder
/// start the next rekey and check that it carries frames both ways.
///
/// The responder is chosen at run time to hold the larger address, the end
/// at which a tie-break at the setup would yield. The forged msg3 reaches
/// the same dispatcher at either end.
///
/// Returns the outcome and a note of the responder's counters for the
/// failure message: msg3s refused for arriving with no handshake to read
/// them, and dual-initiation yields.
async fn rekey_with_window_forgery(forgery: WindowForgery) -> (WindowOutcome, String) {
    use crate::transport::ReceivedPacket;

    let mut nodes = rekey_pair([true, true], None).await;
    let (init, resp) = by_address(&nodes);
    let init_addr = *nodes[init].node.node_addr();
    let resp_addr = *nodes[resp].node.node_addr();
    assert!(
        resp_addr > init_addr,
        "the responder must hold the larger address"
    );

    // The setup reaches the responder only; it holds and answers it. The
    // initiator starts no rekey after this one.
    start_rekey(&mut nodes, init).await;
    quiet_trigger(&mut nodes[init], &resp_addr);
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[resp..=resp]).await;
    assert_eq!(
        nodes[resp].node.stats().session.rekey_armed,
        1,
        "the responder must have answered the setup"
    );

    // The SessionAck reaches the initiator only; it derives the new session
    // and sends msg3, which waits in the responder's queue.
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[init..=init]).await;
    assert!(
        holds_new_keys(&nodes[init], &resp_addr) && !rekey_initiated(&nodes[init], &resp_addr),
        "the initiator must have read the SessionAck and hold the new session"
    );
    assert!(
        nodes[resp]
            .node
            .get_session(&init_addr)
            .is_some_and(|e| e.candidate_count() > 0),
        "the responder must still be waiting for msg3"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    let held: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[resp].packet_rx.try_recv().ok()).collect();
    assert!(
        !held.is_empty(),
        "the initiator's msg3 must be queued at the responder"
    );

    match forgery {
        WindowForgery::Nothing => {}
        WindowForgery::Msg3 => {
            let forged = SessionMsg3::new(vec![0u8; crate::noise::HANDSHAKE_MSG3_SIZE]).encode();
            nodes[resp]
                .node
                .handle_session_payload(&init_addr, &init_addr, &forged, 1280, false)
                .await;
        }
        WindowForgery::Setup => {
            let forged = forge_setup_for(&nodes[resp].node);
            nodes[resp]
                .node
                .handle_session_payload(&init_addr, &init_addr, &forged, 1280, false)
                .await;
            assert_eq!(
                nodes[resp].node.stats().session.rekey_armed,
                2,
                "the forged setup must have been held beside the genuine \
                 candidate, or the test measures nothing"
            );
        }
    }

    // Release the genuine msg3: the responder cuts over and prompts, and the
    // prompt cuts the initiator over.
    for packet in held {
        nodes[resp].node.handle_encrypted_frame(packet).await;
    }
    pump_all(&mut nodes).await;
    let responder_completed = cut_over(&nodes[resp], &init_addr);
    let initiator_cut_over = cut_over(&nodes[init], &resp_addr);

    // Past the initiator's confirmation window, nothing undoes the cutover.
    crate::time::advance(Duration::from_secs(40));
    nodes[init]
        .node
        .poll_session_rekeys(Node::session_now())
        .await;
    pump_all(&mut nodes).await;

    let initiator_to_responder = session_frame_decodes(&mut nodes, init, resp).await;
    let responder_to_initiator = session_frame_decodes(&mut nodes, resp, init).await;

    // The responder's own next rekey, past the dampening its completion of
    // the initiator's rekey opened. Its data frame above crossed its
    // trigger.
    let before = current_epoch(&nodes[resp], &init_addr);
    nodes[resp]
        .node
        .poll_session_rekeys(Node::session_now())
        .await;
    assert!(
        rekey_initiated(&nodes[resp], &init_addr),
        "the responder must start the next rekey"
    );
    pump_until_quiet(&mut nodes).await;
    let next_cycle_carries_both_ways = cut_over(&nodes[resp], &init_addr)
        && current_epoch(&nodes[resp], &init_addr) != before
        && session_frame_decodes(&mut nodes, resp, init).await
        && session_frame_decodes(&mut nodes, init, resp).await;

    let stats = &nodes[resp].node.stats().session;
    let note = format!(
        "the responder refused {} msg3s and yielded {} times",
        stats.bad_state, stats.rekey_yielded
    );
    cleanup_nodes(&mut nodes).await;
    (
        WindowOutcome {
            responder_completed,
            initiator_cut_over,
            initiator_to_responder,
            responder_to_initiator,
            next_cycle_carries_both_ways,
        },
        note,
    )
}

/// The control: with nothing forged, the procedure that measures the two
/// forgeries completes the rekey and carries frames both ways on both cycles.
#[tokio::test]
async fn a_rekey_with_nothing_forged_in_the_responders_window_completes_and_carries_traffic_both_ways()
 {
    let (outcome, note) = rekey_with_window_forgery(WindowForgery::Nothing).await;
    assert_eq!(outcome, WINDOW_HEALTHY, "{note}");
}

/// A garbage msg3 that reaches a rekey responder after the initiator has read
/// the SessionAck must not cost the genuine msg3 its handshake.
#[tokio::test]
async fn a_forged_msg3_in_the_responders_window_does_not_split_the_rekey() {
    let (outcome, note) = rekey_with_window_forgery(WindowForgery::Msg3).await;
    assert_eq!(outcome, WINDOW_HEALTHY, "{note}");
}

/// A forged setup at a larger rekey responder, after the initiator has read
/// the SessionAck, must not cost the genuine msg3 its handshake.
#[tokio::test]
async fn a_forged_setup_at_the_larger_responder_in_its_window_does_not_split_the_rekey() {
    let (outcome, note) = rekey_with_window_forgery(WindowForgery::Setup).await;
    assert_eq!(outcome, WINDOW_HEALTHY, "{note}");
}

// ============================================================================
// Integration tests: who cuts over to a completed session rekey, and when
// ============================================================================

/// Run `node`'s session rekey tick at the session clock's now: the rekey
/// machines' poll.
async fn session_tick(node: &mut TestNode) {
    node.node.poll_session_rekeys(Node::session_now()).await;
}

/// Deliver every frame queued at `nodes[to]` from `from` except the session
/// msg3s, which are lost, and return how many were lost. Each link frame is
/// first opened under `nodes[to]`'s link session without moving its replay
/// window, so the delivery that follows is unaffected.
async fn deliver_losing_msg3(nodes: &mut [TestNode], to: usize, from: &NodeAddr) -> usize {
    use crate::proto::fmp::wire::{EncryptedHeader, strip_inner_header};
    use crate::proto::fsp::wire::{FSP_PHASE_MSG3, FspCommonPrefix};
    use crate::proto::link::LinkMessageType;
    use crate::transport::ReceivedPacket;

    tokio::time::sleep(Duration::from_millis(20)).await;
    let packets: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[to].packet_rx.try_recv().ok()).collect();
    let mut lost = 0;
    for packet in packets {
        let link = EncryptedHeader::parse(&packet.data).and_then(|header| {
            nodes[to]
                .node
                .get_peer(from)?
                .noise_session()?
                .open_unmarked(
                    &packet.data[header.ciphertext_offset()..],
                    header.counter,
                    &header.header_bytes,
                )
                .ok()
        });
        let msg3 = link
            .as_deref()
            .and_then(strip_inner_header)
            .is_some_and(|(_, message)| {
                message.first() == Some(&LinkMessageType::SessionDatagram.to_byte())
                    && SessionDatagram::decode(&message[1..]).is_ok_and(|datagram| {
                        FspCommonPrefix::parse(&datagram.payload)
                            .is_some_and(|prefix| prefix.phase == FSP_PHASE_MSG3)
                    })
            });
        if msg3 {
            lost += 1;
        } else {
            nodes[to].node.handle_encrypted_frame(packet).await;
        }
    }
    lost
}

/// Keep `node`'s rekey trigger toward `peer` from starting another rekey
/// for the rest of the test. A node that rekeys after every message would
/// otherwise start a new rekey on a tick once the first has cut over.
fn quiet_trigger(node: &mut TestNode, peer: &NodeAddr) {
    node.node
        .sessions
        .get_mut(peer)
        .expect("the session must exist")
        .quiet_rekeys();
}

/// How many data frames `node` has received on its session with `peer`.
fn received(node: &TestNode, peer: &NodeAddr) -> u64 {
    node.node
        .get_session(peer)
        .expect("the session must survive")
        .traffic_counters()
        .1
}

/// A rekey whose every msg3 copy is lost costs no frame either way. The
/// initiator keeps sealing its data under the old keys until it hears the
/// responder under the new ones; hearing the responder still on the old
/// keys after its last probe, it discards the new keys at its confirmation
/// deadline instead of moving to them, and the next rekey completes.
#[tokio::test]
async fn every_msg3_lost_loses_no_frame() {
    let mut nodes = rekey_pair([true, false], None).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    let old = current_epoch(&nodes[0], &addr1);

    start_rekey(&mut nodes, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..=1]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[0..=0]).await;
    assert!(
        holds_new_keys(&nodes[0], &addr1),
        "precondition: node 0 read the SessionAck and holds the new keys"
    );
    let mut lost = deliver_losing_msg3(&mut nodes, 1, &addr0).await;

    // A second at a time through node 0's confirmation window, data both
    // ways each second; every msg3 copy is lost.
    for second in 1..=32 {
        crate::time::advance(Duration::from_secs(1));
        session_tick(&mut nodes[0]).await;
        session_tick(&mut nodes[1]).await;
        lost += deliver_losing_msg3(&mut nodes, 1, &addr0).await;
        if !rekey_initiated(&nodes[0], &addr1) {
            let before = received(&nodes[1], &addr0);
            nodes[0]
                .node
                .send_session_data(&addr1, 0, 0, b"node 0 waits for evidence")
                .await
                .expect("send_session_data failed");
            lost += deliver_losing_msg3(&mut nodes, 1, &addr0).await;
            assert_eq!(
                received(&nodes[1], &addr0),
                before + 1,
                "second {second}: node 0's frame must decrypt at node 1, which \
                 never got the msg3"
            );
            assert!(session_frame_decodes(&mut nodes, 1, 0).await);
        }
    }
    assert!(lost >= 5, "the msg3 and its resends must be lost: {lost}");
    assert_eq!(
        current_epoch(&nodes[0], &addr1),
        old,
        "past its confirmation deadline, node 0 must still seal under the keys \
         node 1 has: it heard node 1 on them, so it discarded the new keys \
         rather than move to them"
    );

    // With nothing lost from here, the repair node 0 started completes at
    // both ends.
    let mut rotated = false;
    for _ in 0..70 {
        crate::time::advance(Duration::from_secs(1));
        session_tick(&mut nodes[0]).await;
        session_tick(&mut nodes[1]).await;
        pump_until_quiet(&mut nodes).await;
        if cut_over(&nodes[0], &addr1)
            && cut_over(&nodes[1], &addr0)
            && current_epoch(&nodes[0], &addr1) != old
        {
            rotated = true;
            break;
        }
    }
    assert!(rotated, "a later rekey must complete at both ends");
    assert_eq!(
        (
            nodes[1].node.stats().session.rekey_held,
            nodes[0].node.stats().session.rekey_unanswered
        ),
        (0, 0),
        "the repair node 0 starts at its confirmation deadline must reach node 1 \
         after node 1's handshake for the lost rekey has expired, and complete"
    );
    assert!(session_frame_decodes(&mut nodes, 0, 1).await);
    assert!(session_frame_decodes(&mut nodes, 1, 0).await);

    cleanup_nodes(&mut nodes).await;
}

/// A rekey is confirmed at both ends by the responder's prompt alone: the
/// responder cuts over on msg3 and sends a CoordsWarmup under the new keys,
/// the initiator cuts over on it, and the initiator resends no msg3 though
/// neither end has data to send.
#[tokio::test]
async fn a_rekey_confirms_on_the_responders_prompt_with_no_reverse_traffic() {
    let mut nodes = rekey_pair([true, false], None).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    quiet_trigger(&mut nodes[0], &addr1);
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..=1]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[0..=0]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    // node 0's msg3 is the first of what it sent; a probe under the new
    // keys and a keepalive under the old ones follow it.
    let msg3 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's msg3 must be queued at node 1");
    nodes[1].node.handle_encrypted_frame(msg3).await;
    assert!(
        cut_over(&nodes[1], &addr0),
        "node 1 must cut over at msg3, before any frame of node 0's under the \
         new keys"
    );
    pump_until_quiet(&mut nodes).await;
    assert!(
        cut_over(&nodes[0], &addr1),
        "node 0 must cut over on node 1's prompt, with no timer run"
    );

    let refused = nodes[1].node.stats().session.bad_state;
    for _ in 0..32 {
        crate::time::advance(Duration::from_secs(1));
        session_tick(&mut nodes[0]).await;
        session_tick(&mut nodes[1]).await;
        pump_all(&mut nodes).await;
    }
    assert_eq!(
        nodes[1].node.stats().session.bad_state,
        refused,
        "node 0 must resend no msg3 once it has heard node 1 under the new keys"
    );
    assert!(session_frame_decodes(&mut nodes, 0, 1).await);
    assert!(session_frame_decodes(&mut nodes, 1, 0).await);

    cleanup_nodes(&mut nodes).await;
}

/// The previous keys are kept for one drain window after the first frame
/// that shows the peer moved, and a frame the peer sealed under them, held
/// back and delivered later, does not keep them longer.
#[tokio::test]
async fn a_withheld_previous_epoch_frame_never_extends_the_drain() {
    use crate::transport::ReceivedPacket;

    let mut nodes = rekey_pair([true, false], None).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();

    // A frame node 0 seals under the old keys is held back.
    nodes[0]
        .node
        .send_session_data(&addr1, 0, 0, b"held under the old keys")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let held: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[1].packet_rx.try_recv().ok()).collect();
    assert_eq!(held.len(), 1, "the held frame must be the one queued");

    start_rekey(&mut nodes, 0).await;
    quiet_trigger(&mut nodes[0], &addr1);
    pump_until_quiet(&mut nodes).await;
    crate::time::advance(Duration::from_millis(2_500));
    session_tick(&mut nodes[0]).await;
    session_tick(&mut nodes[1]).await;
    pump_until_quiet(&mut nodes).await;

    // node 0's first data frame under the new keys shows node 1 it moved.
    assert!(session_frame_decodes(&mut nodes, 0, 1).await);
    assert!(
        nodes[1].node.get_session(&addr0).unwrap().is_draining(),
        "node 1 must hold the previous keys while it drains them"
    );

    // Half a drain window later the held frame arrives, and still opens.
    crate::time::advance(Duration::from_secs(5));
    let before = received(&nodes[1], &addr0);
    for packet in held {
        nodes[1].node.handle_encrypted_frame(packet).await;
    }
    assert_eq!(
        received(&nodes[1], &addr0),
        before + 1,
        "the held frame must open under the previous keys"
    );

    crate::time::advance(Duration::from_millis(5_500));
    session_tick(&mut nodes[1]).await;
    assert!(
        !nodes[1].node.get_session(&addr0).unwrap().is_draining(),
        "the previous keys must go one drain window after node 0 was seen to \
         move, whatever arrives under them after that"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Send a session ReceiverReport claiming `highest` frames from `nodes[from]`
/// to `to`, sealed under `nodes[from]`'s current epoch.
async fn send_report(nodes: &mut [TestNode], from: usize, to: &NodeAddr, highest: u64) {
    let body = crate::proto::mmp::SessionReceiverReport::from(&receiver_report(highest)).encode();
    nodes[from]
        .node
        .send_session_msg(to, SessionMessageType::ReceiverReport.to_byte(), &body)
        .await
        .expect("send_session_msg failed");
}

/// An FSP rekey responder that has cut over keeps its new epoch's session
/// MMP free of what the initiator sealed under the old epoch.
///
/// node 1 reads node 0's msg3 and cuts over at once, but its prompt under the
/// new keys is lost, so node 0 keeps waiting for evidence with its data on
/// the old epoch, and node 1 opens node 0's frames under the epoch it is
/// draining. Their payload is still delivered, but they belong to the
/// retired epoch: a data frame's counter must not become the new epoch's
/// highest, which would count every new-epoch frame as reordered, and a
/// ReceiverReport about node 1's old-epoch frames must not become the
/// reference later reports are judged against. Once node 0 hears node 1
/// under the new epoch and moves to it, its frames and reports are counted
/// and accepted.
#[tokio::test]
async fn previous_epoch_report_does_not_reach_new_mmp() {
    let mut nodes = rekey_pair([true, false], None).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();

    // The setup reaches node 1, the ack reaches node 0, node 0's msg3
    // reaches node 1, and node 1's prompt under the new keys is lost.
    start_rekey(&mut nodes, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..=1]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[0..=0]).await;
    assert!(
        holds_new_keys(&nodes[0], &addr1),
        "node 0 must hold the new epoch"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..=1]).await;
    assert!(cut_over(&nodes[1], &addr0), "node 1 must cut over at msg3");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[0]) > 0,
        "node 1's prompt must be lost"
    );
    assert!(
        nodes[0]
            .node
            .get_session(&addr1)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 0 must still wait for evidence"
    );
    let entry = nodes[1].node.get_session(&addr0).unwrap();
    let received = entry.traffic_counters().1;
    let mmp = entry.mmp().expect("node 1 must run session MMP");
    assert_eq!(mmp.receiver.highest_counter(), 0, "the cutover resets MMP");
    assert_eq!(mmp.metrics.rr_counters(), None, "the cutover resets MMP");
    let reports = mmp.metrics.reports_seen();

    // node 0, still on the old epoch, sends data and a report about node 1's
    // old-epoch frames. Only node 1's queue is delivered.
    nodes[0]
        .node
        .send_session_data(&addr1, 0, 0, b"old epoch 0 to 1")
        .await
        .expect("send_session_data failed");
    send_report(&mut nodes, 0, &addr1, 1_000).await;
    pump_all(&mut nodes[1..=1]).await;

    let entry = nodes[1].node.get_session(&addr0).unwrap();
    assert_eq!(
        entry.traffic_counters().1,
        received + 1,
        "an old-epoch frame's payload must still be delivered"
    );
    let mmp = entry.mmp().unwrap();
    assert_eq!(
        mmp.receiver.highest_counter(),
        0,
        "an old-epoch frame's counter must not become the new epoch's highest"
    );
    assert_eq!(
        mmp.metrics.reports_seen(),
        reports,
        "an old-epoch ReceiverReport must not reach the new epoch's metrics"
    );
    assert_eq!(mmp.metrics.rr_counters(), None);

    // node 1's repeated prompt a second later reaches node 0, which cuts
    // over; node 0's frames and reports then feed node 1's MMP.
    crate::time::advance(Duration::from_secs(1));
    nodes[1].node.poll_session_rekeys(Node::session_now()).await;
    pump_all(&mut nodes).await;
    assert!(cut_over(&nodes[0], &addr1), "node 0 must cut over");
    assert!(session_frame_decodes(&mut nodes, 0, 1).await);
    assert!(session_frame_decodes(&mut nodes, 1, 0).await);
    send_report(&mut nodes, 0, &addr1, 5).await;
    pump_all(&mut nodes).await;
    let mmp = nodes[1].node.get_session(&addr0).unwrap().mmp().unwrap();
    assert!(
        mmp.receiver.highest_counter() > 0,
        "new-epoch frames must be counted"
    );
    assert_eq!(
        mmp.metrics.rr_counters().map(|(highest, _, _)| highest),
        Some(5),
        "a new-epoch ReceiverReport must be accepted"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Deliver every frame queued at `nodes[to]`, and return the FSP header
/// flags of each session datagram among them. Each link frame is first
/// opened under `nodes[to]`'s link session with `from` without moving that
/// session's replay window, so the delivery that follows is unaffected.
async fn delivered_flags(nodes: &mut [TestNode], to: usize, from: &NodeAddr) -> Vec<u8> {
    use crate::proto::fmp::wire::{EncryptedHeader, strip_inner_header};
    use crate::proto::link::LinkMessageType;
    use crate::transport::ReceivedPacket;

    tokio::time::sleep(Duration::from_millis(20)).await;
    let packets: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[to].packet_rx.try_recv().ok()).collect();
    let mut flags = Vec::new();
    for packet in packets {
        let link = EncryptedHeader::parse(&packet.data).and_then(|header| {
            nodes[to]
                .node
                .get_peer(from)?
                .noise_session()?
                .open_unmarked(
                    &packet.data[header.ciphertext_offset()..],
                    header.counter,
                    &header.header_bytes,
                )
                .ok()
        });
        if let Some(plaintext) = link
            && let Some((_, message)) = strip_inner_header(&plaintext)
            && message.first() == Some(&LinkMessageType::SessionDatagram.to_byte())
        {
            let datagram = SessionDatagram::decode(&message[1..]).expect("a session datagram");
            flags.push(datagram.payload[1]);
        }
        nodes[to].node.handle_encrypted_frame(packet).await;
    }
    flags
}

/// After a rekey, every message an established session sends carries the
/// key-epoch bit of the epoch it is sealed under: data, reports and a
/// standalone CoordsWarmup alike, and so does a message built for the
/// encrypt worker to seal.
#[tokio::test]
async fn every_send_path_takes_k_from_the_epoch() {
    use crate::proto::fsp::wire::{FSP_FLAG_CP, FSP_FLAG_K};

    let mut nodes = rekey_pair([true, false], None).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    start_rekey(&mut nodes, 0).await;
    pump_until_quiet(&mut nodes).await;
    assert!(cut_over(&nodes[1], &addr0), "node 1 must cut over at msg3");
    assert!(
        cut_over(&nodes[0], &addr1),
        "node 0 must cut over on node 1's prompt"
    );
    assert!(session_frame_decodes(&mut nodes, 0, 1).await);
    let k = nodes[0].node.get_session(&addr1).unwrap().current_k_bit();
    assert!(k, "one cutover sets the key-epoch bit");
    assert_eq!(
        nodes[1].node.get_session(&addr0).unwrap().current_k_bit(),
        k
    );

    let mut sent = Vec::new();
    nodes[0]
        .node
        .send_session_data(&addr1, 0, 0, b"data")
        .await
        .expect("send_session_data failed");
    sent.push(("data", delivered_flags(&mut nodes, 1, &addr0).await));
    send_report(&mut nodes, 0, &addr1, 1).await;
    sent.push(("report", delivered_flags(&mut nodes, 1, &addr0).await));
    nodes[0]
        .node
        .send_coords_warmup(&addr1)
        .await
        .expect("send_coords_warmup failed");
    sent.push(("warmup", delivered_flags(&mut nodes, 1, &addr0).await));
    for (path, flags) in &sent {
        assert_eq!(
            flags.len(),
            1,
            "{path}: one session datagram, got {flags:?}"
        );
        assert_eq!(
            flags[0] & FSP_FLAG_K != 0,
            k,
            "{path}: the K flag must be the epoch's"
        );
    }
    assert_ne!(sent[2].1[0] & FSP_FLAG_CP, 0, "a CoordsWarmup carries CP");

    let reserved = nodes[0]
        .node
        .sessions
        .get_mut(&addr1)
        .unwrap()
        .reserve_send(
            Node::session_now(),
            0,
            SessionMessageType::DataPacket.to_byte(),
            b"x",
        )
        .expect("the session reserves a counter")
        .expect("the session's keys hand out a send key");
    assert_eq!(
        reserved.header[1] & FSP_FLAG_K != 0,
        k,
        "a message built for the encrypt worker must carry the epoch's K flag"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A forged SessionAck arriving midway through an unanswered rekey must not
/// restart its deadline: the rekey ends at the deadline measured from the
/// setup this node sent.
#[tokio::test]
async fn test_forged_session_acks_do_not_hold_an_unanswered_rekey_open_past_its_deadline() {
    let mut nodes = rekey_pair([true, false], None).await;
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[1]) > 0,
        "node 0's SessionSetup must have been queued at node 1 to be lost"
    );

    crate::time::advance(Duration::from_secs(20));
    let forged = forged_session_ack(&nodes[1]);
    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;
    assert_eq!(nodes[0].node.stats().session.ack_handshake_failed, 1);
    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "the unreadable ack must leave the rekey in flight"
    );

    crate::time::advance(Duration::from_secs(10));
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    assert!(
        !rekey_initiated(&nodes[0], &node1_addr),
        "a forged SessionAck must not restart the deadline of the rekey this \
         node initiated"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_unanswered,
        1,
        "the abandoned rekey must be counted once"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: a peer's cutover after a long silence
// ============================================================================

/// A rekey initiator that never hears its responder under the new keys
/// cuts over by assumption at its confirmation deadline, and its frames
/// under the new keys decrypt at a responder that cut over at msg3.
///
/// node 1 reads node 0's msg3 and cuts over, its prompt is lost, and it is
/// silent from then on (session MMP in minimal mode with traffic one way
/// sends nothing back), so node 0 has no evidence and nothing showing node 1
/// stayed on the old keys.
#[tokio::test]
async fn test_silent_responders_initiator_cuts_over_at_its_confirmation_deadline() {
    let mut nodes = rekey_pair([true, false], None).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..=1]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[0..=0]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..=1]).await;
    assert!(
        cut_over(&nodes[1], &node0_addr),
        "node 1 must cut over at msg3"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[0]) > 0,
        "node 1's prompt must be lost"
    );
    assert!(
        holds_new_keys(&nodes[0], &node1_addr) && !cut_over(&nodes[0], &node1_addr),
        "node 0 must still wait for evidence"
    );

    // Past the confirmation window: the handshake timeout plus one tick.
    crate::time::advance(Duration::from_secs(32));
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    assert!(
        cut_over(&nodes[0], &node1_addr),
        "node 0 must cut over by assumption at its confirmation deadline"
    );
    pump_all(&mut nodes).await;

    let recv_before = nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .traffic_counters()
        .1;
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"after the assumed cutover")
        .await
        .expect("send_session_data failed");
    pump_all(&mut nodes).await;
    assert_eq!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .traffic_counters()
            .1,
        recv_before + 1,
        "node 0's frame under the keys it assumed must decrypt at node 1"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A peer that restarts while this node's own rekey waits for evidence is
/// not locked out by it. At the larger address the restarted peer's setup is
/// answered at once, and its authenticated msg3 replaces the waiting keys.
/// At the smaller address the setup is refused while the own rekey waits,
/// since a setup authenticates nothing and could be a deployed peer's rekey
/// that commits on the ack; once this node's confirmation deadline has
/// passed it is idle again and the peer's next attempt re-establishes the
/// session.
#[tokio::test]
async fn test_peer_restart_reestablishes_while_this_nodes_own_rekey_waits_for_evidence() {
    for larger in [true, false] {
        restart_beside_a_waiting_rekey(larger).await;
    }
}

/// The restart of [`test_peer_restart_reestablishes_while_this_nodes_own_rekey_waits_for_evidence`],
/// with the node whose rekey waits at the larger address when `larger`.
async fn restart_beside_a_waiting_rekey(larger: bool) {
    let mut nodes = rekey_pair([true, true], None).await;
    let (small, large) = by_address(&nodes);
    let (waits, restarts) = if larger {
        (large, small)
    } else {
        (small, large)
    };
    let waits_addr = *nodes[waits].node.node_addr();
    let restarts_addr = *nodes[restarts].node.node_addr();
    let waits_pubkey = nodes[waits].node.identity().pubkey_full();
    quiet_trigger(&mut nodes[restarts], &waits_addr);
    // A frame from the peer first, so that whichever node opened the
    // session has heard its peer on it and no longer holds its msg3.
    nodes[restarts]
        .node
        .send_session_data(&waits_addr, 0, 0, b"heard on the session")
        .await
        .expect("send_session_data failed");
    pump_all(&mut nodes).await;

    // The waiting node's rekey completes on the peer's ack, and its msg3 is
    // lost, so it waits for evidence that never comes.
    start_rekey(&mut nodes, waits).await;
    quiet_trigger(&mut nodes[waits], &restarts_addr);
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[restarts..=restarts]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[waits..=waits]).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[restarts]) > 0,
        "the msg3 must be lost"
    );
    assert!(
        nodes[waits]
            .node
            .get_session(&restarts_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "the waiting node must hold its rekey's keys waiting for evidence"
    );

    // The peer restarts and re-initiates.
    nodes[restarts].node.remove_session(&waits_addr);
    nodes[restarts]
        .node
        .initiate_session(waits_addr, waits_pubkey)
        .await
        .expect("re-initiate_session failed");
    pump_all(&mut nodes).await;

    let stats = &nodes[waits].node.stats().session;
    if larger {
        assert_eq!(
            (stats.pending_replaced, stats.rekey_yielded),
            (1, 0),
            "the restarted peer's authenticated msg3 must be what replaces the \
             waiting session, counted as a replacement and not as a yielded \
             rekey in flight"
        );
    } else {
        assert_eq!(
            (stats.rekey_pending, stats.pending_replaced),
            (1, 0),
            "the smaller node refuses the setup while its own rekey waits"
        );
        // Past the confirmation deadline, with nothing heard, the waiting
        // node assumes its rekey and is idle; the peer's next attempt is
        // answered.
        crate::time::advance(Duration::from_secs(32));
        nodes[waits]
            .node
            .poll_session_rekeys(Node::session_now())
            .await;
        nodes[restarts].node.remove_session(&waits_addr);
        nodes[restarts]
            .node
            .initiate_session(waits_addr, waits_pubkey)
            .await
            .expect("re-initiate_session failed");
        pump_all(&mut nodes).await;
    }

    nodes[restarts]
        .node
        .send_session_data(&waits_addr, 0, 0, b"after the restart")
        .await
        .expect("send_session_data failed");
    pump_all(&mut nodes).await;

    let entry = nodes[waits].node.get_session(&restarts_addr).unwrap();
    assert!(
        entry.pending_new_session().is_none(),
        "larger {larger}: the restarted peer's keys must have replaced the waiting ones"
    );
    assert!(
        entry.traffic_counters().1 > 0,
        "larger {larger}: the waiting node must have decrypted the restarted peer's frame"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A peer that restarts loses the session and, holding none, sends nothing
/// on it, so this node's data goes nowhere. Thirty seconds after this node
/// last heard the peer while sending, its silence rule starts a rekey, which
/// the restarted peer answers as a first handshake. The SessionAck carries
/// the peer's new startup epoch, so the rekey reports a restart: this node
/// cuts over at its msg3 with the old keys retired rather than drained,
/// counts the restart, keeps the session, and the peer decrypts the next
/// frame it sends.
#[tokio::test]
async fn fsp_completion_that_reports_a_restart_keeps_the_session_and_delivers_the_next_frame() {
    let mut nodes = rekey_pair([false, false], None).await;
    let addr0 = *nodes[0].node.node_addr();
    let addr1 = *nodes[1].node.node_addr();
    for (from, to) in [(1, addr0), (0, addr1)] {
        nodes[from]
            .node
            .send_session_data(&to, 0, 0, b"before the restart")
            .await
            .expect("send_session_data failed");
    }
    pump_all(&mut nodes).await;
    let old = current_epoch(&nodes[0], &addr1);

    // The peer restarts: a new startup epoch and no session.
    nodes[1].node.remove_session(&addr0);
    nodes[1]
        .node
        .replace_context(|ctx| ctx.startup_epoch = [0x5A; 8]);
    nodes[0]
        .node
        .send_session_data(&addr1, 0, 0, b"into the void")
        .await
        .expect("send_session_data failed");
    pump_all(&mut nodes).await;

    crate::time::advance(Duration::from_secs(29));
    session_tick(&mut nodes[0]).await;
    assert!(
        !rekey_initiated(&nodes[0], &addr1),
        "no rekey before the silence interval has passed"
    );
    crate::time::advance(Duration::from_secs(1));
    session_tick(&mut nodes[0]).await;
    assert!(
        rekey_initiated(&nodes[0], &addr1),
        "the silence rule must start a rekey 30 s after the peer was last heard"
    );
    pump_all(&mut nodes).await;

    let entry = nodes[0]
        .node
        .get_session(&addr1)
        .expect("the session must survive the restart");
    assert_eq!(
        nodes[0].node.stats().session.peer_restarted,
        1,
        "the restart must be counted"
    );
    assert!(
        entry.is_established() && current_epoch(&nodes[0], &addr1) != old,
        "the session must continue under the new keys"
    );
    assert!(
        entry.pending_new_session().is_none() && !entry.is_draining(),
        "a restart cutover moves at the msg3 and retires the old keys, which \
         the restarted peer can no longer use"
    );

    nodes[0]
        .node
        .send_session_data(&addr1, 0, 0, b"after the restart")
        .await
        .expect("send_session_data failed");
    pump_all(&mut nodes).await;
    assert!(
        received(&nodes[1], &addr0) > 0,
        "the restarted peer must decrypt the next frame"
    );

    cleanup_nodes(&mut nodes).await;
}

// ---------------------------------------------------------------------------
// Reactive MtuExceeded: corroboration against what this node actually sent
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_reactive_mtu_exceeded_at_the_floor_no_longer_pins_a_session_this_node_has_not_overfilled()
 {
    // The defect itself. A report of exactly the floor is a legal value, and
    // the admission gate cannot tell an honest forwarder from anyone else, so
    // one packet drove a bound session's path MTU to the floor and pinned the
    // Ipv6Address-keyed entry the SYN-time MSS clamp reads. Nothing this node
    // sent could have overflowed a hop at that size, so no honest report of it
    // exists.
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    let before = node
        .sessions
        .get(&dest)
        .and_then(|e| e.mmp())
        .map(|m| m.path_mtu.current_mtu());

    let inner =
        build_mtu_exceeded_inner(&dest, &reporter, crate::proto::mmp::MIN_REACTIVE_PATH_MTU);
    node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        node.sessions
            .get(&dest)
            .and_then(|e| e.mmp())
            .map(|m| m.path_mtu.current_mtu()),
        before,
        "an uncorroborated report must leave the session path MTU alone"
    );
    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        None,
        "an uncorroborated report must leave no clamp entry behind"
    );
    assert_eq!(
        node.metrics().errors.mtu_exceeded_uncorroborated.get(),
        1,
        "the refusal must be counted apart from the below-floor refusal"
    );
    assert_eq!(
        node.metrics().errors.mtu_exceeded_below_floor.get(),
        0,
        "the floor is not what refused this; the value is exactly at it"
    );
}

#[tokio::test]
async fn an_initiating_session_refuses_an_uncorroborated_report_and_accepts_a_corroborated_one() {
    // The lookup write is the effect that survives on an initiating session,
    // which has no MMP state at all, so this branch needs its own coverage:
    // a guard placed on the apply rather than ahead of it would miss it.
    let mut node = make_node();

    let remote = Identity::generate();
    install_initiating(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    let inner = build_mtu_exceeded_inner(&dest, &reporter, 800);
    node.handle_mtu_exceeded(&reporter, &inner).await;
    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        None,
        "nothing this node sent could have overflowed a hop at 800 bytes"
    );

    // A SessionSetup can itself be the datagram that overflows a hop, so an
    // initiating session must still be able to act on a real report.
    note_sent_wire_len(&mut node, &dest, 1400);
    node.handle_mtu_exceeded(&reporter, &inner).await;
    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        Some(800),
        "a report corroborated by an oversized send must still be applied"
    );
}

/// The MMP state of an established session installed by
/// `install_established_session_with_mmp`, for driving its path MTU directly.
fn session_mmp<'a>(
    node: &'a mut Node,
    dest: &NodeAddr,
) -> &'a mut crate::proto::mmp::MmpSessionState {
    node.sessions
        .get_mut(dest)
        .and_then(|e| e.mmp_mut())
        .expect("session with MMP must exist")
}

#[tokio::test]
async fn an_above_estimate_mtu_exceeded_does_not_count_toward_a_path_mtu_increase() {
    // A reactive MtuExceeded is unauthenticated and can only ever describe a
    // hop that is too small. Fed into the destination's two-way notification
    // path, an above-estimate value became one step of the increase ladder, so
    // anyone on the mesh supplied a third of an increase that only the
    // destination may drive.
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    session_mmp(&mut node, &dest).path_mtu.seed_source_mtu(1200);

    note_sent_wire_len(&mut node, &dest, 1400);
    let t0 = crate::time::mono_ms();
    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1300);
    node.handle_mtu_exceeded(&reporter, &inner).await;

    let path_mtu = &mut session_mmp(&mut node, &dest).path_mtu;
    path_mtu.apply_notification(1300, t0 + 10_000);
    path_mtu.apply_notification(1300, t0 + 25_000);

    assert_eq!(
        path_mtu.current_mtu(),
        1200,
        "two notifications are not an increase; the reactive report must not be the third"
    );
}

#[tokio::test]
async fn an_above_estimate_mtu_exceeded_does_not_reset_a_notification_driven_increase() {
    // The destination is building an honest increase to 1400. A different
    // above-estimate value from anywhere on the mesh used to replace the
    // pending value and restart the ladder, holding the estimate down.
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);

    let path_mtu = &mut session_mmp(&mut node, &dest).path_mtu;
    path_mtu.seed_source_mtu(1200);
    path_mtu.apply_notification(1400, 0);
    path_mtu.apply_notification(1400, 10_000);

    note_sent_wire_len(&mut node, &dest, 1400);
    let inner = build_mtu_exceeded_inner(&dest, &reporter, 1300);
    node.handle_mtu_exceeded(&reporter, &inner).await;

    let path_mtu = &mut session_mmp(&mut node, &dest).path_mtu;
    path_mtu.apply_notification(1400, 25_000);
    assert_eq!(
        path_mtu.current_mtu(),
        1400,
        "the third matching notification must complete the increase the reactive report interrupted"
    );
}

#[tokio::test]
async fn an_above_estimate_mtu_exceeded_does_not_spend_the_evidence_an_honest_decrease_needs() {
    // A report that changes nothing must not consume the sent-frame evidence,
    // or the honest report that follows it is refused as uncorroborated.
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    session_mmp(&mut node, &dest).path_mtu.seed_source_mtu(1200);

    note_sent_wire_len(&mut node, &dest, 1400);
    let above = build_mtu_exceeded_inner(&dest, &reporter, 1300);
    node.handle_mtu_exceeded(&reporter, &above).await;
    let below = build_mtu_exceeded_inner(&dest, &reporter, 1100);
    node.handle_mtu_exceeded(&reporter, &below).await;

    assert_eq!(
        session_mmp(&mut node, &dest).path_mtu.current_mtu(),
        1100,
        "the honest decrease must apply on the evidence the ignored report left unspent"
    );
    assert_eq!(
        node.metrics().errors.mtu_exceeded_uncorroborated.get(),
        0,
        "the honest decrease must not be refused as uncorroborated"
    );
}

#[tokio::test]
async fn a_second_reactive_decrease_needs_its_own_corroborating_send() {
    // The evidence is spent on the decrease it vouched for. Otherwise one
    // large send early in a session would vouch for every forged report for
    // the rest of that session's life.
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);

    note_sent_wire_len(&mut node, &dest, 1400);
    let first = build_mtu_exceeded_inner(&dest, &reporter, 1200);
    node.handle_mtu_exceeded(&reporter, &first).await;
    assert_eq!(
        node.sessions
            .get(&dest)
            .and_then(|e| e.mmp())
            .map(|m| m.path_mtu.current_mtu()),
        Some(1200),
        "the corroborated first decrease is accepted"
    );

    let second = build_mtu_exceeded_inner(&dest, &reporter, 600);
    node.handle_mtu_exceeded(&reporter, &second).await;
    assert_eq!(
        node.sessions
            .get(&dest)
            .and_then(|e| e.mmp())
            .map(|m| m.path_mtu.current_mtu()),
        Some(1200),
        "a further decrease needs evidence of its own"
    );

    // A genuine re-route onto a smaller hop is preceded by a send that hop
    // drops, so the honest sequence still converges.
    note_sent_wire_len(&mut node, &dest, 900);
    node.handle_mtu_exceeded(&reporter, &second).await;
    assert_eq!(
        node.sessions
            .get(&dest)
            .and_then(|e| e.mmp())
            .map(|m| m.path_mtu.current_mtu()),
        Some(600),
        "once this node has again sent something that does not fit, the report applies"
    );
}

#[tokio::test]
async fn a_corroborated_report_below_the_reactive_floor_is_still_refused() {
    // Corroboration and the floor are independent refusals. A hop that really
    // is tiny still cannot drive the clamp into the band where the derived
    // MSS degenerates.
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    note_sent_wire_len(&mut node, &dest, 1400);
    let inner = build_mtu_exceeded_inner(
        &dest,
        &reporter,
        crate::proto::mmp::MIN_REACTIVE_PATH_MTU - 1,
    );
    node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(node.path_mtu_lookup_get(&dest_fips), None);
    assert_eq!(node.metrics().errors.mtu_exceeded_below_floor.get(), 1);
    assert_eq!(node.metrics().errors.mtu_exceeded_uncorroborated.get(), 0);
}

#[tokio::test]
async fn the_authenticated_path_mtu_notification_still_applies_at_the_actionable_floor() {
    // The reactive guards must not leak onto the carrier that arrives inside
    // an established session on the decrypted path, which is authenticated and
    // needs no corroboration.
    let mut node = make_node();

    let remote = Identity::generate();
    install_established_session_with_mmp(&mut node, &remote);
    let dest = *remote.node_addr();

    let floor = crate::proto::mmp::MIN_ACTIONABLE_PATH_MTU;
    let body = build_path_mtu_notification_body(floor);
    node.handle_session_path_mtu_notification(&dest, &body);

    assert_eq!(
        node.sessions
            .get(&dest)
            .and_then(|e| e.mmp())
            .map(|m| m.path_mtu.current_mtu()),
        Some(floor),
        "the authenticated carrier still applies a value at the actionable floor"
    );
}

#[tokio::test]
async fn a_path_broken_flood_releases_the_stored_path_mtu_only_once_per_interval() {
    use crate::proto::routing::PathBroken;

    // PathBroken is unauthenticated and its release discards a bottleneck this
    // node learned the hard way. Unlimited, the claim can be repeated as fast
    // as it can be sent, so a genuinely learned value never survives.
    let mut node = make_node();

    let remote = Identity::generate();
    install_initiating(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);

    let encoded = PathBroken::new(dest, reporter).encode();
    let inner = &encoded[5..];

    node.path_mtu_lookup_insert(dest_fips, 700);
    node.handle_path_broken(&reporter, &reporter, inner).await;
    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        None,
        "the first PathBroken still releases"
    );

    node.path_mtu_lookup_insert(dest_fips, 700);
    node.handle_path_broken(&reporter, &reporter, inner).await;
    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        Some(700),
        "a second release for the same destination inside the interval is refused"
    );
}

/// Session data whose next hop's encrypt worker has exited is still
/// delivered, sealed on the main loop with the FSP and FMP counters the
/// worker path reserved.
#[cfg(unix)]
mod dead_encrypt_worker {
    use super::*;
    use crate::config::UdpConfig;
    use crate::node::tests::pool_with_dead_worker_for;
    use crate::transport::udp::UdpTransport;
    use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};

    /// A test node on a real UDP socket: the worker path needs one.
    async fn make_test_node_udp() -> TestNode {
        let mut node = make_node();
        let transport_id = TransportId::new(1);
        let config = UdpConfig {
            bind_addr: Some("127.0.0.1:0".to_string()),
            mtu: Some(1280),
            ..Default::default()
        };
        let (packet_tx, packet_rx) = packet_channel(256);
        let mut transport = UdpTransport::new(transport_id, None, config, packet_tx);
        transport.start_async().await.unwrap();
        let addr = TransportAddr::from_string(&transport.local_addr().unwrap().to_string());
        node.transports
            .insert(transport_id, TransportHandle::Udp(transport));
        TestNode {
            node,
            transport_id,
            packet_rx: crate::node::tests::spanning_tree::bridge_to_unbounded(packet_rx),
            addr,
        }
    }

    fn fsp_send_counter(node: &Node, dest: &NodeAddr) -> u64 {
        let entry = node.get_session(dest).expect("session");
        assert!(entry.is_established(), "session not established");
        entry.send_counter()
    }

    fn fmp_send_counter(node: &Node, peer: &NodeAddr) -> u64 {
        node.get_peer(peer)
            .expect("peer")
            .noise_session()
            .expect("link session")
            .current_send_counter()
    }

    #[tokio::test]
    async fn session_data_for_a_dead_workers_next_hop_is_still_delivered() {
        let mut nodes = vec![make_test_node_udp().await, make_test_node_udp().await];
        initiate_handshake(&mut nodes, 0, 1).await;
        drain_all_packets(&mut nodes, false).await;
        verify_tree_convergence(&nodes);
        populate_all_coord_caches(&mut nodes);
        establish_pair_session(&mut nodes).await;
        drain_all_packets(&mut nodes, false).await;

        let node0 = *nodes[0].node.node_addr();
        let node1 = *nodes[1].node.node_addr();
        let dest: std::net::SocketAddr = nodes[1].addr.to_string().parse().unwrap();
        let pool = pool_with_dead_worker_for(dest);
        nodes[0].node.supervisor.encrypt_workers = Some(pool.clone());

        let fsp_before = fsp_send_counter(&nodes[0].node, &node1);
        let fmp_before = fmp_send_counter(&nodes[0].node, &node1);
        let recv_before = nodes[1]
            .node
            .get_session(&node0)
            .unwrap()
            .traffic_counters()
            .1;

        nodes[0]
            .node
            .send_session_data(&node1, 0, 0, b"for a dead worker")
            .await
            .expect("send_session_data");
        // Read before anything else runs on A: one packet, one counter each.
        assert_eq!(fsp_send_counter(&nodes[0].node, &node1), fsp_before + 1);
        assert_eq!(fmp_send_counter(&nodes[0].node, &node1), fmp_before + 1);
        assert_eq!(pool.liveness().refused_dispatches(), 1);

        let delivered = |nodes: &[TestNode]| {
            nodes[1]
                .node
                .get_session(&node0)
                .unwrap()
                .traffic_counters()
                .1
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while delivered(&nodes) == recv_before && tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
            process_available_packets(&mut nodes).await;
        }
        assert_eq!(
            delivered(&nodes),
            recv_before + 1,
            "the payload never reached the destination"
        );

        cleanup_nodes(&mut nodes).await;
    }
}

// ============================================================================
// A forged SessionSetup holding a half-open entry for an address it claims
// ============================================================================
//
// A SessionSetup's msg1 is a bare ephemeral and its source address is an
// envelope field, so any node that can get a datagram to the victim can
// name the address of a node it is not. These tests have the victim receive
// one such setup naming its real neighbour (the owner of that address), and
// then show what the half-open entry it leaves does to the owner's setup, to
// the victim's own initiation, and to the victim's own traffic.

/// A SessionSetup addressed to `victim` from an unrelated identity, carrying
/// `claimed`'s coordinates so the ack has a route toward the address it names.
fn forge_setup_naming(claimed: &TestNode, victim: &TestNode) -> Vec<u8> {
    use crate::noise::HandshakeState;
    use crate::proto::fsp::SessionSetup;

    let forger = Identity::generate();
    let mut handshake = HandshakeState::new_initiator(forger.keypair());
    handshake.set_local_epoch([0xA5; 8]);
    let msg1 = handshake.write_message_1().expect("forged msg1 must build");

    SessionSetup::new(
        claimed.node.tree_state().my_coords().clone(),
        victim.node.tree_state().my_coords().clone(),
    )
    .with_handshake(msg1)
    .encode()
}

/// Deliver a forged setup naming `nodes[claimed]` to `nodes[victim]`, over
/// the link from the claimed node (the forger's datagram reaches the victim
/// through its neighbour).
async fn deliver_forged_setup_naming(nodes: &mut [TestNode], claimed: usize, victim: usize) {
    let claimed_addr = *nodes[claimed].node.node_addr();
    let forged = forge_setup_naming(&nodes[claimed], &nodes[victim]);
    nodes[victim]
        .node
        .handle_session_payload(&claimed_addr, &claimed_addr, &forged, 1280, false)
        .await;
    assert!(
        nodes[victim]
            .node
            .get_session(&claimed_addr)
            .is_some_and(|e| !e.is_established()),
        "the forged setup must have left a half-open entry, or the test is not \
         exercising it"
    );
}

#[tokio::test]
async fn a_forged_setup_does_not_stop_the_owners_setup_completing() {
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let victim_addr = *nodes[1].node.node_addr();
    let victim_pubkey = nodes[1].node.identity().pubkey_full();

    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    // The ack built for the forger's ephemeral reaches the owner, which has
    // no handshake toward the victim yet and drops it.
    drain_to_quiescence(&mut nodes).await;

    nodes[0]
        .node
        .initiate_session(victim_addr, victim_pubkey)
        .await
        .expect("the owner's initiation must start");
    drain_to_quiescence(&mut nodes).await;

    let owner_ack_failures = nodes[0].node.stats().session.ack_handshake_failed;
    assert!(
        nodes[0]
            .node
            .get_session(&victim_addr)
            .is_some_and(|e| e.is_established()),
        "the owner's own setup must complete despite the forged setup naming \
         its address; acks the owner could not read: {}",
        owner_ack_failures
    );
    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "the victim must reach Established with the owner"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn losing_the_initiation_tie_break_to_a_forged_setup_keeps_our_handshake() {
    let mut nodes = make_routable_pair().await;
    // The victim is the node with the larger address: it loses the
    // simultaneous-initiation tie-break to any setup naming the other.
    let (owner, victim) = if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    };
    let owner_addr = *nodes[owner].node.node_addr();
    let owner_pubkey = nodes[owner].node.identity().pubkey_full();
    assert!(
        nodes[victim].node.node_addr() > &owner_addr,
        "the victim must be the side with the larger address"
    );

    // The victim initiates toward the owner; its setup is in flight.
    nodes[victim]
        .node
        .initiate_session(owner_addr, owner_pubkey)
        .await
        .expect("the victim's initiation must start");
    assert!(
        nodes[victim]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_initiating()),
        "the victim must be initiating before the forgery arrives"
    );

    // Before the owner's ack comes back, a forged setup naming the owner.
    deliver_forged_setup_naming(&mut nodes, owner, victim).await;

    // The owner answers the victim's genuine setup.
    drain_to_quiescence(&mut nodes).await;

    let victim_entry = nodes[victim].node.get_session(&owner_addr);
    assert!(
        victim_entry.is_some_and(|e| e.is_established()),
        "the victim's own handshake must complete when the owner answers it, \
         whatever a forged setup naming the owner did meanwhile; the victim's \
         entry is {}",
        match victim_entry {
            None => "gone",
            Some(e) if e.is_initiating() => "initiating",
            Some(e) if e.is_awaiting_msg3() => "awaiting msg3 (the forger's half-open entry)",
            Some(_) => "in another state",
        }
    );

    cleanup_nodes(&mut nodes).await;
}

/// A setup naming an address, forged or genuine, never holds this node's
/// own first handshake toward that address back: outbound traffic behind the
/// session the setup opened sends this node's own setup at once, through
/// the TUN path and the native API alike, and the session completes.
#[tokio::test]
async fn outbound_traffic_behind_a_forged_half_open_session_sends_its_own_setup_at_once() {
    // TUN: the victim's own packet to the owner, behind a session a forged
    // setup opened a moment ago.
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let victim_addr = *nodes[1].node.node_addr();

    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    drain_to_quiescence(&mut nodes).await;

    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.supervisor.ipv6tun.tun_tx = Some(tun_tx);

    let src_fips = crate::Ipv6Address::from_node_addr(&victim_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&owner_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, b"behind a forged half-open entry");
    nodes[1].node.handle_tun_outbound(ipv6_packet.clone()).await;
    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_initiating() && e.candidate_count() == 1),
        "the victim's own setup must go out at once, beside the forged setup's candidate"
    );
    drain_to_quiescence(&mut nodes).await;

    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "the victim's own traffic to the owner must start a session of its own \
         instead of waiting behind a half-open session nobody will complete; \
         packets delivered to the owner: {}",
        delivered.len()
    );
    assert_eq!(
        delivered,
        vec![ipv6_packet],
        "the queued packet must reach the owner"
    );
    cleanup_nodes(&mut nodes).await;

    // Native: the same through the native API's send path.
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let owner_xonly = nodes[0].node.identity().pubkey();

    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    drain_to_quiescence(&mut nodes).await;

    let flow = crate::native::registry::FlowKey {
        peer: owner_addr,
        remote: 7000,
        local: 7001,
    };
    nodes[1]
        .node
        .handle_native_outbound(flow, owner_xonly, b"native behind a forged entry".to_vec())
        .await;
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "the victim's own native datagram to the owner must start a session of \
         its own behind a half-open session"
    );
    assert!(
        !nodes[1].node.pending_native.contains_key(&owner_addr),
        "the held native datagram must have been sent once the session established"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_responder_that_receives_one_setup_sends_exactly_one_ack_across_the_handshake_timeout() {
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let timeout_ms = nodes[1]
        .node
        .config()
        .node
        .rate_limit
        .handshake_timeout_secs
        * 1000;

    // Every SessionAck the responder emits goes out through
    // `send_session_datagram`, the only thing that moves this counter on a
    // node with no transit traffic and no established session.
    let originated_before = nodes[1].node.metrics().forwarding.originated_packets.get();
    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    let t0 = Node::session_now();

    // Poll the session across the candidate's whole lifetime and past it,
    // with no further setup arriving.
    let mut now = t0;
    while now <= session_after(t0, timeout_ms.max(40_000) + 1_000) {
        now = session_after(now, 250);
        nodes[1].node.poll_session_rekeys(now).await;
    }
    assert!(
        nodes[1].node.get_session(&owner_addr).is_none(),
        "the half-open session must have ended, so the whole lifetime was run"
    );

    let acks = nodes[1].node.metrics().forwarding.originated_packets.get() - originated_before;
    assert_eq!(
        acks, 1,
        "a responder must send one SessionAck per setup it receives, not \
         resend it on its own timer toward an address the setup named"
    );

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Candidates, this node's own initiation, and one ack per setup
// ============================================================================
//
// A setup is unauthenticated, so the session it opens holds one candidate
// per distinct msg1 and neither silences another setup nor holds back this
// node's own attempt, and only an authenticated msg3 decides between
// crossing handshakes. These tests drive those rules through the node and
// the healthy paths they must leave working.

/// The index of the node with the smaller address and of the one with the
/// larger.
fn by_address(nodes: &[TestNode]) -> (usize, usize) {
    if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    }
}

/// How many candidates `nodes[i]`'s session for `addr` holds.
fn candidates_at(nodes: &[TestNode], i: usize, addr: &NodeAddr) -> usize {
    nodes[i]
        .node
        .get_session(addr)
        .map_or(0, |e| e.candidate_count())
}

/// Discard everything queued at `nodes[i]`, standing for packets lost.
fn lose_queued(nodes: &mut [TestNode], i: usize) -> usize {
    std::iter::from_fn(|| nodes[i].packet_rx.try_recv().ok()).count()
}

/// A msg3 that proves its own candidate forged, by authenticating a key the
/// claimed address is not derived from, drops only that candidate: the
/// owner's candidate beside it stays and its msg3 completes the session.
#[tokio::test]
async fn a_forger_completing_its_own_candidate_does_not_drop_the_owners() {
    let mut node = make_node();
    let owner = Identity::generate();
    let forger = Identity::generate();
    let owner_addr = *owner.node_addr();
    let now = Node::session_now();

    let (mut entry, forger_msg3) = drive_xx_to_msg3(&node, owner_addr, &forger, now);
    let owner_msg3 = hold_another_setup(&node, &mut entry, &owner, now);
    assert_eq!(
        entry.candidate_count(),
        2,
        "precondition: both setups are held"
    );
    node.sessions.insert(owner_addr, entry);

    // The forger completes its own candidate, with its own static key.
    node.handle_session_payload(
        &owner_addr,
        &stub_link_peer(),
        &SessionMsg3::new(forger_msg3).encode(),
        1280,
        false,
    )
    .await;
    assert_eq!(
        node.stats().session.addr_mismatch,
        1,
        "precondition: the forger's msg3 authenticated with a key that does \
         not derive the address"
    );
    assert_eq!(
        node.get_session(&owner_addr).map(|e| e.candidate_count()),
        Some(1),
        "a msg3 proving one candidate forged must drop only that candidate"
    );

    node.handle_session_payload(
        &owner_addr,
        &stub_link_peer(),
        &SessionMsg3::new(owner_msg3).encode(),
        1280,
        false,
    )
    .await;
    assert!(
        node.get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "the owner's own msg3 must still complete its candidate"
    );
}

/// Hold a setup `initiator` writes to `node` in `entry`, beside what it
/// holds, at `now` and over a link of its own, and return the msg3 the
/// initiator writes on the ack.
fn hold_another_setup(
    node: &Node,
    entry: &mut crate::node::session::SessionEntry,
    initiator: &Identity,
    now: crate::node::session::SessionInstant,
) -> Vec<u8> {
    let mut hs = crate::noise::HandshakeState::new_initiator(initiator.keypair());
    hs.set_local_epoch([0x5A; 8]);
    let msg1 = hs.write_message_1().unwrap();
    let opening = !entry.is_established();
    let carrier = NodeAddr::from_bytes([0xCD; 16]);
    let ack = entry
        .step_setup(
            &msg1,
            carrier,
            crate::proto::stp::TreeCoordinate::root(carrier),
            now,
            &node.session_node_keys(),
        )
        .into_iter()
        .find_map(|o| match o {
            fips_core::proto::rekey::Output::Send { msg, .. } => Some(msg),
            _ => None,
        })
        .expect("the setup is held and acknowledged");
    xx_msg3(&hs, &ack, opening)
}

/// A forger's msg3 for its own candidate, followed by bytes that are not an
/// encrypted negotiation payload, completes nothing and drops nothing: the
/// owner's candidate beside it still completes on the owner's msg3.
#[tokio::test]
async fn a_forged_msg3_with_an_undecryptable_negotiation_payload_keeps_the_owners_candidate() {
    let mut node = make_node();
    let owner = Identity::generate();
    let forger = Identity::generate();
    let owner_addr = *owner.node_addr();
    let now = Node::session_now();

    let (mut entry, forger_msg3) = drive_xx_to_msg3(&node, owner_addr, &forger, now);
    let owner_msg3 = hold_another_setup(&node, &mut entry, &owner, now);
    assert_eq!(entry.candidate_count(), 2, "precondition: both setups held");
    node.sessions.insert(owner_addr, entry);

    let mut bad = forger_msg3[..crate::noise::HANDSHAKE_MSG3_SIZE].to_vec();
    bad.extend_from_slice(&[0xAA; 40]);
    node.handle_session_payload(
        &owner_addr,
        &stub_link_peer(),
        &SessionMsg3::new(bad).encode(),
        1280,
        false,
    )
    .await;
    assert_eq!(
        node.get_session(&owner_addr).map(|e| e.candidate_count()),
        Some(2),
        "a forged msg3 for one candidate must not drop the owner's candidate"
    );

    node.handle_session_payload(
        &owner_addr,
        &stub_link_peer(),
        &SessionMsg3::new(owner_msg3).encode(),
        1280,
        false,
    )
    .await;
    assert!(
        node.get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "the owner's msg3 must still complete its candidate"
    );
}

/// A forger's msg3 with an undecryptable negotiation payload, for a
/// candidate held beside this node's own first attempt, leaves that attempt
/// in flight.
#[tokio::test]
async fn a_forged_msg3_with_an_undecryptable_negotiation_payload_keeps_our_initiator_leg() {
    let mut nodes = make_routable_pair().await;
    let (owner, victim) = by_address(&nodes);
    let owner_addr = *nodes[owner].node.node_addr();
    let owner_pubkey = nodes[owner].node.identity().pubkey_full();
    nodes[victim]
        .node
        .initiate_session(owner_addr, owner_pubkey)
        .await
        .expect("initiate");

    let forger = Identity::generate();
    let mut entry = nodes[victim].node.sessions.remove(&owner_addr).unwrap();
    let forger_msg3 = hold_another_setup(
        &nodes[victim].node,
        &mut entry,
        &forger,
        Node::session_now(),
    );
    nodes[victim].node.sessions.insert(owner_addr, entry);

    let mut bad = forger_msg3[..crate::noise::HANDSHAKE_MSG3_SIZE].to_vec();
    bad.extend_from_slice(&[0xAA; 40]);
    nodes[victim]
        .node
        .handle_session_payload(
            &owner_addr,
            &stub_link_peer(),
            &SessionMsg3::new(bad).encode(),
            1280,
            false,
        )
        .await;
    let entry = nodes[victim]
        .node
        .get_session(&owner_addr)
        .expect("the session must survive the forged msg3");
    assert!(
        entry.is_initiating(),
        "a forged msg3 for a candidate must not drop our own attempt"
    );
    assert_eq!(entry.candidate_count(), 1, "the forger's candidate is kept");

    cleanup_nodes(&mut nodes).await;
}

/// A first-handshake SessionAck whose negotiation payload does not decrypt,
/// at an initiator that also holds a candidate, changes nothing: no msg3 is
/// sent, and the attempt, its timers and the candidate stay as they were.
///
/// Every failure inside the profile's reply, a payload that will not
/// decrypt or seal among them, takes the one path a refused reply takes, so
/// this drives that path through the failure the wire can cause at the same
/// step.
#[tokio::test]
async fn negotiation_failure_keeps_candidates() {
    let mut nodes = make_routable_pair().await;
    let (owner, victim) = by_address(&nodes);
    let owner_addr = *nodes[owner].node.node_addr();
    let victim_addr = *nodes[victim].node.node_addr();
    let owner_pubkey = nodes[owner].node.identity().pubkey_full();
    nodes[victim]
        .node
        .initiate_session(owner_addr, owner_pubkey)
        .await
        .expect("initiate");
    let msg1 = take_queued_setup_msg1(&mut nodes, owner, &victim_addr).await;

    // A setup claiming the owner's address held beside the attempt.
    let mut entry = nodes[victim].node.sessions.remove(&owner_addr).unwrap();
    let _ = hold_another_setup(
        &nodes[victim].node,
        &mut entry,
        &Identity::generate(),
        Node::session_now(),
    );
    nodes[victim].node.sessions.insert(owner_addr, entry);
    let entry = nodes[victim].node.get_session(&owner_addr).unwrap();
    assert!(entry.is_initiating() && entry.candidate_count() == 1);
    let wake = entry.next_wake();
    let originated = nodes[victim]
        .node
        .metrics()
        .forwarding
        .originated_packets
        .get();

    // The owner's genuine msg2, its negotiation payload replaced by zeroes.
    let ack = answer_in_flight_msg1(
        &nodes[victim].node,
        &msg1,
        nodes[owner].node.identity(),
        false,
    );
    nodes[victim]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &ack, 1280, false)
        .await;

    let entry = nodes[victim].node.get_session(&owner_addr).unwrap();
    assert_eq!(
        nodes[victim]
            .node
            .metrics()
            .forwarding
            .originated_packets
            .get(),
        originated,
        "no msg3 may be sent on an ack whose payload does not decrypt"
    );
    assert!(entry.is_initiating(), "the attempt must stay in flight");
    assert_eq!(
        entry.next_wake(),
        wake,
        "the attempt's timers must not move"
    );
    assert_eq!(entry.candidate_count(), 1, "the candidate must be kept");
    assert_eq!(nodes[victim].node.stats().session.ack_handshake_failed, 1);

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn forged_setups_inside_the_minimum_age_are_refused_and_the_owner_still_completes() {
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let victim_addr = *nodes[1].node.node_addr();
    let victim_pubkey = nodes[1].node.identity().pubkey_full();

    // The owner's genuine setup reaches the victim and is answered; the ack
    // is still on its way back.
    nodes[0]
        .node
        .initiate_session(victim_addr, victim_pubkey)
        .await
        .expect("the owner's initiation must start");
    let setup = nodes[1]
        .packet_rx
        .try_recv()
        .expect("precondition: the owner's setup is queued at the victim");
    nodes[1].node.handle_encrypted_frame(setup).await;
    assert_eq!(
        candidates_at(&nodes, 1, &owner_addr),
        1,
        "precondition: the owner's setup holds a candidate"
    );

    // Four forged setups over the owner's own link, all inside the minimum
    // age.
    for _ in 0..4 {
        deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    }
    assert_eq!(
        candidates_at(&nodes, 1, &owner_addr),
        2,
        "the link's quota of two fills and the forgeries past it are refused"
    );

    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "a forger flooding setups inside the minimum age must not evict the \
         owner's candidate before its msg3 arrives"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn adding_a_candidate_to_an_existing_entry_checks_the_half_open_share() {
    let configs = (0..2)
        .map(|_| {
            let mut config = Config::new();
            // A half-open share of two.
            config.node.limits.max_sessions = 4;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    populate_all_coord_caches(&mut nodes);
    let owner_addr = *nodes[0].node.node_addr();

    let first = forge_setup_naming(&nodes[0], &nodes[1]);
    nodes[1]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &first, 1280, false)
        .await;
    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    assert_eq!(
        candidates_at(&nodes, 1, &owner_addr),
        2,
        "precondition: two candidates fill the half-open share"
    );
    let refused_before = nodes[1].node.stats().session.half_open_full;

    // A third, over another link, so the link's own quota of two is not
    // what refuses it.
    let forged = forge_setup_naming(&nodes[0], &nodes[1]);
    let other_link = NodeAddr::from_bytes([0xCC; 16]);
    nodes[1]
        .node
        .handle_session_payload(&owner_addr, &other_link, &forged, 1280, false)
        .await;

    assert_eq!(
        candidates_at(&nodes, 1, &owner_addr),
        2,
        "a candidate joining an existing entry must count toward the half-open \
         share like one opening an entry"
    );
    assert_eq!(
        nodes[1].node.stats().session.half_open_full - refused_before,
        1,
        "the refusal must be counted"
    );

    // A copy of a held setup takes no new place of the share: it still draws
    // the ack its candidate stored, which is how a lost ack is recovered.
    let originated = nodes[1].node.metrics().forwarding.originated_packets.get();
    nodes[1]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &first, 1280, false)
        .await;
    assert_eq!(
        (
            nodes[1].node.metrics().forwarding.originated_packets.get() - originated,
            nodes[1].node.stats().session.half_open_full - refused_before,
        ),
        (1, 1),
        "a copy of a held setup must draw its stored ack under a full share"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_signal_for_our_initiation_beside_a_forged_candidate_is_admitted() {
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let owner_pubkey = nodes[0].node.identity().pubkey_full();

    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    nodes[1]
        .node
        .initiate_session(owner_addr, owner_pubkey)
        .await
        .expect("the victim's initiation must start");
    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_initiating() && e.candidate_count() > 0),
        "precondition: our leg sits beside the forged candidate"
    );

    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&owner_addr);
    let refused_before = nodes[1].node.metrics().errors.unbound.mtu.get();
    note_sent_wire_len(&mut nodes[1].node, &owner_addr, 1400);
    let inner = build_mtu_exceeded_inner(&owner_addr, &reporter, 1234);
    nodes[1].node.handle_mtu_exceeded(&reporter, &inner).await;

    assert_eq!(
        nodes[1].node.metrics().errors.unbound.mtu.get(),
        refused_before,
        "a signal about a session this node initiated must be admitted though \
         a forged candidate shares its entry"
    );
    assert_eq!(
        nodes[1].node.path_mtu_lookup_get(&dest_fips),
        Some(1234),
        "the admitted signal must seed the clamp with the reported value"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Both nodes initiate at once and their setups cross. Returns the indices
/// of the tie-break winner and loser, after one pass in which each has read
/// the other's setup.
async fn cross_setups(nodes: &mut [TestNode]) -> (usize, usize) {
    let (winner, loser) = by_address(nodes);
    for (from, to) in [(winner, loser), (loser, winner)] {
        let addr = *nodes[to].node.node_addr();
        let pubkey = nodes[to].node.identity().pubkey_full();
        nodes[from]
            .node
            .initiate_session(addr, pubkey)
            .await
            .expect("initiation must start");
    }
    process_available_packets(nodes).await;
    (winner, loser)
}

/// Both nodes open the session at once and their setups cross. The smaller
/// node refuses the larger's setup while its own attempt is young; the
/// larger holds the smaller's setup as a candidate beside its own attempt
/// and answers it; the smaller completes on that answer, and its msg3
/// completes the larger's candidate, which yields its own attempt. The pair
/// settles on one session, and the larger's attempt sends nothing more.
#[tokio::test]
async fn simultaneous_initiation_converges_with_no_rekey_armed() {
    let mut nodes = make_routable_pair().await;
    let (winner, loser) = cross_setups(&mut nodes).await;
    let winner_addr = *nodes[winner].node.node_addr();
    let loser_addr = *nodes[loser].node.node_addr();
    assert!(
        nodes[loser]
            .node
            .get_session(&winner_addr)
            .is_some_and(|e| e.is_initiating() && e.candidate_count() == 1),
        "precondition: the larger node answered the smaller's setup beside its own attempt"
    );
    assert!(
        nodes[winner]
            .node
            .get_session(&loser_addr)
            .is_some_and(|e| e.is_initiating() && e.candidate_count() == 0),
        "precondition: the smaller node refused the larger's young setup"
    );

    drain_to_quiescence(&mut nodes).await;
    // The larger node's resend schedule reaches its rungs: its attempt is
    // gone, so nothing is sent.
    nodes[loser]
        .node
        .poll_session_rekeys(session_after(Node::session_now(), 8_000))
        .await;
    drain_to_quiescence(&mut nodes).await;

    for i in [winner, loser] {
        let other = *nodes[1 - i].node.node_addr();
        let entry = nodes[i].node.get_session(&other).expect("entry present");
        assert!(entry.is_established(), "node {i} must be established");
        assert!(
            entry.candidate_count() == 0 && entry.pending_new_session().is_none(),
            "node {i} must hold no rekey: a setup of the loser's reaching \
             the established winner arms a spurious one"
        );
    }
    assert_eq!(
        (
            nodes[winner].node.stats().session.rekey_armed,
            nodes[loser].node.stats().session.rekey_armed
        ),
        (0, 0),
        "no setup may reach an established end"
    );
    assert!(
        session_frame_decodes(&mut nodes, winner, loser).await
            && session_frame_decodes(&mut nodes, loser, winner).await,
        "both ends must hold the same keys"
    );
    cleanup_nodes(&mut nodes).await;
}

/// The initiator's first msg3 is lost; the responder, with traffic of its
/// own, opens its own attempt beside the candidate it holds; the
/// initiator's msg3 copy then completes that candidate while the
/// responder's attempt is unanswered, which yields. Both ends hold one
/// epoch, whatever the initiator did with the responder's setup.
#[tokio::test]
async fn a_late_msg3_after_this_node_initiated_leaves_one_established_epoch() {
    let mut nodes = make_routable_pair().await;
    let (initiator, responder) = (0, 1);
    let initiator_addr = *nodes[initiator].node.node_addr();
    let responder_addr = *nodes[responder].node.node_addr();
    let responder_pubkey = nodes[responder].node.identity().pubkey_full();

    nodes[initiator]
        .node
        .initiate_session(responder_addr, responder_pubkey)
        .await
        .expect("initiation must start");
    // Setup to the responder, ack back: the initiator establishes and sends
    // msg3, which is lost.
    process_available_packets(&mut nodes).await;
    process_available_packets(&mut nodes).await;
    assert!(
        nodes[initiator]
            .node
            .get_session(&responder_addr)
            .is_some_and(|e| e.is_established()),
        "precondition: the initiator is established at its end"
    );
    lose_queued(&mut nodes, responder);

    // The responder has traffic for the initiator and initiates itself
    // beside its candidate at once.
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[initiator].node.supervisor.ipv6tun.tun_tx = Some(tun_tx);
    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&responder_addr),
        &crate::Ipv6Address::from_node_addr(&initiator_addr),
        b"late msg3",
    );
    nodes[responder]
        .node
        .handle_tun_outbound(packet.clone())
        .await;
    assert!(
        nodes[responder]
            .node
            .get_session(&initiator_addr)
            .is_some_and(|e| e.is_initiating() && e.candidate_count() > 0),
        "precondition: the responder initiated beside its candidate"
    );

    // The initiator's msg3 resend arrives late.
    nodes[initiator]
        .node
        .poll_session_rekeys(session_after(Node::session_now(), 1_500))
        .await;
    drain_to_quiescence(&mut nodes).await;

    for (i, other) in [(initiator, responder_addr), (responder, initiator_addr)] {
        let entry = nodes[i].node.get_session(&other).expect("entry present");
        assert!(entry.is_established(), "node {i} must be established");
        assert!(
            entry.pending_new_session().is_none(),
            "node {i} must hold no second epoch waiting for cut-over"
        );
    }
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(
        delivered,
        vec![packet],
        "the responder's packet must arrive on the one epoch both ends hold"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A setup never cancels this node's first attempt, at the smaller address
/// too: once the attempt is no longer young, the peer's crossing setup is
/// held as a candidate beside it and answered, and the decision waits for an
/// authenticated msg3, here the peer's, which the unanswered attempt yields
/// to. The pair settles on one session.
#[tokio::test]
async fn a_setup_never_cancels_the_first_handshake_attempt_and_the_pair_converges() {
    let mut nodes = make_routable_pair().await;
    let (small, large) = by_address(&nodes);
    let small_addr = *nodes[small].node.node_addr();
    let large_addr = *nodes[large].node.node_addr();
    let small_pubkey = nodes[small].node.identity().pubkey_full();
    let large_pubkey = nodes[large].node.identity().pubkey_full();

    // The smaller node opens the session and its first setup is lost; six
    // seconds pass, past the age below which its attempt refuses a setup.
    nodes[small]
        .node
        .initiate_session(large_addr, large_pubkey)
        .await
        .expect("the smaller node's initiation must start");
    assert!(
        lose_queued(&mut nodes, large) > 0,
        "precondition: the smaller node's setup was in flight"
    );
    crate::time::advance(Duration::from_secs(6));

    // The larger node opens too; its setup reaches the smaller node.
    nodes[large]
        .node
        .initiate_session(small_addr, small_pubkey)
        .await
        .expect("the larger node's initiation must start");
    process_available_packets(&mut nodes[small..=small]).await;
    assert!(
        nodes[small]
            .node
            .get_session(&large_addr)
            .is_some_and(|e| e.is_initiating() && e.candidate_count() == 1),
        "the smaller node must keep its own attempt beside the peer's setup, \
         not give it up on its unanswered age"
    );

    drain_to_quiescence(&mut nodes).await;
    for (i, other) in [(small, large_addr), (large, small_addr)] {
        assert!(
            nodes[i]
                .node
                .get_session(&other)
                .is_some_and(|e| e.is_established()),
            "node {i} must be established"
        );
    }
    assert!(
        session_frame_decodes(&mut nodes, small, large).await
            && session_frame_decodes(&mut nodes, large, small).await,
        "the pair must share one session"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn outbound_traffic_behind_a_half_open_session_with_no_route_starts_a_lookup() {
    let (mut nodes, _a_rx, _c_rx) = line_of_three_without_cached_coords().await;
    let a = *nodes[0].node.node_addr();
    let c = *nodes[2].node.node_addr();
    install_halfopen(&mut nodes[0].node, c);

    let initiated = nodes[0].node.metrics().lookup.req_initiated.get();
    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&a),
        &crate::Ipv6Address::from_node_addr(&c),
        b"behind a half-open session",
    );
    nodes[0].node.handle_tun_outbound(packet).await;

    assert!(
        !nodes[0]
            .node
            .get_session(&c)
            .is_some_and(|e| e.is_initiating()),
        "precondition: with no coordinates for the destination the initiation \
         fails"
    );
    assert_eq!(
        nodes[0].node.metrics().lookup.req_initiated.get(),
        initiated + 1,
        "a failed initiation behind a half-open session must ask \
         discovery for a route, as it does with no entry at all"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_lost_first_ack_is_recovered_by_the_initiators_resent_setup() {
    let mut nodes = make_routable_pair().await;
    let responder_addr = *nodes[1].node.node_addr();
    let initiator_addr = *nodes[0].node.node_addr();
    let responder_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(responder_addr, responder_pubkey)
        .await
        .expect("initiation must start");
    process_available_packets(&mut nodes).await;
    // The responder's only ack is lost.
    assert!(
        lose_queued(&mut nodes, 0) > 0,
        "precondition: the responder answered"
    );

    nodes[0]
        .node
        .poll_session_rekeys(session_after(Node::session_now(), 1_500))
        .await;
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&responder_addr)
            .is_some_and(|e| e.is_established())
            && nodes[1]
                .node
                .get_session(&initiator_addr)
                .is_some_and(|e| e.is_established()),
        "the initiator's resent setup must draw the stored ack, completing the \
         session with no ack timer at the responder"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A native flow behind a half-open session, to a destination this node holds no
/// key or coordinates for: the initiation finds no route and discovery is
/// asked, so the client's key must be cached for the answer to be accepted.
#[tokio::test]
async fn a_native_send_to_an_uncached_key_behind_a_half_open_session_establishes_after_discovery() {
    use crate::native::registry::FlowKey;
    let mut nodes = run_tree_test(3, &[(0, 1), (1, 2)], false).await;
    let node2_addr = *nodes[2].node.node_addr();
    let node2_xonly = nodes[2].node.identity().pubkey();
    assert!(
        !nodes[0].node.has_cached_identity(&node2_addr),
        "precondition: node 0 must not have node 2's key cached"
    );
    assert!(
        nodes[0].node.coord_cache().get_entry(&node2_addr).is_none(),
        "precondition: node 0 has no coordinates for node 2"
    );

    // A session a forged setup opened.
    {
        let node = &mut nodes[0].node;
        let entry = crate::node::session::SessionEntry::answering_for_test(
            node2_addr,
            node.identity().keypair(),
            Node::session_now(),
        );
        node.sessions.insert(node2_addr, entry);
    }

    let lookup = &nodes[0].node.metrics().lookup;
    let initiated_before = lookup.req_initiated.get();
    let identity_miss_before = lookup.resp_identity_miss.get();

    let flow = FlowKey {
        peer: node2_addr,
        remote: 7000,
        local: 7001,
    };
    nodes[0]
        .node
        .handle_native_outbound(flow, node2_xonly, b"behind a half-open session".to_vec())
        .await;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }
    // A retransmit, after discovery has had its chance.
    nodes[0]
        .node
        .handle_native_outbound(flow, node2_xonly, b"retransmit".to_vec())
        .await;
    for _ in 0..40 {
        tokio::time::sleep(Duration::from_millis(50)).await;
        process_available_packets(&mut nodes).await;
    }

    let lookup = &nodes[0].node.metrics().lookup;
    let (initiated, identity_miss, accepted) = (
        lookup.req_initiated.get() - initiated_before,
        lookup.resp_identity_miss.get() - identity_miss_before,
        lookup.resp_accepted.get(),
    );
    let state = nodes[0].node.get_session(&node2_addr).map(|e| {
        (
            e.is_established(),
            e.is_initiating(),
            e.candidate_count() > 0,
        )
    });
    assert!(
        identity_miss == 0
            && nodes[0]
                .node
                .get_session(&node2_addr)
                .is_some_and(|e| e.is_established()),
        "discovery behind a half-open session must lead to an established session; \
         lookups initiated {initiated}, answers dropped for want of the key {identity_miss}, \
         answers accepted {accepted}, key cached {}, entry (established, initiator leg, candidates) {state:?}",
        nodes[0].node.has_cached_identity(&node2_addr)
    );
    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Session timers across a step of the system clock
// ============================================================================

/// A node holding one established session, touched now.
fn node_with_a_fresh_session(peer: &Identity) -> (Node, crate::NodeAddr) {
    let (mut node, peer_addr) = make_node_with_established_peer(peer);
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.touch(Node::session_now());
    (node, peer_addr)
}

#[test]
fn an_established_session_survives_a_forward_wall_clock_step_past_the_idle_timeout() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = node_with_a_fresh_session(&peer);
    let idle_ms = node.config().node.session.idle_timeout_secs * 1000;

    crate::time::step_wall(i64::try_from(idle_ms).unwrap() + 110_000);
    node.purge_idle_sessions(Node::session_now());

    assert!(
        node.sessions.contains_key(&peer_addr),
        "a session touched just now must not be purged because the system clock jumped ahead"
    );
}

#[test]
fn a_backward_wall_clock_step_does_not_hold_the_idle_purge() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = node_with_a_fresh_session(&peer);
    let idle_secs = node.config().node.session.idle_timeout_secs;

    crate::time::step_wall(-3_600_000);
    crate::time::advance(Duration::from_secs(idle_secs + 1));
    node.purge_idle_sessions(Node::session_now());

    assert!(
        !node.sessions.contains_key(&peer_addr),
        "a session idle for longer than the timeout must be purged although the \
         system clock stepped back"
    );
}

#[tokio::test]
async fn a_forward_wall_clock_step_does_not_trigger_the_time_based_rekey() {
    let configs = (0..2)
        .map(|_| {
            let mut config = Config::new();
            config.node.rekey.after_messages = u64::MAX;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;
    let node1_addr = *nodes[1].node.node_addr();
    let after_secs = nodes[0].node.config().node.rekey.after_secs;

    let past_trigger_secs = after_secs + crate::node::REKEY_JITTER_SECS as u64 + 65;
    crate::time::step_wall(i64::try_from(past_trigger_secs * 1000).unwrap());
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;

    assert!(
        !rekey_initiated(&nodes[0], &node1_addr),
        "a session established just now must not rekey because the system clock jumped ahead"
    );

    // Control: the same age on the monotonic clock does trigger it.
    crate::time::advance(Duration::from_secs(past_trigger_secs));
    nodes[0].node.poll_session_rekeys(Node::session_now()).await;
    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "control: a session past the rekey interval must rekey"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_path_mtu_release_is_admitted_after_a_backward_wall_clock_step() {
    use crate::node::handlers::session::PATH_MTU_RELEASE_MIN_INTERVAL;
    use crate::proto::routing::PathBroken;

    let mut node = make_node();
    let remote = Identity::generate();
    install_initiating(&mut node, &remote);
    let dest = *remote.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let dest_fips = crate::Ipv6Address::from_node_addr(&dest);
    let encoded = PathBroken::new(dest, reporter).encode();
    let inner = &encoded[5..];

    node.path_mtu_lookup_insert(dest_fips, 700);
    node.handle_path_broken(&reporter, &reporter, inner).await;
    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        None,
        "control: the first PathBroken releases"
    );

    crate::time::step_wall(-3_600_000);
    crate::time::advance(PATH_MTU_RELEASE_MIN_INTERVAL + Duration::from_millis(100));
    node.path_mtu_lookup_insert(dest_fips, 700);
    node.handle_path_broken(&reporter, &reporter, inner).await;
    assert_eq!(
        node.path_mtu_lookup_get(&dest_fips),
        None,
        "a release a full interval after the last must be admitted although the \
         system clock stepped back"
    );
}

#[tokio::test]
async fn a_coords_response_is_admitted_after_a_backward_wall_clock_step() {
    use crate::proto::routing::CoordsRequired;

    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;
    let node1_addr = *nodes[1].node.node_addr();
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let encoded = CoordsRequired::new(node1_addr, reporter).encode();
    let interval_ms = nodes[0]
        .node
        .config()
        .node
        .session
        .coords_response_interval_ms;
    // Each standalone CoordsWarmup the response sends takes one send counter.
    let sent = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .get_session(&node1_addr)
            .expect("session present")
            .send_counter()
    };

    let before = sent(&nodes);
    nodes[0]
        .node
        .handle_coords_required(&reporter, &encoded[5..])
        .await;
    assert_eq!(
        sent(&nodes),
        before + 1,
        "control: the first CoordsRequired is answered with a CoordsWarmup"
    );

    crate::time::step_wall(-3_600_000);
    crate::time::advance(Duration::from_millis(interval_ms + 100));
    nodes[0]
        .node
        .handle_coords_required(&reporter, &encoded[5..])
        .await;
    assert_eq!(
        sent(&nodes),
        before + 2,
        "a response a full interval after the last must be admitted although the \
         system clock stepped back"
    );
    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: the identity store and live sessions
// ============================================================================

/// Whether `packet` is an ICMPv6 Destination Unreachable (next header 58,
/// type 1).
fn is_icmpv6_dest_unreachable(packet: &[u8]) -> bool {
    packet.len() > 40 && packet[6] == 58 && packet[40] == 1
}

#[tokio::test]
async fn a_host_reply_to_an_established_session_peer_is_sent_after_the_identity_store_evicts_its_key()
 {
    // The identity store is bounded and evicts by age with no regard for the
    // session table, and the TUN path resolves a destination only through it.
    // Once registrations by other nodes pushed a live session peer out, the
    // host could no longer reply to traffic that peer was still delivering.
    let mut cfg1 = crate::config::Config::new();
    cfg1.node.cache.identity_size = 3;
    let configs = vec![crate::config::Config::new(), cfg1];
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // Age node 0's entry behind the registrations that follow.
    tokio::time::sleep(Duration::from_millis(5)).await;
    for _ in 0..4 {
        let other = Identity::generate();
        nodes[1]
            .node
            .register_identity(*other.node_addr(), other.pubkey_full());
    }
    assert!(
        !nodes[1].node.has_cached_identity(&node0_addr),
        "precondition: node 0's key has been evicted from node 1's store"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|s| s.is_established()),
        "precondition: node 1's session to node 0 is still established"
    );

    let (_app_outbound, node0_tun) = nodes[0].node.enable_app_owned_tun();
    let (tun_tx, node1_tun) = std::sync::mpsc::channel();
    nodes[1].node.supervisor.ipv6tun.tun_tx = Some(tun_tx);

    let src = crate::Ipv6Address::from_node_addr(&node1_addr);
    let dst = crate::Ipv6Address::from_node_addr(&node0_addr);
    let reply = build_ipv6_packet(&src, &dst, b"reply");
    nodes[1].node.handle_tun_outbound(reply.clone()).await;
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }

    let at_node1: Vec<Vec<u8>> = std::iter::from_fn(|| node1_tun.try_recv().ok()).collect();
    assert!(
        !at_node1.iter().any(|p| is_icmpv6_dest_unreachable(p)),
        "node 1 must not answer its own host's reply with Destination Unreachable"
    );
    let at_node0: Vec<Vec<u8>> = std::iter::from_fn(|| node0_tun.try_recv().ok()).collect();
    assert_eq!(
        at_node0,
        vec![reply],
        "the reply must reach node 0 on the established session"
    );
    assert!(
        nodes[1].node.has_cached_identity(&node0_addr),
        "the session's authenticated key restores node 0's entry in the store"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn the_identity_store_fallback_ignores_a_session_that_is_not_established() {
    // Only a key the session has authenticated may stand in for a store
    // entry. A session still in its handshake holds a key nobody has proven.
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();
    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|s| !s.is_established()),
        "precondition: the session is still in its handshake"
    );

    let prefix = node1_addr.prefix();
    nodes[0].node.identity_cache.remove(&prefix);

    assert_eq!(
        nodes[0].node.lookup_by_fips_prefix(&prefix),
        None,
        "a session that is not established must not answer for the store"
    );

    cleanup_nodes(&mut nodes).await;
}

#[test]
fn registering_an_identity_into_a_full_store_never_evicts_the_entry_just_registered() {
    // Eviction picks the entry with the oldest millisecond stamp. When the
    // others are stamped no older than the new one, as happens whenever
    // several registrations land in one millisecond, the minimum could be
    // the entry just inserted, so a registration could undo itself. Stamping
    // the existing entries later than now makes that the only minimum.
    let mut config = crate::config::Config::new();
    config.node.cache.identity_size = 3;
    let mut node = make_node_with(config);
    for i in 0..3u64 {
        let other = Identity::generate();
        let prefix = other.node_addr().prefix();
        node.identity_cache.insert(
            prefix,
            (*other.node_addr(), other.pubkey_full(), u64::MAX - i),
        );
    }

    let newest = Identity::generate();
    node.register_identity(*newest.node_addr(), newest.pubkey_full());

    assert_eq!(node.identity_cache.len(), 3, "the store stays at its bound");
    assert!(
        node.has_cached_identity(newest.node_addr()),
        "the entry just registered must survive its own eviction pass"
    );
}

// ============================================================================
// Characterization: the default UDP MTU across a 1280-byte forwarder
// ============================================================================

/// Build a converged three-node chain with the given MTUs and an established
/// session from node 0 to node 2, warmed past the coordinate piggyback.
async fn session_chain(mtus: [u16; 3]) -> Vec<TestNode> {
    let mut nodes = run_tree_test_with_mtus(&mtus, &[(0, 1), (1, 2)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    let c_addr = *nodes[2].node.node_addr();
    let c_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(c_addr, c_pubkey);
    nodes[0]
        .node
        .initiate_session(c_addr, c_pubkey)
        .await
        .unwrap();
    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[0].node.get_session(&c_addr).unwrap().is_established(),
        "setup: session A to C established"
    );
    let a_fips = crate::Ipv6Address::from_node_addr(nodes[0].node.node_addr());
    let c_fips = crate::Ipv6Address::from_node_addr(&c_addr);
    for _ in 0..5 {
        let small = build_ipv6_packet(&a_fips, &c_fips, &[0u8; 10]);
        nodes[0].node.handle_tun_outbound(small).await;
    }
    drain_to_quiescence(&mut nodes).await;
    nodes
}

/// A's view of the path to C: the session's path MTU and the TCP clamp's
/// lookup entry.
fn path_state(nodes: &[TestNode]) -> (u16, Option<u16>) {
    let c_addr = *nodes[2].node.node_addr();
    let c_fips = crate::Ipv6Address::from_node_addr(&c_addr);
    let entry = nodes[0].node.get_session(&c_addr).unwrap();
    let session_mtu = entry.mmp().expect("MMP state").path_mtu.current_mtu();
    (session_mtu, nodes[0].node.path_mtu_lookup_get(&c_fips))
}

/// What one 1280-byte IPv6 packet from A's TUN to C produced: the packet
/// sizes C's TUN received, A's ICMPv6 answers as (type, reported MTU), and
/// A's path state and TCP clamp toward C afterwards.
#[derive(Debug, PartialEq)]
struct Round {
    delivered: Vec<usize>,
    answers: Vec<(u8, u32)>,
    path: (u16, Option<u16>),
    clamp: u16,
}

/// Send `rounds` 1280-byte IPv6 packets from A's TUN toward C, spaced past
/// the ICMP rate limit, and record what each produced. Also returns the TCP
/// clamp toward C before the first packet.
async fn send_rounds(nodes: &mut [TestNode], rounds: usize) -> (u16, Vec<Round>) {
    let a_fips = crate::Ipv6Address::from_node_addr(nodes[0].node.node_addr());
    let c_fips = crate::Ipv6Address::from_node_addr(nodes[2].node.node_addr());
    let c_bytes = c_fips.to_ipv6().octets();
    let (a_tx, a_rx) = std::sync::mpsc::channel();
    nodes[0].node.supervisor.ipv6tun.tun_tx = Some(a_tx);
    let (c_tx, c_rx) = std::sync::mpsc::channel();
    nodes[2].node.supervisor.ipv6tun.tun_tx = Some(c_tx);
    let global = crate::ipv6tun::icmp::mss_ceiling(nodes[0].node.transport_mtu());
    let clamp = |nodes: &[TestNode]| {
        crate::ipv6tun::tun::per_flow_max_mss(&nodes[0].node.test_replica(), &c_bytes, global)
    };

    let before = clamp(nodes);
    let mut out = Vec::new();
    for _ in 0..rounds {
        let pkt = build_ipv6_packet(&a_fips, &c_fips, &[0xAB; 1240]);
        assert_eq!(pkt.len(), 1280);
        nodes[0].node.handle_tun_outbound(pkt).await;
        drain_to_quiescence(nodes).await;
        out.push(Round {
            delivered: std::iter::from_fn(|| c_rx.try_recv().ok())
                .map(|p| p.len())
                .collect(),
            answers: std::iter::from_fn(|| a_rx.try_recv().ok())
                .map(|p| (p[40], u32::from_be_bytes([p[44], p[45], p[46], p[47]])))
                .collect(),
            path: path_state(nodes),
            clamp: clamp(nodes),
        });
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    (before, out)
}

#[tokio::test]
async fn test_a_chain_of_default_udp_mtu_nodes_delivers_1280_byte_ipv6_packets_end_to_end() {
    let default_mtu = crate::config::UdpConfig::default().mtu();
    let mut nodes = session_chain([default_mtu; 3]).await;

    let (_, rounds) = send_rounds(&mut nodes, 2).await;
    for round in &rounds {
        assert_eq!(round.delivered, vec![1280], "{rounds:?}");
        assert!(round.answers.is_empty(), "{rounds:?}");
    }

    cleanup_nodes(&mut nodes).await;
}

/// Characterization, not a requirement: records what a default node does
/// toward a destination behind a forwarder whose transport MTU is 1280 (one
/// still at the old default, or set by hand). Every packet between 1204 and
/// 1280 bytes is lost on that path, as it is today: the first silently at the
/// forwarder, whose `MtuExceeded` tightens the sender's path MTU to 1280; each
/// later one answered with a Packet Too Big reporting 1203, which a host
/// ignores (RFC 8201). The TCP clamp shows which flows that reaches: a cold
/// destination clamps to 1143 and its segments fit the forwarder; one whose
/// path MTU was learned at 1357 over an all-default path clamps to 1220, so
/// a flow opened before the path changed sends 1280-byte segments that are
/// lost there, while flows opened after the `MtuExceeded` clamp to 1143.
#[tokio::test]
async fn characterize_a_default_node_behind_a_1280_byte_forwarder_loses_1280_byte_packets_and_answers_ptb_1203()
 {
    let default_mtu = crate::config::UdpConfig::default().mtu();
    let narrowed = Round {
        delivered: vec![],
        answers: vec![(2, 1203)],
        path: (1280, Some(1280)),
        clamp: 1143,
    };

    for learned in [None, Some(default_mtu)] {
        let mut nodes = session_chain([default_mtu, 1280, default_mtu]).await;
        assert_eq!(
            path_state(&nodes),
            (default_mtu, None),
            "setup: nothing learned yet"
        );
        if let Some(mtu) = learned {
            // As a discovery over an all-default path would have left it.
            let c_fips = crate::Ipv6Address::from_node_addr(nodes[2].node.node_addr());
            nodes[0].node.path_mtu_lookup_insert(c_fips, mtu);
        }

        let (before, rounds) = send_rounds(&mut nodes, 3).await;
        let expected_before = match learned {
            None => 1143,
            Some(_) => 1220,
        };
        assert_eq!(
            before, expected_before,
            "TCP clamp before, learned {learned:?}"
        );
        assert_eq!(
            rounds[0],
            Round {
                delivered: vec![],
                answers: vec![],
                path: (1280, Some(1280)),
                clamp: 1143,
            },
            "first packet, learned {learned:?}"
        );
        assert_eq!(rounds[1], narrowed, "second packet, learned {learned:?}");
        assert_eq!(rounds[2], narrowed, "third packet, learned {learned:?}");

        cleanup_nodes(&mut nodes).await;
    }
}
