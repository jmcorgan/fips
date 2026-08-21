//! End-to-end session establishment tests.

use super::*;
use crate::node::session::EndToEndState;
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, generate_random_edges, initiate_handshake,
    lock_large_network_test, make_test_node_with_config, populate_all_coord_caches,
    process_available_packets, run_tree_test, run_tree_test_with_configs, run_tree_test_with_mtus,
    run_tree_test_with_profiles, run_tree_test_with_profiles_leaf_smallest,
    verify_tree_convergence,
};
use crate::proto::fsp::{SessionAck, SessionMsg3};
use crate::proto::link::SessionDatagram;

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
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair());

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    assert!(entry.state().is_initiating());
    assert!(!entry.state().is_established());
    assert!(!entry.state().is_awaiting_msg3());
    assert_eq!(entry.created_at(), 1000);
    assert_eq!(entry.last_activity(), 1000);
}

#[test]
fn test_session_entry_rekey_jitter_in_range() {
    use crate::node::REKEY_JITTER_SECS;
    use crate::noise::HandshakeState;

    // Every newly constructed SessionEntry's jitter must lie in the
    // symmetric range [-REKEY_JITTER_SECS, +REKEY_JITTER_SECS].
    for _ in 0..100 {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let handshake = HandshakeState::new_initiator(identity_a.keypair());
        let entry = crate::node::session::SessionEntry::new(
            *identity_b.node_addr(),
            identity_b.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
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
    use crate::noise::HandshakeState;

    // Sanity check that the distribution is roughly symmetric and not
    // stuck at one extreme. With N=200 draws from a uniform ~30-second
    // range, the empirical mean should be well under 5 in absolute value.
    let mut sum: i64 = 0;
    let n: i64 = 200;
    for _ in 0..n {
        let identity_a = Identity::generate();
        let identity_b = Identity::generate();
        let handshake = HandshakeState::new_initiator(identity_a.keypair());
        let entry = crate::node::session::SessionEntry::new(
            *identity_b.node_addr(),
            identity_b.pubkey_full(),
            EndToEndState::Initiating(handshake),
            1000,
            true,
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
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.touch(2000);
    assert_eq!(entry.last_activity(), 2000);
    assert_eq!(entry.created_at(), 1000);
}

#[test]
fn test_session_table_operations() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(node.identity().keypair());

    let dest_addr = *identity_b.node_addr();
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
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
            .state()
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
            .state()
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
            .state()
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
            .state()
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
            .state()
            .is_established()
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .state()
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
            .state()
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
            .state()
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
            .state()
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
            .map(|s| s.state().is_established())
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
            .state()
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
        tn.node.supervisor.tun_tx = Some(tx);
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
        let src_fips = crate::FipsAddress::from_node_addr(&src_addr);
        let dst_fips = crate::FipsAddress::from_node_addr(&dst_addr);
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
    nodes[1].node.supervisor.tun_tx = Some(tx);

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
    let d_fips = crate::FipsAddress::from_node_addr(&d_addr);
    let b_fips = crate::FipsAddress::from_node_addr(&b_addr);
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
            .map(|e| e.state().is_established())
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
        tn.node.supervisor.tun_tx = Some(tx);
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
        let src_fips = crate::FipsAddress::from_node_addr(&src_addr);
        let dst_fips = crate::FipsAddress::from_node_addr(&dest_addr);

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
            if entry.state().is_established() {
                total_established += 1;
            } else if entry.state().is_awaiting_msg3() {
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
    src: &crate::FipsAddress,
    dst: &crate::FipsAddress,
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
    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&peer_addr.as_bytes()[0..15]);
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

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

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
            .state()
            .is_established()
    );

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.supervisor.tun_tx = Some(tun_tx);

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
    cfg0.node.rekey.enabled = true;
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
            .state()
            .is_established(),
        "session established"
    );

    // node 1's TUN receiver observes decoded plaintext.
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.supervisor.tun_tx = Some(tun_tx);
    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

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

    // No session backdating here, unlike the master-branch original: on this
    // line the responder classifies the arrival from the sender's msg3
    // declaration and `establish_inbound` reads no clock at all, so aging the
    // session past a 30s acceptance gate would age it past nothing.

    // Drive the real rekey handshake (msg1/msg2/msg3 over loopback) to cutover.
    for _ in 0..6 {
        nodes[0].node.check_rekey().await;
        nodes[1].node.check_rekey().await;
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
            .state()
            .is_established(),
        "session must remain established after the rekey"
    );

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

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // No session yet
    assert_eq!(nodes[0].node.session_count(), 0);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.supervisor.tun_tx = Some(tun_tx);

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
            .state()
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
            .state()
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
    nodes[0].node.supervisor.tun_tx = Some(tun_tx);

    let src_fips = crate::FipsAddress::from_node_addr(nodes[0].node.node_addr());

    // Build a packet to an unknown FIPS address (not in identity cache)
    let unknown_addr = NodeAddr::from_bytes([0xAA; 16]);
    let unknown_fips = crate::FipsAddress::from_node_addr(&unknown_addr);
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

#[tokio::test]
async fn test_tun_outbound_3node_forwarded() {
    // A—B—C: TUN packet from A destined for C, forwarded through B
    let edges = vec![(0, 1), (1, 2)];
    let mut nodes = run_tree_test(3, &edges, false).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);

    let node0_addr = *nodes[0].node.node_addr();
    let node2_addr = *nodes[2].node.node_addr();

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node2_addr);

    // Register Node 2's identity in Node 0's cache
    // (In production, this would come from the discovery protocol or DNS priming)
    let node2_pubkey = nodes[2].node.identity().pubkey_full();
    nodes[0].node.register_identity(node2_addr, node2_pubkey);

    // Install TUN receiver on Node 2
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[2].node.supervisor.tun_tx = Some(tun_tx);

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
            .state()
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

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

    // Install TUN receiver on Node 1
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[1].node.supervisor.tun_tx = Some(tun_tx);

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
            .state()
            .is_initiating()
    );

    // Drain until session established and queued packets flushed
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .state()
            .is_established()
    );

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

// ============================================================================
// Unit tests: Session idle timeout
// ============================================================================

/// Helper: complete a Noise XX handshake and return the initiator's NoiseSession.
fn make_noise_session(
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
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000, // created at t=1000ms
        true,
    );

    node.sessions.insert(remote_addr, entry);
    assert_eq!(node.session_count(), 1);
    assert!(node.get_session(&remote_addr).unwrap().is_established());

    // Purge at t=92s — should exceed default 90s idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(node.session_count(), 0, "Idle session should be purged");
}

#[test]
fn test_purge_idle_sessions_keeps_active() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let session = make_noise_session(node.identity(), &remote);
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    // Touch at t=80s — recent activity
    entry.touch(81_000);

    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — only 11s since last activity, well within 90s timeout
    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

    assert_eq!(
        node.session_count(),
        1,
        "Active session should survive purge"
    );
}

#[test]
fn test_purge_idle_sessions_ignores_initiating() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let handshake = HandshakeState::new_initiator(node.identity().keypair());
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Purge well past the idle timeout — Initiating sessions should not be touched
    let now_ms = 1000 + 200_000;
    node.purge_idle_sessions(now_ms);

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
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Insert some pending packets for this destination
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(vec![1, 2, 3]);
    node.pending_tun_packets.insert(remote_addr, queue);
    assert!(node.pending_tun_packets.contains_key(&remote_addr));

    // Purge after idle timeout
    let now_ms = 1000 + 92_000;
    node.purge_idle_sessions(now_ms);

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
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

    node.sessions.insert(remote_addr, entry);

    // Even way past any timeout, sessions should survive when disabled
    let now_ms = 1000 + 1_000_000;
    node.purge_idle_sessions(now_ms);

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
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000, // created at t=1s
        true,
    );

    // Do NOT call entry.touch() — simulates a session where only MMP
    // reports have flowed (MMP no longer calls touch). last_activity
    // remains at creation time (1000ms).
    node.sessions.insert(remote_addr, entry);

    // Purge at t=92s — 91s since creation, exceeds 90s idle timeout.
    // Even though MMP reports would have been flowing, they no longer
    // reset the idle timer.
    let now_ms = 92_000;
    node.purge_idle_sessions(now_ms);

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
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair());

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
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
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

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
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );

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
    let mut prefix1 = [0u8; 15];
    prefix1.copy_from_slice(&id1.node_addr().as_bytes()[0..15]);
    node.identity_cache
        .insert(prefix1, (*id1.node_addr(), id1.pubkey_full(), 1000));

    let mut prefix2 = [0u8; 15];
    prefix2.copy_from_slice(&id2.node_addr().as_bytes()[0..15]);
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

    let mut prefix3 = [0u8; 15];
    prefix3.copy_from_slice(&id3.node_addr().as_bytes()[0..15]);
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

    let mut prefix = [0u8; 15];
    prefix.copy_from_slice(&remote_addr.as_bytes()[0..15]);

    let result = node.lookup_by_fips_prefix(&prefix);
    assert!(result.is_some(), "Registered identity should be available");

    let (addr, pk) = result.unwrap();
    assert_eq!(addr, remote_addr);
    assert_eq!(pk, remote.pubkey_full());
}

// ============================================================================
// Session-layer handshake resend tests
// ============================================================================

/// Test that SessionEntry handshake payload storage works correctly.
#[test]
fn test_session_entry_handshake_payload_storage() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    // Initially no handshake payload
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at_ms(), 0);

    // Store a handshake payload
    let payload = vec![0x01, 0x02, 0x03, 0x04];
    entry.set_handshake_payload(payload.clone(), 2000);

    assert_eq!(entry.handshake_payload().unwrap(), &payload);
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at_ms(), 2000);
}

/// Test that resend_count and next_resend_at_ms track correctly on SessionEntry.
#[test]
fn test_session_entry_resend_tracking() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.set_handshake_payload(vec![0x01], 2000);

    // Record first resend
    entry.record_resend(4000);
    assert_eq!(entry.resend_count(), 1);
    assert_eq!(entry.next_resend_at_ms(), 4000);

    // Record second resend
    entry.record_resend(8000);
    assert_eq!(entry.resend_count(), 2);
    assert_eq!(entry.next_resend_at_ms(), 8000);
}

/// Test that clear_handshake_payload clears payload and resets timer.
#[test]
fn test_session_entry_clear_handshake_payload() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );

    entry.set_handshake_payload(vec![0x01, 0x02], 2000);
    entry.record_resend(4000);
    assert!(entry.handshake_payload().is_some());
    assert_eq!(entry.resend_count(), 1);

    // Clear on Established transition
    entry.clear_handshake_payload();
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.next_resend_at_ms(), 0);
    // resend_count is NOT reset — it's a historical record
    assert_eq!(entry.resend_count(), 1);
}

/// Test that session handshake timeout removes stale Initiating sessions.
#[tokio::test]
async fn test_session_handshake_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_b = Identity::generate();
    let handshake = HandshakeState::new_initiator(node.identity().keypair());

    let dest_addr = *identity_b.node_addr();

    // Create a session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
    );
    node.sessions.insert(dest_addr, entry);

    assert!(node.sessions.contains_key(&dest_addr));

    // Before timeout: session should remain
    let timeout_secs = node.config().node.rate_limit.handshake_timeout_secs;
    let before_timeout = 1000 + timeout_secs * 1000 - 1;
    node.resend_pending_session_handshakes(before_timeout).await;
    assert!(
        node.sessions.contains_key(&dest_addr),
        "Session should survive before timeout"
    );

    // After timeout: session should be removed
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(after_timeout).await;
    assert!(
        !node.sessions.contains_key(&dest_addr),
        "Timed-out session should be removed"
    );
}

/// Test that session handshake timeout removes stale AwaitingMsg3 sessions.
#[tokio::test]
async fn test_session_awaiting_msg3_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_responder(identity_b.keypair());

    let src_addr = *identity_a.node_addr();

    // Create an AwaitingMsg3 session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        src_addr,
        identity_a.pubkey_full(),
        EndToEndState::AwaitingMsg3(handshake),
        1000,
        false,
    );
    node.sessions.insert(src_addr, entry);

    assert!(node.sessions.contains_key(&src_addr));

    // After timeout: session should be removed
    let timeout_secs = node.config().node.rate_limit.handshake_timeout_secs;
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(after_timeout).await;
    assert!(
        !node.sessions.contains_key(&src_addr),
        "Timed-out AwaitingMsg3 session should be removed"
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

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

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
            .state()
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
    nodes[0].node.supervisor.tun_tx = Some(tun_tx);

    // Build an IPv6 packet that fits local MTU but exceeds path MTU
    let reduced_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(reduced_mtu) as usize;
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
    nodes[0].node.supervisor.tun_tx = Some(tun_tx2);
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

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node2_addr);

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
            .state()
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
    let local_effective_mtu = crate::upper::icmp::effective_ipv6_mtu(1400) as usize;
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
    nodes[0].node.supervisor.tun_tx = Some(tun_tx2);

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
    let expected_ipv6_mtu = crate::upper::icmp::effective_ipv6_mtu(path_mtu) as u32;
    assert_eq!(
        reported_mtu, expected_ipv6_mtu,
        "ICMPv6 PTB MTU should match path IPv6 MTU (transport MTU {} - overhead)",
        path_mtu
    );

    // Verify a fitting packet still passes through without PTB
    let (tun_tx3, tun_rx3) = std::sync::mpsc::channel();
    nodes[0].node.supervisor.tun_tx = Some(tun_tx3);

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
    use crate::noise::HandshakeState;

    // This branch's FSP rekey is Noise XX, so the responder is built without
    // a pinned remote static; the entry's lifecycle state is what the helper
    // is establishing, not the handshake pattern.
    let handshake = HandshakeState::new_responder(node.identity().keypair());
    let placeholder = node.identity().keypair().public_key();
    let entry = crate::node::session::SessionEntry::new(
        claimed,
        placeholder,
        EndToEndState::AwaitingMsg3(handshake),
        1000,
        false,
    );
    node.sessions.insert(claimed, entry);
}

/// Install the entry `initiate_session` creates: an address this node chose
/// itself, with the handshake still in flight and MMP not yet initialized.
fn install_initiating(node: &mut Node, remote: &Identity) {
    use crate::noise::HandshakeState;

    // Noise XX on this branch: the initiator learns the remote static during
    // the handshake rather than pinning it up front.
    let handshake = HandshakeState::new_initiator(node.identity().keypair());
    let remote_addr = *remote.node_addr();
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Initiating(handshake),
        1000,
        true,
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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

    assert!(
        tn.node.path_mtu_lookup_get(&dest_fips).is_none(),
        "lookup should start empty for this destination"
    );

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

    // Pre-seed with a generous value (e.g., from a discovery reverse-path
    // response that didn't reflect the forward-path bottleneck).
    tn.node.path_mtu_lookup_insert(dest_fips, 1500);

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

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
        crate::upper::icmp::MIN_ACTIONABLE_PATH_MTU - 1,
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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);
    let floor = crate::upper::icmp::MIN_ACTIONABLE_PATH_MTU;

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

    let src_fips = crate::FipsAddress::from_node_addr(&node0_addr);
    let dst_fips = crate::FipsAddress::from_node_addr(&node1_addr);

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
            .state()
            .is_established()
    );

    // Forge the signal: an MtuExceeded claiming the path to node 1 carries
    // nothing at all, reported by a node that is not on the path.
    let reporter = NodeAddr::from_bytes([0xEE; 16]);
    let inner = build_mtu_exceeded_inner(&node1_addr, &reporter, 0);
    nodes[0].node.handle_mtu_exceeded(&reporter, &inner).await;

    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.supervisor.tun_tx = Some(tun_tx);

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

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

    tn.node.handle_path_broken(&reporter, inner).await;

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

    tn.node.handle_path_broken(&reporter, inner).await;

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
/// can tell "restored by the reseed" apart from "never a candidate".
async fn node_with_link_seed(
    mtu: u16,
) -> (
    Node,
    crate::NodeAddr,
    crate::FipsAddress,
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
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);
    let transport_addr = TransportAddr::from_string("127.0.0.1:2121");

    node.seed_path_mtu_for_link_peer(&remote_addr, transport_id, &transport_addr);

    (node, remote_addr, remote_fips, transport_id, transport_addr)
}

#[tokio::test]
async fn test_expired_path_mtu_keeps_the_link_peer_seed() {
    use crate::peer::ActivePeer;

    // The same regression the release helper's reseed half exists to
    // prevent, reproduced on the expiry path. A tighter discovery value
    // overwrites a direct peer's link MTU under keep-tighter, so expiring it
    // with a bare removal would silently drop that peer to the conservative
    // ceiling until its link re-handshakes.
    let (mut node, remote_addr, remote_fips, transport_id, transport_addr) =
        node_with_link_seed(1452).await;

    let remote = Identity::generate();
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
    let (mut node, _remote_addr, remote_fips, _tid, _taddr) = node_with_link_seed(1452).await;
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
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

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
    node.coord_cache_mut().insert(dest, coords, 1000);

    let encoded = PathBroken::new(dest, reporter).encode();
    node.handle_path_broken(&reporter, &encoded[5..]).await;

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

#[tokio::test]
async fn test_path_broken_naming_a_dest_whose_entry_is_an_unauthenticated_responder_handshake_does_not_flush_cached_coords()
 {
    use crate::proto::routing::PathBroken;

    let mut node = make_node();

    let dest = NodeAddr::from_bytes([0xCC; 16]);
    let reporter = NodeAddr::from_bytes([0xBB; 16]);
    let coords = node.tree_state().my_coords().clone();
    node.coord_cache_mut().insert(dest, coords, 1000);

    // One forged SessionSetup naming `dest` would leave exactly this entry.
    install_halfopen(&mut node, dest);

    let encoded = PathBroken::new(dest, reporter).encode();
    node.handle_path_broken(&reporter, &encoded[5..]).await;

    assert!(
        node.coord_cache().get(&dest, 1000).is_some(),
        "a half-open entry keyed on a claimed address must not admit the signal"
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
    node.coord_cache_mut().insert(dest, coords, 1000);

    let encoded = PathBroken::new(dest, reporter).encode();
    node.handle_path_broken(&reporter, &encoded[5..]).await;

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
    let dest_fips = crate::FipsAddress::from_node_addr(&dest);

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
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    entry.init_mmp(&node.config().node.session_mmp);
    node.sessions.insert(remote_addr, entry);
}

#[test]
fn test_handle_path_mtu_notification_writes_path_mtu_lookup_when_empty() {
    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

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
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

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
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

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
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

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
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);

    install_established_session_with_mmp(&mut node, &remote);

    assert_eq!(
        node.metrics().errors.path_mtu_notif_below_floor.get(),
        0,
        "counter starts at zero on a fresh node"
    );

    let body = build_path_mtu_notification_body(crate::upper::icmp::MIN_ACTIONABLE_PATH_MTU - 1);
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
    let remote_fips = crate::FipsAddress::from_node_addr(&remote_addr);
    let transport_addr = TransportAddr::from_string("127.0.0.1:2121");

    let peer_identity = PeerIdentity::from_pubkey_full(remote.pubkey_full());
    let mut peer = ActivePeer::new(peer_identity, LinkId::new(7), 0);
    peer.set_current_addr(transport_id, transport_addr.clone());
    node.peers.insert(remote_addr, peer);

    node.seed_path_mtu_for_link_peer(&remote_addr, transport_id, &transport_addr);
    assert_eq!(
        node.path_mtu_lookup_get(&remote_fips),
        Some(1452),
        "precondition: the direct-link seed is in place"
    );

    let session = make_noise_session(node.identity(), &remote);
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    node.sessions.insert(remote_addr, entry);

    node.purge_idle_sessions(1000 + 92_000);
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

/// Helper: drive a full XX exchange against `responder_identity` and return
/// the responder's half-completed handshake plus the initiator's msg3.
///
/// The msg3 is cryptographically valid for the responder and carries
/// `initiator_identity`'s static key, which is exactly the shape of the
/// defect: a peer that completes a real handshake while the datagram claims
/// somebody else's source address.
fn drive_xx_to_msg3(
    initiator_identity: &Identity,
    responder_identity: &Identity,
) -> (crate::noise::HandshakeState, Vec<u8>) {
    use crate::noise::HandshakeState;

    let mut initiator = HandshakeState::new_initiator(initiator_identity.keypair());
    let mut responder = HandshakeState::new_responder(responder_identity.keypair());

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

    (responder, msg3)
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

    let (responder, msg3) = drive_xx_to_msg3(&attacker, node.identity());

    // Half-open session recorded under the victim's address, as
    // handle_session_setup would have done from the claimed source.
    let entry = crate::node::session::SessionEntry::new(
        victim_addr,
        node.identity().pubkey_full(),
        EndToEndState::AwaitingMsg3(responder),
        1000,
        false,
    );
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

    let (responder, msg3) = drive_xx_to_msg3(&peer, node.identity());

    let entry = crate::node::session::SessionEntry::new(
        peer_addr,
        node.identity().pubkey_full(),
        EndToEndState::AwaitingMsg3(responder),
        1000,
        false,
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
    let mut entry = crate::node::session::SessionEntry::new(
        peer_addr,
        legit.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    entry.mark_established(1000);

    // Responder-side rekey armed, but driven by a different identity.
    let (responder, msg3) = drive_xx_to_msg3(&attacker, node.identity());
    entry.set_rekey_state(responder, false);
    node.sessions.insert(peer_addr, entry);

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
        entry.pending_new_session().is_none(),
        "a rekey from a different static key must not become the pending session"
    );
    assert!(!entry.has_rekey_in_progress());
    assert_eq!(node.stats().session.rekey_key_mismatch, 1);
}

#[tokio::test]
async fn test_rekey_msg3_accepts_established_peer_key() {
    let mut node = make_node();
    let legit = Identity::generate();
    let peer_addr = *legit.node_addr();

    let session = make_noise_session(node.identity(), &legit);
    let mut entry = crate::node::session::SessionEntry::new(
        peer_addr,
        legit.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    entry.mark_established(1000);

    let (responder, msg3) = drive_xx_to_msg3(&legit, node.identity());
    entry.set_rekey_state(responder, false);
    node.sessions.insert(peer_addr, entry);

    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(msg3).encode(),
        1280,
        false,
    )
    .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(entry.pending_new_session().is_some());
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
    let mut entry = crate::node::session::SessionEntry::new(
        peer_addr,
        stored_pubkey,
        EndToEndState::Established(session),
        1000,
        true,
    );
    entry.mark_established(1000);

    let (responder, msg3) = drive_xx_to_msg3(&legit, node.identity());
    entry.set_rekey_state(responder, false);
    node.sessions.insert(peer_addr, entry);

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
        entry.pending_new_session().is_some(),
        "a parity-normalized stored key must not reject a legitimate rekey"
    );
    assert_eq!(node.stats().session.rekey_key_mismatch, 0);
}

/// Install the shape the msg3 epoch-discard defect needs: an established
/// entry holding a completed rekey the peer has not yet cut over to, stamped
/// stale, with a second handshake armed beside it by a stranger's setup.
///
/// Returns the node, the peer's address and the cryptographically valid msg3
/// the stranger would send to finish the handshake it armed.
fn install_stale_pending_beside_a_stranger_armed_handshake(
    peer: &Identity,
    stranger: &Identity,
) -> (Node, crate::NodeAddr, Vec<u8>) {
    let (mut node, peer_addr) = make_node_with_established_peer(false, peer);
    let msg3 = arm_stranger_handshake_beside_stale_pending(&mut node, &peer_addr, peer, stranger);
    (node, peer_addr, msg3)
}

/// Put a stale completed rekey and a stranger-armed handshake on an entry
/// that is already established, and return the msg3 that finishes the
/// stranger's handshake.
///
/// This is what a forged setup leaves behind once `pending_stale` has
/// lapsed: the veto no longer fires, so the fall-through arms a responder
/// handshake beside pending keys it does not touch. `set_pending_session`
/// clears `rekey_state`, so the arming has to follow it, as it does in the
/// handler.
fn arm_stranger_handshake_beside_stale_pending(
    node: &mut Node,
    peer_addr: &crate::NodeAddr,
    peer: &Identity,
    stranger: &Identity,
) -> Vec<u8> {
    let pending = make_noise_session(node.identity(), peer);
    let (responder, msg3) = drive_xx_to_msg3(stranger, node.identity());

    let idle_ms = node.config().node.session.idle_timeout_secs * 1000;
    let now_ms = wall_clock_ms();
    let entry = node.sessions.get_mut(peer_addr).unwrap();
    entry.set_pending_session(pending);
    // Stale enough that `pending_stale` is true, which is what lets a forged
    // setup arm the handshake this state starts from.
    entry.set_rekey_completed_ms(now_ms - idle_ms - 60_000);
    entry.set_rekey_state(responder, false);
    entry.record_peer_rekey(now_ms);

    msg3
}

#[tokio::test]
async fn test_forged_msg3_against_a_peer_armed_handshake_leaves_the_completed_epoch_intact() {
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr, _valid_msg3) =
        install_stale_pending_beside_a_stranger_armed_handshake(&peer, &stranger);

    // Garbage of the right length: `read_message_3` fails on the AEAD.
    let forged = SessionMsg3::new(vec![0u8; crate::noise::HANDSHAKE_MSG3_SIZE]).encode();
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(
        entry.pending_new_session().is_some(),
        "an unauthenticated msg3 must not discard the key epoch the peer may \
         already have cut over to; only the handshake it failed belongs to it"
    );
    assert!(
        entry.is_established(),
        "the running session must be left intact alongside the pending one"
    );
    assert!(
        !entry.has_rekey_in_progress(),
        "the handshake the msg3 failed against must still be abandoned"
    );
}

#[tokio::test]
async fn test_rekey_msg3_with_an_unreadable_negotiation_payload_leaves_the_completed_epoch_intact()
{
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr, valid_msg3) =
        install_stale_pending_beside_a_stranger_armed_handshake(&peer, &stranger);

    // The fifth failure path in this arm, and the one the maintenance branch
    // has no counterpart for: XX msg3 can carry a negotiation payload behind
    // the base message, so `read_message_3` succeeds and the decrypt of the
    // trailer is what fails. Same defect class as its four siblings — nothing
    // about the sender is established at that point either.
    let mut payload = valid_msg3;
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
        entry.pending_new_session().is_some(),
        "a msg3 whose negotiation payload will not decrypt must not discard \
         the completed epoch either"
    );
    assert!(
        entry.is_established(),
        "the running session must be left intact alongside the pending one"
    );
    assert!(
        !entry.has_rekey_in_progress(),
        "the handshake the payload failed against must still be abandoned"
    );
}

#[tokio::test]
async fn test_rekey_msg3_from_a_different_static_key_leaves_the_completed_epoch_intact() {
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr, valid_msg3) =
        install_stale_pending_beside_a_stranger_armed_handshake(&peer, &stranger);

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
        entry.pending_new_session().is_some(),
        "a msg3 whose static key is not this session's peer must not discard \
         the completed epoch either"
    );
    assert!(entry.is_established());
    assert_eq!(
        node.stats().session.rekey_key_mismatch,
        1,
        "the key mismatch must still be counted, so this test also pins that \
         the refusal itself did not move"
    );
}

// ============================================================================
// Integration tests: a setup message naming an established peer
// ============================================================================

/// Build a two-node routable mesh whose nodes both have periodic rekey off.
async fn make_rekey_disabled_pair() -> Vec<TestNode> {
    let configs = (0..2)
        .map(|_| {
            let mut config = Config::new();
            config.node.rekey.enabled = false;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    nodes
}

/// Establish an FSP session from nodes[0] to nodes[1] and assert both sides
/// reached Established.
async fn establish_pair_session(nodes: &mut [TestNode]) {
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    nodes[0]
        .node
        .initiate_session(node1_addr, node1_pubkey)
        .await
        .expect("initiate_session failed");

    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(nodes).await;
    }

    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .expect("initiator session present")
            .is_established(),
        "initiator session must be established before the test body"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder session present")
            .is_established(),
        "responder session must be established before the test body"
    );
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
async fn test_forged_setup_naming_established_peer_leaves_session_carrying_traffic_rekey_disabled()
{
    let mut nodes = make_rekey_disabled_pair().await;
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
    assert!(
        entry.has_rekey_in_progress(),
        "the forged setup must have been observed as a side handshake, \
         not dropped for an unrelated reason"
    );
    assert_eq!(
        nodes[1].node.stats().session.rekey_armed,
        1,
        "arming a handshake from an unauthenticated setup must be counted, \
         since the DEBUG line at that site is invisible at the default level"
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
async fn test_genuine_peer_restart_reestablishes_session_with_rekey_disabled() {
    let mut nodes = make_rekey_disabled_pair().await;
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // Simulate node 0 restarting: it loses its session state but keeps its
    // identity, so its setup message names an address node 1 still holds an
    // established session for.
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
            .pending_new_session()
            .is_some(),
        "the restarted peer's msg3 must have produced a pending session"
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
        entry.pending_new_session().is_none(),
        "the first frame on the new epoch must complete the cutover"
    );
    assert!(
        entry.traffic_counters().1 > 0,
        "node 1 must have decrypted the restarted peer's frame"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_genuine_peer_restart_reestablishes_session_with_rekey_enabled() {
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
            .pending_new_session()
            .is_some(),
        "the restarted peer's msg3 must have produced a pending session"
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
        entry.pending_new_session().is_none(),
        "the first frame on the new epoch must complete the cutover"
    );
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
            config.node.rekey.enabled = false;
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

#[tokio::test]
async fn test_a_drained_setup_bucket_refills_and_admits_the_next_legitimate_setup() {
    // Fast refill: the point is that the denial is transient, and that the
    // initiator's own msg1 resend schedule covers a window this short.
    let mut nodes = make_setup_limited_pair(2, 50.0).await;

    for _ in 0..3 {
        deliver_forged_setup_over_link(&mut nodes).await;
    }
    assert!(
        nodes[1].node.stats().session.setup_rate_limited > 0,
        "the bucket must actually be drained before the refill is tested"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
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

    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("the established session must still be there")
            .has_rekey_in_progress(),
        "a drained stranger bucket must not stop an established peer's rekey \
         arming: suppressed rotation is silent, and the operator's only \
         signal would be a flat rekey_armed"
    );
    assert_eq!(nodes[1].node.stats().session.rekey_armed, 1);

    cleanup_nodes(&mut nodes).await;
}

// ============================================================================
// Integration tests: a forged SessionAck against an in-flight initiation
// ============================================================================

#[tokio::test]
async fn test_forged_session_ack_leaves_the_initiation_able_to_complete_on_the_genuine_ack() {
    let mut nodes = make_rekey_disabled_pair().await;

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

    // A forged ack of exactly the right length. The leading 33 bytes are a
    // valid compressed point, which is the point of the test: random bytes
    // usually fail `PublicKey::from_slice` before anything has been mixed
    // into the symmetric state, so they would not discriminate the rollback.
    let mut payload = Identity::generate().pubkey_full().serialize().to_vec();
    payload.resize(crate::noise::HANDSHAKE_MSG2_SIZE, 0);
    assert_eq!(payload.len(), crate::noise::HANDSHAKE_MSG2_SIZE);
    let coords = nodes[1].node.tree_state().my_coords().clone();
    let forged = SessionAck::new(coords.clone(), coords)
        .with_handshake(payload)
        .encode();

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

/// Answer the msg1 `node` has in flight to `dest_addr` with a cryptographically
/// well-formed XX msg2 under `responder`'s static key.
///
/// This is the shape the two exits below the msg2 read have to survive, and
/// the shape a bare garbage buffer cannot produce: nothing in XX binds msg2 to
/// the identity the initiator dialled, so any keypair at all answers a msg1
/// with a msg2 that reads cleanly. The msg1 comes off the entry's own retained
/// resend copy, so the ephemeral is the real one and the read genuinely
/// succeeds.
///
/// `good_negotiation` chooses between the encrypted negotiation payload a real
/// responder appends and a same-length run of zeroes, which reaches the
/// decrypt failure with everything before it intact.
fn answer_in_flight_msg1(
    node: &Node,
    dest_addr: &crate::NodeAddr,
    responder: &Identity,
    good_negotiation: bool,
) -> Vec<u8> {
    use crate::proto::fmp::NegotiationPayload;
    use crate::proto::fsp::SessionSetup;

    let stored = node
        .get_session(dest_addr)
        .expect("initiating entry present")
        .handshake_payload()
        .expect("the initiator retains its msg1 for resend")
        .to_vec();
    // `set_handshake_payload` stores `SessionSetup::encode()`, which carries
    // the 4-byte FSP common prefix that `decode` expects to be stripped.
    let setup = SessionSetup::decode(&stored[4..]).expect("the retained msg1 must decode");

    let mut handshake = crate::noise::HandshakeState::new_responder(responder.keypair());
    handshake.set_local_epoch([0x77; 8]);
    handshake
        .read_message_1(&setup.handshake_payload)
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
    let mut nodes = make_rekey_disabled_pair().await;

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
    let forged = answer_in_flight_msg1(&nodes[0].node, &node1_addr, &stranger, false);

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

    // The rollback is the half that matters: the msg2 read succeeded here, so
    // the handshake holds the stranger's material until it is put back.
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
    let mut nodes = make_rekey_disabled_pair().await;

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
    let forged = answer_in_flight_msg1(&nodes[0].node, &node1_addr, &stranger, true);

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

// ============================================================================
// Tick-loop maintenance with periodic rekey disabled
// ============================================================================

/// Build a node with the given periodic-rekey setting holding one established
/// session with `peer`, returning the node and the peer's address.
fn make_node_with_established_peer(
    rekey_enabled: bool,
    peer: &Identity,
) -> (Node, crate::NodeAddr) {
    let mut config = Config::new();
    config.node.rekey.enabled = rekey_enabled;
    let mut node = make_node_with(config);
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
    let mut entry = crate::node::session::SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    entry.mark_established(1000);
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

/// Build the initiator-side XX handshake `initiate_session_rekey` would
/// leave on the entry, without needing a route to send its msg1 over.
///
/// XX msg1 is a bare ephemeral, so the peer's static is not needed to build
/// it and `peer` is unused here; the parameter is kept so the call sites read
/// the same as the handshake they stand in for.
fn our_rekey_initiator_handshake(node: &Node, _peer: &Identity) -> crate::noise::HandshakeState {
    let mut handshake = crate::noise::HandshakeState::new_initiator(node.identity().keypair());
    handshake.set_local_epoch([0x11; 8]);
    handshake
        .write_message_1()
        .expect("our own msg1 must build");
    handshake
}

/// Generate an identity whose address sorts strictly below `node_addr`.
fn peer_identity_sorting_below(node_addr: &crate::NodeAddr) -> Identity {
    loop {
        let id = Identity::generate();
        if id.node_addr() < node_addr {
            return id;
        }
    }
}

#[tokio::test]
async fn test_setup_naming_a_peer_whose_address_sorts_above_ours_keeps_our_rekey_and_counts_the_tiebreak()
 {
    let mut config = Config::new();
    config.node.rekey.enabled = false;
    let mut node = make_node_with(config);

    // Our address sorts smaller, so the tie-break keeps us as initiator.
    let peer = peer_identity_sorting_above(node.node_addr());
    let peer_addr = install_established_peer(&mut node, &peer);

    // Our own rekey is in flight as initiator.
    let our_handshake = our_rekey_initiator_handshake(&node, &peer);
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_rekey_state(our_handshake, true);

    let forged = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    assert_eq!(
        node.stats().session.rekey_tiebreak,
        1,
        "winning the dual-initiation tie-break must be counted; its DEBUG line \
         is invisible at the default log level"
    );
    assert_eq!(node.stats().session.rekey_yielded, 0);
    assert_eq!(
        node.stats().session.rekey_armed,
        0,
        "we won, so nothing may have been armed for the sender"
    );
    assert!(
        node.sessions
            .get(&peer_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "our own rekey must survive, which is the behaviour the counter reports"
    );
}

#[tokio::test]
async fn test_setup_naming_a_peer_whose_address_sorts_below_ours_yields_our_rekey_and_counts_it() {
    let mut config = Config::new();
    config.node.rekey.enabled = false;
    let mut node = make_node_with(config);

    // Our address sorts larger, so the tie-break makes us the responder.
    let peer = peer_identity_sorting_below(node.node_addr());
    let peer_addr = install_established_peer(&mut node, &peer);

    let our_handshake = our_rekey_initiator_handshake(&node, &peer);
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_rekey_state(our_handshake, true);

    let forged = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    assert_eq!(
        node.stats().session.rekey_yielded,
        1,
        "yielding our own rekey to an unauthenticated setup message must be \
         counted; a sustained rate here is local key rotation being suppressed"
    );
    assert_eq!(node.stats().session.rekey_tiebreak, 0);
    // The yield counter is recorded before the SessionAck send, so this
    // assertion needs no routing. The two below depend on the send failing:
    // a standalone node has no peers and an empty coord cache, so
    // `send_session_datagram` returns and the responder arming never runs.
    assert_eq!(
        node.stats().session.rekey_armed,
        0,
        "no route, so the handler returns before arming the responder side"
    );
    assert!(
        !node
            .sessions
            .get(&peer_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "our rekey was abandoned by the yield"
    );
}

#[tokio::test]
async fn test_losing_the_tiebreak_against_a_peer_armed_handshake_keeps_the_completed_epoch() {
    let mut config = Config::new();
    config.node.rekey.enabled = false;
    let mut node = make_node_with(config);

    // Our address sorts larger, so the second setup loses the tie-break.
    // Which side of it a given pair lands on is fixed by the two addresses,
    // not chosen by the sender, so this is half of all peers rather than
    // something an attacker selects.
    let peer = peer_identity_sorting_below(node.node_addr());
    let peer_addr = install_established_peer(&mut node, &peer);

    // What a first forged setup leaves: a handshake the *stranger* armed,
    // beside a completed epoch too stale for `pending_outranks` to veto. The
    // tie-break arm gates on `has_rekey_in_progress`, which this satisfies,
    // so a second forged setup reaches the yield with a pending session
    // present. Nothing here required us to be the rekey initiator.
    let stranger = Identity::generate();
    arm_stranger_handshake_beside_stale_pending(&mut node, &peer_addr, &peer, &stranger);
    assert!(
        !node.sessions.get(&peer_addr).unwrap().is_rekey_initiator(),
        "the state under test is a handshake we did not arm"
    );

    let forged = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert_eq!(
        node.stats().session.rekey_yielded,
        1,
        "the test must actually reach the yield arm, or it proves nothing"
    );
    assert!(
        entry.pending_new_session().is_some(),
        "yielding a tie-break to an unauthenticated setup must not discard \
         the key epoch the peer may already have cut over to; two forged \
         setups would otherwise kill the reverse direction"
    );
    assert!(
        entry.is_established(),
        "the running session must be left intact alongside the pending one"
    );
    assert!(
        !entry.has_rekey_in_progress(),
        "the handshake we yielded must still be abandoned"
    );
}

#[tokio::test]
async fn test_a_responder_handshake_with_no_peer_rekey_stamp_is_not_expired_by_the_tick_loop() {
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(false, &peer);

    // Arm a responder-side handshake but leave `last_peer_rekey_ms` at zero.
    // The expiry predicate's `!= 0` conjunct is what stops that unstamped
    // zero being read as an age of the whole Unix epoch. This pins a
    // defence-in-depth guard: the state is unreachable in production, since
    // the only responder arming stamps the field on the adjacent line.
    let (responder, _msg3) = drive_xx_to_msg3(&stranger, node.identity());
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_rekey_state(responder, false);
    assert_eq!(
        node.sessions.get(&peer_addr).unwrap().last_peer_rekey_ms(),
        0,
        "test fixture must actually leave the stamp unset"
    );

    node.check_session_rekey().await;

    assert!(
        node.sessions
            .get(&peer_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "an unstamped handshake must not be read as infinitely old"
    );
    assert_eq!(node.stats().session.rekey_expired, 0);
}

/// Wall-clock milliseconds, matching the clock the tick loop reads.
fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[tokio::test]
async fn test_superseded_key_epoch_is_drained_with_rekey_disabled() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(false, &peer);

    let old = make_noise_session(node.identity(), &peer);
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_previous_session_for_test(old, 1000);
    assert!(node.sessions.get(&peer_addr).unwrap().is_draining());

    node.check_session_rekey().await;

    assert!(
        !node.sessions.get(&peer_addr).unwrap().is_draining(),
        "a drain window that expired long ago must be completed even when \
         periodic rekey is disabled"
    );
}

#[tokio::test]
async fn test_abandoned_peer_armed_rekey_expires_with_rekey_disabled() {
    let peer = Identity::generate();
    let attacker = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(false, &peer);

    // A setup message armed a responder-side handshake whose msg3 never came.
    let (responder, _msg3) = drive_xx_to_msg3(&attacker, node.identity());
    let now_ms = wall_clock_ms();
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.set_rekey_state(responder, false);
    entry.record_peer_rekey(now_ms - 31_000);

    node.check_session_rekey().await;

    let entry = node.sessions.get(&peer_addr).unwrap();
    assert!(
        !entry.has_rekey_in_progress(),
        "rekey state armed by a peer that never sent msg3 must not persist \
         for the life of the session"
    );
    assert!(
        entry.is_established(),
        "expiring the abandoned handshake must leave the session intact"
    );
    assert_eq!(
        node.stats().session.rekey_expired,
        1,
        "the expired handshake must be counted as a handshake timeout"
    );
    assert_eq!(
        node.stats().session.pending_replaced,
        0,
        "no pending session was replaced, so that counter must not move"
    );
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

#[tokio::test]
async fn test_setup_naming_peer_with_pending_session_is_dropped_and_counted() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(false, &peer);

    // A completed rekey is already waiting for the peer to cut over.
    let pending = make_noise_session(node.identity(), &peer);
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_pending_session(pending);

    let forged = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).unwrap();
    assert!(
        !entry.has_rekey_in_progress(),
        "a setup message must not arm a second handshake while a pending \
         session is still waiting for cutover"
    );
    assert!(
        entry.pending_new_session().is_some(),
        "the pending session must survive the dropped setup message"
    );
    assert_eq!(
        node.stats().session.rekey_pending,
        1,
        "the dropped setup message must be counted, since its DEBUG line is \
         invisible at the default log level"
    );
    assert_eq!(
        node.stats().session.rekey_armed,
        0,
        "nothing was armed, so the arming counter must not move"
    );
}

#[tokio::test]
async fn test_setup_never_discards_a_pending_session_when_our_address_loses_the_tiebreak() {
    // The pre-port branch ran the dual-initiation tie-break on `has_pending`
    // as well as `rekey_in_progress`, and called `abandon_rekey()` when this
    // side's address sorted larger. That handed an unauthenticated setup
    // message the power to discard a completed epoch the peer may already
    // have moved to, on roughly half of all peer pairs. Rank the completed
    // epoch above the setup message instead, on every pair.
    // Draw node identities until this node's address sorts larger than the
    // peer's, so the arm the pre-port code would have taken is the losing one.
    let peer = Identity::generate();
    let (mut node, peer_addr) = loop {
        let (node, addr) = make_node_with_established_peer(false, &peer);
        if !crate::proto::fsp::initiation_winner(node.identity().node_addr(), &addr) {
            break (node, addr);
        }
    };

    let pending = make_noise_session(node.identity(), &peer);
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_pending_session(pending);

    let forged = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).unwrap();
    assert!(
        entry.pending_new_session().is_some(),
        "losing the address tie-break must not let an unauthenticated setup \
         discard the epoch the peer may already have cut over to"
    );
    assert!(
        !entry.has_rekey_in_progress(),
        "a fresh pending session outranks the setup message, so nothing is armed"
    );
    assert_eq!(
        node.stats().session.rekey_pending,
        1,
        "the refusal must be counted through the pending guard, not the \
         tie-break"
    );
    assert_eq!(
        node.stats().session.rekey_yielded,
        0,
        "no tie-break was lost: a pending session with no handshake beside it \
         is no longer decided by address order"
    );
}

#[tokio::test]
async fn test_completed_peer_rekey_session_is_never_expired_by_the_tick_loop() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(false, &peer);

    // A rekey the peer armed completed long ago, and the peer has not yet
    // appeared on the new epoch. The keys are the epoch that peer cut over
    // to, so no amount of waiting may discard them.
    let pending = make_noise_session(node.identity(), &peer);
    let idle_ms = node.config().node.session.idle_timeout_secs * 1000;
    let now_ms = wall_clock_ms();
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.set_pending_session(pending);
    entry.set_rekey_completed_ms(now_ms - idle_ms - 60_000);
    entry.record_peer_rekey(now_ms - idle_ms - 60_000);

    for _ in 0..3 {
        node.check_session_rekey().await;
    }

    let entry = node.sessions.get(&peer_addr).unwrap();
    assert!(
        entry.pending_new_session().is_some(),
        "a completed rekey session must survive any wait for the peer's \
         cutover: discarding it makes the peer's next frame undecryptable"
    );
    assert!(
        entry.is_established(),
        "the running session must be left intact alongside it"
    );
    assert_eq!(
        node.stats().session.rekey_expired,
        0,
        "no armed handshake timed out, so that counter must not move"
    );
    assert_eq!(
        node.stats().session.pending_replaced,
        0,
        "nothing replaced the pending session, so that counter must not move"
    );
}

#[tokio::test]
async fn test_expiring_an_armed_handshake_keeps_the_completed_session_beside_it() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(false, &peer);

    // The peer's earlier rekey completed and is still waiting for its
    // cutover; a later setup message armed a handshake whose msg3 never
    // came. Expiring the handshake must not take the keys with it.
    let pending = make_noise_session(node.identity(), &peer);
    let (responder, _msg3) = drive_xx_to_msg3(&peer, node.identity());
    let now_ms = wall_clock_ms();
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.set_pending_session(pending);
    entry.set_rekey_completed_ms(now_ms - 120_000);
    entry.set_rekey_state(responder, false);
    entry.record_peer_rekey(now_ms - 31_000);

    node.check_session_rekey().await;

    let entry = node.sessions.get(&peer_addr).unwrap();
    assert!(
        !entry.has_rekey_in_progress(),
        "the armed handshake must still expire on the handshake timeout"
    );
    assert!(
        entry.pending_new_session().is_some(),
        "expiring the armed handshake must leave the completed session that \
         the peer may already have cut over to"
    );
    assert_eq!(
        node.stats().session.rekey_expired,
        1,
        "the expired handshake must be counted as a handshake timeout"
    );
}

#[tokio::test]
async fn test_fresh_peer_armed_rekey_is_not_expired() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(false, &peer);

    let (responder, _msg3) = drive_xx_to_msg3(&peer, node.identity());
    let now_ms = wall_clock_ms();
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.set_rekey_state(responder, false);
    entry.record_peer_rekey(now_ms);

    node.check_session_rekey().await;

    assert!(
        node.sessions
            .get(&peer_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "a handshake still within the timeout must not be expired out from \
         under a peer whose msg3 is in flight"
    );
}

// ============================================================================
// Integration tests: a peer's cutover after a long silence
// ============================================================================

#[tokio::test]
async fn test_silent_peers_cutover_still_lands_after_the_idle_timeout_has_passed() {
    // Both nodes rekey after a single message, so one data frame drives a
    // full FSP rekey cycle with node 0 as initiator.
    let configs = (0..2)
        .map(|_| {
            let mut config = Config::new();
            config.node.rekey.after_messages = 1;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    // One frame arms node 0's rekey trigger; the cycle then runs to
    // completion, leaving node 1 holding the new epoch as `pending`.
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"before the rekey")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    nodes[0].node.check_session_rekey().await;
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder entry present")
            .pending_new_session()
            .is_some(),
        "the rekey cycle must have left node 1 holding a pending session"
    );

    // Node 0 emits nothing for longer than the idle timeout — with MMP in
    // minimal mode and traffic flowing one way, nothing authenticates
    // against node 1's pending slot in that time.
    let now_ms = wall_clock_ms();
    let idle_ms = nodes[1].node.config().node.session.idle_timeout_secs * 1000;
    let stamp = now_ms - idle_ms - 10_000;
    nodes[1]
        .node
        .sessions
        .get_mut(&node0_addr)
        .unwrap()
        .set_rekey_completed_ms(stamp);
    nodes[1]
        .node
        .sessions
        .get_mut(&node0_addr)
        .unwrap()
        .record_peer_rekey(stamp);
    for _ in 0..3 {
        nodes[1].node.check_session_rekey().await;
    }

    // Node 0 now cuts over on its own liveness timer and speaks again.
    nodes[0]
        .node
        .sessions
        .get_mut(&node1_addr)
        .unwrap()
        .set_rekey_completed_ms(now_ms - 10_000);
    nodes[0].node.check_session_rekey().await;
    let recv_before = nodes[1]
        .node
        .get_session(&node0_addr)
        .unwrap()
        .traffic_counters()
        .1;

    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"after the long silence")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;

    let entry = nodes[1].node.get_session(&node0_addr).unwrap();
    assert_eq!(
        entry.traffic_counters().1,
        recv_before + 1,
        "the peer's first frame on the epoch it cut over to must still \
         decrypt: received {} packets before the frame, {} after",
        recv_before,
        entry.traffic_counters().1
    );
    assert!(
        entry.pending_new_session().is_none(),
        "that frame must also complete node 1's cutover"
    );

    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn test_peer_restart_reestablishes_through_a_pending_session_that_waited_out_the_timeout() {
    // One-second idle timeout, and a rekey after a single message, so a
    // genuine rekey cycle leaves a pending session that ages out of the
    // veto within the test rather than after a minute and a half.
    let configs = (0..2)
        .map(|_| {
            let mut config = Config::new();
            config.node.rekey.after_messages = 1;
            config.node.session.idle_timeout_secs = 1;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1)]).await;
    verify_tree_convergence(&nodes);
    populate_all_coord_caches(&mut nodes);
    establish_pair_session(&mut nodes).await;

    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let node1_pubkey = nodes[1].node.identity().pubkey_full();

    // A real rekey cycle leaves node 1 holding a completed session whose
    // cutover never comes, stamped by the handler that completed it.
    nodes[0]
        .node
        .send_session_data(&node1_addr, 0, 0, b"before the rekey")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes).await;
    nodes[0].node.check_session_rekey().await;
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(20)).await;
        process_available_packets(&mut nodes).await;
    }
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder entry present")
            .pending_new_session()
            .is_some(),
        "the rekey cycle must have left node 1 holding a pending session"
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Node 0 restarts and re-initiates. Its setup message must not be
    // refused indefinitely on account of that pending session, or node 1's
    // own sends keep the session alive and the peer is locked out for good.
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

    assert_eq!(
        nodes[1].node.stats().session.rekey_pending,
        0,
        "a pending session that has waited out the idle timeout must stop \
         vetoing the peer's setup message"
    );
    assert_eq!(
        nodes[1].node.stats().session.pending_replaced,
        1,
        "the restarted peer's authenticated msg3 must be what replaces the \
         waiting session, and the replacement must be counted"
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
        entry.pending_new_session().is_none(),
        "the restarted peer's first frame must complete the cutover"
    );
    assert!(
        entry.traffic_counters().1 > 0,
        "node 1 must have decrypted the restarted peer's frame"
    );

    cleanup_nodes(&mut nodes).await;
}
