//! End-to-end session establishment tests.

use super::*;
use crate::node::session::{EndToEndState, session_after, session_at, session_before};
use crate::node::tests::spanning_tree::{
    TestNode, cleanup_nodes, drain_all_packets, generate_random_edges, initiate_handshake,
    lock_large_network_test, make_test_node_with_config, populate_all_coord_caches,
    process_available_packets, run_tree_test, run_tree_test_with_configs, run_tree_test_with_mtus,
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

// ============================================================================
// Unit tests: SessionEntry data structure
// ============================================================================

#[test]
fn test_session_entry_new_initiating() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
        true,
    );

    assert!(entry.state().is_initiating());
    assert!(!entry.state().is_established());
    assert!(!entry.state().is_awaiting_msg3());
    assert_eq!(entry.created_at(), session_at(1000));
    assert_eq!(entry.last_activity(), session_at(1000));
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
        let handshake =
            HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());
        let entry = crate::node::session::SessionEntry::new(
            *identity_b.node_addr(),
            identity_b.pubkey_full(),
            EndToEndState::Initiating(handshake),
            session_at(1000),
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
        let handshake =
            HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());
        let entry = crate::node::session::SessionEntry::new(
            *identity_b.node_addr(),
            identity_b.pubkey_full(),
            EndToEndState::Initiating(handshake),
            session_at(1000),
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

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
        true,
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
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();
    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());
    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(10_000),
        true,
    );
    entry.mark_established(session_at(10_000));

    assert_eq!(entry.session_timestamp(session_at(11_500)), 1_500);
    assert_eq!(entry.session_timestamp(session_at(9_000)), 0);
}

#[test]
fn test_session_table_operations() {
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let identity_b = Identity::generate();

    let handshake =
        HandshakeState::new_initiator(node.identity().keypair(), identity_b.pubkey_full());

    let dest_addr = *identity_b.node_addr();
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
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

    // Node 1 should now have a session in AwaitingMsg3 state (XK: identity not yet known)
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

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
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

    // Node 2 should have an AwaitingMsg3 session (XK: identity not yet known)
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

    // Node 2 should be Established (transitioned during XK handshake msg3)
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
        // (Responder should already be Established after XK msg3)
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
        "All reverse sends should succeed (responder Established after XK msg3)"
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

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node1_addr);

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
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
            .is_some_and(|s| s.state().is_established()),
        "session established before the route is lost"
    );

    nodes[0].node.coord_cache.remove(&node2_addr);
    if evict_identity {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&node2_addr.as_bytes()[0..15]);
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
            .is_some_and(|s| s.state().is_established()),
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
/// IK rekey handshake over the loopback transport so the AEAD continuity across
/// the cutover is asserted end to end.
///
/// Deterministic, no wall-clock wait: `rekey.after_messages = 1` makes the
/// first sent datagram cross the initiator's trigger, and both sessions are
/// backdated past the responder's 30s rekey-acceptance gate.
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
            .state()
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

    // Age both sessions past the responder's 30s rekey-acceptance gate so the
    // rekey msg1 is treated as a rekey rather than a fresh connection.
    nodes[0]
        .node
        .get_peer_mut(&node1_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));
    nodes[1]
        .node
        .get_peer_mut(&node0_addr)
        .unwrap()
        .test_backdate_session_established(Duration::from_secs(31));

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

/// A two-node pair with an FSP session over an FMP link whose link sessions
/// have been aged, with a TUN receiver on each node. Built by
/// [`aged_link_pair`].
pub(super) struct AgedLinkPair {
    pub(super) nodes: Vec<TestNode>,
    pub(super) node0_addr: NodeAddr,
    pub(super) node1_addr: NodeAddr,
    pub(super) fips0: crate::Ipv6Address,
    pub(super) fips1: crate::Ipv6Address,
    pub(super) tun0_rx: std::sync::mpsc::Receiver<Vec<u8>>,
    pub(super) tun1_rx: std::sync::mpsc::Receiver<Vec<u8>>,
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
                .is_some_and(|s| s.state().is_established()),
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
        fips0,
        fips1,
        tun0_rx,
        tun1_rx,
    }
}

/// A two-node pair caught mid FMP rekey, with node 1's msg2 held back from
/// node 0. Built by [`rekey_pair_with_held_msg2`].
pub(super) struct HeldMsg2Pair {
    pub(super) nodes: Vec<TestNode>,
    pub(super) node0_addr: NodeAddr,
    pub(super) node1_addr: NodeAddr,
    pub(super) fips0: crate::Ipv6Address,
    pub(super) fips1: crate::Ipv6Address,
    pub(super) tun0_rx: std::sync::mpsc::Receiver<Vec<u8>>,
    pub(super) tun1_rx: std::sync::mpsc::Receiver<Vec<u8>>,
    pub(super) node0_idx_before: Option<crate::utils::index::SessionIndex>,
    pub(super) node1_idx_before: Option<crate::utils::index::SessionIndex>,
    pub(super) rekey_idx: crate::utils::index::SessionIndex,
    pub(super) held_msg2: crate::transport::ReceivedPacket,
}

/// Build a two-node pair with an FSP session, age both link sessions past
/// both rekey gates, start node 0's FMP rekey, deliver its msg1 to node 1
/// only, and pull node 1's real msg2 out of node 0's queue.
///
/// node 0 rekeys on time and node 1 only ever responds, so node 1 holds the
/// new session it committed at msg1 and node 0 is mid-cycle when this
/// returns. Both directions are shown to decode before the rekey, so a later
/// delivery failure is the rekey's and not the harness's.
pub(super) async fn rekey_pair_with_held_msg2() -> HeldMsg2Pair {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG2};
    use crate::transport::ReceivedPacket;

    const REKEY_AFTER_SECS: u64 = 60;

    // node 0 rekeys on time; node 1 only ever responds.
    let mut cfg0 = crate::config::Config::new();
    cfg0.node.rekey.after_secs = REKEY_AFTER_SECS;
    cfg0.node.rekey.after_messages = u64::MAX;
    let mut cfg1 = crate::config::Config::new();
    cfg1.node.rekey.after_secs = u64::MAX;
    cfg1.node.rekey.after_messages = u64::MAX;

    // Age both sessions past both rekey gates: node 0's jittered time trigger,
    // and node 1's 30 s floor below which a msg1 is a duplicate, not a rekey.
    let age = Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let AgedLinkPair {
        mut nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun0_rx,
        tun1_rx,
    } = aged_link_pair(cfg0, cfg1, age).await;
    let node0_idx_before = nodes[0].node.get_peer(&node1_addr).unwrap().our_index();
    let node1_idx_before = nodes[1].node.get_peer(&node0_addr).unwrap().our_index();

    // node 0 starts the rekey; its msg1 lands in node 1's queue.
    nodes[0].node.check_rekey().await;
    let rekey_idx = nodes[0]
        .node
        .get_peer(&node1_addr)
        .unwrap()
        .rekey_our_index()
        .expect("node 0 must have started a rekey");

    // Deliver the msg1 to node 1 only. node 1 answers as the rekey responder
    // and commits its new session at once.
    assert_eq!(
        process_available_packets(&mut nodes[1..]).await,
        1,
        "node 1 must have exactly node 0's rekey msg1 queued"
    );
    assert!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 1 must answer the msg1 as a rekey and hold its new session"
    );

    // Hold node 1's real msg2 back.
    let mut held: Vec<ReceivedPacket> =
        std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert_eq!(held.len(), 1, "node 0 must have only node 1's msg2 queued");
    let held_msg2 = held.remove(0);
    assert_eq!(
        CommonPrefix::parse(&held_msg2.data).map(|p| p.phase),
        Some(PHASE_MSG2),
        "the held packet must be node 1's msg2"
    );

    HeldMsg2Pair {
        nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun0_rx,
        tun1_rx,
        node0_idx_before,
        node1_idx_before,
        rekey_idx,
        held_msg2,
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

/// Drive node 0's rekey msg1 resend ladder on the synthetic clock from
/// `base_ms`: at the default 1 s interval and 2x backoff, resends at +1, +3,
/// +7, +15 and +31 s, then the abandon past the budget at +63 s. Each resend
/// is delivered to node 1, and every msg2 node 1 sends back is lost. Returns
/// the number of msg2s lost.
async fn walk_ladder_losing_msg2s(nodes: &mut [TestNode], base_ms: u64) -> usize {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG2};

    let mut lost = 0;
    for offset_s in [1u64, 3, 7, 15, 31, 63] {
        nodes[0]
            .node
            .resend_rekeys_at(base_ms + offset_s * 1000)
            .await;
        process_available_packets(&mut nodes[1..]).await;
        while let Ok(packet) = nodes[0].packet_rx.try_recv() {
            assert_eq!(
                CommonPrefix::parse(&packet.data).map(|p| p.phase),
                Some(PHASE_MSG2),
                "only node 1's msg2s may be queued at node 0 during the ladder"
            );
            lost += 1;
        }
        pump_until_quiet(nodes).await;
    }
    lost
}

/// A forged rekey msg2 that carries the initiator's live rekey index must not
/// split the link.
///
/// An on-path observer sees the rekey msg1 go out, reads the initiator's
/// cleartext rekey index from it, and delivers a msg2 of the right size under
/// that index ahead of the responder's real reply. Under IK the forgery cannot
/// authenticate: only the responder's static key produces a msg2 the initiator
/// can read. The IK responder committed its new session as pending when it
/// answered msg1 and promotes it on the initiator's first new-epoch frame, so
/// the initiator must complete the cycle on the real msg2 for either direction
/// to survive.
///
/// Deterministic, no wall-clock wait: both sessions are backdated past node 0's
/// time trigger and node 1's rekey-acceptance floor, node 1 never initiates,
/// and every handshake message is delivered by hand.
#[tokio::test]
async fn forged_rekey_msg2_does_not_split_the_link() {
    use crate::noise::HANDSHAKE_MSG2_SIZE;
    use crate::proto::fmp::wire::build_msg2;
    use crate::transport::ReceivedPacket;
    use crate::utils::index::SessionIndex;

    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun0_rx,
        tun1_rx,
        node0_idx_before,
        node1_idx_before,
        rekey_idx,
        held_msg2: real_msg2,
    } = rekey_pair_with_held_msg2().await;

    // The forgery: a well-formed header naming node 0's live rekey index, a
    // valid curve point as the ephemeral so the read gets as far as mixing it
    // into the handshake, and an epoch ciphertext that cannot authenticate.
    // The source is node 1's address, as a spoofed UDP source would be.
    let mut forged_noise = Identity::generate().pubkey_full().serialize().to_vec();
    forged_noise.resize(HANDSHAKE_MSG2_SIZE, 0xA5);
    let forged = ReceivedPacket::new(
        nodes[0].transport_id,
        nodes[1].addr.clone(),
        build_msg2(SessionIndex::new(0x5EED_F00D), rekey_idx, &forged_noise),
    );
    nodes[0].node.handle_msg2(forged).await;

    // Release the real msg2, then run one rekey tick on each node.
    nodes[0].node.handle_msg2(real_msg2).await;
    nodes[0].node.check_rekey().await;
    nodes[1].node.check_rekey().await;
    pump_until_quiet(&mut nodes).await;

    let post_fwd = build_ipv6_packet(&fips0, &fips1, b"post-rekey 0 to 1");
    let post_rev = build_ipv6_packet(&fips1, &fips0, b"post-rekey 1 to 0");
    nodes[0].node.handle_tun_outbound(post_fwd.clone()).await;
    nodes[1].node.handle_tun_outbound(post_rev.clone()).await;
    pump_until_quiet(&mut nodes).await;

    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![post_fwd],
        "node 0 to node 1 must decode after the forged msg2"
    );

    // node 1 promotes its pending session when node 0's first frame on the new
    // epoch authenticates against it. This is one of the two assertions that
    // tell the outcomes apart (see below), and it also rules out a pass in
    // which no rekey happened at all.
    assert_ne!(
        nodes[1].node.get_peer(&node0_addr).unwrap().our_index(),
        node1_idx_before,
        "node 1 must have promoted its pending session on node 0's first new-epoch frame"
    );

    // node 1 to node 0 must still decode, but it no longer tells the outcomes
    // apart: if node 0 lost the cycle to the forgery, node 1 never promotes and
    // both nodes stay on their original sessions, so this passes either way.
    // The promotion assertion above and node 0's cutover assertion below are
    // the ones that catch a lost cycle; keep both.
    let handshake = &nodes[0].node.stats().handshake;
    let (bad_state, unknown) = (handshake.bad_state, handshake.unknown_connection);
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![post_rev],
        "node 1 to node 0 must decode after the forged msg2 \
         (node 0 handshake rejects: bad_state={bad_state}, unknown_connection={unknown})"
    );

    let peer = nodes[0].node.get_peer(&node1_addr).unwrap();
    assert_ne!(
        peer.our_index(),
        node0_idx_before,
        "node 0 must have completed the rekey on the real msg2 and cut over"
    );
    assert!(
        !peer.rekey_in_progress(),
        "node 0 must not be left mid-rekey"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A rekey msg2 lost in transit, with no attacker present, must not split the
/// link.
///
/// node 1 answers node 0's rekey msg1 and holds its new session as pending.
/// node 1's msg2 never arrives, so node 0 never shows it holds the new keys,
/// and node 1's own rekey tick must not cut over to them. node 0 walks its
/// whole msg1 resend ladder, each resend's msg2 lost too, and re-fires after
/// the abandon; node 1 answers each resend with the msg2 it already sent and
/// refuses the re-fired msg1 while it holds the pending. Data must flow both
/// ways on the original sessions throughout. The assertion that tells the outcomes
/// apart is node 1 to node 0: a node 1 that cut over would seal to the rekey
/// index node 0 abandoned.
///
/// What this does not model: the tick loop and the link-dead reap are not
/// driven, only the rekey tick and the resend function, each called by hand.
/// The resend ladder runs on a synthetic millisecond clock, while node 1's
/// pending install time is a real `Instant`, so node 1 is still inside its
/// hold when the ladder ends. The retirement of the pending and the rekey that
/// completes after it are covered by
/// `a_responder_retires_an_unadopted_rekey_and_the_next_rekey_completes`.
#[tokio::test]
async fn dropped_rekey_msg2_does_not_split_the_link() {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun0_rx,
        tun1_rx,
        node1_idx_before,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;

    // The msg2 is lost. The helper already asserted it was a msg2 frame, so
    // this drop is of the real reply.
    drop(held_msg2);

    // node 1 answered the rekey, so its tick must not commit to the new keys:
    // node 0 has not shown it holds them.
    nodes[1].node.check_rekey().await;
    let node1_peer = nodes[1].node.get_peer(&node0_addr).unwrap();
    assert_eq!(
        node1_peer.our_index(),
        node1_idx_before,
        "node 1 must not cut over to a session node 0 has not adopted"
    );
    assert!(
        node1_peer.pending_new_session().is_some(),
        "node 1 must still hold the session it answered with"
    );
    let node1_rejects_before = nodes[1].node.stats().handshake.rekey_pending;

    assert_eq!(
        walk_ladder_losing_msg2s(&mut nodes, crate::time::mono_ms()).await,
        5,
        "node 1 must answer each of node 0's five resends"
    );
    assert!(
        !nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .rekey_in_progress(),
        "node 0 must have abandoned the cycle at the resend budget"
    );

    // node 0 was never dampened (it never received a msg1 from node 1), so
    // its cadence fires again.
    nodes[0].node.check_rekey().await;
    pump_until_quiet(&mut nodes).await;
    nodes[0].node.check_rekey().await;
    nodes[1].node.check_rekey().await;
    pump_until_quiet(&mut nodes).await;
    assert_eq!(
        nodes[1].node.stats().handshake.rekey_pending - node1_rejects_before,
        1,
        "node 1 must refuse node 0's re-fired msg1 while it holds the pending"
    );

    let post_fwd = build_ipv6_packet(&fips0, &fips1, b"post-loss 0 to 1");
    let post_rev = build_ipv6_packet(&fips1, &fips0, b"post-loss 1 to 0");
    nodes[0].node.handle_tun_outbound(post_fwd.clone()).await;
    nodes[1].node.handle_tun_outbound(post_rev.clone()).await;
    pump_until_quiet(&mut nodes).await;

    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![post_fwd],
        "node 0 to node 1 must decode after the lost msg2"
    );

    // The discriminating assertion. node 1 still seals on its original session,
    // to node 0's original index, which stays registered because node 0 never
    // cut over. It decodes only because node 1 held back: had node 1 cut over
    // on its own tick, it would seal to the rekey index node 0 abandoned.
    let handshake = &nodes[0].node.stats().handshake;
    let (bad_state, unknown) = (handshake.bad_state, handshake.unknown_connection);
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![post_rev],
        "node 1 to node 0 must decode after the lost msg2 \
         (node 0 handshake rejects: bad_state={bad_state}, unknown_connection={unknown})"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A rekey responder whose msg2 was lost must not cut over on its own tick,
/// and must not answer the initiator's resent msg1 with the msg2 it stored at
/// startup.
///
/// A responder that cut over on its own tick reset its session age, so the
/// resent msg1 fell under the 30 s floor below which a msg1 is taken as a
/// duplicate of the startup one, and the responder resent its startup msg2,
/// addressed to the startup index the initiator no longer dispatches. Every
/// resend in the ladder met the same answer, and the rekey stalled until a
/// fresh handshake replaced the link.
///
/// Today the responder refuses the resent msg1 while it holds the pending and
/// sends no msg2 at all. A responder that instead resends the msg2 it answered
/// the rekey with is also correct, so the assertion admits a msg2 addressed to
/// the rekey index and refuses only one addressed anywhere else.
#[tokio::test]
async fn a_lost_rekey_msg2_is_not_followed_by_a_cutover_or_the_startup_msg2() {
    use crate::proto::fmp::wire::{CommonPrefix, Msg2Header, PHASE_MSG2};

    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_idx_before,
        rekey_idx,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    let startup_msg2 = nodes[1]
        .node
        .get_peer(&node0_addr)
        .unwrap()
        .handshake_msg2()
        .map(|m| m.to_vec());

    // The msg2 is lost, and node 1's rekey tick runs before node 0 resends.
    drop(held_msg2);
    nodes[1].node.check_rekey().await;
    let node1_idx_after_tick = nodes[1].node.get_peer(&node0_addr).unwrap().our_index();

    // node 0's first msg1 resend, delivered to node 1 only.
    nodes[0]
        .node
        .resend_rekeys_at(crate::time::mono_ms() + 1000)
        .await;
    assert_eq!(
        process_available_packets(&mut nodes[1..]).await,
        1,
        "node 1 must have exactly node 0's resent rekey msg1 queued"
    );

    let msg2s: Vec<Vec<u8>> = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok())
        .filter(|p| CommonPrefix::parse(&p.data).map(|c| c.phase) == Some(PHASE_MSG2))
        .map(|p| p.data)
        .collect();
    for msg2 in &msg2s {
        let receiver = Msg2Header::parse(msg2).map(|h| h.receiver_idx);
        assert_eq!(
            receiver,
            Some(rekey_idx),
            "node 1 answered the resent rekey msg1 with a msg2 not addressed to the rekey \
             (it is the stored startup msg2: {})",
            startup_msg2.as_deref() == Some(msg2.as_slice())
        );
    }
    assert_eq!(
        node1_idx_after_tick, node1_idx_before,
        "node 1 must not cut over on its own tick to a session node 0 never adopted"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A rekey responder whose msg2 was lost holds the pending session it
/// answered with until the hold passes, then retires it: the pending slot and
/// its role are emptied, its index is unregistered and freed, and the current
/// session is untouched. The initiator's next msg1 is then answered and the
/// rekey completes, with node 1 promoted by node 0's first new-epoch frame and
/// data flowing both ways.
#[tokio::test]
async fn a_responder_retires_an_unadopted_rekey_and_the_next_rekey_completes() {
    use crate::node::handlers::rekey::pending_hold;

    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun0_rx,
        tun1_rx,
        node0_idx_before,
        node1_idx_before,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;

    // 1. The msg2 is lost; node 1 holds the pending it answered with.
    drop(held_msg2);
    nodes[1].node.check_rekey().await;
    let node1_peer = nodes[1].node.get_peer(&node0_addr).unwrap();
    assert_eq!(
        node1_peer.our_index(),
        node1_idx_before,
        "node 1 must not cut over to a session node 0 has not adopted"
    );
    let pending_idx = node1_peer
        .pending_our_index()
        .expect("node 1 must still hold the session it answered with");

    // 2. node 0 walks its ladder to the abandon, losing node 1's answer to
    // every resend, and re-fires; node 1 refuses the re-fired msg1 while it
    // holds the pending.
    walk_ladder_losing_msg2s(&mut nodes, crate::time::mono_ms()).await;
    nodes[0].node.check_rekey().await;
    pump_until_quiet(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .rekey_in_progress(),
        "node 0 must have re-fired its rekey after the abandon"
    );
    assert!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 1 must still hold its pending after refusing the re-fired msg1"
    );

    // 3. The hold passes.
    let hold = pending_hold(&nodes[1].node.config().node);
    nodes[1]
        .node
        .get_peer_mut(&node0_addr)
        .unwrap()
        .backdate_pending(hold + Duration::from_secs(1));

    // 4. node 1's tick retires the pending.
    nodes[1].node.check_rekey().await;
    let node1_peer = nodes[1].node.get_peer(&node0_addr).unwrap();
    assert!(
        node1_peer.pending_new_session().is_none(),
        "node 1 must have retired the unadopted pending session"
    );
    assert_eq!(node1_peer.pending_role(), None);
    assert_eq!(
        node1_peer.our_index(),
        node1_idx_before,
        "retirement must leave node 1's current session alone"
    );
    assert!(
        !nodes[1]
            .node
            .peers_by_index
            .contains_key(&(nodes[1].transport_id, pending_idx.as_u32())),
        "the retired pending index must be unregistered"
    );
    assert!(
        !nodes[1].node.index_allocator.is_allocated(pending_idx),
        "the retired pending index must be freed"
    );

    // 5. node 0's next resend of the re-fired msg1 is answered now, and node 0
    // reads the msg2.
    nodes[0]
        .node
        .resend_rekeys_at(crate::time::mono_ms() + 1_000)
        .await;
    pump_until_quiet(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 0 must have completed the re-fired rekey on node 1's answer"
    );

    // 6. node 0 cuts over; node 1 holds until node 0's first new-epoch frame.
    nodes[0].node.check_rekey().await;
    nodes[1].node.check_rekey().await;
    pump_until_quiet(&mut nodes).await;

    let post_fwd = build_ipv6_packet(&fips0, &fips1, b"post-retire 0 to 1");
    let post_rev = build_ipv6_packet(&fips1, &fips0, b"post-retire 1 to 0");
    nodes[0].node.handle_tun_outbound(post_fwd.clone()).await;
    pump_until_quiet(&mut nodes).await;
    nodes[1].node.handle_tun_outbound(post_rev.clone()).await;
    pump_until_quiet(&mut nodes).await;

    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![post_fwd],
        "node 0 to node 1 must decode after the retry"
    );
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![post_rev],
        "node 1 to node 0 must decode after the retry"
    );
    assert_ne!(
        nodes[0].node.get_peer(&node1_addr).unwrap().our_index(),
        node0_idx_before,
        "node 0 must have cut over on the retried rekey"
    );
    assert_ne!(
        nodes[1].node.get_peer(&node0_addr).unwrap().our_index(),
        node1_idx_before,
        "node 1 must have promoted on node 0's first new-epoch frame"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A rekey responder whose msg2 was lost answers the initiator's resend of the
/// same msg1 with the msg2 it already sent, so the cycle completes one resend
/// interval after the loss rather than after the responder hold.
///
/// node 1 must not allocate or arm a second pending for the resend: the msg2
/// it repeats is bound to the pending it already holds, and node 0 reads that
/// msg2 to complete the handshake it started. The rekey then finishes as an
/// unbroken one would, with node 1 promoting on node 0's first new-epoch frame.
#[tokio::test]
async fn a_resent_rekey_msg1_draws_the_held_msg2_and_the_rekey_completes() {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun0_rx,
        tun1_rx,
        node0_idx_before,
        node1_idx_before,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;

    // The msg2 is lost.
    let lost_msg2 = held_msg2.data.clone();
    drop(held_msg2);
    let pending_idx = nodes[1]
        .node
        .get_peer(&node0_addr)
        .unwrap()
        .pending_our_index()
        .expect("node 1 must hold the session it answered with");
    let node1_rejects_before = nodes[1].node.stats().handshake.bad_state;

    // node 0's first resend, at +1 s, reaches node 1 only.
    nodes[0]
        .node
        .resend_rekeys_at(crate::time::mono_ms() + 1_000)
        .await;
    assert_eq!(
        process_available_packets(&mut nodes[1..]).await,
        1,
        "node 1 must have exactly node 0's resent msg1 queued"
    );
    assert_eq!(
        nodes[1].node.stats().handshake.bad_state,
        node1_rejects_before,
        "node 1 must answer the resent msg1, not refuse it"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_our_index(),
        Some(pending_idx),
        "node 1 must keep the pending it holds, not arm another"
    );

    // node 1's answer is the msg2 that was lost, byte for byte.
    let answered: Vec<_> = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert_eq!(answered.len(), 1, "node 0 must have one answer queued");
    assert_eq!(
        answered[0].data, lost_msg2,
        "node 1 must resend the msg2 it sent for this msg1"
    );
    nodes[0]
        .node
        .handle_msg2(answered.into_iter().next().unwrap())
        .await;
    assert!(
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 0 must complete its rekey on the resent msg2"
    );

    // node 0 cuts over; node 1 promotes on node 0's first new-epoch frame.
    nodes[0].node.check_rekey().await;
    nodes[1].node.check_rekey().await;
    pump_until_quiet(&mut nodes).await;
    let post_fwd = build_ipv6_packet(&fips0, &fips1, b"post-resend 0 to 1");
    let post_rev = build_ipv6_packet(&fips1, &fips0, b"post-resend 1 to 0");
    nodes[0].node.handle_tun_outbound(post_fwd.clone()).await;
    pump_until_quiet(&mut nodes).await;
    nodes[1].node.handle_tun_outbound(post_rev.clone()).await;
    pump_until_quiet(&mut nodes).await;

    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![post_fwd], "node 0 to node 1 must decode");
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(got, vec![post_rev], "node 1 to node 0 must decode");
    assert_ne!(
        nodes[0].node.get_peer(&node1_addr).unwrap().our_index(),
        node0_idx_before,
        "node 0 must have cut over"
    );
    let node1_peer = nodes[1].node.get_peer(&node0_addr).unwrap();
    assert_eq!(
        node1_peer.our_index(),
        Some(pending_idx),
        "node 1 must have promoted the pending it answered with"
    );
    assert_ne!(node1_peer.our_index(), node1_idx_before);

    cleanup_nodes(&mut nodes).await;
}

/// A copy of the msg1 that armed a responder's pending, arriving from an
/// address that is not the peer's current one but that maps to the peer's
/// link, draws the held msg2 only on the peer's established link. Nothing
/// goes back to the address the copy came from. A copy from an address that
/// does not map to the link is refused outright, while the link works.
///
/// A captured msg1 still authenticates as the peer when replayed, so the
/// responder cannot tell a replay from a resend; answering the datagram's
/// source would hand anyone who sends one a reflector.
#[tokio::test]
async fn a_held_rekey_msg2_is_resent_only_on_the_peers_established_link() {
    use crate::node::tests::spanning_tree::make_test_node;

    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    let lost_msg2 = held_msg2.data.clone();
    drop(held_msg2);
    let mut third = vec![make_test_node().await];

    // Capture node 0's resend and deliver it to node 1 under the third node's
    // address, as a spoofed source would.
    nodes[0]
        .node
        .resend_rekeys_at(crate::time::mono_ms() + 1_000)
        .await;
    let mut msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's resent msg1 must be queued at node 1");
    msg1.remote_addr = third[0].addr.clone();
    let link = nodes[1].node.get_peer(&node0_addr).unwrap().link_id();
    let key = (nodes[1].transport_id, third[0].addr.clone());
    nodes[1].node.addr_to_link.insert(key, link);
    nodes[1].node.handle_msg1(msg1).await;

    assert!(
        third[0].packet_rx.try_recv().is_err(),
        "nothing may be sent to the source of the copy"
    );
    let answered: Vec<_> = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert_eq!(
        answered.iter().map(|p| &p.data).collect::<Vec<_>>(),
        vec![&lost_msg2],
        "the held msg2 must go to node 0 on its established link"
    );
    assert!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 1 must still hold its pending"
    );

    cleanup_nodes(&mut nodes).await;
    cleanup_nodes(&mut third).await;
}

/// A ReceiverReport about `highest` frames, as the link-layer message a peer
/// sends: the type byte followed by the body.
fn receiver_report_message(highest: u64) -> Vec<u8> {
    crate::proto::mmp::ReceiverReport {
        highest_counter: highest,
        cumulative_packets_recv: highest,
        cumulative_bytes_recv: highest * 100,
        timestamp_echo: 0,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
        interval_packets_recv: highest as u32,
        interval_bytes_recv: (highest * 100) as u32,
    }
    .encode()
}

/// A link rekey initiator that has cut over keeps its new session's MMP state
/// free of frames the responder sealed on the old session.
///
/// node 0 cuts over and resets its MMP receiver and metrics. node 1 has not
/// yet seen a frame on the new epoch, so it still sends on the old session,
/// and node 0 decrypts those frames against its previous session during the
/// drain. Their payload is still delivered, but they describe the old
/// session: a data frame's counter must not become the new session's highest
/// counter, which would make every new-session frame count as a reorder, and
/// a ReceiverReport about node 0's old-session traffic must not become the
/// baseline later reports are judged against, which would reject every
/// new-session report as regressed. Once node 1 promotes, its frames and
/// reports on the new session are counted and accepted.
#[tokio::test]
async fn frames_on_the_previous_link_session_do_not_feed_the_new_sessions_mmp() {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun0_rx,
        tun1_rx,
        node0_idx_before,
        node1_idx_before,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;

    // node 0 completes its rekey and cuts over on its own tick; nothing is
    // delivered to node 1, which stays on the old session.
    nodes[0].node.handle_msg2(held_msg2).await;
    nodes[0].node.check_rekey().await;
    let peer = nodes[0].node.get_peer(&node1_addr).unwrap();
    assert_ne!(peer.our_index(), node0_idx_before, "node 0 must cut over");
    let mmp = peer.mmp().expect("node 0 must run link MMP");
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

    // node 0's first new-epoch frame promotes node 1; node 1's frames and
    // reports on the new session then feed node 0's MMP.
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

    let HeldMsg2Pair {
        mut nodes,
        node1_addr,
        node0_idx_before,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    nodes[0].node.handle_msg2(held_msg2).await;
    nodes[0].node.check_rekey().await;
    let peer = nodes[0].node.get_peer(&node1_addr).unwrap();
    let previous_idx = peer.previous_our_index().expect("node 0 must be draining");
    assert_eq!(Some(previous_idx), node0_idx_before);
    let current_idx = peer.our_index().expect("node 0 must have cut over");

    // A bounced worker plaintext: the 4-byte session timestamp, then a
    // ReceiverReport about 1000 frames.
    let (transport_id, remote_addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    let bounce = |receiver_idx: u32, counter: u64| {
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
            fmp_flags: 0,
            fmp_plaintext_len: data.len(),
            packet_data: data,
            fmp_plaintext_offset: 0,
        }
    };

    let previous = bounce(previous_idx.as_u32(), 900);
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

    let current = bounce(current_idx.as_u32(), 1);
    nodes[0].node.process_decrypt_fallback(current).await;
    let mmp = nodes[0].node.get_peer(&node1_addr).unwrap().mmp().unwrap();
    assert_eq!(mmp.receiver.highest_counter(), 1);
    assert_eq!(mmp.metrics.rr_counters().map(|(h, _, _)| h), Some(1_000));

    cleanup_nodes(&mut nodes).await;
}

/// Where a captured link rekey msg1 is replayed from, once the cycle it
/// started has completed and the new link session is past the 30 s rekey
/// floor.
#[derive(Clone, Copy, Debug)]
enum ReplaySource {
    /// No replay: the control the other two are measured against.
    Nothing,
    /// An address the node has no link with.
    ThirdAddress,
    /// The peer's own link address.
    PeerAddress,
}

/// The rekey that is attempted after the replay.
#[derive(Clone, Copy, Debug)]
enum ReplayProbe {
    /// node 0, the peer, starts its next rekey.
    PeerRekey,
    /// node 1's own trigger, past its time threshold and its dampening.
    OwnTrigger,
}

/// What a replayed link msg1 left behind.
#[derive(Debug, PartialEq, Eq)]
struct ReplayOutcome {
    /// node 1 holds a pending responder session after the replay.
    armed_pending: bool,
    /// Rekey msg2s node 1 sent to the replay's source address.
    msg2_to_source: usize,
    /// The probed rekey went ahead: node 0 completed on node 1's answer, or
    /// node 1 started one of its own.
    probe_proceeded: bool,
}

/// The outcome when a replay changes nothing.
const REPLAY_HARMLESS: ReplayOutcome = ReplayOutcome {
    armed_pending: false,
    msg2_to_source: 0,
    probe_proceeded: true,
};

/// Deliver `packets` to `node` as the network would have.
async fn dispatch_link_packets(
    node: &mut TestNode,
    packets: Vec<crate::transport::ReceivedPacket>,
) {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_ESTABLISHED, PHASE_MSG1, PHASE_MSG2};

    for packet in packets {
        match CommonPrefix::parse(&packet.data).map(|p| p.phase) {
            Some(PHASE_MSG1) => node.node.handle_msg1(packet).await,
            Some(PHASE_MSG2) => node.node.handle_msg2(packet).await,
            Some(PHASE_ESTABLISHED) => node.node.handle_encrypted_frame(packet).await,
            _ => {}
        }
    }
}

/// Run `cycles` genuine FMP rekeys from node 0 to completion while keeping a
/// copy of the first one's msg1, age node 1's new link session past the 30 s
/// rekey floor, replay the copy to node 1 from `source`, then attempt the
/// rekey `probe` names.
///
/// Both nodes rekey on time, so node 1 has a trigger of its own to probe; its
/// tick is never run before the probe, so it never initiates earlier. A third
/// node with no link to either stands in for the third address, so a msg2 sent
/// there is observable.
async fn replay_link_msg1_after_its_cycle(
    source: ReplaySource,
    probe: ReplayProbe,
    cycles: usize,
) -> ReplayOutcome {
    replay_link_msg1(source, probe, cycles, true).await
}

/// [`replay_link_msg1_after_its_cycle`], with the replay sent either past the
/// rekey floors (`past_floor`) or straight after the last cutover, inside the
/// 10 s in which a same-epoch msg1 is still taken as a duplicate of the link
/// setup.
async fn replay_link_msg1(
    source: ReplaySource,
    probe: ReplayProbe,
    cycles: usize,
    past_floor: bool,
) -> ReplayOutcome {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1, PHASE_MSG2};
    use crate::transport::ReceivedPacket;

    const REKEY_AFTER_SECS: u64 = 60;
    let trigger_age =
        Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let config = || {
        let mut config = crate::config::Config::new();
        config.node.rekey.after_secs = REKEY_AFTER_SECS;
        config.node.rekey.after_messages = u64::MAX;
        config
    };
    let AgedLinkPair {
        mut nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun1_rx,
        ..
    } = aged_link_pair(config(), config(), trigger_age).await;
    nodes.push(make_test_node_with_config(crate::config::Config::new(), 1280).await);

    // The genuine cycles, with a copy of the first one's msg1 kept on the way.
    let mut captured = None;
    for cycle in 0..cycles {
        if cycle > 0 {
            nodes[0]
                .node
                .get_peer_mut(&node1_addr)
                .unwrap()
                .test_backdate_session_established(trigger_age);
            nodes[1]
                .node
                .get_peer_mut(&node0_addr)
                .unwrap()
                .test_backdate_session_established(Duration::from_secs(31));
        }
        let node1_idx_before = nodes[1].node.get_peer(&node0_addr).unwrap().our_index();
        nodes[0].node.check_rekey().await;
        let msg1 = nodes[1]
            .packet_rx
            .try_recv()
            .expect("node 0's rekey msg1 must be queued at node 1");
        assert_eq!(
            CommonPrefix::parse(&msg1.data).map(|p| p.phase),
            Some(PHASE_MSG1),
            "the captured packet must be node 0's rekey msg1"
        );
        captured.get_or_insert_with(|| msg1.data.clone());
        nodes[1].node.handle_msg1(msg1).await;
        pump_until_quiet(&mut nodes).await;
        nodes[0].node.check_rekey().await;
        let first = build_ipv6_packet(&fips0, &fips1, b"first frame on the new link epoch");
        nodes[0].node.handle_tun_outbound(first.clone()).await;
        pump_until_quiet(&mut nodes).await;
        let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
        assert_eq!(
            got,
            vec![first],
            "node 0's first new-epoch frame must decode"
        );
        let peer1 = nodes[1].node.get_peer(&node0_addr).unwrap();
        assert!(
            peer1.pending_new_session().is_none() && peer1.our_index() != node1_idx_before,
            "node 1 must have promoted the genuine cycle's session"
        );
    }
    let captured = captured.expect("at least one cycle must run");

    // Past the floor below which a same-epoch msg1 is a duplicate.
    if past_floor {
        nodes[1]
            .node
            .get_peer_mut(&node0_addr)
            .unwrap()
            .test_backdate_session_established(Duration::from_secs(31));
    }

    let from = match source {
        ReplaySource::Nothing => None,
        ReplaySource::ThirdAddress => Some(2),
        ReplaySource::PeerAddress => Some(0),
    };
    let mut msg2_to_source = 0;
    if let Some(from) = from {
        let replay = ReceivedPacket::new(nodes[1].transport_id, nodes[from].addr.clone(), captured);
        nodes[1].node.handle_msg1(replay).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        let reached: Vec<ReceivedPacket> =
            std::iter::from_fn(|| nodes[from].packet_rx.try_recv().ok()).collect();
        msg2_to_source = reached
            .iter()
            .filter(|p| CommonPrefix::parse(&p.data).map(|p| p.phase) == Some(PHASE_MSG2))
            .count();
        dispatch_link_packets(&mut nodes[from], reached).await;
        pump_until_quiet(&mut nodes).await;
    }
    let armed_pending = nodes[1]
        .node
        .get_peer(&node0_addr)
        .unwrap()
        .pending_new_session()
        .is_some();

    let probe_proceeded = match probe {
        ReplayProbe::PeerRekey => {
            nodes[0]
                .node
                .get_peer_mut(&node1_addr)
                .unwrap()
                .test_backdate_session_established(trigger_age);
            nodes[0].node.check_rekey().await;
            assert!(
                nodes[0]
                    .node
                    .get_peer(&node1_addr)
                    .unwrap()
                    .rekey_in_progress(),
                "node 0 must start its next rekey"
            );
            pump_until_quiet(&mut nodes).await;
            nodes[0]
                .node
                .get_peer(&node1_addr)
                .unwrap()
                .pending_new_session()
                .is_some()
        }
        ReplayProbe::OwnTrigger => {
            let peer = nodes[1].node.get_peer_mut(&node0_addr).unwrap();
            peer.test_backdate_session_established(trigger_age);
            peer.backdate_dampener(Duration::from_secs(31));
            nodes[1].node.check_rekey().await;
            nodes[1]
                .node
                .get_peer(&node0_addr)
                .unwrap()
                .rekey_in_progress()
        }
    };

    cleanup_nodes(&mut nodes).await;
    ReplayOutcome {
        armed_pending,
        msg2_to_source,
        probe_proceeded,
    }
}

/// The control for the peer's next rekey: with nothing replayed, the
/// procedure that measures the replays sees node 1 answer node 0's next rekey.
#[tokio::test]
async fn a_peers_next_link_rekey_is_answered_when_nothing_is_replayed() {
    let outcome =
        replay_link_msg1_after_its_cycle(ReplaySource::Nothing, ReplayProbe::PeerRekey, 1).await;
    assert_eq!(outcome, REPLAY_HARMLESS);
}

/// The control for the node's own trigger: with nothing replayed, node 1
/// starts its own rekey once past its threshold and its dampening.
#[tokio::test]
async fn a_nodes_own_link_rekey_trigger_fires_when_nothing_is_replayed() {
    let outcome =
        replay_link_msg1_after_its_cycle(ReplaySource::Nothing, ReplayProbe::OwnTrigger, 1).await;
    assert_eq!(outcome, REPLAY_HARMLESS);
}

/// A link msg1 from a completed cycle, replayed from an address the node has
/// no link with, must not hold a pending that refuses the peer's next rekey.
#[tokio::test]
async fn a_link_msg1_replayed_from_a_third_address_does_not_block_the_peers_next_rekey() {
    let outcome =
        replay_link_msg1_after_its_cycle(ReplaySource::ThirdAddress, ReplayProbe::PeerRekey, 1)
            .await;
    assert_eq!(outcome, REPLAY_HARMLESS);
}

/// A link msg1 from a completed cycle, replayed from an address the node has
/// no link with, must not hold a pending that suppresses the node's own rekey.
#[tokio::test]
async fn a_link_msg1_replayed_from_a_third_address_does_not_suppress_the_nodes_own_rekey() {
    let outcome =
        replay_link_msg1_after_its_cycle(ReplaySource::ThirdAddress, ReplayProbe::OwnTrigger, 1)
            .await;
    assert_eq!(outcome, REPLAY_HARMLESS);
}

/// A link msg1 from a completed cycle, replayed from the peer's own address,
/// must not hold a pending that refuses the peer's next rekey.
#[tokio::test]
async fn a_link_msg1_replayed_from_the_peers_address_does_not_block_the_peers_next_rekey() {
    let outcome =
        replay_link_msg1_after_its_cycle(ReplaySource::PeerAddress, ReplayProbe::PeerRekey, 1)
            .await;
    assert_eq!(outcome, REPLAY_HARMLESS);
}

/// A link msg1 from a completed cycle, replayed from the peer's own address,
/// must not hold a pending that suppresses the node's own rekey.
#[tokio::test]
async fn a_link_msg1_replayed_from_the_peers_address_does_not_suppress_the_nodes_own_rekey() {
    let outcome =
        replay_link_msg1_after_its_cycle(ReplaySource::PeerAddress, ReplayProbe::OwnTrigger, 1)
            .await;
    assert_eq!(outcome, REPLAY_HARMLESS);
}

/// A link msg1 from an earlier cycle than the last one, replayed from the
/// peer's own address, is refused as well: the node keeps the msg1s of its
/// ended cycles, not only the latest. From the peer's address the replay is
/// on the link, so it reaches that record; from an address off the link it
/// is refused before the record is read.
#[tokio::test]
async fn a_link_msg1_replayed_from_an_earlier_cycle_does_not_block_the_peers_next_rekey() {
    let outcome =
        replay_link_msg1_after_its_cycle(ReplaySource::PeerAddress, ReplayProbe::PeerRekey, 3)
            .await;
    assert_eq!(outcome, REPLAY_HARMLESS);
}

/// A link msg1 replayed from an address the node has no link with, inside the
/// 10 s after a cutover, is taken as a duplicate of the link setup. The stored
/// setup msg2 it draws goes to the peer's established link, never to the
/// address the copy came from, and nothing else changes.
#[tokio::test]
async fn a_link_msg1_replayed_inside_the_rekey_floor_draws_nothing_to_its_source() {
    let outcome = replay_link_msg1(
        ReplaySource::ThirdAddress,
        ReplayProbe::OwnTrigger,
        1,
        false,
    )
    .await;
    assert_eq!(outcome, REPLAY_HARMLESS);
}

/// A fresh rekey msg1 that arrives from an address other than the peer's
/// current one, but that maps to the peer's link, is answered on the peer's
/// established link, not at the address it came from, and the rekey
/// completes there. From an address that does not map to the link the msg1
/// is refused while the link works.
#[tokio::test]
async fn a_rekey_msg2_answers_on_the_peers_established_link_when_the_msg1_source_maps_to_it() {
    use crate::node::tests::spanning_tree::make_test_node;
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG2};

    const REKEY_AFTER_SECS: u64 = 60;
    let trigger_age =
        Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let mut cfg0 = crate::config::Config::new();
    cfg0.node.rekey.after_secs = REKEY_AFTER_SECS;
    cfg0.node.rekey.after_messages = u64::MAX;
    let mut cfg1 = crate::config::Config::new();
    cfg1.node.rekey.after_secs = u64::MAX;
    cfg1.node.rekey.after_messages = u64::MAX;
    let AgedLinkPair {
        mut nodes,
        node0_addr,
        node1_addr,
        ..
    } = aged_link_pair(cfg0, cfg1, trigger_age).await;
    let mut third = vec![make_test_node().await];

    nodes[0].node.check_rekey().await;
    let mut msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's rekey msg1 must be queued at node 1");
    msg1.remote_addr = third[0].addr.clone();
    let link = nodes[1].node.get_peer(&node0_addr).unwrap().link_id();
    let key = (nodes[1].transport_id, third[0].addr.clone());
    nodes[1].node.addr_to_link.insert(key, link);
    nodes[1].node.handle_msg1(msg1).await;

    assert!(
        third[0].packet_rx.try_recv().is_err(),
        "nothing may be sent to the address the msg1 came from"
    );
    let answered: Vec<_> = std::iter::from_fn(|| nodes[0].packet_rx.try_recv().ok()).collect();
    assert_eq!(
        answered
            .iter()
            .map(|p| CommonPrefix::parse(&p.data).map(|p| p.phase))
            .collect::<Vec<_>>(),
        vec![Some(PHASE_MSG2)],
        "the msg2 must go to node 0 on its established link"
    );
    assert!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 1 must hold the session it answered with"
    );
    nodes[0]
        .node
        .handle_msg2(answered.into_iter().next().unwrap())
        .await;
    assert!(
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 0 must complete its rekey on the answer"
    );

    cleanup_nodes(&mut nodes).await;
    cleanup_nodes(&mut third).await;
}

/// A rekey msg1 that arrives on a transport other than the peer's link, from
/// an address that maps to the link, is answered on the link, and the
/// pending session's index is registered under the link's transport: the
/// peer's frames on the new session arrive there, and retirement removes the
/// entry by the peer's transport. Such a msg1 is answered only when it maps
/// to the link, or while a finished connect to the link's address waits to
/// be pooled; the mapping reaches the answer deterministically.
#[tokio::test]
async fn a_rekey_answered_on_the_established_link_registers_its_index_on_that_transport() {
    use crate::transport::TransportId;

    const REKEY_AFTER_SECS: u64 = 60;
    let trigger_age =
        Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let mut cfg0 = crate::config::Config::new();
    cfg0.node.rekey.after_secs = REKEY_AFTER_SECS;
    cfg0.node.rekey.after_messages = u64::MAX;
    let mut cfg1 = crate::config::Config::new();
    cfg1.node.rekey.after_secs = u64::MAX;
    cfg1.node.rekey.after_messages = u64::MAX;
    let AgedLinkPair {
        mut nodes,
        node0_addr,
        node1_addr,
        fips0,
        fips1,
        tun1_rx,
        ..
    } = aged_link_pair(cfg0, cfg1, trigger_age).await;
    let link_transport = nodes[1].transport_id;
    let other_transport = TransportId::new(link_transport.as_u32() + 1);

    nodes[0].node.check_rekey().await;
    let mut msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's rekey msg1 must be queued at node 1");
    msg1.transport_id = other_transport;
    let link = nodes[1].node.get_peer(&node0_addr).unwrap().link_id();
    let key = (other_transport, nodes[0].addr.clone());
    nodes[1].node.addr_to_link.insert(key, link);
    nodes[1].node.handle_msg1(msg1).await;
    let pending_idx = nodes[1]
        .node
        .get_peer(&node0_addr)
        .unwrap()
        .pending_our_index()
        .expect("node 1 must answer the msg1 and hold its new session");
    assert!(
        nodes[1]
            .node
            .peers_by_index
            .contains_key(&(link_transport, pending_idx.as_u32())),
        "the pending index must be registered under the link's transport"
    );
    assert!(
        !nodes[1]
            .node
            .peers_by_index
            .contains_key(&(other_transport, pending_idx.as_u32())),
        "the pending index must not be registered under the msg1's transport"
    );

    // node 0 completes and cuts over; its first new-epoch frame, on the link,
    // must find node 1's pending and promote it.
    pump_until_quiet(&mut nodes).await;
    nodes[0].node.check_rekey().await;
    let first = build_ipv6_packet(&fips0, &fips1, b"first frame on the new link epoch");
    nodes[0].node.handle_tun_outbound(first.clone()).await;
    pump_until_quiet(&mut nodes).await;
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun1_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![first],
        "node 0's first new-epoch frame must decode"
    );
    assert_eq!(
        nodes[1].node.get_peer(&node0_addr).unwrap().our_index(),
        Some(pending_idx),
        "node 1 must promote the pending on node 0's first new-epoch frame"
    );
    assert!(
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_none()
    );

    cleanup_nodes(&mut nodes).await;
}

/// The record of answered msg1s lives with the peer, so a msg1 captured before
/// the peering was formed again, with the peer's epoch unchanged, is not
/// recognized. This node restarting reaches the same state, as does a link
/// torn down and re-formed. Kept as the record of that residual: it stays red
/// until a msg1 carries something that ties it to one cycle, which is a wire
/// change.
#[tokio::test]
#[ignore = "residual: a link msg1 captured before the peering was re-formed in the same peer epoch still arms a responder pending; the answered-msg1 record does not survive the peering"]
async fn a_link_msg1_captured_before_the_peering_was_re_formed_does_not_arm_a_pending() {
    use crate::transport::ReceivedPacket;

    const REKEY_AFTER_SECS: u64 = 60;
    let trigger_age =
        Duration::from_secs(REKEY_AFTER_SECS + crate::node::REKEY_JITTER_SECS as u64 + 1);
    let mut cfg0 = crate::config::Config::new();
    cfg0.node.rekey.after_secs = REKEY_AFTER_SECS;
    cfg0.node.rekey.after_messages = u64::MAX;
    let mut cfg1 = crate::config::Config::new();
    cfg1.node.rekey.after_secs = u64::MAX;
    cfg1.node.rekey.after_messages = u64::MAX;
    let AgedLinkPair {
        mut nodes,
        node0_addr,
        node1_addr,
        ..
    } = aged_link_pair(cfg0, cfg1, trigger_age).await;

    // node 1 answers node 0's rekey; a copy of the msg1 is kept.
    nodes[0].node.check_rekey().await;
    let msg1 = nodes[1]
        .packet_rx
        .try_recv()
        .expect("node 0's rekey msg1 must be queued at node 1");
    let captured = msg1.data.clone();
    nodes[1].node.handle_msg1(msg1).await;
    assert!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "setup: node 1 must answer the genuine msg1"
    );

    // The peering is torn down and formed again; neither node restarts, so
    // node 0's epoch, which the captured msg1 carries, is unchanged.
    nodes[0].node.remove_active_peer(&node1_addr);
    nodes[1].node.remove_active_peer(&node0_addr);
    pump_until_quiet(&mut nodes).await;
    initiate_handshake(&mut nodes, 0, 1).await;
    drain_all_packets(&mut nodes, false).await;
    nodes[1]
        .node
        .get_peer_mut(&node0_addr)
        .expect("setup: the peering must be formed again")
        .test_backdate_session_established(Duration::from_secs(31));

    let replay = ReceivedPacket::new(nodes[1].transport_id, nodes[0].addr.clone(), captured);
    nodes[1].node.handle_msg1(replay).await;
    assert!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_none(),
        "a copy of a msg1 from before the peering was re-formed must not arm a pending"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The responder hold is the drain ceiling at stock settings, and a raised
/// link-dead timeout or heartbeat interval raises it past that ceiling, taking
/// the larger of the two rather than their sum.
#[test]
fn the_responder_hold_is_the_drain_ceiling_at_stock_settings_and_outlasts_a_raised_link_dead_timeout()
 {
    use crate::node::handlers::rekey::{drain_max_retention_ms, pending_hold};

    let stock = crate::config::NodeConfig::default();
    assert_eq!(pending_hold(&stock), Duration::from_secs(120));
    assert_eq!(
        pending_hold(&stock),
        Duration::from_millis(drain_max_retention_ms(&stock.rate_limit))
    );

    // 31 s of msg1 ladder (1+2+4+8+16), three 1 s ticks, and 200 s of
    // link-dead timeout: 234 s.
    let raised = crate::config::NodeConfig {
        link_dead_timeout_secs: 200,
        ..Default::default()
    };
    assert_eq!(pending_hold(&raised), Duration::from_secs(234));

    // The heartbeat term raised instead, link-dead at its default: the floor
    // takes the larger of the two, so 234 s again, not 264 s.
    let raised = crate::config::NodeConfig {
        heartbeat_interval_secs: 200,
        ..Default::default()
    };
    assert_eq!(pending_hold(&raised), Duration::from_secs(234));
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
            .is_some_and(|s| s.state().is_established()),
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
            .is_some_and(|s| s.state().is_initiating()),
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
            .is_some_and(|s| s.state().is_initiating()),
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
        nodes[0]
            .node
            .queue_pending_tun_packet_for_test(NodeAddr::from_bytes(bytes), vec![0x60; 40]);
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
            .is_some_and(|s| s.state().is_initiating()),
        "precondition: a session started"
    );
    assert!(rx0.try_recv().is_err(), "a refused packet is not answered");

    drain_to_quiescence(&mut nodes).await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1)
            .is_some_and(|s| s.state().is_established())
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

/// Helper: complete a Noise IK handshake and return the initiator's NoiseSession.
pub(super) fn make_noise_session(
    our_identity: &Identity,
    remote_identity: &Identity,
) -> crate::noise::NoiseSession {
    use crate::noise::HandshakeState;

    let mut initiator =
        HandshakeState::new_initiator(our_identity.keypair(), remote_identity.pubkey_full());
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
        session_at(1000), // created at t=1000ms
        true,
    );

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
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        session_at(1000),
        true,
    );

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
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let remote = Identity::generate();
    let remote_addr = *remote.node_addr();

    let handshake = HandshakeState::new_initiator(node.identity().keypair(), remote.pubkey_full());
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
        true,
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
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        session_at(1000),
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
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        session_at(1000),
        true,
    );

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
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        session_at(1000), // created at t=1s
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
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
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
        session_at(1000),
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
        session_at(1000),
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

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
        true,
    );

    // Initially no handshake payload
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at(), None);

    // Store a handshake payload
    let payload = vec![0x01, 0x02, 0x03, 0x04];
    entry.set_handshake_payload(payload.clone(), session_at(2000));

    assert_eq!(entry.handshake_payload().unwrap(), &payload);
    assert_eq!(entry.resend_count(), 0);
    assert_eq!(entry.next_resend_at(), Some(session_at(2000)));
}

/// Test that resend_count and next_resend_at_ms track correctly on SessionEntry.
#[test]
fn test_session_entry_resend_tracking() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
        true,
    );

    entry.set_handshake_payload(vec![0x01], session_at(2000));

    // Record first resend
    entry.record_resend(session_at(4000));
    assert_eq!(entry.resend_count(), 1);
    assert_eq!(entry.next_resend_at(), Some(session_at(4000)));

    // Record second resend
    entry.record_resend(session_at(8000));
    assert_eq!(entry.resend_count(), 2);
    assert_eq!(entry.next_resend_at(), Some(session_at(8000)));
}

/// Test that clear_handshake_payload clears payload and resets timer.
#[test]
fn test_session_entry_clear_handshake_payload() {
    use crate::noise::HandshakeState;

    let identity_a = Identity::generate();
    let identity_b = Identity::generate();

    let handshake = HandshakeState::new_initiator(identity_a.keypair(), identity_b.pubkey_full());

    let mut entry = crate::node::session::SessionEntry::new(
        *identity_b.node_addr(),
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
        true,
    );

    entry.set_handshake_payload(vec![0x01, 0x02], session_at(2000));
    entry.record_resend(session_at(4000));
    assert!(entry.handshake_payload().is_some());
    assert_eq!(entry.resend_count(), 1);

    // Clear on Established transition
    entry.clear_handshake_payload();
    assert!(entry.handshake_payload().is_none());
    assert_eq!(entry.next_resend_at(), None);
    // resend_count is NOT reset — it's a historical record
    assert_eq!(entry.resend_count(), 1);
}

/// Test that session handshake timeout removes stale Initiating sessions.
#[tokio::test]
async fn test_session_handshake_timeout() {
    use crate::noise::HandshakeState;

    let mut node = make_node();

    let identity_b = Identity::generate();
    let handshake =
        HandshakeState::new_initiator(node.identity().keypair(), identity_b.pubkey_full());

    let dest_addr = *identity_b.node_addr();

    // Create a session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        dest_addr,
        identity_b.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
        true,
    );
    node.sessions.insert(dest_addr, entry);

    assert!(node.sessions.contains_key(&dest_addr));

    // Before timeout: session should remain
    let timeout_secs = node.config().node.rate_limit.handshake_timeout_secs;
    let before_timeout = 1000 + timeout_secs * 1000 - 1;
    node.resend_pending_session_handshakes(session_at(before_timeout))
        .await;
    assert!(
        node.sessions.contains_key(&dest_addr),
        "Session should survive before timeout"
    );

    // After timeout: session should be removed
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(session_at(after_timeout))
        .await;
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

    let handshake = HandshakeState::new_xk_responder(identity_b.keypair());

    let src_addr = *identity_a.node_addr();

    // Create an AwaitingMsg3 session at time 1000
    let entry = crate::node::session::SessionEntry::new(
        src_addr,
        identity_a.pubkey_full(),
        EndToEndState::AwaitingMsg3(handshake),
        session_at(1000),
        false,
    );
    node.sessions.insert(src_addr, entry);

    assert!(node.sessions.contains_key(&src_addr));

    // After timeout: session should be removed
    let timeout_secs = node.config().node.rate_limit.handshake_timeout_secs;
    let after_timeout = 1000 + timeout_secs * 1000 + 1;
    node.resend_pending_session_handshakes(session_at(after_timeout))
        .await;
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

    let src_fips = crate::Ipv6Address::from_node_addr(&node0_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&node1_addr);

    // Establish session (XK: 3 messages — Setup, Ack, Msg3)
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
    use crate::noise::HandshakeState;

    let handshake = HandshakeState::new_xk_responder(node.identity().keypair());
    let placeholder = node.identity().keypair().public_key();
    let entry = crate::node::session::SessionEntry::new(
        claimed,
        placeholder,
        EndToEndState::AwaitingMsg3(handshake),
        session_at(1000),
        false,
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
    use crate::noise::HandshakeState;

    let handshake =
        HandshakeState::new_xk_initiator(node.identity().keypair(), remote.pubkey_full());
    let remote_addr = *remote.node_addr();
    let entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Initiating(handshake),
        session_at(1000),
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
            .state()
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
/// can tell "restored by the reseed" apart from "never a candidate".
async fn node_with_link_seed(
    mtu: u16,
) -> (
    Node,
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

/// A half-open responder entry holds this node's own key as a placeholder
/// for the peer's, so the identity-cache fill that runs before the signal's
/// lookup would file that key under the claimed address if the signal were
/// admitted. With no cached identity for the address beforehand, none may
/// follow.
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
    let mut entry = crate::node::session::SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        session_at(1000),
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
        session_at(1000),
        true,
    );
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
// Session identity binding: XK msg3 source address / static key
// ============================================================================

/// Helper: drive a full XK exchange against `responder_identity` and return
/// the responder's half-completed handshake plus the initiator's msg3.
///
/// The msg3 is cryptographically valid for the responder and carries
/// `initiator_identity`'s static key, which is exactly the shape of the
/// defect: a peer that completes a real handshake while the datagram claims
/// somebody else's source address.
fn drive_xk_to_msg3(
    initiator_identity: &Identity,
    responder_identity: &Identity,
) -> (crate::noise::HandshakeState, Vec<u8>) {
    use crate::noise::HandshakeState;

    let mut initiator = HandshakeState::new_xk_initiator(
        initiator_identity.keypair(),
        responder_identity.pubkey_full(),
    );
    let mut responder = HandshakeState::new_xk_responder(responder_identity.keypair());

    let mut init_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut init_epoch);
    initiator.set_local_epoch(init_epoch);
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    responder.set_local_epoch(resp_epoch);

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator.write_xk_message_3().unwrap();

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

    let (responder, msg3) = drive_xk_to_msg3(&attacker, node.identity());

    // Half-open session recorded under the victim's address, as
    // handle_session_setup would have done from the claimed source, a
    // handshake timeout ago, so its hold does not keep the entry once the
    // msg3 drops the candidate.
    let timeout_ms = node.config().node.rate_limit.handshake_timeout_secs * 1000;
    let entry = crate::node::session::SessionEntry::new(
        victim_addr,
        node.identity().pubkey_full(),
        EndToEndState::AwaitingMsg3(responder),
        session_before(Node::session_now(), timeout_ms + 1_000),
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

    let (responder, msg3) = drive_xk_to_msg3(&peer, node.identity());

    let entry = crate::node::session::SessionEntry::new(
        peer_addr,
        node.identity().pubkey_full(),
        EndToEndState::AwaitingMsg3(responder),
        session_at(1000),
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
        session_at(1000),
        true,
    );
    entry.mark_established(session_at(1000));

    // Responder-side rekey armed, but driven by a different identity.
    let (responder, msg3) = drive_xk_to_msg3(&attacker, node.identity());
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
        session_at(1000),
        true,
    );
    entry.mark_established(session_at(1000));

    let (responder, msg3) = drive_xk_to_msg3(&legit, node.identity());
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
        session_at(1000),
        true,
    );
    entry.mark_established(session_at(1000));

    let (responder, msg3) = drive_xk_to_msg3(&legit, node.identity());
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
    let (mut node, peer_addr) = make_node_with_established_peer(peer);
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
    let (responder, msg3) = drive_xk_to_msg3(stranger, node.identity());

    let idle_ms = node.config().node.session.idle_timeout_secs * 1000;
    let now = Node::session_now();
    let entry = node.sessions.get_mut(peer_addr).unwrap();
    entry.set_pending_session(pending);
    // Stale enough that `pending_stale` is true, which is what lets a forged
    // setup arm the handshake this state starts from.
    entry.set_rekey_completed(session_before(now, idle_ms + 60_000));
    entry.set_rekey_state(responder, false);
    entry.record_peer_rekey(now);

    msg3
}

#[tokio::test]
async fn test_forged_msg3_against_a_peer_armed_handshake_leaves_the_completed_epoch_intact() {
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr, valid_msg3) =
        install_stale_pending_beside_a_stranger_armed_handshake(&peer, &stranger);
    // Backdate the stamp the handshake's deadline runs from, so a restore
    // that restamped it to the current time could not match by accident.
    let armed_at = session_before(Node::session_now(), 5_000);
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .record_peer_rekey(armed_at);

    // Garbage of the right length: `read_xk_message_3` fails on the AEAD.
    let forged = SessionMsg3::new(vec![0u8; crate::noise::XK_HANDSHAKE_MSG3_SIZE]).encode();
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert_eq!(
        entry.last_peer_rekey(),
        Some(armed_at),
        "the restore must not restamp the handshake's deadline, or a spray \
         would hold it open"
    );
    assert!(
        entry.pending_new_session().is_some(),
        "an unauthenticated msg3 must not discard the key epoch the peer may \
         already have cut over to"
    );
    assert!(
        entry.is_established(),
        "the running session must be left intact alongside the pending one"
    );
    assert!(
        entry.has_rekey_in_progress() && !entry.is_rekey_initiator(),
        "an unreadable msg3 must not discard the handshake it failed against"
    );

    // The handshake went back rolled back: the msg3 that genuinely finishes
    // it still reads, and the key-mismatch arm, not the read, refuses it.
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
    assert!(entry.pending_new_session().is_some());
    assert!(!entry.has_rekey_in_progress());
}

#[tokio::test]
async fn test_rekey_msg3_from_a_different_static_key_leaves_the_completed_epoch_intact() {
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr, valid_msg3) =
        install_stale_pending_beside_a_stranger_armed_handshake(&peer, &stranger);

    // Cryptographically valid for the handshake the stranger armed, so
    // `read_xk_message_3` succeeds and the key-mismatch branch decides.
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

/// Build a two-node routable mesh with default configs and every node's
/// coordinate cache populated.
async fn make_routable_pair() -> Vec<TestNode> {
    let configs = (0..2).map(|_| Config::new()).collect();
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
fn forge_setup_from_stranger(nodes: &[TestNode]) -> Vec<u8> {
    use crate::noise::HandshakeState;
    use crate::proto::fsp::SessionSetup;

    let attacker = Identity::generate();
    let mut handshake = HandshakeState::new_xk_initiator(
        attacker.keypair(),
        nodes[1].node.identity().pubkey_full(),
    );
    handshake.set_local_epoch([0xA5; 8]);
    let msg1 = handshake
        .write_xk_message_1()
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
    // The cap is a ceiling, not a latch: half-open entries are reaped after
    // `handshake_timeout_secs` and the room they free must be usable.
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

    let timeout_ms = nodes[1]
        .node
        .config()
        .node
        .rate_limit
        .handshake_timeout_secs
        * 1000;
    let now = Node::session_now();
    nodes[1]
        .node
        .resend_pending_session_handshakes(session_after(now, timeout_ms + 1))
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
/// the symmetric state. The epoch ciphertext after it is zeroed, so the read
/// fails only once the point has been mixed in.
fn forged_session_ack(from: &TestNode) -> Vec<u8> {
    let mut payload = Identity::generate().pubkey_full().serialize().to_vec();
    payload.extend_from_slice(&[0u8; crate::noise::EPOCH_ENCRYPTED_SIZE]);
    assert_eq!(payload.len(), crate::noise::XK_HANDSHAKE_MSG2_SIZE);
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
    let forged = SessionMsg3::new(vec![0u8; crate::noise::XK_HANDSHAKE_MSG3_SIZE]).encode();
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

/// One lost initial msg3 must cost one resend, not the session, and the
/// recovery must not depend on a rekey.
#[tokio::test]
async fn a_lost_initial_msg3_is_resent_and_the_responder_completes_the_session() {
    let mut nodes = pair_with_lost_initial_msg3().await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    let (tun0_tx, tun0_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun0_tx);
    let (tun1_tx, tun1_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun1_tx);
    let fips0 = crate::Ipv6Address::from_node_addr(&node0_addr);
    let fips1 = crate::Ipv6Address::from_node_addr(&node1_addr);

    let interval_ms = nodes[0]
        .node
        .config()
        .node
        .rate_limit
        .handshake_resend_interval_ms;
    nodes[0]
        .node
        .resend_pending_session_handshakes(session_after(Node::session_now(), interval_ms + 1))
        .await;
    pump_until_quiet(&mut nodes).await;

    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .expect("responder entry present")
            .is_established(),
        "node 1 must complete the session once node 0 resends its msg3"
    );

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

/// On a healthy session the retained msg3 is released by the responder's
/// first frame, so the resend window is one round trip wide and a later tick
/// sends nothing.
#[tokio::test]
async fn an_initiator_stops_resending_msg3_once_a_responder_frame_authenticates() {
    let mut nodes = make_routable_pair().await;
    establish_pair_session(&mut nodes).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let (tun0_tx, tun0_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun0_tx);
    let fips0 = crate::Ipv6Address::from_node_addr(&node0_addr);
    let fips1 = crate::Ipv6Address::from_node_addr(&node1_addr);
    let interval_ms = nodes[0]
        .node
        .config()
        .node
        .rate_limit
        .handshake_resend_interval_ms;

    // Control: before the responder has sent anything, the sweep does resend,
    // so a silent sweep at the end is the release and not a dead driver.
    let t1 = session_after(Node::session_now(), interval_ms + 1);
    nodes[0].node.resend_pending_session_handshakes(t1).await;
    assert_eq!(
        drain_queued(&mut nodes[1]),
        1,
        "control: the sweep must resend msg3 while the responder is unheard"
    );

    let rev = build_ipv6_packet(&fips1, &fips0, b"responder's first frame");
    nodes[1].node.handle_tun_outbound(rev.clone()).await;
    pump_until_quiet(&mut nodes).await;
    let got: Vec<Vec<u8>> = std::iter::from_fn(|| tun0_rx.try_recv().ok()).collect();
    assert_eq!(
        got,
        vec![rev],
        "the responder's frame must authenticate at node 0"
    );
    assert_eq!(nodes[1].packet_rx.len(), 0, "nothing may be left queued");

    nodes[0]
        .node
        .resend_pending_session_handshakes(session_after(t1, 64_000))
        .await;
    assert_eq!(
        nodes[1].packet_rx.len(),
        0,
        "a msg3 the responder has answered must not be resent"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The resend is harmless to a responder that already completed: it is
/// refused as a bad-state reject and both directions keep decoding. This is
/// the wire-neutrality claim, observed rather than argued.
#[tokio::test]
async fn a_resent_msg3_reaching_an_established_responder_is_refused_and_the_session_keeps_working()
{
    let mut nodes = make_routable_pair().await;
    establish_pair_session(&mut nodes).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();
    let (tun0_tx, tun0_rx) = std::sync::mpsc::channel();
    nodes[0].node.install_tun(tun0_tx);
    let (tun1_tx, tun1_rx) = std::sync::mpsc::channel();
    nodes[1].node.install_tun(tun1_tx);
    let fips0 = crate::Ipv6Address::from_node_addr(&node0_addr);
    let fips1 = crate::Ipv6Address::from_node_addr(&node1_addr);
    let interval_ms = nodes[0]
        .node
        .config()
        .node
        .rate_limit
        .handshake_resend_interval_ms;
    let before = nodes[1].node.stats().session.bad_state;

    nodes[0]
        .node
        .resend_pending_session_handshakes(session_after(Node::session_now(), interval_ms + 1))
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

/// The resend ladder is bounded in count and in time: after
/// `handshake_max_resends` resends nothing more is sent and the payload is no
/// longer held, while the session itself is kept.
#[tokio::test]
async fn initial_msg3_resends_stop_at_the_budget_and_release_the_payload() {
    let mut nodes = pair_with_lost_initial_msg3().await;
    let node1_addr = *nodes[1].node.node_addr();
    let max_resends = nodes[0].node.config().node.rate_limit.handshake_max_resends;

    // 64 s steps pass any single backoff interval at stock settings, so each
    // step is due. Node 0 holds only its established entry, so the sweep's
    // timeout pass cannot remove anything on it.
    let mut now = Node::session_now();
    let mut sent = Vec::new();
    for _ in 0..(max_resends + 2) {
        now = session_after(now, 64_000);
        nodes[0].node.resend_pending_session_handshakes(now).await;
        sent.push(drain_queued(&mut nodes[1]));
    }
    let mut expected = vec![1; max_resends as usize];
    expected.extend([0, 0]);
    assert_eq!(
        sent, expected,
        "one resend per due tick up to the budget, then none"
    );

    let entry = nodes[0]
        .node
        .get_session(&node1_addr)
        .expect("the release must not tear the session down");
    assert!(
        entry.handshake_payload().is_none(),
        "the msg3 must no longer be held once the budget is spent"
    );
    assert!(
        entry.is_established(),
        "node 0's session must stay established after the release"
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
    nodes[0].node.check_session_rekey().await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .is_some_and(|e| e.has_rekey_in_progress() && e.is_rekey_initiator()),
        "node 0 must have initiated a rekey"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..]).await;
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .is_some_and(|e| e.has_rekey_in_progress() && !e.is_rekey_initiator()),
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
        entry.has_rekey_in_progress() && entry.is_rekey_initiator(),
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
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 0 must complete the rekey on the genuine ack"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "node 1 must hold the new session after msg3"
    );

    // node 0 cuts over on its liveness timer, and data decodes both ways on
    // the new epoch.
    let now = Node::session_now();
    nodes[0]
        .node
        .sessions
        .get_mut(&node1_addr)
        .unwrap()
        .set_rekey_completed(session_before(now, 10_000));
    nodes[0].node.check_session_rekey().await;
    assert!(
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_none(),
        "node 0 must have cut over"
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
        "node 0's first new-epoch frame must complete node 1's cutover"
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

    nodes[0].node.check_session_rekey().await;
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
        nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "the rekey must complete at node 0"
    );
    assert!(
        nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .pending_new_session()
            .is_some(),
        "and at node 1"
    );

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
    let mut entry = crate::node::session::SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Established(session),
        session_at(1000),
        true,
    );
    entry.mark_established(session_at(1000));
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

/// Build the initiator-side XK handshake `initiate_session_rekey` would
/// leave on the entry, without needing a route to send its msg1 over.
fn our_rekey_initiator_handshake(node: &Node, peer: &Identity) -> crate::noise::HandshakeState {
    let mut handshake = crate::noise::HandshakeState::new_xk_initiator(
        node.identity().keypair(),
        peer.pubkey_full(),
    );
    handshake.set_local_epoch([0x11; 8]);
    handshake
        .write_xk_message_1()
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
    let mut node = make_node_with(Config::new());

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
    let mut node = make_node_with(Config::new());

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
async fn test_a_setup_against_a_peer_armed_handshake_is_dropped_and_keeps_the_handshake_and_the_completed_epoch()
 {
    let mut node = make_node_with(Config::new());

    // Our address sorts larger, which is the end that used to yield: the
    // tie-break would make us the responder to the second setup.
    let peer = peer_identity_sorting_below(node.node_addr());
    let peer_addr = install_established_peer(&mut node, &peer);

    // What a first setup leaves: a handshake the sender armed, beside a
    // completed epoch too stale for `pending_outranks` to veto, so only the
    // armed handshake stands between a second setup and the arming path.
    let stranger = Identity::generate();
    let valid_msg3 =
        arm_stranger_handshake_beside_stale_pending(&mut node, &peer_addr, &peer, &stranger);
    assert!(
        !node.sessions.get(&peer_addr).unwrap().is_rekey_initiator(),
        "the state under test is a handshake we did not arm"
    );

    let forged = forge_setup_for(&node);
    node.handle_session_payload(&peer_addr, &stub_link_peer(), &forged, 1280, false)
        .await;

    let stats = &node.stats().session;
    assert_eq!(
        stats.rekey_held, 1,
        "a setup meeting a peer-armed handshake must be dropped and counted"
    );
    assert_eq!(
        (stats.rekey_yielded, stats.rekey_tiebreak, stats.rekey_armed),
        (0, 0, 0),
        "the tie-break is for two initiators; nothing may yield or arm here"
    );
    let entry = node.sessions.get(&peer_addr).expect("session present");
    assert!(
        entry.pending_new_session().is_some() && entry.is_established(),
        "the completed epoch and the running session must be left intact"
    );
    assert!(
        entry.has_rekey_in_progress() && !entry.is_rekey_initiator(),
        "the handshake the peer armed must survive the setup, since a peer \
         that read our SessionAck needs it for its msg3"
    );

    // The kept handshake is the same one: its own msg3 still reads.
    node.handle_session_payload(
        &peer_addr,
        &stub_link_peer(),
        &SessionMsg3::new(valid_msg3).encode(),
        1280,
        false,
    )
    .await;
    assert_eq!(node.stats().session.rekey_key_mismatch, 1);
}

#[tokio::test]
async fn test_a_responder_handshake_with_no_peer_rekey_stamp_is_not_expired_by_the_tick_loop() {
    let peer = Identity::generate();
    let stranger = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

    // Arm a responder-side handshake but leave `last_peer_rekey` unset.
    // The expiry predicate's "stamp present" conjunct is what stops that
    // unset stamp being read as infinitely old. This pins a
    // defence-in-depth guard: the state is unreachable in production, since
    // the only responder arming stamps the field on the adjacent line.
    let (responder, _msg3) = drive_xk_to_msg3(&stranger, node.identity());
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_rekey_state(responder, false);
    assert_eq!(
        node.sessions.get(&peer_addr).unwrap().last_peer_rekey(),
        None,
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

/// The counterpart for a handshake this node armed: with no `initiated`
/// stamp it reads as expired, deliberately, since dropping it costs a retry
/// and keeping it stops rotation.
#[tokio::test]
async fn an_initiator_rekey_without_a_stamp_reads_as_expired() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

    let ours = crate::noise::HandshakeState::new_xk_initiator(
        node.identity().keypair(),
        peer.pubkey_full(),
    );
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_rekey_state(ours, true);
    assert_eq!(
        node.sessions.get(&peer_addr).unwrap().initiated(),
        None,
        "test fixture must actually leave the stamp unset"
    );

    node.check_session_rekey().await;

    assert!(
        !node
            .sessions
            .get(&peer_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "an unstamped handshake this node armed must be retired"
    );
    assert_eq!(node.stats().session.rekey_unanswered, 1);
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

    let old = make_noise_session(node.identity(), &peer);
    node.sessions
        .get_mut(&peer_addr)
        .unwrap()
        .set_previous_session_for_test(old, session_at(1000));
    assert!(node.sessions.get(&peer_addr).unwrap().is_draining());

    // The session clock is monotonic and counts from process start, so the
    // drain started at 1 s is long ago only once that much time has passed.
    crate::time::advance(std::time::Duration::from_secs(3_600));
    node.check_session_rekey().await;

    assert!(
        !node.sessions.get(&peer_addr).unwrap().is_draining(),
        "a drain window that expired long ago must be completed"
    );
}

#[tokio::test]
async fn test_abandoned_peer_armed_rekey_expires_on_the_handshake_timeout() {
    let peer = Identity::generate();
    let attacker = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

    // A setup message armed a responder-side handshake whose msg3 never came.
    let (responder, _msg3) = drive_xk_to_msg3(&attacker, node.identity());
    let now = Node::session_now();
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.set_rekey_state(responder, false);
    entry.record_peer_rekey(session_before(now, 31_000));

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
    let mut handshake =
        HandshakeState::new_xk_initiator(stranger.keypair(), node.identity().pubkey_full());
    handshake.set_local_epoch([0x5A; 8]);
    let msg1 = handshake
        .write_xk_message_1()
        .expect("stranger msg1 must build");

    let coords = node.tree_state().my_coords().clone();
    SessionSetup::new(coords.clone(), coords)
        .with_handshake(msg1)
        .encode()
}

#[tokio::test]
async fn test_setup_naming_peer_with_pending_session_is_dropped_and_counted() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

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
async fn test_completed_peer_rekey_session_is_never_expired_by_the_tick_loop() {
    let peer = Identity::generate();
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

    // A rekey the peer armed completed long ago, and the peer has not yet
    // appeared on the new epoch. The keys are the epoch that peer cut over
    // to, so no amount of waiting may discard them.
    let pending = make_noise_session(node.identity(), &peer);
    let idle_ms = node.config().node.session.idle_timeout_secs * 1000;
    let now = Node::session_now();
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.set_pending_session(pending);
    entry.set_rekey_completed(session_before(now, idle_ms + 60_000));
    entry.record_peer_rekey(session_before(now, idle_ms + 60_000));

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
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

    // The peer's earlier rekey completed and is still waiting for its
    // cutover; a later setup message armed a handshake whose msg3 never
    // came. Expiring the handshake must not take the keys with it.
    let pending = make_noise_session(node.identity(), &peer);
    let (responder, _msg3) = drive_xk_to_msg3(&peer, node.identity());
    let now = Node::session_now();
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.set_pending_session(pending);
    entry.set_rekey_completed(session_before(now, 120_000));
    entry.set_rekey_state(responder, false);
    entry.record_peer_rekey(session_before(now, 31_000));

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
    let (mut node, peer_addr) = make_node_with_established_peer(&peer);

    let (responder, _msg3) = drive_xk_to_msg3(&peer, node.identity());
    let now = Node::session_now();
    let entry = node.sessions.get_mut(&peer_addr).unwrap();
    entry.set_rekey_state(responder, false);
    entry.record_peer_rekey(now);

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
    nodes
}

/// Send one data frame from `nodes[from]` across its rekey trigger, deliver
/// it, then run `nodes[from]`'s tick so it sends a rekey SessionSetup, and
/// assert it now holds an initiated rekey.
async fn start_rekey(nodes: &mut [TestNode], from: usize) {
    let peer = *nodes[1 - from].node.node_addr();
    nodes[from]
        .node
        .send_session_data(&peer, 0, 0, b"crosses the rekey trigger")
        .await
        .expect("send_session_data failed");
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(nodes).await;

    nodes[from].node.check_session_rekey().await;
    assert!(
        rekey_initiated(&nodes[from], &peer),
        "node {from} must have initiated a rekey"
    );
}

/// Whether `node` holds a rekey handshake toward `peer` that it initiated.
fn rekey_initiated(node: &TestNode, peer: &NodeAddr) -> bool {
    node.node
        .get_session(peer)
        .is_some_and(|e| e.has_rekey_in_progress() && e.is_rekey_initiator())
}

/// Whether `node`'s session with `peer` holds a completed rekey session.
fn holds_pending(node: &TestNode, peer: &NodeAddr) -> bool {
    node.node
        .get_session(peer)
        .is_some_and(|e| e.pending_new_session().is_some())
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

/// A rekey whose SessionSetup was lost is retired once the handshake timeout
/// has passed, and the trigger then starts a fresh rekey that completes.
#[tokio::test]
async fn test_a_rekey_whose_session_setup_was_lost_is_retired_after_the_handshake_timeout_and_retried()
 {
    let mut nodes = rekey_pair([true, false], Some(1)).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[1]) > 0,
        "node 0's SessionSetup must have been queued at node 1 to be lost"
    );
    assert_eq!(nodes[1].node.stats().session.rekey_armed, 0);
    assert!(
        !nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "the setup must really have been dropped before node 1 armed"
    );

    tokio::time::sleep(Duration::from_millis(1200)).await;
    nodes[0].node.check_session_rekey().await;
    assert!(
        !nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "an unanswered rekey this node initiated must be retired after the \
         handshake timeout, or the trigger stays vetoed for good"
    );

    nodes[0].node.check_session_rekey().await;
    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "the trigger must start a fresh rekey once the old one is retired"
    );
    pump_all(&mut nodes).await;
    assert_eq!(
        nodes[1].node.stats().session.rekey_armed,
        1,
        "the retried setup must reach node 1"
    );
    assert!(
        holds_pending(&nodes[0], &node1_addr) && holds_pending(&nodes[1], &node0_addr),
        "the retried rekey must complete on both nodes"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_unanswered,
        1,
        "the retired handshake must be counted once"
    );
    assert_eq!(nodes[1].node.stats().session.rekey_unanswered, 0);

    cleanup_nodes(&mut nodes).await;
}

/// A rekey whose SessionAck was lost is retired once the handshake timeout
/// has passed, beside the responder's own expiry, and the retry completes.
#[tokio::test]
async fn test_a_rekey_whose_session_ack_was_lost_is_retired_after_the_handshake_timeout_and_retried()
 {
    let mut nodes = rekey_pair([true, false], Some(1)).await;
    let node0_addr = *nodes[0].node.node_addr();
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[1..]).await;
    assert_eq!(
        nodes[1].node.stats().session.rekey_armed,
        1,
        "node 1 must have armed as the rekey responder"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[0]) > 0,
        "node 1's SessionAck must have been queued at node 0 to be lost"
    );

    tokio::time::sleep(Duration::from_millis(1200)).await;
    nodes[1].node.check_session_rekey().await;
    assert_eq!(
        nodes[1].node.stats().session.rekey_expired,
        1,
        "node 1's own handshake must expire on the existing responder rule"
    );
    assert!(
        !nodes[1]
            .node
            .get_session(&node0_addr)
            .unwrap()
            .has_rekey_in_progress()
    );

    nodes[0].node.check_session_rekey().await;
    assert!(
        !nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "an unanswered rekey this node initiated must be retired after the \
         handshake timeout, or the trigger stays vetoed for good"
    );

    nodes[0].node.check_session_rekey().await;
    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "the trigger must start a fresh rekey once the old one is retired"
    );
    pump_all(&mut nodes).await;
    assert_eq!(
        nodes[1].node.stats().session.rekey_armed,
        2,
        "the retried setup must reach node 1"
    );
    assert!(
        holds_pending(&nodes[0], &node1_addr) && holds_pending(&nodes[1], &node0_addr),
        "the retried rekey must complete on both nodes"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_unanswered,
        1,
        "the retired handshake must be counted once"
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
/// stranger, and return how many rekey handshakes the victim has armed.
async fn forge_rekey_setup(nodes: &mut [TestNode], claimed: usize, victim: usize) -> u64 {
    let claimed_addr = *nodes[claimed].node.node_addr();
    let forged = forge_setup_naming(&nodes[claimed], &nodes[victim]);
    nodes[victim]
        .node
        .handle_session_payload(&claimed_addr, &claimed_addr, &forged, 1280, false)
        .await;
    nodes[victim].node.stats().session.rekey_armed
}

/// Forged setups naming each end of an established pair, delivered to the
/// other end once per handshake timeout, each just after the handshake the
/// last one armed has expired, must not stop the pair's scheduled rotation:
/// each end's own rekey trigger fires, and each end completes a rekey with
/// the other. Today each forged setup arms a responder handshake that vetoes
/// the trigger and opens the dampening window, and a genuine setup that meets
/// the other end's armed handshake is dropped, so neither end rotates while
/// the forger keeps this up.
#[tokio::test]
#[ignore = "known defect: an unauthenticated setup naming an established peer arms a handshake that vetoes the node's own rekey and refuses the peer's"]
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
            assert_eq!(
                forge_rekey_setup(&mut nodes, 1 - victim, victim).await,
                window,
                "precondition: the forged setup of window {window} must reach node {victim}"
            );
        }
        for i in 0..2 {
            nodes[i].node.check_session_rekey().await;
            initiated[i] |= rekey_initiated(&nodes[i], &addrs[1 - i]);
        }
        pump_all(&mut nodes).await;
        for i in 0..2 {
            completed[i] |= holds_pending(&nodes[i], &addrs[1 - i]);
        }
        crate::time::advance(timeout);
        for end in nodes.iter_mut() {
            end.node.check_session_rekey().await;
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
/// completes with the peer. Today the larger node abandons its own rekey for
/// the forged one before reading the forged msg1, so one setup cancels its
/// rotation.
#[tokio::test]
#[ignore = "known defect: at the larger address a forged setup makes the node abandon its own rekey in flight"]
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
    assert_eq!(
        forge_rekey_setup(&mut nodes, small, large).await,
        1,
        "precondition: the forged setup must reach the larger node and be answered"
    );
    assert!(
        rekey_initiated(&nodes[large], &small_addr),
        "the larger node's own rekey must survive a forged setup naming its peer"
    );

    pump_all(&mut nodes).await;
    assert!(
        holds_pending(&nodes[large], &small_addr) && holds_pending(&nodes[small], &large_addr),
        "the larger node's own rekey must then complete with its peer"
    );
    cleanup_nodes(&mut nodes).await;
}

/// Drive a lost SessionAck, then a retry that meets the responder's own
/// handshake from the first attempt, still armed because nothing has run the
/// responder's expiry yet.
///
/// Both nodes would rekey after one message; the initiator is picked at run
/// time so that the responder holds the smaller address when
/// `responder_smaller`, and the larger otherwise. Only the initiator's tick
/// is run before the responder has armed, after which the responder is
/// dampened and cannot start a rekey of its own inside the test.
///
/// A responder holding a handshake its peer armed drops the retry before
/// arming anything, at either address, since that handshake is the only one
/// a peer that read the SessionAck could finish. Both handshakes then
/// expire, and the next retry completes one timeout later.
async fn lostack_retry(responder_smaller: bool) {
    let mut nodes = rekey_pair([true, true], Some(1)).await;
    let node0_smaller =
        crate::proto::fsp::initiation_winner(nodes[0].node.node_addr(), nodes[1].node.node_addr());
    let resp = if responder_smaller == node0_smaller {
        0
    } else {
        1
    };
    let init = 1 - resp;
    let init_addr = *nodes[init].node.node_addr();
    let resp_addr = *nodes[resp].node.node_addr();

    // First attempt: the responder arms, and its SessionAck is lost.
    start_rekey(&mut nodes, init).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[resp..=resp]).await;
    assert_eq!(
        nodes[resp].node.stats().session.rekey_armed,
        1,
        "the responder must have armed"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[init]) > 0,
        "the responder's SessionAck must have been queued to be lost"
    );

    tokio::time::sleep(Duration::from_millis(1200)).await;
    nodes[init].node.check_session_rekey().await;
    assert!(
        !nodes[init]
            .node
            .get_session(&resp_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "an unanswered rekey this node initiated must be retired after the \
         handshake timeout, or the trigger stays vetoed for good"
    );

    // The retry reaches a responder still holding the first handshake.
    nodes[init].node.check_session_rekey().await;
    assert!(
        rekey_initiated(&nodes[init], &resp_addr),
        "the trigger must start a fresh rekey once the old one is retired"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[resp..=resp]).await;
    let stats = &nodes[resp].node.stats().session;
    assert_eq!(
        stats.rekey_held, 1,
        "the retry must have met the responder's stale handshake"
    );
    assert_eq!(
        (stats.rekey_tiebreak, stats.rekey_yielded),
        (0, 0),
        "a handshake the peer armed is not a dual initiation at either address"
    );
    pump_all(&mut nodes).await;

    assert!(
        !holds_pending(&nodes[init], &resp_addr) && !holds_pending(&nodes[resp], &init_addr),
        "a retry the responder dropped completes nothing"
    );
    tokio::time::sleep(Duration::from_millis(1200)).await;
    nodes[resp].node.check_session_rekey().await;
    assert_eq!(
        nodes[resp].node.stats().session.rekey_expired,
        1,
        "the responder's stale handshake must expire on its own rule"
    );
    nodes[init].node.check_session_rekey().await;
    assert!(
        !nodes[init]
            .node
            .get_session(&resp_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "the retry the responder dropped must itself be retired"
    );
    nodes[init].node.check_session_rekey().await;
    assert!(
        rekey_initiated(&nodes[init], &resp_addr),
        "the trigger must start a second retry"
    );
    pump_all(&mut nodes).await;

    assert!(
        holds_pending(&nodes[init], &resp_addr) && holds_pending(&nodes[resp], &init_addr),
        "the retried rekey must complete on both nodes"
    );
    // The first handshake and the retry the responder dropped.
    assert_eq!(
        nodes[init].node.stats().session.rekey_unanswered,
        2,
        "every retired handshake must be counted once"
    );
    assert_eq!(nodes[resp].node.stats().session.rekey_unanswered, 0);

    cleanup_nodes(&mut nodes).await;
}

/// A retry dropped on the tie-break by a smaller responder still holding its
/// stale handshake completes once both handshakes have expired.
#[tokio::test]
async fn test_a_retry_dropped_by_a_smaller_responders_stale_handshake_completes_one_timeout_later()
{
    lostack_retry(true).await;
}

/// A retry dropped by a larger responder still holding its stale handshake
/// completes once both handshakes have expired, as at a smaller one: the
/// larger end no longer yields a handshake its peer armed.
#[tokio::test]
async fn test_a_retry_dropped_by_a_larger_responders_stale_handshake_completes_one_timeout_later() {
    lostack_retry(false).await;
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
        holds_pending(&nodes[0], &node1_addr) && !rekey_initiated(&nodes[0], &node1_addr),
        "precondition: node 0 read the SessionAck and holds the new session"
    );
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        drop_queued(&mut nodes[1]),
        1,
        "precondition: the msg3 is the one packet lost"
    );
    assert!(
        !holds_pending(&nodes[1], &node0_addr),
        "precondition: node 1 has not completed the rekey"
    );

    let base = Node::session_now();
    nodes[0]
        .node
        .resend_pending_session_msg3(session_after(base, 64_000))
        .await;
    pump_all(&mut nodes).await;

    assert!(
        holds_pending(&nodes[1], &node0_addr),
        "the resent msg3 must complete the rekey at node 1"
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
    /// address, delivered at the larger address, where the dual-initiation
    /// tie-break would yield to it.
    Setup,
}

/// What a rekey left behind once a forgery may have reached its window.
#[derive(Debug, PartialEq, Eq)]
struct WindowOutcome {
    /// The responder completed the handshake on the initiator's genuine msg3.
    responder_completed: bool,
    /// The initiator cut over on its liveness timer.
    initiator_cut_over: bool,
    /// A frame the initiator sent after its cutover and after its whole msg3
    /// resend budget decoded at the responder.
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

/// Cut `nodes[init]` over to the rekey it initiated by running its tick with
/// the liveness timer already elapsed, and report whether it did.
async fn cut_over_initiator(nodes: &mut [TestNode], init: usize, resp_addr: &NodeAddr) -> bool {
    nodes[init]
        .node
        .sessions
        .get_mut(resp_addr)
        .unwrap()
        .set_rekey_completed(session_before(Node::session_now(), 10_000));
    nodes[init].node.check_session_rekey().await;
    let entry = nodes[init].node.get_session(resp_addr).unwrap();
    entry.pending_new_session().is_none() && !entry.has_rekey_in_progress()
}

/// Drive a genuine FSP rekey to the point where the initiator has read the
/// SessionAck and derived the new session, deliver `forgery` to the
/// responder, then release the initiator's genuine msg3 and follow the cycle
/// through the initiator's cutover, its msg3 resend budget, and one data frame
/// each way. Then let the responder start the next rekey and check that it
/// carries frames both ways.
///
/// The responder is chosen at run time to hold the larger address, the end
/// at which the dual-initiation tie-break yields; a smaller responder wins it
/// and drops the forged setup regardless. The forged msg3 reaches the same
/// arm at either end.
///
/// Returns the outcome and a note of the responder's counters for the
/// failure message: msg3s refused for arriving with no handshake to read
/// them, and dual-initiation yields.
async fn rekey_with_window_forgery(forgery: WindowForgery) -> (WindowOutcome, String) {
    use crate::transport::ReceivedPacket;

    let mut nodes = rekey_pair([true, true], None).await;
    let node0_smaller =
        crate::proto::fsp::initiation_winner(nodes[0].node.node_addr(), nodes[1].node.node_addr());
    let (init, resp) = if node0_smaller { (0, 1) } else { (1, 0) };
    let init_addr = *nodes[init].node.node_addr();
    let resp_addr = *nodes[resp].node.node_addr();
    assert!(
        !crate::proto::fsp::initiation_winner(&resp_addr, &init_addr),
        "the responder must hold the larger address"
    );

    // The setup reaches the responder only; it arms and answers.
    start_rekey(&mut nodes, init).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[resp..=resp]).await;
    assert_eq!(
        nodes[resp].node.stats().session.rekey_armed,
        1,
        "the responder must have armed"
    );

    // The SessionAck reaches the initiator only; it derives the new session
    // and sends msg3, which waits in the responder's queue.
    tokio::time::sleep(Duration::from_millis(20)).await;
    process_available_packets(&mut nodes[init..=init]).await;
    assert!(
        holds_pending(&nodes[init], &resp_addr)
            && !nodes[init]
                .node
                .get_session(&resp_addr)
                .unwrap()
                .has_rekey_in_progress(),
        "the initiator must have read the SessionAck and hold the new session"
    );
    assert!(
        nodes[resp]
            .node
            .get_session(&init_addr)
            .is_some_and(|e| e.has_rekey_in_progress() && !e.is_rekey_initiator()),
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
            let forged = SessionMsg3::new(vec![0u8; crate::noise::XK_HANDSHAKE_MSG3_SIZE]).encode();
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
                nodes[resp].node.stats().session.rekey_held,
                1,
                "the forged setup must have reached the armed handshake and \
                 been held off, or the test measures nothing"
            );
        }
    }

    // Release the genuine msg3.
    for packet in held {
        nodes[resp].node.handle_encrypted_frame(packet).await;
    }
    pump_all(&mut nodes).await;
    let responder_completed = holds_pending(&nodes[resp], &init_addr);

    // The initiator cuts over on its timer, then spends its msg3 resend
    // budget: a resend is what recovers a msg3 that was merely lost.
    let initiator_cut_over = cut_over_initiator(&mut nodes, init, &resp_addr).await;
    let max_resends = nodes[init]
        .node
        .config()
        .node
        .rate_limit
        .handshake_max_resends;
    let base = Node::session_now();
    for step in 1..=u64::from(max_resends) + 1 {
        nodes[init]
            .node
            .resend_pending_session_msg3(session_after(base, step * 64_000))
            .await;
        pump_all(&mut nodes).await;
    }

    let initiator_to_responder = session_frame_decodes(&mut nodes, init, resp).await;
    let responder_to_initiator = session_frame_decodes(&mut nodes, resp, init).await;

    // The responder's own next rekey, once past the dampening that the
    // initiator's setup started. Its data frame above crossed its trigger.
    nodes[resp]
        .node
        .sessions
        .get_mut(&init_addr)
        .unwrap()
        .record_peer_rekey(session_before(Node::session_now(), 60_000));
    nodes[resp].node.check_session_rekey().await;
    assert!(
        rekey_initiated(&nodes[resp], &init_addr),
        "the responder must start the next rekey"
    );
    pump_all(&mut nodes).await;
    let next_cycle_carries_both_ways = cut_over_initiator(&mut nodes, resp, &init_addr).await
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

/// A forged SessionAck arriving midway through an unanswered rekey must not
/// restart its deadline: the rekey is retired on the timeout measured from
/// the setup this node sent.
#[tokio::test]
async fn test_forged_session_acks_do_not_hold_an_unanswered_rekey_open_past_its_deadline() {
    let mut nodes = rekey_pair([true, false], Some(1)).await;
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        drop_queued(&mut nodes[1]) > 0,
        "node 0's SessionSetup must have been queued at node 1 to be lost"
    );

    tokio::time::sleep(Duration::from_millis(600)).await;
    let forged = forged_session_ack(&nodes[1]);
    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;
    assert_eq!(nodes[0].node.stats().session.ack_handshake_failed, 1);
    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "the unreadable ack must have put the handshake back"
    );

    let forged_at = std::time::Instant::now();
    tokio::time::sleep(Duration::from_millis(600)).await;
    nodes[0].node.check_session_rekey().await;
    println!(
        "forged ack to check: {} ms",
        forged_at.elapsed().as_millis()
    );
    assert!(
        !nodes[0]
            .node
            .get_session(&node1_addr)
            .unwrap()
            .has_rekey_in_progress(),
        "a forged SessionAck must not restart the deadline of the rekey this \
         node initiated"
    );
    assert_eq!(
        nodes[0].node.stats().session.rekey_unanswered,
        1,
        "the retired handshake must be counted once"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Putting a handshake back after an unreadable SessionAck leaves the stamp
/// its deadline runs from exactly where arming wrote it.
#[tokio::test]
async fn test_an_unreadable_session_ack_does_not_push_out_the_rekey_deadline() {
    let mut nodes = rekey_pair([true, false], None).await;
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    let armed_at = nodes[0].node.get_session(&node1_addr).unwrap().initiated();
    assert_ne!(armed_at, None, "arming must stamp the deadline");

    tokio::time::sleep(Duration::from_millis(5)).await;
    let forged = forged_session_ack(&nodes[1]);
    nodes[0]
        .node
        .handle_session_payload(&node1_addr, &node1_addr, &forged, 1280, false)
        .await;
    assert_eq!(nodes[0].node.stats().session.ack_handshake_failed, 1);
    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "the unreadable ack must have put the handshake back"
    );
    assert_eq!(
        nodes[0].node.get_session(&node1_addr).unwrap().initiated(),
        armed_at,
        "the restore must not restamp the deadline"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A fresh rekey this node initiated is not retired because the peer's own
/// last rekey is older than the handshake timeout.
#[tokio::test]
async fn test_a_fresh_initiated_rekey_is_not_retired_on_the_peers_older_rekey_stamp() {
    let mut nodes = rekey_pair([true, false], None).await;
    let node1_addr = *nodes[1].node.node_addr();

    start_rekey(&mut nodes, 0).await;
    // A peer rekey long past both the handshake timeout and the dampening.
    nodes[0]
        .node
        .sessions
        .get_mut(&node1_addr)
        .unwrap()
        .record_peer_rekey(session_before(Node::session_now(), 60_000));
    let armed_at = nodes[0].node.get_session(&node1_addr).unwrap().initiated();

    nodes[0].node.check_session_rekey().await;

    assert!(
        rekey_initiated(&nodes[0], &node1_addr),
        "a fresh rekey this node initiated must not be retired on the peer's clock"
    );
    assert_eq!(
        nodes[0].node.get_session(&node1_addr).unwrap().initiated(),
        armed_at,
        "the rekey must be the same one, not retired and re-armed"
    );
    let stats = &nodes[0].node.stats().session;
    assert_eq!(stats.rekey_expired, 0);
    assert_eq!(stats.rekey_unanswered, 0);

    cleanup_nodes(&mut nodes).await;
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
    let now = Node::session_now();
    let idle_ms = nodes[1].node.config().node.session.idle_timeout_secs * 1000;
    let stamp = session_before(now, idle_ms + 10_000);
    nodes[1]
        .node
        .sessions
        .get_mut(&node0_addr)
        .unwrap()
        .set_rekey_completed(stamp);
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
        .set_rekey_completed(session_before(now, 10_000));
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
        match node.get_session(dest).expect("session").state() {
            EndToEndState::Established(session) => session.current_send_counter(),
            _ => panic!("session not established"),
        }
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
    let mut handshake =
        HandshakeState::new_xk_initiator(forger.keypair(), victim.node.identity().pubkey_full());
    handshake.set_local_epoch([0xA5; 8]);
    let msg1 = handshake
        .write_xk_message_1()
        .expect("forged msg1 must build");

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
        !crate::proto::fsp::initiation_winner(nodes[victim].node.node_addr(), &owner_addr),
        "the victim must be the side that loses the tie-break"
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

/// Move `nodes[i]`'s half-open entry for `addr` `by_ms` into the past: every
/// stamp its handshake legs are aged by. Stands for that much time passing
/// with no setup arriving.
fn age_entry(nodes: &mut [TestNode], i: usize, addr: &NodeAddr, by_ms: u64) {
    nodes[i]
        .node
        .sessions
        .get_mut(addr)
        .expect("the entry to age must exist")
        .backdate_handshake(by_ms);
}

/// Past `HALF_OPEN_MIN_AGE`, with a margin.
const PAST_MIN_AGE_MS: u64 = crate::node::session::HALF_OPEN_MIN_AGE.as_millis() as u64 + 100;

#[tokio::test]
async fn outbound_traffic_behind_an_aged_half_open_entry_initiates_a_session() {
    // TUN: the victim's own packet to the owner, behind a forged entry that
    // has had the minimum age to complete and has not.
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let victim_addr = *nodes[1].node.node_addr();

    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    drain_to_quiescence(&mut nodes).await;
    age_entry(&mut nodes, 1, &owner_addr, PAST_MIN_AGE_MS);

    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.supervisor.ipv6tun.tun_tx = Some(tun_tx);

    let src_fips = crate::Ipv6Address::from_node_addr(&victim_addr);
    let dst_fips = crate::Ipv6Address::from_node_addr(&owner_addr);
    let ipv6_packet = build_ipv6_packet(&src_fips, &dst_fips, b"behind a forged half-open entry");
    nodes[1].node.handle_tun_outbound(ipv6_packet.clone()).await;
    drain_to_quiescence(&mut nodes).await;

    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "the victim's own traffic to the owner must start a session of its own \
         instead of waiting behind a half-open entry nobody will complete; \
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
    age_entry(&mut nodes, 1, &owner_addr, PAST_MIN_AGE_MS);

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
         its own behind an aged half-open entry"
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

    // Run the handshake timer across the whole handshake timeout and past
    // it, with no further setup arriving.
    let mut now = t0;
    while now <= session_after(t0, timeout_ms + 1_000) {
        now = session_after(now, 250);
        nodes[1].node.resend_pending_session_handshakes(now).await;
    }
    assert!(
        nodes[1].node.get_session(&owner_addr).is_none(),
        "the half-open entry must have been reaped, so the whole timeout was run"
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
// Responder candidates, this node's own initiation, and one ack per setup
// ============================================================================
//
// A setup is unauthenticated, so the half-open state it leaves holds one
// responder candidate per distinct msg1 and neither silences another setup
// nor blocks this node's own initiation. These tests drive the candidate
// rules and the healthy paths they must leave working.

/// The index of the node with the smaller address (which wins the
/// simultaneous-initiation tie-break) and of the one with the larger.
fn by_address(nodes: &[TestNode]) -> (usize, usize) {
    if nodes[0].node.node_addr() < nodes[1].node.node_addr() {
        (0, 1)
    } else {
        (1, 0)
    }
}

/// A SessionSetup from `initiator`'s own identity to `responder`, with the
/// initiator's handshake kept so the test can finish it from the ack.
fn held_setup(
    initiator: &TestNode,
    responder: &TestNode,
) -> (crate::noise::HandshakeState, Vec<u8>, Vec<u8>) {
    use crate::noise::HandshakeState;
    use crate::proto::fsp::SessionSetup;

    let mut handshake = HandshakeState::new_xk_initiator(
        initiator.node.identity().keypair(),
        responder.node.identity().pubkey_full(),
    );
    handshake.set_local_epoch(initiator.node.startup_epoch());
    let msg1 = handshake.write_xk_message_1().expect("msg1 must build");
    let wire = SessionSetup::new(
        initiator.node.tree_state().my_coords().clone(),
        responder.node.tree_state().my_coords().clone(),
    )
    .with_handshake(msg1.clone())
    .encode();
    (handshake, msg1, wire)
}

/// The msg3 `handshake` writes after reading the stored ack `ack`.
fn msg3_from_ack(handshake: &mut crate::noise::HandshakeState, ack: &[u8]) -> Vec<u8> {
    use crate::proto::fsp::wire::FSP_COMMON_PREFIX_SIZE;

    let ack = SessionAck::decode(&ack[FSP_COMMON_PREFIX_SIZE..]).expect("stored ack decodes");
    handshake
        .read_xk_message_2(&ack.handshake_payload)
        .expect("the ack answers this handshake");
    SessionMsg3::new(handshake.write_xk_message_3().expect("msg3 must build")).encode()
}

/// How many responder candidates `nodes[i]` holds for `addr`.
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

#[tokio::test]
async fn losing_the_tie_break_to_a_forged_setup_after_our_first_setup_was_lost_still_initiates_after_the_minimum_age()
 {
    let mut nodes = make_routable_pair().await;
    let (owner, victim) = by_address(&nodes);
    let owner_addr = *nodes[owner].node.node_addr();
    let owner_pubkey = nodes[owner].node.identity().pubkey_full();

    nodes[victim]
        .node
        .initiate_session(owner_addr, owner_pubkey)
        .await
        .expect("the victim's initiation must start");
    // The victim's first setup is lost on the way.
    assert!(
        lose_queued(&mut nodes, owner) > 0,
        "precondition: the victim's setup was in flight"
    );

    // A forged setup naming the owner: the victim loses the tie-break and
    // answers it, pausing its own setup resends.
    deliver_forged_setup_naming(&mut nodes, owner, victim).await;
    let entry = nodes[victim].node.get_session(&owner_addr).unwrap();
    assert!(
        entry.has_initiator_leg() && entry.initiator_paused(),
        "precondition: the victim kept its own leg, paused, beside the forged candidate"
    );
    drain_to_quiescence(&mut nodes).await;

    // The minimum age passes with nothing completed.
    age_entry(&mut nodes, victim, &owner_addr, PAST_MIN_AGE_MS);
    nodes[victim]
        .node
        .resend_pending_session_handshakes(Node::session_now())
        .await;
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[victim]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "a paused leg must resume its setup once the forged candidate has had \
         the minimum age, instead of waiting for the handshake timeout"
    );
    assert!(
        nodes[owner]
            .node
            .get_session(nodes[victim].node.node_addr())
            .is_some_and(|e| e.is_established()),
        "the owner must reach Established with the victim"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn an_owner_initiating_with_the_smaller_address_still_reaches_a_node_whose_slots_are_held_young()
 {
    use crate::node::session::MAX_HALF_OPEN_RESPONDERS;

    let mut nodes = make_routable_pair().await;
    let (owner, victim) = by_address(&nodes);
    let owner_addr = *nodes[owner].node.node_addr();
    let victim_addr = *nodes[victim].node.node_addr();
    let victim_pubkey = nodes[victim].node.identity().pubkey_full();

    // The forger fills the victim's candidate slots for the owner's address.
    for _ in 0..MAX_HALF_OPEN_RESPONDERS {
        deliver_forged_setup_naming(&mut nodes, owner, victim).await;
    }
    lose_queued(&mut nodes, owner);

    // The owner, with the smaller address, initiates; its setup reaches the
    // victim while every slot is young, and is refused.
    nodes[owner]
        .node
        .initiate_session(victim_addr, victim_pubkey)
        .await
        .expect("the owner's initiation must start");
    drain_to_quiescence(&mut nodes).await;
    assert!(
        !nodes[owner]
            .node
            .get_session(&victim_addr)
            .is_some_and(|e| e.is_established()),
        "precondition: the owner's setup was refused while the slots were young"
    );

    // The minimum age passes at both ends; the forger keeps the victim's
    // slots young by forging again, which never moves the entry's opening.
    age_entry(&mut nodes, victim, &owner_addr, PAST_MIN_AGE_MS);
    age_entry(&mut nodes, owner, &victim_addr, PAST_MIN_AGE_MS);
    for _ in 0..MAX_HALF_OPEN_RESPONDERS {
        deliver_forged_setup_naming(&mut nodes, owner, victim).await;
    }
    lose_queued(&mut nodes, owner);

    // The victim has traffic for the owner and initiates itself.
    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[owner].node.supervisor.ipv6tun.tun_tx = Some(tun_tx);
    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&victim_addr),
        &crate::Ipv6Address::from_node_addr(&owner_addr),
        b"slots held young",
    );
    nodes[victim].node.handle_tun_outbound(packet.clone()).await;
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[owner]
            .node
            .get_session(&victim_addr)
            .is_some_and(|e| e.is_established())
            && nodes[victim]
                .node
                .get_session(&owner_addr)
                .is_some_and(|e| e.is_established()),
        "an owner whose own setup has gone unanswered for the minimum age must \
         answer the victim's setup despite winning the tie-break, so the pair \
         completes"
    );
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered, vec![packet], "the victim's packet must arrive");
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_forger_completing_its_own_candidate_does_not_drop_the_owners() {
    use crate::node::session::{CandidateAdmission, ResponderCandidate, SessionEntry};

    let mut node = make_node();
    let owner = Identity::generate();
    let forger = Identity::generate();
    let owner_addr = *owner.node_addr();

    let (forger_leg, forger_msg3) = drive_xk_to_msg3(&forger, node.identity());
    let (owner_leg, owner_msg3) = drive_xk_to_msg3(&owner, node.identity());
    let mut entry = SessionEntry::new(
        owner_addr,
        node.identity().pubkey_full(),
        EndToEndState::AwaitingMsg3(forger_leg),
        Node::session_now(),
        false,
    );
    entry.add_candidate(
        ResponderCandidate::new(
            owner_leg,
            vec![0x01],
            Vec::new(),
            stub_link_peer(),
            Node::session_now(),
        ),
        CandidateAdmission::Room,
    );
    node.sessions.insert(owner_addr, entry);

    // The forger completes its own candidate, with its own static key.
    node.handle_session_payload(
        &owner_addr,
        &stub_link_peer(),
        &forger_msg3_wire(forger_msg3),
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

/// Frame a raw XK msg3 as a SessionMsg3 payload.
fn forger_msg3_wire(msg3: Vec<u8>) -> Vec<u8> {
    SessionMsg3::new(msg3).encode()
}

#[tokio::test]
async fn forged_setups_inside_the_minimum_age_are_refused_and_the_owner_still_completes() {
    use crate::node::session::MAX_HALF_OPEN_RESPONDERS;

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

    // As many forged setups as there are slots, all inside the minimum age.
    for _ in 0..MAX_HALF_OPEN_RESPONDERS {
        deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    }
    assert_eq!(
        candidates_at(&nodes, 1, &owner_addr),
        MAX_HALF_OPEN_RESPONDERS,
        "the slots fill and the forgery past them is refused"
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
async fn a_forger_refreshing_every_1250_ms_does_not_stop_this_node_initiating() {
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let victim_addr = *nodes[1].node.node_addr();

    // One forged setup every 1.25 s for 6.25 s: with four slots and a 5 s
    // minimum age, every slot stays younger than the minimum age.
    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    for _ in 0..5 {
        age_entry(&mut nodes, 1, &owner_addr, 1_250);
        deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    }
    lose_queued(&mut nodes, 0);

    let (tun_tx, tun_rx) = std::sync::mpsc::channel();
    nodes[0].node.supervisor.ipv6tun.tun_tx = Some(tun_tx);
    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&victim_addr),
        &crate::Ipv6Address::from_node_addr(&owner_addr),
        b"forger refreshing",
    );
    nodes[1].node.handle_tun_outbound(packet.clone()).await;
    drain_to_quiescence(&mut nodes).await;

    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "the hold is measured from when the entry opened, so a forger keeping \
         every candidate young must not stop this node initiating"
    );
    let delivered: Vec<Vec<u8>> = std::iter::from_fn(|| tun_rx.try_recv().ok()).collect();
    assert_eq!(delivered, vec![packet], "the victim's packet must arrive");
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

    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    deliver_forged_setup_naming(&mut nodes, 0, 1).await;
    assert_eq!(
        candidates_at(&nodes, 1, &owner_addr),
        2,
        "precondition: two candidates fill the half-open share"
    );
    let refused_before = nodes[1].node.stats().session.half_open_full;

    let forged = forge_setup_naming(&nodes[0], &nodes[1]);
    nodes[1]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &forged, 1280, false)
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
            .is_some_and(|e| e.has_initiator_leg() && e.has_candidates()),
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

#[tokio::test]
async fn a_msg3_reaches_a_candidate_beside_our_initiator_leg() {
    use crate::node::session::{CandidateAdmission, ResponderCandidate, SessionEntry};
    use crate::noise::HandshakeState;

    let mut node = make_node();
    let peer = Identity::generate();
    let peer_addr = *peer.node_addr();

    let (responder, msg3) = drive_xk_to_msg3(&peer, node.identity());
    let ours = HandshakeState::new_xk_initiator(node.identity().keypair(), peer.pubkey_full());
    let mut entry = SessionEntry::new(
        peer_addr,
        peer.pubkey_full(),
        EndToEndState::Initiating(ours),
        Node::session_now(),
        true,
    );
    entry.add_candidate(
        ResponderCandidate::new(
            responder,
            vec![0x01],
            Vec::new(),
            stub_link_peer(),
            Node::session_now(),
        ),
        CandidateAdmission::Room,
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
        node.get_session(&peer_addr)
            .is_some_and(|e| e.is_established()),
        "a msg3 for a responder candidate must complete it although our own \
         initiator leg shares the entry"
    );
}

#[tokio::test]
async fn an_identical_resent_setup_draws_a_byte_identical_ack() {
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let (mut handshake, msg1, setup) = held_setup(&nodes[0], &nodes[1]);

    nodes[1]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &setup, 1280, false)
        .await;
    let first = nodes[1]
        .node
        .get_session(&owner_addr)
        .and_then(|e| e.candidate_ack(&msg1))
        .expect("the setup must be answered and its ack stored")
        .to_vec();
    let originated = nodes[1].node.metrics().forwarding.originated_packets.get();

    nodes[1]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &setup, 1280, false)
        .await;
    assert_eq!(
        nodes[1].node.metrics().forwarding.originated_packets.get() - originated,
        1,
        "the resent setup must draw one ack"
    );
    assert_eq!(
        candidates_at(&nodes, 1, &owner_addr),
        1,
        "an identical setup must not add a candidate"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .and_then(|e| e.candidate_ack(&msg1))
            .map(<[u8]>::to_vec),
        Some(first.clone()),
        "the ack resent is the one first sent"
    );

    let msg3 = msg3_from_ack(&mut handshake, &first);
    nodes[1]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &msg3, 1280, false)
        .await;
    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "the owner's msg3 must then establish"
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

#[tokio::test]
async fn simultaneous_initiation_converges_with_no_rekey_armed() {
    let mut nodes = make_routable_pair().await;
    let (winner, loser) = cross_setups(&mut nodes).await;
    let winner_addr = *nodes[winner].node.node_addr();
    assert!(
        nodes[loser]
            .node
            .get_session(&winner_addr)
            .is_some_and(|e| e.initiator_paused()),
        "precondition: the loser answered the winner's setup and paused its own"
    );

    // The winner reads the loser's ack and establishes; then the loser's
    // resend timer fires before the winner's msg3 reaches it.
    process_available_packets(&mut nodes).await;
    nodes[loser]
        .node
        .resend_pending_session_handshakes(session_after(Node::session_now(), 2_000))
        .await;
    drain_to_quiescence(&mut nodes).await;

    for i in [winner, loser] {
        let other = *nodes[1 - i].node.node_addr();
        let entry = nodes[i].node.get_session(&other).expect("entry present");
        assert!(entry.is_established(), "node {i} must be established");
        assert!(
            !entry.has_rekey_in_progress() && entry.pending_new_session().is_none(),
            "node {i} must hold no rekey: a resent setup from the loser reaching \
             the established winner arms a spurious one"
        );
    }
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn honest_simultaneous_initiation_never_resumes_the_paused_leg() {
    let mut nodes = make_routable_pair().await;
    let (winner, loser) = cross_setups(&mut nodes).await;
    let winner_addr = *nodes[winner].node.node_addr();
    drain_to_quiescence(&mut nodes).await;

    let entry = nodes[loser]
        .node
        .get_session(&winner_addr)
        .expect("entry present");
    assert!(
        entry.is_established() && !entry.has_initiator_leg(),
        "an honest simultaneous initiation completes inside the minimum age, \
         leaving no paused leg behind"
    );

    // Well past the minimum age, nothing resumes.
    nodes[loser]
        .node
        .resend_pending_session_handshakes(session_after(Node::session_now(), PAST_MIN_AGE_MS))
        .await;
    drain_to_quiescence(&mut nodes).await;
    assert_eq!(
        nodes[winner].node.stats().session.rekey_armed,
        0,
        "no setup of the loser's may reach the winner after it established"
    );
    cleanup_nodes(&mut nodes).await;
}

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

    // Five seconds on, the responder has traffic for the initiator and
    // initiates itself beside its candidate.
    age_entry(&mut nodes, responder, &initiator_addr, PAST_MIN_AGE_MS);
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
            .is_some_and(|e| e.has_initiator_leg() && e.has_candidates()),
        "precondition: the responder initiated beside its candidate"
    );

    // The initiator's msg3 resend arrives late.
    nodes[initiator]
        .node
        .resend_pending_session_handshakes(session_after(Node::session_now(), 1_500))
        .await;
    drain_to_quiescence(&mut nodes).await;

    for (i, other) in [(initiator, responder_addr), (responder, initiator_addr)] {
        let entry = nodes[i].node.get_session(&other).expect("entry present");
        assert!(entry.is_established(), "node {i} must be established");
        assert!(
            entry.pending_new_session().is_none(),
            "node {i} must hold no second epoch waiting for cut-over"
        );
        assert!(
            !entry.has_rekey_in_progress() && nodes[i].node.stats().session.rekey_armed == 0,
            "node {i} must hold no rekey handshake: the responder's setup \
             reaching the established initiator arms one its peer never \
             completes, which then refuses that peer's genuine rekeys; \
             rekey in progress {}, rekeys armed {}",
            entry.has_rekey_in_progress(),
            nodes[i].node.stats().session.rekey_armed
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

#[tokio::test]
async fn a_winner_whose_setup_went_unanswered_converges_with_the_peers_own_initiation() {
    let mut nodes = make_routable_pair().await;
    let (winner, loser) = by_address(&nodes);
    let winner_addr = *nodes[winner].node.node_addr();
    let loser_addr = *nodes[loser].node.node_addr();
    let winner_pubkey = nodes[winner].node.identity().pubkey_full();
    let loser_pubkey = nodes[loser].node.identity().pubkey_full();

    // The tie-break winner initiates and its first setup is lost; it goes
    // unanswered for the minimum age. No forger is involved.
    nodes[winner]
        .node
        .initiate_session(loser_addr, loser_pubkey)
        .await
        .expect("the winner's initiation must start");
    assert!(
        lose_queued(&mut nodes, loser) > 0,
        "precondition: the winner's setup was in flight"
    );
    age_entry(&mut nodes, winner, &loser_addr, PAST_MIN_AGE_MS);

    // The loser now has traffic and initiates, and the winner's resend
    // crosses the loser's setup.
    nodes[loser]
        .node
        .initiate_session(winner_addr, winner_pubkey)
        .await
        .expect("the loser's initiation must start");
    nodes[winner]
        .node
        .resend_pending_session_handshakes(session_after(Node::session_now(), 1_500))
        .await;
    drain_to_quiescence(&mut nodes).await;

    let (to_winner_tx, to_winner_rx) = std::sync::mpsc::channel();
    let (to_loser_tx, to_loser_rx) = std::sync::mpsc::channel();
    nodes[winner].node.supervisor.ipv6tun.tun_tx = Some(to_winner_tx);
    nodes[loser].node.supervisor.ipv6tun.tun_tx = Some(to_loser_tx);
    let winner_fips = crate::Ipv6Address::from_node_addr(&winner_addr);
    let loser_fips = crate::Ipv6Address::from_node_addr(&loser_addr);
    let to_loser = build_ipv6_packet(&winner_fips, &loser_fips, b"winner to loser");
    let to_winner = build_ipv6_packet(&loser_fips, &winner_fips, b"loser to winner");
    nodes[winner]
        .node
        .handle_tun_outbound(to_loser.clone())
        .await;
    nodes[loser]
        .node
        .handle_tun_outbound(to_winner.clone())
        .await;
    drain_to_quiescence(&mut nodes).await;

    let at_loser: Vec<Vec<u8>> = std::iter::from_fn(|| to_loser_rx.try_recv().ok()).collect();
    let at_winner: Vec<Vec<u8>> = std::iter::from_fn(|| to_winner_rx.try_recv().ok()).collect();
    let initiators: Vec<bool> = [(winner, loser_addr), (loser, winner_addr)]
        .iter()
        .map(|(i, other)| {
            nodes[*i]
                .node
                .get_session(other)
                .is_some_and(|e| e.is_established() && e.is_initiator())
        })
        .collect();
    assert_eq!(
        (at_loser, at_winner),
        (vec![to_loser], vec![to_winner]),
        "the pair must share one session after the winner answers the \
         peer's setup; established as initiator (winner, loser): {initiators:?}"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_setup_after_every_candidate_expired_does_not_inherit_their_age() {
    let mut nodes = make_routable_pair().await;
    let (small, large) = by_address(&nodes);
    let small_addr = *nodes[small].node.node_addr();
    let small_pubkey = nodes[small].node.identity().pubkey_full();

    // A forged candidate naming the smaller node, 26 s old, then the larger
    // node's own initiation beside it (its setups are lost).
    deliver_forged_setup_naming(&mut nodes, small, large).await;
    age_entry(&mut nodes, large, &small_addr, 26_000);
    nodes[large]
        .node
        .initiate_session(small_addr, small_pubkey)
        .await
        .expect("the initiation must start");
    lose_queued(&mut nodes, small);

    // The forged candidate passes the handshake timeout; the leg lives on.
    nodes[large]
        .node
        .resend_pending_session_handshakes(session_after(Node::session_now(), 5_000))
        .await;
    lose_queued(&mut nodes, small);
    let entry = nodes[large].node.get_session(&small_addr).unwrap();
    assert!(
        entry.has_initiator_leg() && !entry.has_candidates(),
        "precondition: only the initiator leg is left"
    );

    // An honest setup from the smaller node: the larger loses the tie-break
    // and pauses its leg beside the new candidate.
    let (_, _, setup) = held_setup(&nodes[small], &nodes[large]);
    nodes[large]
        .node
        .handle_session_payload(&small_addr, &small_addr, &setup, 1280, false)
        .await;
    assert!(
        nodes[large]
            .node
            .get_session(&small_addr)
            .is_some_and(|e| e.has_candidates() && e.initiator_paused()),
        "precondition: the leg is paused beside the honest candidate"
    );

    nodes[large]
        .node
        .resend_pending_session_handshakes(Node::session_now())
        .await;
    assert!(
        nodes[large]
            .node
            .get_session(&small_addr)
            .is_some_and(|e| e.initiator_paused()),
        "the paused leg must wait the minimum age from the candidate that \
         paused it, not from candidates that have already expired"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn outbound_traffic_behind_an_aged_half_open_entry_with_no_route_starts_a_lookup() {
    let (mut nodes, _a_rx, _c_rx) = line_of_three_without_cached_coords().await;
    let a = *nodes[0].node.node_addr();
    let c = *nodes[2].node.node_addr();
    install_halfopen(&mut nodes[0].node, c);
    age_entry(&mut nodes, 0, &c, PAST_MIN_AGE_MS);

    let initiated = nodes[0].node.metrics().lookup.req_initiated.get();
    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&a),
        &crate::Ipv6Address::from_node_addr(&c),
        b"behind an aged half-open entry",
    );
    nodes[0].node.handle_tun_outbound(packet).await;

    assert!(
        !nodes[0]
            .node
            .get_session(&c)
            .is_some_and(|e| e.has_initiator_leg()),
        "precondition: with no coordinates for the destination the initiation \
         fails"
    );
    assert_eq!(
        nodes[0].node.metrics().lookup.req_initiated.get(),
        initiated + 1,
        "a failed initiation behind an aged half-open entry must ask \
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
        .resend_pending_session_handshakes(session_after(Node::session_now(), 1_500))
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

/// A SessionSetup naming `claimed`, written by a stranger to `victim`, with
/// the stranger's handshake kept so the test can complete it from the
/// victim's stored ack: a forger reading acks on the path to `claimed`.
fn forged_held_setup(
    claimed: &TestNode,
    victim: &TestNode,
) -> (crate::noise::HandshakeState, Vec<u8>, Vec<u8>) {
    use crate::noise::HandshakeState;
    use crate::proto::fsp::SessionSetup;

    let forger = Identity::generate();
    let mut handshake =
        HandshakeState::new_xk_initiator(forger.keypair(), victim.node.identity().pubkey_full());
    handshake.set_local_epoch([0xA5; 8]);
    let msg1 = handshake
        .write_xk_message_1()
        .expect("forged msg1 must build");
    let wire = SessionSetup::new(
        claimed.node.tree_state().my_coords().clone(),
        victim.node.tree_state().my_coords().clone(),
    )
    .with_handshake(msg1.clone())
    .encode();
    (handshake, msg1, wire)
}

#[tokio::test]
async fn a_forger_completing_its_candidate_beside_a_paused_leg_does_not_strand_it() {
    let mut nodes = make_routable_pair().await;
    let (owner, victim) = by_address(&nodes);
    let owner_addr = *nodes[owner].node.node_addr();
    let owner_pubkey = nodes[owner].node.identity().pubkey_full();

    // The victim initiates and its first setup is lost; a forged setup
    // naming the owner wins the tie-break, so the victim pauses its leg
    // beside the forged candidate.
    nodes[victim]
        .node
        .initiate_session(owner_addr, owner_pubkey)
        .await
        .expect("the victim's initiation must start");
    assert!(
        lose_queued(&mut nodes, owner) > 0,
        "precondition: setup in flight"
    );
    let (mut forger_hs, forger_msg1, forged) = forged_held_setup(&nodes[owner], &nodes[victim]);
    nodes[victim]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &forged, 1280, false)
        .await;
    let ack = {
        let entry = nodes[victim].node.get_session(&owner_addr).unwrap();
        assert!(
            entry.has_initiator_leg() && entry.initiator_paused(),
            "precondition: the victim paused its own leg beside the forged candidate"
        );
        entry
            .candidate_ack(&forger_msg1)
            .expect("the forged candidate's ack")
            .to_vec()
    };
    lose_queued(&mut nodes, owner);

    // The forger completes its own candidate with its own static key, which
    // drops that candidate and leaves the paused leg alone in the entry.
    let msg3 = msg3_from_ack(&mut forger_hs, &ack);
    nodes[victim]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &msg3, 1280, false)
        .await;
    assert_eq!(
        nodes[victim].node.stats().session.addr_mismatch,
        1,
        "precondition: the forger's msg3 was refused as an address mismatch"
    );

    // With no candidate left there is nothing to answer instead, so the
    // next resend sweep resumes the leg without waiting for the minimum age.
    nodes[victim]
        .node
        .resend_pending_session_handshakes(Node::session_now())
        .await;
    drain_to_quiescence(&mut nodes).await;

    let entry = nodes[victim].node.get_session(&owner_addr);
    assert!(
        entry.is_some_and(|e| e.is_established()),
        "a paused leg left with no candidate must resume rather than wait for \
         the handshake timeout; victim entry: established {:?}, initiator leg \
         {:?}, paused {:?}, candidates {:?}",
        entry.map(|e| e.is_established()),
        entry.map(|e| e.has_initiator_leg()),
        entry.map(|e| e.initiator_paused()),
        entry.map(|e| e.candidate_count()),
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_forger_dropping_its_candidate_with_a_msg3_does_not_restart_the_hold() {
    let mut nodes = make_routable_pair().await;
    let owner = 0;
    let victim = 1;
    let owner_addr = *nodes[owner].node.node_addr();
    let victim_addr = *nodes[victim].node.node_addr();
    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&victim_addr),
        &crate::Ipv6Address::from_node_addr(&owner_addr),
        b"held behind a forger",
    );

    // Each cycle stands for 3 s: a forged setup naming the owner, the
    // victim's own packet for the owner 3 s later, then the forger's msg3
    // completing its own candidate, which the victim refuses as an address
    // mismatch. The next forged setup follows at once.
    let mut elapsed_ms = 0u64;
    let mut initiated_at_ms = None;
    for _ in 0..4 {
        let (mut forger_hs, forger_msg1, forged) = forged_held_setup(&nodes[owner], &nodes[victim]);
        nodes[victim]
            .node
            .handle_session_payload(&owner_addr, &owner_addr, &forged, 1280, false)
            .await;
        let ack = nodes[victim]
            .node
            .get_session(&owner_addr)
            .and_then(|e| e.candidate_ack(&forger_msg1).map(<[u8]>::to_vec))
            .expect("the forged setup must have opened a candidate");
        lose_queued(&mut nodes, owner);

        age_entry(&mut nodes, victim, &owner_addr, 3_000);
        elapsed_ms += 3_000;
        nodes[victim].node.handle_tun_outbound(packet.clone()).await;
        if nodes[victim]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.has_initiator_leg() || e.is_established())
        {
            initiated_at_ms = Some(elapsed_ms);
            break;
        }
        lose_queued(&mut nodes, owner);

        let msg3 = msg3_from_ack(&mut forger_hs, &ack);
        nodes[victim]
            .node
            .handle_session_payload(&owner_addr, &owner_addr, &msg3, 1280, false)
            .await;
        // A reaper tick between the msg3 and the next setup.
        nodes[victim]
            .node
            .resend_pending_session_handshakes(Node::session_now())
            .await;
    }

    assert!(
        initiated_at_ms
            .is_some_and(|t| t <= 2 * crate::node::session::HALF_OPEN_MIN_AGE.as_millis() as u64),
        "the victim must initiate itself once its traffic has been held behind \
         forged setups for the minimum age, whatever the forger sends; after \
         {elapsed_ms} ms it initiated at {initiated_at_ms:?} (address \
         mismatches {})",
        nodes[victim].node.stats().session.addr_mismatch
    );
    cleanup_nodes(&mut nodes).await;
}

#[test]
fn a_full_entry_evicts_the_newcomers_own_links_aged_candidate_before_an_older_one() {
    use crate::node::session::{
        CandidateAdmission, HALF_OPEN_MIN_AGE, ResponderCandidate, admit_candidate,
    };
    use crate::noise::HandshakeState;

    let now = session_at(100_000);
    let own_link = *Identity::generate().node_addr();
    let other_link = *Identity::generate().node_addr();
    let candidate = |link: NodeAddr, age_ms: u64| {
        ResponderCandidate::new(
            HandshakeState::new_xk_responder(Identity::generate().keypair()),
            vec![0x01],
            Vec::new(),
            link,
            session_before(now, age_ms),
        )
    };
    let aged = HALF_OPEN_MIN_AGE.as_millis() as u64;
    // The oldest aged candidate arrived over another link; an older-than-
    // minimum one arrived over the newcomer's own link.
    let candidates = vec![
        candidate(other_link, aged + 20_000),
        candidate(own_link, aged + 10_000),
        candidate(other_link, aged + 5_000),
        candidate(other_link, aged + 1_000),
    ];

    assert_eq!(
        admit_candidate(&candidates, &own_link, now),
        CandidateAdmission::Evict(1),
        "a newcomer must evict the aged candidate from its own link peer \
         before an older one from another link"
    );
    let stranger_link = *Identity::generate().node_addr();
    assert_eq!(
        admit_candidate(&candidates, &stranger_link, now),
        CandidateAdmission::Evict(0),
        "with no aged candidate on its own link, a newcomer evicts the oldest \
         aged candidate"
    );
}

/// Open a hold at `nodes[victim]` with a forged setup naming
/// `nodes[claimed]`, then drop its candidate with the forger's own msg3, as a
/// forger reading the victim's ack would: the entry is left with no leg.
async fn hold_left_by_a_forgers_msg3(nodes: &mut [TestNode], claimed: usize, victim: usize) {
    let claimed_addr = *nodes[claimed].node.node_addr();
    let (mut forger_hs, forger_msg1, forged) = forged_held_setup(&nodes[claimed], &nodes[victim]);
    nodes[victim]
        .node
        .handle_session_payload(&claimed_addr, &claimed_addr, &forged, 1280, false)
        .await;
    let ack = nodes[victim]
        .node
        .get_session(&claimed_addr)
        .and_then(|e| e.candidate_ack(&forger_msg1).map(<[u8]>::to_vec))
        .expect("the forged setup must have opened a candidate");
    lose_queued(nodes, claimed);
    let msg3 = msg3_from_ack(&mut forger_hs, &ack);
    nodes[victim]
        .node
        .handle_session_payload(&claimed_addr, &claimed_addr, &msg3, 1280, false)
        .await;
    assert!(
        nodes[victim]
            .node
            .get_session(&claimed_addr)
            .is_some_and(|e| !e.has_candidates() && !e.has_initiator_leg()),
        "precondition: the forger's msg3 left the entry with no leg"
    );
}

#[tokio::test]
async fn outbound_traffic_behind_an_aged_hold_whose_candidate_a_forger_dropped_initiates() {
    let mut nodes = make_routable_pair().await;
    let owner_addr = *nodes[0].node.node_addr();
    let victim_addr = *nodes[1].node.node_addr();

    hold_left_by_a_forgers_msg3(&mut nodes, 0, 1).await;
    age_entry(&mut nodes, 1, &owner_addr, PAST_MIN_AGE_MS);

    let packet = build_ipv6_packet(
        &crate::Ipv6Address::from_node_addr(&victim_addr),
        &crate::Ipv6Address::from_node_addr(&owner_addr),
        b"behind a hold with no candidate",
    );
    nodes[1].node.handle_tun_outbound(packet).await;

    assert!(
        nodes[1]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.has_initiator_leg()),
        "a hold the minimum age old must make this node initiate even after \
         the forger has dropped its own candidate"
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_hold_whose_candidate_a_forger_dropped_still_counts_toward_the_half_open_share() {
    let configs = (0..4)
        .map(|_| {
            let mut config = Config::new();
            // A half-open share of two.
            config.node.limits.max_sessions = 4;
            config
        })
        .collect();
    let mut nodes = run_tree_test_with_configs(configs, &[(0, 1), (1, 2), (1, 3)]).await;
    populate_all_coord_caches(&mut nodes);
    let third_addr = *nodes[3].node.node_addr();

    // A hold kept with no candidate, then one candidate for another address.
    hold_left_by_a_forgers_msg3(&mut nodes, 0, 1).await;
    deliver_forged_setup_naming(&mut nodes, 2, 1).await;
    let refused_before = nodes[1].node.stats().session.half_open_full;

    let forged = forge_setup_naming(&nodes[3], &nodes[1]);
    nodes[1]
        .node
        .handle_session_payload(&third_addr, &third_addr, &forged, 1280, false)
        .await;

    assert_eq!(
        nodes[1].node.stats().session.half_open_full - refused_before,
        1,
        "a hold kept after its last candidate was dropped must count toward \
         the half-open share, or a forger completing its own candidates could \
         fill the table past it"
    );
    assert!(
        nodes[1].node.get_session(&third_addr).is_none(),
        "the refused setup must open no entry"
    );
    cleanup_nodes(&mut nodes).await;
}

/// A native flow behind an aged hold, to a destination this node holds no
/// key or coordinates for: the initiation finds no route and discovery is
/// asked, so the client's key must be cached for the answer to be accepted.
#[tokio::test]
async fn a_native_send_to_an_uncached_key_behind_an_aged_hold_establishes_after_discovery() {
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

    // A forged setup's entry, opened now and aged past the minimum age.
    {
        let node = &mut nodes[0].node;
        let handshake = crate::noise::HandshakeState::new_xk_responder(node.identity().keypair());
        let placeholder = node.identity().keypair().public_key();
        let entry = crate::node::session::SessionEntry::new(
            node2_addr,
            placeholder,
            EndToEndState::AwaitingMsg3(handshake),
            Node::session_now(),
            false,
        );
        node.sessions.insert(node2_addr, entry);
    }
    age_entry(&mut nodes, 0, &node2_addr, PAST_MIN_AGE_MS);

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
        .handle_native_outbound(flow, node2_xonly, b"behind an aged hold".to_vec())
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
            e.has_initiator_leg(),
            e.has_candidates(),
        )
    });
    assert!(
        identity_miss == 0
            && nodes[0]
                .node
                .get_session(&node2_addr)
                .is_some_and(|e| e.is_established()),
        "discovery behind an aged hold must lead to an established session; \
         lookups initiated {initiated}, answers dropped for want of the key {identity_miss}, \
         answers accepted {accepted}, key cached {}, entry (established, initiator leg, candidates) {state:?}",
        nodes[0].node.has_cached_identity(&node2_addr)
    );
    cleanup_nodes(&mut nodes).await;
}

/// No forger. The tie-break loser initiates and the winner answers it, but
/// that ack is delayed on the path. Past the minimum age the winner has
/// traffic and initiates beside the candidate it holds; its setup reaches
/// the loser first, which pauses its leg and answers. The delayed ack then
/// completes the paused leg, and the pair must still settle on one session.
#[tokio::test]
async fn a_paused_leg_completed_by_an_ack_sent_before_the_pause_converges() {
    let mut nodes = make_routable_pair().await;
    let (winner, loser) = by_address(&nodes);
    let winner_addr = *nodes[winner].node.node_addr();
    let loser_addr = *nodes[loser].node.node_addr();
    let winner_pubkey = nodes[winner].node.identity().pubkey_full();

    // The loser initiates; the winner answers as a responder.
    nodes[loser]
        .node
        .initiate_session(winner_addr, winner_pubkey)
        .await
        .expect("the loser's initiation must start");
    process_available_packets(&mut nodes).await;
    assert_eq!(
        candidates_at(&nodes, winner, &loser_addr),
        1,
        "precondition: winner holds the loser's candidate"
    );
    // The winner's ack is held on the path.
    let held: Vec<_> = std::iter::from_fn(|| nodes[loser].packet_rx.try_recv().ok()).collect();
    assert!(
        !held.is_empty(),
        "precondition: the winner's ack was in flight"
    );

    // Past the minimum age the winner has traffic for the loser and
    // initiates beside the candidate.
    age_entry(&mut nodes, winner, &loser_addr, PAST_MIN_AGE_MS);
    let winner_fips = crate::Ipv6Address::from_node_addr(&winner_addr);
    let loser_fips = crate::Ipv6Address::from_node_addr(&loser_addr);
    nodes[winner]
        .node
        .handle_tun_outbound(build_ipv6_packet(&winner_fips, &loser_fips, b"first"))
        .await;
    assert!(
        nodes[winner]
            .node
            .get_session(&loser_addr)
            .is_some_and(|e| e.has_initiator_leg() && e.has_candidates()),
        "precondition: the winner initiated beside the loser's candidate"
    );

    // The winner's setup reaches the loser first: it loses the tie-break,
    // pauses its leg and answers.
    process_available_packets(&mut nodes).await;
    assert!(
        nodes[loser]
            .node
            .get_session(&winner_addr)
            .is_some_and(|e| e.initiator_paused() && e.has_candidates()),
        "precondition: the loser paused its leg beside the winner's candidate"
    );

    // The delayed ack now reaches the loser.
    for packet in held {
        nodes[loser].node.handle_encrypted_frame(packet).await;
    }
    drain_to_quiescence(&mut nodes).await;

    let (to_winner_tx, to_winner_rx) = std::sync::mpsc::channel();
    let (to_loser_tx, to_loser_rx) = std::sync::mpsc::channel();
    nodes[winner].node.supervisor.ipv6tun.tun_tx = Some(to_winner_tx);
    nodes[loser].node.supervisor.ipv6tun.tun_tx = Some(to_loser_tx);
    let to_loser = build_ipv6_packet(&winner_fips, &loser_fips, b"winner to loser");
    let to_winner = build_ipv6_packet(&loser_fips, &winner_fips, b"loser to winner");
    nodes[winner]
        .node
        .handle_tun_outbound(to_loser.clone())
        .await;
    nodes[loser]
        .node
        .handle_tun_outbound(to_winner.clone())
        .await;
    drain_to_quiescence(&mut nodes).await;

    let at_loser: Vec<Vec<u8>> = std::iter::from_fn(|| to_loser_rx.try_recv().ok()).collect();
    let at_winner: Vec<Vec<u8>> = std::iter::from_fn(|| to_winner_rx.try_recv().ok()).collect();
    let state: Vec<(bool, bool)> = [(winner, loser_addr), (loser, winner_addr)]
        .iter()
        .map(|(i, other)| {
            nodes[*i]
                .node
                .get_session(other)
                .map_or((false, false), |e| (e.is_established(), e.is_initiator()))
        })
        .collect();
    assert!(
        at_loser.contains(&to_loser) && at_winner.contains(&to_winner),
        "the pair must share one session; (established, initiator) at (winner, loser): {state:?}; \
         delivered to loser {}, to winner {}; bad_state (winner, loser) ({}, {})",
        at_loser.len(),
        at_winner.len(),
        nodes[winner].node.stats().session.bad_state,
        nodes[loser].node.stats().session.bad_state,
    );
    cleanup_nodes(&mut nodes).await;
}

/// The tie-break loser's leg, paused beside a forged candidate, completed
/// by the owner's ack held from before the forgery: the loser is established
/// with the forged candidate kept beside the session. Returns the owner's
/// and the loser's index, the forger's handshake and the forged candidate's
/// ack.
async fn loser_established_beside_a_forged_candidate(
    nodes: &mut [TestNode],
) -> (usize, usize, crate::noise::HandshakeState, Vec<u8>) {
    let (owner, victim) = by_address(nodes);
    let owner_addr = *nodes[owner].node.node_addr();
    let owner_pubkey = nodes[owner].node.identity().pubkey_full();

    nodes[victim]
        .node
        .initiate_session(owner_addr, owner_pubkey)
        .await
        .expect("the victim's initiation must start");
    process_available_packets(nodes).await;
    let held: Vec<_> = std::iter::from_fn(|| nodes[victim].packet_rx.try_recv().ok()).collect();
    assert!(
        !held.is_empty(),
        "precondition: the owner's ack was in flight"
    );

    let (forger_hs, forger_msg1, forged) = forged_held_setup(&nodes[owner], &nodes[victim]);
    nodes[victim]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &forged, 1280, false)
        .await;
    let ack = nodes[victim]
        .node
        .get_session(&owner_addr)
        .and_then(|e| e.candidate_ack(&forger_msg1))
        .expect("the forged candidate's ack")
        .to_vec();
    lose_queued(nodes, owner);

    for packet in held {
        nodes[victim].node.handle_encrypted_frame(packet).await;
    }
    assert!(
        nodes[victim]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established() && e.candidate_count() == 1),
        "precondition: the victim established and kept the forged candidate"
    );
    (owner, victim, forger_hs, ack)
}

#[tokio::test]
async fn a_forgers_msg3_against_a_candidate_kept_beside_the_losers_session_leaves_the_session() {
    let mut nodes = make_routable_pair().await;
    let (owner, victim, mut forger_hs, ack) =
        loser_established_beside_a_forged_candidate(&mut nodes).await;
    let owner_addr = *nodes[owner].node.node_addr();
    let victim_addr = *nodes[victim].node.node_addr();

    // The forger completes its candidate with its own static key.
    let msg3 = msg3_from_ack(&mut forger_hs, &ack);
    nodes[victim]
        .node
        .handle_session_payload(&owner_addr, &owner_addr, &msg3, 1280, false)
        .await;
    assert_eq!(
        nodes[victim].node.stats().session.addr_mismatch,
        1,
        "precondition: the forger's msg3 was refused as an address mismatch"
    );
    assert!(
        nodes[victim]
            .node
            .get_session(&owner_addr)
            .is_some_and(|e| e.is_established()),
        "a forger's msg3 against a candidate kept beside the session must \
         leave the session in place"
    );
    drain_to_quiescence(&mut nodes).await;

    let (to_owner_tx, to_owner_rx) = std::sync::mpsc::channel();
    nodes[owner].node.supervisor.ipv6tun.tun_tx = Some(to_owner_tx);
    let owner_fips = crate::Ipv6Address::from_node_addr(&owner_addr);
    let victim_fips = crate::Ipv6Address::from_node_addr(&victim_addr);
    let packet = build_ipv6_packet(&victim_fips, &owner_fips, b"after the forger");
    nodes[victim].node.handle_tun_outbound(packet.clone()).await;
    drain_to_quiescence(&mut nodes).await;
    let at_owner: Vec<Vec<u8>> = std::iter::from_fn(|| to_owner_rx.try_recv().ok()).collect();
    assert!(
        at_owner.contains(&packet),
        "a forger's msg3 against a candidate kept beside the session must \
         leave the session; victim entry established {:?}",
        nodes[victim]
            .node
            .get_session(&owner_addr)
            .map(|e| e.is_established()),
    );
    cleanup_nodes(&mut nodes).await;
}

#[tokio::test]
async fn a_candidate_kept_beside_the_losers_session_expires_on_its_own_deadline() {
    let mut nodes = make_routable_pair().await;
    let (owner, victim, _, _) = loser_established_beside_a_forged_candidate(&mut nodes).await;
    let owner_addr = *nodes[owner].node.node_addr();
    let timeout_ms = nodes[victim]
        .node
        .config()
        .node
        .rate_limit
        .handshake_timeout_secs
        * 1000;

    age_entry(&mut nodes, victim, &owner_addr, timeout_ms + 1_000);
    nodes[victim]
        .node
        .resend_pending_session_handshakes(Node::session_now())
        .await;

    let entry = nodes[victim].node.get_session(&owner_addr);
    assert_eq!(
        entry.map(|e| (e.is_established(), e.candidate_count())),
        Some((true, 0)),
        "a candidate kept beside an established session must expire a \
         handshake timeout after its setup, leaving the session"
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
    entry.mark_established(Node::session_now());
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
    nodes[0].node.check_session_rekey().await;

    assert!(
        !rekey_initiated(&nodes[0], &node1_addr),
        "a session established just now must not rekey because the system clock jumped ahead"
    );

    // Control: the same age on the monotonic clock does trigger it.
    crate::time::advance(Duration::from_secs(past_trigger_secs));
    nodes[0].node.check_session_rekey().await;
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
