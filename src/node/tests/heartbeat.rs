//! Link-dead heartbeat rekey-awareness integration tests.
//!
//! `check_link_heartbeats()` reaps a peer after the link-dead timeout,
//! but suppresses teardown while an FMP rekey is genuinely in flight with
//! its msg1 retransmission budget unexhausted. These tests drive a real
//! two-node UDP peering, inject rekey state on the peer, and verify the
//! suppress / resume / regression behaviors. `link_dead_timeout_secs` is
//! set to 0 so the elapsed-time predicate is always satisfied and the only
//! variable is the rekey-active guard.

use super::spanning_tree::*;
use super::*;
use crate::Identity;
use crate::noise::HandshakeState;
use crate::utils::index::SessionIndex;

/// Arm a real (initiator) FMP rekey on the peer the given node holds for
/// `peer_addr`, so the msg1 resend budget can be exercised.
fn arm_rekey(node: &mut crate::node::Node, peer_addr: &NodeAddr) {
    let local = Identity::generate();
    let hs = HandshakeState::new_initiator(local.keypair());
    let peer = node.get_peer_mut(peer_addr).expect("peer present");
    peer.set_rekey_state(hs, SessionIndex::new(7), vec![0xAB; 64], 0);
}

/// Set `link_dead_timeout_secs` on an already-constructed node via the
/// sole-store copy-on-write context swap (immutable state is no longer a
/// directly-pokeable field; `config()` is a read-only accessor).
fn set_link_dead_timeout(node: &mut crate::node::Node, secs: u64) {
    node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.node.link_dead_timeout_secs = secs;
        ctx.config = std::sync::Arc::new(cfg);
    });
}

/// Set `node.heartbeat_interval_secs` on an already-constructed node, the same
/// way `set_link_dead_timeout` does. This is the knob the retry gate must not
/// floor.
fn set_heartbeat_interval(node: &mut crate::node::Node, secs: u64) {
    node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.node.heartbeat_interval_secs = secs;
        ctx.config = std::sync::Arc::new(cfg);
    });
}

/// A heartbeat whose send failed is not recorded as having landed, and the
/// failed attempt is not retried on the very next tick.
///
/// The failure is forced by taking the node's transport handles away, so the
/// encrypted send fails before any I/O with `TransportNotFound`. Marking the
/// send before it happens, which is what this replaced, would record the peer
/// as heartbeated and suppress the next attempt for a whole interval although
/// the peer heard nothing.
#[tokio::test]
async fn a_failed_heartbeat_send_is_not_recorded_as_landed() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());

    // Whatever landed during convergence is the baseline this asserts against.
    let landed_before = nodes[0]
        .node
        .get_peer(&addr_1)
        .unwrap()
        .last_heartbeat_sent();

    // Due on every tick, so the only variable is what the send does.
    set_heartbeat_interval(&mut nodes[0].node, 0);
    nodes[0].node.transports.clear();

    nodes[0].node.check_link_heartbeats().await;

    let peer = nodes[0].node.get_peer(&addr_1).expect("peer present");
    let failed_at = peer
        .last_heartbeat_attempt()
        .expect("the attempt is recorded even though the send failed");
    assert_eq!(
        peer.last_heartbeat_sent(),
        landed_before,
        "a heartbeat whose send failed was recorded as having landed"
    );

    // The retry gate spaces the next attempt out rather than letting a failing
    // peer be retried on every tick.
    nodes[0].node.check_link_heartbeats().await;

    let peer = nodes[0].node.get_peer(&addr_1).expect("peer present");
    assert_eq!(
        peer.last_heartbeat_attempt(),
        Some(failed_at),
        "a peer whose send failed was retried inside the retry interval"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A peer past the link-dead timeout is NOT reaped while an FMP rekey is in
/// progress with its msg1 budget unexhausted.
#[tokio::test]
async fn heartbeat_suppressed_during_rekey() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());

    // Force every link to read as dead on elapsed time alone.
    set_link_dead_timeout(&mut nodes[0].node, 0);

    // Arm a rekey with budget left (count 0 < max_resends default 5).
    arm_rekey(&mut nodes[0].node, &addr_1);
    assert!(nodes[0].node.get_peer(&addr_1).unwrap().rekey_in_progress());

    nodes[0].node.check_link_heartbeats().await;

    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "peer reaped despite an in-flight rekey with budget remaining"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Once the msg1 budget is exhausted the rekey-active guard no longer
/// holds, so a peer past the link-dead timeout IS reaped.
#[tokio::test]
async fn heartbeat_resumes_after_budget_exhausted() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());

    set_link_dead_timeout(&mut nodes[0].node, 0);
    let max_resends = nodes[0].node.config().node.rate_limit.handshake_max_resends;

    arm_rekey(&mut nodes[0].node, &addr_1);

    // Exhaust the budget: count reaches max_resends, guard goes false.
    let peer = nodes[0].node.get_peer_mut(&addr_1).unwrap();
    for i in 0..max_resends {
        peer.record_rekey_msg1_resend(1000 + i as u64 * 100);
    }
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .rekey_msg1_resend_count(),
        max_resends
    );

    nodes[0].node.check_link_heartbeats().await;

    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "peer not reaped after its rekey budget was exhausted"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Next-only: a peer past the link-dead timeout is NOT reaped while a
/// retained FMP rekey msg3 is still being retransmitted with its budget
/// unexhausted. This is the XX/next msg3-liveness arm of the suppression
/// predicate, distinct from the msg1 arm above.
#[tokio::test]
async fn heartbeat_suppressed_during_msg3_retransmit() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());

    set_link_dead_timeout(&mut nodes[0].node, 0);

    // Retain a msg3 payload with budget left (count 0 < max_resends), with
    // no msg1 rekey in flight: only the msg3 arm of the guard can hold.
    let peer = nodes[0].node.get_peer_mut(&addr_1).unwrap();
    peer.set_rekey_msg3_payload(vec![0xCD; 64], 1000);
    assert!(!peer.rekey_in_progress());
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .rekey_msg3_resend_count(),
        0
    );

    nodes[0].node.check_link_heartbeats().await;

    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "peer reaped despite a retained rekey msg3 with budget remaining"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Regression guard: with no rekey in flight, a peer past the link-dead
/// timeout is reaped exactly as before.
#[tokio::test]
async fn heartbeat_unaffected_without_rekey() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    assert!(nodes[0].node.get_peer(&addr_1).is_some());
    assert!(!nodes[0].node.get_peer(&addr_1).unwrap().rekey_in_progress());

    set_link_dead_timeout(&mut nodes[0].node, 0);

    nodes[0].node.check_link_heartbeats().await;

    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "dead peer with no rekey in flight should be reaped"
    );

    cleanup_nodes(&mut nodes).await;
}

/// Rewind a peer's heartbeat bookkeeping by `age`, as if that long had passed
/// since its last successful send.
///
/// The sweep reads `std::time::Instant`, which tokio's paused clock does not
/// move, so elapsed time is staged on the peer rather than waited out. Sets
/// both timestamps, which is the state a *healthy* peer is in.
fn age_heartbeat(node: &mut crate::node::Node, addr: &NodeAddr, age: Duration) {
    let then = std::time::Instant::now() - age;
    node.peers
        .get_mut(addr)
        .expect("peer present")
        .mark_heartbeat_sent(then);
}

/// **The retry gate must not floor a healthy peer's configured interval.**
///
/// A successful send stamps `last_heartbeat_sent` and `last_heartbeat_attempt`
/// with the same instant. Gating every peer on the attempt timestamp therefore
/// gates the healthy path too, and the effective interval becomes the larger of
/// the configured value and `HEARTBEAT_RETRY_INTERVAL` — so a configured 1s
/// becomes 2s, silently, with nothing validating the value and nothing saying
/// why. `src/node/tests/tcp.rs` already configures 1s against a 3s dead
/// timeout, which is the margin that would quietly halve.
#[tokio::test]
async fn a_healthy_peer_is_heartbeated_on_its_configured_interval() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    set_heartbeat_interval(&mut nodes[0].node, 1);

    // Past the configured interval, short of the failure-retry interval. That
    // window is the whole defect: healthy, due, and gated anyway.
    age_heartbeat(&mut nodes[0].node, &addr_1, Duration::from_millis(1_200));
    let before = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("peer 1 is established")
        .last_heartbeat_sent()
        .expect("staged above");

    nodes[0].node.check_link_heartbeats().await;

    let after = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("peer 1 is still established")
        .last_heartbeat_sent()
        .expect("still sent");
    assert!(
        after > before,
        "a healthy peer must be heartbeated on its configured interval, not \
         floored at the failure-retry interval"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The other half: after a send that *failed*, the retry is spaced out rather
/// than reattempted on the very next tick.
///
/// Without that spacing a peer whose send keeps failing is retried every tick,
/// and the send behind it can await an unbounded stream write on the rx loop.
/// The peer is re-pinned onto a UDP transport that was never started, so its
/// send fails with `NotStarted` before touching a socket.
#[tokio::test]
async fn a_failing_peer_is_retried_after_the_gap_and_not_before() {
    use crate::transport::{TransportAddr, TransportHandle, TransportId, packet_channel};

    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    set_heartbeat_interval(&mut nodes[0].node, 1);

    let dead_id = TransportId::new(91);
    let (tx, _rx) = packet_channel(64);
    nodes[0].node.transports.insert(
        dead_id,
        TransportHandle::Udp(crate::transport::udp::UdpTransport::new(
            dead_id,
            None,
            crate::config::UdpConfig::default(),
            tx,
        )),
    );
    nodes[0]
        .node
        .peers
        .get_mut(&addr_1)
        .expect("peer 1 is established")
        .set_current_addr(dead_id, TransportAddr::from_string("10.0.0.2:2121"));

    // Long overdue and healthy-looking, so the sweep will try.
    age_heartbeat(&mut nodes[0].node, &addr_1, Duration::from_secs(10));
    nodes[0].node.check_link_heartbeats().await;

    let attempt_1 = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("peer 1 is established")
        .last_heartbeat_attempt()
        .expect("a failed send is still an attempt");
    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .unwrap()
            .last_heartbeat_sent()
            .expect("staged")
            < attempt_1,
        "the failed send must not have stamped a success"
    );

    // Immediately after: still inside the gap, so no second attempt.
    nodes[0].node.check_link_heartbeats().await;
    assert_eq!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .expect("peer 1 is established")
            .last_heartbeat_attempt(),
        Some(attempt_1),
        "a failing peer must not be retried on the very next tick"
    );

    // Stage the gap as elapsed, keeping the attempt newer than the success so
    // the peer still reads as "last one failed".
    let past = std::time::Instant::now() - Duration::from_secs(3);
    nodes[0]
        .node
        .peers
        .get_mut(&addr_1)
        .expect("peer present")
        .mark_heartbeat_attempt(past);

    nodes[0].node.check_link_heartbeats().await;
    let attempt_2 = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("peer 1 is established")
        .last_heartbeat_attempt()
        .expect("still attempted");
    assert!(
        attempt_2 > past,
        "a failing peer must be retried once the gap has passed"
    );

    cleanup_nodes(&mut nodes).await;
}

// ---------------------------------------------------------------------------
// Reaping peers when their interface goes away
//
// The detach edge is both earlier and more certain than inactivity, so it is
// the better trigger for withdrawing what the interface carried. These drive
// the same real two-node peering the liveness tests use, because a peer only
// reaches the established context the reap acts on by actually peering.
// ---------------------------------------------------------------------------

/// A peer reachable only through an interface that has gone is withdrawn on
/// the detach edge, without waiting out `link_dead_timeout_secs`.
///
/// Note what is *not* set here: the link-dead timeout keeps its default, and
/// no time is advanced. The peer is live by every liveness measure and is
/// still withdrawn, because the transport under it is gone — which is the
/// whole distinction this adds.
#[tokio::test]
async fn a_detached_transport_withdraws_the_peers_that_needed_it() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let transport_id = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("peer present")
        .transport_id()
        .expect("an established peer names its transport");

    let reaped = nodes[0].node.reap_peers_on_transport(transport_id).await;

    assert_eq!(reaped, 1);
    assert!(
        nodes[0].node.get_peer(&addr_1).is_none(),
        "a peer must not outlive the interface it was reachable through"
    );

    cleanup_nodes(&mut nodes).await;
}

/// The reap is scoped to the transport that detached.
///
/// The failure this guards is the one that would make the feature worse than
/// the defect: an interface going away must not withdraw the peers that were
/// never reachable through it, which on a mesh router is most of them.
#[tokio::test]
async fn a_detached_transport_leaves_other_transports_peers_alone() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);

    let addr_1 = *nodes[1].node.node_addr();
    let peer_transport = nodes[0]
        .node
        .get_peer(&addr_1)
        .expect("peer present")
        .transport_id()
        .expect("an established peer names its transport");

    // A transport this peer was never reachable through.
    let unrelated = TransportId::new(peer_transport.as_u32() + 100);
    let reaped = nodes[0].node.reap_peers_on_transport(unrelated).await;

    assert_eq!(reaped, 0, "an unrelated transport withdraws nothing");
    assert!(
        nodes[0].node.get_peer(&addr_1).is_some(),
        "a peer on a healthy transport must survive another one detaching"
    );

    cleanup_nodes(&mut nodes).await;
}
