//! Link-dead heartbeat rekey-awareness integration tests.
//!
//! `check_link_heartbeats()` reaps a peer after the link-dead timeout,
//! but suppresses teardown while this node's FMP rekey is in flight. These
//! tests drive a two-node peering, let the link machine's time trigger
//! start a rekey, and verify the suppress / resume / regression behaviors.
//! `link_dead_timeout_secs` is set to 0 so the elapsed-time predicate is
//! always satisfied and the only variable is the rekey-active guard.

use super::spanning_tree::*;
use super::*;

/// Set `link_dead_timeout_secs` on an already-constructed node via the
/// sole-store copy-on-write context swap (immutable state is no longer a
/// directly-pokeable field; `config()` is a read-only accessor).
pub(super) fn set_link_dead_timeout(node: &mut crate::node::Node, secs: u64) {
    node.replace_context(|ctx| {
        let mut cfg = (*ctx.config).clone();
        cfg.node.link_dead_timeout_secs = secs;
        ctx.config = std::sync::Arc::new(cfg);
    });
}

/// Set `node.heartbeat_interval_secs` on an already-constructed node, the same
/// way `set_link_dead_timeout` does. This is the knob the retry gate must not
/// floor.
pub(super) fn set_heartbeat_interval(node: &mut crate::node::Node, secs: u64) {
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

/// The rekey msg1s queued at `tn`, taking every packet off its queue.
fn msg1s(tn: &mut TestNode) -> Vec<Vec<u8>> {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1};

    std::iter::from_fn(|| tn.packet_rx.try_recv().ok())
        .map(|p| p.data)
        .filter(|d| CommonPrefix::parse(d).is_some_and(|p| p.phase == PHASE_MSG1))
        .collect()
}

/// A link rekey toward a peer that has gone silent sends its msg1 at 0, 1,
/// 3, 7 and 15 s and no copy at 31 s, and ends 30 s after its first msg1;
/// the poll that ends it starts no other, and the next waits out a back-off
/// of one tick plus up to 15 s. The link is kept while an attempt is in
/// flight, even one whose every msg1 the transport refuses, and is reaped
/// by the first link-dead check after that attempt ends.
///
/// The tick checks heartbeats before it polls the link machines, so the
/// back-off is what lets the reap run between two attempts.
#[tokio::test]
async fn a_silent_peers_link_rekey_ends_30_s_after_its_first_msg1_backs_off_and_the_link_is_reaped_after_an_attempt_whose_sends_all_fail()
 {
    use super::rekey_parity::{age_link, linked_pair, rekey_config, trigger_age};

    let mut nodes = linked_pair(rekey_config(60), crate::config::Config::new()).await;
    let peer = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    let in_flight = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .get_peer(&peer)
            .is_some_and(|p| p.rekey_in_progress())
    };

    nodes[0].node.poll_link_rekeys().await;
    let first = msg1s(&mut nodes[1]);
    assert!(
        in_flight(&nodes) && first.len() == 1,
        "control: the time trigger started a rekey and its msg1 went out"
    );

    // Node 1 is never driven, so nothing answers.
    let mut copies = Vec::new();
    for s in 1..=30u64 {
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.poll_link_rekeys().await;
        for m in msg1s(&mut nodes[1]) {
            assert_eq!(
                m, first[0],
                "at {s} s a msg1 other than the first's copy went out"
            );
            copies.push(s);
        }
    }
    assert!(
        !in_flight(&nodes),
        "the attempt must end 30 s after its first msg1, and the poll that ends it must start no other"
    );
    assert_eq!(
        copies,
        [1, 3, 7, 15],
        "the msg1 must be resent at 1, 3, 7 and 15 s and not at 31 s"
    );

    // From here every send fails.
    nodes[0].node.transports.clear();
    let mut next = None;
    for s in 31..=46u64 {
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.poll_link_rekeys().await;
        if in_flight(&nodes) {
            next = Some(s);
            break;
        }
    }
    let next =
        next.expect("the next attempt must start once one tick plus at most 15 s have passed");

    // One-second ticks in the node's order, the peer past the link-dead
    // timeout throughout.
    set_link_dead_timeout(&mut nodes[0].node, 0);
    let mut reaped_at = None;
    for s in next + 1..=next + 60 {
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.check_link_heartbeats().await;
        if nodes[0].node.get_peer(&peer).is_none() {
            reaped_at = Some(s);
            break;
        }
        nodes[0].node.poll_link_rekeys().await;
    }
    assert_eq!(
        reaped_at,
        Some(next + 31),
        "the link must be kept while the attempt started at {next} s is in flight, every msg1 of it \
         refused, and reaped by the first link-dead check after it ends at {} s",
        next + 30
    );

    cleanup_nodes(&mut nodes).await;
}

/// The established frames queued at `tn`, each with the receiver index its
/// header names, taking every packet off its queue.
fn frames(tn: &mut TestNode) -> Vec<(SessionIndex, ReceivedPacket)> {
    use crate::proto::fmp::wire::EncryptedHeader;

    std::iter::from_fn(|| tn.packet_rx.try_recv().ok())
        .filter_map(|p| EncryptedHeader::parse(&p.data).map(|h| (h.receiver_idx, p)))
        .collect()
}

/// A link rekey's initiator prompts its peer under the new session at its
/// cutover, and again 1 s and 3 s after it while it has not heard the peer
/// under that session; the responder that adopts on a prompt prompts once
/// in turn, and that frame stops the initiator's prompts. A responder
/// whose first prompts were lost therefore adopts within seconds rather
/// than on the next heartbeat or data, and the initiator hears the peer
/// under the new session at once instead of only on the previous one.
///
/// Run twice: the first prompt to arrive is the one sent at 1 s, after
/// which the 3 s one must not be sent, and the one sent at 3 s, after
/// which there is no rung left.
#[tokio::test]
async fn a_link_cutover_prompts_the_peer_at_once_and_at_1_s_and_3_s_until_it_is_heard_and_the_adoption_prompts_once()
 {
    use super::rekey_parity::{
        age_link, cutover, linked_pair, rekey_config, rekey_to_pending, trigger_age,
    };

    for kept in [1u64, 3] {
        let mut nodes = linked_pair(rekey_config(60), crate::config::Config::new()).await;
        let a = *nodes[0].node.node_addr();
        let b = *nodes[1].node.node_addr();
        age_link(&mut nodes, 0, 1, trigger_age());
        let b_pending = rekey_to_pending(&mut nodes, 0, 1).await;
        cutover(&mut nodes[0], &b).await;
        let a_current = nodes[0].node.get_peer(&b).unwrap().our_index().unwrap();

        // Every prompt sent before the one at `kept` s is lost.
        for (s, step) in [(0u64, 0u64), (1, 1), (3, 2)] {
            crate::time::advance(Duration::from_secs(step));
            if s > 0 {
                nodes[0].node.poll_link_rekeys().await;
            }
            let queued = frames(&mut nodes[1]);
            let indices: Vec<_> = queued.iter().map(|(i, _)| *i).collect();
            if s > kept {
                assert!(
                    queued.is_empty(),
                    "heard under the new session at {kept} s, the initiator must send nothing at \
                     {s} s; queued: {indices:?}"
                );
                continue;
            }
            assert!(
                queued.len() == 1 && queued[0].0 == b_pending,
                "at {s} s after the cutover the initiator must send one frame under the new \
                 session, to the responder's pending index; queued: {indices:?}"
            );
            if s < kept {
                continue;
            }

            // This prompt arrives: the responder adopts and prompts once.
            for (_, p) in queued {
                nodes[1].node.handle_encrypted_frame(p).await;
            }
            let peer = nodes[1].node.get_peer(&a).unwrap();
            assert!(
                peer.pending_new_session().is_none() && peer.our_index() == Some(b_pending),
                "the responder adopts the new session on the prompt sent at {kept} s"
            );
            let answer = frames(&mut nodes[0]);
            assert!(
                answer.len() == 1 && answer[0].0 == a_current,
                "the adoption must send one frame under the new session; queued: {:?}",
                answer.iter().map(|(i, _)| *i).collect::<Vec<_>>()
            );
            for (_, p) in answer {
                nodes[0].node.handle_encrypted_frame(p).await;
            }
        }

        // Neither end prompts again.
        for _ in 0..10 {
            crate::time::advance(Duration::from_secs(1));
            nodes[0].node.poll_link_rekeys().await;
            nodes[1].node.poll_link_rekeys().await;
        }
        let late = (frames(&mut nodes[1]).len(), frames(&mut nodes[0]).len());
        assert_eq!(
            late,
            (0, 0),
            "heard at {kept} s: no prompt may follow once each end has heard the other under \
             the new session"
        );

        cleanup_nodes(&mut nodes).await;
    }
}

/// After this node's link rekey cutover, a peer that never hears the new
/// session goes on sealing under the previous one. Nothing shows the peer
/// moved, so the previous session is kept until the drain's 120 s ceiling,
/// and the peer's frames under it count for liveness: the link is not
/// reaped at the link-dead timeout while they keep arriving.
///
/// Every frame this node sends after the cutover is lost; the peer's
/// heartbeats arrive every 5 s.
#[tokio::test]
async fn a_peer_heard_only_under_the_previous_session_after_a_cutover_keeps_it_to_the_drain_ceiling_and_is_not_reaped()
 {
    use super::rekey_parity::{
        age_link, cutover, deliver, heartbeat, linked_pair, rekey_config, rekey_to_pending,
    };

    // A rekey interval long enough that no second rekey starts in the run.
    let after = 300;
    let mut nodes = linked_pair(rekey_config(after), crate::config::Config::new()).await;
    let a = *nodes[0].node.node_addr();
    let b = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, Duration::from_secs(after + 16));
    rekey_to_pending(&mut nodes, 0, 1).await;
    let previous = nodes[0].node.get_peer(&b).unwrap().our_index();
    cutover(&mut nodes[0], &b).await;

    let mut reaped = None;
    let mut dropped = None;
    for s in (5..=125u64).step_by(5) {
        crate::time::advance(Duration::from_secs(5));
        while nodes[1].packet_rx.try_recv().is_ok() {}
        heartbeat(&mut nodes[1], &a).await;
        deliver(&mut nodes[0]).await;
        nodes[0].node.check_link_heartbeats().await;
        if nodes[0].node.get_peer(&b).is_none() {
            reaped = Some(s);
            break;
        }
        nodes[0].node.poll_link_rekeys().await;
        let held = nodes[0].node.get_peer(&b).unwrap().previous_our_index();
        if dropped.is_none() && held != previous {
            dropped = Some(s);
        }
    }
    assert_eq!(
        (reaped, dropped),
        (None, Some(120)),
        "(reaped at, previous session dropped at), in seconds after the cutover: the peer must \
         be kept while its frames arrive under the previous session, and that session held to \
         the drain's 120 s ceiling"
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
