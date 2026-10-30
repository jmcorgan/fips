//! Dials made after a peer restarts, checked for the outcome that matters to
//! both ends: each holds the other on the same link session (each end's
//! index for the peer is the index the peer names it by), frames
//! authenticate both ways, and the end-to-end session to the restarted peer
//! is cleared.
//!
//! D is the node that kept running and still holds the peering of R's
//! previous run; R restarted and holds nothing. Either D alone dials, or
//! both dial at once, with either node's msg1 processed first and either
//! node the smaller address.

use super::rekey_parity::{deliver, heartbeat, linked_pair, pump, stale_session};
use super::spanning_tree::{TestNode, cleanup_nodes, initiate_handshake, restarted_node};
use super::*;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1, PHASE_MSG2};

/// What a case ended with, as a list of the failures found (empty when both
/// ends hold one session and frames authenticate both ways).
async fn check_outcome(nodes: &mut [TestNode], d: usize, r: usize) -> Vec<String> {
    let d_addr = *nodes[d].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    let mut bad = Vec::new();
    let (Some(dp), Some(rp)) = (
        nodes[d].node.get_peer(&r_addr),
        nodes[r].node.get_peer(&d_addr),
    ) else {
        bad.push(format!(
            "an end holds no peer (D holds R: {}, R holds D: {})",
            nodes[d].node.get_peer(&r_addr).is_some(),
            nodes[r].node.get_peer(&d_addr).is_some()
        ));
        return bad;
    };
    if dp.our_index() != rp.their_index() || dp.their_index() != rp.our_index() {
        let direction = |tn: &TestNode, link| tn.node.links.get(&link).map(|l| l.direction());
        bad.push(format!(
            "the ends hold different sessions (D our/their {:?}/{:?} on its {:?} link, R \
             our/their {:?}/{:?} on its {:?} link; D's handshake refusals {:?}, R's {:?})",
            dp.our_index(),
            dp.their_index(),
            direction(&nodes[d], dp.link_id()),
            rp.our_index(),
            rp.their_index(),
            direction(&nodes[r], rp.link_id()),
            nodes[d].node.stats().handshake.snapshot(),
            nodes[r].node.stats().handshake.snapshot(),
        ));
    }
    if nodes[d].node.get_session(&r_addr).is_some() {
        bad.push("D still holds the end-to-end session of R's previous run".into());
    }

    // Frames each way, each checked by the receiver's last-seen stamp moving
    // and no decryption failure, so a frame that never arrived is not read
    // as one that authenticated.
    for (from, to) in [(d, r), (r, d)] {
        let to_addr = *nodes[to].node.node_addr();
        let from_addr = *nodes[from].node.node_addr();
        let seen = |nodes: &[TestNode]| {
            nodes[to]
                .node
                .get_peer(&from_addr)
                .map(|p| (p.last_seen(), p.consecutive_decrypt_failures()))
        };
        let before = seen(nodes);
        // Real time passes rather than a step of the test wall clock: the
        // receiver stamps `last_seen` with the frame's receipt time, which
        // such a step does not move, and the restart gates compare that
        // stamp with the stepped clock, so a step would make a peering
        // installed moments earlier look idle to them.
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        if nodes[from].node.get_peer(&to_addr).is_none() {
            continue;
        }
        heartbeat(&mut nodes[from], &to_addr).await;
        deliver(&mut nodes[to]).await;
        let after = seen(nodes);
        let ok = matches!((before, after), (Some((b, _)), Some((a, 0))) if a > b);
        if !ok {
            let dir = if from == d { "D to R" } else { "R to D" };
            bad.push(format!(
                "a heartbeat {dir} did not authenticate (last seen and failures before {before:?}, after {after:?})"
            ));
        }
    }
    bad
}

/// A linked pair after R restarts, with D holding an end-to-end session to
/// R's previous run. D is the smaller address when `d_smaller`, and dialled
/// the original link when `d_dialled` (so it holds an outbound link, which
/// makes any later dial of its own a swap whatever the tie-break). Pairs are
/// drawn until the address order matches, since addresses come from fresh
/// keys.
async fn restarted_pair(d_smaller: bool, d_dialled: bool) -> (Vec<TestNode>, usize, usize) {
    let (d, r) = if d_dialled { (0, 1) } else { (1, 0) };
    for _ in 0..64 {
        let mut nodes = linked_pair(Config::new(), Config::new()).await;
        if (nodes[d].node.node_addr() < nodes[r].node.node_addr()) != d_smaller {
            cleanup_nodes(&mut nodes).await;
            continue;
        }
        let r_addr = *nodes[r].node.node_addr();
        stale_session(&mut nodes[d].node, r_addr);
        let restarted = restarted_node(&nodes[r], Config::new());
        drop(std::mem::replace(&mut nodes[r], restarted));
        return (nodes, d, r);
    }
    panic!("no pair in 64 draws had the address order asked for");
}

/// Every placement of D: smaller or larger address, original dialer or not.
const PLACEMENTS: [(bool, bool); 4] = [(true, true), (true, false), (false, true), (false, false)];

/// D alone dials R after R restarts, in every placement of D: both ends
/// hold the session of D's dial, frames authenticate both ways, and D has
/// cleared its end-to-end session to R. D larger and not the original dialer
/// is the case that once kept R's previous session (a tie-break loss with
/// no own dial on record).
#[tokio::test]
async fn one_dial_after_a_peer_restart_leaves_both_ends_on_one_session_with_end_to_end_sessions_cleared()
 {
    let mut failures = Vec::new();
    for (d_smaller, d_dialled) in PLACEMENTS {
        let (mut nodes, d, r) = restarted_pair(d_smaller, d_dialled).await;
        initiate_handshake(&mut nodes, d, r).await;
        pump(&mut nodes).await;
        for f in check_outcome(&mut nodes, d, r).await {
            failures.push(format!(
                "D smaller {d_smaller}, D dialled the original link {d_dialled}: {f}"
            ));
        }
        cleanup_nodes(&mut nodes).await;
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Process the handshake messages queued at `tn` in the reverse of their
/// arrival order, so the answer to its own dial is read before the other
/// node's msg1, as when the msg1 is delayed on the path.
async fn deliver_reversed(tn: &mut TestNode) {
    let mut queued: Vec<ReceivedPacket> =
        std::iter::from_fn(|| tn.packet_rx.try_recv().ok()).collect();
    queued.reverse();
    for packet in queued {
        match CommonPrefix::parse(&packet.data).map(|p| p.phase) {
            Some(PHASE_MSG1) => tn.node.handle_msg1(packet).await,
            Some(PHASE_MSG2) => tn.node.handle_msg2(packet).await,
            _ => tn.node.handle_encrypted_frame(packet).await,
        }
    }
}

/// Both D and R dial after R restarts, both msg1s in flight at once: one
/// node reads the other's msg1 first, and the second reads what reached it
/// (the other's msg1 and the answer to its own) in arrival order or
/// reversed. Every placement of D, and D's last frame from R's previous run
/// either just now or 16 s back (outside the 15 s floor on a restart). Both
/// ends must settle on one session.
#[tokio::test]
async fn both_ends_dialling_after_a_peer_restart_settle_on_one_session_in_either_message_order() {
    let mut failures = Vec::new();
    for (d_first, reversed) in [(true, false), (true, true), (false, false), (false, true)] {
        for (d_smaller, d_dialled) in PLACEMENTS {
            for silent in [false, true] {
                let (mut nodes, d, r) = restarted_pair(d_smaller, d_dialled).await;
                let r_addr = *nodes[r].node.node_addr();
                if silent {
                    nodes[d]
                        .node
                        .get_peer_mut(&r_addr)
                        .expect("D holds R's previous run")
                        .touch(Node::now_ms() - 16_000);
                }
                initiate_handshake(&mut nodes, d, r).await;
                initiate_handshake(&mut nodes, r, d).await;
                let (first, second) = if d_first { (r, d) } else { (d, r) };
                // `first` processes the other's msg1 before `second` sees
                // anything.
                deliver(&mut nodes[first]).await;
                if reversed {
                    deliver_reversed(&mut nodes[second]).await;
                } else {
                    deliver(&mut nodes[second]).await;
                }
                pump(&mut nodes).await;
                let label = format!(
                    "{} msg1 first, second reader {}, D smaller {d_smaller}, D dialled the original link \
                     {d_dialled}, D's last frame from R {}",
                    if d_first { "D's" } else { "R's" },
                    if reversed {
                        "answer first"
                    } else {
                        "in arrival order"
                    },
                    if silent { "16 s back" } else { "just now" }
                );
                for f in check_outcome(&mut nodes, d, r).await {
                    failures.push(format!("{label}: {f}"));
                }
                cleanup_nodes(&mut nodes).await;
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// Control for the test above, with no restart: two nodes that have never
/// peered dial each other at once, in the same four orders. Separates a
/// split the restart causes from one any crossed pair of dials reaches.
#[tokio::test]
async fn two_fresh_nodes_dialling_each_other_settle_on_one_session_in_either_message_order() {
    use super::spanning_tree::make_test_node;

    let mut failures = Vec::new();
    for (zero_first, reversed) in [(true, false), (true, true), (false, false), (false, true)] {
        for zero_smaller in [true, false] {
            let mut nodes = loop {
                let nodes = vec![make_test_node().await, make_test_node().await];
                if (nodes[0].node.node_addr() < nodes[1].node.node_addr()) == zero_smaller {
                    break nodes;
                }
            };
            initiate_handshake(&mut nodes, 0, 1).await;
            initiate_handshake(&mut nodes, 1, 0).await;
            let (first, second) = if zero_first { (1, 0) } else { (0, 1) };
            deliver(&mut nodes[first]).await;
            if reversed {
                deliver_reversed(&mut nodes[second]).await;
            } else {
                deliver(&mut nodes[second]).await;
            }
            pump(&mut nodes).await;
            let label = format!(
                "node 0's msg1 first {zero_first}, second reader {}, node 0 smaller {zero_smaller}",
                if reversed {
                    "answer first"
                } else {
                    "in arrival order"
                },
            );
            for f in check_outcome(&mut nodes, 0, 1).await {
                failures.push(format!("{label}: {f}"));
            }
            cleanup_nodes(&mut nodes).await;
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}
