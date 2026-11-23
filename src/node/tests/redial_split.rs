//! A node that drops an aged link and redials its peer, on loopback.
//!
//! Two nodes are peered over loopback. One of them (the redialer) removes the
//! other locally, without a word on the wire, once the link is older than the
//! 30 s link-age floor, and dials it again. The other (the answerer) still
//! holds the redialer, and settles the redial at its msg3 against the link it
//! holds. Each test pins which end dialed that first link.
//!
//! - The redialer dialed it: the redial is a second handshake dialed by the
//!   same side, and the answerer moves onto it whichever node is the smaller
//!   (FRC-2201 Section 5.7). Both ends converge on one session at once.
//! - The answerer dialed it: the redial meets the answerer's own dial, and
//!   the address order settles it. A smaller redialer converges at once,
//!   the larger answerer moving onto it. A larger redialer's handshake is
//!   one FRC-2201 Section 5.7 refuses until the old link is declared dead:
//!   the smaller answerer keeps its own dial, and the pair converges only
//!   after both ends' link-dead reaps and a fresh dial.
//!
//! The pair has converged when their session indices pair and a frame each
//! sends on its current session authenticates at the other. No test sleeps:
//! loopback delivery is synchronous, packets are handed on by
//! `process_available_packets`, and simulated time moves with
//! `crate::time::advance` and `crate::time::step_wall`.

use super::rekey_parity::age_link;
use super::spanning_tree::{
    TestNode, cleanup_nodes, initiate_handshake, make_test_node_with_config,
    process_available_packets,
};
use super::*;
use crate::proto::link::LinkMessageType;

/// Past the 31 s link-age floor on `next`: the 30 s `link_age` plus the 1 s
/// check (`fips_core::proto::rekey` `floor_link`), above which a deployed
/// peer takes a same-epoch msg1 for a rekey rather than a fresh dial.
const LINK_AGE: Duration = Duration::from_secs(32);

/// Most delivery rounds `settle` runs before giving up on quiescence.
const ROUNDS: usize = 50;

/// Simulated seconds the reap is waited for: four link-dead timeouts.
const RECOVERY_SECS: u64 = 120;

/// Deliver queued packets between the nodes until a round moves none.
/// Returns the number of rounds that moved a packet.
async fn settle(nodes: &mut [TestNode]) -> usize {
    for round in 0..ROUNDS {
        if process_available_packets(nodes).await == 0 {
            return round;
        }
    }
    panic!("setup: packets still moving after {ROUNDS} rounds");
}

/// Deliver the packets queued at `nodes[at]`, and only there.
async fn deliver(nodes: &mut [TestNode], at: usize) -> usize {
    process_available_packets(std::slice::from_mut(&mut nodes[at])).await
}

fn addr(nodes: &[TestNode], i: usize) -> NodeAddr {
    *nodes[i].node.node_addr()
}

/// Whether `x` and `y` each hold the other with session indices that pair:
/// each end's own index is the index the other sends to.
fn paired(nodes: &[TestNode], x: usize, y: usize) -> bool {
    let (Some(px), Some(py)) = (
        nodes[x].node.get_peer(&addr(nodes, y)),
        nodes[y].node.get_peer(&addr(nodes, x)),
    ) else {
        return false;
    };
    px.our_index().is_some()
        && py.our_index().is_some()
        && px.our_index() == py.their_index()
        && py.our_index() == px.their_index()
}

/// Authenticated frames `at` has counted from `from`, or `None` when `at`
/// holds no such peer.
fn received(nodes: &[TestNode], at: usize, from: usize) -> Option<u64> {
    nodes[at]
        .node
        .get_peer(&addr(nodes, from))
        .map(|p| p.link_stats().packets_recv)
}

/// Whether a heartbeat `from` sends on its current session to `to`
/// authenticates at `to`. Every other queued packet is delivered first, so
/// the count moves only for this frame or frames it provokes.
async fn authenticates(nodes: &mut [TestNode], from: usize, to: usize) -> bool {
    settle(nodes).await;
    let Some(before) = received(nodes, to, from) else {
        return false;
    };
    let to_addr = addr(nodes, to);
    if nodes[from]
        .node
        .send_encrypted_link_message(&to_addr, &[LinkMessageType::Heartbeat.to_byte()])
        .await
        .is_err()
    {
        return false;
    }
    settle(nodes).await;
    received(nodes, to, from).is_some_and(|after| after > before)
}

/// What the pair looks like at one moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct State {
    redialer_holds: bool,
    answerer_holds: bool,
    paired: bool,
    redialer_to_answerer: bool,
    answerer_to_redialer: bool,
    redialer_has_filter: bool,
}

impl State {
    fn converged(&self) -> bool {
        self.paired && self.redialer_to_answerer && self.answerer_to_redialer
    }
}

async fn observe(nodes: &mut [TestNode], r: usize, n: usize) -> State {
    let r_addr = addr(nodes, r);
    let n_addr = addr(nodes, n);
    let paired = paired(nodes, r, n);
    let redialer_to_answerer = authenticates(nodes, r, n).await;
    let answerer_to_redialer = authenticates(nodes, n, r).await;
    State {
        redialer_holds: nodes[r].node.get_peer(&n_addr).is_some(),
        answerer_holds: nodes[n].node.get_peer(&r_addr).is_some(),
        paired,
        redialer_to_answerer,
        answerer_to_redialer,
        redialer_has_filter: nodes[r]
            .node
            .get_peer(&n_addr)
            .is_some_and(|p| p.inbound_filter().is_some()),
    }
}

/// One pass of the periodic work the daemon's tick runs that bears on a
/// peering: timeouts, peering timers and retries, tree and bloom state, MMP
/// reports, link heartbeats and liveness, and link rekeys.
async fn tick(tn: &mut TestNode) {
    let node = &mut tn.node;
    node.check_timeouts().await;
    node.drive_peer_timers(Node::now_ms()).await;
    node.process_pending_retries(Node::peering_now()).await;
    node.check_tree_state().await;
    node.check_bloom_state().await;
    node.check_mmp_reports().await;
    node.check_link_heartbeats().await;
    node.poll_link_rekeys().await;
}

/// The redial, up to and including the answerer's msg3, with every step's
/// precondition asserted: the redialer is the larger node when
/// `redialer_larger`, and dialed the first link when `redialer_dialed`.
/// Returns the nodes and (redialer, answerer).
async fn redial(redialer_larger: bool, redialer_dialed: bool) -> (Vec<TestNode>, usize, usize) {
    let mut nodes = vec![
        make_test_node_with_config(Config::new(), 1280).await,
        make_test_node_with_config(Config::new(), 1280).await,
    ];
    let larger = if addr(&nodes, 0) > addr(&nodes, 1) {
        0
    } else {
        1
    };
    let (r, n) = if redialer_larger {
        (larger, 1 - larger)
    } else {
        (1 - larger, larger)
    };
    let (dialer, dialed) = if redialer_dialed { (r, n) } else { (n, r) };
    initiate_handshake(&mut nodes, dialer, dialed).await;
    settle(&mut nodes).await;
    for tn in nodes.iter_mut() {
        tn.node.bloom_state.set_update_debounce_ms(0);
    }
    let r_addr = addr(&nodes, r);
    let n_addr = addr(&nodes, n);
    assert_eq!(
        r_addr > n_addr,
        redialer_larger,
        "precondition: the redialer is the {} node",
        if redialer_larger { "larger" } else { "smaller" }
    );
    assert!(
        paired(&nodes, r, n),
        "precondition: the first peering's indices pair"
    );
    assert!(
        authenticates(&mut nodes, r, n).await && authenticates(&mut nodes, n, r).await,
        "precondition: frames authenticate both ways on the first peering"
    );

    age_link(&mut nodes, r, n, LINK_AGE);
    for (x, y) in [(r, n_addr), (n, r_addr)] {
        let p = nodes[x].node.get_peer(&y).unwrap();
        let link = p.link_established_at().map(crate::peer::since);
        let session = p.session_established_at().map(crate::peer::since);
        assert!(
            link.is_some_and(|a| a >= LINK_AGE) && session.is_some_and(|a| a >= LINK_AGE),
            "precondition: both ends' link and session are past the link-age floor \
             (link {link:?}, session {session:?})"
        );
    }
    let r_old = nodes[r].node.get_peer(&n_addr).unwrap().our_index();

    nodes[r].node.remove_active_peer(&n_addr);
    assert!(
        nodes[r].node.get_peer(&n_addr).is_none(),
        "precondition: the redialer dropped the answerer"
    );
    assert!(
        nodes[n].node.get_peer(&r_addr).is_some(),
        "precondition: the answerer still holds the redialer"
    );

    initiate_handshake(&mut nodes, r, n).await;
    assert_eq!(
        deliver(&mut nodes, n).await,
        1,
        "precondition: only the redial's msg1 is queued at the answerer"
    );
    assert_eq!(
        deliver(&mut nodes, r).await,
        1,
        "precondition: only the answerer's msg2 is queued at the redialer"
    );
    let r_new = nodes[r]
        .node
        .get_peer(&n_addr)
        .expect("precondition: the redialer promoted the answerer from the msg2")
        .our_index();
    assert!(
        r_new.is_some() && r_new != r_old,
        "precondition: the redialer holds a new session"
    );
    assert!(
        deliver(&mut nodes, n).await >= 1,
        "precondition: the redial's msg3 reaches the answerer"
    );
    assert!(
        nodes[n].node.get_peer(&r_addr).is_some(),
        "precondition: the answerer still holds the redialer after the msg3"
    );
    (nodes, r, n)
}

/// The pair's state after the redial's delivery rounds, three bloom ticks
/// apart.
async fn after_rounds(nodes: &mut [TestNode], r: usize, n: usize) -> State {
    for _ in 0..3 {
        for tn in nodes.iter_mut() {
            tn.node.check_bloom_state().await;
        }
        settle(nodes).await;
    }
    observe(nodes, r, n).await
}

/// The redial converges at once: after the delivery rounds both ends hold
/// one session that carries frames both ways.
async fn converges(redialer_larger: bool, redialer_dialed: bool) {
    let (mut nodes, r, n) = redial(redialer_larger, redialer_dialed).await;
    let st = after_rounds(&mut nodes, r, n).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        st.converged(),
        "defect: the pair must hold one session carrying frames both ways: {st:?}"
    );
}

/// The larger node redials a link it dialed: the smaller answerer moves at
/// the redial's msg3 by the same-side rule.
#[tokio::test]
async fn a_larger_node_redialing_an_aged_link_it_dialed_converges_on_one_session_both_ways() {
    converges(true, true).await;
}

/// The smaller node redials a link it dialed: the larger answerer moves.
#[tokio::test]
async fn a_smaller_node_redialing_an_aged_link_it_dialed_converges_on_one_session_both_ways() {
    converges(false, true).await;
}

/// The smaller node redials a link the answerer dialed: the larger answerer
/// moves by the address order.
#[tokio::test]
async fn a_smaller_node_redialing_an_aged_link_the_answerer_dialed_converges_on_one_session_both_ways()
 {
    converges(false, false).await;
}

/// The larger node redials a link the answerer dialed, a handshake FRC-2201
/// Section 5.7 refuses until the old link is declared dead. The smaller
/// answerer keeps its own dial. Both ends keep the other, on sessions that
/// do not pair and carry no frame either way, until their link-dead check
/// reaps the other at the 30 s timeout; nothing re-pairs them before that.
/// Once both have reaped, a fresh dial is a net-new promotion at each end
/// and converges.
#[tokio::test]
async fn a_larger_node_redialing_an_aged_link_the_answerer_dialed_converges_only_after_both_ends_reap_at_the_link_dead_timeout()
 {
    let (mut nodes, r, n) = redial(true, false).await;
    settle(&mut nodes).await;
    let dead = nodes[0].node.config().node.link_dead_timeout_secs;
    assert_eq!(dead, 30, "precondition: the stock link-dead timeout");

    let mut reaped_at = None;
    for s in 0..=RECOVERY_SECS {
        if s > 0 {
            crate::time::advance(Duration::from_secs(1));
            crate::time::step_wall(1000);
            for tn in nodes.iter_mut() {
                tick(tn).await;
            }
            settle(&mut nodes).await;
        }
        let st = observe(&mut nodes, r, n).await;
        assert!(
            !st.converged(),
            "the pair converged at {s}s, before any reap: {st:?}"
        );
        if !st.redialer_holds && !st.answerer_holds {
            reaped_at = Some(s);
            break;
        }
        assert!(
            st.redialer_holds && st.answerer_holds,
            "one end reaped without the other at {s}s: {st:?}"
        );
        assert!(
            !st.paired && !st.redialer_to_answerer && !st.answerer_to_redialer,
            "the split must hold unpaired and silent both ways until the reap, at {s}s: {st:?}"
        );
    }
    assert_eq!(
        reaped_at,
        Some(dead),
        "both ends reap the other at the link-dead timeout"
    );

    initiate_handshake(&mut nodes, r, n).await;
    settle(&mut nodes).await;
    let st = observe(&mut nodes, r, n).await;
    cleanup_nodes(&mut nodes).await;
    assert!(
        st.converged(),
        "a fresh dial after both reaps converges: {st:?}"
    );
}
