//! Rekey timing against a stepped system clock.
//!
//! A host's wall clock can jump either way (an NTP correction, a manual set,
//! a resume from suspend), and a rekey schedule read from it would fire or
//! stall on the jump rather than on elapsed time. These tests step the wall
//! clock and advance the monotonic one independently, with the test hooks of
//! `crate::time`, and assert that only monotonic time moves a rekey.

use super::rekey_parity::{
    age_link, deliver, linked_pair, pass_cutover_delay, rekey_config, trigger_age,
};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;

/// A rekey msg1 is resent when the monotonic resend interval has passed, and
/// a step of the wall clock either way neither sends one early nor holds one
/// back. A resend is a msg1 queued at the peer.
#[tokio::test]
async fn host_wall_clock_step_changes_no_rekey_decision() {
    let mut nodes = linked_pair(rekey_config(60), crate::config::Config::new()).await;
    let peer = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    nodes[0].node.poll_link_rekeys().await;
    assert!(
        nodes[0].node.get_peer(&peer).unwrap().rekey_in_progress(),
        "precondition: node 0 started a rekey and its msg1 went out"
    );
    assert_eq!(
        queued(&mut nodes[1]),
        1,
        "precondition: the first msg1 is queued"
    );

    // An hour forward on the wall clock, no monotonic time: nothing is due.
    crate::time::step_wall(3_600_000);
    nodes[0].node.poll_link_rekeys().await;
    assert_eq!(
        queued(&mut nodes[1]),
        0,
        "a forward wall-clock step must not send a msg1 resend early"
    );

    // Two hours back on the wall clock, and the first rung of monotonic time:
    // the first resend is due.
    crate::time::step_wall(-7_200_000);
    crate::time::advance(Duration::from_secs(1));
    nodes[0].node.poll_link_rekeys().await;
    assert_eq!(
        queued(&mut nodes[1]),
        1,
        "a backward wall-clock step must not hold back a msg1 resend that is due"
    );
    cleanup_nodes(&mut nodes).await;
}

/// How many packets are queued at `tn`, taking them off its queue.
fn queued(tn: &mut TestNode) -> usize {
    std::iter::from_fn(|| tn.packet_rx.try_recv().ok()).count()
}

/// The rekey msg1 queued at `tn`, if any, taking every packet off its
/// queue.
fn queued_msg1(tn: &mut TestNode) -> Option<ReceivedPacket> {
    use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1};

    std::iter::from_fn(|| tn.packet_rx.try_recv().ok())
        .filter(|p| CommonPrefix::parse(&p.data).is_some_and(|c| c.phase == PHASE_MSG1))
        .last()
}

/// Poll `nodes[0]`'s link rekeys once a second for up to `limit` seconds,
/// and return the age `age` reads just before the poll that put its first
/// msg1 on the wire to node 1, with that msg1.
async fn first_msg1(
    nodes: &mut [TestNode],
    limit: u64,
    age: impl Fn(&TestNode) -> Duration,
) -> Option<(Duration, ReceivedPacket)> {
    for _ in 0..=limit {
        let at = age(&nodes[0]);
        nodes[0].node.poll_link_rekeys().await;
        if let Some(msg1) = queued_msg1(&mut nodes[1]) {
            return Some((at, msg1));
        }
        crate::time::advance(Duration::from_secs(1));
    }
    None
}

/// Send one heartbeat from `nodes[0]` to `peer`, so its send counter is past
/// a message trigger of 1, and drop what reaches node 1.
async fn count_one_frame(nodes: &mut [TestNode], peer: &NodeAddr) {
    nodes[0]
        .node
        .send_encrypted_link_message(
            peer,
            &[crate::proto::link::LinkMessageType::Heartbeat.to_byte()],
        )
        .await
        .expect("heartbeat send");
    let _ = queued_msg1(&mut nodes[1]);
}

/// A rekey this node starts on its message trigger waits until the link is
/// 31 s old and its session 31 s past the last cutover, one tick above the
/// 30 s below which a deployed peer takes a msg1 for a fresh dial rather
/// than a rekey.
#[tokio::test]
async fn a_message_triggered_link_rekey_waits_for_the_31_s_link_and_session_age_floors() {
    let floor = Duration::from_secs(31);
    let tick = Duration::from_secs(1);
    let mut cfg0 = rekey_config(3600);
    cfg0.node.rekey.after_messages = 1;
    let mut nodes = linked_pair(cfg0, rekey_config(3600)).await;
    let peer = *nodes[1].node.node_addr();
    let link_age = move |tn: &TestNode| {
        crate::peer::since(
            tn.node
                .get_peer(&peer)
                .unwrap()
                .link_established_at()
                .unwrap(),
        )
    };
    count_one_frame(&mut nodes, &peer).await;
    let (at, msg1) = first_msg1(&mut nodes, 40, link_age)
        .await
        .expect("a message-triggered rekey must start");
    assert!(
        at >= floor && at < floor + tick,
        "the first rekey must start at the first poll once the link is 31 s old, not at {at:?}"
    );

    // Node 1's leg answers, node 0 completes on the msg2 and node 1 takes
    // its msg3, node 0 cuts over after the delay, the two hear each other
    // under the new session, and node 0's next frame is counted.
    nodes[1].node.handle_msg1(msg1).await;
    deliver(&mut nodes[0]).await;
    deliver(&mut nodes[1]).await;
    pass_cutover_delay();
    nodes[0].node.poll_link_rekeys().await;
    deliver(&mut nodes[1]).await;
    deliver(&mut nodes[0]).await;
    assert!(
        nodes[0]
            .node
            .get_peer(&peer)
            .is_some_and(|p| !p.rekey_in_progress() && p.pending_new_session().is_none()),
        "setup: node 0 completed its rekey and cut over"
    );
    count_one_frame(&mut nodes, &peer).await;
    let since_cutover =
        move |tn: &TestNode| tn.node.get_peer(&peer).unwrap().since_cutover().unwrap();
    let (at, _) = first_msg1(&mut nodes, 40, since_cutover)
        .await
        .expect("the next message-triggered rekey must start");
    assert!(
        at >= floor && at < floor + tick,
        "the next rekey must start at the first poll 31 s after the cutover, not at {at:?}"
    );

    cleanup_nodes(&mut nodes).await;
}
