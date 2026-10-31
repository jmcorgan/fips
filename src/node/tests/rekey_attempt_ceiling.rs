//! The ceiling on a link rekey attempt: a node must end a rekey attempt that
//! has not completed no later than one `REKEY_CHECK_INTERVAL` after
//! `HANDSHAKE_TIMEOUT` has passed since its first msg1, with
//! `HANDSHAKE_TIMEOUT` at most 30 s and `REKEY_CHECK_INTERVAL` at most 1 s
//! for this bound (FRC-1201, Sections 3.5 and 5.8). So no attempt runs past
//! 31 s, and no msg1 of it goes out after that.
//!
//! The peer is never driven, so nothing answers. A node given a longer
//! handshake timeout still ends its link rekey attempts by then.

use super::rekey_parity::{age_link, linked_pair, rekey_config, trigger_age};
use super::spanning_tree::{TestNode, cleanup_nodes};
use super::*;
use crate::proto::fmp::wire::{CommonPrefix, PHASE_MSG1};

/// The most a rekey attempt may run after its first msg1: the 30 s ceiling
/// on `HANDSHAKE_TIMEOUT` plus the 1 s ceiling on `REKEY_CHECK_INTERVAL`.
const ATTEMPT_CEILING_SECS: u64 = 31;

/// The rekey msg1s queued at `tn`, taking every packet off its queue.
fn msg1s(tn: &mut TestNode) -> usize {
    std::iter::from_fn(|| tn.packet_rx.try_recv().ok())
        .filter(|p| CommonPrefix::parse(&p.data).is_some_and(|c| c.phase == PHASE_MSG1))
        .count()
}

/// Start node 0's link rekey toward a silent node 1 and poll it once a
/// second for up to `secs`. Returns the second of the first poll after which
/// the attempt is no longer in flight, if any, and the seconds at which a
/// msg1 copy went out before then. The poll that ends an attempt starts no
/// other, so the first poll that finds none in flight is the one that ended
/// it; a later attempt, after its random back-off, is not counted.
async fn run_unanswered_rekey(config: Config, secs: u64) -> (Option<u64>, Vec<u64>) {
    let mut nodes = linked_pair(config, Config::new()).await;
    let peer = *nodes[1].node.node_addr();
    age_link(&mut nodes, 0, 1, trigger_age());
    let in_flight = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .get_peer(&peer)
            .is_some_and(|p| p.rekey_in_progress())
    };
    nodes[0].node.poll_link_rekeys().await;
    assert!(
        in_flight(&nodes) && msg1s(&mut nodes[1]) == 1,
        "control: the time trigger started a rekey and its msg1 went out"
    );
    let mut copies = Vec::new();
    let mut ended = None;
    for s in 1..=secs {
        crate::time::advance(Duration::from_secs(1));
        nodes[0].node.poll_link_rekeys().await;
        if msg1s(&mut nodes[1]) > 0 {
            copies.push(s);
        }
        if !in_flight(&nodes) {
            ended = Some(s);
            break;
        }
    }
    cleanup_nodes(&mut nodes).await;
    (ended, copies)
}

/// With a 60 s handshake timeout configured, the node's unanswered link
/// rekey has ended by 31 s after its first msg1, with no msg1 copy after
/// that.
#[tokio::test]
async fn a_link_rekey_attempt_ends_by_31_s_even_with_a_60_s_handshake_timeout_configured() {
    let mut config = rekey_config(60);
    config.node.rate_limit.handshake_timeout_secs = 60;
    let (ended, copies) = run_unanswered_rekey(config, ATTEMPT_CEILING_SECS).await;
    assert!(
        ended.is_some(),
        "with `node.rate_limit.handshake_timeout_secs` = 60 the link rekey attempt was still in \
         flight {ATTEMPT_CEILING_SECS} s after its first msg1, past the 31 s bound \
         (msg1 copies at {copies:?} s)"
    );
}

/// Healthy path, and the control that the attempt and its resends are
/// observed: at stock settings the attempt resends its msg1 and has ended by
/// 31 s.
#[tokio::test]
async fn at_stock_settings_a_link_rekey_attempt_resends_and_ends_by_31_s() {
    let (ended, copies) = run_unanswered_rekey(rekey_config(60), ATTEMPT_CEILING_SECS).await;
    assert!(!copies.is_empty(), "control: the attempt resent its msg1");
    assert!(
        ended.is_some(),
        "stock settings: the attempt ran past 31 s (msg1 copies at {copies:?} s)"
    );
}
