//! A restart met by a late rekey msg1 of the peer's previous run.
//!
//! Node D holds R's previous run on a link old enough to rekey. R
//! restarts, D dials it (and R dials D too, in half the cases), and R
//! answers D's dial. Once R's new peering is past the unheard floor (1 s),
//! D starts its own rekey of the old peering, then reads what R sent and
//! moves onto R's new run; only then does R read D's rekey msg1. Both ends
//! must be left on one session, in every placement of D: the smaller or the
//! larger node, the one that dialed the old link or not (a known defect,
//! with a control inside the floor).
//!
//! Setup checks are marked `precondition:`; the assertion of the behaviour
//! is marked `defect:`.

use super::super::rekey_parity::{deliver, linked_pair, rekey_config, trigger_age};
use super::super::spanning_tree::{TestNode, cleanup_nodes, initiate_handshake, restarted_node};
use super::super::*;
use super::{pump, settled, with_path};

/// Past the 1 s floor below which an unheard peering is not replaced.
const PAST_FLOOR: Duration = Duration::from_millis(1_100);

/// Every placement of D: (D the smaller node, D dialed the old link).
const PLACEMENTS: [(bool, bool); 4] = [(true, true), (true, false), (false, true), (false, false)];

/// The pair after D's rekey msg1 of R's previous run reaches the restarted
/// R, `wait` after R promoted on D's dial; `both` has R dial D too. Whether
/// the two ends are left on one working session.
async fn late_rekey(
    d_smaller: bool,
    d_dialed: bool,
    both: bool,
    wait: Duration,
) -> Result<(), String> {
    let (d, r) = if d_dialed { (0, 1) } else { (1, 0) };
    let mut nodes: Vec<TestNode> = loop {
        let mut nodes = linked_pair(
            with_path(rekey_config(60), false),
            with_path(rekey_config(60), false),
        )
        .await;
        if (nodes[d].node.node_addr() < nodes[r].node.node_addr()) == d_smaller {
            break nodes;
        }
        cleanup_nodes(&mut nodes).await;
    };
    let d_addr = *nodes[d].node.node_addr();
    let r_addr = *nodes[r].node.node_addr();
    let restarted = restarted_node(&nodes[r], with_path(rekey_config(60), false));
    drop(std::mem::replace(&mut nodes[r], restarted));
    nodes[d]
        .node
        .get_peer_mut(&r_addr)
        .expect("precondition: D holds R's previous run")
        .test_backdate_session_established(trigger_age());

    initiate_handshake(&mut nodes, d, r).await;
    if both {
        initiate_handshake(&mut nodes, r, d).await;
    }
    deliver(&mut nodes[r]).await;
    assert!(
        nodes[r].node.get_peer(&d_addr).is_some(),
        "precondition: the restarted R promoted on D's dial"
    );
    crate::time::advance(wait);
    nodes[d].node.poll_link_rekeys().await;
    assert!(
        nodes[d]
            .node
            .get_peer(&r_addr)
            .is_some_and(|p| p.rekey_in_progress()),
        "precondition: D started its rekey of R's previous run"
    );
    deliver(&mut nodes[d]).await;
    deliver(&mut nodes[r]).await;
    pump(&mut nodes).await;
    let out = settled(&mut nodes, d, r).await;
    cleanup_nodes(&mut nodes).await;
    out
}

/// The placements in which the pair is not left on one working session,
/// with what was seen, when R reads D's rekey msg1 `wait` after promoting.
async fn splits(wait: Duration) -> Vec<String> {
    let mut out = Vec::new();
    for both in [true, false] {
        for (d_smaller, d_dialed) in PLACEMENTS {
            if let Err(e) = late_rekey(d_smaller, d_dialed, both, wait).await {
                out.push(format!(
                    "D smaller {d_smaller}, D dialed {d_dialed}, R dials too {both}: {e}"
                ));
            }
        }
    }
    out
}

/// Past the unheard floor, the late rekey msg1 of R's previous run, read
/// by the restarted R, leaves one working session in every placement.
#[tokio::test]
#[ignore = "known defect: a rekey msg1 of the peer's previous run, read past the unheard floor, replaces the restarted node's peering while the peer has moved onto it"]
async fn a_rekey_msg1_of_the_peers_previous_run_read_late_by_the_restarted_node_leaves_one_session()
{
    let split = splits(PAST_FLOOR).await;
    assert!(split.is_empty(), "defect: {split:#?}");
}

/// Inside the unheard floor the same msg1 leaves one working session in
/// every placement: the assertion the pin makes can pass.
#[tokio::test]
async fn a_rekey_msg1_of_the_peers_previous_run_read_inside_the_unheard_floor_leaves_one_session() {
    let split = splits(Duration::ZERO).await;
    assert!(split.is_empty(), "defect: {split:#?}");
}
