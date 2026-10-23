//! Pacing of the outgoing-filter recompute that inbound FilterAnnounces
//! trigger.
//!
//! These tests use the P -- M -- C fixture from `bloom.rs`, where P is M's
//! parent and C is M's child.

use super::bloom::{M, deliver_filter, flip_fixture};
use super::spanning_tree::*;
use super::*;

/// A burst of accepted announces from one peer is stored at once but costs
/// one outgoing-filter recompute on the next tick, and that recompute uses
/// the newest stored filter.
#[tokio::test]
async fn test_bloom_a_burst_of_filter_announces_from_one_peer_costs_one_inbound_recompute_per_tick()
{
    let mut fx = flip_fixture(true).await;
    let (c, p) = (fx.c, fx.p);
    let markers: Vec<NodeAddr> = (0..50u8).map(|i| make_node_addr(0x20 + i)).collect();

    let r0 = fx.nodes[M].node.bloom_state.inbound_recomputes();
    for marker in &markers {
        // Checks M stored each one.
        deliver_filter(&mut fx, &[c, *marker]).await;
    }
    fx.nodes[M].node.check_bloom_state().await;
    let r1 = fx.nodes[M].node.bloom_state.inbound_recomputes();

    assert!(
        r1 - r0 <= 1,
        "50 announces from one peer must cost at most one recompute per tick, ran {}",
        r1 - r0
    );
    let sent = fx.nodes[M]
        .node
        .bloom_state
        .last_sent_filter(&p)
        .expect("M has sent a filter to P");
    assert!(
        sent.contains(&markers[49]),
        "the filter sent to P must carry the newest stored filter"
    );
    assert!(
        !sent.contains(&markers[0]),
        "the filter sent to P must not carry a superseded filter"
    );
    cleanup_nodes(&mut fx.nodes).await;
}
