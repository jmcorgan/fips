//! What a FilterAnnounce sender puts on the wire, read at the receiver.
//!
//! These tests use the P -- M -- C fixture from `bloom.rs`, where P is M's
//! parent and C is M's child, and read what P stores for M after M sends.

use super::bloom::{
    FlipFixture, M, P, deliver_filter, flip_fixture, flip_fixture_with_configs, marker, sent_count,
};
use super::spanning_tree::*;
use super::*;
use crate::proto::bloom::{
    ACCEPT_FPR_CAP as V1_CAP, BloomFilter, DEFAULT_HASH_COUNT, FilterAnnounce,
};

/// The FilterAnnounce sequence P stores for M.
fn parent_seq(fx: &FlipFixture) -> u64 {
    fx.nodes[P]
        .node
        .get_peer(&fx.m)
        .expect("P has M as a peer")
        .filter_sequence()
}

/// Deliver `filter` to M from `from`, one sequence above what M stores for
/// that peer, and check M stored it.
async fn deliver_from(fx: &mut FlipFixture, from: NodeAddr, filter: &BloomFilter) {
    let seq = fx.nodes[M].node.get_peer(&from).unwrap().filter_sequence() + 1;
    let mut payload = FilterAnnounce::new(filter.clone(), seq).encode().unwrap();
    payload.remove(0); // strip msg_type byte
    fx.nodes[M]
        .node
        .handle_filter_announce(&from, &payload)
        .await;

    assert_eq!(
        fx.nodes[M].node.get_peer(&from).unwrap().inbound_filter(),
        Some(filter),
        "setup: M must store the delivered filter"
    );
}

/// Deliver to M, from P, an announce holding P and `addr`.
async fn deliver_from_parent(fx: &mut FlipFixture, addr: NodeAddr) {
    let p = fx.p;
    let mut filter = BloomFilter::new();
    filter.insert(&p);
    filter.insert(&addr);
    deliver_from(fx, p, &filter).await;
}

/// Run M's pending sends and deliver what they put on the wire.
async fn send_and_deliver(fx: &mut FlipFixture) {
    fx.nodes[M].node.send_pending_filter_announces().await;
    process_available_packets(&mut fx.nodes).await;
}

/// The sequences one peer receives advance by one per announce sent to that
/// peer, whatever was sent to other peers in between.
#[tokio::test]
async fn test_bloom_filter_announce_sequences_a_peer_receives_count_only_the_announces_sent_to_it()
{
    let mut fx = flip_fixture(true).await;
    let (c, p) = (fx.c, fx.p);

    deliver_filter(&mut fx, &[c, marker()]).await;
    send_and_deliver(&mut fx).await;
    let s0 = parent_seq(&fx);
    assert!(s0 > 0, "control: P must hold a filter from M");

    // P's announces change only M's filter to C, so each round sends one
    // announce, to C, and none to P.
    for i in 0..4u8 {
        deliver_from_parent(&mut fx, make_node_addr(0xc0 + i)).await;
        fx.nodes[M].node.flush_inbound_changes();
        assert!(
            !fx.nodes[M].node.bloom_state.needs_update(&p),
            "control: P's announce must not change M's filter to P"
        );
        let before = sent_count(&fx);
        send_and_deliver(&mut fx).await;
        assert_eq!(
            sent_count(&fx),
            before + 1,
            "control: M must send exactly one announce, to C"
        );
    }
    assert_eq!(
        parent_seq(&fx),
        s0,
        "control: P must receive nothing in between"
    );

    deliver_filter(&mut fx, &[c, marker(), make_node_addr(0xd0)]).await;
    send_and_deliver(&mut fx).await;
    let s1 = parent_seq(&fx);

    assert_eq!(
        s1,
        s0 + 1,
        "P's next sequence must follow its last one, not count announces sent to C"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// The floor a new peer's sequence starts from grows by at least 256 per
/// microsecond, so a re-established peer starts above everything it was
/// sent before.
#[test]
fn test_bloom_sequence_floor_rises_by_at_least_256_per_elapsed_microsecond() {
    let node = make_node();
    let before = node.seq_floor();
    let started = std::time::Instant::now();
    std::thread::sleep(std::time::Duration::from_millis(2));
    let elapsed = u64::try_from(started.elapsed().as_micros()).unwrap();
    let after = node.seq_floor();

    assert!(elapsed >= 2000, "setup: the sleep must last 2ms");
    assert!(
        after - before >= 256 * elapsed,
        "the floor rose by {} over {elapsed}us; it must rise by at least {}",
        after - before,
        256 * elapsed
    );
}

// ===== An outgoing filter above the v1 FPR cap =====

/// A filter with exactly `bits` bits set, none of them among the bits of M's
/// base filter, so the union M sends P has at least `bits + 1` bits set.
fn dense_filter(fx: &FlipFixture, bits: usize) -> BloomFilter {
    let base = fx.nodes[M].node.bloom_state.base_filter();
    let mut bytes = vec![0u8; base.as_bytes().len()];
    let mut left = bits;
    for (byte, &taken) in bytes.iter_mut().zip(base.as_bytes()) {
        for bit in 0..8 {
            let mask = 1u8 << bit;
            if left > 0 && taken & mask == 0 {
                *byte |= mask;
                left -= 1;
            }
        }
    }
    assert_eq!(
        left, 0,
        "setup: the base filter leaves room for {bits} bits"
    );
    let filter = BloomFilter::from_bytes(bytes, DEFAULT_HASH_COUNT).unwrap();
    assert_eq!(filter.count_ones(), bits);
    filter
}

/// The filter M would send P now, computed from M's stored inbound filters.
fn union_to_parent(fx: &FlipFixture) -> BloomFilter {
    let node = &fx.nodes[M].node;
    let peer_filters = node.peer_inbound_filters();
    node.bloom_state
        .compute_outgoing_filters(&[fx.p], &peer_filters)
        .remove(&fx.p)
        .expect("an outgoing filter for P")
}

/// Deliver C's `filter` to M and check it is accepted while the union M
/// would send P is above the v1 cap.
async fn deliver_over_cap(fx: &mut FlipFixture, filter: &BloomFilter) {
    let c = fx.c;
    deliver_from(fx, c, filter).await;
    let union = union_to_parent(fx);
    assert!(
        union.fpr() > V1_CAP,
        "setup: the union to P ({}) must be above the v1 cap",
        union.fpr()
    );
}

/// What P holds for M: the stored filter and its sequence.
fn parent_holds(fx: &FlipFixture) -> (Option<BloomFilter>, u64) {
    let peer = fx.nodes[P].node.get_peer(&fx.m).expect("P has M as a peer");
    (peer.inbound_filter().cloned(), peer.filter_sequence())
}

/// Configs for P, M and C with the given `max_inbound_fpr` at P and at M.
fn caps(parent: f64, middle: f64) -> Vec<crate::config::Config> {
    [parent, middle, V1_CAP]
        .into_iter()
        .map(|cap| {
            let mut config = crate::config::Config::new();
            config.node.bloom.max_inbound_fpr = cap;
            config
        })
        .collect()
}

/// A node sends a peer its outgoing filter whatever the filter's fill:
/// toward a receiver whose own cap admits the filter, the filter arrives
/// and is stored.
#[tokio::test]
async fn test_bloom_outgoing_filter_above_the_v1_cap_is_sent_and_stored_by_a_receiver_whose_cap_admits_it()
 {
    let mut fx = flip_fixture_with_configs(true, caps(0.30, V1_CAP)).await;
    let p = fx.p;
    let dense = dense_filter(&fx, 5937);
    deliver_over_cap(&mut fx, &dense).await;
    let union = union_to_parent(&fx);
    assert!(
        union.fpr() <= 0.30,
        "setup: P's own cap ({}) would accept the union",
        union.fpr()
    );

    let (_, seq_before) = parent_holds(&fx);
    let sent_before = sent_count(&fx);
    send_and_deliver(&mut fx).await;

    assert_eq!(
        sent_count(&fx),
        sent_before + 1,
        "M must send P its outgoing filter above the v1 cap"
    );
    let (held, seq) = parent_holds(&fx);
    assert_eq!(held, Some(union), "P must store the filter M sent");
    assert!(seq > seq_before, "P must store a new sequence for M");
    assert!(
        !fx.nodes[M].node.bloom_state.needs_update(&p),
        "the update to P must no longer be pending"
    );
    cleanup_nodes(&mut fx.nodes).await;
}

/// An outgoing filter above a receiver's cap is still sent and recorded as
/// the last filter sent; the receiver discards it and keeps the filter and
/// sequence it last accepted.
#[tokio::test]
async fn test_bloom_outgoing_filter_above_the_v1_cap_is_sent_and_recorded_while_a_default_cap_receiver_keeps_its_last_filter()
 {
    let mut fx = flip_fixture(true).await;
    let p = fx.p;
    let dense = dense_filter(&fx, 5937);
    deliver_over_cap(&mut fx, &dense).await;
    let union = union_to_parent(&fx);

    let holds_before = parent_holds(&fx);
    let sent_before = sent_count(&fx);
    let rejected_before = fx.nodes[P].node.metrics().bloom.fill_exceeded.get();
    send_and_deliver(&mut fx).await;

    assert_eq!(
        sent_count(&fx),
        sent_before + 1,
        "M must send P its outgoing filter whatever its fill"
    );
    let bloom = &fx.nodes[M].node.bloom_state;
    assert_eq!(
        bloom.last_sent_filter(&p),
        Some(&union),
        "M must record the filter it sent as the last sent to P"
    );
    assert!(
        !bloom.needs_update(&p),
        "the update to P must no longer be pending"
    );
    assert_eq!(
        fx.nodes[P].node.metrics().bloom.fill_exceeded.get(),
        rejected_before + 1,
        "P, at the default cap, must discard the filter"
    );
    assert_eq!(
        parent_holds(&fx),
        holds_before,
        "P must keep the filter and sequence it last accepted from M"
    );
    cleanup_nodes(&mut fx.nodes).await;
}
