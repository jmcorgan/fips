//! Tests for the sans-IO routing decision core.

use super::util::{MockPeer, MockRoutingView, make_coords, make_datagram_ref, make_next_hop};
use crate::proto::link::SessionDatagramRef;
use crate::proto::routing::RoutingSignalType;
use crate::proto::routing::{
    DropReason, RouteAction, RouteOutcome, Router, RoutingView, select_best_candidate,
};
use crate::testutil::make_node_addr;
use crate::{NodeAddr, TreeCoordinate};

/// Decode a forwarded byte buffer (which carries the leading msg_type byte)
/// back into a borrowed view so tests can inspect the re-encoded header.
fn decode_forward(bytes: &[u8]) -> SessionDatagramRef<'_> {
    SessionDatagramRef::decode(&bytes[1..]).expect("forwarded datagram re-decodes")
}

fn choose_candidate(
    rv: &MockRoutingView,
    dest: &NodeAddr,
    dest_coords: &TreeCoordinate,
    my_coords: &TreeCoordinate,
) -> Option<NodeAddr> {
    select_best_candidate(rv, dest, dest_coords, my_coords)
}

fn mock_peer(
    addr: u8,
    dest: NodeAddr,
    may_reach: bool,
    can_send: bool,
    link_cost: f64,
    coords: Option<&[u8]>,
) -> MockPeer {
    MockPeer {
        addr: make_node_addr(addr),
        reach: may_reach.then_some(dest).into_iter().collect(),
        can_send,
        link_cost,
        coords: coords.map(make_coords),
    }
}

/// A transit datagram that arrived already exhausted is dropped and charged
/// to `TtlExhausted`. A next hop is supplied so the drop is evidence of the
/// TTL gate rather than of an absent route.
#[test]
fn ttl_zero_drops_as_exhausted() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let dg = make_datagram_ref(0, make_node_addr(0x20));
    let rv = MockRoutingView::new(false);
    let out = router.route(
        &dg,
        &my_addr,
        false,
        Some(make_next_hop(make_node_addr(0x30), 1400)),
        &rv,
    );
    assert!(matches!(
        out,
        RouteOutcome::Drop {
            reason: DropReason::TtlExhausted
        }
    ));
}

/// Acceptance: a datagram addressed to this node with ttl=0 is delivered
/// locally. The TTL governs forwarding, not delivery to the addressed host,
/// so the gate sits after the local-delivery test — and `TtlExhausted` is
/// not charged for a delivered datagram.
#[test]
fn ttl_zero_to_self_delivers_local() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let dg = make_datagram_ref(0, my_addr);
    let rv = MockRoutingView::new(false);
    let out = router.route(&dg, &my_addr, false, None, &rv);
    assert!(
        matches!(out, RouteOutcome::DeliverLocal),
        "ttl=0 addressed to this node must still be delivered locally"
    );
}

/// Acceptance: a transit datagram arriving with ttl=1 would leave with ttl=0,
/// so it is dropped here rather than transmitted. A next hop is supplied, so
/// a `Forward` outcome would mean it had been put on the wire at ttl=0.
#[test]
fn ttl_one_transit_drops_before_forwarding() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let dg = make_datagram_ref(1, make_node_addr(0x20));
    let rv = MockRoutingView::new(false);
    let out = router.route(
        &dg,
        &my_addr,
        false,
        Some(make_next_hop(make_node_addr(0x30), 1400)),
        &rv,
    );
    assert!(
        matches!(
            out,
            RouteOutcome::Drop {
                reason: DropReason::TtlExhausted
            }
        ),
        "transit ttl=1 must be dropped as TTL-exhausted, not forwarded at ttl=0"
    );
}

/// Acceptance: the other side of the same boundary — a transit datagram
/// arriving with ttl=2 clears the gate and leaves with ttl=1.
#[test]
fn ttl_two_transit_forwards_at_one() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let nh_addr = make_node_addr(0x30);
    let dg = make_datagram_ref(2, make_node_addr(0x20));
    let rv = MockRoutingView::new(false);
    let out = router.route(
        &dg,
        &my_addr,
        false,
        Some(make_next_hop(nh_addr, 1400)),
        &rv,
    );
    match out {
        RouteOutcome::Forward { bytes, .. } => {
            assert_eq!(
                decode_forward(&bytes).ttl,
                1,
                "transit ttl=2 must leave with ttl=1"
            );
        }
        _ => panic!("expected Forward"),
    }
}

#[test]
fn destination_is_self_delivers_local() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let dg = make_datagram_ref(5, my_addr);
    let rv = MockRoutingView::new(false);
    // A next hop is irrelevant for local delivery; the shell would pass None.
    let out = router.route(&dg, &my_addr, false, None, &rv);
    assert!(matches!(out, RouteOutcome::DeliverLocal));
}

#[test]
fn transit_without_next_hop_is_no_route() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let dg = make_datagram_ref(5, make_node_addr(0x20));
    let rv = MockRoutingView::new(false);
    let out = router.route(&dg, &my_addr, false, None, &rv);
    assert!(matches!(out, RouteOutcome::NoRoute));
}

#[test]
fn forward_decrements_ttl_and_folds_link_mtu() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let nh_addr = make_node_addr(0x30);
    let dg = make_datagram_ref(5, make_node_addr(0x20));
    let rv = MockRoutingView::new(false);
    let out = router.route(
        &dg,
        &my_addr,
        false,
        Some(make_next_hop(nh_addr, 1400)),
        &rv,
    );
    match out {
        RouteOutcome::Forward {
            next_hop,
            bytes,
            outgoing_ce,
        } => {
            assert_eq!(next_hop, nh_addr);
            assert!(!outgoing_ce);
            let decoded = decode_forward(&bytes);
            assert_eq!(decoded.ttl, 4, "TTL decremented once");
            assert_eq!(decoded.path_mtu, 1400, "link MTU is the smaller bound");
        }
        _ => panic!("expected Forward"),
    }
}

#[test]
fn forward_keeps_smaller_datagram_path_mtu() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let nh_addr = make_node_addr(0x30);
    let mut dg = make_datagram_ref(5, make_node_addr(0x20));
    dg.path_mtu = 900; // datagram already bounded below the link MTU
    let rv = MockRoutingView::new(false);
    let out = router.route(
        &dg,
        &my_addr,
        false,
        Some(make_next_hop(nh_addr, 1400)),
        &rv,
    );
    match out {
        RouteOutcome::Forward { bytes, .. } => {
            let decoded = decode_forward(&bytes);
            assert_eq!(decoded.path_mtu, 900, "datagram MTU is the smaller bound");
        }
        _ => panic!("expected Forward"),
    }
}

#[test]
fn outgoing_ce_set_by_incoming_ce() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let nh_addr = make_node_addr(0x30);
    let dg = make_datagram_ref(5, make_node_addr(0x20));
    let rv = MockRoutingView::new(false); // not locally congested
    let out = router.route(&dg, &my_addr, true, Some(make_next_hop(nh_addr, 1400)), &rv);
    match out {
        RouteOutcome::Forward { outgoing_ce, .. } => assert!(outgoing_ce),
        _ => panic!("expected Forward"),
    }
}

#[test]
fn outgoing_ce_set_by_local_congestion() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let nh_addr = make_node_addr(0x30);
    let dg = make_datagram_ref(5, make_node_addr(0x20));
    let rv = MockRoutingView::new(true); // locally congested
    let out = router.route(
        &dg,
        &my_addr,
        false,
        Some(make_next_hop(nh_addr, 1400)),
        &rv,
    );
    match out {
        RouteOutcome::Forward { outgoing_ce, .. } => assert!(outgoing_ce),
        _ => panic!("expected Forward"),
    }
}

#[test]
fn outgoing_ce_clear_when_neither_signal() {
    let mut router = Router::new();
    let my_addr = make_node_addr(0x10);
    let nh_addr = make_node_addr(0x30);
    let dg = make_datagram_ref(5, make_node_addr(0x20));
    let rv = MockRoutingView::new(false);
    let out = router.route(
        &dg,
        &my_addr,
        false,
        Some(make_next_hop(nh_addr, 1400)),
        &rv,
    );
    match out {
        RouteOutcome::Forward { outgoing_ce, .. } => assert!(!outgoing_ce),
        _ => panic!("expected Forward"),
    }
}

#[test]
fn cached_coords_reads_the_view_table() {
    let target = make_node_addr(0x40);
    let rv = MockRoutingView {
        congested: false,
        coords: vec![(target, TreeCoordinate::root(target))],
        peers: Vec::new(),
    };
    assert!(rv.cached_coords(&target, 0).is_some());
    assert!(rv.cached_coords(&make_node_addr(0x41), 0).is_none());
}

#[test]
fn candidate_selection_is_independent_of_peer_enumeration_order() {
    let dest = make_node_addr(0x50);
    let root = 0x00;
    let my_coords = make_coords(&[0x10, root]);
    let dest_coords = make_coords(&[0x50, root]);
    let lower_addr = mock_peer(0x20, dest, true, true, 1.0, Some(&[root]));
    let higher_addr = mock_peer(0x30, dest, true, true, 1.0, Some(&[root]));

    let forward = MockRoutingView {
        peers: vec![lower_addr.clone(), higher_addr.clone()],
        ..MockRoutingView::new(false)
    };
    let reverse = MockRoutingView {
        peers: vec![higher_addr, lower_addr],
        ..MockRoutingView::new(false)
    };

    assert_eq!(
        choose_candidate(&forward, &dest, &dest_coords, &my_coords),
        Some(make_node_addr(0x20))
    );
    assert_eq!(
        choose_candidate(&reverse, &dest, &dest_coords, &my_coords),
        Some(make_node_addr(0x20))
    );
}

#[test]
fn candidate_selection_filters_bloom_unsendable_and_missing_coords() {
    let dest = make_node_addr(0x50);
    let root = 0x00;
    let my_coords = make_coords(&[0x10, root]);
    let dest_coords = make_coords(&[0x50, root]);
    let eligible = make_node_addr(0x60);
    let rv = MockRoutingView {
        peers: vec![
            mock_peer(0x01, dest, true, false, 0.0, Some(&[0x50, root])),
            mock_peer(0x02, dest, true, true, 0.0, None),
            mock_peer(0x03, dest, false, true, 0.0, Some(&[0x50, root])),
            mock_peer(0x60, dest, true, true, 10.0, Some(&[root])),
        ],
        ..MockRoutingView::new(false)
    };

    assert_eq!(
        choose_candidate(&rv, &dest, &dest_coords, &my_coords),
        Some(eligible)
    );
}

#[test]
fn candidate_must_be_strictly_closer_than_self() {
    let dest = make_node_addr(0x50);
    let root = 0x00;
    let my_coords = make_coords(&[0x10, root]);
    let dest_coords = make_coords(&[0x50, root]);
    let rv = MockRoutingView {
        peers: vec![
            // A sibling is exactly as far from dest as this node.
            mock_peer(0x20, dest, true, true, 1.0, Some(&[0x20, root])),
            // This descendant of a sibling is farther from dest.
            mock_peer(0x21, dest, true, true, 0.5, Some(&[0x21, 0x20, root])),
        ],
        ..MockRoutingView::new(false)
    };

    assert_eq!(choose_candidate(&rv, &dest, &dest_coords, &my_coords), None);
}

#[test]
fn candidate_ordering_is_cost_then_distance_then_address() {
    let dest = make_node_addr(0x50);
    let root = 0x00;
    let my_coords = make_coords(&[0x10, 0x11, root]);
    let dest_coords = make_coords(&[0x50, root]);
    let rv = MockRoutingView {
        peers: vec![
            // Lowest address loses because distance precedes address.
            mock_peer(0x01, dest, true, true, 1.0, Some(&[root])),
            // Closest peer loses because cost is the primary key.
            mock_peer(0x02, dest, true, true, 1.0, Some(&[0x50, root])),
            mock_peer(0x04, dest, true, true, 0.5, Some(&[root])),
            // Same cost and distance: lower address wins.
            mock_peer(0x03, dest, true, true, 0.5, Some(&[root])),
        ],
        ..MockRoutingView::new(false)
    };

    assert_eq!(
        choose_candidate(&rv, &dest, &dest_coords, &my_coords),
        Some(make_node_addr(0x03))
    );
}

/// Extract the error-PDU msg_type byte from an encoded routing-error action.
/// The action bytes are a SessionDatagram (leading link msg_type byte, then
/// the header); its payload is the error PDU, whose msg_type sits at offset 4
/// after the 4-byte FSP prefix.
fn error_pdu_type(action: &RouteAction) -> u8 {
    let RouteAction::SendError { bytes, .. } = action;
    let dg = SessionDatagramRef::decode(&bytes[1..]).expect("error datagram re-decodes");
    dg.payload[4]
}

#[test]
fn synth_uses_pathbroken_when_coords_cached() {
    let mut router = Router::new();
    let dest = make_node_addr(0x20);
    let source = make_node_addr(0x21);
    let my_addr = make_node_addr(0x10);
    let rv = MockRoutingView {
        congested: false,
        coords: vec![(dest, TreeCoordinate::root(dest))],
        peers: Vec::new(),
    };
    let action = router
        .synth_routing_error(&dest, &source, &my_addr, &rv, 0, 64)
        .expect("gate passes on first call");
    let RouteAction::SendError { toward, .. } = &action;
    assert_eq!(
        *toward, source,
        "error routes back toward the failed source"
    );
    assert_eq!(
        error_pdu_type(&action),
        RoutingSignalType::PathBroken.to_byte(),
        "cached coords select PathBroken",
    );
}

#[test]
fn synth_uses_coords_required_when_not_cached() {
    let mut router = Router::new();
    let dest = make_node_addr(0x20);
    let source = make_node_addr(0x21);
    let my_addr = make_node_addr(0x10);
    let rv = MockRoutingView::new(false); // empty coord table
    let action = router
        .synth_routing_error(&dest, &source, &my_addr, &rv, 0, 64)
        .expect("gate passes on first call");
    assert_eq!(
        error_pdu_type(&action),
        RoutingSignalType::CoordsRequired.to_byte(),
        "absent coords select CoordsRequired",
    );
}

#[test]
fn synth_rate_limit_gate_suppresses_second_call() {
    let mut router = Router::new();
    let dest = make_node_addr(0x20);
    let source = make_node_addr(0x21);
    let my_addr = make_node_addr(0x10);
    let rv = MockRoutingView::new(false);
    // First call for this destination passes the gate.
    assert!(
        router
            .synth_routing_error(&dest, &source, &my_addr, &rv, 0, 64)
            .is_some()
    );
    // An immediate second call for the same destination is within the
    // rate-limit window and is suppressed (no sleeps needed — the two calls
    // are microseconds apart, well under the 100 ms interval).
    assert!(
        router
            .synth_routing_error(&dest, &source, &my_addr, &rv, 0, 64)
            .is_none()
    );
    // A different destination is independent and still allowed.
    let other = make_node_addr(0x22);
    assert!(
        router
            .synth_routing_error(&other, &source, &my_addr, &rv, 0, 64)
            .is_some()
    );
}

/// Extract the bottleneck MTU (trailing u16 LE) from an MtuExceeded action's
/// PDU. Layout after the outer link byte + SessionDatagram header: FSP prefix
/// (4) + msg_type (1) + flags (1) + dest_addr (16) + reporter (16) + mtu (2).
fn mtu_exceeded_bottleneck(action: &RouteAction) -> u16 {
    let RouteAction::SendError { bytes, .. } = action;
    let dg = SessionDatagramRef::decode(&bytes[1..]).expect("error datagram re-decodes");
    let p = dg.payload;
    u16::from_le_bytes([p[38], p[39]])
}

#[test]
fn synth_mtu_exceeded_carries_bottleneck_and_targets_source() {
    let mut router = Router::new();
    let dest = make_node_addr(0x20);
    let source = make_node_addr(0x21);
    let my_addr = make_node_addr(0x10);
    let action = router
        .synth_mtu_exceeded(&dest, &source, &my_addr, 1280, 0, 64)
        .expect("gate passes on first call");
    let RouteAction::SendError { toward, .. } = &action;
    assert_eq!(
        *toward, source,
        "signal routes back toward the failed source"
    );
    assert_eq!(
        error_pdu_type(&action),
        RoutingSignalType::MtuExceeded.to_byte(),
        "PDU is an MtuExceeded signal",
    );
    assert_eq!(
        mtu_exceeded_bottleneck(&action),
        1280,
        "bottleneck MTU is carried verbatim",
    );
}

#[test]
fn synth_mtu_exceeded_rate_limit_gate_suppresses_second_call() {
    let mut router = Router::new();
    let dest = make_node_addr(0x20);
    let source = make_node_addr(0x21);
    let my_addr = make_node_addr(0x10);
    // First call for this destination passes the gate.
    assert!(
        router
            .synth_mtu_exceeded(&dest, &source, &my_addr, 1280, 0, 64)
            .is_some()
    );
    // Immediate second call for the same destination is suppressed.
    assert!(
        router
            .synth_mtu_exceeded(&dest, &source, &my_addr, 1280, 0, 64)
            .is_none()
    );
    // A different destination is independent and still allowed.
    let other = make_node_addr(0x22);
    assert!(
        router
            .synth_mtu_exceeded(&other, &source, &my_addr, 1280, 0, 64)
            .is_some()
    );
}
