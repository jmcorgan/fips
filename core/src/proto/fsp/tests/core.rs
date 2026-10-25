//! Tests for the pure FSP session decision core.

use crate::identity::Ipv6Address;
use crate::proto::fsp::core::{Fsp, FspAction, push_bounded_pending, should_apply_path_mtu};
use crate::testutil::make_node_addr;
use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

// ===== coords / MTU emit-policy =====

#[test]
fn plan_coords_required_lookup_gated_on_identity() {
    let fsp = Fsp::new();
    let dest = make_node_addr(5);
    assert_eq!(
        fsp.plan_coords_required_lookup(dest, true),
        vec![FspAction::InitiateLookup { dest }]
    );
    assert!(fsp.plan_coords_required_lookup(dest, false).is_empty());
}

#[test]
fn plan_path_broken_removes_an_unverified_entry_then_looks_it_up() {
    use crate::proto::fsp::quorum::QuorumVerdict;
    let fsp = Fsp::new();
    let dest = make_node_addr(6);
    let expected = vec![
        FspAction::InvalidateCoords { addr: dest },
        FspAction::InitiateLookup { dest },
    ];
    // The quorum is irrelevant to a hint: removed either way.
    for quorum in [QuorumVerdict::Below { distinct: 0 }, QuorumVerdict::Reached] {
        assert_eq!(fsp.plan_path_broken(dest, false, quorum), expected);
    }
}

#[test]
fn plan_path_broken_keeps_a_verified_entry_below_quorum_and_looks_it_up() {
    use crate::proto::fsp::quorum::QuorumVerdict;
    let fsp = Fsp::new();
    let dest = make_node_addr(6);
    assert_eq!(
        fsp.plan_path_broken(dest, true, QuorumVerdict::Below { distinct: 1 }),
        vec![FspAction::InitiateLookup { dest }]
    );
}

#[test]
fn plan_path_broken_demotes_a_verified_entry_at_quorum_then_looks_it_up() {
    use crate::proto::fsp::quorum::QuorumVerdict;
    let fsp = Fsp::new();
    let dest = make_node_addr(6);
    assert_eq!(
        fsp.plan_path_broken(dest, true, QuorumVerdict::Reached),
        vec![
            FspAction::DemoteCoords { addr: dest },
            FspAction::InitiateLookup { dest },
        ]
    );
}

#[test]
fn plan_path_mtu_tighten_emits_only_when_tighter() {
    let fsp = Fsp::new();
    let fa = Ipv6Address::from_node_addr(&make_node_addr(7));
    // No existing, or candidate tighter → emit.
    assert_eq!(
        fsp.plan_path_mtu_tighten(fa, None, 1400),
        vec![FspAction::TightenPathMtuLookup {
            fips_addr: fa,
            mtu: 1400
        }]
    );
    assert_eq!(
        fsp.plan_path_mtu_tighten(fa, Some(1500), 1400),
        vec![FspAction::TightenPathMtuLookup {
            fips_addr: fa,
            mtu: 1400
        }]
    );
    // Existing already tighter or equal → keep, emit nothing.
    assert!(fsp.plan_path_mtu_tighten(fa, Some(1300), 1400).is_empty());
    assert!(fsp.plan_path_mtu_tighten(fa, Some(1400), 1400).is_empty());
}

#[test]
fn should_apply_path_mtu_keeps_tighter() {
    assert!(should_apply_path_mtu(None, 1400)); // no existing → apply
    assert!(should_apply_path_mtu(Some(1500), 1400)); // candidate tighter → apply
    assert!(!should_apply_path_mtu(Some(1300), 1400)); // existing tighter → keep
    assert!(!should_apply_path_mtu(Some(1400), 1400)); // equal → keep
}

#[test]
fn push_bounded_pending_drops_oldest_at_capacity() {
    let mut q: VecDeque<Vec<u8>> = VecDeque::new();
    push_bounded_pending(&mut q, vec![1], 2);
    push_bounded_pending(&mut q, vec![2], 2);
    push_bounded_pending(&mut q, vec![3], 2); // drops [1]
    assert_eq!(q.len(), 2);
    assert_eq!(q.front(), Some(&vec![2]));
    assert_eq!(q.back(), Some(&vec![3]));
}
