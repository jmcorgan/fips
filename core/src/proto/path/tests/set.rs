//! Tests for the path set: identity by (transport, address), the limits,
//! eviction order, path identifiers and the address rules.

use super::*;
use crate::testutil::TestInstant;
use alloc::format;

/// The set the rules are tested on: instants of the test clock and no
/// driver state.
type PathSet = super::PathSet<TestInstant, ()>;

/// A path of [`PathSet`].
type PeerPath = super::PeerPath<TestInstant, ()>;

/// The instant `ms` milliseconds after the test clock's epoch.
fn at(ms: u64) -> TestInstant {
    TestInstant(ms)
}

/// The first local transport.
fn ta() -> TransportId {
    TransportId::new(1)
}

/// The second local transport.
fn tb() -> TransportId {
    TransportId::new(2)
}

fn addr(n: u32) -> TransportAddr {
    TransportAddr::from_string(&format!("10.0.0.{n}:2121"))
}

/// An identifier source that yields 1, 2, 3, ...
fn counter() -> impl FnMut() -> u32 {
    let mut next = 0;
    move || {
        next += 1;
        next
    }
}

/// Admit a new path and return its index, failing the test if it was not
/// added.
fn add(
    set: &mut PathSet,
    transport: TransportId,
    a: TransportAddr,
    ids: &mut impl FnMut() -> u32,
) -> usize {
    match set.admit(transport, a, Medium::Other, &mut *ids) {
        Ok(Admission::Added {
            index,
            evicted: None,
        }) => index,
        other => panic!("expected a plain add, got {other:?}"),
    }
}

/// Admit and return the evicted path, failing the test unless one was.
fn add_evicting(
    set: &mut PathSet,
    transport: TransportId,
    a: TransportAddr,
    ids: &mut impl FnMut() -> u32,
) -> PeerPath {
    match set.admit(transport, a, Medium::Other, &mut *ids) {
        Ok(Admission::Added {
            evicted: Some(p), ..
        }) => p,
        other => panic!("expected an eviction, got {other:?}"),
    }
}

fn count_on(set: &PathSet, transport: TransportId) -> usize {
    set.paths()
        .iter()
        .filter(|p| p.transport_id() == transport)
        .count()
}

#[test]
fn a_known_pair_returns_the_existing_path() {
    let mut ids = counter();
    let mut set = PathSet::new();
    let i = add(&mut set, ta(), addr(1), &mut ids);
    let id = set.get(i).unwrap().path_id();
    match set.admit(ta(), addr(1), Medium::Other, &mut ids) {
        Ok(Admission::Known(j)) => assert_eq!(j, i),
        other => panic!("expected the known path, got {other:?}"),
    }
    assert_eq!(set.len(), 1);
    assert_eq!(set.get(i).unwrap().path_id(), id, "identifier unchanged");
}

#[test]
fn two_addresses_on_one_transport_are_two_paths() {
    let mut ids = counter();
    let mut set = PathSet::new();
    let i = add(&mut set, ta(), addr(1), &mut ids);
    let j = add(&mut set, ta(), addr(2), &mut ids);
    assert_ne!(i, j);
    assert_eq!(set.len(), 2);
    assert_eq!(set.find(ta(), &addr(1)), Some(i));
    assert_eq!(set.find(ta(), &addr(2)), Some(j));
    // The same address on another transport is a third path.
    let k = add(&mut set, tb(), addr(1), &mut ids);
    assert_eq!(set.find(tb(), &addr(1)), Some(k));
    assert_eq!(set.len(), 3);
}

#[test]
fn a_new_path_is_admitted_probing_and_not_acked_and_does_not_become_active() {
    let mut ids = counter();
    let mut set = PathSet::new();
    let i = add(&mut set, ta(), addr(1), &mut ids);
    let p = set.get(i).unwrap();
    assert_eq!(p.state(), PathState::Probing);
    assert!(!p.acked());
    assert_eq!(p.peer_id(), None);
    assert_eq!(set.active_index(), None);
}

#[test]
fn a_fifth_path_on_one_transport_is_refused_when_nothing_is_evictable() {
    let mut ids = counter();
    let mut set = PathSet::new();
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        add(&mut set, ta(), addr(n), &mut ids);
    }
    assert_eq!(
        set.admit(ta(), addr(99), Medium::Other, &mut ids)
            .unwrap_err(),
        PathRefused::TransportFull
    );
    assert_eq!(set.len(), PATH_MAX_PER_TRANSPORT);
    // Another transport still has room.
    add(&mut set, tb(), addr(99), &mut ids);
}

#[test]
fn a_ninth_path_to_the_peer_is_refused_when_nothing_is_evictable() {
    let mut ids = counter();
    let mut set = PathSet::new();
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        add(&mut set, ta(), addr(n), &mut ids);
        add(&mut set, tb(), addr(n), &mut ids);
    }
    assert_eq!(set.len(), PATH_MAX_PER_PEER);
    let c = TransportId::new(3);
    assert_eq!(
        set.admit(c, addr(99), Medium::Other, &mut ids).unwrap_err(),
        PathRefused::PeerFull
    );
    assert_eq!(set.len(), PATH_MAX_PER_PEER);
}

#[test]
fn a_ble_binding_holds_one_path_to_a_peer() {
    let mut ids = counter();
    let mut set = PathSet::new();
    let first = set
        .admit(ta(), addr(1), Medium::Ble, &mut ids)
        .expect("the binding's first path is admitted")
        .index();
    set.transition(first, PathState::Live, at(0));
    assert_eq!(
        set.admit(ta(), addr(2), Medium::Ble, &mut ids).unwrap_err(),
        PathRefused::TransportFull,
        "a second address on the same BLE binding is refused"
    );
    assert!(matches!(
        set.admit(ta(), addr(1), Medium::Ble, &mut ids),
        Ok(Admission::Known(i)) if i == first
    ));
    assert_eq!(set.len(), 1);
    // The same transport counted as another kind would take the second.
    add(&mut set, ta(), addr(2), &mut ids);
}

#[test]
fn two_ble_bindings_hold_a_path_each() {
    let mut ids = counter();
    let mut set = PathSet::new();
    set.admit(ta(), addr(1), Medium::Ble, &mut ids)
        .expect("the first binding's path");
    set.admit(tb(), addr(2), Medium::Ble, &mut ids)
        .expect("a second BLE binding holds a path of its own");
    assert_eq!(set.len(), 2);
}

#[test]
fn a_dead_ble_path_makes_room_for_its_replacement() {
    let mut ids = counter();
    let mut set = PathSet::new();
    let old = set
        .admit(ta(), addr(1), Medium::Ble, &mut ids)
        .unwrap()
        .index();
    set.transition(old, PathState::Dead, at(0));
    match set.admit(ta(), addr(2), Medium::Ble, &mut ids) {
        Ok(Admission::Added {
            evicted: Some(p), ..
        }) => assert_eq!(p.addr(), &addr(1)),
        other => panic!("expected the Dead path to be evicted, got {other:?}"),
    }
    assert_eq!(set.len(), 1);
    assert!(set.find(ta(), &addr(2)).is_some());
}

#[test]
fn a_dead_active_ble_path_is_not_discarded_for_another() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert_eq!(
        set.rebind(ta(), addr(1), Medium::Ble, &mut ids).0,
        Rebind::Switched
    );
    set.transition(set.active_index().unwrap(), PathState::Dead, at(0));
    assert_eq!(
        set.rebind(ta(), addr(2), Medium::Ble, &mut ids).0,
        Rebind::Refused
    );
    assert_eq!(set.find(ta(), &addr(2)), None, "the binding is full");
    assert_eq!(set.active().unwrap().addr(), &addr(1));
}

#[test]
fn dead_paths_count_toward_the_per_transport_limit() {
    let now = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        let i = add(&mut set, ta(), addr(n), &mut ids);
        set.transition(i, PathState::Dead, now);
    }
    // Four Dead paths fill the transport: the fifth replaces one rather
    // than being held beside them.
    add_evicting(&mut set, ta(), addr(99), &mut ids);
    assert_eq!(count_on(&set, ta()), PATH_MAX_PER_TRANSPORT);
}

#[test]
fn dead_paths_count_toward_the_per_peer_limit() {
    let now = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        add(&mut set, ta(), addr(n), &mut ids);
        let i = add(&mut set, tb(), addr(n), &mut ids);
        set.transition(i, PathState::Dead, now);
    }
    let c = TransportId::new(3);
    let evicted = add_evicting(&mut set, c, addr(99), &mut ids);
    assert_eq!(evicted.state(), PathState::Dead);
    assert_eq!(set.len(), PATH_MAX_PER_PEER);
}

#[test]
fn a_never_acked_dead_path_is_evicted_before_an_acked_one() {
    let t0 = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    let live = add(&mut set, ta(), addr(0), &mut ids);
    set.transition(live, PathState::Live, t0);
    let acked = add(&mut set, ta(), addr(1), &mut ids);
    set.mark_acked(acked);
    // The acked one has been Dead longer, and still goes second.
    set.transition(acked, PathState::Dead, t0);
    let unacked = add(&mut set, ta(), addr(2), &mut ids);
    set.transition(unacked, PathState::Dead, at(5000));
    add(&mut set, ta(), addr(3), &mut ids);

    let evicted = add_evicting(&mut set, ta(), addr(4), &mut ids);
    assert_eq!(evicted.addr(), &addr(2));
    assert!(!evicted.acked());
    let evicted = add_evicting(&mut set, ta(), addr(5), &mut ids);
    assert_eq!(evicted.addr(), &addr(1), "then the acked Dead path");
}

#[test]
fn among_acked_dead_paths_the_one_dead_longest_is_evicted() {
    let t0 = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    let live = add(&mut set, ta(), addr(0), &mut ids);
    set.transition(live, PathState::Live, t0);
    for (n, secs) in [(1, 30), (2, 10), (3, 20)] {
        let i = add(&mut set, ta(), addr(n), &mut ids);
        set.mark_acked(i);
        set.transition(i, PathState::Dead, at(secs * 1000));
    }
    let evicted = add_evicting(&mut set, ta(), addr(9), &mut ids);
    assert_eq!(evicted.addr(), &addr(2), "Dead since t0+10s, the longest");
}

#[test]
fn a_dead_path_keeps_its_first_dead_time_when_marked_dead_again() {
    let t0 = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    let i = add(&mut set, ta(), addr(1), &mut ids);
    set.transition(i, PathState::Dead, t0);
    set.transition(i, PathState::Dead, at(9000));
    assert_eq!(set.get(i).unwrap().dead_since(), Some(t0));
    set.transition(i, PathState::Probing, at(10000));
    assert_eq!(set.get(i).unwrap().dead_since(), None);
}

#[test]
fn a_per_transport_overflow_is_refused_when_the_only_dead_path_is_on_another_transport() {
    let now = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        let i = add(&mut set, ta(), addr(n), &mut ids);
        set.transition(i, PathState::Live, now);
    }
    let other = add(&mut set, tb(), addr(50), &mut ids);
    set.transition(other, PathState::Dead, now);

    assert_eq!(
        set.admit(ta(), addr(99), Medium::Other, &mut ids)
            .unwrap_err(),
        PathRefused::TransportFull
    );
    assert_eq!(
        set.find(tb(), &addr(50))
            .map(|i| set.get(i).unwrap().state()),
        Some(PathState::Dead),
        "the other transport's Dead path does not count toward the first transport's limit and survives"
    );
    assert_eq!(set.len(), PATH_MAX_PER_TRANSPORT + 1);
}

#[test]
fn with_both_limits_full_the_evicted_path_is_on_the_new_paths_transport() {
    let t0 = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        let i = add(&mut set, ta(), addr(n), &mut ids);
        set.transition(i, PathState::Live, t0);
        let j = add(&mut set, tb(), addr(n), &mut ids);
        set.transition(j, PathState::Live, t0);
    }
    // An older, never-acked Dead path on the second transport would win on order alone.
    let b_dead = set.find(tb(), &addr(0)).unwrap();
    set.transition(b_dead, PathState::Dead, t0);
    let a_dead = set.find(ta(), &addr(3)).unwrap();
    set.mark_acked(a_dead);
    set.transition(a_dead, PathState::Dead, at(60000));

    let evicted = add_evicting(&mut set, ta(), addr(99), &mut ids);
    assert_eq!(evicted.transport_id(), ta());
    assert_eq!(evicted.addr(), &addr(3));
    assert_eq!(count_on(&set, ta()), PATH_MAX_PER_TRANSPORT);
    assert_eq!(set.len(), PATH_MAX_PER_PEER);
    assert!(
        set.find(tb(), &addr(0)).is_some(),
        "the second transport's Dead path survives"
    );
}

#[test]
fn the_last_acked_dead_path_is_kept_while_no_path_is_live_and_evictable_once_one_is() {
    let now = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    let last = add(&mut set, ta(), addr(0), &mut ids);
    set.mark_acked(last);
    set.transition(last, PathState::Dead, now);
    for n in 1..PATH_MAX_PER_TRANSPORT as u32 {
        add(&mut set, ta(), addr(n), &mut ids);
    }
    assert_eq!(
        set.admit(ta(), addr(99), Medium::Other, &mut ids)
            .unwrap_err(),
        PathRefused::TransportFull,
        "the link's last acked Dead path is not discarded while nothing is Live"
    );

    let probing = set.find(ta(), &addr(1)).unwrap();
    set.transition(probing, PathState::Live, now);
    let evicted = add_evicting(&mut set, ta(), addr(99), &mut ids);
    assert_eq!(evicted.addr(), &addr(0));
}

#[test]
fn with_two_acked_dead_paths_and_none_live_the_longer_dead_one_may_go() {
    let mut ids = counter();
    let mut set = PathSet::new();
    for (n, secs) in [(0, 5), (1, 1)] {
        let i = add(&mut set, ta(), addr(n), &mut ids);
        set.mark_acked(i);
        set.transition(i, PathState::Dead, at(secs * 1000));
    }
    add(&mut set, ta(), addr(2), &mut ids);
    add(&mut set, ta(), addr(3), &mut ids);

    let evicted = add_evicting(&mut set, ta(), addr(98), &mut ids);
    assert_eq!(evicted.addr(), &addr(1));
    // Now addr(0) is the last acked Dead path, and nothing is Live.
    assert_eq!(
        set.admit(ta(), addr(99), Medium::Other, &mut ids)
            .unwrap_err(),
        PathRefused::TransportFull
    );
}

#[test]
fn the_active_path_is_never_evicted_and_stays_active_after_an_eviction() {
    let t0 = at(0);
    let mut ids = counter();
    let mut set = PathSet::new();
    let first = add(&mut set, ta(), addr(0), &mut ids);
    set.mark_acked(first);
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    let active_id = set.active().unwrap().path_id();
    // The active path goes Dead, longest of all; another is Live.
    set.transition(set.active_index().unwrap(), PathState::Dead, t0);
    set.transition(first, PathState::Dead, at(1000));
    let live = add(&mut set, ta(), addr(2), &mut ids);
    set.transition(live, PathState::Live, t0);
    add(&mut set, ta(), addr(3), &mut ids);

    let evicted = add_evicting(&mut set, ta(), addr(4), &mut ids);
    assert_eq!(evicted.addr(), &addr(0), "the active path is skipped");
    assert_eq!(set.active().unwrap().path_id(), active_id);
    assert_eq!(set.active().unwrap().addr(), &addr(1));
}

#[test]
fn discarding_the_active_path_leaves_the_set_with_none() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    add(&mut set, tb(), addr(2), &mut ids);
    let gone = set.discard(0).expect("the active path is held");
    assert_eq!(gone.addr(), &addr(1));
    assert_eq!(set.active_index(), None);
    assert!(set.active().is_none());
    assert_eq!(set.len(), 1);
    assert_eq!(set.get(0).unwrap().addr(), &addr(2));
    assert!(set.discard(1).is_none(), "no path at that index");
    assert_eq!(set.len(), 1);
}

#[test]
fn discarding_a_path_keeps_the_active_index_on_its_path() {
    let mut ids = counter();
    let mut set = PathSet::new();
    add(&mut set, ta(), addr(0), &mut ids);
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    add(&mut set, ta(), addr(2), &mut ids);
    assert_eq!(set.active_index(), Some(1));
    // A path before the active one: the index moves down with its path.
    assert_eq!(set.discard(0).unwrap().addr(), &addr(0));
    assert_eq!(set.active_index(), Some(0));
    assert_eq!(set.active().unwrap().addr(), &addr(1));
    // A path after it: the index stays.
    assert_eq!(set.discard(1).unwrap().addr(), &addr(2));
    assert_eq!(set.active_index(), Some(0));
    assert_eq!(set.active().unwrap().addr(), &addr(1));
}

#[test]
fn activating_makes_an_acked_path_active_and_refuses_one_never_acked() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    add(&mut set, tb(), addr(2), &mut ids);
    add(&mut set, tb(), addr(3), &mut ids);
    // A Probing path never acked does not carry the link.
    assert!(!set.activate(1));
    assert_eq!(set.active_index(), Some(0));
    // Acked, even once Dead, it may.
    set.mark_acked(2);
    set.transition(2, PathState::Dead, at(5));
    assert!(set.activate(2));
    assert_eq!(set.active().unwrap().addr(), &addr(3));
    assert!(set.activate(0));
    assert_eq!(set.active_index(), Some(0));
    // No path at the index: nothing changes.
    assert!(!set.activate(3));
    assert_eq!(set.active_index(), Some(0));
}

#[test]
fn path_ids_are_never_zero_and_never_repeat_in_the_set() {
    let mut draws = [0u32, 7, 0, 7, 7, 9].into_iter();
    let mut ids = move || draws.next().expect("generator exhausted");
    let mut set = PathSet::new();
    let i = add(&mut set, ta(), addr(1), &mut ids);
    let j = add(&mut set, ta(), addr(2), &mut ids);
    assert_eq!(set.get(i).unwrap().path_id(), 7, "0 is skipped");
    assert_eq!(
        set.get(j).unwrap().path_id(),
        9,
        "0 and the duplicate 7 are skipped"
    );
}

#[test]
fn a_peer_id_of_zero_is_not_learned() {
    let mut ids = counter();
    let mut set = PathSet::new();
    let i = add(&mut set, ta(), addr(1), &mut ids);
    assert!(!set.learn_peer(i, 0));
    assert_eq!(set.get(i).unwrap().peer_id(), None);
    assert!(set.learn_peer(i, 0xdead_beef));
    assert_eq!(set.get(i).unwrap().peer_id(), Some(0xdead_beef));
}

#[test]
fn a_path_is_found_by_the_peers_identifier_on_its_transport_only() {
    let mut ids = counter();
    let mut set = PathSet::new();
    let a = add(&mut set, ta(), addr(1), &mut ids);
    let b = add(&mut set, tb(), addr(1), &mut ids);
    assert!(set.learn_peer(a, 42));
    assert!(set.learn_peer(b, 43));
    assert_eq!(set.find_by_peer(ta(), 42), Some(a));
    assert_eq!(set.find_by_peer(tb(), 43), Some(b));
    assert_eq!(set.find_by_peer(tb(), 42), None);
}

#[test]
fn the_original_path_is_bound_live_acked_and_active() {
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(1), counter()).is_ok());
    let p = set.active().unwrap();
    assert_eq!(p.state(), PathState::Live);
    assert!(p.acked());
    assert_ne!(p.path_id(), 0);
    assert_eq!((p.transport_id(), p.addr()), (ta(), &addr(1)));
}

#[test]
fn a_single_path_roams_its_address_inside_its_transport() {
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(1), counter()).is_ok());
    let roam = set.roam(ta(), addr(2), counter());
    assert_eq!(
        roam,
        Roam::Roamed {
            from: (ta(), addr(1))
        }
    );
    assert!(roam.changed());
    assert_eq!(roam.left(), Some((ta(), addr(1))), "the pair the peer left");
    assert_eq!(set.active().unwrap().addr(), &addr(2));
    assert_eq!(
        set.roam(ta(), addr(2), counter()),
        Roam::Unmoved,
        "same address: nothing changed"
    );
    assert_eq!(
        set.roam(tb(), addr(3), counter()),
        Roam::Unmoved,
        "another transport moves nothing"
    );
    assert_eq!(set.active().unwrap().transport_id(), ta());
    assert_eq!(set.active().unwrap().addr(), &addr(2));
}

#[test]
fn with_two_paths_a_frame_from_a_new_address_moves_nothing() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    add(&mut set, tb(), addr(5), &mut ids);
    assert_eq!(set.roam(ta(), addr(2), &mut ids), Roam::Unmoved);
    assert_eq!(set.roam(tb(), addr(6), &mut ids), Roam::Unmoved);
    assert_eq!(set.active().unwrap().addr(), &addr(1));
    assert!(set.find(tb(), &addr(5)).is_some());
    assert!(set.find(tb(), &addr(6)).is_none());
}

#[test]
fn rebind_with_no_path_binds_the_original_and_onto_the_active_pair_is_unchanged() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert_eq!(
        set.rebind(ta(), addr(1), Medium::Other, &mut ids).0,
        Rebind::Switched
    );
    let p = set.active().unwrap();
    assert_eq!((p.transport_id(), p.addr()), (ta(), &addr(1)));
    assert_eq!(p.state(), PathState::Live);
    assert!(p.acked());
    assert_eq!(
        set.rebind(ta(), addr(1), Medium::Other, &mut ids).0,
        Rebind::Unchanged,
        "already there"
    );
    assert_eq!(set.len(), 1);
}

#[test]
fn rebind_onto_a_pair_not_held_admits_it_probing_and_is_refused() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    let active_id = set.active().unwrap().path_id();

    assert_eq!(
        set.rebind(tb(), addr(2), Medium::Other, &mut ids).0,
        Rebind::Refused
    );
    assert_eq!(set.len(), 2, "the new pair is a path of its own");
    let new = set.get(set.find(tb(), &addr(2)).unwrap()).unwrap();
    assert_eq!(new.state(), PathState::Probing);
    assert!(!new.acked());
    assert_ne!(new.path_id(), active_id, "with an identifier of its own");
    let active = set.active().unwrap();
    assert_eq!(active.path_id(), active_id, "the active path is untouched");
    assert_eq!((active.transport_id(), active.addr()), (ta(), &addr(1)));
}

#[test]
fn rebind_to_a_held_pair_makes_that_path_active() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    let other = add(&mut set, tb(), addr(2), &mut ids);
    set.mark_acked(other);
    assert_eq!(
        set.rebind(tb(), addr(2), Medium::Other, &mut ids).0,
        Rebind::Switched
    );
    assert_eq!(set.active_index(), Some(other));
    assert_eq!(set.len(), 2);
}

/// A held pair carries the link only once one of our probes on it has been
/// answered: until then a rebind onto it is refused and the active path
/// stays where it is.
#[test]
fn rebind_to_a_held_unacked_pair_is_refused_until_it_is_acked() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    let original = set.active_index();
    let other = add(&mut set, tb(), addr(2), &mut ids);
    assert_eq!(
        set.rebind(tb(), addr(2), Medium::Other, &mut ids).0,
        Rebind::Refused
    );
    assert_eq!(set.active_index(), original);
    assert_eq!(
        set.len(),
        2,
        "the held pair is neither dropped nor added again"
    );
    set.mark_acked(other);
    assert_eq!(
        set.rebind(tb(), addr(2), Medium::Other, &mut ids).0,
        Rebind::Switched
    );
    assert_eq!(set.active_index(), Some(other));
}

#[test]
fn rebind_onto_a_full_transport_is_refused() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(0), &mut ids).is_ok());
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        add(&mut set, tb(), addr(10 + n), &mut ids);
    }
    assert_eq!(
        set.rebind(tb(), addr(99), Medium::Other, &mut ids).0,
        Rebind::Refused
    );
    assert_eq!(set.active().unwrap().transport_id(), ta());
    assert_eq!(count_on(&set, tb()), PATH_MAX_PER_TRANSPORT);
    assert_eq!(
        set.find(tb(), &addr(99)),
        None,
        "the refused pair is not held"
    );
}

/// A peer with no path is bound by its first authentic frame: the roaming
/// rule binds the original path itself and says so.
#[test]
fn a_set_with_no_path_is_bound_by_the_first_roam() {
    let mut set = PathSet::new();
    assert_eq!(set.roam(ta(), addr(1), counter()), Roam::Bound);
    let p = set.active().unwrap();
    assert_eq!((p.transport_id(), p.addr()), (ta(), &addr(1)));
    assert_eq!(p.state(), PathState::Live);
    assert!(p.acked());
}

/// A single path that is not active roams like the active one, but the rule
/// reports it by index, for the caller to release that path's driver slot,
/// and names no pair the peer left.
#[test]
fn a_roam_of_a_single_path_that_is_not_active_is_reported_as_standby() {
    let mut ids = counter();
    let mut set = PathSet::new();
    let i = add(&mut set, ta(), addr(1), &mut ids);
    assert_eq!(set.active_index(), None);
    let roam = set.roam(ta(), addr(2), &mut ids);
    assert_eq!(roam, Roam::Standby { index: i });
    assert!(!roam.changed());
    assert_eq!(roam.left(), None);
    assert_eq!(set.get(i).unwrap().addr(), &addr(2));
    assert_eq!(set.active_index(), None);
}

/// A rebind that admits a new pair into a full transport hands the Dead
/// path it discarded back to the caller instead of dropping it.
#[test]
fn a_rebind_hands_back_the_dead_path_it_evicted_to_admit_a_pair() {
    let mut ids = counter();
    let mut set = PathSet::new();
    assert!(set.bind_original(ta(), addr(0), &mut ids).is_ok());
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        let i = add(&mut set, tb(), addr(10 + n), &mut ids);
        set.transition(i, PathState::Dead, at(u64::from(n)));
    }
    let (result, evicted) = set.rebind(tb(), addr(99), Medium::Other, &mut ids);
    assert_eq!(result, Rebind::Refused);
    let evicted = evicted.expect("the Dead path discarded for the pair");
    assert_eq!(evicted.transport_id(), tb());
    assert_eq!(evicted.addr(), &addr(10), "the one Dead longest");
    assert!(set.find(tb(), &addr(99)).is_some());
}

/// With no active path, a rebind binds the pair as the original path and
/// hands back the Dead path discarded to make room for it.
#[test]
fn a_rebind_with_no_active_path_hands_back_the_dead_path_it_evicted_to_bind() {
    let mut ids = counter();
    let mut set = PathSet::new();
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        let i = add(&mut set, ta(), addr(n), &mut ids);
        set.transition(i, PathState::Dead, at(u64::from(n)));
    }
    let (result, evicted) = set.rebind(ta(), addr(99), Medium::Other, &mut ids);
    assert_eq!(result, Rebind::Switched);
    assert_eq!(
        evicted
            .expect("the Dead path discarded for the original")
            .addr(),
        &addr(0)
    );
    assert_eq!(set.active().unwrap().addr(), &addr(99));
}

std::thread_local! {
    /// Driver slots dropped on this test's thread.
    static SLOT_DROPS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// A driver slot that counts its drops, standing in for one whose drop
/// closes a socket.
#[derive(Debug, Default)]
struct CountedSlot;

impl Drop for CountedSlot {
    fn drop(&mut self) {
        SLOT_DROPS.with(|d| d.set(d.get() + 1));
    }
}

/// Driver slots dropped on this thread so far.
fn slot_drops() -> usize {
    SLOT_DROPS.with(|d| d.get())
}

/// The set never drops a path's driver slot itself: every path a rule
/// discards (an eviction by `admit`, by `rebind`'s admission, by `rebind`'s
/// bind of an original path) and every path a refused or moved request
/// leaves behind stays with the set or comes back to the caller, so the
/// host decides when a slot such as a connected socket closes.
#[test]
fn no_rule_drops_a_driver_slot_it_does_not_hand_back() {
    let mut ids = counter();
    let mut set = super::PathSet::<TestInstant, CountedSlot>::new();
    let mut handed = alloc::vec::Vec::new();

    // A rebind with no active path binds the original, evicting a Dead path.
    for n in 0..PATH_MAX_PER_TRANSPORT as u32 {
        let i = set
            .admit(ta(), addr(n), Medium::Other, &mut ids)
            .unwrap()
            .index();
        set.transition(i, PathState::Dead, at(u64::from(n)));
    }
    let (result, evicted) = set.rebind(ta(), addr(90), Medium::Other, &mut ids);
    assert_eq!(result, Rebind::Switched);
    handed.extend(evicted);
    // A rebind's admission onto a full transport evicts another.
    let (result, evicted) = set.rebind(ta(), addr(91), Medium::Other, &mut ids);
    assert_eq!(result, Rebind::Refused);
    handed.extend(evicted);
    // A plain admission evicts the third and the fourth.
    for n in [92, 93] {
        match set.admit(ta(), addr(n), Medium::Other, &mut ids) {
            Ok(Admission::Added { evicted, .. }) => handed.extend(evicted),
            other => panic!("expected an admission, got {other:?}"),
        }
    }
    // A refusal and a roam that moves nothing keep every path.
    assert!(set.admit(ta(), addr(94), Medium::Other, &mut ids).is_err());
    assert_eq!(set.roam(ta(), addr(95), &mut ids), Roam::Unmoved);
    assert_eq!(slot_drops(), 0, "the set dropped no slot itself");
    assert_eq!(handed.len(), 4, "the four Dead paths came back");

    // A single path that is not active roams: its slot stays on the path.
    let mut single = super::PathSet::<TestInstant, CountedSlot>::new();
    single
        .admit(tb(), addr(1), Medium::Other, &mut ids)
        .unwrap();
    assert_eq!(
        single.roam(tb(), addr(2), &mut ids),
        Roam::Standby { index: 0 }
    );
    // A first roam binds a fresh set's original path.
    let mut fresh = super::PathSet::<TestInstant, CountedSlot>::new();
    assert_eq!(fresh.roam(tb(), addr(3), &mut ids), Roam::Bound);
    // The active path it bound roams: its slot stays on the path.
    assert_eq!(
        fresh.roam(tb(), addr(4), &mut ids),
        Roam::Roamed {
            from: (tb(), addr(3))
        }
    );
    assert_eq!(slot_drops(), 0, "the set dropped no slot itself");

    let held = set.len() + single.len() + fresh.len();
    drop(handed);
    drop((set, single, fresh));
    assert_eq!(slot_drops(), 4 + held, "every slot is dropped by its owner");
}

/// The source query: the original path is proven and active; an admitted
/// pair is unproven until one of our probes on it is answered, then proven
/// and not active; a pair not held is no path.
#[test]
fn classify_tells_a_proven_path_from_an_unproven_one_and_from_no_path() {
    let mut set = PathSet::new();
    let mut ids = counter();
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    let b = add(&mut set, tb(), addr(2), &mut ids);
    assert_eq!(
        set.classify(ta(), &addr(1)),
        Match::Proven {
            active: true,
            state: PathState::Live
        }
    );
    assert_eq!(set.classify(tb(), &addr(2)), Match::Unproven);
    assert_eq!(set.classify(tb(), &addr(9)), Match::None);
    assert_eq!(
        set.classify(ta(), &addr(2)),
        Match::None,
        "a path is its pair: the address on another transport is no path"
    );

    set.mark_acked(b);
    assert_eq!(
        set.classify(tb(), &addr(2)),
        Match::Proven {
            active: false,
            state: PathState::Probing
        }
    );
}

/// An acked path stays proven in any state, Dead included; a path that was
/// never acked is unproven when it is Dead too. The active path answers
/// proven and active whatever its state.
#[test]
fn classify_keeps_an_acked_path_proven_when_dead_and_a_never_acked_one_unproven() {
    let mut set = PathSet::new();
    let mut ids = counter();
    assert!(set.bind_original(ta(), addr(1), &mut ids).is_ok());
    let acked = add(&mut set, tb(), addr(2), &mut ids);
    let never = add(&mut set, tb(), addr(3), &mut ids);
    set.mark_acked(acked);
    set.transition(acked, PathState::Dead, at(10));
    set.transition(never, PathState::Dead, at(10));
    set.transition(0, PathState::Suspect, at(10));

    assert_eq!(
        set.classify(tb(), &addr(2)),
        Match::Proven {
            active: false,
            state: PathState::Dead
        }
    );
    assert_eq!(set.classify(tb(), &addr(3)), Match::Unproven);
    assert_eq!(
        set.classify(ta(), &addr(1)),
        Match::Proven {
            active: true,
            state: PathState::Suspect
        }
    );

    assert_eq!(
        set.rebind(tb(), addr(2), Medium::Other, &mut ids).0,
        Rebind::Switched
    );
    assert_eq!(
        set.classify(tb(), &addr(2)),
        Match::Proven {
            active: true,
            state: PathState::Dead
        },
        "the path a rebind made active answers active"
    );
    assert!(matches!(
        set.classify(ta(), &addr(1)),
        Match::Proven { active: false, .. }
    ));
}
