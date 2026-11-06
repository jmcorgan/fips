//! Tests of the candidate table (`proto::path::candidate::tests::...`):
//! fresh reports and repeats, unlisting, hold-back by discard and by
//! absence, release, pruning what a release left unlisted, forgetting a
//! removed transport, the order a full table
//! replaces entries in, and that the table allocates nothing.

use alloc::format;
use alloc::vec::Vec;

use super::*;
use crate::testutil::allocations;

/// Local transport `n`.
fn t(n: u32) -> TransportId {
    TransportId::new(n)
}

/// The peer's address `n`.
fn addr(n: u8) -> TransportAddr {
    TransportAddr::from_string(&format!("10.0.0.{n}:2121"))
}

/// No pair is held as a path.
fn none(_: TransportId, _: &TransportAddr) -> bool {
    false
}

/// The entries of `c` as (transport, address byte, held), in slot order.
fn listed(c: &Candidates) -> Vec<(u32, u8, bool)> {
    c.iter()
        .map(|e| {
            let text = e.addr().as_str().expect("a text address");
            let n = text
                .trim_start_matches("10.0.0.")
                .trim_end_matches(":2121")
                .parse()
                .expect("an address of the tests");
            (e.transport().as_u32(), n, e.held())
        })
        .collect()
}

/// A table holding addresses 1 to 8 on transport 1, from `Config`, the
/// first reported first.
fn full() -> Candidates {
    let mut c = Candidates::new();
    for n in 1..=8 {
        assert_eq!(
            c.report(t(1), addr(n), Source::Config, none),
            Report::New(usize::from(n - 1))
        );
    }
    c
}

#[test]
fn a_repeat_changes_only_recency_and_a_new_source_or_request_is_fresh() {
    let mut c = Candidates::new();
    assert_eq!(
        c.report(t(1), addr(1), Source::Config, none),
        Report::New(0)
    );
    assert_eq!(
        c.report(t(1), addr(1), Source::Config, none),
        Report::Repeat(0)
    );
    let e = c.get(0).expect("the entry");
    assert!(e.sources().has(Source::Config));
    assert!(!e.sources().has(Source::Nostr));
    // Another source is fresh, and then a repeat of its own.
    assert_eq!(
        c.report(t(1), addr(1), Source::Nostr, none),
        Report::Again(0)
    );
    assert_eq!(
        c.report(t(1), addr(1), Source::Nostr, none),
        Report::Repeat(0)
    );
    // An operator's request is fresh every time.
    for _ in 0..3 {
        assert_eq!(
            c.report(t(1), addr(1), Source::Request, none),
            Report::Again(0)
        );
    }
    // A repeat of a held-back entry leaves it held back; a fresh report
    // releases it.
    c.hold(t(1), addr(1), none);
    assert_eq!(
        c.report(t(1), addr(1), Source::Config, none),
        Report::Repeat(0)
    );
    assert!(c.get(0).expect("the entry").held());
    assert_eq!(
        c.report(t(1), addr(1), Source::Discovery, none),
        Report::Again(0)
    );
    assert!(!c.get(0).expect("the entry").held());
    // The same address on another transport is another entry.
    assert_eq!(
        c.report(t(2), addr(1), Source::Config, none),
        Report::New(1)
    );
}

#[test]
fn an_entry_is_forgotten_when_its_last_source_unlists_it_unless_it_is_held_back() {
    let mut c = Candidates::new();
    c.report(t(1), addr(1), Source::Config, none);
    c.report(t(1), addr(1), Source::Nostr, none);
    assert!(!c.unlist(t(1), &addr(1), Source::Config));
    assert_eq!(listed(&c), [(1, 1, false)]);
    let e = c.get(0).expect("the entry");
    assert!(!e.sources().has(Source::Config) && e.sources().has(Source::Nostr));
    // A source that does not list it, or a pair with no entry, changes
    // nothing.
    assert!(!c.unlist(t(1), &addr(1), Source::Heard));
    assert!(!c.unlist(t(1), &addr(9), Source::Nostr));
    assert_eq!(listed(&c), [(1, 1, false)]);
    assert!(c.unlist(t(1), &addr(1), Source::Nostr));
    assert_eq!(listed(&c), []);
    // A held-back entry stays, held back, with no source.
    c.report(t(1), addr(2), Source::Config, none);
    c.hold(t(1), addr(2), none);
    assert!(!c.unlist(t(1), &addr(2), Source::Config));
    assert_eq!(listed(&c), [(1, 2, true)]);
    assert!(c.get(0).expect("the entry").sources().is_empty());
    // The source's next report is fresh.
    assert_eq!(
        c.report(t(1), addr(2), Source::Config, none),
        Report::Again(0)
    );
}

#[test]
fn release_frees_the_held_entries_of_one_transport_only() {
    let mut c = Candidates::new();
    for (k, n) in [(1, 1), (1, 2), (2, 3), (1, 4)] {
        c.report(t(k), addr(n), Source::Config, none);
    }
    c.hold(t(1), addr(1), none);
    c.hold(t(2), addr(3), none);
    c.hold(t(1), addr(4), none);
    // A discarded pair with no entry is entered, held back.
    c.hold(t(1), addr(5), none);
    assert_eq!(
        listed(&c),
        [
            (1, 1, true),
            (1, 2, false),
            (2, 3, true),
            (1, 4, true),
            (1, 5, true)
        ]
    );
    assert_eq!(c.release(t(1)), 0b1_1001);
    assert_eq!(
        listed(&c),
        [
            (1, 1, false),
            (1, 2, false),
            (2, 3, true),
            (1, 4, false),
            (1, 5, false)
        ]
    );
    assert_eq!(c.release(t(1)), 0);
    assert_eq!(c.release(t(2)), 0b100);
    assert_eq!(c.release(t(3)), 0);
}

#[test]
fn absence_holds_back_every_entry_of_one_transport_only() {
    let mut c = Candidates::new();
    for (k, n) in [(1, 1), (2, 2), (1, 3)] {
        c.report(t(k), addr(n), Source::Config, none);
    }
    c.absent(t(1));
    assert_eq!(listed(&c), [(1, 1, true), (2, 2, false), (1, 3, true)]);
    // Their sources still list them.
    assert!(c.get(0).expect("the entry").sources().has(Source::Config));
    c.absent(t(3));
    assert_eq!(listed(&c), [(1, 1, true), (2, 2, false), (1, 3, true)]);
}

#[test]
fn a_full_table_replaces_an_unlisted_held_back_entry_then_the_least_recent_free_one() {
    let mut c = full();
    // Address 6 held back and unlisted, 7 held back and still listed; 1 is
    // the least recent, 2 refreshed by a repeat.
    c.hold(t(1), addr(6), none);
    c.unlist(t(1), &addr(6), Source::Config);
    c.hold(t(1), addr(7), none);
    c.report(t(1), addr(2), Source::Config, none);
    assert_eq!(
        c.report(t(1), addr(9), Source::Config, none),
        Report::New(5)
    );
    assert_eq!(
        c.report(t(1), addr(10), Source::Config, none),
        Report::New(0)
    );
    assert_eq!(
        c.report(t(1), addr(11), Source::Config, none),
        Report::New(2)
    );
    assert_eq!(
        c.report(t(1), addr(12), Source::Config, none),
        Report::New(3)
    );
    // A pair discarded with no entry takes the same order.
    c.hold(t(1), addr(13), none);
    assert_eq!(c.find(t(1), &addr(13)), Some(4));
    assert!(
        c.find(t(1), &addr(7)).is_some(),
        "listed and held back: kept"
    );
}

#[test]
fn a_full_table_never_replaces_a_path_or_a_held_back_entry_a_source_lists() {
    let mut c = full();
    // Addresses 1 to 4 are paths; 5 to 8 are held back, still listed.
    let paths = |_: TransportId, a: &TransportAddr| (1..=4).any(|n| *a == addr(n));
    for n in 5..=8 {
        c.hold(t(1), addr(n), paths);
    }
    assert_eq!(c.report(t(1), addr(9), Source::Config, paths), Report::Full);
    c.hold(t(1), addr(10), paths);
    assert_eq!(c.find(t(1), &addr(10)), None, "not entered");
    assert_eq!(listed(&c).len(), 8);
    assert_eq!(c.find(t(1), &addr(9)), None);
    // A known pair is still reported.
    assert_eq!(
        c.report(t(1), addr(5), Source::Config, paths),
        Report::Repeat(4)
    );
}

#[test]
fn a_table_of_paths_and_listed_held_back_entries_drops_the_report() {
    let mut c = full();
    // Every entry is a path, the least recent first.
    let paths = |_: TransportId, _: &TransportAddr| true;
    assert_eq!(c.report(t(2), addr(9), Source::Nostr, paths), Report::Full);
    assert_eq!(listed(&c).len(), 8);
    assert_eq!(c.find(t(1), &addr(1)), Some(0));
    // Seven paths and one held-back entry its source lists: the same.
    let seven = |_: TransportId, a: &TransportAddr| *a != addr(8);
    c.hold(t(1), addr(8), seven);
    assert_eq!(c.report(t(2), addr(9), Source::Nostr, seven), Report::Full);
    // Once unlisted it may go.
    c.unlist(t(1), &addr(8), Source::Config);
    assert_eq!(
        c.report(t(2), addr(9), Source::Nostr, seven),
        Report::New(7)
    );
}

#[test]
fn prune_forgets_only_the_released_entries_no_source_lists_and_no_path_holds() {
    let mut c = Candidates::new();
    // Address 1 listed; 2 and 3 held back with no source, 3 held as a
    // path; 4 held back with no source on another transport.
    c.report(t(1), addr(1), Source::Config, none);
    c.hold(t(1), addr(2), none);
    c.hold(t(1), addr(3), none);
    c.hold(t(2), addr(4), none);
    let mask = c.release(t(1));
    assert_eq!(mask, 0b110);
    let path = |tr: TransportId, a: &TransportAddr| tr == t(1) && a == &addr(3);
    c.prune(mask, path);
    assert_eq!(listed(&c), [(1, 1, false), (1, 3, false), (2, 4, true)]);
    // A slot the mask leaves out is kept, released or not.
    c.hold(t(1), addr(5), none);
    let mask = c.release(t(1));
    c.prune(mask & !(1 << 1), none);
    assert_eq!(
        listed(&c),
        [(1, 1, false), (1, 5, false), (1, 3, false), (2, 4, true)]
    );
}

#[test]
fn forget_drops_only_the_removed_transports_entries() {
    let mut c = Candidates::new();
    for (k, n) in [(1, 1), (2, 2), (1, 3), (3, 4)] {
        c.report(t(k), addr(n), Source::Config, none);
    }
    c.hold(t(1), addr(3), none);
    c.forget(t(1));
    assert_eq!(listed(&c), [(2, 2, false), (3, 4, false)]);
    // A report of a forgotten pair is new.
    assert!(matches!(
        c.report(t(1), addr(3), Source::Config, none),
        Report::New(_)
    ));
}

#[test]
fn the_table_allocates_nothing() {
    let addrs: Vec<TransportAddr> = (1..=20).map(addr).collect();
    let mut c = Candidates::new();
    // Address 1 is held as a path, so a full table has one it never takes.
    let path = addr(1);
    let near = |_: TransportId, a: &TransportAddr| *a == path;
    let before = allocations();
    for round in 0..50u32 {
        for (k, a) in addrs.iter().enumerate() {
            let tr = t(1 + (k as u32 + round) % 3);
            let source = if k % 2 == 0 {
                Source::Config
            } else {
                Source::Discovery
            };
            let _ = c.report(tr, a.clone(), source, near);
            if k % 5 == 0 {
                c.hold(tr, a.clone(), near);
            }
            if k % 7 == 0 {
                let _ = c.unlist(tr, a, source);
            }
        }
        c.absent(t(1 + round % 3));
        let _ = c.release(t(1 + (round + 1) % 3));
    }
    assert_eq!(allocations(), before, "the table allocated");
    let v: Vec<u8> = Vec::with_capacity(1);
    assert!(allocations() > before, "the counter missed an allocation");
    drop(v);
}
