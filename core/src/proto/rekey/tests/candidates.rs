//! Tests of `candidates.rs`: the bound and the first-handshake eviction
//! rule.

use super::*;
use crate::proto::rekey::tests::stub::{Local, Xk};
use crate::testutil::TestInstant;
use crate::time::Duration;

/// A list with candidates on the given carriers, born at the given
/// seconds.
fn list(born: &[(u8, u64)]) -> Candidates<Xk, TestInstant> {
    let local = Local::new(1, 1);
    let mut c = Candidates::new();
    for &(carrier, at) in born {
        let (hs, _) =
            <Xk as Profile>::answer(&local, &[1, 9, 9, 9, 9, 9, 9, 9, 9]).expect("answer");
        c.add(
            Box::new(hs),
            alloc::vec![1],
            alloc::vec![2],
            carrier,
            0,
            TestInstant(at * 1000),
            TestInstant(at * 1000 + 40_000),
        );
    }
    c
}

#[test]
fn eviction_takes_the_oldest_unprotected_candidate_of_the_fullest_carrier_and_never_a_carriers_only_one()
 {
    let young = Duration::from_secs(5);
    let c = list(&[(1, 0), (1, 1)]);
    assert!(!c.room(1), "a carrier holds at most two");
    assert!(c.room(2));
    assert_eq!(
        c.victim(1, TestInstant(4_000), young),
        None,
        "both are younger than the protection age"
    );
    assert_eq!(
        c.victim(1, TestInstant(5_500), young),
        Some(0),
        "the oldest past the protection age"
    );
    let c = list(&[(1, 0), (2, 0), (3, 0), (3, 1)]);
    assert!(!c.room(4), "the list holds at most four");
    assert_eq!(
        c.victim(4, TestInstant(10_000), young),
        Some(2),
        "taken from the carrier holding the most"
    );
    let c = list(&[(1, 0), (2, 0), (3, 0), (4, 0)]);
    assert_eq!(
        c.victim(5, TestInstant(10_000), young),
        None,
        "never a carrier's only candidate"
    );
}
