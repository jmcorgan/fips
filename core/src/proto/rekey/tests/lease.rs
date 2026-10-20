//! Tests of `lease.rs`.

use super::*;

/// A source that hands out one index.
struct One(Option<u32>);

impl IndexSource for One {
    fn draw(&mut self) -> Option<u32> {
        self.0.take()
    }
}

#[test]
fn a_lease_dropped_without_release_is_counted_as_leaked_and_a_released_one_is_not() {
    let before = leaked();
    let lease = allocate(&mut One(Some(5))).expect("one index");
    assert_eq!(lease.index(), 5);
    assert_eq!(lease.release(), 5);
    assert_eq!(leaked(), before, "a released lease is not a leak");
    let lease = allocate(&mut One(Some(6))).expect("one index");
    drop(lease);
    assert_eq!(
        leaked(),
        before + 1,
        "a dropped lease is counted, and dropping it does not panic"
    );
    assert!(
        allocate(&mut One(None)).is_none(),
        "an empty source gives no lease"
    );
}
