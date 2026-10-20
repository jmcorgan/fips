//! Tests of `record.rs`.

use super::*;

/// A distinct digest per number.
fn d(n: u32) -> Digest {
    let mut b = [0u8; 32];
    b[..4].copy_from_slice(&n.to_le_bytes());
    Digest(b)
}

#[test]
fn replay_record_never_exceeds_its_bound() {
    let mut r = Record::setup(d(0), d(1), None);
    for n in 2..2 + 3 * RECORD_BOUND as u32 {
        r.push(d(n));
        assert!(
            r.len() <= RECORD_BOUND + 1,
            "at most the bound plus the setup msg1"
        );
    }
    assert_eq!(r.len(), RECORD_BOUND + 1);
    assert!(
        r.holds(&d(1)),
        "the setup msg1's ephemeral is kept outside the bound"
    );
    assert!(!r.holds(&d(2)), "the oldest entries went first");
    assert!(r.holds(&d(1 + 3 * RECORD_BOUND as u32)));
    assert!(r.is_setup(&d(0)));
}

#[test]
fn absorbing_an_older_record_of_the_same_peer_epoch_keeps_its_ephemerals_within_the_bound() {
    let mut old = Record::setup(d(10), d(11), None);
    old.push(d(12));
    let mut new = Record::setup(d(20), d(21), Some(alloc::vec![9]));
    new.push(d(22));
    new.absorb(old);
    for n in [11, 12, 21, 22] {
        assert!(new.holds(&d(n)), "ephemeral {n} is held");
    }
    assert!(
        new.is_setup(&d(20)) && !new.is_setup(&d(10)),
        "the setup msg1 is this peering's"
    );
    assert_eq!(new.setup_answer(), Some(&alloc::vec![9]));
    let mut big = Record::new();
    for n in 0..RECORD_BOUND as u32 {
        big.push(d(100 + n));
    }
    new.absorb(big);
    assert!(new.len() <= RECORD_BOUND + 1);
}
