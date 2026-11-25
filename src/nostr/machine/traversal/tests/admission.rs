use super::*;
use crate::nostr::machine::tests::ZeroEntropy;

fn admission(global: usize, per_sender: usize) -> Admission {
    Admission::new(global, per_sender, KeyedHasher::new::<ZeroEntropy>())
}

#[test]
fn the_global_limit_refuses_past_its_count() {
    let mut a = admission(3, 2);
    for sender in ["npub1a", "npub1b", "npub1c"] {
        assert!(
            a.try_admit(sender).is_ok(),
            "{sender} is inside both bounds"
        );
    }
    assert_eq!(a.try_admit("npub1d"), Err(AdmissionReject::GlobalFull));
    // A sender with room of its own is refused on the global bound too.
    assert_eq!(a.try_admit("npub1a"), Err(AdmissionReject::GlobalFull));
}

#[test]
fn a_sender_at_its_allowance_is_refused_while_others_are_admitted() {
    let mut a = admission(16, 2);
    assert!(a.try_admit("npub1spam").is_ok());
    assert!(a.try_admit("npub1spam").is_ok());
    assert_eq!(a.try_admit("npub1spam"), Err(AdmissionReject::SenderFull));
    assert!(a.try_admit("npub1honest").is_ok());
}

#[test]
fn a_released_slot_is_reusable_and_an_idle_sender_is_forgotten() {
    let mut a = admission(2, 1);
    let first = a.try_admit("npub1a").unwrap();
    let held = a.try_admit("npub1b").unwrap();
    assert_eq!(a.try_admit("npub1a"), Err(AdmissionReject::SenderFull));
    assert_eq!(a.tracked_senders(), 2);

    a.release(first);
    assert_eq!(a.tracked_senders(), 1, "a sender with no slot is forgotten");
    let again = a.try_admit("npub1a").expect("the released slot is free");
    assert_ne!(again, first, "a slot id is not reused");

    // Releasing a slot twice gives nothing back twice.
    a.release(first);
    assert_eq!(a.try_admit("npub1c"), Err(AdmissionReject::GlobalFull));
    a.release(held);
    a.release(again);
    assert_eq!(a.tracked_senders(), 0);
}

#[test]
fn one_sender_cannot_take_more_than_its_allowance_or_deny_another_sender() {
    let mut a = admission(16, 4);

    // The attacker pushes for the whole global pool, which is what makes
    // the victim's assertion below discriminating: without per-npub
    // accounting it takes all sixteen and the victim is refused.
    let mut held = Vec::new();
    let mut refusals = Vec::new();
    for _ in 0..16 {
        match a.try_admit("npub1attacker") {
            Ok(slot) => held.push(slot),
            Err(reject) => refusals.push(reject),
        }
    }

    assert_eq!(
        held.len(),
        4,
        "one npub must not hold more than its own allowance"
    );
    assert!(
        refusals
            .iter()
            .all(|reject| *reject == AdmissionReject::SenderFull),
        "a sender over its allowance is refused on its own account, not on the pool's: {refusals:?}"
    );
    assert!(
        a.try_admit("npub1victim").is_ok(),
        "a second sender must still be admitted while the pool has slots"
    );
}

#[test]
fn several_peers_bootstrapping_at_once_are_all_admitted() {
    let mut a = admission(16, 4);
    for peer in 0..8 {
        a.try_admit(&format!("npub1peer{peer}"))
            .unwrap_or_else(|e| panic!("peer {peer} should be admitted, got {e:?}"));
    }
}

#[test]
fn an_idle_sender_is_reclaimed_so_the_map_cannot_grow_without_bound() {
    let mut a = admission(16, 4);

    // Three senders stay busy for the whole test, so the map bound and
    // not a collapse to a single entry is what the assertion measures.
    for peer in 0..3 {
        a.try_admit(&format!("npub1busy{peer}"))
            .expect("a busy peer is inside both bounds");
    }

    for sender in 0..100 {
        let slot = a
            .try_admit(&format!("npub1transient{sender}"))
            .expect("a transient sender is inside both bounds");
        a.release(slot);
    }

    // The three still-held entries. Each transient sender is forgotten
    // when its slot is released.
    assert_eq!(a.tracked_senders(), 3);
}
