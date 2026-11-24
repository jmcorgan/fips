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
