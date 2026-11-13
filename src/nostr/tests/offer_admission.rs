use super::*;

#[test]
fn one_sender_cannot_take_more_than_its_allowance_or_deny_another_sender() {
    let admission = OfferAdmission::new(16, 4);

    // The attacker pushes for the whole global pool, which is what makes
    // the victim's assertion below discriminating: without per-npub
    // accounting it takes all sixteen and the victim is refused.
    let mut held = Vec::new();
    let mut refusals = Vec::new();
    for _ in 0..16 {
        match admission.try_admit("npub1attacker") {
            Ok(permit) => held.push(permit),
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
        admission.try_admit("npub1victim").is_ok(),
        "a second sender must still be admitted while the pool has slots"
    );
}

#[test]
fn several_peers_bootstrapping_at_once_are_all_admitted() {
    let admission = OfferAdmission::new(16, 4);

    let mut held = Vec::new();
    for peer in 0..8 {
        held.push(
            admission
                .try_admit(&format!("npub1peer{peer}"))
                .unwrap_or_else(|e| panic!("peer {peer} should be admitted, got {e:?}")),
        );
    }
}

#[test]
fn an_idle_sender_is_reclaimed_so_the_map_cannot_grow_without_bound() {
    let admission = OfferAdmission::new(16, 4);

    // Three senders stay busy for the whole test, so the map bound and
    // not a collapse to a single entry is what the assertion measures.
    let mut held = Vec::new();
    for peer in 0..3 {
        held.push(
            admission
                .try_admit(&format!("npub1busy{peer}"))
                .expect("a busy peer is inside both bounds"),
        );
    }

    for sender in 0..100 {
        drop(
            admission
                .try_admit(&format!("npub1transient{sender}"))
                .expect("a transient sender is inside both bounds"),
        );
    }

    // Three still-held entries, plus the last transient sender, which was
    // inserted after the prune that would have removed it.
    assert_eq!(admission.tracked_senders(), 4);
}
