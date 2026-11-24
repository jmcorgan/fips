use super::*;
use crate::nostr::machine::tests::TestInstant;

#[test]
fn a_flood_is_admitted_up_to_the_burst_and_shed_after_it() {
    let start = TestInstant(0);
    let mut gate = SignalGate::new(start);

    let admitted = (0..1000)
        .filter(|_| gate.admit(false, start).is_ok())
        .count();

    assert_eq!(admitted, SIGNAL_BURST as usize);
    assert_eq!(gate.admit(false, start), Err(SignalShed::Shared));
}

#[test]
fn tokens_refill_so_a_steady_legitimate_signal_rate_is_never_shed() {
    let start = TestInstant(0);
    let mut gate = SignalGate::new(start);

    // One second per iteration at exactly the sustained rate, for long
    // enough that an arithmetic error in the refill drains the bucket.
    for second in 0..100u64 {
        let now = TestInstant(start.0 + second * 1000);
        for signal in 0..SIGNAL_RATE_PER_SEC as usize {
            assert_eq!(
                gate.admit(false, now),
                Ok(()),
                "signal {signal} of second {second} should be admitted"
            );
        }
    }
}

#[test]
fn a_flood_cannot_shed_the_answers_to_traversals_this_node_started() {
    let start = TestInstant(0);
    let mut gate = SignalGate::new(start);

    // The flood arrives while this node has nothing outstanding, so it
    // cannot reach the reserve at all.
    for _ in 0..1000 {
        let _ = gate.admit(false, start);
    }
    assert_eq!(gate.admit(false, start), Err(SignalShed::Shared));

    let admitted = (0..1000)
        .filter(|_| gate.admit(true, start).is_ok())
        .count();
    assert_eq!(admitted, ANSWER_RESERVE_BURST as usize);
    assert_eq!(gate.admit(true, start), Err(SignalShed::Reserve));
}

#[test]
fn the_reserve_is_untouched_while_the_shared_allowance_still_has_tokens() {
    let start = TestInstant(0);
    let mut gate = SignalGate::new(start);

    // Every one of these is inside the shared burst, so none of them may
    // spend the reserve even though the caller is entitled to it.
    for _ in 0..SIGNAL_BURST as usize {
        assert_eq!(gate.admit(true, start), Ok(()));
    }

    let reserve_admitted = (0..1000)
        .filter(|_| gate.admit(true, start).is_ok())
        .count();
    assert_eq!(reserve_admitted, ANSWER_RESERVE_BURST as usize);
}
