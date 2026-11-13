//! Tests that the clock-skew estimate (`estimate_clock_skew` in `signal.rs`)
//! never overflows on the two timestamps a responder supplies in its answer,
//! and yields no estimate rather than a wrong one or a panic.

use super::super::signal::{create_traversal_answer, create_traversal_offer, estimate_clock_skew};
use super::super::types::{TraversalAnswer, TraversalOffer};

const T1: u64 = 1_700_000_000_000;

fn offer() -> TraversalOffer {
    create_traversal_offer(
        "sess-1".to_string(),
        T1,
        60_000,
        "offer-1".to_string(),
        "npub1client".to_string(),
        "npub1server".to_string(),
        None,
        vec![],
        None,
    )
}

/// An answer whose responder says it received the offer at `t2` and issued
/// the answer at `t3`.
fn answer(t2: u64, t3: u64) -> TraversalAnswer {
    let mut answer = create_traversal_answer(
        "sess-1".to_string(),
        T1 + 50,
        60_000,
        "answer-1".to_string(),
        "npub1server".to_string(),
        "npub1client".to_string(),
        "offer-1".to_string(),
        true,
        None,
        vec![],
        None,
        None,
        None,
        Some(T1 + 50),
    );
    answer.offer_received_at = Some(t2);
    answer.issued_at = t3;
    answer
}

#[test]
fn estimate_clock_skew_returns_none_on_out_of_range_responder_timestamps() {
    for huge in [i64::MAX as u64, u64::MAX] {
        assert_eq!(
            estimate_clock_skew(&offer(), &answer(huge, huge), T1 + 100),
            None,
            "{huge}"
        );
    }
}

#[test]
fn estimate_clock_skew_returns_none_when_in_range_responder_timestamps_overflow_the_sum() {
    // Each difference fits an i64; their sum does not.
    let t2 = i64::MAX as u64 - 1;
    let t4 = T1 + 100;
    let t3 = t4 + 2 * T1;
    assert_eq!(estimate_clock_skew(&offer(), &answer(t2, t3), t4), None);
}

#[test]
fn estimate_clock_skew_still_estimates_an_ordinary_round_trip() {
    // Responder 1 s ahead, 50 ms each way: received at T1 + 1050, answered
    // at T1 + 1060, answer back at T1 + 110.
    let skew = estimate_clock_skew(&offer(), &answer(T1 + 1050, T1 + 1060), T1 + 110);
    assert_eq!(skew, Some(1000));
}
