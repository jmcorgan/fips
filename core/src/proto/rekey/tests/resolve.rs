//! Tests of `resolve.rs`: the agreement table.

use super::*;
use crate::testutil::make_node_addr;

/// Whether the attempt of `owner` survives given both ends' verdicts on
/// the other's attempt.
fn survives(own_verdict: Verdict, other_verdict: Verdict) -> bool {
    matches!(own_verdict, Verdict::KeepOwn | Verdict::DiscardCompeting)
        && matches!(other_verdict, Verdict::YieldOwn | Verdict::Accept)
}

#[test]
fn both_ends_name_the_same_survivor_for_every_pair() {
    let (a, b) = (make_node_addr(1), make_node_addr(2));
    assert!(a < b);
    let owns = [Own::Unanswered, Own::Completed];
    for (x, y) in [(a, b), (b, a)] {
        for ox in owns {
            for oy in owns {
                for commit in [Commit::AtAnswer, Commit::AtFinal] {
                    let vx = resolve(commit, ox, &x, &y, false);
                    let vy = resolve(commit, oy, &y, &x, false);
                    let x_wins = survives(vx, vy);
                    let y_wins = survives(vy, vx);
                    let possible = match commit {
                        // B's msg1 can reach A only while B is unanswered.
                        Commit::AtAnswer => oy == Own::Unanswered,
                        // A completed msg3 exists only for a completed attempt.
                        Commit::AtFinal => oy == Own::Completed,
                    };
                    if !possible || (commit == Commit::AtFinal && ox == Own::Unanswered) {
                        continue;
                    }
                    assert!(
                        !(x_wins && y_wins),
                        "{commit:?} {ox:?}/{oy:?}: both ends keep their own attempt"
                    );
                }
            }
        }
    }
    assert_eq!(
        resolve(Commit::AtAnswer, Own::Unanswered, &a, &b, false),
        Verdict::KeepOwn
    );
    assert_eq!(
        resolve(Commit::AtAnswer, Own::Unanswered, &b, &a, false),
        Verdict::YieldOwn
    );
    assert_eq!(
        resolve(Commit::AtAnswer, Own::Completed, &b, &a, false),
        Verdict::DiscardCompeting
    );
    assert_eq!(
        resolve(Commit::AtFinal, Own::Unanswered, &a, &b, false),
        Verdict::YieldOwn
    );
    assert_eq!(
        resolve(Commit::AtFinal, Own::Completed, &a, &b, false),
        Verdict::KeepOwn
    );
    assert_eq!(
        resolve(Commit::AtFinal, Own::Completed, &b, &a, false),
        Verdict::YieldOwn
    );
    assert_eq!(
        resolve(Commit::AtFinal, Own::Completed, &a, &b, true),
        Verdict::YieldOwn,
        "a restarted peer wins"
    );
    assert_eq!(
        resolve(Commit::AtFinal, Own::None, &a, &b, true),
        Verdict::Accept
    );
}
