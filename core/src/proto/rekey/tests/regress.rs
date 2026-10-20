//! Scripted schedules: the fault schedules of historical defects and of
//! the design's adversarial traces, replayed through the simulator with
//! every oracle on and a zero O2 bound, so each must end converged without
//! losing one data frame to an epoch the receiver does not hold.
//!
//! Each schedule names the outcome it holds. Where both nodes send, node 0
//! starts the first rekey at 105 s (its first jitter draw is the lowest of
//! the band) and node 1 would start at 135 s; where node 1 is silent, node
//! 0's silence rule starts one every 30 s instead. Node 0 has the smaller
//! address.

use alloc::vec;
use alloc::vec::Vec;

use super::sim::{Class, Fate, Report, Rule, World, params, scripted, tail};
use super::stub::{Ik, Stub, Xk, with};
use crate::proto::rekey::{Config, MsgKind};
use crate::time::Duration;

/// Node 0's first rekey when both nodes send.
const T: u64 = 105_000;

/// Node 0's first rekey when node 1 is silent: the silence rule's.
const SILENT: u64 = 30_000;

/// The end of every schedule's scripted part.
const END: u64 = T + 300_000;

/// A pair whose node 0 rekeys first.
fn pair<P: Stub>() -> World<P> {
    World::<P>::pair_queued(params::<P>(), false, [vec![0], vec![30]])
}

/// A rule dropping `class` from node `from` sent in `[since, until)`.
fn drop(from: usize, class: Class, since: u64, until: u64) -> Rule {
    Rule {
        from,
        class,
        since,
        until,
        fate: Fate::Drop,
    }
}

/// Whether a run's track shows the outcome named.
fn shows(r: &Report, outcome: &str) -> bool {
    r.track.outcomes.iter().any(|(_, _, o)| o == outcome)
}

/// One schedule: its name, its run, and the state it must reach to test
/// anything, with that state described.
type Schedule = (
    &'static str,
    fn() -> Report,
    fn(&Report) -> bool,
    &'static str,
);

/// The schedules.
fn schedules() -> Vec<Schedule> {
    vec![
        (
            "the silent responder's only prompt lost loses no initiator frame",
            || {
                // The responder prompts once as it cuts over on msg3, and
                // that prompt is lost. Only the initiator's next probe or
                // previous-epoch frame draws another before the responder's
                // drain ends; a responder that took the probe as the
                // initiator having moved would draw none.
                let rules = vec![drop(1, Class::Prompt, SILENT, SILENT + 500)];
                scripted(pair::<Xk>(), [500, 0], rules, END, 0)
            },
            |r| {
                r.track.assumed == 0
                    && r.track.installs[0]
                        .first()
                        .is_some_and(|&t| (SILENT + 500..SILENT + 10_000).contains(&t))
            },
            "the initiator cut over on a later prompt, inside the responder's drain",
        ),
        (
            "every msg3 lost with the responder sending loses no frame and is repaired",
            || {
                // The responder sends less often than the initiator, so an
                // initiator that missed the peer staying and assumed its
                // cutover seals frames the responder cannot open before the
                // next old-epoch frame reverts it.
                let rules = vec![drop(0, Class::Hs(MsgKind::Msg3), T, T + 40_000)];
                scripted(pair::<Xk>(), [200, 2_000], rules, END, 0)
            },
            |r| shows(r, "PeerStayedOnOld"),
            "the initiator saw the peer stay and retired its epoch",
        ),
        (
            "an old frame withheld past an assumed cutover returns it to pending and loses nothing",
            || {
                let rules = vec![
                    drop(1, Class::Prompt, T, T + 36_000),
                    drop(1, Class::Data, T, T + 36_000),
                    Rule {
                        from: 1,
                        class: Class::Data,
                        since: T - 3_000,
                        until: T,
                        fate: Fate::HoldOnce(T + 35_000),
                    },
                ];
                scripted(pair::<Xk>(), [500, 500], rules, END, 0)
            },
            |r| r.track.assumed > 0 && r.track.reverts > 0,
            "an assumed cutover was reverted",
        ),
        (
            "every msg2 lost leaves the responder's pending unadopted and loses no frame",
            || {
                let rules = vec![drop(1, Class::Hs(MsgKind::Msg2), T, T + 40_000)];
                scripted(pair::<Ik>(), [500, 500], rules, END, 0)
            },
            |r| shows(r, "Unadopted"),
            "the responder's pending went unadopted",
        ),
        (
            "a peer's rekey over an unevidenced drain retires the drain and leaks no index",
            || {
                // A 50 s rotation with a 5 s band: node 0 starts at 45 s and
                // node 1, its prompts lost, starts again at about 95 s while
                // node 0 still drains the first epoch unevidenced.
                let params = with(Config::fmp(), |c| {
                    c.after = Duration::from_secs(50);
                    c.jitter = 5;
                });
                let w = World::<Ik>::pair_queued(params, false, [vec![0], vec![10]]);
                let rules = vec![drop(1, Class::Prompt, 40_000, 80_000)];
                scripted(w, [500, 0], rules, 300_000, 0)
            },
            |r| r.track.installs[0].len() >= 2 && r.track.installs[0][1] < 45_000 + 120_000,
            "node 0 cut over again inside the first epoch's drain ceiling",
        ),
        (
            "every first-handshake msg3 lost is repaired within the msg3 ladder and one handshake",
            || {
                // Node 0 dials and installs on the ack; node 1 never reads a
                // msg3 until the ladder's last rung has passed. Node 0 is
                // silent, so only the end of its msg3 ladder can start the
                // repair (its silence rule needs data sent). Node 1 sends
                // nothing before it installs, so the outcome checked is the
                // repair's start at the last rung, then convergence and no
                // frame lost once node 1 sends.
                let w = World::<Xk>::opening(params::<Xk>(), false, None);
                let rules = vec![drop(0, Class::Hs(MsgKind::Msg3), 0, 32_000)];
                scripted(w, [0, 500], rules, 300_000, 0)
            },
            |r| {
                r.track.starts[0]
                    .get(1)
                    .is_some_and(|&t| (31_000..33_000).contains(&t))
            },
            "node 0 started its repair at the msg3 ladder's last rung",
        ),
    ]
}

#[test]
fn scripted_schedules_lose_no_frame_beyond_their_bounds_and_converge() {
    for (name, run, reached, state) in schedules() {
        let r = run();
        if let Some(f) = &r.failure {
            panic!("{name}: {f}\nlog tail:\n{}", tail(&r.log));
        }
        assert!(
            reached(&r),
            "{name}: never reached its state ({state}), so it tested nothing"
        );
    }
}
