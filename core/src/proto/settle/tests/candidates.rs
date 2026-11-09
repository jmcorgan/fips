//! Candidate rules for the two settlement cases left for later, explored
//! in the world beside the core's own rules.
//!
//! The candidates are built into the core behind a test-only choice
//! (`Candidate` in `faults.rs`), each changing one decision:
//!
//! - **Dialer settle**, for the late second dial: the dialer keeps the
//!   session it moved off decryptable, and the peer's first frame under
//!   either session settles the one it keeps, as the model encodes the
//!   operator's rule. The comparison with the model keeps the model's
//!   fallback here, so the late second dial is no named difference.
//! - **Responder hold**, for the late second dial: a responder that
//!   replaced an unheard peering keeps the replaced session for 15 s, and
//!   the dialer's first frame under either settles the one it keeps; the
//!   dialer keeps the session it moved off as under the dialer's rule.
//! - **Aged move**, for the dial on the peer's aged link: an own dial
//!   completing for a peer held through a link old enough to rekey moves
//!   onto that dial, whatever the held link's direction.
//!
//! The candidate's nodes are joint nodes with multipath off
//! (`joint/party.rs`): the core under the candidate, with a real rekey
//! machine and bundle per held peer. A session the core keeps is the peer's
//! machines left as they are, receive-only, beside the machines the shell
//! builds for the session the peer is held on next, from what the kept ones
//! show and a copy of their replay record (`joint::machines::Machines::beside`).
//! That is a test's choice: the node has no second machine for one peer.
//!
//! Each candidate is explored on the starts it addresses and on every
//! named start the core's own rules pass (all but the two left for later),
//! the start with two paths on real bundles as the joint world builds it,
//! with the candidate at both ends, and at either end against the core's
//! own rules, the reference model, and the models of the current node at
//! multipath off and of the deployed node, in both address orders. Only the
//! dialer's candidate is compared with the model step by step. A split on a
//! path that showed a known shape is exempt, except the shapes the
//! candidate addresses: the stale frame and the later dial read first for
//! the two late-dial candidates, the dial taken as a rekey for the aged
//! move; so is the breach `joint/pins.rs` holds of a proven path left with
//! no connection. At a node of a deployed model the properties other than
//! one session are that node's own and are not asserted, as in
//! `legacy/explore.rs`.
//!
//! The outcome is recorded, not required to be clean: `candidates.txt`
//! lists, per candidate, every breach a run shows that the core's own
//! rules do not show in the same pairing (`new`), and every pairing the
//! core's own rules do not converge in (`legacy/not-converging.txt`) that
//! the candidate converges in (`gone`). A test fails when its runs differ
//! from the list either way, so the list cannot go stale. The scripted
//! pins of the two cases are run under each candidate as well.
//!
//! The explored runs, and everything only they use, need the
//! `slow-explorers` feature, which local CI turns on with `--slow-tests`
//! and GitHub CI does not; the two scripted tests need only `slow-tests`.

use alloc::string::String;
use alloc::vec::Vec;

use super::super::faults::{Candidate, under_candidate};
use super::regress::{aged_rekey_answered, late_dial_splits};
#[cfg(feature = "slow-explorers")]
use {
    super::super::model::history::Node,
    super::explore::Act,
    super::joint::Mode,
    super::joint::explore::lapsed,
    super::joint::party::JointParty,
    super::joint::starts::uncapped,
    super::legacy::maint::maint,
    super::legacy::master::master,
    super::oracle::{Breach, Oracle, Swept, sweep},
    super::party::Configured,
    super::starts::{Maker, Start, flipped, model},
    super::world::{Party, Shape, World},
    alloc::boxed::Box,
    alloc::format,
};

/// What a candidate node runs against.
#[cfg(feature = "slow-explorers")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Other {
    /// The candidate at every node.
    Both,
    /// The core's own rules.
    Plain,
    /// The reference model.
    Model,
    /// The model of the current node.
    Master,
    /// The model of the deployed node.
    Maint,
}

#[cfg(feature = "slow-explorers")]
impl Other {
    const ALL: [Other; 5] = [
        Self::Both,
        Self::Plain,
        Self::Model,
        Self::Master,
        Self::Maint,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::Both => "itself",
            Self::Plain => "core",
            Self::Model => "model",
            Self::Master => "master off",
            Self::Maint => "maint",
        }
    }

    /// Whether this is a model of a deployed node.
    fn legacy(self) -> bool {
        match self {
            Self::Master | Self::Maint => true,
            Self::Both | Self::Plain | Self::Model => false,
        }
    }
}

/// Candidate number `c` of [`Candidate::ALL`]; past the last, none: the
/// core's own rules, for a run's baseline.
#[cfg(feature = "slow-explorers")]
fn cand(c: u8) -> Option<Candidate> {
    Candidate::ALL.get(usize::from(c)).copied()
}

/// A joint node at multipath off running candidate `c`, or the core's own
/// rules with none.
#[cfg(feature = "slow-explorers")]
fn joint(ix: usize, me: Node, configured: Vec<Configured>, c: Option<Candidate>) -> Box<dyn Party> {
    Box::new(JointParty::under(ix, me, configured, Mode::Off, c))
}

/// Node `ix` of a pairing: candidate `C` at node `AT`, or at every node
/// when `OTHER` is 0, and otherwise what `OTHER` names (1 the core's own
/// rules, 2 the model, 3 the model of master at multipath off, 4 that of
/// maint).
#[cfg(feature = "slow-explorers")]
fn pairing<const C: u8, const OTHER: u8, const AT: usize>(
    ix: usize,
    me: Node,
    configured: Vec<Configured>,
) -> Box<dyn Party> {
    if OTHER == 0 || ix == AT {
        return joint(ix, me, configured, cand(C));
    }
    match OTHER {
        1 => joint(ix, me, configured, None),
        2 => model(ix, me, configured),
        3 => master(ix, me, configured),
        _ => maint(ix, me, configured),
    }
}

/// The maker of candidate `c` (none for the core's own rules) at node `at`
/// against `other`.
#[cfg(feature = "slow-explorers")]
fn maker(c: Option<Candidate>, other: Other, at: usize) -> Maker {
    macro_rules! of {
        ($c:literal) => {
            match (other, at) {
                (Other::Both, _) => pairing::<$c, 0, 0>,
                (Other::Plain, 0) => pairing::<$c, 1, 0>,
                (Other::Plain, _) => pairing::<$c, 1, 1>,
                (Other::Model, 0) => pairing::<$c, 2, 0>,
                (Other::Model, _) => pairing::<$c, 2, 1>,
                (Other::Master, 0) => pairing::<$c, 3, 0>,
                (Other::Master, _) => pairing::<$c, 3, 1>,
                (Other::Maint, 0) => pairing::<$c, 4, 0>,
                (Other::Maint, _) => pairing::<$c, 4, 1>,
            }
        };
    }
    match c {
        Some(Candidate::DialerSettle) => of!(0),
        Some(Candidate::ResponderHold) => of!(1),
        Some(Candidate::AgedMove) => of!(2),
        None => of!(3),
    }
}

/// The start candidate `c` addresses beside the ones the core's own rules
/// pass, and the shapes it is meant to leave no split behind.
#[cfg(feature = "slow-explorers")]
fn addresses(c: Candidate) -> (u8, &'static [Shape]) {
    match c {
        Candidate::DialerSettle | Candidate::ResponderHold => {
            (6, &[Shape::StaleFrame, Shape::LaterDialFirst])
        }
        Candidate::AgedMove => (7, &[Shape::DialAsRekey]),
    }
}

/// One run: a start with candidate `cand` at node `at` against `other`,
/// in the start's address order or the other.
#[cfg(feature = "slow-explorers")]
struct Run {
    st: Start,
    cand: Candidate,
    other: Other,
    at: usize,
    flip: bool,
}

#[cfg(feature = "slow-explorers")]
impl Run {
    fn order(&self) -> &'static str {
        if self.flip { "flipped" } else { "as written" }
    }

    /// The run's name, as `candidates.txt` lists it.
    fn name(&self) -> String {
        match self.other {
            Other::Both => format!(
                "{}: {:?} at every node, {}",
                self.st.name,
                self.cand,
                self.order()
            ),
            Other::Plain | Other::Model | Other::Master | Other::Maint => format!(
                "{}: {:?} at n{} against {}, {}",
                self.st.name,
                self.cand,
                self.at,
                self.other.name(),
                self.order()
            ),
        }
    }

    /// The name of the run of the core's own rules in the same pairing, as
    /// `legacy/not-converging.txt` lists it, for a deployed model.
    fn plain(&self) -> Option<String> {
        self.other.legacy().then(|| {
            format!(
                "{}: joint off at n{} against {}, {}",
                self.st.name,
                self.at,
                self.other.name(),
                self.order()
            )
        })
    }

    fn sweep(&self) -> Swept {
        self.sweep_of(&self.st)
    }

    /// The same run with the core's own rules where the candidate was.
    fn baseline(&self) -> Swept {
        let mut st = named()
            .into_iter()
            .find(|s| s.name == self.st.name)
            .expect("the start exists");
        st.maker = maker(None, self.other, self.at);
        self.sweep_of(&st)
    }

    fn sweep_of(&self, st: &Start) -> Swept {
        let (_, shapes) = addresses(self.cand);
        let exempt = |w: &World, b: &Breach| {
            (b.oracle == Oracle::OneSession && w.kinds().iter().any(|s| !shapes.contains(s)))
                || lapsed(w, b)
        };
        let go = || sweep(st, st.depth, &exempt);
        if self.flip { flipped(go) } else { go() }
    }

    /// The breaches of `swept` that count: at a deployed model's node only
    /// a split, elsewhere every property.
    fn counted(&self, swept: Swept) -> Vec<(Breach, Vec<Act>)> {
        swept
            .found
            .into_iter()
            .filter(|(b, _)| {
                !self.other.legacy() || b.node == self.at || b.oracle == Oracle::OneSession
            })
            .collect()
    }
}

/// The named starts, the one with two paths on real bundles, as the joint
/// world builds them; the starts only joint nodes run are not among them.
#[cfg(feature = "slow-explorers")]
fn named() -> Vec<Start> {
    uncapped(super::joint::off)
        .into_iter()
        .filter(|s| s.number <= 14)
        .collect()
}

/// Every run of candidate `c`.
#[cfg(feature = "slow-explorers")]
fn runs(c: Candidate) -> Vec<Run> {
    let (extra, _) = addresses(c);
    let mut out = Vec::new();
    for st in named() {
        let n = st.number;
        if matches!(n, 6 | 7) && n != extra {
            continue;
        }
        for other in Other::ALL {
            let ends: &[usize] = if other == Other::Both { &[0] } else { &[0, 1] };
            let flips: &[bool] = if matches!(n, 5 | 6 | 11 | 12) {
                &[false]
            } else {
                &[false, true]
            };
            for &at in ends {
                for &flip in flips {
                    let mut st = named()
                        .into_iter()
                        .find(|s| s.name == st.name)
                        .expect("the start exists");
                    st.maker = maker(Some(c), other, at);
                    out.push(Run {
                        st,
                        cand: c,
                        other,
                        at,
                        flip,
                    });
                }
            }
        }
    }
    out
}

/// One breach of a run, as `candidates.txt` keys it: the run, the
/// property's name and the node.
#[cfg(feature = "slow-explorers")]
type Key = (String, String, usize);

/// One counted breach of a run under the candidate, with what it says,
/// its shortest path, and whether the run's baseline shows it too.
#[cfg(feature = "slow-explorers")]
struct Shown {
    key: Key,
    what: String,
    path: Vec<Act>,
    kept: bool,
}

/// The breaches the runs found that count. Each run that shows one is run
/// again with the core's own rules in the candidate's place, and a breach
/// that run shows too is kept rather than new.
#[cfg(feature = "slow-explorers")]
fn found(runs: &[Run]) -> Vec<Shown> {
    let report = std::thread::scope(|sc| {
        let hs: Vec<_> = runs
            .iter()
            .map(|r| {
                sc.spawn(move || {
                    let t = std::time::Instant::now();
                    let swept = r.sweep();
                    std::eprintln!(
                        "{}: {} states, {} leaves healed in {} ms, exempted {:?}",
                        r.name(),
                        swept.stats.states,
                        swept.stats.leaves.len(),
                        t.elapsed().as_millis(),
                        swept.exempted
                    );
                    let mine = r.counted(swept);
                    let base = if mine.is_empty() {
                        Vec::new()
                    } else {
                        r.counted(r.baseline())
                    };
                    (mine, base)
                })
            })
            .collect();
        hs.into_iter()
            .map(|h| h.join().unwrap_or_else(|e| std::panic::resume_unwind(e)))
            .collect::<Vec<_>>()
    });
    let mut out = Vec::new();
    for (r, (mine, base)) in runs.iter().zip(report) {
        for (b, path) in mine {
            let kept = base
                .iter()
                .any(|(c, _)| c.oracle == b.oracle && c.node == b.node);
            out.push(Shown {
                key: (r.name(), format!("{:?}", b.oracle), b.node),
                what: b.what,
                path,
                kept,
            });
        }
    }
    out
}

/// Splits a tab-separated line of `file` into `n` fields.
#[cfg(feature = "slow-explorers")]
fn fields<'a>(file: &str, l: &'a str, n: usize) -> Vec<&'a str> {
    let f: Vec<&str> = l.split('\t').collect();
    assert!(f.len() == n, "{file}: a malformed line: {l:?}");
    f
}

/// The lines of `candidates.txt` for candidate `c`: the run, the
/// property, the node and whether the breach is new or gone.
#[cfg(feature = "slow-explorers")]
fn recorded(c: Candidate) -> Vec<(Key, String)> {
    let name = format!("{c:?}");
    include_str!("candidates.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| fields("candidates.txt", l, 5))
        .filter(|f| f[0] == name)
        .map(|f| {
            let node = f[3]
                .parse()
                .unwrap_or_else(|_| panic!("candidates.txt: a malformed node: {f:?}"));
            ((f[1].into(), f[2].into(), node), f[4].into())
        })
        .collect()
}

/// The pairings of the core's own rules with a deployed model found not to
/// converge, as `legacy/not-converging.txt` lists them.
#[cfg(feature = "slow-explorers")]
fn not_converging() -> Vec<Key> {
    include_str!("legacy/not-converging.txt")
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| fields("not-converging.txt", l, 3))
        .map(|f| {
            let node = f[2]
                .parse()
                .unwrap_or_else(|_| panic!("not-converging.txt: a malformed node: {f:?}"));
            (f[0].into(), f[1].into(), node)
        })
        .collect()
}

/// Asserts that candidate `c`'s runs show exactly the breaches that
/// `candidates.txt` records for it.
#[cfg(feature = "slow-explorers")]
fn outcome(c: Candidate) {
    let runs = runs(c);
    let found = found(&runs);
    let plain = not_converging();
    let mut shown: Vec<(Key, String)> = Vec::new();
    for f in &found {
        let what = if f.kept { "kept" } else { "new" };
        std::eprintln!(
            "{} ({what}): {} at n{}: {}\n  path {:?}",
            f.key.0,
            f.key.1,
            f.key.2,
            f.what,
            f.path
        );
        shown.push((f.key.clone(), what.into()));
    }
    for r in &runs {
        let Some(p) = r.plain() else { continue };
        for (_, oracle, node) in plain.iter().filter(|(n, ..)| *n == p) {
            let still = found
                .iter()
                .any(|f| f.key.0 == r.name() && f.key.1 == *oracle && f.key.2 == *node);
            if !still {
                shown.push(((r.name(), oracle.clone(), *node), "gone".into()));
            }
        }
    }
    let list = recorded(c);
    let line = |(k, w): &(Key, String)| format!("{c:?}\t{}\t{}\t{}\t{w}", k.0, k.1, k.2);
    let unlisted: Vec<String> = shown
        .iter()
        .filter(|s| !list.contains(s))
        .map(line)
        .collect();
    let stale: Vec<String> = list
        .iter()
        .filter(|s| !shown.contains(s))
        .map(line)
        .collect();
    let count = |w: &str| shown.iter().filter(|(_, x)| x == w).count();
    std::eprintln!(
        "{c:?}: {} runs, {} breaches new, {} kept, {} gone",
        runs.len(),
        count("new"),
        count("kept"),
        count("gone")
    );
    assert!(
        unlisted.is_empty() && stale.is_empty(),
        "{c:?}: not listed:\n{}\nlisted and no longer shown:\n{}",
        unlisted.join("\n"),
        stale.join("\n")
    );
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_dialer_settle_candidate_explored_shows_exactly_the_breaches_recorded_for_it() {
    outcome(Candidate::DialerSettle);
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_responder_hold_candidate_explored_shows_exactly_the_breaches_recorded_for_it() {
    outcome(Candidate::ResponderHold);
}

#[cfg(feature = "slow-explorers")]
#[test]
fn the_aged_move_candidate_explored_shows_exactly_the_breaches_recorded_for_it() {
    outcome(Candidate::AgedMove);
}

/// The splits after each late second dial pin's schedule, with the core
/// at both ends running `c`.
fn late(c: Option<Candidate>) -> Vec<String> {
    under_candidate(c, || {
        [
            "second msg2 first, larger dialer",
            "second msg2 first, smaller dialer",
        ]
        .into_iter()
        .flat_map(|name| late_dial_splits(6, name))
        .collect()
    })
}

#[test]
fn both_late_dial_candidates_settle_a_late_second_dial_answered_in_the_other_order() {
    assert!(
        !late(None).is_empty(),
        "precondition: the core's own rules split there"
    );
    for c in [Candidate::DialerSettle, Candidate::ResponderHold] {
        let split = late(Some(c));
        assert!(split.is_empty(), "{c:?}: the two ends split: {split:?}");
    }
    let split = late(Some(Candidate::AgedMove));
    assert!(
        !split.is_empty(),
        "the aged move leaves the late second dial as it was"
    );
}

#[test]
fn the_aged_move_candidate_answers_the_rekey_after_a_dial_on_the_aged_link_once_its_frame_arrives_first()
 {
    let answered = |c, frame_first| under_candidate(c, || aged_rekey_answered(frame_first));
    assert!(
        !answered(None, true) && !answered(None, false),
        "precondition: under the core's own rules the rekey is left unanswered in either order"
    );
    assert!(
        answered(Some(Candidate::AgedMove), true),
        "under the aged move the rekey is answered once the moved session's frame arrived"
    );
    assert!(
        !answered(Some(Candidate::AgedMove), false),
        "under the aged move a rekey that overtakes that frame is still refused"
    );
    for c in [Candidate::DialerSettle, Candidate::ResponderHold] {
        assert!(
            !answered(Some(c), true),
            "{c:?} leaves the dial on the aged link as it was"
        );
    }
}
