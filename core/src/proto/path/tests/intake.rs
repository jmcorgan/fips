//! The candidates a bundle holds (multipath v1 draft, Section 5.4, the
//! note, and Section 5.6): held whatever the capability and path policy,
//! probed at once on a fresh report while the peer is capable, never on a
//! repeat; never moving a path; the per-peer cap; hold-back after a
//! discard or an interface's departure, and the release by carrier,
//! presence, a fresh report or local discovery finding the peer again;
//! forgetting a removed transport; turning capable; a disabled bundle
//! holding nothing; and a poll offering again a candidate a rule refused,
//! reporting the refusal again only when the rule changes. Every test drives a `Bundle` through its inputs in the
//! shell.

use alloc::vec::Vec;

use super::shell::*;
use crate::proto::path::{
    Class, Input, Kind, PathRef, PathState, Refusal, Role, Rule, Source, Why,
};
use crate::testutil::TestInstant;

/// The candidates `n` holds, as (pair, held back).
fn held(n: &Node) -> Vec<(PathRef, bool)> {
    n.b.candidates()
        .iter()
        .map(|e| (pair(e.transport(), e.addr().clone()), e.held()))
        .collect()
}

/// Configuration's report of `to`.
fn found(to: &PathRef) -> Input {
    Input::Candidate {
        transport: to.transport,
        addr: to.addr.clone(),
        source: Source::Config,
    }
}

/// Whether `n` holds `to` as a candidate held back.
fn back(n: &Node, to: &PathRef) -> bool {
    held(n).contains(&(to.clone(), true))
}

/// The new paths in `out`: pair and why.
fn admitted(out: &[Out]) -> Vec<(PathRef, Why)> {
    states(out)
        .into_iter()
        .filter(|c| c.2.is_none() && c.3 == Some(PathState::Probing))
        .map(|c| (c.0, c.4))
        .collect()
}

/// Report `to` from `source` and leave its probes unanswered, answering
/// every other, until its path is exhausted and discarded at the grace:
/// its pair is then held back.
fn given_up(n: &mut Node, log: &mut Log, to: &PathRef, source: Source) {
    let start = n.now.0;
    let out = n.report(to.transport, to.addr.clone(), source);
    let answers = &mut |_: u64, at: &PathRef| at != to;
    handle(n, log, out, answers);
    run(n, log, start + 700_000, answers);
    let last = log.changes(to).last().copied();
    assert!(
        matches!(last, Some((_, Some(PathState::Dead), None, Why::Grace))),
        "{last:?}"
    );
    assert!(back(n, to), "{:?}", held(n));
}

#[test]
fn candidates_are_held_whatever_the_capability_and_the_rules() {
    // A peer not known to be capable: held, not admitted, and only a
    // capability probe goes, on the original path.
    let mut n = Node::new(201);
    let out = n.report(t(2), addr(2), Source::Nostr);
    assert!(states(&out).is_empty(), "{out:?}");
    assert_eq!(out.len(), 1, "{out:?}");
    probe_on(&out, &p());
    assert_eq!(held(&n), [(q(), false)]);
    assert_eq!(n.b.paths().len(), 1);
    // A Tor candidate on a clear link: refused, and held.
    let facts = Stub::default().fact(t(3), Fact::Class(Class::Tor));
    let mut n = Node::capable(202).with(facts);
    let out = n.candidate(t(3), addr(3));
    assert_eq!(refusals(&out), [(r(), Refusal::Rule(Rule::Class))]);
    assert_eq!(held(&n), [(r(), false)]);
    assert!(
        n.b.candidates()
            .get(0)
            .unwrap()
            .sources()
            .has(Source::Config)
    );
}

#[test]
fn a_candidate_of_a_capable_peer_is_probed_at_once_and_a_repeat_sends_nothing_more() {
    let facts = Stub::default().fact(t(5), Fact::Dials(false));
    let mut n = Node::capable(203).with(facts);
    let out = n.candidate(t(2), addr(2));
    assert_eq!(admitted(&out), [(q(), Why::Candidate)]);
    probe_on(&out, &q());
    assert!(n.candidate(t(2), addr(2)).is_empty());
    // A candidate the rules refuse is refused once; its repeats give
    // nothing.
    let far = pair(t(5), addr(5));
    let out = n.candidate(t(5), addr(5));
    assert_eq!(refusals(&out), [(far.clone(), Refusal::Rule(Rule::Dial))]);
    for k in 1..=5 {
        n.now = TestInstant(k);
        assert!(n.candidate(t(5), addr(5)).is_empty());
    }
    // So is one refused for room: transport 2 holds four paths at most.
    for k in 6..=8 {
        n.candidate(t(2), addr(k));
    }
    let out = n.candidate(t(2), addr(9));
    assert_eq!(refusals(&out), [(pair(t(2), addr(9)), Refusal::Full)]);
    assert!(n.candidate(t(2), addr(9)).is_empty());
}

/// The pair numbered 5 on transport 5, which the tests below refuse by a
/// rule first.
fn far() -> PathRef {
    pair(t(5), addr(5))
}

/// A capable node whose transport 5 does not dial the peer, holding
/// `far()` as a candidate refused for the dial rule.
fn dial_refused(seed: u64) -> Node {
    let facts = Stub::default().fact(t(5), Fact::Dials(false));
    let mut n = Node::capable(seed).with(facts);
    let out = n.candidate(t(5), addr(5));
    assert_eq!(refusals(&out), [(far(), Refusal::Rule(Rule::Dial))]);
    assert!(admitted(&out).is_empty(), "{out:?}");
    assert_eq!(refused(&n, &far()), Some(Rule::Dial));
    n
}

/// The rule recorded as refusing the candidate `to` at its last attempt.
fn refused(n: &Node, to: &PathRef) -> Option<Rule> {
    n.b.candidates()
        .iter()
        .find(|e| e.transport() == to.transport && e.addr() == &to.addr)
        .expect("the candidate is held")
        .refused()
}

/// Whether a poll at `n.now` comes before the bundle's next wake.
fn before_wake(n: &Node) -> bool {
    n.b.next_wake().is_none_or(|w| n.now < w)
}

/// A candidate a rule refused is offered again at the next poll after the
/// facts change, and admitted then with no fresh report of it (operator's
/// choice on the draft's Section 5.5: a change in the facts takes effect
/// at the next poll). Mutation: no re-offer on a poll.
#[test]
fn a_poll_after_the_facts_change_admits_a_candidate_a_rule_refused() {
    let mut n = dial_refused(206);
    n.facts.change(t(5), Fact::Dials(true));
    n.now = TestInstant(10);
    assert!(before_wake(&n), "precondition: an early poll");
    let out = n.poll();
    assert_eq!(admitted(&out), [(far(), Why::Candidate)]);
    probe_on(&out, &far());
    assert!(refusals(&out).is_empty(), "{out:?}");
    assert_eq!(refused(&n, &far()), None);
}

/// A candidate the rules still refuse gives no refusal at later polls,
/// early ones or at the wake, while the facts are unchanged; a fresh
/// report of it is refused again as before. Mutation: a re-offer reports
/// its refusal every time.
#[test]
fn a_candidate_a_rule_still_refuses_gives_no_refusal_on_later_polls() {
    let mut n = dial_refused(207);
    // A second path, so the bundle has wakes to poll at.
    let mut log = Log::default();
    let out = n.candidate(t(2), addr(2));
    handle(&mut n, &mut log, out, &mut all);
    for k in 1..=5 {
        n.now = TestInstant(k);
        assert!(before_wake(&n), "precondition: an early poll");
        let out = n.poll();
        assert!(out.is_empty(), "{out:?}");
    }
    let mut polls = 0;
    while let Some(out) = n.tick(TestInstant(10_000)) {
        polls += 1;
        assert!(refusals(&out).is_empty(), "{out:?}");
        assert!(!admitted(&out).iter().any(|(to, _)| *to == far()));
        handle(&mut n, &mut log, out, &mut all);
    }
    assert!(polls > 0, "precondition: the bundle woke in the 10 s");
    assert_eq!(refused(&n, &far()), Some(Rule::Dial));
    assert!(n.b.paths().find(t(5), &addr(5)).is_none());
    let out = n.report(t(5), addr(5), Source::Request);
    assert_eq!(refusals(&out), [(far(), Refusal::Rule(Rule::Dial))]);
}

/// A poll reports a refused candidate again only when the rule refusing
/// it changes, and once for each change. Mutation: a re-offer compares
/// with the recorded rule but never records the new one.
#[test]
fn a_poll_reports_a_refused_candidate_again_only_when_the_refusing_rule_changes() {
    let mut n = dial_refused(208);
    n.facts.change(t(5), Fact::Role(Role::Never));
    n.now = TestInstant(10);
    let out = n.poll();
    assert_eq!(refusals(&out), [(far(), Refusal::Rule(Rule::Role))]);
    assert_eq!(refused(&n, &far()), Some(Rule::Role));
    n.now = TestInstant(20);
    let out = n.poll();
    assert!(out.is_empty(), "the same rule again: {out:?}");
    n.facts.change(t(5), Fact::Role(Role::Normal));
    n.now = TestInstant(30);
    let out = n.poll();
    assert_eq!(refusals(&out), [(far(), Refusal::Rule(Rule::Dial))]);
    n.facts.change(t(5), Fact::Dials(true));
    n.now = TestInstant(40);
    let out = n.poll();
    assert_eq!(admitted(&out), [(far(), Why::Candidate)]);
}

/// A candidate a rule refused that a poll then finds no room for is
/// refused once for room and waits for its next trigger: later polls give
/// nothing. Mutation: keep the rule recorded on a refusal for room.
#[test]
fn a_rule_refused_candidate_a_poll_finds_no_room_for_is_refused_once_and_waits_for_its_next_trigger()
 {
    // Transport 2 takes the kind of the peer's address, so an Internet
    // address on it is refused on this Local link and a local one is not.
    let facts = Stub::default().fact(t(2), Fact::Kind(None));
    let mut n = Node::capable(209).with(facts);
    let far = pair(t(2), public(9));
    let out = n.candidate(t(2), public(9));
    assert_eq!(refusals(&out), [(far.clone(), Refusal::Rule(Rule::Kind))]);
    // Transport 2 filled to its four paths, all Probing.
    for k in [2, 6, 7, 8] {
        let out = n.candidate(t(2), addr(k));
        assert_eq!(admitted(&out), [(pair(t(2), addr(k)), Why::Candidate)]);
    }
    n.facts.change(t(2), Fact::Kind(Some(Kind::Local)));
    n.now = TestInstant(10);
    let out = n.poll();
    assert_eq!(refusals(&out), [(far.clone(), Refusal::Full)]);
    assert!(admitted(&out).is_empty(), "{out:?}");
    assert_eq!(refused(&n, &far), None);
    for k in 11..=15 {
        n.now = TestInstant(k);
        assert!(before_wake(&n), "precondition: an early poll");
        let out = n.poll();
        assert!(out.is_empty(), "{out:?}");
    }
    assert!(n.b.paths().find(t(2), &public(9)).is_none());
    assert!(
        n.b.candidates()
            .iter()
            .any(|e| e.transport() == t(2) && e.addr() == &public(9)),
        "the candidate is still held"
    );
}

#[test]
fn a_beacon_candidate_never_moves_a_path_including_a_suspect_active_one() {
    // The original is our active path, Suspect after carrier loss, with a
    // second path still Probing beside it.
    let mut n = Node::capable(204);
    n.candidate(t(2), addr(2));
    step(&mut n, 10, down(1));
    assert_eq!(state(&n, &p()), PathState::Suspect);
    assert_eq!(active(&n), Some(p()));
    let index = n.b.paths().find(t(1), &addr(1));
    let out = n.report(t(1), addr(5), Source::Discovery);
    assert!(moved(&out).is_empty(), "{out:?}");
    assert_eq!(admitted(&out), [(pair(t(1), addr(5)), Why::Candidate)]);
    assert_eq!(n.b.paths().find(t(1), &addr(1)), index);
    assert_eq!(active(&n), Some(p()));
    // A peer not known to be capable: its one path stays where it is, and
    // only a capability probe goes, on it.
    let mut n = Node::new(205);
    step(&mut n, 10, down(1));
    let out = n.report(t(1), addr(5), Source::Discovery);
    assert!(moved(&out).is_empty() && states(&out).is_empty(), "{out:?}");
    assert_eq!(out.len(), 1, "{out:?}");
    probe_on(&out, &p());
    assert_eq!(n.b.paths().find(t(1), &addr(1)), Some(0));
    assert_eq!(n.b.paths().len(), 1);
}

#[test]
fn the_ninth_candidate_replaces_the_least_recent_one_not_a_path() {
    // Transport 5 is never dialled, so its candidates are held and refused.
    let facts = Stub::default().fact(t(5), Fact::Dials(false));
    let mut n = Node::capable(206).with(facts);
    n.candidate(t(2), addr(2));
    for k in 3..=9 {
        n.candidate(t(5), addr(k));
    }
    assert_eq!(held(&n).len(), 8);
    let out = n.candidate(t(5), addr(10));
    assert_eq!(
        refusals(&out),
        [(pair(t(5), addr(10)), Refusal::Rule(Rule::Dial))]
    );
    let pairs: Vec<PathRef> = held(&n).into_iter().map(|(to, _)| to).collect();
    assert!(pairs.contains(&q()), "a path is never replaced");
    assert!(!pairs.contains(&pair(t(5), addr(3))), "{pairs:?}");
    assert!(pairs.contains(&pair(t(5), addr(9))));
    assert!(pairs.contains(&pair(t(5), addr(10))));
    // A repeat refreshes an entry, which then outlasts older ones.
    n.candidate(t(5), addr(4));
    n.candidate(t(5), addr(11));
    let pairs: Vec<PathRef> = held(&n).into_iter().map(|(to, _)| to).collect();
    assert!(pairs.contains(&pair(t(5), addr(4))));
    assert!(!pairs.contains(&pair(t(5), addr(5))), "{pairs:?}");
}

#[test]
fn a_held_back_pair_its_source_still_lists_stays_quiet_on_a_full_table() {
    let facts = Stub::default().fact(t(5), Fact::Dials(false));
    let mut n = Node::capable(207).with(facts);
    let mut log = Log::default();
    for k in 3..=9 {
        n.candidate(t(5), addr(k));
    }
    given_up(&mut n, &mut log, &q(), Source::Config);
    assert_eq!(held(&n).len(), 8);
    // A ninth pair from configuration, then hours of configuration
    // repeating all nine each minute: the pairs on transport 5 cycle
    // through the table, and the held-back pair is never probed.
    let nine: Vec<PathRef> = core::iter::once(q())
        .chain((3..=10).map(|k| pair(t(5), addr(k))))
        .collect();
    for minute in 0..180 {
        n.now = TestInstant(n.now.0 + 60_000);
        for to in &nine {
            let out = n.candidate(to.transport, to.addr.clone());
            assert!(probes(&out).is_empty(), "minute {minute}: {out:?}");
            assert!(admitted(&out).is_empty(), "minute {minute}: {out:?}");
        }
        assert!(back(&n, &q()), "minute {minute}: {:?}", held(&n));
    }
}

#[test]
fn turning_capable_probes_every_held_candidate_the_rules_allow() {
    let facts = Stub::default().fact(t(3), Fact::Class(Class::Tor));
    let mut n = Node::new(208).with(facts);
    let far = pair(t(2), addr(5));
    // Held, not admitted: the first sends a capability probe, and the
    // others nothing while it is outstanding.
    for (k, to) in [q(), r(), far.clone()].into_iter().enumerate() {
        let out = n.candidate(to.transport, to.addr);
        assert!(states(&out).is_empty(), "{out:?}");
        assert_eq!(probes(&out).len(), usize::from(k == 0), "{out:?}");
    }
    // The peer's probe on the original path makes it capable.
    let out = n.probe(t(1), addr(1), probe_from(0xA, 1, 27));
    assert!(n.b.capable());
    assert_eq!(
        admitted(&out),
        [(q(), Why::Candidate), (far.clone(), Why::Candidate)]
    );
    probe_on(&out, &q());
    probe_on(&out, &far);
    assert_eq!(refusals(&out), [(r(), Refusal::Rule(Rule::Class))]);
    assert_eq!(sent_acks(&out).len(), 1, "the probe is answered");
}

#[test]
fn a_discarded_paths_candidate_is_held_back_until_its_source_reports_it_again() {
    let mut n = Node::capable(209);
    let mut log = Log::default();
    given_up(&mut n, &mut log, &q(), Source::Config);
    // Hours of repeats and polls send nothing.
    for k in 0..180 {
        n.now = TestInstant(700_000 + k * 60_000);
        assert!(n.poll().is_empty());
        assert!(n.candidate(t(2), addr(2)).is_empty());
    }
    assert!(back(&n, &q()), "{:?}", held(&n));
    // The source drops it and lists it again: probed at once.
    assert!(n.unlist(t(2), addr(2), Source::Config).is_empty());
    assert!(back(&n, &q()), "held back with no source");
    let out = n.candidate(t(2), addr(2));
    assert_eq!(admitted(&out), [(q(), Why::Candidate)]);
    probe_on(&out, &q());
    // A report from another source releases it as well.
    let mut n = Node::capable(210);
    let mut log = Log::default();
    given_up(&mut n, &mut log, &q(), Source::Config);
    let out = n.report(t(2), addr(2), Source::Nostr);
    assert_eq!(admitted(&out), [(q(), Why::Candidate)]);
}

#[test]
fn a_candidate_held_back_after_a_discard_is_released_when_its_transport_regains_carrier() {
    let mut n = Node::capable(211);
    let mut log = Log::default();
    given_up(&mut n, &mut log, &q(), Source::Config);
    let at = n.now.0;
    step(&mut n, at + 1, down(2));
    assert!(back(&n, &q()));
    let out = step(
        &mut n,
        at + 2,
        Input::Carrier {
            transport: t(2),
            up: true,
        },
    );
    assert_eq!(admitted(&out), [(q(), Why::Candidate)]);
    probe_on(&out, &q());
    assert_eq!(held(&n), [(q(), false)]);
}

#[test]
fn presence_loss_holds_back_every_candidate_on_its_transport_and_its_return_probes_them() {
    let mut n = Node::capable(212);
    live_path(&mut n, t(2), addr(2), 0xB);
    let far = pair(t(2), addr(5));
    n.candidate(t(2), addr(5));
    let olds = [path(&n, &q()).path_id(), path(&n, &far).path_id()];
    // A third candidate on transport 2 is refused while it is not dialled,
    // and held with no path.
    let spare = pair(t(2), addr(6));
    n.facts.change(t(2), Fact::Dials(false));
    let out = n.candidate(t(2), addr(6));
    assert_eq!(refusals(&out), [(spare.clone(), Refusal::Rule(Rule::Dial))]);
    n.facts.change(t(2), Fact::Dials(true));
    let presence = |present| Input::Present {
        transport: t(2),
        present,
    };
    // The interface leaves: its paths are discarded, as by removal.
    let out = step(&mut n, 10, presence(false));
    assert_eq!(
        states(&out),
        [
            (q(), olds[0], Some(PathState::Live), None, Why::Removed),
            (
                far.clone(),
                olds[1],
                Some(PathState::Probing),
                None,
                Why::Removed
            ),
        ]
    );
    assert_eq!(released(&out).len(), 2);
    assert_eq!(n.b.paths().len(), 1);
    assert_eq!(
        held(&n),
        [(q(), true), (far.clone(), true), (spare.clone(), true)]
    );
    // A repeat while it is away probes nothing.
    assert!(step(&mut n, 15, found(&spare)).is_empty());
    // It comes back: all three are new paths, probed at once.
    let out = step(&mut n, 20, presence(true));
    assert_eq!(
        admitted(&out),
        [
            (q(), Why::Candidate),
            (far.clone(), Why::Candidate),
            (spare.clone(), Why::Candidate)
        ]
    );
    for to in [q(), far.clone(), spare] {
        let id = path(&n, &to).path_id();
        assert!(!olds.contains(&id), "a new identifier");
        assert_eq!(probe_on(&out, &to).path_id, id);
    }
}

#[test]
fn a_path_evicted_to_make_room_is_held_back() {
    let mut n = Node::capable(213);
    n.probe(t(1), addr(2), probe_from(0x12, 1, 27));
    n.probe(t(1), addr(3), probe_from(0x13, 1, 27));
    let gone = pair(t(1), addr(4));
    let i = live_path(&mut n, t(1), addr(4), 0x14);
    n.closed(t(1), addr(4), close_from(n.id(i)));
    let out = n.probe(t(1), addr(5), probe_from(0x15, 1, 27));
    assert_eq!(
        states(&out).first().map(|c| (c.0.clone(), c.4)),
        Some((gone.clone(), Why::Evicted))
    );
    assert!(back(&n, &gone), "{:?}", held(&n));
    // The pairs the peer's probes created, with no entry, are entered
    // only when they are given up.
    assert_eq!(held(&n).len(), 1);
    assert!(n.candidate(t(1), addr(4)).is_empty(), "a repeat");
    assert!(back(&n, &gone));
}

#[test]
fn a_removed_transport_forgets_its_candidates() {
    let mut n = Node::capable(214);
    n.candidate(t(2), addr(2));
    n.candidate(t(3), addr(3));
    n.facts.change(t(2), Fact::Dials(false));
    n.candidate(t(2), addr(5));
    n.facts.change(t(2), Fact::Dials(true));
    assert_eq!(held(&n).len(), 3);
    step(&mut n, 10, gone(2));
    assert_eq!(held(&n), [(r(), false)]);
    // A later report is a first one.
    let out = step(&mut n, 20, found(&pair(t(2), addr(5))));
    assert_eq!(admitted(&out), [(pair(t(2), addr(5)), Why::Candidate)]);
}

#[test]
fn a_fresh_discovery_report_finds_the_peer_again_on_its_transport() {
    let mut n = Node::capable(215);
    let mut log = Log::default();
    let far = pair(t(2), addr(5));
    given_up(&mut n, &mut log, &far, Source::Discovery);
    // An acked path on the same transport, closed by the peer: Dead.
    n.now = TestInstant(n.now.0 + 1);
    live_path(&mut n, t(2), addr(2), 0xB);
    let at = n.now.0 + 1;
    shut(&mut n, at, &q());
    assert_eq!(state(&n, &q()), PathState::Dead);
    // Local discovery reports a new pair on transport 2: the peer is found
    // again there.
    n.now = TestInstant(at + 1);
    let out = n.report(t(2), addr(9), Source::Discovery);
    let revived: Vec<_> = states(&out)
        .into_iter()
        .filter(|c| c.0 == q())
        .map(|c| (c.2, c.3, c.4))
        .collect();
    assert_eq!(
        revived,
        [(Some(PathState::Dead), Some(PathState::Probing), Why::Found)]
    );
    assert_eq!(
        admitted(&out),
        [
            (pair(t(2), addr(9)), Why::Candidate),
            (far.clone(), Why::Candidate)
        ]
    );
    for to in [far.clone(), pair(t(2), addr(9))] {
        probe_on(&out, &to);
    }
    // q keeps the stop it took on becoming Dead, so its first probe waits
    // for the floor's first instant.
    assert!(
        probes(&out).iter().all(|(to, _)| *to != q()),
        "q probed at once: {out:?}"
    );
    assert_eq!(
        path(&n, &q()).live().next_at(),
        Some(TestInstant(at + FLOOR_MIN))
    );
    assert!(!back(&n, &far));
}

#[test]
fn beacons_repeating_for_an_hour_send_nothing_more() {
    let mut n = Node::capable(216);
    let mut log = Log::default();
    given_up(&mut n, &mut log, &q(), Source::Discovery);
    let start = n.now.0;
    for k in 1..=3_600 {
        n.now = TestInstant(start + k * 1_000);
        let out = n.report(t(2), addr(2), Source::Discovery);
        assert!(out.is_empty(), "beacon {k}: {out:?}");
    }
    assert!(back(&n, &q()));
}

#[test]
fn a_disabled_bundle_holds_no_candidate() {
    let mut n = Node::disabled(217);
    for source in [Source::Config, Source::Discovery, Source::Request] {
        n.report(t(2), addr(2), source);
        n.report(t(1), addr(5), source);
    }
    assert!(held(&n).is_empty());
    n.unlist(t(2), addr(2), Source::Config);
    assert!(held(&n).is_empty());
    // Its one path goes with its interface: nothing is held back.
    step(
        &mut n,
        10,
        Input::Present {
            transport: t(1),
            present: false,
        },
    );
    assert!(held(&n).is_empty(), "{:?}", held(&n));
}

#[test]
fn turning_capable_admits_no_candidate_held_back_by_its_interface_leaving() {
    let mut n = Node::new(217);
    n.candidate(t(2), addr(2));
    n.candidate(t(3), addr(3));
    let left = Input::Present {
        transport: t(2),
        present: false,
    };
    step(&mut n, 10, left);
    assert!(back(&n, &q()), "{:?}", held(&n));
    n.now = TestInstant(20);
    let out = n.heard();
    assert!(n.b.capable());
    assert_eq!(admitted(&out), [(r(), Why::Candidate)]);
}

#[test]
fn a_path_the_peer_created_is_held_back_when_its_interface_leaves_and_probed_on_its_return() {
    let mut n = Node::capable(218);
    n.probe(t(2), addr(2), probe_from(peer(&q()), 1, 27));
    path(&n, &q());
    assert!(
        held(&n).is_empty(),
        "no candidate for a path the peer created"
    );
    let presence = |present| Input::Present {
        transport: t(2),
        present,
    };
    step(&mut n, 1_000, presence(false));
    assert!(n.b.paths().find(t(2), &addr(2)).is_none());
    assert_eq!(held(&n), [(q(), true)], "entered with no source");
    let out = step(&mut n, 2_000, presence(true));
    assert_eq!(admitted(&out), [(q(), Why::Candidate)]);
    probe_on(&out, &q());
    assert_eq!(held(&n), [(q(), false)], "kept as the path's");
}

#[test]
fn a_candidate_unlisted_while_held_back_is_forgotten_at_its_release_unless_admitted() {
    let presence = |present| Input::Present {
        transport: t(2),
        present,
    };
    let unlisted = || Input::Unlisted {
        transport: t(2),
        addr: addr(2),
        source: Source::Config,
    };
    // A peer not known to be capable: offered at the interface's return,
    // admitted nowhere and forgotten, so turning capable probes nothing.
    let mut n = Node::new(219);
    n.candidate(t(2), addr(2));
    step(&mut n, 1_000, presence(false));
    step(&mut n, 2_000, unlisted());
    assert_eq!(held(&n), [(q(), true)], "held back with no source");
    step(&mut n, 3_000, presence(true));
    assert!(held(&n).is_empty(), "{:?}", held(&n));
    n.now = TestInstant(4_000);
    let out = n.heard();
    assert!(admitted(&out).is_empty(), "{out:?}");
    // A capable peer: admitted at the return, and kept as the path's.
    let mut n = Node::capable(220);
    n.candidate(t(2), addr(2));
    step(&mut n, 1_000, presence(false));
    step(&mut n, 2_000, unlisted());
    assert_eq!(held(&n), [(q(), true)], "held back with no source");
    let out = step(&mut n, 3_000, presence(true));
    assert_eq!(admitted(&out), [(q(), Why::Candidate)]);
    assert_eq!(held(&n), [(q(), false)]);
}
