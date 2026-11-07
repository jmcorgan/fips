//! Path policy in the machine (multipath v1 draft, Section 5.5, and the
//! "Policy allows" conditions of Section 5.6): which candidates are
//! probed, which received probes create or move a path, which Dead paths
//! are probed again, and the link's class and kind, its original path's.
//! Every test drives a `Bundle` through its inputs in the shell, which also
//! checks after every call that no output admits, revives, moves or
//! probes a path against the rules.

use alloc::format;
use alloc::vec::Vec;

use super::shell::*;
use crate::proto::path::{
    Class, Config, Input, Kind, Output, Params, PathRef, PathState, Refusal, Role, Rule, Scope,
    Source, Why,
};
use crate::testutil::TestInstant;
use crate::transport::TransportAddr;

/// Whether `out` sends anything or asks for a connection.
fn sends(out: &[Out]) -> bool {
    out.iter()
        .any(|o| matches!(o, Output::Send { .. } | Output::Connect { .. }))
}

/// The refusal of `to` by `rule`, alone.
fn refused(to: PathRef, rule: Rule) -> [(PathRef, Refusal); 1] {
    [(to, Refusal::Rule(rule))]
}

/// A node with `facts` beside its default original path, made capable by
/// a message.
fn capable(seed: u64, facts: Stub) -> Node {
    let mut n = Node::new(seed).with(facts);
    n.heard();
    n
}

/// Probes on the original path only are answered.
fn only_p(_: u64, to: &PathRef) -> bool {
    *to == p()
}

/// Step `input` at `ms` and log it, then answer at once each probe on the
/// original path as [`handle`] does. Returns the step's outputs.
fn feed(n: &mut Node, log: &mut Log, ms: u64, input: Input) -> Vec<Out> {
    let out = at(n, log, ms, input);
    for (to, probe) in probes(&out) {
        if to == p() {
            let reply = n.ack(to.transport, to.addr.clone(), ack_for(&probe, peer(&to)));
            handle(n, log, reply, &mut only_p);
        }
    }
    out
}

/// A probe from the peer on its path `path_id`, padded as a new path's.
fn padded(path_id: u32, probe_id: u32) -> crate::proto::path::wire::PathProbe {
    probe_from(path_id, probe_id, 1200)
}

#[test]
fn a_candidate_on_another_anonymity_class_is_never_probed() {
    let facts = Stub::default()
        .fact(t(2), Fact::Class(Class::Tor))
        .fact(t(3), Fact::Class(Class::Nym));
    let mut n = capable(201, facts);
    for (on, a) in [(t(2), addr(2)), (t(3), addr(3))] {
        let out = n.candidate(on, a.clone());
        assert_eq!(refusals(&out), refused(pair(on, a), Rule::Class));
        assert!(!sends(&out), "{out:?}");
    }
    assert_eq!(n.b.paths().len(), 1);
    assert_eq!(n.b.next_wake(), None, "nothing is probed or timed");

    // A clear candidate of a link reached over Tor.
    let tor = Stub::default().fact(t(1), Fact::Class(Class::Tor));
    let mut n = Node::on(202, Params::draft(), tor, p());
    assert_eq!(n.b.scope().class, Class::Tor);
    n.heard();
    let out = n.candidate(t(2), addr(2));
    assert_eq!(refusals(&out), refused(q(), Rule::Class));
    assert!(!sends(&out), "{out:?}");
    assert_eq!(n.b.paths().len(), 1);
}

#[test]
fn a_probe_that_would_create_a_path_across_classes_is_not_answered() {
    let facts = || {
        Stub::default()
            .fact(t(2), Fact::Class(Class::Tor))
            .fact(t(3), Fact::Class(Class::Nym))
    };
    for (on, a) in [(t(2), addr(2)), (t(3), addr(3))] {
        let mut n = Node::new(203).with(facts());
        let out = n.probe(on, a.clone(), padded(0xB, 1));
        assert_eq!(refusals(&out), refused(pair(on, a), Rule::Class));
        assert!(sent_acks(&out).is_empty(), "{out:?}");
        assert!(!sends(&out), "{out:?}");
        assert_eq!(n.b.paths().len(), 1);
    }
    // A probe on a clear transport of a link reached over Tor.
    let tor = Stub::default().fact(t(1), Fact::Class(Class::Tor));
    let mut n = Node::on(204, Params::draft(), tor, p());
    let out = n.probe(t(2), addr(2), padded(0xB, 1));
    assert_eq!(refusals(&out), refused(q(), Rule::Class));
    assert!(!sends(&out), "{out:?}");
    assert_eq!(n.b.paths().len(), 1);
}

#[test]
fn with_kinds_unmixed_a_path_of_another_kind_is_neither_probed_nor_created() {
    // A LAN link; transport 2 takes the kind of the peer's address.
    let mut n = capable(205, Stub::default().fact(t(2), Fact::Kind(None)));
    let out = n.candidate(t(2), public(2));
    assert_eq!(refusals(&out), refused(pair(t(2), public(2)), Rule::Kind));
    assert!(!sends(&out), "{out:?}");
    let out = n.probe(t(2), public(3), padded(0xB, 1));
    assert_eq!(refusals(&out), refused(pair(t(2), public(3)), Rule::Kind));
    assert!(!sends(&out), "{out:?}");
    assert_eq!(n.b.paths().len(), 1);
    // A local address on the same transport is of the link's kind.
    let out = n.candidate(t(2), addr(2));
    probe_on(&out, &q());
}

#[test]
fn with_kinds_mixed_a_path_of_another_kind_is_probed() {
    let cfg = Config {
        mix_kinds: true,
        ..Config::draft()
    };
    let params = Params::new(cfg).expect("valid settings");
    let facts = Stub::default()
        .fact(t(2), Fact::Kind(None))
        .fact(t(3), Fact::Kind(Some(Kind::Internet)));
    let mut n = Node::on(206, params, facts, p());
    n.heard();
    let out = n.candidate(t(2), public(2));
    probe_on(&out, &pair(t(2), public(2)));
    assert!(refusals(&out).is_empty(), "{out:?}");
    let out = n.probe(t(3), addr(3), padded(0xC, 1));
    assert_eq!(sent_acks(&out).len(), 1, "{out:?}");
    assert_eq!(n.b.paths().len(), 3);
}

#[test]
fn a_path_takes_the_kind_of_its_address_unless_its_transport_has_one() {
    // A link on a transport fixed Local; transport 2 has no fixed kind,
    // and transport 3 is fixed Local.
    let mut n = capable(207, Stub::default().fact(t(2), Fact::Kind(None)));
    let lan = TransportAddr::from_string("192.168.1.2:2121");
    let wan = TransportAddr::from_string("8.8.8.8:2121");
    let out = n.candidate(t(2), lan.clone());
    probe_on(&out, &pair(t(2), lan));
    let out = n.candidate(t(2), wan.clone());
    assert_eq!(refusals(&out), refused(pair(t(2), wan.clone()), Rule::Kind));
    assert!(!sends(&out), "{out:?}");
    let out = n.candidate(t(3), wan.clone());
    probe_on(&out, &pair(t(3), wan));
    assert_eq!(n.b.paths().len(), 3);
}

#[test]
fn a_probe_on_a_transport_that_would_refuse_the_peers_handshake_creates_no_path() {
    let mut n = Node::new(208).with(Stub::default().fact(t(2), Fact::Accepts(false)));
    let out = n.probe(t(2), addr(2), padded(0xB, 1));
    assert_eq!(refusals(&out), refused(q(), Rule::Accept));
    assert!(!sends(&out), "{out:?}");
    assert!(states(&out).is_empty(), "{out:?}");
    assert_eq!(n.b.paths().len(), 1);
    // The node still dials there: a candidate on it is probed.
    let out = n.candidate(t(2), addr(2));
    probe_on(&out, &q());
}

#[test]
fn a_probe_that_finds_a_held_path_is_answered_whatever_the_accept_fact() {
    // The original path is on a transport that only dials.
    let outbound = Stub::default().fact(t(1), Fact::Accepts(false));
    let mut n = Node::on(209, Params::draft(), outbound, p());
    let out = n.probe(t(1), addr(1), probe_from(0xA, 1, 27));
    let acks = sent_acks(&out);
    assert_eq!(acks.len(), 1, "{out:?}");
    assert_eq!(acks[0].0, p());
    assert_eq!(acks[0].1.echo_path_id, 0xA);
    assert_eq!(n.b.paths().get(0).unwrap().peer_id(), Some(0xA));
    assert!(n.b.capable());
    // A probe from another address on it would create a path, and does
    // not.
    let out = n.probe(t(1), addr(5), padded(0xB, 1));
    assert_eq!(refusals(&out), refused(pair(t(1), addr(5)), Rule::Accept));
    assert_eq!(n.b.paths().len(), 1);
}

#[test]
fn a_candidate_on_a_transport_we_would_not_dial_is_never_probed() {
    let mut n = capable(210, Stub::default().fact(t(2), Fact::Dials(false)));
    let out = n.candidate(t(2), addr(2));
    assert_eq!(refusals(&out), refused(q(), Rule::Dial));
    assert!(!sends(&out), "{out:?}");
    assert_eq!(n.b.paths().len(), 1);
    assert_eq!(n.b.next_wake(), None);
}

#[test]
fn a_transport_whose_role_is_never_carries_no_path() {
    let mut n = capable(211, Stub::default().fact(t(2), Fact::Role(Role::Never)));
    let out = n.candidate(t(2), addr(2));
    assert_eq!(refusals(&out), refused(q(), Rule::Role));
    assert!(!sends(&out), "{out:?}");
    let out = n.probe(t(2), addr(3), padded(0xB, 1));
    assert_eq!(refusals(&out), refused(pair(t(2), addr(3)), Rule::Role));
    assert!(!sends(&out), "{out:?}");
    assert_eq!(n.b.paths().len(), 1);
}

#[test]
fn a_probe_that_would_move_a_path_to_another_kind_is_refused_and_moves_nothing() {
    // Two paths, the second Live on transport 2, which from now on takes
    // the kind of the peer's address.
    let mut n = two(212);
    n.facts.change(t(2), Fact::Kind(None));
    let out = n.probe(t(2), public(2), padded(peer(&q()), 7));
    assert_eq!(refusals(&out), refused(pair(t(2), public(2)), Rule::Kind));
    assert!(moved(&out).is_empty(), "{out:?}");
    assert!(!sends(&out), "{out:?}");
    assert_eq!(
        state(&n, &q()),
        PathState::Live,
        "still held at its address"
    );
    // A local address on it is of the link's kind: the path moves there.
    let out = n.probe(t(2), addr(7), padded(peer(&q()), 8));
    assert_eq!(moved(&out).len(), 1, "{out:?}");
    assert_eq!(sent_acks(&out).len(), 1, "{out:?}");
}

#[test]
fn the_original_path_moves_to_a_new_address_whatever_the_rules() {
    // The peer's identifier for the original path is learned from its
    // probe; then the original's transport is set never to carry paths.
    let mut n = two(214);
    n.probe(t(1), addr(1), padded(peer(&p()), 1));
    assert_eq!(path(&n, &p()).peer_id(), Some(peer(&p())));
    n.facts.change(t(1), Fact::Role(Role::Never));
    let out = n.probe(t(1), addr(9), padded(peer(&p()), 2));
    assert!(refusals(&out).is_empty(), "{out:?}");
    assert_eq!(moved(&out).len(), 1, "{out:?}");
    assert_eq!(sent_acks(&out).len(), 1, "{out:?}");
    path(&n, &pair(t(1), addr(9)));
}

#[test]
fn an_ack_from_an_address_the_rules_refuse_counts_but_moves_nothing() {
    // The second path made Suspect by carrier loss, then its next probe
    // answered from an Internet address on transport 2.
    let mut n = two(213);
    n.facts.change(t(2), Fact::Kind(None));
    let mut log = Log::default();
    at(&mut n, &mut log, 100, down(2));
    assert_eq!(state(&n, &q()), PathState::Suspect);
    while !log
        .probes
        .iter()
        .any(|(at, to, _)| *at >= 100 && *to == q())
    {
        let out = n.tick(TestInstant(10_000)).expect("a wake");
        handle(&mut n, &mut log, out, &mut only_p);
    }
    let (_, _, probe) = log
        .probes
        .iter()
        .rev()
        .find(|(_, to, _)| *to == q())
        .cloned()
        .expect("a probe on the second path");
    let out = n.ack(t(2), public(2), ack_for(&probe, peer(&q())));
    assert!(moved(&out).is_empty(), "{out:?}");
    assert!(refusals(&out).is_empty(), "{out:?}");
    assert_eq!(state(&n, &q()), PathState::Live, "the answer still counts");
}

#[test]
fn the_links_class_and_kind_are_its_original_paths() {
    // A link made on a public address of a transport with no fixed kind.
    let facts = Stub::default()
        .fact(t(1), Fact::Kind(None))
        .fact(t(2), Fact::Kind(None));
    let mut n = Node::on(214, Params::draft(), facts, pair(t(1), public(1)));
    assert_eq!(
        n.b.scope(),
        Scope {
            class: Class::Clear,
            kind: Kind::Internet
        }
    );
    n.heard();
    let out = n.candidate(t(2), addr(2));
    assert_eq!(refusals(&out), refused(q(), Rule::Kind));
    let out = n.candidate(t(2), public(2));
    probe_on(&out, &pair(t(2), public(2)));
}

#[test]
fn a_refused_probe_still_makes_the_peer_capable() {
    let mut n = Node::new(215).with(Stub::default().fact(t(2), Fact::Role(Role::Never)));
    let out = n.probe(t(2), addr(2), padded(0xB, 1));
    assert!(n.b.capable());
    assert!(matches!(out.first(), Some(Output::Capable)), "{out:?}");
    assert_eq!(refusals(&out), refused(q(), Rule::Role));
}

#[test]
fn a_dead_path_on_a_transport_we_would_not_dial_is_revived_only_by_the_peers_probe() {
    // Transport 2 accepts the peer's handshake and does not dial it.
    let mut n = Node::new(216).with(Stub::default().fact(t(2), Fact::Dials(false)));
    let mut log = Log::default();
    // The peer's probe creates the path; ours on it is answered.
    let created = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: padded(0xB, 1),
    };
    let out = at(&mut n, &mut log, 0, created);
    handle(&mut n, &mut log, out, &mut all);
    assert_eq!(state(&n, &q()), PathState::Live);
    // Closed by the peer, it is Dead, acked and held.
    let close = Input::Close {
        transport: t(2),
        addr: addr(2),
        msg: close_from(path(&n, &q()).path_id()),
    };
    feed(&mut n, &mut log, 1_000, close);
    assert_eq!(state(&n, &q()), PathState::Dead);
    // Carrier's return on its transport.
    let up = Input::Carrier {
        transport: t(2),
        up: true,
    };
    feed(&mut n, &mut log, 2_000, up);
    assert_eq!(state(&n, &q()), PathState::Dead);
    // A candidate report of its pair.
    let report = Input::Candidate {
        transport: t(2),
        addr: addr(2),
        source: Source::Config,
    };
    let out = feed(&mut n, &mut log, 3_000, report);
    assert_eq!(refusals(&out), refused(q(), Rule::Dial));
    assert_eq!(state(&n, &q()), PathState::Dead);
    // Minutes of polls, past many rounds of the Dead cadence.
    run(&mut n, &mut log, 240_000, &mut only_p);
    assert_eq!(state(&n, &q()), PathState::Dead);
    // The active path leaving Live with nothing Live.
    feed(&mut n, &mut log, 241_000, down(1));
    run(&mut n, &mut log, 245_000, &mut only_p);
    let left = log.changes(&p());
    assert!(
        left.iter()
            .any(|c| c.0 == 241_000 && c.2 == Some(PathState::Suspect)),
        "{left:?}"
    );
    let late: Vec<u64> = log.on(&q()).into_iter().filter(|at| *at >= 1_000).collect();
    assert!(late.is_empty(), "the Dead path was probed at {late:?}");
    assert_eq!(state(&n, &q()), PathState::Dead);
    // The peer's probe brings it back, answered, and it is probed at once:
    // the node accepts the peer there, so the probe could create the path
    // (Section 5.6, the Dead row for a probe received and accepted).
    let revived = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: padded(0xB, 2),
    };
    let out = at(&mut n, &mut log, 246_000, revived);
    assert_eq!(state(&n, &q()), PathState::Probing);
    assert_eq!(sent_acks(&out).len(), 1, "{out:?}");
    let back = log.changes(&q());
    assert_eq!(
        back.last().map(|c| (c.1, c.2, c.3)),
        Some((Some(PathState::Dead), Some(PathState::Probing), Why::Probed))
    );
    probe_on(&out, &q());
}

#[test]
fn the_original_path_is_probed_when_dead_whatever_the_dial_fact() {
    // The original path is on a transport that does not dial the peer.
    let undialled = Stub::default().fact(t(1), Fact::Dials(false));
    let mut n = Node::on(217, Params::draft(), undialled, p());
    n.heard();
    live_path(&mut n, t(2), addr(2), peer(&q()));
    let mut log = Log::default();
    let out = shut(&mut n, 100, &p());
    log.add(n.now, &out);
    assert_eq!(state(&n, &p()), PathState::Dead);
    let mut only_q = |_: u64, to: &PathRef| *to == q();
    run(&mut n, &mut log, 10_000, &mut only_q);
    let dead = log.on(&p());
    assert!(!dead.is_empty(), "the Dead original path was never probed");
}

#[test]
fn a_dead_path_is_brought_back_by_the_peers_probe_only_where_that_probe_could_create_it() {
    // q is Dead by the peer's close. Then t2 dials the peer or not, and
    // accepts it or not; neither is as for a peer the ACL denies. The
    // peer's probe on q is answered whatever the rules (Section 5.1, step
    // 2). It brings q back to Probing, probed at once, only where a probe
    // from q's pair could create a path, the node accepting the peer there,
    // whether or not it dials it (Section 5.6, the Dead row for a probe
    // received and accepted, "Policy allows" read as for creating a path).
    for (dials, accepts) in [(false, false), (true, true), (false, true), (true, false)] {
        let case = format!("dials {dials}, accepts {accepts}");
        let mut n = two(218);
        let mut log = Log::default();
        run(&mut n, &mut log, 999, &mut all);
        let close = Input::Close {
            transport: t(2),
            addr: addr(2),
            msg: close_from(path(&n, &q()).path_id()),
        };
        at(&mut n, &mut log, 1_000, close);
        assert_eq!(state(&n, &q()), PathState::Dead, "precondition: q Dead");
        n.facts.change(t(2), Fact::Dials(dials));
        n.facts.change(t(2), Fact::Accepts(accepts));
        run(&mut n, &mut log, 5_000, &mut only_p);
        let found = Input::Probe {
            transport: t(2),
            addr: addr(2),
            msg: padded(0xB, 7),
        };
        let out = at(&mut n, &mut log, 5_000, found);
        assert_eq!(sent_acks(&out).len(), 1, "{case}: {out:?}");
        let ours = probes(&out).iter().filter(|(to, _)| *to == q()).count();
        if accepts {
            assert_eq!(state(&n, &q()), PathState::Probing, "{case}");
            assert_eq!(ours, 1, "{case}: q revived and probed at once: {out:?}");
            continue;
        }
        assert_eq!(state(&n, &q()), PathState::Dead, "{case}: q stays Dead");
        assert!(states(&out).iter().all(|c| c.0 != q()), "{case}: {out:?}");
        if dials {
            // Its Dead cadence goes on.
            continue;
        }
        assert_eq!(ours, 0, "q probed in the step of the peer's probe: {out:?}");
        run(&mut n, &mut log, 40_000, &mut only_p);
        let after: Vec<u64> = log.on(&q()).into_iter().filter(|at| *at >= 5_000).collect();
        assert!(after.is_empty(), "q probed at {after:?}");
        assert_eq!(state(&n, &q()), PathState::Dead);
    }
}

#[test]
fn the_original_path_is_brought_back_by_the_peers_probe_whatever_the_rules() {
    // The original path's transport neither dials nor accepts the peer, as
    // for a peer the ACL denies.
    let denied = Stub::default()
        .fact(t(1), Fact::Dials(false))
        .fact(t(1), Fact::Accepts(false));
    let mut n = Node::on(221, Params::draft(), denied, p());
    n.heard();
    live_path(&mut n, t(2), addr(2), peer(&q()));
    let mut log = Log::default();
    let out = shut(&mut n, 100, &p());
    log.add(n.now, &out);
    assert_eq!(state(&n, &p()), PathState::Dead, "precondition: p Dead");
    let found = Input::Probe {
        transport: t(1),
        addr: addr(1),
        msg: probe_from(0xA, 1, 27),
    };
    let out = at(&mut n, &mut log, 200, found);
    assert_eq!(sent_acks(&out).len(), 1, "{out:?}");
    assert_eq!(state(&n, &p()), PathState::Probing, "p brought back");
    probe_on(&out, &p());
}

#[test]
fn an_early_probe_asked_for_on_a_dead_path_goes_only_where_policy_allows() {
    // As above, a path on a transport that does not dial the peer, created
    // by the peer's probe, answered, then closed by the peer: Dead and
    // acked, so its at-once probe would otherwise go (Section 5.6).
    let mut n = Node::new(219).with(Stub::default().fact(t(2), Fact::Dials(false)));
    let mut log = Log::default();
    let created = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: padded(0xB, 1),
    };
    let out = at(&mut n, &mut log, 0, created);
    handle(&mut n, &mut log, out, &mut all);
    assert_eq!(state(&n, &q()), PathState::Live);
    let close = Input::Close {
        transport: t(2),
        addr: addr(2),
        msg: close_from(path(&n, &q()).path_id()),
    };
    feed(&mut n, &mut log, 1_000, close);
    assert_eq!(state(&n, &q()), PathState::Dead);
    assert!(path(&n, &q()).acked(), "precondition: q acked");
    // t2 now also refuses the peer's handshake, so the peer's probes on q
    // leave it Dead. The peer marks q ACTIVE, then clears it, which asks
    // for a probe at once; policy does not let this node probe q.
    n.facts.change(t(2), Fact::Accepts(false));
    let set = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: marked(0xB, 2, true),
    };
    feed(&mut n, &mut log, 2_000, set);
    assert_eq!(
        state(&n, &q()),
        PathState::Dead,
        "the peer's probe left q Dead"
    );
    let clear = Input::Probe {
        transport: t(2),
        addr: addr(2),
        msg: marked(0xB, 3, false),
    };
    let out = feed(&mut n, &mut log, 2_050, clear);
    assert_eq!(sent_acks(&out).len(), 1, "{out:?}");
    let ours = probes(&out).iter().filter(|(to, _)| *to == q()).count();
    assert_eq!(ours, 0, "q probed at once against path policy: {out:?}");
    assert_eq!(state(&n, &q()), PathState::Dead);
    assert!(path(&n, &q()).acked());
}

#[test]
fn a_working_standby_is_still_probed_after_the_node_stops_dialling_its_transport() {
    // q is a Live standby; then t2 stops dialling the peer. Path policy
    // governs probing a Dead path again (Section 5.6), so q's routine
    // checks go on while it is Live and Suspect, and stop once it is Dead.
    let mut n = two(220);
    let mut log = Log::default();
    n.facts.change(t(2), Fact::Dials(false));
    run(&mut n, &mut log, 5_000, &mut all);
    assert_eq!(state(&n, &q()), PathState::Live);
    let live = log.on(&q()).len();
    assert!(live >= 4, "standby probes on q in 5 s: {live}");
    // Answers on q stop.
    run(&mut n, &mut log, 60_000, &mut only_p);
    let changes = log.changes(&q());
    let when = |s: PathState| {
        changes
            .iter()
            .find(|c| c.2 == Some(s))
            .map(|c| c.0)
            .unwrap_or_else(|| panic!("q never {s:?}: {changes:?}"))
    };
    let (suspect, dead) = (when(PathState::Suspect), when(PathState::Dead));
    let on = log.on(&q());
    assert!(
        on.iter().any(|at| *at > suspect && *at <= dead),
        "q not probed while Suspect ({suspect} to {dead} ms): {on:?}"
    );
    let after: Vec<u64> = on.into_iter().filter(|at| *at > dead).collect();
    assert!(after.is_empty(), "q probed once Dead: {after:?}");
}
