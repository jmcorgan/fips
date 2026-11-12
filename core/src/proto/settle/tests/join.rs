//! Tests of the join function's routing: what each rekey machine output
//! and each bundle output becomes, where a released path goes, a roam and
//! a bind, the order of a step's outputs, and that a rekey step through it
//! allocates nothing. None of these needs a machine, so none is built.
//! Then its machine calls, on the stub IK profile's keys: a move refused
//! for a setup of another key, a removal, and a start on a link. No switch
//! breaks what these tests guard, so each test's break is a scratch edit
//! of the function, named in the test's doc comment and run by hand.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use super::*;
use crate::proto::path::{Refusal, Switch, Why};
use crate::proto::rekey::tests::stub::{Ik, Local, Mid, Pool, RecvKey, read_msg1};
use crate::proto::rekey::{
    Abandon, EpochTag, EvidenceKind, Layer, Msg1Read, MsgKind, Purpose, Reason, Role, Route, Slot,
    TagSource, Teardown,
};
use crate::testutil::{TestClock, TestEntropy, allocations};

/// A rekey machine output of the stub IK profile.
type Out = rekey::Output<Ik>;

/// A step, as the tests see it.
type Seen = Step<Ik, ()>;

/// The peer the steps are for.
fn peer() -> NodeAddr {
    NodeAddr::from_bytes([2; 16])
}

/// The link the peer is held on.
const LINK: LinkNo = LinkNo(7);

/// The link a path was released from, where the peer moved off it.
const OFF: LinkNo = LinkNo(3);

/// The steps `join` gives for `event`.
fn joined(event: Event<'_, '_, '_, Ik, TestClock, TestEntropy, ()>) -> Vec<Seen> {
    match join(peer(), event) {
        Ok(steps) => steps.collect(),
        Err(lease) => {
            lease.release();
            panic!("only a start is refused")
        }
    }
}

/// The steps for the rekey outputs `out`.
fn rekeyed(out: Vec<Out>) -> Vec<Seen> {
    joined(Event::Rekey { out })
}

/// Release every lease `steps` hand back, as the shell would.
fn freed(steps: Vec<Seen>) {
    for s in steps {
        match s {
            Step::Rekey(rekey::Output::Release(lease)) => {
                lease.release();
            }
            Step::Core(_) | Step::Replace(_) | Step::Rekey(_) | Step::Path(_) => {}
        }
    }
}

/// A step, printed: a core input in full, anything else by its output.
fn shown(s: &Seen) -> String {
    match s {
        Step::Core(i) => format!("core {i:?}"),
        Step::Replace(_) => String::from("replace"),
        Step::Rekey(o) => format!("rekey {o:?}"),
        Step::Path(o) => format!("path {o:?}"),
    }
}

/// An epoch tag.
fn tag() -> EpochTag {
    TagSource::new().draw()
}

/// A msg1 the stub IK machine would ask to have replace the peering.
fn msg1() -> Authentic<<Ik as Profile>::Msg1, Replayable> {
    let (us, them) = (Local::new(1, 1), Local::new(2, 2));
    let (_, wire) = Ik::initiate(&them, &us.key, Some(9)).expect("the stub writes a msg1");
    read_msg1(&us, &wire).expect("the stub reads its own msg1")
}

/// What a rekey output should become, printed as [`shown`] prints it.
enum Want {
    /// A core input.
    Core(In),
    /// A replacement for the core's gates.
    Replace,
    /// The output itself, the shell's own.
    Shell,
}

/// Every rekey machine output this test can build, with what it should
/// become.
fn every_rekey_output() -> Vec<(Out, Want)> {
    let t = tag();
    vec![
        (
            rekey::Output::Send {
                msg: vec![1, 2],
                kind: MsgKind::Msg1,
                route: Route::Arrival,
            },
            Want::Shell,
        ),
        (rekey::Output::Prompt { tag: t }, Want::Shell),
        (
            rekey::Output::Deliver {
                slot: Slot::Current,
                tag: t,
                range: 0..1,
            },
            Want::Shell,
        ),
        (
            rekey::Output::Bind {
                transport: 1,
                index: 4,
                tag: Some(t),
                purpose: Purpose::Current,
            },
            Want::Shell,
        ),
        (
            rekey::Output::Unbind {
                transport: 1,
                index: 4,
            },
            Want::Shell,
        ),
        (
            rekey::Output::Delegate {
                tag: t,
                transport: 1,
                index: 4,
                recv: RecvKey {
                    key: [5; 8],
                    floor: None,
                    highest: None,
                },
            },
            Want::Shell,
        ),
        (
            rekey::Output::Revoke {
                tag: t,
                transport: 1,
                index: 4,
            },
            Want::Shell,
        ),
        (rekey::Output::Release(IndexLease::for_test(4)), Want::Shell),
        (
            rekey::Output::Installed {
                tag: t,
                role: Role::Responder,
                evidence: EvidenceKind::Frame,
            },
            Want::Shell,
        ),
        (rekey::Output::Retired { tag: t }, Want::Shell),
        (rekey::Output::Reverted { tag: t }, Want::Shell),
        (
            rekey::Output::PeerRestarted {
                layer: Layer::Fmp,
                epoch: [6; 8],
            },
            Want::Core(In::Restarted {
                peer: peer(),
                epoch: [6; 8],
            }),
        ),
        (
            rekey::Output::Rekeyed {
                role: Role::Initiator,
            },
            Want::Shell,
        ),
        (
            rekey::Output::ReplaceRequested { tok: msg1() },
            Want::Replace,
        ),
        (rekey::Output::Reject(Reason::Replay), Want::Shell),
        (rekey::Output::Abandoned(Abandon::Unanswered), Want::Shell),
        (
            rekey::Output::Teardown(Teardown::OpeningIdle),
            Want::Core(In::Ended { peer: peer() }),
        ),
    ]
}

/// Each rekey output becomes one step: a restart report and a teardown
/// the core's input for the peer, a replacement request a replacement for
/// the core's gates, and every other output the shell's own, unchanged.
/// Breaks, each a scratch edit of the join function: a teardown routed as
/// the shell's own, and a restart report dropped.
#[test]
fn each_rekey_output_routes_to_the_core_or_the_shell() {
    for (o, want) in every_rekey_output() {
        let before = format!("rekey {o:?}");
        let steps = rekeyed(vec![o]);
        assert_eq!(
            steps.len(),
            1,
            "{before} becomes exactly one step: {:?}",
            steps.iter().map(shown).collect::<Vec<_>>()
        );
        match (&steps[0], want) {
            (Step::Core(got), Want::Core(i)) => {
                assert_eq!(*got, i, "{before} tells the core of this peer")
            }
            (Step::Replace(_), Want::Replace) => {}
            (Step::Rekey(_), Want::Shell) => {
                assert_eq!(shown(&steps[0]), before, "the shell's own, unchanged")
            }
            (got, Want::Core(_) | Want::Replace | Want::Shell) => {
                panic!("{before} routed as {}", shown(got))
            }
        }
        freed(steps);
    }
}

/// A path of the stub transport at `port`.
fn path(port: u16) -> PathRef {
    PathRef {
        transport: TransportId::new(1),
        addr: TransportAddr::from_string(&format!("10.0.0.1:{port}")),
    }
}

/// What the test's bundle holds of a path after the step: the path at
/// port 2 acknowledged and not Live, every other Live.
fn read(p: &PathRef) -> Proven {
    if *p == path(2) {
        Proven::Acked
    } else {
        Proven::Live
    }
}

/// Every bundle output, each with the core input it stands for on `LINK`.
fn every_bundle_output() -> Vec<(path::Output<()>, Option<In>)> {
    let state = |port, next| path::Output::State {
        to: path(port),
        path_id: 1,
        from: Some(PathState::Probing),
        next,
        why: Why::Answered,
    };
    vec![
        (
            path::Output::Send {
                to: path(1),
                bytes: vec![1],
            },
            None,
        ),
        (
            path::Output::Moved {
                from: path(1),
                to: path(3),
                driver: (),
            },
            Some(In::Moved {
                link: LINK,
                from: pair(&path(1)),
                to: pair(&path(3)),
            }),
        ),
        (
            path::Output::Released {
                to: path(4),
                driver: (),
                keep: true,
            },
            Some(In::Released {
                link: LINK,
                pair: pair(&path(4)),
                keep: true,
            }),
        ),
        (
            state(2, Some(PathState::Live)),
            Some(In::State {
                link: LINK,
                pair: pair(&path(2)),
                proven: Proven::Acked,
            }),
        ),
        (
            state(5, Some(PathState::Live)),
            Some(In::State {
                link: LINK,
                pair: pair(&path(5)),
                proven: Proven::Live,
            }),
        ),
        (state(6, None), None),
        (path::Output::Capable, None),
        (path::Output::NotCapable, None),
        (
            path::Output::Refused {
                to: path(1),
                why: Refusal::Full,
            },
            None,
        ),
        (
            path::Output::Switched {
                from: Some(path(1)),
                to: path(5),
                why: Switch::Mandatory,
            },
            Some(In::Switched {
                link: LINK,
                to: pair(&path(5)),
            }),
        ),
        (
            path::Output::Switched {
                from: None,
                to: path(5),
                why: Switch::Handover,
            },
            Some(In::Switched {
                link: LINK,
                to: pair(&path(5)),
            }),
        ),
        (path::Output::Orphaned, Some(In::Orphaned { peer: peer() })),
        (path::Output::Connect { to: path(1) }, None),
        (
            path::Output::Proven {
                to: path(1),
                mtu: 1280,
            },
            None,
        ),
    ]
}

/// The steps for the one bundle output `o`.
fn pathed(o: path::Output<()>, link: Option<LinkNo>, released: Option<LinkNo>) -> Vec<Seen> {
    joined(Event::Paths {
        out: vec![o],
        read: &read,
        link,
        released,
    })
}

/// Each bundle output comes back as itself, followed by the core input it
/// stands for, if any: a state change with the path's proven state read
/// from the bundle after the step, a move, a switch (with the old active
/// path kept or discarded), a release and an orphaning.
/// A discarded path's state change, the capability reports, a refusal, a
/// send and a connect stand for none. Breaks: a move's `from` and `to`
/// swapped; a discarded path's state change mirrored.
#[test]
fn each_bundle_output_mirrors_to_its_input() {
    for (o, want) in every_bundle_output() {
        let before = format!("path {o:?}");
        let steps = pathed(o, Some(LINK), None);
        let got: Vec<String> = steps.iter().map(shown).collect();
        let mut expected = vec![before.clone()];
        expected.extend(want.map(|i| format!("core {i:?}")));
        assert_eq!(got, expected, "{before} and the input it stands for");
    }
}

/// At a removal no link is given, and no bundle output reaches the core:
/// the link's record goes with it. Break: a release routed with no link.
#[test]
fn a_bundle_output_at_a_removal_reaches_no_link() {
    for (o, _) in every_bundle_output() {
        let before = format!("path {o:?}");
        let got: Vec<String> = pathed(o, None, None).iter().map(shown).collect();
        assert_eq!(got, core::slice::from_ref(&before), "{before} at a removal");
    }
}

/// A path released from the link the peer moved off goes to that link,
/// while the step's other outputs go to the link the peer holds. Break:
/// `released` ignored.
#[test]
fn a_released_path_goes_to_the_link_moved_off() {
    let out = vec![
        path::Output::Released {
            to: path(4),
            driver: (),
            keep: false,
        },
        path::Output::State {
            to: path(5),
            path_id: 2,
            from: None,
            next: Some(PathState::Live),
            why: Why::Probed,
        },
    ];
    let cores: Vec<In> = joined(Event::Paths {
        out,
        read: &read,
        link: Some(LINK),
        released: Some(OFF),
    })
    .into_iter()
    .filter_map(|s| match s {
        Step::Core(i) => Some(i),
        Step::Replace(_) | Step::Rekey(_) | Step::Path(_) => None,
    })
    .collect();
    assert_eq!(
        cores,
        [
            In::Released {
                link: OFF,
                pair: pair(&path(4)),
                keep: false,
            },
            In::State {
                link: LINK,
                pair: pair(&path(5)),
                proven: Proven::Live,
            },
        ]
    );
}

/// A one-path roam is the path moved to the frame's pair, and a bind of a
/// bundle holding no path is a Live path there: one core input each, and
/// nothing else. Break: the two swapped.
#[test]
fn a_roam_is_moved_and_a_bind_is_a_live_path() {
    let (from, to) = (pair(&path(1)), pair(&path(2)));
    let roam: Vec<String> = joined(Event::Roam {
        link: LINK,
        from: Some(from.clone()),
        to: to.clone(),
    })
    .iter()
    .map(shown)
    .collect();
    let moved = In::Moved {
        link: LINK,
        from,
        to: to.clone(),
    };
    assert_eq!(roam, [format!("core {moved:?}")], "a roam is a move");
    let bind: Vec<String> = joined(Event::Roam {
        link: LINK,
        from: None,
        to: to.clone(),
    })
    .iter()
    .map(shown)
    .collect();
    let live = In::State {
        link: LINK,
        pair: to,
        proven: Proven::Live,
    };
    assert_eq!(bind, [format!("core {live:?}")], "a bind is a Live path");
}

/// A step's outputs come back in the order the machine gave them, each
/// bundle output's core input right after it. Break: the outputs reversed.
#[test]
fn a_steps_outputs_come_back_in_order() {
    let t = tag();
    let out: Vec<Out> = vec![
        rekey::Output::Reject(Reason::Replay),
        rekey::Output::Teardown(Teardown::CounterExhausted),
        rekey::Output::Retired { tag: t },
        rekey::Output::Abandoned(Abandon::Yielded),
    ];
    let expected = [
        format!("rekey {:?}", out[0]),
        format!("core {:?}", In::Ended { peer: peer() }),
        format!("rekey {:?}", out[2]),
        format!("rekey {:?}", out[3]),
    ];
    let got: Vec<String> = rekeyed(out).iter().map(shown).collect();
    assert_eq!(got, expected, "the rekey machine's order");

    let out = vec![
        path::Output::Moved {
            from: path(1),
            to: path(3),
            driver: (),
        },
        path::Output::Capable,
        path::Output::Orphaned,
    ];
    let expected = [
        format!("path {:?}", out[0]),
        format!(
            "core {:?}",
            In::Moved {
                link: LINK,
                from: pair(&path(1)),
                to: pair(&path(3)),
            }
        ),
        format!("path {:?}", out[1]),
        format!("path {:?}", out[2]),
        format!("core {:?}", In::Orphaned { peer: peer() }),
    ];
    let got: Vec<String> = joined(Event::Paths {
        out,
        read: &read,
        link: Some(LINK),
        released: None,
    })
    .iter()
    .map(shown)
    .collect();
    assert_eq!(got, expected, "the bundle's order");
}

/// The number of steps `join` gives for the rekey outputs `out`, with the
/// allocations made by the call and the walk over its steps.
fn counted(out: Vec<Out>) -> (u32, u64) {
    let before = allocations();
    let mut n = 0;
    if let Ok(steps) = join::<Ik, TestClock, TestEntropy, ()>(peer(), Event::Rekey { out }) {
        for step in steps {
            match step {
                Step::Rekey(_) => n += 1,
                Step::Core(_) | Step::Replace(_) | Step::Path(_) => {}
            }
        }
    }
    (n, allocations() - before)
}

/// A step of the rekey machine through the join function allocates
/// nothing, on the output a refused frame gives and on the one an
/// authentic frame gives, so a frame through it costs no allocation. The
/// counter's own check shows it sees an allocation in this thread. Break:
/// the rekey step's outputs collected into a new vector of steps.
#[test]
fn a_rekey_step_through_join_allocates_nothing() {
    let refused: Vec<Out> = vec![rekey::Output::Reject(Reason::ShortPlaintext)];
    assert_eq!(counted(refused), (1, 0), "a refused frame's step");
    let frame: Vec<Out> = vec![rekey::Output::Deliver {
        slot: Slot::Current,
        tag: tag(),
        range: 0..1,
    }];
    assert_eq!(counted(frame), (1, 0), "an authentic frame's step");
    let before = allocations();
    let v: Vec<u8> = vec![1];
    assert!(allocations() > before, "the counter missed an allocation");
    drop(v);
}

/// A node on the stub IK profile's keys, with the capabilities its rekey
/// machines borrow.
struct Node {
    local: Local,
    pool: Pool,
    tags: TagSource,
    jitter: Mid,
    scratch: Vec<u8>,
}

impl Node {
    /// The node made from `seed`.
    fn new(seed: u8) -> Self {
        Self {
            local: Local::new(seed, seed),
            pool: Pool::new(100),
            tags: TagSource::new(),
            jitter: Mid::default(),
            scratch: Vec::new(),
        }
    }

    /// A rekey machine's `Env` over its capabilities, on the transport
    /// [`path`]'s pairs use.
    fn env(&mut self) -> rekey::Env<'_, Ik> {
        rekey::Env {
            indices: &mut self.pool,
            transport: 1,
            tags: &mut self.tags,
            workers: false,
            jitter: &mut self.jitter,
            local: &self.local,
            scratch: &mut self.scratch,
        }
    }
}

/// Transport facts with every transport clear and Normal, datagram, and
/// accepting and dialling the peer.
struct Clear;

impl path::Facts for Clear {
    fn mtu(&self, _transport: TransportId, _addr: &TransportAddr) -> usize {
        1280
    }

    fn medium(&self, _transport: TransportId, _addr: &TransportAddr) -> path::Medium {
        path::Medium::Unknown
    }

    fn oriented(&self, _transport: TransportId) -> bool {
        false
    }

    fn class(&self, _transport: TransportId) -> path::Class {
        path::Class::Clear
    }

    fn kind(&self, _transport: TransportId) -> Option<path::Kind> {
        None
    }

    fn role(&self, _transport: TransportId) -> path::Role {
        path::Role::Normal
    }

    fn accepts(&self, _transport: TransportId) -> bool {
        true
    }

    fn dials(&self, _transport: TransportId) -> bool {
        true
    }
}

/// A rekey machine of the stub IK profile.
type Machine = Rekey<Ik, TestClock>;

/// A bundle whose driver slots are nothing.
type Paths = Bundle<TestClock, TestEntropy, ()>;

/// The steps of a machine call, as the tests see them.
type Called = Joined<Ik, (), crate::testutil::TestInstant>;

/// A handshake `me` opened to `peer`, completed at `me`'s end: the setup
/// `me`'s rekey machine is built on, its index bound on transport 1, and
/// the replay record of the handshake.
fn handshake(me: &mut Node, peer: &mut Node) -> (Setup<Ik>, Record) {
    let ours = rekey::allocate(&mut me.pool).expect("an index");
    let theirs = rekey::allocate(&mut peer.pool).expect("an index");
    let (state, m1) =
        Ik::initiate(&me.local, &peer.local.key, Some(ours.index())).expect("the stub writes");
    let tok = read_msg1(&peer.local, &m1).expect("the msg1 reads");
    let (_, m2) = tok
        .get()
        .answer(&peer.local, Some(theirs.index()))
        .expect("the stub answers");
    let index = theirs.release();
    peer.pool.free(index);
    let done = Ik::reply(&state, &me.local, &m2)
        .expect("the msg2 reads")
        .done;
    let record = Record::setup(tok.get().digest(), tok.get().ephemeral(), None);
    let setup = Setup {
        done,
        lease: ours,
        theirs: index,
        transport: 1,
    };
    (setup, record)
}

/// Build `me`'s machines for `peer` on `setup` at time 0, its original
/// path [`path`] 1, into the two slots, for a peer held on `link`.
fn started(
    me: &mut Node,
    peer: &Node,
    (setup, record): (Setup<Ik>, Record),
    slots: (&mut Option<Machine>, &mut Option<Paths>),
    link: Option<LinkNo>,
) -> Vec<Seen> {
    let now = crate::testutil::TestInstant(0);
    let facts = rekey::SetupFacts {
        peer_epoch: Some(setup.done.epoch),
        k: false,
        link_since: now,
        started: now,
        peer_k: None,
        last_rx: None,
        record,
    };
    let me_addr = me.local.addr();
    let mut env = me.env();
    let mut caps = Caps {
        params: crate::proto::settle::parity::rekey(false),
        me: me_addr,
        now,
        env: &mut env,
    };
    let to = path(1);
    let start = Event::Start {
        rekey: slots.0,
        bundle: slots.1,
        key: peer.local.key,
        setup,
        facts,
        caps: &mut caps,
        to: (to.transport, to.addr),
        params: crate::proto::settle::parity::path(false),
        env: &path::Env {
            facts: &Clear,
            cost: 1.0,
        },
        link,
    };
    match join(peer.local.addr(), start) {
        Ok(steps) => steps.collect(),
        Err(lease) => {
            lease.release();
            panic!("the setup authenticated the peer's key")
        }
    }
}

/// The core inputs among `steps`.
fn cores(steps: &[Seen]) -> Vec<&In> {
    steps
        .iter()
        .filter_map(|s| match s {
            Step::Core(i) => Some(i),
            Step::Replace(_) | Step::Rekey(_) | Step::Path(_) => None,
        })
        .collect()
}

/// Every lease among `steps` back to `me`'s pool.
fn returned(me: &mut Node, steps: Vec<Seen>) {
    for s in steps {
        match s {
            Step::Rekey(rekey::Output::Release(lease)) => me.pool.free(lease.release()),
            Step::Core(_) | Step::Replace(_) | Step::Rekey(_) | Step::Path(_) => {}
        }
    }
}

/// A rekey machine's every field that can change, printed.
fn state(m: &Machine) -> String {
    let mut s = String::new();
    m.state(&mut s).expect("a string takes the state");
    s
}

/// A start builds the rekey machine and the bundle into their slots, and
/// on a link the core holds it tells the core of the original path as a
/// Live path, after the machine's own outputs, since a new bundle reports
/// nothing; with no link it tells the core nothing. Break, a scratch edit
/// of the join function: the start's core input dropped, which also reds
/// the joint world's mirror oracle at every start.
#[test]
fn a_start_mirrors_the_original_path_as_live() {
    let (mut me, mut b) = (Node::new(1), Node::new(2));
    for link in [Some(LINK), None] {
        let done = handshake(&mut me, &mut b);
        let (mut rekey, mut bundle) = (None, None);
        let steps = started(&mut me, &b, done, (&mut rekey, &mut bundle), link);
        let bundle = bundle.expect("the bundle is built");
        assert!(rekey.is_some(), "the rekey machine is built");
        assert_eq!(
            proven(&bundle, &path(1)),
            Proven::Live,
            "the original path is Live in the bundle"
        );
        let live = In::State {
            link: LINK,
            pair: pair(&path(1)),
            proven: Proven::Live,
        };
        let want: Vec<&In> = link.map(|_| &live).into_iter().collect();
        assert_eq!(cores(&steps), want, "the core is told on {link:?}");
        if link.is_some() {
            assert!(
                matches!(steps.last(), Some(Step::Core(_))),
                "the original path comes after the machine's outputs: {:?}",
                steps.iter().map(shown).collect::<Vec<_>>()
            );
        }
        let (mut slot, mut paths) = (rekey, Some(bundle));
        let stop = Event::Stop {
            rekey: &mut slot,
            bundle: &mut paths,
            why: Close::Admin,
        };
        let closed: Called = match join(b.local.addr(), stop) {
            Ok(steps) => steps,
            Err(_) => unreachable!("only a start is refused"),
        };
        returned(&mut me, closed.collect());
    }
    assert!(me.pool.used.is_empty(), "every index goes back to the pool");
}

/// A move onto a setup that authenticated another key than the one the
/// rekey machine holds builds nothing: the machine goes back in its slot
/// as it was, the bundle is not started again, and the setup's lease comes
/// back as a release, the one step. Break, a scratch edit of the join
/// function: the bundle renewed before the key is compared.
#[test]
fn a_move_refused_for_another_key_leaves_both_machines_as_they_were() {
    let (mut me, mut b, mut c) = (Node::new(1), Node::new(2), Node::new(3));
    let done = handshake(&mut me, &mut b);
    let (mut rekey, mut bundle) = (None, None);
    let steps = started(&mut me, &b, done, (&mut rekey, &mut bundle), Some(LINK));
    returned(&mut me, steps);
    let mut bundle = bundle.expect("the bundle is built");
    let before = (
        state(rekey.as_ref().expect("the rekey machine is built")),
        format!("{bundle:?}"),
    );
    let (other, _) = handshake(&mut me, &mut c);
    let lease = other.lease.index();
    let me_addr = me.local.addr();
    let mut env = me.env();
    let mut caps = Caps {
        params: crate::proto::settle::parity::rekey(false),
        me: me_addr,
        now: crate::testutil::TestInstant(5_000),
        env: &mut env,
    };
    let to = path(2);
    let shift = Event::Shift {
        rekey: &mut rekey,
        bundle: Some(&mut bundle),
        setup: other,
        caps: &mut caps,
        to: (to.transport, to.addr),
        env: &path::Env {
            facts: &Clear,
            cost: 1.0,
        },
    };
    let moved: Called = match join(b.local.addr(), shift) {
        Ok(steps) => steps,
        Err(_) => unreachable!("only a start is refused"),
    };
    assert!(!moved.built, "a setup of another key builds no machine");
    assert!(moved.carry.is_none(), "a refused move carries nothing");
    let steps: Vec<Seen> = moved.collect();
    assert!(
        matches!(
            steps.as_slice(),
            [Step::Rekey(rekey::Output::Release(l))] if l.index() == lease
        ),
        "the one step is the setup's lease released: {:?}",
        steps.iter().map(shown).collect::<Vec<_>>()
    );
    returned(&mut me, steps);
    let after = (
        state(rekey.as_ref().expect("the machine goes back in its slot")),
        format!("{bundle:?}"),
    );
    assert_eq!(after.0, before.0, "the rekey machine is as it was");
    assert_eq!(after.1, before.1, "the bundle is as it was");
}

/// A removal empties both slots, closes the bundle before the rekey
/// machine, and hands back what the rekey machine carried for the node's
/// record store: the peer's startup epoch, the link's age and the replay
/// record. Break, a scratch edit of the join function: what the machine
/// carried dropped.
#[test]
fn a_stop_files_what_the_rekey_machine_carried() {
    let (mut me, mut b) = (Node::new(1), Node::new(2));
    let done = handshake(&mut me, &mut b);
    let epoch = done.0.done.epoch;
    let (mut rekey, mut bundle) = (None, None);
    let steps = started(&mut me, &b, done, (&mut rekey, &mut bundle), Some(LINK));
    returned(&mut me, steps);
    let record = rekey
        .as_ref()
        .expect("the rekey machine is built")
        .memory()
        .1
        .len();
    assert_eq!(record, 1, "precondition: the setup is on record");
    let stop = Event::Stop {
        rekey: &mut rekey,
        bundle: &mut bundle,
        why: Close::Admin,
    };
    let mut stopped: Called = match join(b.local.addr(), stop) {
        Ok(steps) => steps,
        Err(_) => unreachable!("only a start is refused"),
    };
    let carry = stopped.carry.take().expect("the closed machine carried");
    let steps: Vec<Seen> = stopped.collect();
    assert!(
        rekey.is_none() && bundle.is_none(),
        "both slots are emptied"
    );
    assert_eq!(carry.peer_epoch, Some(epoch), "the peer's startup epoch");
    assert_eq!(
        carry.link_since,
        crate::testutil::TestInstant(0),
        "the link's age"
    );
    assert_eq!(carry.record.len(), record, "the replay record");
    let shape: Vec<char> = steps
        .iter()
        .map(|s| match s {
            Step::Path(_) => 'p',
            Step::Rekey(_) => 'r',
            Step::Core(_) | Step::Replace(_) => 'c',
        })
        .collect();
    let first = shape.iter().position(|&c| c == 'r');
    assert!(
        shape.contains(&'p')
            && first.is_some_and(|i| shape[..i].iter().all(|&c| c == 'p'))
            && shape[first.unwrap_or(0)..].iter().all(|&c| c == 'r'),
        "the bundle's outputs, then the rekey machine's, and no core input: {:?}",
        steps.iter().map(shown).collect::<Vec<_>>()
    );
    returned(&mut me, steps);
    assert!(me.pool.used.is_empty(), "every index goes back to the pool");
}
