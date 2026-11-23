//! Tests of the handshake legs: deadlines, the resend schedule, the stored
//! answer, the poll's timing, a deadline at the end of the clock, and the
//! leases.

use alloc::vec::Vec;

use super::*;
use crate::proto::rekey::leaked;
use crate::proto::settle::links::{Dir, Holder};
use crate::testutil::TestInstant;
use crate::transport::{TransportAddr, TransportId};

fn pair(port: u16) -> Pair {
    Pair {
        transport: TransportId::new(1),
        addr: TransportAddr::from_string(&alloc::format!("10.0.0.1:{port}")),
    }
}

fn peer() -> NodeAddr {
    NodeAddr::from_bytes([2; 16])
}

fn t(ms: u64) -> TestInstant {
    TestInstant(ms)
}

const MSG1: &[u8] = b"msg1 of the dial";
const MSG2: &[u8] = b"msg2 of the answer";

/// A leg's start on `link`, holding a lease on `index`.
fn start(link: LinkNo, peer: Option<NodeAddr>, index: u32) -> Start {
    Start {
        link,
        peer,
        msg1: MSG1.to_vec(),
        lease: IndexLease::for_test(index),
        resends: None,
        held: None,
    }
}

/// A dial leg on a new link at `port`, started at `at`.
fn dialed(
    legs: &mut Legs<TestInstant>,
    links: &mut Links,
    port: u16,
    at: u64,
    params: &Params,
) -> LinkNo {
    let link = links.open(pair(port), Dir::Outbound, Holder::Leg);
    let old = legs.dial(start(link, Some(peer()), u32::from(port)), t(at), params);
    assert!(old.is_none(), "precondition: a new link holds no leg");
    link
}

/// Release every lease `out` returns.
fn release(out: Vec<LegOut>) -> Vec<LegOut> {
    out.into_iter()
        .filter_map(|o| match o {
            LegOut::Reaped { lease, .. } => {
                lease.release();
                None
            }
            LegOut::Resend { .. } => Some(o),
        })
        .collect()
}

/// Records current behaviour (rule S-52: the 30 s deadline): open to change by decision. Its
/// other assertions are not.
#[test]
fn a_dial_leg_is_reaped_at_its_deadline_and_returns_its_lease() {
    let p = Params::default();
    let mut links = Links::new();
    let mut legs = Legs::new();
    let link = dialed(&mut legs, &mut links, 5, 0, &p);
    let early = legs.poll(t(29_999), &mut links);
    assert!(
        early.iter().all(|o| matches!(o, LegOut::Resend { .. })),
        "nothing is reaped before the deadline"
    );
    let mut out = legs.poll(t(30_000), &mut links);
    let Some(LegOut::Reaped {
        link: l,
        peer: who,
        dialed,
        closes,
        lease,
    }) = out.pop()
    else {
        panic!("the leg is reaped at 30 s, got {out:?}");
    };
    assert_eq!((l, who, dialed), (link, Some(peer()), true));
    assert_eq!(
        closes,
        [pair(5)],
        "its link is retired and its connection closed"
    );
    assert_eq!(lease.release(), 5, "the lease comes back");
    assert!(links.get(link).is_none() && legs.get(link).is_none());
}

/// Run the dial leg on `link` to its end, polling at each wake and
/// reporting each resend sent there, and return the instants of its
/// resends. Each resend must repeat the msg1 byte for byte.
fn resends(legs: &mut Legs<TestInstant>, links: &mut Links, link: LinkNo, p: &Params) -> Vec<u64> {
    let mut times = Vec::new();
    let mut polls = 0;
    while let Some(wake) = legs.next_wake() {
        polls += 1;
        assert!(polls < 20, "the leg is still held after {polls} wakes");
        for o in release(legs.poll(wake, links)) {
            let LegOut::Resend { link: l, bytes } = o else {
                unreachable!("reaps are released")
            };
            assert_eq!(
                (l, bytes.as_slice()),
                (link, MSG1),
                "the msg1, byte for byte"
            );
            times.push(wake.0);
            legs.resent(link, wake, p);
        }
    }
    times
}

/// Records current behaviour (rules S-47 and S-54: the resend times and count): open to change
/// by decision. Its other assertions are not.
#[test]
fn resends_follow_the_backoff_and_repeat_the_msg1_byte_for_byte() {
    // Run to the end at each wake: within the 30 s deadline the resends
    // fall at 1, 3, 7 and 15 s; with a longer deadline the fifth at 31 s
    // is the last.
    for (handshake, want) in [
        (30, alloc::vec![1_000, 3_000, 7_000, 15_000]),
        (60, alloc::vec![1_000, 3_000, 7_000, 15_000, 31_000]),
    ] {
        let p = Params {
            handshake: Duration::from_secs(handshake),
            ..Params::default()
        };
        let mut links = Links::new();
        let mut legs = Legs::new();
        let link = dialed(&mut legs, &mut links, 6, 0, &p);
        let times = resends(&mut legs, &mut links, link, &p);
        assert_eq!(times, want, "with a {handshake} s deadline");
    }
}

/// Records current behaviour (rule S-47: the resend waits): open to change by decision. Its
/// other assertions are not.
#[test]
fn a_configured_multiplier_spaces_the_resends_as_the_node_truncates_them() {
    // The node's schedule: the first resend one interval after the dial,
    // and after the n-th the interval times the multiplier to the n-th
    // power, truncated to the millisecond. At 1.3333 the waits are 1333,
    // 1777, 2370 and 3160 ms; doubling would give 2, 4, 8 and 16 s.
    for (multiplier, want) in [
        (1.3333, alloc::vec![1_000, 2_333, 4_110, 6_480, 9_640]),
        (1.5, alloc::vec![1_000, 2_500, 4_750, 8_125, 13_187]),
        (2.0, alloc::vec![1_000, 3_000, 7_000, 15_000, 31_000]),
        (2.5005, alloc::vec![1_000, 3_500, 9_752, 25_386, 64_479]),
    ] {
        let p = Params {
            handshake: Duration::from_secs(120),
            backoff: f64::to_bits(multiplier),
            ..Params::default()
        };
        let mut links = Links::new();
        let mut legs = Legs::new();
        let link = dialed(&mut legs, &mut links, 6, 0, &p);
        let times = resends(&mut legs, &mut links, link, &p);
        assert_eq!(
            times, want,
            "defect: at a multiplier of {multiplier} the resends are not where the node sends them"
        );
    }
}

#[test]
fn a_dials_first_resend_comes_a_second_after_its_msg1_whatever_the_configured_interval() {
    // The node arms a dial's first resend a second after its msg1, whatever
    // the configured interval, and spaces the later ones from the configured
    // interval: after the n-th, the interval times the multiplier to the
    // n-th power.
    for (interval, want) in [
        (500, alloc::vec![1_000, 2_000, 4_000, 8_000, 16_000]),
        (1_000, alloc::vec![1_000, 3_000, 7_000, 15_000, 31_000]),
        (3_000, alloc::vec![1_000, 7_000, 19_000, 43_000, 91_000]),
    ] {
        let p = Params {
            handshake: Duration::from_secs(120),
            resend: Duration::from_millis(interval),
            ..Params::default()
        };
        let mut links = Links::new();
        let mut legs = Legs::new();
        let link = dialed(&mut legs, &mut links, 6, 0, &p);
        let times = resends(&mut legs, &mut links, link, &p);
        assert_eq!(
            times, want,
            "defect: at a resend interval of {interval} ms the resends are not where the node sends them"
        );
    }
}

#[test]
fn an_mdns_directed_dial_stops_at_its_resend_cap() {
    // Configured for eight resends, with a deadline past all of them. The
    // node caps a dial an mDNS advert directs at an unconfigured node at
    // five (`DISCOVERY_RESENDS`, as `Start.resends`), which never raises
    // the configured count.
    let p = Params {
        handshake: Duration::from_secs(600),
        resends: 8,
        ..Params::default()
    };
    let all = alloc::vec![
        1_000, 3_000, 7_000, 15_000, 31_000, 63_000, 127_000, 255_000
    ];
    for (cap, want) in [(Some(5), &all[..5]), (None, &all[..]), (Some(10), &all[..])] {
        let mut links = Links::new();
        let mut legs = Legs::new();
        let link = links.open(pair(6), Dir::Outbound, Holder::Leg);
        let start = Start {
            resends: cap,
            ..start(link, Some(peer()), 6)
        };
        assert!(legs.dial(start, t(0), &p).is_none());
        let times = resends(&mut legs, &mut links, link, &p);
        assert_eq!(
            times, want,
            "defect: a dial capped at {cap:?} resends is not stopped at its cap"
        );
    }
}

/// Records current behaviour (rule S-52: the 30 s deadline): open to change by decision. Its
/// other assertions are not.
#[test]
fn a_responder_leg_answers_a_resend_with_its_stored_msg2_and_is_reclaimed() {
    let p = Params::default();
    let mut links = Links::new();
    let mut legs = Legs::new();
    let link = links.open(pair(7), Dir::Inbound, Holder::Leg);
    let old = legs.answer(start(link, Some(peer()), 7), MSG2.to_vec(), t(0), &p);
    assert!(old.is_none());
    assert_eq!(
        legs.stored(link, MSG1),
        Some(MSG2),
        "the stored msg2, byte for byte"
    );
    assert_eq!(
        legs.stored(link, b"another msg1"),
        None,
        "only for its own msg1"
    );
    assert!(
        release(legs.poll(t(29_999), &mut links)).is_empty(),
        "no resend of a msg2"
    );
    assert!(legs.get(link).is_some(), "held until its deadline");
    let out = legs.poll(t(30_000), &mut links);
    assert!(
        matches!(out.as_slice(), [LegOut::Reaped { dialed: false, .. }]),
        "reclaimed at its deadline, got {out:?}"
    );
    release(out);
}

#[test]
fn a_poll_before_the_next_wake_does_nothing() {
    let p = Params::default();
    let mut links = Links::new();
    let mut legs = Legs::new();
    let link = dialed(&mut legs, &mut links, 8, 0, &p);
    assert_eq!(
        legs.next_wake(),
        Some(t(1_000)),
        "precondition: the first resend"
    );
    assert!(legs.poll(t(999), &mut links).is_empty());
    assert_eq!(
        legs.poll(t(1_000), &mut links).len(),
        1,
        "precondition: due at it"
    );
    legs.resent(link, t(1_000), &p);
    assert_eq!(legs.next_wake(), Some(t(3_000)));
    assert!(legs.poll(t(2_999), &mut links).is_empty());
    let closed = legs.close(&mut links);
    closed.leases.into_iter().for_each(|l| {
        l.release();
    });
}

/// An instant whose range ends at 65.535 s.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Short(u16);

impl Instant for Short {
    fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_millis(u64::from(self.0.saturating_sub(earlier.0)))
    }

    fn checked_add(self, d: Duration) -> Option<Self> {
        let ms = u16::try_from(d.as_millis()).ok()?;
        self.0.checked_add(ms).map(Self)
    }

    fn checked_sub(self, d: Duration) -> Option<Self> {
        let ms = u16::try_from(d.as_millis()).ok()?;
        self.0.checked_sub(ms).map(Self)
    }
}

#[test]
fn a_deadline_past_the_end_of_the_clock_saturates() {
    let p = Params::default();
    let mut links = Links::new();
    let mut legs: Legs<Short> = Legs::new();
    let link = links.open(pair(9), Dir::Outbound, Holder::Leg);
    let old = legs.dial(start(link, None, 9), Short(60_000), &p);
    assert!(old.is_none());
    let end = legs.get(link).map(Leg::deadline).expect("the leg is held");
    assert!(
        end > Short(60_000),
        "the deadline still lies ahead, at {end:?}"
    );
    let out = legs.poll(Short(u16::MAX), &mut links);
    let reaped = out
        .into_iter()
        .filter_map(|o| match o {
            LegOut::Reaped { lease, .. } => Some(lease.release()),
            LegOut::Resend { .. } => None,
        })
        .count();
    assert_eq!(reaped, 1, "reaped at the end of the clock");
}

#[test]
fn close_returns_every_lease_and_retires_every_link() {
    let before = leaked();
    let p = Params::default();
    let mut links = Links::new();
    let mut legs = Legs::new();
    dialed(&mut legs, &mut links, 10, 0, &p);
    dialed(&mut legs, &mut links, 11, 0, &p);
    let link = links.open(pair(12), Dir::Inbound, Holder::Leg);
    let old = legs.answer(start(link, None, 12), MSG2.to_vec(), t(0), &p);
    assert!(old.is_none());
    let closed = legs.close(&mut links);
    let mut got: Vec<u32> = closed.leases.into_iter().map(IndexLease::release).collect();
    got.sort_unstable();
    assert_eq!(got, [10, 11, 12], "every lease");
    assert!(links.index().is_empty(), "every link retired");
    drop(legs);
    assert_eq!(leaked(), before, "no lease leaked");
}

#[test]
fn a_quieted_dial_resends_nothing_more_and_is_still_reaped_at_its_deadline() {
    let p = Params::default();
    let mut links = Links::new();
    let mut legs = Legs::new();
    let link = dialed(&mut legs, &mut links, 11, 0, &p);
    legs.unsent(link, t(500), &p);
    legs.quiet(link);
    assert!(
        release(legs.poll(t(29_999), &mut links)).is_empty(),
        "defect: a quieted dial was resent"
    );
    assert_eq!(legs.get(link).map(Leg::sent), Some(0));
    let out = legs.poll(t(30_000), &mut links);
    assert!(
        matches!(out.as_slice(), [LegOut::Reaped { dialed: true, .. }]),
        "reaped at its deadline, got {out:?}"
    );
    release(out);
}

#[test]
fn the_resends_alone_ask_for_each_due_resend_byte_for_byte_and_reap_no_leg_past_its_deadline() {
    let p = Params::default();
    let mut links = Links::new();
    let mut legs = Legs::new();
    let link = dialed(&mut legs, &mut links, 13, 0, &p);
    assert!(
        legs.resends(t(999)).is_empty(),
        "defect: a resend was asked for before it was due"
    );
    assert_eq!(
        legs.resends(t(1_000)),
        [LegOut::Resend {
            link,
            bytes: MSG1.to_vec(),
        }],
        "defect: the due resend is not the dial's msg1, byte for byte"
    );
    assert_eq!(
        legs.resends(t(30_000)),
        [LegOut::Resend {
            link,
            bytes: MSG1.to_vec(),
        }],
        "still due at the deadline, which only a reap acts on"
    );
    assert!(legs.get(link).is_some(), "no leg is reaped");
    assert_eq!(links.index().len(), 1, "no link is retired");
    let closed = legs.close(&mut links);
    closed.leases.into_iter().for_each(|l| {
        l.release();
    });
}
