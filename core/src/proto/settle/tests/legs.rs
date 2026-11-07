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
        let mut times = Vec::new();
        let mut polls = 0;
        while let Some(wake) = legs.next_wake() {
            polls += 1;
            assert!(polls < 20, "the leg is still held after {polls} wakes");
            for o in release(legs.poll(wake, &mut links)) {
                let LegOut::Resend { link: l, bytes } = o else {
                    unreachable!("reaps are released")
                };
                assert_eq!(
                    (l, bytes.as_slice()),
                    (link, MSG1),
                    "the msg1, byte for byte"
                );
                times.push(wake.0);
                legs.resent(link, wake, &p);
            }
        }
        assert_eq!(times, want, "with a {handshake} s deadline");
    }
}

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
