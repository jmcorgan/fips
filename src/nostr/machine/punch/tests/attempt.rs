//! The punch attempt on a test instant of whole milliseconds, with Unix time
//! at C.1's time of publication.

use super::super::super::tests::TestInstant;
use super::*;

const SESSION: &str = "1830297600000-0123456789abcdef";
const T0_MS: u64 = 1_830_297_600_000;

fn addr(text: &str) -> SocketAddr {
    text.parse().unwrap()
}

/// The two planned targets the tests punch.
fn targets() -> Vec<SocketAddr> {
    vec![addr("198.51.100.10:40000"), addr("203.0.113.20:50000")]
}

/// A hint starting `delay_ms` from now, probing every `interval_ms` for
/// `duration_ms`.
fn hint(delay_ms: u64, interval_ms: u64, duration_ms: u64) -> PunchHint {
    PunchHint {
        start_at_ms: T0_MS + delay_ms,
        interval_ms,
        duration_ms,
    }
}

/// An attempt started at 0 with a 10 s timeout, probing at once every
/// 200 ms for 10 s.
fn attempt() -> Attempt<TestInstant> {
    Attempt::new(
        SESSION,
        targets(),
        &hint(0, 200, 10_000),
        Duration::from_secs(10),
        TestInstant(0),
        T0_MS,
    )
    .unwrap()
}

fn probe(sequence: u32) -> Vec<u8> {
    build_punch_packet(PunchPacketKind::Probe, sequence, SESSION).to_vec()
}

fn ack(sequence: u32) -> Vec<u8> {
    build_punch_packet(PunchPacketKind::Ack, sequence, SESSION).to_vec()
}

/// Run every deadline up to `until`, and return each step's instant with
/// what it asked for.
fn run_until(a: &mut Attempt<TestInstant>, until: u64) -> Vec<(u64, Vec<PunchOut>)> {
    let mut steps = Vec::new();
    while let Some(at) = a.deadline().filter(|at| at.0 <= until) {
        steps.push((at.0, a.timeout(at)));
    }
    steps
}

#[test]
fn an_unplanned_source_is_refused_before_it_is_acked() {
    let mut a = attempt();
    let out = a.datagram(addr("192.0.2.99:40000"), &probe(1), TestInstant(5));
    assert!(out.is_empty(), "an unplanned source was answered: {out:?}");
    assert_eq!(a.tally().unplanned, 1);
    assert!(a.deadline().is_some(), "the attempt goes on");
}

#[test]
fn a_probe_from_a_planned_target_is_acked_and_adopted() {
    let mut a = attempt();
    let target = targets()[1];
    let out = a.datagram(target, &probe(7), TestInstant(5));
    assert_eq!(
        out,
        vec![
            PunchOut::Send {
                dst: target,
                bytes: ack(7),
            },
            PunchOut::Adopt(target),
        ]
    );
    assert_eq!(a.deadline(), None, "the attempt has ended");
}

#[test]
fn an_exact_target_is_adopted_at_once_even_over_a_held_remapped_one() {
    let mut a = attempt();
    let remapped = addr("198.51.100.10:41111");
    assert!(a.datagram(remapped, &ack(0), TestInstant(5)).is_empty());
    let exact = targets()[0];
    assert_eq!(
        a.datagram(exact, &ack(0), TestInstant(100)),
        vec![PunchOut::Adopt(exact)]
    );
    // A packet for another session from a planned target is not an answer.
    let mut b = attempt();
    let other = build_punch_packet(PunchPacketKind::Ack, 0, "another-session");
    assert!(b.datagram(exact, &other, TestInstant(5)).is_empty());
    assert!(b.deadline().is_some());
}

#[test]
fn a_remapped_port_is_adopted_once_the_settle_passes() {
    let mut a = attempt();
    let remapped = addr("203.0.113.20:51234");
    let out = a.datagram(remapped, &probe(2), TestInstant(1_000));
    assert_eq!(
        out,
        vec![PunchOut::Send {
            dst: remapped,
            bytes: ack(2),
        }],
        "a remapped probe is acked but not adopted yet"
    );
    let steps = run_until(&mut a, 1_000 + 250);
    let adopted: Vec<u64> = steps
        .iter()
        .filter(|(_, out)| out.contains(&PunchOut::Adopt(remapped)))
        .map(|(at, _)| *at)
        .collect();
    assert_eq!(
        adopted,
        vec![1_250],
        "adopted when the 250 ms settle passed"
    );
}

#[test]
fn a_later_remapped_source_supersedes_the_held_one_without_moving_the_settle() {
    let mut a = attempt();
    let first = addr("198.51.100.10:41000");
    let second = addr("203.0.113.20:52000");
    a.datagram(first, &ack(0), TestInstant(1_000));
    a.datagram(second, &ack(0), TestInstant(1_100));
    assert_eq!(a.tally().superseded, 1);
    let steps = run_until(&mut a, 1_300);
    assert!(
        steps
            .iter()
            .any(|(at, out)| *at == 1_250 && out == &vec![PunchOut::Adopt(second)]),
        "{steps:?}"
    );
}

#[test]
fn an_attempt_with_nothing_to_adopt_times_out_and_counts_receive_errors() {
    let mut a = attempt();
    a.recv_error("Connection refused".to_string());
    let steps = run_until(&mut a, 20_000);
    let ends: Vec<_> = steps
        .iter()
        .filter(|(_, out)| out.contains(&PunchOut::TimedOut))
        .map(|(at, _)| *at)
        .collect();
    assert_eq!(ends, vec![10_000], "the attempt ends at its timeout, once");
    assert_eq!(a.deadline(), None);
    assert_eq!(a.tally().recv_errors, 1);
    assert_eq!(a.tally().last_error.as_deref(), Some("Connection refused"));

    let none = Attempt::<TestInstant>::new(
        SESSION,
        Vec::new(),
        &hint(0, 200, 10_000),
        Duration::from_secs(10),
        TestInstant(0),
        T0_MS,
    );
    assert_eq!(
        none.err(),
        Some(Error::Protocol("no-punch-targets".to_string()))
    );
}

#[test]
fn probes_go_to_every_target_each_round_from_the_hinted_start_until_the_duration_ends() {
    // Starts 300 ms from now; the 5 ms interval is raised to 20 ms; the
    // rounds run for 100 ms.
    let mut a = Attempt::new(
        SESSION,
        targets(),
        &hint(300, 5, 100),
        Duration::from_secs(10),
        TestInstant(0),
        T0_MS,
    )
    .unwrap();
    let rounds: Vec<(u64, Vec<PunchOut>)> = run_until(&mut a, 2_000)
        .into_iter()
        .filter(|(_, out)| !out.is_empty())
        .collect();
    let instants: Vec<u64> = rounds.iter().map(|(at, _)| *at).collect();
    assert_eq!(instants, vec![300, 320, 340, 360, 380]);
    for (sequence, (_, out)) in rounds.iter().enumerate() {
        let sent: Vec<PunchOut> = targets()
            .into_iter()
            .map(|dst| PunchOut::Send {
                dst,
                bytes: probe(sequence as u32),
            })
            .collect();
        assert_eq!(out, &sent, "round {sequence}");
    }

    // A duration of 0 still sends one round.
    let mut once = Attempt::new(
        SESSION,
        targets(),
        &hint(0, 200, 0),
        Duration::from_secs(1),
        TestInstant(0),
        T0_MS,
    )
    .unwrap();
    let sent = run_until(&mut once, 900)
        .into_iter()
        .filter(|(_, out)| !out.is_empty())
        .count();
    assert_eq!(sent, 1);
}

#[test]
fn the_frc_c7_punch_packets_hold() {
    let hex = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    assert_eq!(
        hex(&session_hash(SESSION)),
        "d4bf9bd274d1dba5ac253c5842680c5f"
    );
    assert_eq!(
        hex(&probe(0)),
        "4e50544300000000d4bf9bd274d1dba5ac253c5842680c5f"
    );
    assert_eq!(
        hex(&ack(0)),
        "4e50544100000000d4bf9bd274d1dba5ac253c5842680c5f"
    );
    assert_eq!(
        hex(&probe(5)),
        "4e50544300000005d4bf9bd274d1dba5ac253c5842680c5f"
    );
    // The attempt's first round is the sequence-0 probe, and it acks the
    // peer's sequence-5 probe with the sequence-5 ack.
    let mut a = attempt();
    let first = a.timeout(TestInstant(0));
    assert_eq!(
        first[0],
        PunchOut::Send {
            dst: targets()[0],
            bytes: probe(0),
        }
    );
    let out = a.datagram(targets()[0], &probe(5), TestInstant(10));
    assert_eq!(
        hex(match &out[0] {
            PunchOut::Send { bytes, .. } => bytes,
            other => panic!("no ack: {other:?}"),
        }),
        "4e50544100000005d4bf9bd274d1dba5ac253c5842680c5f"
    );
}
