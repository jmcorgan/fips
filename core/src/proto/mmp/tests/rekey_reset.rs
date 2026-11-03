//! What a rekey cutover's reset leaves in the MMP state of a link and of a
//! session, judged against a fresh state of the same form and role by what
//! each part outputs, since the parts' fields are private to their modules.
//!
//! - The receiver builds the reports a fresh receiver builds: none right
//!   after the reset, and the same ones from the same new-session frames,
//!   once its lifetime totals are taken off.
//! - The metrics judge the new session's reports as fresh metrics do: the
//!   same loss rate, last accepted report and CE count right after the
//!   reset and after each of two new reports. The reverse delivery ratio
//!   and the ETX are kept until the new session measures them, then match.
//! - The spin bit acts on the new session's first frame as a fresh state of
//!   its role does.
//!
//! What the reset keeps is checked kept: the receiver's and the sender's
//! lifetime totals, the report interval, the SRTT, the report and RTT
//! sample counts, the reverse delivery ratio, the ETX, the goodput, the
//! smoothed ETX and loss, and the spin role. The new session's frames
//! start after the jitter grace the reset sets, which `state.rs` tests.
//!
//! Everything the reset carries, by part:
//!
//! - The sender, whole. Its interval state is carried too, so the first
//!   sender report after the reset starts at an old-session counter and
//!   counts the bytes of both sessions. Nothing in the node reads a sender
//!   report beyond tracing it, so only that report's content on the wire
//!   is affected; this file does not assert it.
//! - The receiver's lifetime packet and byte totals, its report interval
//!   and last report time, and its SRTT sample count (report scheduling).
//! - The metrics' SRTT, their smoothed trends (RTT, loss, goodput, jitter,
//!   ETX), the reverse delivery ratio, the ETX, the goodput, the last RTT
//!   sample, and the report and RTT sample counters: they refresh from the
//!   new session's data.
//! - The spin bit's role.
//! - The aggregate's mode and log timing, and a session's path MTU state.

use crate::proto::mmp::algorithms::SpinBitState;
use crate::proto::mmp::receiver::ReceiverState;
use crate::proto::mmp::{DEFAULT_LOG_INTERVAL_SECS, DEFAULT_OWD_WINDOW_SIZE, MmpMetrics, MmpMode};
use crate::proto::mmp::{MmpPeerState, MmpSessionState, ReceiverReport};

/// When the cutover happens, in injected milliseconds.
const CUTOVER_MS: u64 = 100_000;
/// When the new session's frames start: past the receiver's 15 s jitter
/// grace, so a fresh receiver and a reset one both take every frame.
const NEW_START_MS: u64 = CUTOVER_MS + 60_000;
/// Frames the receiver saw on the old session.
const OLD_FRAMES: u64 = 60;
/// Frames of the old session the receiver counted, `OLD_FRAMES` less the
/// four lost and plus the one that arrived late.
const OLD_RECEIVED: u64 = OLD_FRAMES - 4 + 1;
/// Frames each spin state saw on the old session. Odd, since both roles
/// change the bit they send at every frame: the old session then leaves
/// `true` set, and a reset that keeps the bit it sends is seen.
const OLD_SPIN_FRAMES: u64 = OLD_FRAMES + 1;

/// A state of form `$ty` and spin role `$init`.
macro_rules! new_state {
    ($ty:ty, $init:expr) => {
        <$ty>::new(
            MmpMode::Full,
            DEFAULT_LOG_INTERVAL_SECS,
            DEFAULT_OWD_WINDOW_SIZE,
            $init,
        )
    };
}

/// Feed `r` the frames `first..=last` but `lost`, then `late` again out of
/// order, from `start_ms`. Transit varies frame to frame and every fifth
/// frame carries CE, so jitter, the one-way-delay trend, loss bursts,
/// reordering and ECN all have something to count. Returns the time of the
/// last frame.
fn frames(
    r: &mut ReceiverState,
    first: u64,
    last: u64,
    lost: &[u64],
    late: Option<u64>,
    start_ms: u64,
) -> u64 {
    let mut t = start_ms;
    for c in first..=last {
        if lost.contains(&c) {
            continue;
        }
        t += 10 + (c % 7) * 3;
        r.record_recv(c, (c * 10) as u32, 100, c % 5 == 0, t);
    }
    if let Some(c) = late {
        t += 5;
        r.record_recv(c, (c * 10) as u32, 100, false, t);
    }
    t
}

/// The old session as the receiver saw it: a report part way through, then
/// more frames, so the reset meets interval counts, a loss burst, a
/// reordered frame, CE marks and a one-way-delay window all in progress.
fn old_session(r: &mut ReceiverState) {
    let t = frames(r, 1, 40, &[30, 31, 32], Some(31), 1_000);
    r.build_report(t + 20);
    frames(r, 41, OLD_FRAMES, &[52], None, t + 40);
}

/// Feed the reset receiver `s` and the fresh receiver `f` the same two
/// rounds of new-session frames, and assert each round's report is the
/// same once `s`'s lifetime totals are taken off.
fn assert_reports_match(
    s: &mut ReceiverState,
    f: &mut ReceiverState,
    kept: (u64, u64),
    what: &str,
) {
    let rounds: [(u64, u64, &[u64], Option<u64>); 2] =
        [(1, 20, &[8, 9], Some(9)), (21, 40, &[33], None)];
    let mut start = NEW_START_MS;
    for (round, (first, last, lost, late)) in rounds.into_iter().enumerate() {
        let t = frames(s, first, last, lost, late, start);
        frames(f, first, last, lost, late, start);
        let mut a = s
            .build_report(t + 50)
            .expect("precondition: a report from the reset receiver");
        let b = f
            .build_report(t + 50)
            .expect("precondition: a report from the fresh receiver");
        // Wrapping, so a reset that zeroed a lifetime total fails at the
        // comparison below rather than at an overflow here.
        a.cumulative_packets_recv = a.cumulative_packets_recv.wrapping_sub(kept.0);
        a.cumulative_bytes_recv = a.cumulative_bytes_recv.wrapping_sub(kept.1);
        assert_eq!(
            a, b,
            "defect: {what}: round {round} of the new session is reported differently from a fresh receiver's"
        );
        start = t + 100;
    }
}

/// Reset a state of form `$ty` after an old session and compare its
/// receiver's reports with a fresh state's.
macro_rules! check_receiver {
    ($ty:ty, $what:expr) => {{
        let mut s = new_state!($ty, false);
        let mut f = new_state!($ty, false);
        old_session(&mut s.receiver);
        s.receiver.update_report_interval_from_srtt(300_000);
        for c in 1..=OLD_FRAMES {
            s.sender.record_sent(c, (c * 10) as u32, 100);
        }
        let kept = (
            s.receiver.cumulative_packets_recv(),
            s.receiver.cumulative_bytes_recv(),
        );
        let interval = s.receiver.report_interval_ms();
        let sent = s.sender.cumulative_packets_sent();
        assert!(
            kept.0 == OLD_RECEIVED
                && s.receiver.highest_counter() == OLD_FRAMES
                && s.receiver.ecn_ce_count() > 0
                && s.receiver.jitter_us() > 0
                && interval != f.receiver.report_interval_ms()
                && sent == OLD_FRAMES,
            "precondition: {}: the old session left state for the reset to clear or keep",
            $what
        );

        s.reset_for_rekey(CUTOVER_MS);

        assert_eq!(
            s.receiver.build_report(CUTOVER_MS),
            f.receiver.build_report(CUTOVER_MS),
            "defect: {}: right after the reset the receiver reports differently from a fresh one",
            $what
        );
        assert_reports_match(&mut s.receiver, &mut f.receiver, kept, $what);
        assert!(
            s.receiver.report_interval_ms() == interval
                && s.sender.cumulative_packets_sent() == sent,
            "defect: {}: the reset dropped the report interval or the sender's totals",
            $what
        );
    }};
}

/// A report from the peer about our frames up to `highest`, `packets` of
/// them received, with `ce` CE marks and `reorder` reordered frames.
fn report(highest: u64, packets: u64, ce: u32, reorder: u32, echo: u32) -> ReceiverReport {
    ReceiverReport {
        highest_counter: highest,
        cumulative_packets_recv: packets,
        cumulative_bytes_recv: packets * 100,
        timestamp_echo: echo,
        dwell_time: 0,
        max_burst_loss: 0,
        mean_burst_loss: 0,
        jitter: 0,
        ecn_ce_count: ce,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: reorder,
        interval_packets_recv: 0,
        interval_bytes_recv: 0,
    }
}

/// What the metrics make of the new session's reports, independent of what
/// the reset keeps: the loss rate, the last accepted report and its CE count.
fn judged(m: &MmpMetrics) -> (f64, Option<(u64, u64, u32)>, u32) {
    (m.loss_rate(), m.rr_counters(), m.last_ecn_ce_count())
}

/// What the reset keeps in the metrics.
#[derive(Debug, PartialEq)]
struct Carried {
    srtt_ms: Option<f64>,
    reports_seen: u64,
    rtt_samples: u64,
    reverse: f64,
    etx: f64,
    goodput_bps: f64,
    smoothed_etx: Option<f64>,
    smoothed_loss: Option<f64>,
}

impl Carried {
    /// Read what the reset keeps from `m`.
    fn of(m: &MmpMetrics) -> Self {
        Self {
            srtt_ms: m.srtt_ms(),
            reports_seen: m.reports_seen(),
            rtt_samples: m.rtt_samples(),
            reverse: m.delivery_ratio_reverse,
            etx: m.etx,
            goodput_bps: m.goodput_bps(),
            smoothed_etx: m.smoothed_etx(),
            smoothed_loss: m.smoothed_loss(),
        }
    }
}

/// Reset a state of form `$ty` after an old session with forward and
/// reverse loss, then feed it and a fresh state the same two new-session
/// reports, each followed by the reverse delivery update the node makes
/// from its receiver (whose lifetime total the reset keeps).
macro_rules! check_metrics {
    ($ty:ty, $what:expr) => {{
        let mut s = new_state!($ty, false);
        let mut f = new_state!($ty, false);
        s.metrics
            .process_receiver_report(&report(20, 20, 0, 0, 400), 500, 1_000);
        s.metrics.update_reverse_delivery(20, 20);
        s.metrics
            .process_receiver_report(&report(50, 40, 3, 1, 1_400), 1_500, 2_000);
        s.metrics.update_reverse_delivery(35, 50);
        let kept = Carried::of(&s.metrics);
        assert!(
            s.metrics.loss_rate() > 0.0
                && s.metrics.last_ecn_ce_count() > 0
                && s.metrics.rr_counters().is_some()
                && kept.srtt_ms.is_some()
                && kept.reverse < 1.0,
            "precondition: {}: the old session left loss, CE marks, an SRTT and a reverse ratio",
            $what
        );

        s.reset_for_rekey(CUTOVER_MS);

        assert_eq!(
            judged(&s.metrics),
            judged(&f.metrics),
            "defect: {}: right after the reset the metrics judge differently from fresh ones",
            $what
        );
        assert_eq!(
            Carried::of(&s.metrics),
            kept,
            "defect: {}: the reset dropped what the metrics keep",
            $what
        );

        s.metrics
            .process_receiver_report(&report(10, 8, 1, 0, 0), 0, NEW_START_MS);
        f.metrics
            .process_receiver_report(&report(10, 8, 1, 0, 0), 0, NEW_START_MS);
        s.metrics.update_reverse_delivery(35 + 8, 10);
        f.metrics.update_reverse_delivery(8, 10);
        assert_eq!(
            judged(&s.metrics),
            judged(&f.metrics),
            "defect: {}: the new session's first report is judged differently from fresh metrics'",
            $what
        );
        assert!(
            s.metrics.delivery_ratio_reverse == kept.reverse,
            "defect: {}: a reverse delivery ratio was measured across the cutover: {} kept, {} now",
            $what,
            kept.reverse,
            s.metrics.delivery_ratio_reverse
        );

        s.metrics
            .process_receiver_report(&report(30, 25, 2, 1, 0), 0, NEW_START_MS + 1_000);
        f.metrics
            .process_receiver_report(&report(30, 25, 2, 1, 0), 0, NEW_START_MS + 1_000);
        s.metrics.update_reverse_delivery(35 + 20, 30);
        f.metrics.update_reverse_delivery(20, 30);
        assert_eq!(
            (
                judged(&s.metrics),
                s.metrics.delivery_ratio_reverse,
                s.metrics.etx
            ),
            (
                judged(&f.metrics),
                f.metrics.delivery_ratio_reverse,
                f.metrics.etx
            ),
            "defect: {}: the new session's second report is judged differently from fresh metrics'",
            $what
        );
    }};
}

/// Whether `spin` acts on the new session's first frame as a fresh state of
/// its role does: it sends `false`; as a responder it reflects the frame at
/// counter 1; as an initiator its first round trip yields no RTT sample.
fn spin_is_fresh(spin: &mut SpinBitState) -> Result<(), &'static str> {
    if spin.tx_bit() {
        return Err("it sends the old session's bit");
    }
    if spin.is_initiator() {
        if spin.rx_observe(false, 1, CUTOVER_MS + 10).is_some() {
            return Err("its first round trip measured an RTT from an old-session edge");
        }
    } else {
        spin.rx_observe(true, 1, CUTOVER_MS + 10);
        if !spin.tx_bit() {
            return Err("it does not reflect the new session's first frame");
        }
    }
    Ok(())
}

/// Spin a state of form `$ty` and role `$init` through an old session,
/// reset it, and assert its spin bit is a fresh state's of the same role.
macro_rules! check_spin {
    ($ty:ty, $init:expr, $what:expr) => {{
        let mut s = new_state!($ty, $init);
        for c in 1..=OLD_SPIN_FRAMES {
            // An initiator's frames reflect its own bit (a round trip each),
            // a responder's carry a new bit each time.
            let bit = s.spin_bit.tx_bit() ^ !s.spin_bit.is_initiator();
            s.spin_bit.rx_observe(bit, c, c * 10);
        }
        assert!(
            s.spin_bit.tx_bit(),
            "precondition: {}: the old session left the spin bit set",
            $what
        );
        s.reset_for_rekey(CUTOVER_MS);
        assert!(
            s.spin_bit.is_initiator() == $init,
            "defect: {}: the reset changed the spin role",
            $what
        );
        let spin = spin_is_fresh(&mut s.spin_bit);
        assert!(
            spin.is_ok(),
            "defect: {}: the spin bit is not a fresh state's after the reset: {:?}",
            $what,
            spin
        );
    }};
}

#[test]
fn a_link_rekey_reset_leaves_the_receiver_reporting_the_new_session_as_a_fresh_receiver_does() {
    check_receiver!(MmpPeerState, "link");
}

#[test]
fn a_session_rekey_reset_leaves_the_receiver_reporting_the_new_session_as_a_fresh_receiver_does() {
    check_receiver!(MmpSessionState, "session");
}

#[test]
fn a_link_rekey_reset_leaves_the_metrics_judging_the_new_sessions_reports_as_fresh_metrics_do() {
    check_metrics!(MmpPeerState, "link");
}

#[test]
fn a_session_rekey_reset_leaves_the_metrics_judging_the_new_sessions_reports_as_fresh_metrics_do() {
    check_metrics!(MmpSessionState, "session");
}

#[test]
fn a_link_initiators_rekey_reset_restarts_its_spin_bit_and_keeps_the_role() {
    check_spin!(MmpPeerState, true, "link initiator");
}

#[test]
fn a_link_responders_rekey_reset_restarts_its_spin_bit_and_keeps_the_role() {
    check_spin!(MmpPeerState, false, "link responder");
}

#[test]
fn a_session_initiators_rekey_reset_restarts_its_spin_bit_and_keeps_the_role() {
    check_spin!(MmpSessionState, true, "session initiator");
}

#[test]
fn a_session_responders_rekey_reset_restarts_its_spin_bit_and_keeps_the_role() {
    check_spin!(MmpSessionState, false, "session responder");
}
