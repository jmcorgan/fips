//! Tests of `params.rs`: the draft's values, what `Params::new` refuses and
//! how it says so, and the round-trip window it derives.

use super::*;
use alloc::string::ToString;
use alloc::vec::Vec;

/// The draft's values with one change.
fn draft(f: impl FnOnce(&mut Config)) -> Result<Params, ParamsError> {
    let mut c = Config::draft();
    f(&mut c);
    Params::new(c)
}

/// A change setting one field to zero, with the name its error carries.
type Zero = (fn(&mut Config), &'static str);

/// Every interval and count that must be positive.
const ZEROS: [Zero; 17] = [
    (|c| c.switch_dwell = Duration::ZERO, "the switch dwell"),
    (
        |c| c.active_interval = Duration::ZERO,
        "the active probe interval",
    ),
    (
        |c| c.standby_interval = Duration::ZERO,
        "the standby probe interval",
    ),
    (|c| c.timeout = Duration::ZERO, "the probe timeout floor"),
    (|c| c.verdict_cap = Duration::ZERO, "the verdict cap"),
    (|c| c.heartbeat = Duration::ZERO, "the heartbeat interval"),
    (
        |c| c.dead_interval = Duration::ZERO,
        "the Dead probe interval cap",
    ),
    (|c| c.grace = Duration::ZERO, "the Dead grace"),
    (|c| c.span = Duration::ZERO, "the capability probe span"),
    (
        |c| c.cap = Duration::ZERO,
        "the capability probe interval cap",
    ),
    (|c| c.min_samples = 0, "the minimum samples"),
    (|c| c.suspect = 0, "the Suspect count"),
    (|c| c.retire = 0, "the retire count"),
    (|c| c.discovery = 0, "the discovery probe count"),
    (|c| c.auth_limit = 0, "the authentication failure limit"),
    (|c| c.ring = 0, "the probe ring"),
    (|c| c.budget = 0, "the capability probe budget"),
];

#[test]
fn the_draft_values_are_the_draft_constants() {
    let expected = Config {
        enabled: true,
        switch_margin: 1.3,
        switch_dwell: Duration::from_secs(2),
        min_samples: 2,
        active_interval: Duration::from_millis(200),
        standby_interval: Duration::from_secs(1),
        mix_kinds: false,
        timeout: Duration::from_millis(400),
        // Not in Appendix A: the draft leaves the timeout to the node.
        verdict_cap: Duration::from_secs(3),
        suspect: 3,
        retire: 10,
        discovery: 8,
        heartbeat: Duration::from_secs(10),
        dead_interval: Duration::from_secs(30),
        grace: Duration::from_secs(600),
        auth_limit: 20,
        ring: 8,
        budget: 3,
        span: Duration::from_secs(30),
        cap: Duration::from_secs(600),
    };
    assert_eq!(Config::draft(), expected, "Appendix A of the draft");
    assert_eq!(Params::draft().config(), &expected);
    assert_eq!(RING, 8);
}

#[test]
fn a_zero_interval_or_count_is_refused_and_named() {
    for (zero, name) in ZEROS {
        assert_eq!(draft(zero), Err(ParamsError::Zero(name)), "{name}");
    }
}

#[test]
fn a_margin_below_one_or_not_finite_is_refused() {
    for margin in [0.99, 0.0, -1.3, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            draft(|c| c.switch_margin = margin),
            Err(ParamsError::Margin),
            "margin {margin}"
        );
    }
    assert!(draft(|c| c.switch_margin = 1.0).is_ok());
}

#[test]
fn a_ring_larger_than_eight_is_refused() {
    assert_eq!(draft(|c| c.ring = 9), Err(ParamsError::Ring));
    assert_eq!(draft(|c| c.ring = u8::MAX), Err(ParamsError::Ring));
    assert!(draft(|c| c.ring = 8).is_ok());
    assert!(draft(|c| c.ring = 1).is_ok());
}

#[test]
fn every_error_message_is_one_sentence_with_no_run_of_spaces() {
    let mut errors: Vec<ParamsError> = ZEROS.iter().map(|&(_, n)| ParamsError::Zero(n)).collect();
    errors.extend([ParamsError::Margin, ParamsError::Ring]);
    for e in errors {
        let m = e.to_string();
        assert!(!m.contains("  "), "a run of spaces: {m:?}");
        assert!(!m.contains('\n'), "a line break: {m:?}");
        assert_eq!(m.trim(), m, "leading or trailing space: {m:?}");
        assert!(
            !m.contains(". ") && !m.ends_with('.'),
            "not one sentence: {m:?}"
        );
        assert!(
            m.starts_with("the "),
            "not a sentence about one setting: {m:?}"
        );
    }
    assert_eq!(
        ParamsError::Ring.to_string(),
        "the probe ring must hold at most 8 probes"
    );
}

#[test]
fn the_rtt_window_is_at_least_thirty_seconds() {
    assert_eq!(
        Params::draft().window,
        Duration::from_secs(30),
        "two standby intervals per sample is 4 s at the defaults, under the floor"
    );
    let wide = draft(|c| c.min_samples = 20).expect("valid");
    assert_eq!(
        wide.window,
        Duration::from_secs(40),
        "1 s by 20 samples by 2"
    );
}
