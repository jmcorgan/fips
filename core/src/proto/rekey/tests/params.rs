//! Tests of `params.rs`: what `Params::new` refuses and what it derives.

use super::*;

/// The FMP defaults with one change.
fn fmp(f: impl FnOnce(&mut Config)) -> Result<Params, ParamsError> {
    let mut c = Config::fmp();
    f(&mut c);
    Params::new(c)
}

#[test]
fn params_reject_after_secs_not_above_jitter() {
    let r = fmp(|c| {
        c.after = Duration::from_secs(15);
        c.link_age = Duration::ZERO;
    });
    assert_eq!(r, Err(ParamsError::AfterNotAboveJitter));
    assert!(
        fmp(|c| {
            c.after = Duration::from_secs(16);
            c.link_age = Duration::ZERO;
        })
        .is_ok()
    );
}

#[test]
fn params_reject_zero_after_messages() {
    assert_eq!(fmp(|c| c.messages = 0), Err(ParamsError::ZeroMessages));
    assert!(fmp(|c| c.messages = 1).is_ok());
}

#[test]
fn params_reject_after_secs_below_jitter_plus_min_link_age() {
    assert_eq!(
        fmp(|c| c.after = Duration::from_secs(44)),
        Err(ParamsError::AfterBelowLinkFloor),
        "15 s of jitter plus a 30 s link-age floor needs at least 45 s"
    );
    assert!(fmp(|c| c.after = Duration::from_secs(45)).is_ok());
}

#[test]
fn params_reject_settings_under_which_a_timer_fires_on_every_poll_or_never() {
    assert_eq!(
        fmp(|c| c.messages = c.soft + 1),
        Err(ParamsError::MessagesPastSoft)
    );
    assert_eq!(
        fmp(|c| c.after = Duration::from_secs(MAX_AFTER + 1)),
        Err(ParamsError::AfterTooLong)
    );
    assert_eq!(
        fmp(|c| c.check = Duration::ZERO),
        Err(ParamsError::Zero("the check interval"))
    );
    assert_eq!(
        fmp(|c| c.silence = Duration::ZERO),
        Err(ParamsError::Zero("the silence interval"))
    );
    assert_eq!(
        fmp(|c| c.handshake = Duration::from_secs(3)),
        Err(ParamsError::HandshakeTooShort)
    );
    assert_eq!(
        fmp(|c| c.drain = Duration::from_secs(2)),
        Err(ParamsError::DrainTooShort)
    );
    assert_eq!(
        fmp(|c| c.retention = Duration::from_secs(9)),
        Err(ParamsError::RetentionBelowDrain)
    );
    assert_eq!(
        fmp(|c| c.hold = Duration::from_secs(31)),
        Err(ParamsError::HoldTooShort)
    );
    assert_eq!(fmp(|c| c.soft = c.hard), Err(ParamsError::SoftNotBelowHard));
}

#[test]
fn derived_values_match_their_derivations_at_the_defaults() {
    let p = Params::fsp();
    assert_eq!(p.confirm, Duration::from_secs(31), "confirmation window");
    assert_eq!(p.span, Duration::from_secs(41), "confirmation span");
    assert_eq!(p.grace, Duration::from_secs(8), "probe grace cap");
    assert_eq!(p.rung, Duration::from_secs(9), "setup first-rung cap");
    assert_eq!(p.gap, Duration::from_secs(4), "keepalive gap");
    assert_eq!(p.budget, Duration::from_secs(30), "attempt budget");
    assert_eq!(
        p.inert(),
        Inert {
            first: 1,
            probes: 1
        },
        "the 31 s rungs are reported inert"
    );
    assert_eq!(p.backoff(1), Duration::from_secs(1));
    assert_eq!(p.backoff(3), Duration::from_secs(4));
    assert_eq!(
        p.backoff(200),
        Duration::from_secs(120),
        "capped at the pending hold"
    );
    let short = Params::new(Config {
        resends: 3,
        ..Config::fmp()
    })
    .expect("valid");
    assert_eq!(
        short.budget,
        Duration::from_secs(8),
        "three resends end at 7 s plus one check"
    );
    assert_eq!(short.inert().first, 0);
}
