//! Tests for `Config::apply_floors`: a bloom setting or the lookup retry
//! ladder outside its bound runs at the bound's value with one warning, and a
//! setting inside its bound is left alone without one.

use super::*;
use crate::testutil::capture_logs;

/// Whether `line` carries the field `name` with the `Debug` text `value`.
fn has_field(line: &str, name: &str, value: &str) -> bool {
    let want = format!("{name}={value}");
    line.split(' ').any(|t| t == want)
}

/// Apply the floors to `config` and return the warnings logged.
fn floor_warnings(config: &mut Config) -> Vec<String> {
    let ((), logs) = capture_logs(|| config.apply_floors());
    logs.warnings()
}

#[test]
fn a_bloom_update_debounce_below_the_500_ms_send_interval_runs_at_500_with_one_warning_naming_the_key()
 {
    for ms in [0u64, 100, 499] {
        let mut config = Config::default();
        config.node.bloom.update_debounce_ms = ms;
        let warnings = floor_warnings(&mut config);
        assert_eq!(config.node.bloom.update_debounce_ms, 500, "{ms}");
        assert_eq!(warnings.len(), 1, "{ms}: {warnings:?}");
        let line = &warnings[0];
        assert!(
            has_field(line, "key", "\"node.bloom.update_debounce_ms\""),
            "{line}"
        );
        assert!(has_field(line, "configured", &ms.to_string()), "{line}");
        assert!(has_field(line, "used", "500"), "{line}");
    }
}

#[test]
fn a_bloom_update_debounce_of_500_ms_or_more_is_left_alone_without_a_warning() {
    let config = Config::default();
    assert_eq!(config.node.bloom.update_debounce_ms, 500);
    for ms in [500u64, 60_000] {
        let mut config = Config::default();
        config.node.bloom.update_debounce_ms = ms;
        let warnings = floor_warnings(&mut config);
        assert_eq!(config.node.bloom.update_debounce_ms, ms);
        assert!(warnings.is_empty(), "{ms}: {warnings:?}");
    }
}

/// Assert that `cap` ran as 0.20 with one warning naming the key and values.
fn assert_cap_floored(cap: f64) {
    let mut config = Config::default();
    config.node.bloom.max_inbound_fpr = cap;
    let warnings = floor_warnings(&mut config);
    assert_eq!(config.node.bloom.max_inbound_fpr, ACCEPT_FPR_CAP, "{cap}");
    assert_eq!(warnings.len(), 1, "{cap}: {warnings:?}");
    let line = &warnings[0];
    assert!(
        has_field(line, "key", "\"node.bloom.max_inbound_fpr\""),
        "{line}"
    );
    assert!(has_field(line, "configured", &format!("{cap:?}")), "{line}");
    assert!(has_field(line, "used", "0.2"), "{line}");
}

#[test]
fn a_bloom_max_inbound_fpr_below_the_0_20_floor_runs_at_0_20_with_one_warning_naming_the_key() {
    // A cap below 0.20 discards the filters of conformant peers; 0 or a
    // negative cap discards every filter (FRC-1402 Section 4.7.1).
    for cap in [0.10, 0.0, 0.199, -0.1, f64::NEG_INFINITY] {
        assert_cap_floored(cap);
    }
}

#[test]
fn a_bloom_max_inbound_fpr_that_turns_the_cap_off_falls_back_to_the_0_20_default_with_one_warning()
{
    // At 1.0 or above, or NaN, the cap never fires and the poisoning check
    // is off.
    assert_eq!(
        Config::default().node.bloom.max_inbound_fpr,
        ACCEPT_FPR_CAP,
        "the fallback is the default"
    );
    for cap in [1.0, 1.5, f64::INFINITY, f64::NAN] {
        assert_cap_floored(cap);
    }
}

#[test]
fn a_bloom_max_inbound_fpr_at_or_above_0_20_and_below_1_0_is_left_alone_without_a_warning() {
    for cap in [0.20, 0.30, 0.99] {
        let mut config = Config::default();
        config.node.bloom.max_inbound_fpr = cap;
        let warnings = floor_warnings(&mut config);
        assert_eq!(config.node.bloom.max_inbound_fpr.to_bits(), cap.to_bits());
        assert!(warnings.is_empty(), "{cap}: {warnings:?}");
    }
}

#[test]
fn both_bloom_settings_below_their_floors_give_one_warning_each() {
    let mut config = Config::default();
    config.node.bloom.update_debounce_ms = 0;
    config.node.bloom.max_inbound_fpr = 0.0;
    let warnings = floor_warnings(&mut config);
    assert_eq!(warnings.len(), 2, "{warnings:?}");
    for key in [
        "\"node.bloom.update_debounce_ms\"",
        "\"node.bloom.max_inbound_fpr\"",
    ] {
        assert_eq!(
            warnings.iter().filter(|l| has_field(l, "key", key)).count(),
            1,
            "{key}: {warnings:?}"
        );
    }
}

/// The lookup ladder key, as its warning's `key` field logs it.
const LADDER_KEY: &str = "\"node.lookup.attempt_timeouts_secs\"";

#[test]
fn an_empty_lookup_ladder_runs_as_the_default_with_one_warning_naming_the_key() {
    let mut config = Config::default();
    config.node.lookup.attempt_timeouts_secs = Vec::new();
    let warnings = floor_warnings(&mut config);
    assert_eq!(config.node.lookup.attempt_timeouts_secs, vec![1, 2, 4, 8]);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(has_field(&warnings[0], "key", LADDER_KEY), "{warnings:?}");
}

#[test]
fn a_lookup_ladder_over_255_entries_runs_its_first_255_with_one_warning_naming_the_lengths() {
    let mut config = Config::default();
    let ladder: Vec<u64> = (1..=300).collect();
    config.node.lookup.attempt_timeouts_secs = ladder.clone();
    let warnings = floor_warnings(&mut config);
    assert_eq!(config.node.lookup.attempt_timeouts_secs, ladder[..255]);
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    let line = &warnings[0];
    assert!(has_field(line, "key", LADDER_KEY), "{line}");
    assert!(has_field(line, "configured", "300"), "{line}");
    assert!(has_field(line, "used", "255"), "{line}");
}

#[test]
fn the_default_lookup_ladder_and_one_of_255_entries_are_left_alone_without_a_warning() {
    let full: Vec<u64> = (1..=255).collect();
    for ladder in [Config::default().node.lookup.attempt_timeouts_secs, full] {
        let mut config = Config::default();
        config.node.lookup.attempt_timeouts_secs = ladder.clone();
        let warnings = floor_warnings(&mut config);
        assert_eq!(config.node.lookup.attempt_timeouts_secs, ladder);
        assert!(warnings.is_empty(), "{warnings:?}");
    }
}

#[test]
fn applying_the_floors_twice_changes_nothing_and_warns_nothing_the_second_time() {
    let mut config = Config::default();
    config.node.lookup.attempt_timeouts_secs = Vec::new();
    config.node.bloom.update_debounce_ms = 0;
    let _ = floor_warnings(&mut config);
    let ladder = config.node.lookup.attempt_timeouts_secs.clone();
    let warnings = floor_warnings(&mut config);
    assert_eq!(config.node.lookup.attempt_timeouts_secs, ladder);
    assert!(warnings.is_empty(), "{warnings:?}");
}
