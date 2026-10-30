//! Tests for `Config::apply_floors` (`floors.rs`): a value outside its bound
//! runs at the bound with one warning naming the key, the configured value
//! and the value used; a value inside it, and the shipped defaults, are kept
//! without a warning.

use super::*;
use crate::testutil::{capture_logs, log_field};

/// One bounded key, with values outside and inside its bound.
struct Case {
    /// The key as the warning names it.
    key: &'static str,
    /// The warning's message.
    message: &'static str,
    /// The value a node runs with when the configured one is outside.
    used: u64,
    /// Configured values the node does not run with.
    outside: &'static [u64],
    /// Configured values the node runs with as given.
    inside: &'static [u64],
    /// Write the key in a configuration.
    set: fn(&mut Config, u64),
    /// Read the key from a configuration.
    get: fn(&Config) -> u64,
}

/// Every key `apply_floors` changes.
const CASES: &[Case] = &[Case {
    key: "node.link_dead_timeout_secs",
    message: "configured value is below the 30 s a link must stay silent before it is declared dead; running at 30 s",
    used: 30,
    outside: &[0, 3, 29],
    inside: &[30, 31, 300],
    set: |c, v| c.node.link_dead_timeout_secs = v,
    get: |c| c.node.link_dead_timeout_secs,
}];

/// The default configuration with `case`'s key set to `value`, after
/// `apply_floors`, and the log it wrote.
fn floored(case: &Case, value: u64) -> (Config, crate::testutil::LogCapture) {
    let mut config = Config::default();
    (case.set)(&mut config, value);
    capture_logs(|| {
        config.apply_floors();
        config
    })
}

#[test]
fn a_value_outside_its_bound_runs_at_the_bound_with_one_warning_naming_the_key_the_configured_value_and_the_value_used()
 {
    for case in CASES {
        for &value in case.outside {
            let (config, logs) = floored(case, value);
            assert_eq!(
                (case.get)(&config),
                case.used,
                "{} = {value} was kept",
                case.key
            );
            assert_eq!(
                logs.warnings().len(),
                1,
                "{} = {value}: one warning, got {:?}",
                case.key,
                logs.lines()
            );
            assert_eq!(
                logs.targets(case.message),
                vec!["fips::config"],
                "{} = {value}: the warning's message and target, got {:?}",
                case.key,
                logs.lines()
            );
            let line = logs.line(case.message).unwrap();
            let key = format!("{:?}", case.key);
            assert_eq!(log_field(&line, "key"), Some(key.as_str()), "{line}");
            let configured = value.to_string();
            assert_eq!(
                log_field(&line, "configured"),
                Some(configured.as_str()),
                "{line}"
            );
            let used = case.used.to_string();
            assert_eq!(log_field(&line, "used"), Some(used.as_str()), "{line}");
        }
    }
}

#[test]
fn a_value_inside_its_bound_is_kept_without_a_warning() {
    for case in CASES {
        for &value in case.inside {
            let (config, logs) = floored(case, value);
            assert_eq!((case.get)(&config), value, "{} = {value}", case.key);
            assert!(
                logs.warnings().is_empty(),
                "{} = {value} warned: {:?}",
                case.key,
                logs.lines()
            );
        }
    }
}

#[test]
fn the_default_configuration_is_inside_every_bound_and_logs_nothing() {
    let ((), logs) = capture_logs(|| Config::default().apply_floors());
    assert!(logs.lines().is_empty(), "{:?}", logs.lines());
}

#[test]
fn applying_the_floors_a_second_time_changes_and_logs_nothing() {
    let mut config = Config::default();
    for case in CASES {
        (case.set)(&mut config, case.outside[0]);
    }
    config.apply_floors();
    let once = config.to_yaml().unwrap();
    let (again, logs) = capture_logs(|| {
        config.apply_floors();
        config
    });
    assert_eq!(again.to_yaml().unwrap(), once);
    assert!(logs.lines().is_empty(), "{:?}", logs.lines());
}

#[test]
fn a_node_built_with_a_given_identity_runs_with_the_floors_applied() {
    let mut config = Config::default();
    for case in CASES {
        (case.set)(&mut config, case.outside[0]);
    }
    let node = crate::node::Node::with_identity(crate::Identity::generate(), config)
        .expect("the node is built");
    for case in CASES {
        assert_eq!((case.get)(node.config()), case.used, "{}", case.key);
    }
}
