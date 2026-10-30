//! Tests for `Config::apply_floors` (`floors.rs`): a value outside its bound
//! runs at the bound with one warning naming the key, the configured value
//! and the value used; a value bounded only for some uses is kept, with the
//! same warning naming the value used there; a value inside its bound, and
//! the shipped defaults, are kept without a warning.

use super::*;
use crate::testutil::{capture_logs, log_field};

/// One bounded key, with values outside and inside its bound.
struct Case {
    /// The key as the warning names it.
    key: &'static str,
    /// The warning's message.
    message: &'static str,
    /// The value used where the bound applies, when the configured one is
    /// outside it.
    used: u64,
    /// Configured values outside the bound.
    outside: &'static [u64],
    /// Configured values the node runs with as given.
    inside: &'static [u64],
    /// Write the key in a configuration.
    set: fn(&mut Config, u64),
    /// Read the key from a configuration.
    get: fn(&Config) -> u64,
}

/// Every key `apply_floors` changes.
const CASES: &[Case] = &[
    Case {
        key: "node.link_dead_timeout_secs",
        message: "configured value is below the 30 s a link must stay silent before it is declared dead; running at 30 s",
        used: 30,
        outside: &[0, 3, 29],
        inside: &[30, 31, 300],
        set: |c, v| c.node.link_dead_timeout_secs = v,
        get: |c| c.node.link_dead_timeout_secs,
    },
    Case {
        key: "node.rendezvous.nostr.signal_ttl_secs",
        message: "configured value is below the 120 s least lifetime of a traversal signal; running at 120 s",
        used: 120,
        outside: &[0, 45, 119],
        inside: &[120, 179],
        set: |c, v| c.node.rendezvous.nostr.signal_ttl_secs = v,
        get: |c| c.node.rendezvous.nostr.signal_ttl_secs,
    },
    Case {
        key: "node.rendezvous.nostr.attempt_timeout_secs",
        message: "configured value is below the 10 s least punch attempt timeout; running at 10 s",
        used: 10,
        outside: &[0, 6, 9],
        inside: &[10, 11],
        set: |c, v| c.node.rendezvous.nostr.attempt_timeout_secs = v,
        get: |c| c.node.rendezvous.nostr.attempt_timeout_secs,
    },
    Case {
        key: "node.rendezvous.nostr.max_concurrent_incoming_offers",
        message: "configured value is below the 16 traversal offers a node must handle at once; running at 16",
        used: 16,
        outside: &[0, 15],
        inside: &[16, 17],
        set: |c, v| c.node.rendezvous.nostr.max_concurrent_incoming_offers = v as usize,
        get: |c| c.node.rendezvous.nostr.max_concurrent_incoming_offers as u64,
    },
    Case {
        key: "node.rendezvous.nostr.max_concurrent_offers_per_npub",
        message: "configured value is below the 4 traversal offers a node must handle at once from one sender; running at 4",
        used: 4,
        outside: &[0, 1, 3],
        inside: &[4, 5],
        set: |c, v| c.node.rendezvous.nostr.max_concurrent_offers_per_npub = v as usize,
        get: |c| c.node.rendezvous.nostr.max_concurrent_offers_per_npub as u64,
    },
];

/// Every key `apply_floors` keeps and warns about, its bound applying only
/// where it is used.
const CAPPED: &[Case] = &[
    Case {
        key: "node.rate_limit.handshake_max_resends",
        message: "configured value is above the 5 msg1 resends allowed to a handshake an mDNS advert directs at a node not configured to dial; those handshakes resend at most 5 times",
        used: 5,
        outside: &[6, 10],
        inside: &[0, 5],
        set: |c, v| c.node.rate_limit.handshake_max_resends = v as u32,
        get: |c| u64::from(c.node.rate_limit.handshake_max_resends),
    },
    Case {
        key: "node.rate_limit.handshake_timeout_secs",
        message: "configured value is above the 30 s a link rekey attempt may run; link rekey attempts end within 30 s",
        used: 30,
        outside: &[31, 60],
        inside: &[10, 30],
        set: |c, v| c.node.rate_limit.handshake_timeout_secs = v,
        get: |c| c.node.rate_limit.handshake_timeout_secs,
    },
];

/// Assert that `logs` holds exactly one warning, `case`'s, with target
/// `fips::config` and fields naming the key, `configured` and the value used.
fn assert_one_warning(case: &Case, configured: u64, logs: &crate::testutil::LogCapture) {
    assert_eq!(
        logs.warnings().len(),
        1,
        "{} = {configured}: one warning, got {:?}",
        case.key,
        logs.lines()
    );
    assert_eq!(
        logs.targets(case.message),
        vec!["fips::config"],
        "{} = {configured}: the warning's message and target, got {:?}",
        case.key,
        logs.lines()
    );
    let line = logs.line(case.message).unwrap();
    let key = format!("{:?}", case.key);
    assert_eq!(log_field(&line, "key"), Some(key.as_str()), "{line}");
    let configured = configured.to_string();
    assert_eq!(
        log_field(&line, "configured"),
        Some(configured.as_str()),
        "{line}"
    );
    let used = case.used.to_string();
    assert_eq!(log_field(&line, "used"), Some(used.as_str()), "{line}");
}

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
            assert_one_warning(case, value, &logs);
        }
    }
}

#[test]
fn a_value_above_a_bound_that_applies_only_to_some_uses_is_kept_with_one_warning_naming_the_value_used_there()
 {
    for case in CAPPED {
        for &value in case.outside {
            let (config, logs) = floored(case, value);
            assert_eq!(
                (case.get)(&config),
                value,
                "{} = {value} was changed",
                case.key
            );
            assert_one_warning(case, value, &logs);
        }
    }
}

#[test]
fn a_value_inside_its_bound_is_kept_without_a_warning() {
    for case in CASES.iter().chain(CAPPED) {
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
