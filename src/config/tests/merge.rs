//! Tests for how a later configuration file's `tun` and `dns` sections, and
//! `node.identity.persistent`, layer over an earlier one's: through
//! `Config::merge`, which has only parsed values and judges the on-off
//! settings by value, and through `Config::load_from_paths`, which reads
//! which keys each file names.

use super::*;

/// Merge `later` over `base` the way `load_from_paths` layers two files.
fn merged(mut base: Config, later: Config) -> Config {
    base.merge(later);
    base
}

/// A configuration whose `tun.enabled` is `enabled` and is otherwise
/// default.
fn with_tun(enabled: bool) -> Config {
    let mut config = Config::new();
    config.tun.enabled = enabled;
    config
}

/// A configuration whose `dns.enabled` is `enabled` and is otherwise
/// default.
fn with_dns(enabled: bool) -> Config {
    let mut config = Config::new();
    config.dns.enabled = enabled;
    config
}

/// Merging a parsed config turns the TUN on over one that left it off, and
/// one that leaves it off does not turn off a TUN the earlier one turned on,
/// since a parsed `false` may be a key left out.
#[test]
fn merging_a_parsed_config_turns_the_tun_on_but_not_off() {
    assert!(merged(with_tun(false), with_tun(true)).tun.enabled);
    assert!(merged(with_tun(true), with_tun(false)).tun.enabled);
}

/// A later file's `tun.name` and `tun.mtu` replace the earlier file's when
/// it sets them, and the earlier values stay when it does not.
#[test]
fn a_later_tun_name_or_mtu_replaces_the_earlier_one_and_an_unset_one_keeps_it() {
    let mut base = Config::new();
    base.tun.name = Some("early0".to_string());
    base.tun.mtu = Some(1400);

    let mut later = Config::new();
    later.tun.name = Some("late0".to_string());
    later.tun.mtu = Some(1300);
    let replaced = merged(base.clone(), later);
    assert_eq!(replaced.tun.name.as_deref(), Some("late0"));
    assert_eq!(replaced.tun.mtu, Some(1300));

    let kept = merged(base, Config::new());
    assert_eq!(kept.tun.name.as_deref(), Some("early0"));
    assert_eq!(kept.tun.mtu, Some(1400));
}

/// Merging a parsed config always takes its `dns.enabled`: one at the default
/// of true turns the responder back on, and one set false turns it off.
#[test]
fn merging_a_parsed_config_always_takes_dns_enabled_even_at_its_default() {
    let later = Config::new();
    assert!(later.dns.enabled, "the default this test relies on");
    assert!(merged(with_dns(false), later).dns.enabled);
    assert!(!merged(with_dns(true), with_dns(false)).dns.enabled);
}

/// A later file's `dns.bind_addr`, `dns.port` and `dns.ttl` each replace
/// the earlier file's when it sets them, and the earlier values stay when it
/// does not.
#[test]
fn a_later_dns_bind_addr_port_or_ttl_replaces_the_earlier_one_and_an_unset_one_keeps_it() {
    let mut base = Config::new();
    base.dns.bind_addr = Some("::1".to_string());
    base.dns.port = Some(5354);
    base.dns.ttl = Some(300);

    let mut later = Config::new();
    later.dns.bind_addr = Some("::".to_string());
    later.dns.port = Some(5353);
    later.dns.ttl = Some(60);
    let replaced = merged(base.clone(), later);
    assert_eq!(replaced.dns.bind_addr.as_deref(), Some("::"));
    assert_eq!(replaced.dns.port, Some(5353));
    assert_eq!(replaced.dns.ttl, Some(60));

    let kept = merged(base, Config::new());
    assert_eq!(kept.dns.bind_addr.as_deref(), Some("::1"));
    assert_eq!(kept.dns.port, Some(5354));
    assert_eq!(kept.dns.ttl, Some(300));
}

/// Load configuration files in order through `load_from_paths`, the path
/// `Config::load` takes over the search paths, and return the result.
fn loaded(files: &[&str]) -> Config {
    let dir = tempfile::TempDir::new().unwrap();
    let paths: Vec<PathBuf> = files
        .iter()
        .enumerate()
        .map(|(i, text)| {
            let path = dir.path().join(format!("{i}.yaml"));
            std::fs::write(&path, text).unwrap();
            path
        })
        .collect();
    Config::load_from_paths(&paths).expect("the files load").0
}

/// The first file every layering test starts from: a transport, so the
/// merged result is never refused as configuring nothing, and `extra`.
fn base(extra: &str) -> String {
    format!("transports:\n  udp: {{}}\n{extra}")
}

/// A later file that sets `tun.enabled: false` turns off a TUN an earlier
/// file turned on; one that does not name the key leaves it on.
#[test]
fn a_later_file_setting_tun_enabled_false_turns_the_tun_off() {
    let earlier = base("tun:\n  enabled: true\n");
    for later in ["peers: []\n", "tun:\n", "tun:\n  mtu: 1400\n"] {
        assert!(
            loaded(&[&earlier, later]).tun.enabled,
            "a later file not naming tun.enabled ({later:?}) turned the TUN off"
        );
    }
    assert!(
        !loaded(&[&earlier, "tun:\n  enabled: false\n"]).tun.enabled,
        "the later file's tun.enabled: false did not turn the TUN off"
    );
    assert!(
        loaded(&[&base(""), "tun:\n  enabled: true\n"]).tun.enabled,
        "a later file's tun.enabled: true did not turn the TUN on"
    );
}

/// A later file that does not name `dns.enabled` leaves off a responder an
/// earlier file turned off, including one with a bare `dns:` header; one
/// that sets it true turns it back on, and false over true turns it off.
#[test]
fn a_later_file_that_does_not_name_dns_enabled_keeps_the_earlier_value() {
    let off = base("dns:\n  enabled: false\n");
    for later in ["peers: []\n", "dns:\n", "dns:\n  port: 5355\n"] {
        assert!(
            !loaded(&[&off, later]).dns.enabled,
            "a later file not naming dns.enabled ({later:?}) turned the responder back on"
        );
    }
    assert!(
        loaded(&[&off, "dns:\n  enabled: true\n"]).dns.enabled,
        "a later dns.enabled: true did not turn the responder on"
    );
    assert!(
        !loaded(&[&base(""), "dns:\n  enabled: false\n"]).dns.enabled,
        "a later dns.enabled: false did not turn the default responder off"
    );
    assert!(
        loaded(&[&base(""), "peers: []\n"]).dns.enabled,
        "with no file naming dns.enabled the responder is not on by default"
    );
}

/// A later file that sets `node.identity.persistent: false` turns off
/// persistence an earlier file turned on; one that does not name the key
/// leaves it on.
#[test]
fn a_later_file_setting_identity_persistent_false_turns_persistence_off() {
    let earlier = base("node:\n  identity:\n    persistent: true\n");
    for later in [
        "peers: []\n",
        "node:\n  identity:\n",
        "node:\n  leaf_only: true\n",
    ] {
        assert!(
            loaded(&[&earlier, later]).node.identity.persistent,
            "a later file not naming persistent ({later:?}) turned persistence off"
        );
    }
    assert!(
        !loaded(&[&earlier, "node:\n  identity:\n    persistent: false\n"])
            .node
            .identity
            .persistent,
        "the later file's identity.persistent: false did not turn persistence off"
    );
}

/// When `node.identity.persistent: true` is the only thing the files
/// configure, a later `false` leaves them configuring nothing, so the load is
/// refused rather than starting an ephemeral node that would move `fips.key`
/// aside.
#[test]
fn a_later_persistent_false_over_files_that_configure_nothing_else_is_refused() {
    let dir = tempfile::TempDir::new().unwrap();
    let paths = [dir.path().join("0.yaml"), dir.path().join("1.yaml")];
    std::fs::write(&paths[0], "node:\n  identity:\n    persistent: true\n").unwrap();
    std::fs::write(&paths[1], "node:\n  identity:\n    persistent: false\n").unwrap();
    assert!(
        Config::load_from_paths(&paths[..1]).is_ok(),
        "the persistent file alone loads"
    );
    let err = Config::load_from_paths(&paths).expect_err("the two files load");
    assert!(
        matches!(
            &err,
            ConfigError::EmptyConfig { paths: found } if found.as_slice() == paths.as_slice()
        ),
        "{err}"
    );
}

/// Three files: each flag takes the value of the last file that names it,
/// whatever the files between say about other keys.
#[test]
fn each_enable_flag_takes_the_value_of_the_last_file_that_names_it() {
    let config = loaded(&[
        &base("tun:\n  enabled: true\ndns:\n  enabled: false\n"),
        "tun:\n  enabled: false\ndns:\n  enabled: true\n",
        "tun:\n  name: late0\ndns:\n  ttl: 60\n",
    ]);
    assert!(!config.tun.enabled, "the middle file turned the TUN off");
    assert!(
        config.dns.enabled,
        "the middle file turned the responder on"
    );
    assert_eq!(config.tun.name.as_deref(), Some("late0"));
    assert_eq!(config.dns.ttl, Some(60));
}
