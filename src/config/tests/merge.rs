//! Tests for how `Config::merge` layers a later configuration file's `tun`
//! and `dns` sections over an earlier one's.

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

/// A later file turns the TUN on over an earlier file that left it off, and
/// one that leaves it off does not turn off a TUN an earlier file turned on.
#[test]
fn a_later_file_can_turn_the_tun_on_but_not_off() {
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

/// A later file decides `dns.enabled` whatever it holds: one that leaves the
/// key at its default of true turns the responder back on, and one that
/// sets it false turns it off.
#[test]
fn a_later_file_always_decides_whether_dns_is_enabled_even_at_its_default() {
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
