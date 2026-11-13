use super::*;

fn ip(text: &str) -> IpAddr {
    text.parse().expect("test address")
}

fn set(pairs: &[(&str, u8)]) -> OnLinkPrefixes {
    OnLinkPrefixes::from_pairs(pairs.iter().map(|(a, l)| (ip(a), *l)))
}

#[test]
fn ipv4_prefixes_hold_exactly_their_range() {
    let s24 = set(&[("192.168.1.10", 24)]);
    assert!(s24.contains(ip("192.168.1.200")));
    assert!(!s24.contains(ip("192.168.2.1")));

    let s25 = set(&[("192.168.1.10", 25)]);
    assert!(s25.contains(ip("192.168.1.127")));
    assert!(!s25.contains(ip("192.168.1.128")));

    let s16 = set(&[("10.20.1.1", 16)]);
    assert!(s16.contains(ip("10.20.7.8")));
    assert!(!s16.contains(ip("10.21.0.1")));

    let s32 = set(&[("203.0.113.5", 32)]);
    assert!(s32.contains(ip("203.0.113.5")));
    assert!(!s32.contains(ip("203.0.113.6")));
}

#[test]
fn ipv6_prefixes_hold_exactly_their_range() {
    let s64 = set(&[("fd00::2", 64)]);
    assert!(s64.contains(ip("fd00::1")));
    assert!(!s64.contains(ip("fd01::1")));

    let s128 = set(&[("2001:db8::1", 128)]);
    assert!(s128.contains(ip("2001:db8::1")));
    assert!(!s128.contains(ip("2001:db8::2")));
}

#[test]
fn ipv4_mapped_addresses_are_judged_as_ipv4() {
    let s = set(&[("::ffff:192.168.1.10", 24)]);
    assert!(s.contains(ip("192.168.1.7")));
    assert!(s.contains(ip("::ffff:192.168.1.7")));
    assert!(!s.contains(ip("::ffff:192.168.2.7")));
}

#[test]
fn a_zero_length_prefix_is_discarded_and_holds_nothing() {
    let s = set(&[("192.168.1.1", 0)]);
    assert!(s.is_empty());
    assert!(!s.contains(ip("8.8.8.8")));
}

#[test]
fn families_never_match_each_other() {
    let s = set(&[("192.168.1.1", 24)]);
    assert!(!s.contains(ip("fd00::1")));
}

#[test]
fn share_link_needs_one_prefix_holding_both_addresses() {
    let s = set(&[("192.168.1.1", 24), ("10.0.0.1", 8)]);
    assert!(s.share_link(ip("192.168.1.5"), ip("192.168.1.50")));
    assert!(!s.share_link(ip("192.168.1.5"), ip("10.9.8.7")));
    assert!(!s.share_link(ip("192.168.1.5"), ip("192.168.2.5")));
    assert!(OnLinkPrefixes::default().is_empty());
    assert!(!OnLinkPrefixes::default().share_link(ip("10.0.0.1"), ip("10.0.0.2")));
}

#[test]
fn contains_on_holds_only_the_named_interfaces_prefixes() {
    let s = OnLinkPrefixes::from_indexed([
        (ip("192.168.1.10"), 24, Some(2)),
        (ip("10.8.0.2"), 24, Some(3)),
        (ip("172.17.0.1"), 16, None),
    ]);
    assert!(s.contains_on(ip("192.168.1.7"), &[2]));
    assert!(!s.contains_on(ip("10.8.0.5"), &[2]));
    assert!(s.contains_on(ip("10.8.0.5"), &[2, 3]));
    assert!(
        !s.contains_on(ip("172.17.0.9"), &[2, 3]),
        "unknown interface"
    );
    assert!(!s.contains_on(ip("192.168.1.7"), &[]));
    assert!(s.contains(ip("172.17.0.9")));
    assert!(!set(&[("192.168.1.10", 24)]).contains_on(ip("192.168.1.7"), &[2]));
}

#[test]
fn a_discarded_zero_length_prefix_or_an_empty_read_is_reported() {
    let partly = set(&[("192.168.1.1", 0), ("10.0.0.1", 8)]);
    assert_eq!(partly.discarded(), 1);
    assert!(read_suspect(2, &partly));
    assert!(read_suspect(2, &OnLinkPrefixes::default()));
    assert!(!read_suspect(0, &OnLinkPrefixes::default()));
    let healthy = set(&[("10.0.0.1", 8)]);
    assert!(!read_suspect(1, &healthy));
}
