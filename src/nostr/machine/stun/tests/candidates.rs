use super::{InterfaceAddr, is_private_overlay_candidate_ip, local_candidates};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[test]
fn private_overlay_candidate_filter_includes_rfc1918_and_ula() {
    assert!(is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
        192, 168, 1, 10
    ))));
    assert!(is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
        10, 0, 0, 4
    ))));
    assert!(is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
        172, 16, 5, 20
    ))));
    assert!(is_private_overlay_candidate_ip(IpAddr::V6(
        "fd00::1234".parse::<Ipv6Addr>().unwrap()
    )));
}

#[test]
fn private_overlay_candidate_filter_excludes_public_and_link_local() {
    assert!(!is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
        8, 8, 8, 8
    ))));
    assert!(!is_private_overlay_candidate_ip(IpAddr::V4(Ipv4Addr::new(
        169, 254, 1, 10
    ))));
    assert!(!is_private_overlay_candidate_ip(IpAddr::V6(
        "fe80::1".parse::<Ipv6Addr>().unwrap()
    )));
    assert!(!is_private_overlay_candidate_ip(IpAddr::V6(
        "2001:db8::1".parse::<Ipv6Addr>().unwrap()
    )));
}

/// An interface address with the given flags.
fn iface(ip: &str, up: bool, loopback: bool) -> InterfaceAddr {
    InterfaceAddr {
        ip: ip.parse().unwrap(),
        up,
        loopback,
    }
}

#[test]
fn selection_takes_private_interface_addresses_in_listing_order_then_the_observed_ones() {
    let interfaces = [
        iface("192.168.1.10", true, false),
        iface("fd00::5", true, false),
        iface("10.0.0.4", true, false),
    ];
    let observed = [
        Some("192.168.1.10".parse().unwrap()),
        Some("2001:db8::7".parse().unwrap()),
        None,
        Some("0.0.0.0".parse().unwrap()),
    ];
    assert_eq!(
        local_candidates(&interfaces, &observed),
        ["192.168.1.10", "fd00::5", "10.0.0.4", "2001:db8::7"]
    );
}

#[test]
fn selection_skips_down_loopback_and_public_interface_addresses() {
    let interfaces = [
        iface("192.168.1.10", false, false),
        iface("10.0.0.1", true, true),
        iface("8.8.4.4", true, false),
        iface("fe80::1", true, false),
        iface("172.16.5.20", true, false),
    ];
    assert_eq!(local_candidates(&interfaces, &[]), ["172.16.5.20"]);
}

#[test]
fn selection_keeps_an_observed_address_whatever_its_range() {
    let observed = [
        Some("203.0.113.9".parse().unwrap()),
        Some("::".parse().unwrap()),
    ];
    assert_eq!(local_candidates(&[], &observed), ["203.0.113.9"]);
}
