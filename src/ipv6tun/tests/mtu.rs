//! Each function against a literal copy of its earlier definition at every
//! `u16` input, so the saturating edges are covered, and the values at the
//! inputs the call sites pass.

use super::*;
use crate::ipv6tun::tun::IPV6_MIN_MTU;
use crate::proto::framing::payload_limit;

/// The transport form as first written: the transport MTU less 77.
fn old_effective(transport_mtu: u16) -> u16 {
    transport_mtu.saturating_sub(77)
}

/// The transport-form TCP MSS as first written.
fn old_ceiling(transport_mtu: u16) -> u16 {
    old_effective(transport_mtu)
        .saturating_sub(40)
        .saturating_sub(20)
}

/// The payload-limit form as first written: the limit plus 33.
fn old_ipv6(limit: u16) -> u16 {
    limit.saturating_add(33)
}

/// The payload-limit TCP MSS as first written.
fn old_mss(limit: u16) -> u16 {
    old_ipv6(limit).saturating_sub(40).saturating_sub(20)
}

/// The adapter's seed expression as first written, at any transport MTU.
fn old_seed(transport_mtu: u16) -> u16 {
    old_effective(transport_mtu).saturating_sub(33)
}

#[test]
fn effective_ipv6_mtu_equals_the_old_transport_mtu_less_77_at_every_u16() {
    for t in 0..=u16::MAX {
        assert_eq!(effective_ipv6_mtu(t), old_effective(t), "transport MTU {t}");
    }
}

#[test]
fn mss_ceiling_equals_the_old_definition_at_every_u16() {
    for t in 0..=u16::MAX {
        assert_eq!(mss_ceiling(t), old_ceiling(t), "transport MTU {t}");
    }
}

#[test]
fn ipv6_mtu_equals_the_old_payload_limit_plus_33_at_every_u16_including_saturation() {
    for l in 0..=u16::MAX {
        assert_eq!(ipv6_mtu(l), old_ipv6(l), "payload limit {l}");
    }
}

#[test]
fn tcp_mss_equals_the_old_definition_at_every_u16() {
    for l in 0..=u16::MAX {
        assert_eq!(tcp_mss(l), old_mss(l), "payload limit {l}");
    }
}

#[test]
fn the_payload_limit_equals_the_old_adapter_seed_expression_at_every_u16() {
    for t in 0..=u16::MAX {
        assert_eq!(payload_limit(t), old_seed(t), "transport MTU {t}");
    }
}

#[test]
fn the_known_answers_at_the_call_site_inputs_are_unchanged() {
    assert_eq!(FIPS_IPV6_OVERHEAD, 77);
    assert_eq!(IPV6_MIN_MTU + FIPS_IPV6_OVERHEAD, 1357);
    assert_eq!(effective_ipv6_mtu(1280), 1203);
    assert_eq!(mss_ceiling(1280), 1143);
    assert_eq!(mss_ceiling(137), 0);
    assert_eq!(mss_ceiling(138), 1);
    assert_eq!(ipv6_mtu(1170), 1203);
    assert_eq!(tcp_mss(1170), 1143);
    assert_eq!(tcp_mss(27), 0);
    assert_eq!(tcp_mss(28), 1);
    assert_eq!(crate::config::UdpConfig::default().mtu(), 1357);
}
