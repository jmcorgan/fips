use super::payload_limit;

/// The payload limit as it was first written, with the framing overhead
/// (106) and the port header (4) as literals, so a change to either
/// constant also shows here.
fn old_limit(mtu: u16) -> u16 {
    mtu.saturating_sub(106).saturating_sub(4)
}

#[test]
fn payload_limit_equals_the_old_two_step_subtraction_at_every_u16() {
    for mtu in 0..=u16::MAX {
        assert_eq!(payload_limit(mtu), old_limit(mtu), "mtu {mtu}");
    }
}

#[test]
fn payload_limit_is_zero_up_to_110_bytes_and_1170_at_the_ipv6_minimum() {
    assert_eq!(payload_limit(0), 0);
    assert_eq!(payload_limit(109), 0);
    assert_eq!(payload_limit(110), 0);
    assert_eq!(payload_limit(111), 1);
    assert_eq!(payload_limit(1280), 1170);
    assert_eq!(payload_limit(u16::MAX), 65425);
}
