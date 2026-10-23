use super::*;
use crate::ipv6tun::icmp::mss_ceiling;
use crate::ipv6tun::link::PeerKey;
use crate::node::path_mtu::payload_limit;

#[test]
fn the_mss_ceiling_from_a_payload_limit_equals_the_one_from_the_transport_mtu_for_every_mtu() {
    for mtu in 0..=u16::MAX {
        assert_eq!(
            tcp_mss(payload_limit(mtu)),
            mss_ceiling(mtu),
            "transport MTU {mtu}"
        );
    }
}

#[test]
fn the_ipv6_mtu_from_a_payload_limit_equals_the_one_from_the_transport_mtu_from_110_up() {
    for mtu in 110..=u16::MAX {
        assert_eq!(
            ipv6_mtu(payload_limit(mtu)),
            effective_ipv6_mtu(mtu),
            "transport MTU {mtu}"
        );
    }
}

#[test]
fn below_110_the_payload_limit_reports_an_ipv6_mtu_of_33_where_too_small_for_any_packet() {
    // No IPv6 packet fits either way: the smallest is a 40-byte header.
    for mtu in 0..110 {
        assert_eq!(
            ipv6_mtu(payload_limit(mtu)),
            HEADER_SAVING,
            "transport MTU {mtu}"
        );
        assert!(effective_ipv6_mtu(mtu) < 40, "transport MTU {mtu}");
    }
}

#[test]
fn before_any_attach_the_state_is_the_ipv6_minimum() {
    let state = MeshState::new();
    assert_eq!(
        state.ceiling().load(Ordering::Relaxed),
        mss_ceiling(IPV6_MIN_MTU)
    );
    assert_eq!(state.ipv6_mtu(), effective_ipv6_mtu(IPV6_MIN_MTU));
}

#[test]
fn applying_the_node_messages_updates_the_shared_state() {
    let state = MeshState::new();
    let ceiling = state.ceiling();
    let us = PeerKey::any();

    assert_eq!(
        state.apply(FromMesh::Attached {
            node: us,
            payload_limit: payload_limit(1357),
        }),
        Applied::Attached(us.address().to_ipv6())
    );
    assert_eq!(ceiling.load(Ordering::Relaxed), mss_ceiling(1357));

    state.apply(FromMesh::NodeMtu {
        payload_limit: payload_limit(1500),
    });
    assert_eq!(ceiling.load(Ordering::Relaxed), mss_ceiling(1500));
    assert_eq!(state.ipv6_mtu(), effective_ipv6_mtu(1500));

    assert_eq!(state.apply(FromMesh::Synced), Applied::Synced);
}
