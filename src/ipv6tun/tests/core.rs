use super::*;
use crate::ipv6tun::icmp::{effective_ipv6_mtu, mss_ceiling};
use crate::ipv6tun::ipv6_shim::HEADER_SAVING;
use crate::ipv6tun::link::any_key;
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
    assert!(state.paths().read().unwrap().is_empty());
}

#[test]
fn applying_the_node_messages_updates_the_shared_state() {
    let state = MeshState::new();
    let ceiling = state.ceiling();
    let paths = state.paths();
    let us = any_key();
    let peer = any_key();

    assert_eq!(
        state.apply(FromMesh::Attached {
            node: us,
            payload_limit: payload_limit(1357),
        }),
        Applied::Attached(us.address().to_ipv6())
    );
    assert_eq!(ceiling.load(Ordering::Relaxed), mss_ceiling(1357));

    state.apply(FromMesh::PathMtu {
        peer,
        payload_limit: Some(payload_limit(1280)),
    });
    assert_eq!(
        paths.read().unwrap().get(&peer.address()).copied(),
        Some(payload_limit(1280))
    );

    state.apply(FromMesh::NodeMtu {
        payload_limit: payload_limit(1500),
    });
    assert_eq!(ceiling.load(Ordering::Relaxed), mss_ceiling(1500));
    assert_eq!(state.ipv6_mtu(), effective_ipv6_mtu(1500));

    state.apply(FromMesh::PathMtu {
        peer,
        payload_limit: None,
    });
    assert!(paths.read().unwrap().is_empty());
    assert_eq!(state.apply(FromMesh::Synced), Applied::Synced);
}

#[test]
fn the_key_map_takes_known_keys_and_drops_forgotten_ones_by_prefix() {
    let state = MeshState::new();
    let peer = any_key();
    let prefix = peer.addr().prefix();
    assert_eq!(state.key(&prefix), None);
    state.apply(FromMesh::KnownKey { peer });
    assert_eq!(state.key(&prefix), Some(peer));
    state.apply(FromMesh::ForgotKey { peer, learned: 0 });
    assert_eq!(state.key(&prefix), None);
}

#[test]
fn a_key_learned_after_the_node_decided_to_forget_it_is_kept() {
    let state = MeshState::new();
    let peer = any_key();
    state.apply(FromMesh::KnownKey { peer });
    let report = state.learn(peer);
    assert_eq!(report.seq, 1);
    state.apply(FromMesh::ForgotKey {
        peer,
        learned: report.seq - 1,
    });
    assert_eq!(state.key(&peer.addr().prefix()), Some(peer), "kept");
    state.apply(FromMesh::ForgotKey {
        peer,
        learned: report.seq,
    });
    assert_eq!(
        state.key(&peer.addr().prefix()),
        None,
        "the node had seen it"
    );
}

#[test]
fn an_attach_drops_every_key_before_its_replay() {
    let state = MeshState::new();
    let old = any_key();
    state.apply(FromMesh::KnownKey { peer: old });
    state.apply(FromMesh::Attached {
        node: any_key(),
        payload_limit: 1170,
    });
    assert_eq!(state.key(&old.addr().prefix()), None);
}

/// The address the companion of the key map holds for `peer`, if any.
fn companion(state: &MeshState, peer: &PeerKey) -> Option<crate::Ipv6Address> {
    state.addresses.read().unwrap().get(peer).copied()
}

#[test]
fn the_address_companion_follows_known_and_forgotten_keys() {
    let state = MeshState::new();
    let peer = any_key();
    state.apply(FromMesh::KnownKey { peer });
    assert_eq!(companion(&state, &peer), Some(peer.address()));
    assert_eq!(state.address(&peer), peer.address());
    state.apply(FromMesh::ForgotKey { peer, learned: 0 });
    assert_eq!(companion(&state, &peer), None);
}

#[test]
fn the_address_companion_keeps_a_key_learned_after_the_node_decided_to_forget_it() {
    let state = MeshState::new();
    let peer = any_key();
    state.apply(FromMesh::KnownKey { peer });
    let report = state.learn(peer);
    state.apply(FromMesh::ForgotKey {
        peer,
        learned: report.seq - 1,
    });
    assert_eq!(companion(&state, &peer), Some(peer.address()), "kept");
    state.apply(FromMesh::ForgotKey {
        peer,
        learned: report.seq,
    });
    assert_eq!(companion(&state, &peer), None, "the node had seen it");
}

#[test]
fn a_key_the_dns_responder_learned_is_in_the_address_companion() {
    let state = MeshState::new();
    let peer = any_key();
    state.learn(peer);
    assert_eq!(companion(&state, &peer), Some(peer.address()));
}

#[test]
fn an_attach_clears_the_address_companion() {
    let state = MeshState::new();
    let old = any_key();
    state.apply(FromMesh::KnownKey { peer: old });
    state.apply(FromMesh::Attached {
        node: any_key(),
        payload_limit: 1170,
    });
    assert_eq!(companion(&state, &old), None);
}

#[test]
fn a_prefix_that_changes_hands_drops_the_old_keys_address() {
    // Two keys whose addresses share a prefix cannot be generated, so the
    // old holder is placed under the new key's prefix by hand, with its
    // address, as a KnownKey for it would have left them.
    let state = MeshState::new();
    let old = any_key();
    let new = any_key();
    state.keys.write().unwrap().insert(
        new.addr().prefix(),
        Known {
            peer: old,
            learned: 0,
        },
    );
    state.addresses.write().unwrap().insert(old, old.address());
    state.apply(FromMesh::KnownKey { peer: new });
    assert_eq!(state.key(&new.addr().prefix()), Some(new));
    assert_eq!(
        companion(&state, &old),
        None,
        "the old holder's address goes"
    );
    assert_eq!(companion(&state, &new), Some(new.address()));
}

#[test]
fn the_address_of_a_key_the_adapter_does_not_hold_is_hashed_from_the_key() {
    let state = MeshState::new();
    let stranger = any_key();
    assert_eq!(companion(&state, &stranger), None);
    assert_eq!(state.address(&stranger), stranger.address());
}
