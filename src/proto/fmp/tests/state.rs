//! Unit tests for the pure FMP connection state ([`ConnectionState`]). These
//! exercise the extracted bookkeeping directly, with no crypto involved; the
//! crypto-driving transition behavior is covered by the shell `peer::connection`
//! suite, and the handshake phase itself lives on the control machine.

use crate::proto::fmp::ConnectionState;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::SessionIndex;
use crate::{Identity, PeerIdentity};

fn make_peer_identity() -> PeerIdentity {
    PeerIdentity::from_pubkey(Identity::generate().pubkey())
}

#[test]
fn outbound_initializes_pure_fields() {
    let identity = make_peer_identity();
    let state = ConnectionState::outbound(LinkId::new(1), identity, 1000);

    assert!(state.is_outbound());
    assert!(!state.is_inbound());
    assert!(state.expected_identity().is_some());
    assert_eq!(state.link_id(), LinkId::new(1));
    assert_eq!(state.started_at(), 1000);
    assert_eq!(state.last_activity(), 1000);
    assert!(state.transport_id().is_none());
    assert!(state.source_addr().is_none());
    assert!(state.remote_epoch().is_none());
    assert_eq!(state.resend_count(), 0);
    assert_eq!(state.next_resend_at_ms(), 0);
}

#[test]
fn inbound_initializes_pure_fields() {
    let state = ConnectionState::inbound(LinkId::new(2), 2000);

    assert!(state.is_inbound());
    assert!(!state.is_outbound());
    assert!(state.expected_identity().is_none());
    assert_eq!(state.started_at(), 2000);
}

#[test]
fn inbound_with_transport_sets_transport_and_addr() {
    let addr = TransportAddr::from_string("192.0.2.1:5000");
    let state =
        ConnectionState::inbound_with_transport(LinkId::new(3), TransportId::new(7), addr, 3000);

    assert!(state.is_inbound());
    assert_eq!(state.transport_id(), Some(TransportId::new(7)));
    assert_eq!(
        state.source_addr().map(|a| a.as_str().unwrap().to_string()),
        Some("192.0.2.1:5000".to_string())
    );
}

#[test]
fn index_setters_round_trip() {
    let mut state = ConnectionState::inbound(LinkId::new(1), 0);
    assert!(state.our_index().is_none());
    assert!(state.their_index().is_none());

    state.set_our_index(SessionIndex::new(0x1111));
    state.set_their_index(SessionIndex::new(0x2222));
    assert_eq!(state.our_index(), Some(SessionIndex::new(0x1111)));
    assert_eq!(state.their_index(), Some(SessionIndex::new(0x2222)));
}

#[test]
fn transport_and_source_setters_round_trip() {
    let mut state = ConnectionState::outbound(LinkId::new(1), make_peer_identity(), 0);
    state.set_transport_id(TransportId::new(9));
    state.set_source_addr(TransportAddr::from_string("peer"));
    assert_eq!(state.transport_id(), Some(TransportId::new(9)));
    assert_eq!(state.source_addr().and_then(|a| a.as_str()), Some("peer"));
}

#[test]
fn identity_and_epoch_setters() {
    let mut state = ConnectionState::inbound(LinkId::new(1), 0);
    assert!(state.expected_identity().is_none());
    assert!(state.remote_epoch().is_none());

    let identity = make_peer_identity();
    let node_addr = *identity.node_addr();
    state.set_expected_identity(identity);
    state.set_remote_epoch(Some([9u8; 8]));

    assert_eq!(
        state.expected_identity().map(|id| *id.node_addr()),
        Some(node_addr)
    );
    assert_eq!(state.remote_epoch(), Some([9u8; 8]));
}

#[test]
fn resend_bookkeeping() {
    let mut state = ConnectionState::outbound(LinkId::new(1), make_peer_identity(), 0);
    assert!(state.handshake_msg1().is_none());
    assert!(state.handshake_msg2().is_none());

    state.set_handshake_msg1(vec![1, 2, 3], 500);
    assert_eq!(state.handshake_msg1(), Some(&[1u8, 2, 3][..]));
    assert_eq!(state.resend_count(), 0);
    assert_eq!(state.next_resend_at_ms(), 500);

    state.record_resend(900);
    assert_eq!(state.resend_count(), 1);
    assert_eq!(state.next_resend_at_ms(), 900);

    state.record_resend(1300);
    assert_eq!(state.resend_count(), 2);
    assert_eq!(state.next_resend_at_ms(), 1300);

    // set_handshake_msg1 resets the resend counter.
    state.set_handshake_msg1(vec![4, 5], 100);
    assert_eq!(state.handshake_msg1(), Some(&[4u8, 5][..]));
    assert_eq!(state.resend_count(), 0);
    assert_eq!(state.next_resend_at_ms(), 100);

    state.set_handshake_msg2(vec![6, 7, 8]);
    assert_eq!(state.handshake_msg2(), Some(&[6u8, 7, 8][..]));
}

#[test]
fn timing_and_touch() {
    let mut state = ConnectionState::outbound(LinkId::new(1), make_peer_identity(), 1000);
    assert_eq!(state.duration(1500), 500);
    assert_eq!(state.idle_time(1500), 500);
    assert!(!state.is_timed_out(1500, 1000));
    assert!(state.is_timed_out(2500, 1000));

    // touch resets idle_time but not duration.
    state.touch(2000);
    assert_eq!(state.last_activity(), 2000);
    assert_eq!(state.idle_time(2500), 500);
    assert_eq!(state.duration(2500), 1500);
    assert!(!state.is_timed_out(2500, 1000));
}
