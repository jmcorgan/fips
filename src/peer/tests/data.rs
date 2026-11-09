//! Unit tests for `PeerData` (`src/peer/data.rs`).

use super::*;
use crate::config::MmpConfig;
use crate::node::diag::HsLine;
use crate::noise::{HandshakeState, NoiseSession};
use crate::peer::{ActivePeer, LinkCaps, peer_now, test_caps, test_link_params};
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::IndexAllocator;
use crate::{Identity, PeerIdentity};
use fips_core::proto::rekey::{IndexLease, NodeKeys, Record};

const AUTHENTICATED_AT: u64 = 1000;

/// Link statistics a constructor can only have from its argument.
fn stats_with(packets_sent: u64) -> LinkStats {
    let mut stats = LinkStats::new();
    stats.packets_sent = packets_sent;
    stats
}

fn make_peer_identity() -> PeerIdentity {
    PeerIdentity::from_pubkey(Identity::generate().pubkey())
}

/// The initiator's end of a completed IK handshake, and the identity of the
/// peer it authenticated.
fn ik_session() -> (NoiseSession, PeerIdentity) {
    let (ours, theirs) = (Identity::generate(), Identity::generate());
    let mut initiator = HandshakeState::new_initiator(ours.keypair(), theirs.pubkey_full());
    initiator.set_local_epoch([1; 8]);
    let mut responder = HandshakeState::new_responder(theirs.keypair());
    responder.set_local_epoch([2; 8]);
    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    (
        initiator.into_session().unwrap(),
        PeerIdentity::from_pubkey(theirs.pubkey()),
    )
}

/// A peer built by `with_session`, the constructor a real promotion runs.
fn promoted_peer(is_initiator: bool, link_stats: LinkStats) -> ActivePeer {
    let (session, identity) = ik_session();
    let local = NodeKeys::new(Identity::generate().keypair(), [0; 8]);
    let mut indices = IndexAllocator::new();
    let mut caps = LinkCaps {
        indices: &mut indices,
        local: &local,
        me: *identity.node_addr(),
        params: test_link_params(),
        record: Record::new(),
        workers: false,
        path: test_caps(),
    };
    let built = ActivePeer::with_session(
        identity,
        LinkId::new(1),
        AUTHENTICATED_AT,
        session,
        IndexLease::for_test(1),
        SessionIndex::new(2),
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:9000"),
        link_stats,
        is_initiator,
        &MmpConfig::default(),
        None,
        &mut caps,
    );
    let Ok((peer, _outputs)) = built else {
        panic!("the session authenticated the identity's key");
    };
    peer
}

/// A peer built by `with_test_session`, which writes the record by itself.
fn test_keyed_peer(is_initiator: bool, link_stats: LinkStats) -> ActivePeer {
    let (session, identity) = ik_session();
    ActivePeer::with_test_session(
        identity,
        LinkId::new(1),
        AUTHENTICATED_AT,
        session,
        SessionIndex::new(1),
        SessionIndex::new(2),
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:9000"),
        link_stats,
        is_initiator,
        &MmpConfig::default(),
        None,
    )
}

/// The values of a new record that differ between its constructors.
struct Differs {
    /// `is_heard`.
    heard: bool,
    /// `link_stats().packets_sent`.
    packets_sent: u64,
    /// The MMP spin role, `None` for a peer that holds no MMP.
    spin_initiator: Option<bool>,
}

/// Assert that `peer`, built no earlier than `before`, holds a new record: read
/// through `ActivePeer`, every field, so that a transcription into the record
/// reds here under the constructor's `name`.
fn assert_new_record(name: &str, peer: &mut ActivePeer, before: PeerInstant, want: Differs) {
    assert!(peer.declaration().is_none(), "{name}: declaration");
    assert!(peer.coords().is_none(), "{name}: ancestry");

    assert_eq!(peer.last_tree_announce_sent_ms(), None, "{name}: stamp");
    assert!(
        !peer.has_pending_tree_announce(),
        "{name}: pending tree announce"
    );
    assert!(peer.inbound_filter().is_none(), "{name}: inbound filter");
    assert_eq!(peer.filter_sequence(), 0, "{name}: filter sequence");
    assert!(
        peer.filter_is_stale(0, u64::MAX),
        "{name}: a filter was received"
    );
    assert!(peer.needs_filter_update(), "{name}: a filter is owed");

    assert_eq!(peer.authenticated_at(), AUTHENTICATED_AT, "{name}: auth");
    assert_eq!(
        peer.link_stats().packets_sent,
        want.packets_sent,
        "{name}: link stats"
    );
    assert_eq!(peer.last_seen(), AUTHENTICATED_AT, "{name}: last seen");
    assert!(peer.last_heartbeat_sent().is_none(), "{name}: heartbeat");
    assert!(
        peer.last_heartbeat_attempt().is_none(),
        "{name}: heartbeat attempt"
    );

    let after = peer_now();
    let promoted = peer.promoted_at();
    assert!(
        before <= promoted && promoted <= after,
        "{name}: promoted at construction"
    );
    assert_eq!(
        peer.heard_at(),
        promoted,
        "{name}: heard at is the promotion"
    );
    assert_eq!(peer.is_heard(), want.heard, "{name}: heard");
    assert!(!peer.heard(), "{name}: no frame heard yet");

    assert!(peer.handshake_msg2().is_none(), "{name}: stored msg2");
    assert!(peer.setup_ephemeral().is_none(), "{name}: setup ephemeral");

    assert!(peer.hs_lines().unreported().is_none(), "{name}: hs lines");
    assert_eq!(peer.replay_suppressed_total(), 0, "{name}: replay total");
    assert_eq!(peer.replay_suppressed_count(), 0, "{name}: replay count");
    assert_eq!(peer.prev_frames(), 0, "{name}: previous session frames");
    assert_eq!(peer.last_failed(), None, "{name}: failed index");

    assert_eq!(
        peer.mmp().map(|mmp| mmp.spin_bit.is_initiator()),
        want.spin_initiator,
        "{name}: MMP"
    );

    assert_eq!(
        peer.hs_lines_mut().count(HsLine::Resend),
        1,
        "{name}: line counts start at nothing"
    );
    peer.record_tree_announce_sent(AUTHENTICATED_AT);
    assert!(
        !peer.can_send_tree_announce(AUTHENTICATED_AT + 499),
        "{name}: the announce interval is not 500 ms"
    );
    assert!(
        peer.can_send_tree_announce(AUTHENTICATED_AT + 500),
        "{name}: the announce interval is not 500 ms"
    );
}

#[test]
fn a_new_record_holds_what_each_constructor_held_before() {
    let before = peer_now();
    let mut new = ActivePeer::new(make_peer_identity(), LinkId::new(1), AUTHENTICATED_AT);
    assert_new_record(
        "new",
        &mut new,
        before,
        Differs {
            heard: true,
            packets_sent: 0,
            spin_initiator: None,
        },
    );

    let before = peer_now();
    let mut with_stats = ActivePeer::with_stats(
        make_peer_identity(),
        LinkId::new(1),
        AUTHENTICATED_AT,
        stats_with(7),
    );
    assert_new_record(
        "with_stats",
        &mut with_stats,
        before,
        Differs {
            heard: true,
            packets_sent: 7,
            spin_initiator: None,
        },
    );

    type Build = fn(bool, LinkStats) -> ActivePeer;
    let keyed: [(&str, Build); 2] = [
        ("with_session", promoted_peer),
        ("with_test_session", test_keyed_peer),
    ];
    for (constructor, build) in keyed {
        for is_initiator in [true, false] {
            let name = format!("{constructor}, is_initiator {is_initiator}");
            let before = peer_now();
            let mut peer = build(is_initiator, stats_with(9));
            assert_new_record(
                &name,
                &mut peer,
                before,
                Differs {
                    heard: is_initiator,
                    packets_sent: 9,
                    spin_initiator: Some(is_initiator),
                },
            );
        }
    }

    // No accessor tells these from a value they replaced: the replay count
    // saturates at a base above the total.
    let record = PeerData::new(AUTHENTICATED_AT, peer_now(), false);
    assert_eq!(record.replay_base, 0, "replay base");
    assert_eq!(record.filter_received_at, 0, "filter received at");
    assert_eq!(
        record.tree_announce_min_interval_ms, 500,
        "announce interval"
    );
}
