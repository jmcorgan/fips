//! Unit tests for `ActivePeer` (`src/peer/active.rs`).

use super::*;
use crate::Identity;
use crate::node::diag::HsLine;

fn make_peer_identity() -> PeerIdentity {
    let identity = Identity::generate();
    PeerIdentity::from_pubkey(identity.pubkey())
}

fn make_node_addr(val: u8) -> NodeAddr {
    let mut bytes = [0u8; 16];
    bytes[0] = val;
    NodeAddr::from_bytes(bytes)
}

fn make_coords(ids: &[u8]) -> TreeCoordinate {
    TreeCoordinate::from_addrs(ids.iter().map(|&v| make_node_addr(v)).collect()).unwrap()
}

#[test]
fn test_connectivity_state_properties() {
    assert!(!ConnectivityState::Connected.is_terminal());
    assert!(!ConnectivityState::Stale.is_terminal());
}

#[test]
fn test_active_peer_creation() {
    let identity = make_peer_identity();
    let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert_eq!(peer.identity().node_addr(), identity.node_addr());
    assert_eq!(peer.link_id(), LinkId::new(1));
    assert!(!peer.is_disconnected());
    assert_eq!(peer.authenticated_at(), 1000);
    assert!(peer.needs_filter_update()); // New peers need filter
}

#[test]
fn test_npub_cache_matches_identity() {
    let identity = make_peer_identity();
    let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert_eq!(peer.npub(), identity.npub());
    assert_eq!(peer.npub_str(), identity.npub());
    assert_eq!(peer.short_npub(), identity.short_npub());
}

#[test]
fn test_npub_cache_matches_identity_with_session() {
    // `with_session` builds its own struct literal, so it needs its
    // own check that the cache is populated from the same identity.
    let identity = make_peer_identity();
    let (session, _peer_session) = ik_session_pair();

    let peer = ActivePeer::with_session(
        identity,
        LinkId::new(1),
        1000,
        session,
        SessionIndex::new(1),
        SessionIndex::new(2),
        TransportId::new(1),
        TransportAddr::from_string("127.0.0.1:9000"),
        LinkStats::new(),
        true,
        &MmpConfig::default(),
        None,
    );

    assert_eq!(peer.npub(), identity.npub());
    assert_eq!(peer.short_npub(), identity.short_npub());
}

#[test]
fn test_npub_is_memoized_not_rederived() {
    // The whole point of the fix: the strings are stored on the peer,
    // not recomputed per call. A stored string keeps one heap buffer,
    // so repeated borrows have a stable address. A per-call bech32
    // encode would hand back a fresh allocation each time.
    let identity = make_peer_identity();
    let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    let first = peer.npub_str().as_ptr();
    let second = peer.npub_str().as_ptr();
    assert_eq!(first, second);

    let short_first = peer.short_npub().as_ptr();
    let short_second = peer.short_npub().as_ptr();
    assert_eq!(short_first, short_second);
}

#[test]
fn test_tree_position() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert!(!peer.has_tree_position());
    assert!(peer.coords().is_none());

    let node = make_node_addr(1);
    let parent = make_node_addr(2);
    let decl = ParentDeclaration::new(node, parent, 1, 1000);
    let coords = make_coords(&[1, 2, 0]);

    peer.update_tree_position(decl, coords, 2000);

    assert!(peer.has_tree_position());
    assert!(peer.coords().is_some());
    assert_eq!(peer.last_seen(), 2000);
}

#[test]
fn test_bloom_filter() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);
    let target = make_node_addr(42);

    assert!(!peer.may_reach(&target));
    assert!(peer.filter_is_stale(2000, 500));

    let mut filter = BloomFilter::new();
    filter.insert(&target);
    peer.update_filter(filter, 1, 1500);

    assert!(peer.may_reach(&target));
    assert!(!peer.filter_is_stale(1800, 500));
    assert!(peer.filter_is_stale(2500, 500));
}

#[test]
fn test_timing() {
    let identity = make_peer_identity();
    let peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert_eq!(peer.connection_duration(2000), 1000);
    assert_eq!(peer.idle_time(2000), 1000);
}

#[test]
fn test_filter_update_flag() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    assert!(peer.needs_filter_update()); // New peer

    peer.clear_filter_update_needed();
    assert!(!peer.needs_filter_update());

    peer.mark_filter_update_needed();
    assert!(peer.needs_filter_update());
}

#[test]
fn test_with_stats() {
    let identity = make_peer_identity();
    let mut stats = LinkStats::new();
    stats.record_sent(100);
    stats.record_recv(200, 500);

    let peer = ActivePeer::with_stats(identity, LinkId::new(1), 1000, stats);

    assert_eq!(peer.link_stats().packets_sent, 1);
    assert_eq!(peer.link_stats().packets_recv, 1);
}

#[test]
fn test_replay_suppression_counter() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    // Initial count is zero
    assert_eq!(peer.replay_suppressed_count(), 0);

    // Increment returns new count
    assert_eq!(peer.increment_replay_suppressed(), 1);
    assert_eq!(peer.increment_replay_suppressed(), 2);
    assert_eq!(peer.increment_replay_suppressed(), 3);
    assert_eq!(peer.replay_suppressed_count(), 3);

    // Reset returns previous count and zeroes it
    assert_eq!(peer.reset_replay_suppressed(), 3);
    assert_eq!(peer.replay_suppressed_count(), 0);

    // Can increment again after reset
    assert_eq!(peer.increment_replay_suppressed(), 1);
    assert_eq!(peer.replay_suppressed_count(), 1);

    // Reset when zero returns zero
    peer.reset_replay_suppressed();
    assert_eq!(peer.reset_replay_suppressed(), 0);
}

#[test]
fn test_increment_decrypt_failures_monotonic() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    // Initial count is zero
    assert_eq!(peer.consecutive_decrypt_failures(), 0);

    // Each call returns a strictly increasing count
    let mut prev = 0u32;
    for expected in 1..=25u32 {
        let count = peer.increment_decrypt_failures();
        assert_eq!(count, expected, "increment must return monotonic count");
        assert!(count > prev, "count must strictly increase");
        assert_eq!(peer.consecutive_decrypt_failures(), count);
        prev = count;
    }
}

#[test]
fn test_reset_decrypt_failures_zeroes_counter() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    // Drive counter up
    for _ in 0..7 {
        peer.increment_decrypt_failures();
    }
    assert_eq!(peer.consecutive_decrypt_failures(), 7);

    // Reset zeroes it
    peer.reset_decrypt_failures();
    assert_eq!(peer.consecutive_decrypt_failures(), 0);

    // Reset on zero is a no-op (still zero, no panic)
    peer.reset_decrypt_failures();
    assert_eq!(peer.consecutive_decrypt_failures(), 0);

    // Counter resumes at 1 after reset
    assert_eq!(peer.increment_decrypt_failures(), 1);
    assert_eq!(peer.consecutive_decrypt_failures(), 1);
}

#[test]
fn the_consecutive_decrypt_failure_counter_saturates_instead_of_overflowing() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);

    // Nothing resets the counter between authenticated frames, so a long
    // run of failures must not overflow it.
    peer.send.consecutive_decrypt_failures = u32::MAX - 1;
    assert_eq!(peer.increment_decrypt_failures(), u32::MAX);
    assert_eq!(peer.increment_decrypt_failures(), u32::MAX);
    assert_eq!(peer.consecutive_decrypt_failures(), u32::MAX);
}

#[test]
fn test_rekey_jitter_in_range() {
    // Every newly constructed peer's jitter must lie in the
    // symmetric range [-REKEY_JITTER_SECS, +REKEY_JITTER_SECS].
    for _ in 0..100 {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);
        let j = peer.rekey_jitter_secs();
        assert!(
            (-REKEY_JITTER_SECS..=REKEY_JITTER_SECS).contains(&j),
            "jitter {} outside [-{}, +{}]",
            j,
            REKEY_JITTER_SECS,
            REKEY_JITTER_SECS
        );
    }
}

#[test]
fn test_rekey_jitter_mean_near_zero() {
    // Sanity check that the distribution is roughly symmetric and
    // not stuck at one extreme. With N=200 draws from a uniform
    // ~30-second-wide range, the empirical mean should be well
    // under 5 in absolute value with overwhelming probability.
    let mut sum: i64 = 0;
    let n: i64 = 200;
    for _ in 0..n {
        let identity = make_peer_identity();
        let peer = ActivePeer::new(identity, LinkId::new(1), 1000);
        sum += peer.rekey_jitter_secs();
    }
    let mean = sum / n;
    assert!(
        mean.abs() < 5,
        "empirical mean {} not within 5 of 0 over {} samples",
        mean,
        n
    );
}

/// Put a peer into a rekey-in-progress state with a real (initiator)
/// handshake so the msg1 resend budget can be exercised.
fn arm_rekey(peer: &mut ActivePeer) {
    let remote = Identity::generate();
    let local = Identity::generate();
    let hs = NoiseHandshakeState::new_initiator(local.keypair(), remote.pubkey_full());
    peer.set_rekey_state(hs, SessionIndex::new(7), vec![0xAB; 64], 0);
}

#[test]
fn rekey_msg1_resend_count_increments_and_caps() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);
    arm_rekey(&mut peer);

    assert!(peer.rekey_in_progress());
    assert_eq!(peer.rekey_msg1_resend_count(), 0);
    assert!(peer.rekey_msg1().is_some());

    // The driver records one resend per call; the count tracks them.
    let max_resends: u32 = 5;
    for i in 0..max_resends {
        peer.record_rekey_msg1_resend(1000 + i as u64 * 100);
        assert_eq!(peer.rekey_msg1_resend_count(), i + 1);
    }
    assert_eq!(peer.rekey_msg1_resend_count(), max_resends);
}

#[test]
fn rekey_msg1_budget_exhaustion_abandons_cleanly() {
    let identity = make_peer_identity();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 1000);
    arm_rekey(&mut peer);

    // Simulate the driver exhausting its budget.
    let max_resends: u32 = 5;
    for i in 0..max_resends {
        peer.record_rekey_msg1_resend(1000 + i as u64 * 100);
    }
    assert_eq!(peer.rekey_msg1_resend_count(), max_resends);

    // Budget exhausted -> abandon: state clears and the counter resets.
    peer.abandon_rekey();
    assert!(!peer.rekey_in_progress());
    assert!(peer.rekey_msg1().is_none());
    assert_eq!(peer.rekey_msg1_resend_count(), 0);
}

// === FMP rekey cutover: authenticate-before-promote ===
//
// IK-adapted analogue of the FSP trial-decrypt tests
// (node/session/mod.rs `trial_decrypt_picks_pending_and_promotes` /
// `trial_decrypt_failed_slot_leaves_replay_window_intact`). The FMP
// cutover is gated on an authenticated decrypt against `pending`, not
// the bare header K-bit. These tests exercise that primitive:
// `pending_new_session_mut()` trial-decrypt followed by
// `handle_peer_kbit_flip()` promotion.

/// Complete an IK handshake and return the (sender, receiver) session
/// pair. The receiver decrypts what the sender seals.
fn ik_session_pair() -> (NoiseSession, NoiseSession) {
    let initiator_id = Identity::generate();
    let responder_id = Identity::generate();
    let mut initiator =
        NoiseHandshakeState::new_initiator(initiator_id.keypair(), responder_id.pubkey_full());
    initiator.set_local_epoch([0xA1, 0xB2, 0xC3, 0xD4, 0x11, 0x22, 0x33, 0x44]);
    let mut responder = NoiseHandshakeState::new_responder(responder_id.keypair());
    responder.set_local_epoch([0xD4, 0xC3, 0xB2, 0xA1, 0x44, 0x33, 0x22, 0x11]);

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();

    (
        initiator.into_session().unwrap(),
        responder.into_session().unwrap(),
    )
}

/// Seal an FMP frame the way the send path does: returns
/// `(ciphertext, counter, header_bytes)` for the given K-bit.
fn seal_fmp(
    sender: &mut NoiseSession,
    receiver_idx: SessionIndex,
    plaintext: &[u8],
    k_bit: bool,
) -> (Vec<u8>, u64, [u8; 16]) {
    use crate::proto::fmp::wire::{FLAG_KEY_EPOCH, build_established_header};
    let counter = sender.current_send_counter();
    let flags = if k_bit { FLAG_KEY_EPOCH } else { 0 };
    let header = build_established_header(receiver_idx, counter, flags, plaintext.len() as u16);
    let ciphertext = sender.encrypt_with_aad(plaintext, &header).unwrap();
    (ciphertext, counter, header)
}

/// Build a peer whose `current` slot is `current_recv`.
fn peer_with_current(current_recv: NoiseSession) -> ActivePeer {
    let identity = make_peer_identity();
    ActivePeer::with_session(
        identity,
        LinkId::new(1),
        1_000,
        current_recv,
        SessionIndex::new(1),
        SessionIndex::new(2),
        TransportId::new(1),
        TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:01"),
        LinkStats::new(),
        true,
        &MmpConfig::default(),
        None,
    )
}

/// Count `n` pending-refusal lines on `peer` this session.
fn count_pending_lines(peer: &mut ActivePeer, n: u32) {
    for _ in 0..n {
        peer.hs_lines_mut().count(HsLine::Pending);
    }
}

// Each session change carries what the session withheld and restarts the
// count, whichever side made the change.
#[test]
fn every_session_change_carries_the_withheld_handshake_lines_and_restarts_the_count() {
    let (_cur_send, cur_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);

    count_pending_lines(&mut peer, 5);
    let (_s, pend_recv) = ik_session_pair();
    peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));
    assert!(peer.handle_peer_kbit_flip().is_some());
    assert_eq!(peer.hs_lines_mut().count(HsLine::Pending), 1);

    count_pending_lines(&mut peer, 3);
    let (_s, pend_recv) = ik_session_pair();
    peer.set_pending_session(pend_recv, SessionIndex::new(5), SessionIndex::new(6));
    assert!(peer.cutover_to_new_session().is_some());

    count_pending_lines(&mut peer, 6);
    let (_s, next_recv) = ik_session_pair();
    peer.replace_session(next_recv, SessionIndex::new(7), SessionIndex::new(8));

    // 2 from the first session, 1 from the second, 3 from the third.
    let carried = peer.hs_lines_mut().take_carried().expect("lines withheld");
    assert_eq!(carried.of(HsLine::Pending), 6);
    assert_eq!(peer.hs_lines().unreported(), None);
}

// A genuine new-epoch frame authenticates against `pending` and the
// peer promotes: pending -> current, K-bit flips, plaintext delivered.
#[test]
fn cutover_pending_authenticates_and_promotes() {
    let (_cur_send, cur_recv) = ik_session_pair();
    let (mut pend_send, pend_recv) = ik_session_pair();

    let mut peer = peer_with_current(cur_recv);
    let k_before = peer.current_k_bit();
    peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));

    // Peer sealed in the new epoch with the flipped K-bit.
    let (ct, counter, hdr) = seal_fmp(
        &mut pend_send,
        SessionIndex::new(3),
        b"new-epoch",
        !k_before,
    );

    // Trial-decrypt against pending succeeds (the cutover signal).
    let plaintext = peer
        .pending_new_session_mut()
        .and_then(|p| p.decrypt_with_replay_check_and_aad(&ct, counter, &hdr).ok())
        .expect("new-epoch frame must authenticate against pending");
    assert_eq!(plaintext, b"new-epoch");

    // Promotion moves pending -> current and flips the K-bit.
    assert!(peer.handle_peer_kbit_flip().is_some());
    assert!(peer.pending_new_session().is_none());
    assert_eq!(peer.current_k_bit(), !k_before);
    assert!(peer.previous_session().is_some());
}

// A stale/mismatched frame on a K-bit flip does NOT authenticate
// against `pending`: no promotion, `pending` preserved with its replay
// window intact, and the genuine current session still decrypts a
// subsequent steady-state frame.
#[test]
fn cutover_stale_frame_does_not_promote() {
    let (mut cur_send, cur_recv) = ik_session_pair();
    let (_pend_send, pend_recv) = ik_session_pair();
    // A third, unrelated session whose ciphertext will NOT authenticate
    // against `pending` (wrong keys) — simulates a flip belonging to a
    // different rekey epoch.
    let (mut stale_send, _stale_recv) = ik_session_pair();

    let mut peer = peer_with_current(cur_recv);
    let k_before = peer.current_k_bit();
    peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));

    // Frame carries the flipped K-bit but is sealed in an unrelated
    // session: it must fail to authenticate against `pending`.
    let (ct, counter, hdr) = seal_fmp(&mut stale_send, SessionIndex::new(3), b"stale", !k_before);
    let result = peer
        .pending_new_session_mut()
        .and_then(|p| p.decrypt_with_replay_check_and_aad(&ct, counter, &hdr).ok());
    assert!(
        result.is_none(),
        "stale frame must not authenticate against pending"
    );

    // No promotion happened: pending preserved, K-bit unchanged.
    assert!(peer.pending_new_session().is_some());
    assert_eq!(peer.current_k_bit(), k_before);

    // The trial-decrypt left pending's replay window untouched, and the
    // genuine current session still decrypts steady-state traffic — the
    // fall-through path the handler takes on a non-authenticating flip.
    let (ct2, counter2, hdr2) = seal_fmp(&mut cur_send, SessionIndex::new(1), b"steady", k_before);
    let cur_pt = peer.noise_session_mut().and_then(|s| {
        s.decrypt_with_replay_check_and_aad(&ct2, counter2, &hdr2)
            .ok()
    });
    assert_eq!(cur_pt.as_deref(), Some(&b"steady"[..]));
}

/// Whether `peer`'s link instant reads at least `age` old.
fn link_at_least(peer: &ActivePeer, age: Duration) -> bool {
    since(peer.link_established_at()) >= age
}

/// The link instant is set at construction and is not moved by an
/// initiator cutover, an adoption of the peer's rekey, or a
/// cross-connection swap, each of which restarts the session instant.
/// A pending whose msg2 revealed a peer restart leaves it alone while
/// held, and restarts it when it is cut over, adopted or abandoned.
#[test]
fn the_link_instant_is_set_at_construction_and_kept_through_initiator_cutover_peer_adoption_and_cross_connection_swap_but_reset_when_a_revealed_restart_leaves_the_slot()
 {
    let aged = Duration::from_secs(5);
    let fresh = Duration::from_secs(1);
    let (_cur_send, cur_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    assert!(
        since(peer.link_established_at()) < fresh,
        "construction sets the link instant"
    );
    peer.test_backdate_session_established(aged);

    let (_s, pend_recv) = ik_session_pair();
    peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));
    assert!(peer.cutover_to_new_session().is_some());
    assert!(since(peer.session_established_at()) < fresh);
    assert!(
        link_at_least(&peer, aged),
        "initiator cutover kept the link"
    );

    let (_s, pend_recv) = ik_session_pair();
    peer.answer_rekey(
        pend_recv,
        SessionIndex::new(5),
        SessionIndex::new(6),
        answer(),
    );
    assert!(peer.adopt_pending(false).is_some());
    assert!(since(peer.session_established_at()) < fresh);
    assert!(link_at_least(&peer, aged), "adoption kept the link");

    let (_s, swap) = ik_session_pair();
    peer.replace_session(swap, SessionIndex::new(7), SessionIndex::new(8));
    assert!(
        link_at_least(&peer, aged),
        "a cross-connection swap kept the link"
    );

    type Exit = fn(&mut ActivePeer) -> Option<SessionIndex>;
    let exits: [(&str, Exit); 3] = [
        ("cutover", ActivePeer::cutover_to_new_session),
        ("adopt", |p| p.adopt_pending(false)),
        ("abandon", ActivePeer::abandon_rekey),
    ];
    for (name, exit) in exits {
        let (_cur_send, cur_recv) = ik_session_pair();
        let mut peer = peer_with_current(cur_recv);
        peer.test_backdate_session_established(aged);
        let (_s, pend_recv) = ik_session_pair();
        peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));
        peer.note_restart();
        assert!(
            link_at_least(&peer, aged),
            "{name}: the link keeps its age while the restart pending is held"
        );
        assert!(exit(&mut peer).is_some(), "{name}: the pending must exit");
        assert!(
            since(peer.link_established_at()) < fresh,
            "{name}: the restart pending leaving the slot restarts the link"
        );
    }
}

/// Backdating the session moves the link instant back with it when the
/// link would otherwise read younger, and never moves it forward.
#[test]
fn backdating_the_session_never_leaves_the_link_younger_than_the_session() {
    let (_cur_send, cur_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    peer.test_backdate_session_established(Duration::from_secs(40));
    assert!(peer.link_established_at() <= peer.session_established_at());
    assert!(link_at_least(&peer, Duration::from_secs(40)));

    let (_s, pend_recv) = ik_session_pair();
    peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));
    assert!(peer.cutover_to_new_session().is_some());
    peer.test_backdate_session_established(Duration::from_secs(12));
    assert!(
        link_at_least(&peer, Duration::from_secs(40)),
        "a smaller backdate after a cutover leaves the older link as it was"
    );
    assert!(peer.link_established_at() <= peer.session_established_at());
}

/// A stand-in for the answer a responder records when it arms a pending.
fn answer() -> RekeyAnswer {
    RekeyAnswer {
        msg1: crate::proto::fmp::Msg1Digest::of(b"msg1"),
        msg2: vec![0x02; 8],
    }
}

/// The answer that armed a responder pending is held exactly as long as
/// the pending: it leaves on retirement, on promotion, and on abandon,
/// leaving its msg1 recorded as an ended cycle, and a pending this node
/// initiated carries none.
#[test]
fn the_answer_that_armed_a_pending_leaves_with_it() {
    type Exit = fn(&mut ActivePeer) -> Option<SessionIndex>;
    let exits: [(&str, Exit); 3] = [
        ("retire", ActivePeer::retire_pending),
        ("promote", ActivePeer::handle_peer_kbit_flip),
        ("abandon", ActivePeer::abandon_rekey),
    ];
    for (name, exit) in exits {
        let (_cur_send, cur_recv) = ik_session_pair();
        let (_pend_send, pend_recv) = ik_session_pair();
        let mut peer = peer_with_current(cur_recv);
        peer.answer_rekey(
            pend_recv,
            SessionIndex::new(3),
            SessionIndex::new(4),
            answer(),
        );
        assert_eq!(
            peer.rekey_answer().map(|a| a.msg2.clone()),
            Some(vec![0x02; 8]),
            "{name}: the answer must be held with the pending"
        );
        assert!(exit(&mut peer).is_some(), "{name}: the pending must exit");
        assert!(peer.pending_new_session().is_none());
        assert!(
            peer.rekey_answer().is_none(),
            "{name}: the answer must leave with the pending"
        );
        assert!(
            peer.answered_before(&answer().msg1),
            "{name}: the answered msg1 must be remembered as an ended cycle"
        );
    }

    let (_cur_send, cur_recv) = ik_session_pair();
    let (_pend_send, pend_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));
    assert!(peer.rekey_answer().is_none());
}

/// Retiring a pending session this node answered hands back its index for
/// the caller to free, empties the pending slot and its role, and leaves
/// the current session alone.
#[test]
fn retiring_an_answered_pending_returns_its_index_and_empties_the_slot() {
    let (_cur_send, cur_recv) = ik_session_pair();
    let (_pend_send, pend_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    peer.answer_rekey(
        pend_recv,
        SessionIndex::new(3),
        SessionIndex::new(4),
        answer(),
    );
    assert_eq!(peer.pending_role(), Some(RekeyRole::Responder));

    assert_eq!(peer.retire_pending(), Some(SessionIndex::new(3)));
    assert!(peer.pending_new_session().is_none());
    assert_eq!(peer.pending_role(), None);
    assert_eq!(peer.pending_their_index(), None);
    assert_eq!(peer.pending_our_index(), None);
    assert!(peer.noise_session().is_some());
    assert_eq!(peer.our_index(), Some(SessionIndex::new(1)));
}

/// Retirement leaves a pending session this node initiated in place: that
/// one is cut over on this node's schedule, never retired.
#[test]
fn retire_leaves_a_pending_this_node_initiated_in_place() {
    let (_cur_send, cur_recv) = ik_session_pair();
    let (_pend_send, pend_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));
    assert_eq!(peer.pending_role(), Some(RekeyRole::Initiator));

    assert_eq!(peer.retire_pending(), None);
    assert!(peer.pending_new_session().is_some());
    assert_eq!(peer.pending_role(), Some(RekeyRole::Initiator));
}

/// Promoting an answered pending session on the peer's first new-epoch
/// frame clears its role and install time with the slot.
#[test]
fn promotion_on_the_peers_new_epoch_frame_clears_the_pending_role() {
    let (_cur_send, cur_recv) = ik_session_pair();
    let (_pend_send, pend_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    peer.answer_rekey(
        pend_recv,
        SessionIndex::new(3),
        SessionIndex::new(4),
        answer(),
    );

    assert!(peer.handle_peer_kbit_flip().is_some());
    assert_eq!(peer.pending_role(), None);
    assert!(!peer.pending_expired(Duration::ZERO));
}

/// The pending hold is measured from the install time: not expired inside
/// the hold, expired once the install time is older than it.
#[test]
fn pending_expiry_reads_the_install_time_against_the_hold() {
    let (_cur_send, cur_recv) = ik_session_pair();
    let (_pend_send, pend_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    peer.answer_rekey(
        pend_recv,
        SessionIndex::new(3),
        SessionIndex::new(4),
        answer(),
    );

    assert!(!peer.pending_expired(Duration::from_secs(60)));
    peer.backdate_pending(Duration::from_secs(61));
    assert!(peer.pending_expired(Duration::from_secs(60)));
}

/// The responder's pending hold, the rekey dampening and the drain are all
/// measured on the peer clock, so advancing the host's monotonic clock in a
/// test passes each of them, with no backdate, at its exact length and not
/// before.
#[test]
fn advancing_the_monotonic_clock_passes_the_pending_hold_the_rekey_dampening_and_the_drain_at_their_lengths()
 {
    const HOLD: Duration = Duration::from_secs(60);
    const DAMPENING_SECS: u64 = 30;
    const DRAIN_SECS: u64 = 10;
    let tick = Duration::from_millis(100);
    let (_cur_send, cur_recv) = ik_session_pair();
    let (_pend_send, pend_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    peer.answer_rekey(
        pend_recv,
        SessionIndex::new(3),
        SessionIndex::new(4),
        answer(),
    );
    peer.record_peer_rekey();

    crate::time::advance(Duration::from_secs(DAMPENING_SECS) - tick);
    assert!(
        peer.is_rekey_dampened(DAMPENING_SECS),
        "dampened inside its window"
    );
    crate::time::advance(tick);
    assert!(
        !peer.is_rekey_dampened(DAMPENING_SECS),
        "dampening ends at its length"
    );

    crate::time::advance(HOLD - Duration::from_secs(DAMPENING_SECS) - tick);
    assert!(
        !peer.pending_expired(HOLD),
        "the pending is held inside the hold"
    );
    crate::time::advance(tick);
    assert!(peer.pending_expired(HOLD), "the hold passes at its length");

    assert!(peer.handle_peer_kbit_flip().is_some());
    crate::time::advance(Duration::from_secs(DRAIN_SECS) - tick);
    assert!(
        !peer.drain_expired(DRAIN_SECS),
        "the drain runs inside its window"
    );
    crate::time::advance(tick);
    assert!(
        peer.drain_expired(DRAIN_SECS),
        "the drain ends at its length"
    );
}

/// Both cutover bodies restart the previous-session frame count and stamp
/// the cutover time, and completing the drain keeps both.
#[test]
fn each_cutover_restarts_the_previous_frame_count_and_stamps_the_cutover() {
    type Cutover = fn(&mut ActivePeer) -> Option<SessionIndex>;
    let cutovers: [(&str, Cutover); 2] = [
        ("initiator", ActivePeer::cutover_to_new_session),
        ("responder", ActivePeer::handle_peer_kbit_flip),
    ];
    for (name, cutover) in cutovers {
        let (_cur_send, cur_recv) = ik_session_pair();
        let (_pend_send, pend_recv) = ik_session_pair();
        let mut peer = peer_with_current(cur_recv);
        assert!(peer.since_cutover().is_none(), "{name}: no cutover yet");
        peer.count_previous();
        peer.count_previous();
        assert_eq!(peer.prev_frames(), 2);
        peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));

        assert!(cutover(&mut peer).is_some(), "{name}: the cutover runs");
        assert_eq!(peer.prev_frames(), 0, "{name}: the count restarts");
        assert!(
            peer.since_cutover().is_some(),
            "{name}: the cutover is stamped"
        );

        peer.count_previous();
        assert!(peer.complete_drain().is_some());
        assert_eq!(peer.prev_frames(), 1, "{name}: the drain keeps the count");
        assert!(
            peer.since_cutover().is_some(),
            "{name}: the drain keeps the stamp"
        );
    }
}

/// The last failing index is the one most recently recorded.
#[test]
fn the_last_failed_index_is_the_most_recent_one_recorded() {
    let (_cur_send, cur_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    assert_eq!(peer.last_failed(), None);
    peer.record_failed(SessionIndex::new(5));
    peer.record_failed(SessionIndex::new(6));
    assert_eq!(peer.last_failed(), Some(SessionIndex::new(6)));
}

/// An index names the current, previous or pending slot it belongs to,
/// the pending one by the role that produced it, and any other index
/// names none.
#[test]
fn an_index_names_the_slot_of_the_session_it_belongs_to() {
    use crate::node::diag::Slot;

    let (_cur_send, cur_recv) = ik_session_pair();
    let (_pend_send, pend_recv) = ik_session_pair();
    let mut peer = peer_with_current(cur_recv);
    assert_eq!(Slot::of(&peer, SessionIndex::new(1)), Slot::Current);
    assert_eq!(Slot::of(&peer, SessionIndex::new(9)), Slot::Unknown);

    peer.answer_rekey(
        pend_recv,
        SessionIndex::new(3),
        SessionIndex::new(4),
        answer(),
    );
    assert_eq!(
        Slot::of(&peer, SessionIndex::new(3)),
        Slot::PendingResponder
    );
    assert!(peer.handle_peer_kbit_flip().is_some());
    assert_eq!(Slot::of(&peer, SessionIndex::new(3)), Slot::Current);
    assert_eq!(Slot::of(&peer, SessionIndex::new(1)), Slot::Previous);

    let (_next_send, next_recv) = ik_session_pair();
    peer.set_pending_session(next_recv, SessionIndex::new(5), SessionIndex::new(6));
    assert_eq!(
        Slot::of(&peer, SessionIndex::new(5)),
        Slot::PendingInitiator
    );
    assert_eq!(Slot::Unknown.to_string(), "none");
    assert_eq!(Slot::PendingInitiator.to_string(), "pending-initiator");
}

/// A peer starts unheard, is heard after its first authenticated frame, and
/// stays heard across either cutover and the drain that follows it.
#[test]
fn a_peer_is_unheard_until_its_first_frame_and_stays_heard_across_both_cutovers() {
    let mut fresh = ActivePeer::new(make_peer_identity(), LinkId::new(1), 1000);
    assert!(!fresh.heard(), "a new peer starts unheard");
    fresh.touch(2000);
    assert!(fresh.heard(), "a frame marks the peer heard");

    type Cutover = fn(&mut ActivePeer) -> Option<SessionIndex>;
    let cutovers: [(&str, Cutover); 2] = [
        ("initiator", ActivePeer::cutover_to_new_session),
        ("responder", ActivePeer::handle_peer_kbit_flip),
    ];
    for (name, cutover) in cutovers {
        let (_cur_send, cur_recv) = ik_session_pair();
        let (_pend_send, pend_recv) = ik_session_pair();
        let mut peer = peer_with_current(cur_recv);
        assert!(!peer.heard(), "{name}: a promoted peer starts unheard");
        peer.touch(2000);
        assert!(peer.heard(), "{name}: a frame marks the peer heard");
        peer.set_pending_session(pend_recv, SessionIndex::new(3), SessionIndex::new(4));

        assert!(cutover(&mut peer).is_some(), "{name}: the cutover runs");
        assert!(peer.heard(), "{name}: the cutover keeps the peer heard");
        assert!(peer.complete_drain().is_some(), "{name}: the drain runs");
        assert!(peer.heard(), "{name}: the drain keeps the peer heard");
    }
}
