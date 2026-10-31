//! Unit tests for `ActivePeer` (`src/peer/active.rs`).

use super::*;
use crate::Identity;
use crate::node::REKEY_JITTER_SECS;
use crate::node::diag::HsLine;
use std::sync::LazyLock;

/// A lease on `index` for a test peer, outside any allocator.
fn lease(index: u32) -> IndexLease {
    IndexLease::for_test(index)
}

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
    let (session, _peer_session) = xx_session_pair();

    let peer = ActivePeer::with_test_session(
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
        let peer = peer_with_current(xx_session_pair().1);
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
        let peer = peer_with_current(xx_session_pair().1);
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

// === Link rekeys driven through the machine ===
//
// Two ends of one test link, each an `ActivePeer` holding the other's half
// of every session, rekeyed through `step_link` as the node drives them, so
// what the shell does around a cutover is tested on real sessions.

/// The two nodes every test session runs between, so each session a test
/// peer holds authenticates the same peer key, as a link machine requires.
/// Each handshake still draws fresh ephemerals, so every pair is a distinct
/// epoch.
static PAIR: LazyLock<(Identity, Identity)> =
    LazyLock::new(|| (Identity::generate(), Identity::generate()));

/// The startup epoch of the first node of [`PAIR`].
const EPOCH_A: [u8; 8] = [0xA1, 0xB2, 0xC3, 0xD4, 0x11, 0x22, 0x33, 0x44];

/// The startup epoch of the second node of [`PAIR`].
const EPOCH_B: [u8; 8] = [0xD4, 0xC3, 0xB2, 0xA1, 0x44, 0x33, 0x22, 0x11];

/// Complete an XX handshake between the two nodes of [`PAIR`] and return the
/// (initiator, responder) session pair.
fn xx_session_pair() -> (NoiseSession, NoiseSession) {
    let (initiator_id, responder_id) = &*PAIR;
    let mut initiator = crate::noise::HandshakeState::new_initiator(initiator_id.keypair());
    initiator.set_local_epoch(EPOCH_A);
    let mut responder = crate::noise::HandshakeState::new_responder(responder_id.keypair());
    responder.set_local_epoch(EPOCH_B);

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    let msg3 = initiator.write_message_3().unwrap();
    responder.read_message_3(&msg3).unwrap();

    (
        initiator.into_session().unwrap(),
        responder.into_session().unwrap(),
    )
}

/// Build a peer whose `current` slot is `current_recv`.
fn peer_with_current(current_recv: NoiseSession) -> ActivePeer {
    let identity = make_peer_identity();
    ActivePeer::with_test_session(
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

/// One end of a test link: its peer entry for the other end, its node's
/// identity and keys and its node's index allocator.
struct End {
    peer: ActivePeer,
    id: Identity,
    keys: fips_core::proto::rekey::NodeKeys,
    alloc: crate::utils::index::IndexAllocator,
}

impl End {
    /// Step this end's link machine with `input` now and carry out what the
    /// node would beside the network: a cutover's shell resets and the
    /// release of retired indices. Returns the outputs.
    fn step(&mut self, input: fips_core::proto::rekey::Input<'_, LinkProfile>) -> LinkOutputs {
        let out = self.peer.step_link(
            peer_now(),
            input,
            &mut self.alloc,
            &self.keys,
            NodeProfile::Full,
            false,
        );
        self.carry(&out);
        out
    }

    /// Carry out the shell's part of `out`.
    fn carry(&mut self, out: &LinkOutputs) {
        for o in out {
            if matches!(o, LinkOutput::Installed { .. }) {
                self.peer.after_cutover();
            }
        }
    }

    /// A heartbeat sealed under this end's current session, framed for the
    /// other end.
    fn frame(&mut self) -> Vec<u8> {
        use crate::proto::fmp::wire::{FLAG_KEY_EPOCH, build_encrypted, build_established_header};
        let sealed = self
            .peer
            .seal(peer_now())
            .expect("the current session seals");
        let mut plaintext = (sealed.elapsed.as_millis() as u32).to_le_bytes().to_vec();
        plaintext.push(crate::proto::link::LinkMessageType::Heartbeat.to_byte());
        let flags = if sealed.k { FLAG_KEY_EPOCH } else { 0 };
        let header = build_established_header(
            SessionIndex::new(sealed.theirs.expect("the peer's index")),
            sealed.counter,
            flags,
            plaintext.len() as u16,
        );
        let ciphertext =
            fips_core::noise::seal(sealed.key.key(), sealed.counter, &header, &plaintext)
                .expect("the session seals");
        build_encrypted(&header, &ciphertext)
    }

    /// Take the frame `frame` the other end sent, returning the outputs.
    fn take(&mut self, frame: &[u8]) -> LinkOutputs {
        let header = crate::proto::fmp::wire::EncryptedHeader::parse(frame).expect("a frame");
        let mut buf = frame.to_vec();
        let hint = fips_core::proto::rekey::FrameHint {
            counter: header.counter,
            k: header.flags & crate::proto::fmp::wire::FLAG_KEY_EPOCH != 0,
            index: header.receiver_idx.as_u32(),
            body: header.ciphertext_offset(),
        };
        self.step(fips_core::proto::rekey::Input::Frame {
            buf: &mut buf,
            hint,
        })
    }
}

/// The handshake message of `kind` among `out`.
fn sent(out: &LinkOutputs, kind: fips_core::proto::rekey::MsgKind) -> Vec<u8> {
    out.iter()
        .find_map(|o| match o {
            LinkOutput::Send { msg, kind: k, .. } if *k == kind => Some(msg.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no {kind:?} among {out:?}"))
}

/// Whether `out` reports a cutover.
fn installed(out: &LinkOutputs) -> bool {
    out.iter()
        .any(|o| matches!(o, LinkOutput::Installed { .. }))
}

/// The two ends of a test link [`LINK_AGE`] old, `a` the first node of
/// [`PAIR`] and `b` the second, each knowing the other's startup epoch.
fn ends() -> (End, End) {
    let (a_session, b_session) = xx_session_pair();
    let (a_id, b_id) = &*PAIR;
    let end = |id: &Identity, peer: &Identity, session, ours, theirs, epoch, peer_epoch| End {
        peer: ActivePeer::with_test_session(
            PeerIdentity::from_pubkey_full(peer.pubkey_full()),
            LinkId::new(1),
            1_000,
            session,
            SessionIndex::new(ours),
            SessionIndex::new(theirs),
            TransportId::new(1),
            TransportAddr::from_string("hci0/AA:BB:CC:DD:EE:01"),
            LinkStats::new(),
            true,
            &MmpConfig::default(),
            Some(peer_epoch),
        ),
        id: id.clone(),
        keys: fips_core::proto::rekey::NodeKeys::new(id.keypair(), epoch),
        alloc: crate::utils::index::IndexAllocator::new(),
    };
    let (mut a, mut b) = (
        end(a_id, b_id, a_session, 1, 2, EPOCH_A, EPOCH_B),
        end(b_id, a_id, b_session, 2, 1, EPOCH_B, EPOCH_A),
    );
    // Old enough that each end answers the other's rekey.
    a.peer.test_backdate_session_established(LINK_AGE);
    b.peer.test_backdate_session_established(LINK_AGE);
    (a, b)
}

/// The age each test link starts at: past the link and session ages at
/// which a msg1 is answered as a rekey.
const LINK_AGE: Duration = Duration::from_secs(40);

/// Run an XX rekey `from` starts to `to` as far as both holding the pending
/// session: its msg1, `to`'s leg answer with a leased index, the msg2 that
/// completes `from`'s attempt and sends msg3, and the msg3, read on the
/// leg's handshake and handed to `to`'s machine as a rekey.
fn rekey_to_pending(from: &mut End, to: &mut End) {
    use crate::proto::fmp::wire::{Msg1Header, build_msg2};
    use fips_core::proto::fmp::rekey::read_final;
    use fips_core::proto::rekey::{Input, Intent, MsgKind, Role, allocate};
    let out = from
        .peer
        .start_rekey_now(peer_now(), &mut from.alloc, &from.keys);
    let msg1 = sent(&out, MsgKind::Setup);
    let header = Msg1Header::parse(&msg1).expect("a framed msg1");
    let mut leg = crate::noise::HandshakeState::new_responder(to.id.keypair());
    leg.set_local_epoch(to.keys.epoch());
    leg.read_message_1(&msg1[header.noise_msg1_offset..])
        .expect("the msg1 reads");
    let mut noise_msg2 = leg.write_message_2().expect("the msg2 builds");
    let payload = crate::proto::fmp::NegotiationPayload::fmp(1, 1, NodeProfile::Full).encode();
    noise_msg2.extend(leg.encrypt_payload(&payload).expect("the payload seals"));
    let lease = allocate(&mut to.alloc).expect("an index for the leg");
    let msg2 = build_msg2(
        SessionIndex::new(lease.index()),
        header.sender_idx,
        &noise_msg2,
    );
    let out = from.step(Input::Reply {
        bytes: &msg2,
        route: (),
    });
    let msg3 = sent(&out, MsgKind::Msg3);
    let fin = read_final(&leg, &msg3, Some(lease)).expect("the msg3 reads");
    to.step(Input::PeerDone {
        tok: fin.into_rekey(),
        intent: Intent::Rekey,
    });
    assert_eq!(from.peer.pending_role(), Some(Role::Initiator));
    assert_eq!(to.peer.pending_role(), Some(Role::Responder));
}

/// The cutover of the initiator's pending at its first poll after the
/// cutover delay, which the test clock is advanced past.
fn initiator_cutover(end: &mut End) {
    crate::time::advance(fips_core::proto::rekey::Config::fmp().delay);
    let out = end.step(fips_core::proto::rekey::Input::Poll);
    assert!(
        installed(&out),
        "the initiator cuts over at its poll: {out:?}"
    );
}

/// The responder's adoption of its pending on the initiator's first frame
/// under the new session.
fn responder_adoption(initiator: &mut End, responder: &mut End) {
    let frame = initiator.frame();
    let out = responder.take(&frame);
    assert!(
        installed(&out),
        "the responder adopts on the frame: {out:?}"
    );
}

/// The initiator hears the responder under the new session, which shows
/// the peer moved: the initiator's drain ends one window later.
fn heard_back(responder: &mut End, initiator: &mut End) {
    let frame = responder.frame();
    let out = initiator.take(&frame);
    assert!(
        out.iter().any(|o| matches!(o, LinkOutput::Deliver { .. })),
        "the initiator opens the responder's frame: {out:?}"
    );
}

/// Count `n` msg2-resend lines on `peer` this session.
fn count_resend_lines(peer: &mut ActivePeer, n: u32) {
    for _ in 0..n {
        peer.hs_lines_mut().count(HsLine::Resend);
    }
}

// Each session change carries what the session withheld and restarts the
// count, whichever side made the change.
#[test]
fn every_session_change_carries_the_withheld_handshake_lines_and_restarts_the_count() {
    let (mut a, mut b) = ends();

    count_resend_lines(&mut b.peer, 5);
    rekey_to_pending(&mut a, &mut b);
    initiator_cutover(&mut a);
    responder_adoption(&mut a, &mut b);
    assert_eq!(b.peer.hs_lines_mut().count(HsLine::Resend), 1);

    count_resend_lines(&mut b.peer, 3);
    // a answers once its session is old enough to rekey again.
    crate::time::advance(crate::peer::test_link_params().config().session_age);
    rekey_to_pending(&mut b, &mut a);
    initiator_cutover(&mut b);

    count_resend_lines(&mut b.peer, 6);
    let (_s, next_recv) = xx_session_pair();
    let mut caps = crate::peer::LinkCaps {
        indices: &mut b.alloc,
        local: &b.keys,
        me: *PeerIdentity::from_pubkey_full(PAIR.1.pubkey_full()).node_addr(),
        params: crate::peer::test_link_params(),
        record: Record::new(),
        workers: false,
        profile: NodeProfile::Full,
    };
    let _ = b
        .peer
        .move_session(next_recv, lease(7), SessionIndex::new(8), &mut caps);

    // 2 from the first session, 1 from the second, 3 from the third.
    let carried = b
        .peer
        .hs_lines_mut()
        .take_carried()
        .expect("lines withheld");
    assert_eq!(carried.of(HsLine::Resend), 6);
    assert_eq!(b.peer.hs_lines().unreported(), None);
}

/// Backdating the session moves the link instant back with it when the
/// link would otherwise read younger, and never moves it forward.
#[test]
fn backdating_the_session_never_leaves_the_link_younger_than_the_session() {
    let (mut a, mut b) = ends();
    a.peer
        .test_backdate_session_established(Duration::from_secs(40));
    assert!(a.peer.link_established_at() <= a.peer.session_established_at());
    assert!(since(a.peer.link_established_at().unwrap()) >= Duration::from_secs(40));

    rekey_to_pending(&mut a, &mut b);
    initiator_cutover(&mut a);
    a.peer
        .test_backdate_session_established(Duration::from_secs(12));
    assert!(
        since(a.peer.link_established_at().unwrap()) >= Duration::from_secs(40),
        "a smaller backdate after a cutover leaves the older link as it was"
    );
    assert!(a.peer.link_established_at() <= a.peer.session_established_at());
}

/// The responder's pending hold, the rekey dampening and the drain are all
/// measured on the peer clock, so advancing the host's monotonic clock in a
/// test passes each of them, with no backdate, at its exact length and not
/// before.
#[test]
fn advancing_the_monotonic_clock_passes_the_pending_hold_the_rekey_dampening_and_the_drain_at_their_lengths()
 {
    use fips_core::proto::rekey::Input;
    let hold = crate::peer::test_link_params().config().hold;
    let dampening = crate::peer::test_link_params().config().dampening;
    let drain = crate::peer::test_link_params().config().drain;
    let tick = Duration::from_millis(100);

    // b answers a's rekey: it holds a responder pending and is dampened.
    let (mut a, mut b) = ends();
    rekey_to_pending(&mut a, &mut b);
    crate::time::advance(dampening - tick);
    assert!(b.peer.dampened(), "dampened inside its window");
    crate::time::advance(tick);
    assert!(!b.peer.dampened(), "dampening ends at its length");

    crate::time::advance(hold - dampening - tick);
    b.step(Input::Poll);
    assert!(
        b.peer.pending_new_session().is_some(),
        "the pending is held inside the hold"
    );
    crate::time::advance(tick);
    b.step(Input::Poll);
    assert!(
        b.peer.pending_new_session().is_none(),
        "the hold passes at its length"
    );

    // a cuts over and hears b under the new session: the drain runs one
    // window from that frame.
    let (mut a, mut b) = ends();
    rekey_to_pending(&mut a, &mut b);
    initiator_cutover(&mut a);
    responder_adoption(&mut a, &mut b);
    heard_back(&mut b, &mut a);
    crate::time::advance(drain - tick);
    a.step(Input::Poll);
    assert!(a.peer.is_draining(), "the drain runs inside its window");
    crate::time::advance(tick);
    a.step(Input::Poll);
    assert!(!a.peer.is_draining(), "the drain ends at its length");
}

/// Both cutovers restart the previous-session frame count and stamp the
/// cutover time, and the drain's end keeps both.
#[test]
fn each_cutover_restarts_the_previous_frame_count_and_stamps_the_cutover() {
    use fips_core::proto::rekey::Input;
    for initiator in [true, false] {
        let name = if initiator { "initiator" } else { "responder" };
        let (mut a, mut b) = ends();
        let end = if initiator { &mut a } else { &mut b };
        assert!(end.peer.since_cutover().is_none(), "{name}: no cutover yet");
        end.peer.count_previous();
        end.peer.count_previous();
        assert_eq!(end.peer.prev_frames(), 2);

        rekey_to_pending(&mut a, &mut b);
        initiator_cutover(&mut a);
        responder_adoption(&mut a, &mut b);
        heard_back(&mut b, &mut a);
        let end = if initiator { &mut a } else { &mut b };
        assert_eq!(end.peer.prev_frames(), 0, "{name}: the count restarts");
        assert!(
            end.peer.since_cutover().is_some(),
            "{name}: the cutover is stamped"
        );

        end.peer.count_previous();
        crate::time::advance(crate::peer::test_link_params().config().drain);
        end.step(Input::Poll);
        assert!(!end.peer.is_draining(), "{name}: the drain ended");
        assert_eq!(
            end.peer.prev_frames(),
            1,
            "{name}: the drain keeps the count"
        );
        assert!(
            end.peer.since_cutover().is_some(),
            "{name}: the drain keeps the stamp"
        );
    }
}

/// Each cutover restarts the inner-header timestamp: the new session's
/// timestamp base is the cutover, whatever the old session's age.
#[test]
fn each_cutover_restarts_the_inner_header_timestamp_at_the_new_session() {
    for initiator in [true, false] {
        let name = if initiator { "initiator" } else { "responder" };
        let (mut a, mut b) = ends();
        a.peer.test_backdate_session_start(Duration::from_secs(10));
        b.peer.test_backdate_session_start(Duration::from_secs(10));
        let end = if initiator { &a } else { &b };
        assert!(
            end.peer.session_elapsed_ms() >= 10_000,
            "{name}: precondition: the old session's timestamp reads its age"
        );
        rekey_to_pending(&mut a, &mut b);
        initiator_cutover(&mut a);
        responder_adoption(&mut a, &mut b);
        let end = if initiator { &a } else { &b };
        assert!(
            end.peer.session_elapsed_ms() < 1_000,
            "{name}: the timestamp restarts at the cutover"
        );
    }
}

/// The last failing index is the one most recently recorded.
#[test]
fn the_last_failed_index_is_the_most_recent_one_recorded() {
    let (_cur_send, cur_recv) = xx_session_pair();
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

    let (mut a, mut b) = ends();
    assert_eq!(Slot::of(&b.peer, SessionIndex::new(2)), Slot::Current);
    assert_eq!(Slot::of(&b.peer, SessionIndex::new(9)), Slot::Unknown);

    rekey_to_pending(&mut a, &mut b);
    let answered = b.peer.pending_our_index().expect("b holds a pending");
    assert_eq!(Slot::of(&b.peer, answered), Slot::Pending);
    initiator_cutover(&mut a);
    responder_adoption(&mut a, &mut b);
    assert_eq!(Slot::of(&b.peer, answered), Slot::Current);
    assert_eq!(Slot::of(&b.peer, SessionIndex::new(2)), Slot::Previous);

    crate::time::advance(crate::peer::test_link_params().config().drain);
    b.step(fips_core::proto::rekey::Input::Poll);
    rekey_to_pending(&mut b, &mut a);
    let made = b.peer.pending_our_index().expect("b holds its own pending");
    assert_eq!(Slot::of(&b.peer, made), Slot::Pending);
    assert_eq!(Slot::Unknown.to_string(), "none");
    assert_eq!(Slot::Pending.to_string(), "pending");
}

/// A link frame the current session opened is refused when it arrives
/// again: the open marks that session's replay window, as the inline decrypt
/// always has, and the second copy is delivered to nobody.
#[test]
fn a_link_frame_opened_once_is_refused_when_it_arrives_again() {
    use fips_core::proto::rekey::Reason;
    let (mut a, mut b) = ends();
    let frame = a.frame();
    let first = b.take(&frame);
    assert!(
        first
            .iter()
            .any(|o| matches!(o, LinkOutput::Deliver { .. })),
        "the frame's first arrival is delivered: {first:?}"
    );
    let second = b.take(&frame);
    assert!(
        !second
            .iter()
            .any(|o| matches!(o, LinkOutput::Deliver { .. })),
        "the frame's second arrival is delivered again: {second:?}"
    );
    assert!(
        second
            .iter()
            .any(|o| matches!(o, LinkOutput::Reject(Reason::Replay))),
        "the frame's second arrival is refused as a replay: {second:?}"
    );
}

/// A peer starts unheard, is heard after its first authenticated frame, and
/// stays heard across either cutover and the drain that follows it.
#[test]
fn a_peer_is_unheard_until_its_first_frame_and_stays_heard_across_both_cutovers() {
    use fips_core::proto::rekey::Input;
    let mut fresh = ActivePeer::new(make_peer_identity(), LinkId::new(1), 1000);
    assert!(!fresh.heard(), "a new peer starts unheard");
    fresh.touch(2000);
    assert!(fresh.heard(), "a frame marks the peer heard");

    for initiator in [true, false] {
        let name = if initiator { "initiator" } else { "responder" };
        let (mut a, mut b) = ends();
        for end in [&mut a, &mut b] {
            end.peer.send.heard = false;
            assert!(!end.peer.heard(), "{name}: a promoted peer starts unheard");
            end.peer.touch(2000);
            assert!(end.peer.heard(), "{name}: a frame marks the peer heard");
        }
        rekey_to_pending(&mut a, &mut b);
        initiator_cutover(&mut a);
        responder_adoption(&mut a, &mut b);
        heard_back(&mut b, &mut a);
        let end = if initiator { &mut a } else { &mut b };
        assert!(end.peer.heard(), "{name}: the cutover keeps the peer heard");
        crate::time::advance(crate::peer::test_link_params().config().drain);
        end.step(Input::Poll);
        assert!(!end.peer.is_draining(), "{name}: the drain runs");
        assert!(end.peer.heard(), "{name}: the drain keeps the peer heard");
    }
}

/// The responder's adoption of the pending session takes the K-bit of the
/// initiator's frame that adopts it, whichever K-bit the responder held, and
/// the pending session becomes current under the index the responder's leg
/// drew.
#[test]
fn adopting_the_pending_takes_the_frames_kbit() {
    for (ours, frame) in [(false, false), (false, true), (true, false), (true, true)] {
        let (mut a, mut b) = ends();
        b.peer.force_kbit(ours);
        a.peer.force_kbit(!frame);
        rekey_to_pending(&mut a, &mut b);
        initiator_cutover(&mut a);
        assert_eq!(
            a.peer.current_k_bit(),
            frame,
            "precondition: the initiator seals at {frame} after its cutover"
        );
        let pending = b.peer.pending_our_index();
        responder_adoption(&mut a, &mut b);
        assert_eq!(b.peer.current_k_bit(), frame, "ours {ours}, frame {frame}");
        assert_eq!(b.peer.our_index(), pending, "ours {ours}, frame {frame}");
    }
}

/// Record `frames` link frames at counters `from..from + frames` on `peer`'s
/// receiver-side MMP observer.
fn record_frames(peer: &mut ActivePeer, from: u64, frames: u64) {
    let now = crate::time::mono_ms();
    let mmp = peer.mmp_mut().expect("the test peer holds link MMP state");
    for counter in from..from + frames {
        mmp.receiver
            .record_recv(counter, counter as u32, 100, false, now);
    }
}

/// Move `end`'s link onto a fresh session under our index 7 and the peer's
/// index 8, as the node does when crossed dials resolve onto the other
/// dial's session, and check that the link moved.
fn cross_move(end: &mut End) {
    let (_s, next_recv) = xx_session_pair();
    let mut caps = crate::peer::LinkCaps {
        indices: &mut end.alloc,
        local: &end.keys,
        me: *PeerIdentity::from_pubkey_full(PAIR.1.pubkey_full()).node_addr(),
        params: crate::peer::test_link_params(),
        record: Record::new(),
        workers: false,
        profile: NodeProfile::Full,
    };
    let out = end
        .peer
        .move_session(next_recv, lease(7), SessionIndex::new(8), &mut caps);
    end.carry(&out);
    assert_eq!(
        end.peer.our_index(),
        Some(SessionIndex::new(7)),
        "precondition: the link moved onto the new session: {out:?}"
    );
}

/// The peer's receiver report on our link frames: `highest` the highest
/// counter it has seen, `packets` the frames of 100 bytes it has received in
/// all, none reordered and no timestamp echoed.
fn peer_report(highest: u64, packets: u64) -> crate::proto::mmp::ReceiverReport {
    crate::proto::mmp::ReceiverReport {
        highest_counter: highest,
        cumulative_packets_recv: packets,
        cumulative_bytes_recv: packets * 100,
        timestamp_echo: 0,
        dwell_time: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
    }
}

/// When crossed dials are resolved by moving the link onto another session,
/// the node resets the link's counter-derived MMP receive state as at a
/// cutover. The new session's counter starts at 0, so a report built after
/// the move counts from the new session alone.
#[test]
fn a_cross_connection_move_resets_the_link_mmp_observer_as_a_cutover_does() {
    let (_a, mut b) = ends();
    record_frames(&mut b.peer, 0, 200);

    cross_move(&mut b);

    record_frames(&mut b.peer, 0, 5);
    let report = b
        .peer
        .mmp_mut()
        .expect("link MMP state")
        .receiver
        .build_report(crate::time::mono_ms())
        .expect("frames were recorded");
    assert_eq!(
        report.highest_counter, 4,
        "highest_counter counts from the new session"
    );
    assert_eq!(
        report.cumulative_reorder_count, 0,
        "the new session's frames are not counted as reordered"
    );
}

/// When crossed dials move the link onto another session, the node forgets
/// the last receiver report the peer sent on the replaced session, as at a
/// cutover. The peer's reports on the new session count our frames from 0,
/// so the node accepts them rather than dropping them as stale until our
/// new counter passes the old one.
#[test]
fn a_cross_connection_move_accepts_the_peers_receiver_reports_on_the_new_session() {
    let (_a, mut b) = ends();
    let metrics = &mut b.peer.mmp_mut().expect("link MMP state").metrics;
    let _ = metrics.process_receiver_report(&peer_report(199, 200), 0, 1_000);
    assert_eq!(
        metrics.rr_counters(),
        Some((199, 200, 0)),
        "precondition: the report on the replaced session is accepted"
    );

    cross_move(&mut b);

    let metrics = &mut b.peer.mmp_mut().expect("link MMP state").metrics;
    let (_, log) = metrics.process_receiver_report(&peer_report(4, 205), 0, 2_000);
    assert!(
        !matches!(log, crate::proto::mmp::RrLog::Stale { .. }),
        "the peer's first report on the new session is not dropped as stale"
    );
    assert_eq!(
        metrics.rr_counters(),
        Some((4, 205, 0)),
        "the peer's first report on the new session is accepted"
    );
}
