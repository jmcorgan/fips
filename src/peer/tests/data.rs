//! Unit tests for `PeerData` (`src/peer/data.rs`).

use super::*;
use crate::config::MmpConfig;
use crate::node::diag::HsLine;
use crate::noise::{HandshakeState, NoiseSession};
use crate::peer::{ActivePeer, LinkCaps, peer_now, test_caps, test_link_params};
use crate::proto::mmp::MmpMode;
use crate::testutil::with_lf;
use crate::transport::{LinkId, TransportAddr, TransportId};
use crate::utils::index::IndexAllocator;
use crate::{Identity, NodeAddr, PeerIdentity};
use fips_core::proto::rekey::{IndexLease, NodeKeys, Record, Role};

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

// === Settling the record by the table ===

/// The monotonic reading a test settles at.
const NOW_MS: u64 = 50_000;

/// What a dirtied record is built at, read once so that two records built
/// from it hold the same values.
#[derive(Clone, Copy)]
struct At {
    instant: Instant,
    peer: PeerInstant,
}

impl At {
    fn now() -> Self {
        Self {
            instant: Instant::now(),
            peer: peer_now(),
        }
    }
}

/// A record with every field away from `PeerData::new`'s: a tree position, a
/// filter, stamps, heard flags, a stored setup, counts with lines withheld and
/// refusals past the base, frames on a previous session, and an MMP state the
/// core dirtied in every field of spin role `is_initiator`.
fn dirtied(at: At, is_initiator: bool) -> PeerData {
    let mut filter = BloomFilter::new();
    filter.insert(&NodeAddr::from_bytes([42; 16]));
    let mut hs_lines = HsLineCounts::default();
    for _ in 0..9 {
        hs_lines.count(HsLine::Resend);
    }
    hs_lines.roll();
    for _ in 0..7 {
        hs_lines.count(HsLine::Resend);
    }
    PeerData {
        declaration: Some(ParentDeclaration::new(
            NodeAddr::from_bytes([1; 16]),
            NodeAddr::from_bytes([2; 16]),
            3,
            4_000,
        )),
        ancestry: Some(
            TreeCoordinate::from_addrs(vec![
                NodeAddr::from_bytes([1; 16]),
                NodeAddr::from_bytes([2; 16]),
            ])
            .unwrap(),
        ),
        tree_announce_min_interval_ms: 750,
        last_tree_announce_sent_ms: Some(30_000),
        pending_tree_announce: true,
        inbound_filter: Some(filter),
        filter_sequence: 6,
        filter_received_at: 31_000,
        pending_filter_update: false,
        authenticated_at: 2_000,
        link_stats: stats_with(11),
        last_seen: 32_000,
        last_heartbeat_sent: Some(at.instant),
        last_heartbeat_attempt: Some(at.instant),
        promoted_at: at.peer,
        heard_at: at.peer,
        heard: !is_initiator,
        frame_heard: true,
        handshake_msg2: Some(vec![9; 40]),
        setup_ephemeral: EphemeralDigest::of_noise_msg1(&[5; 64]),
        hs_lines,
        replay_total: Arc::new(AtomicU64::new(8)),
        replay_base: 3,
        prev_frames: 5,
        failed_idx: Some(SessionIndex::new(77)),
        mmp: Some(MmpPeerState::dirtied(MmpMode::Full, 30, 32, is_initiator)),
    }
}

/// A way to build a record at an instant.
type Build = fn(At) -> PeerData;

/// The records a settle is checked on: dirtied at both roles, and new with
/// and without MMP, whose flags a write of a dirtied value would change.
fn records() -> [(&'static str, Build); 4] {
    [
        ("dirtied initiator", |at| dirtied(at, true)),
        ("dirtied responder", |at| dirtied(at, false)),
        ("new", |at| PeerData::new(AUTHENTICATED_AT, at.peer, true)),
        ("new with MMP", |at| {
            let mut data = PeerData::new(AUTHENTICATED_AT, at.peer, false);
            data.mmp = Some(fresh_mmp(false));
            data
        }),
    ]
}

/// Each row of `data`, as text, but MMP and its spin bit, which `mmp_rows`
/// compares. Names every field, so a new one does not compile here either.
fn rows(data: &PeerData) -> Vec<(DataRow, String)> {
    let PeerData {
        declaration,
        ancestry,
        tree_announce_min_interval_ms,
        last_tree_announce_sent_ms,
        pending_tree_announce,
        inbound_filter,
        filter_sequence,
        filter_received_at,
        pending_filter_update,
        authenticated_at,
        link_stats,
        last_seen,
        last_heartbeat_sent,
        last_heartbeat_attempt,
        promoted_at,
        heard_at,
        heard,
        frame_heard,
        handshake_msg2,
        setup_ephemeral,
        hs_lines,
        replay_total,
        replay_base,
        prev_frames,
        failed_idx,
        mmp: _,
    } = data;
    let filter = inbound_filter
        .as_ref()
        .map(|f| f.contains(&NodeAddr::from_bytes([42; 16])));
    vec![
        (
            DataRow::PeerFilter,
            format!("{inbound_filter:?} {filter:?} {filter_sequence} {filter_received_at}"),
        ),
        (DataRow::FilterPending, format!("{pending_filter_update}")),
        (
            DataRow::TreePosition,
            format!("{declaration:?} {ancestry:?}"),
        ),
        (DataRow::TreePending, format!("{pending_tree_announce}")),
        (
            DataRow::TreeStamp,
            format!("{last_tree_announce_sent_ms:?}"),
        ),
        (
            DataRow::TreeInterval,
            format!("{tree_announce_min_interval_ms}"),
        ),
        (
            DataRow::Heard,
            format!("{heard} {frame_heard} {heard_at:?} {promoted_at:?}"),
        ),
        (
            DataRow::StoredSetup,
            format!("{handshake_msg2:?} {setup_ephemeral:?}"),
        ),
        (
            DataRow::Stats,
            format!(
                "{link_stats:?} {authenticated_at} {last_seen} {last_heartbeat_sent:?} \
                 {last_heartbeat_attempt:?} {failed_idx:?}"
            ),
        ),
        (DataRow::PrevFrames, format!("{prev_frames}")),
        (DataRow::HsLines, format!("{hs_lines:?}")),
        (DataRow::ReplayBase, format!("{replay_base}")),
        (DataRow::ReplayTotal, format!("{replay_total:?}")),
    ]
}

/// The MMP rows of `got` that differ from `want`'s: `Spin` if the spin bit
/// state does, `Mmp` if anything else does.
fn mmp_rows(got: &PeerData, want: &PeerData) -> Vec<DataRow> {
    let diff = match (&got.mmp, &want.mmp) {
        (Some(got), Some(want)) => got.fresh_diff(want),
        (None, None) => Vec::new(),
        (Some(_), None) | (None, Some(_)) => vec!["presence"],
    };
    let mut wrong = Vec::new();
    if diff.iter().any(|name| *name != "spin_bit") {
        wrong.push(DataRow::Mmp);
    }
    if diff.contains(&"spin_bit") {
        wrong.push(DataRow::Spin);
    }
    wrong
}

/// The rows where `got` does not hold what `want` holds.
fn wrong_rows(got: &PeerData, want: &PeerData) -> Vec<DataRow> {
    let mut wrong: Vec<DataRow> = rows(got)
        .into_iter()
        .zip(rows(want))
        .filter(|((_, g), (_, w))| g != w)
        .map(|((row, _), _)| row)
        .collect();
    wrong.extend(mmp_rows(got, want));
    wrong
}

/// `data` with `t`'s cell applied by hand, row by row, as this file reads
/// the table: a reset as the row's reset, a roll, the base moved up to the
/// total, a clear.
fn expected(mut data: PeerData, t: &Transition) -> PeerData {
    for &row in DataRow::ALL {
        match (row, data_cell(row, t)) {
            (_, DataCell::Keep) => {}
            (DataRow::Mmp, DataCell::Reset) => {
                if let Some(mmp) = &mut data.mmp {
                    mmp.reset_for_rekey(NOW_MS);
                }
            }
            // The spin bit restarts in MMP's reset.
            (DataRow::Spin, DataCell::Reset) => {}
            (DataRow::PrevFrames, DataCell::Reset) => data.prev_frames = 0,
            (DataRow::HsLines, DataCell::Roll) => data.hs_lines.roll(),
            (DataRow::ReplayBase, DataCell::Base) => {
                data.replay_base = data.replay_total.load(Ordering::Relaxed);
            }
            (DataRow::PeerFilter, DataCell::Clear) => {
                data.inbound_filter = None;
                data.filter_sequence = 0;
                data.filter_received_at = 0;
            }
            (DataRow::TreePosition, DataCell::Clear) => {
                data.declaration = None;
                data.ancestry = None;
            }
            (row, cell) => panic!("this file reads no {cell:?} for {row:?} at {t:?}"),
        }
    }
    data
}

/// Settle `t` on each of `records`, and assert each row holds what its cell
/// says, from the value before or a reset's, and that the shared total is the
/// same allocation. Returns the dirtied initiator's record before and after,
/// for the caller's own assertions.
fn assert_settles(t: &Transition) -> (PeerData, PeerData) {
    let at = At::now();
    for (name, build) in records() {
        let mut got = build(at);
        let total = Arc::clone(&got.replay_total);
        got.settle(t, NOW_MS);
        let want = expected(build(at), t);
        assert_eq!(
            wrong_rows(&got, &want),
            Vec::<DataRow>::new(),
            "defect: settling {t:?} on a {name} record left these rows other than their cells say"
        );
        assert!(
            Arc::ptr_eq(&total, &got.replay_total),
            "defect: settling {t:?} on a {name} record replaced the total the decrypt workers hold"
        );
    }
    let before = dirtied(at, true);
    let mut after = dirtied(at, true);
    after.settle(t, NOW_MS);
    (before, after)
}

/// A new link MMP state of spin role `is_initiator`, as `dirtied` holds.
fn fresh_mmp(is_initiator: bool) -> MmpPeerState {
    MmpPeerState::new(MmpMode::Full, 30, 32, is_initiator)
}

#[test]
fn settle_applies_every_row_of_the_table() {
    assert_eq!(
        ROWS.as_slice(),
        DataRow::ALL,
        "defect: settle does not apply every row of the record"
    );
}

#[test]
fn a_dirtied_record_differs_from_a_new_one_in_every_row() {
    let at = At::now();
    let mut new = PeerData::new(AUTHENTICATED_AT, at.peer, true);
    new.mmp = Some(fresh_mmp(true));
    let mut wrong = wrong_rows(&dirtied(at, true), &new);
    wrong.sort_by_key(|row| DataRow::ALL.iter().position(|r| r == row));
    assert_eq!(
        wrong,
        DataRow::ALL,
        "precondition: a dirtied record differs from a new one in every row"
    );
    assert_eq!(
        wrong_rows(&dirtied(at, true), &dirtied(at, true)),
        Vec::<DataRow>::new(),
        "precondition: two records dirtied at one instant compare the same"
    );
}

#[test]
fn a_cutover_resets_what_its_cells_say_and_carries_the_rest() {
    for role in [Role::Initiator, Role::Responder] {
        let t = Transition::Cutover { role };
        let (before, after) = assert_settles(&t);
        assert_eq!(
            after.prev_frames, 0,
            "defect: {t:?} kept the previous session's frames"
        );
        assert_eq!(
            after.replay_base, 8,
            "defect: {t:?} did not move the replay base to the total"
        );
        assert_eq!(after.replay_total.load(Ordering::Relaxed), 8);
        assert_ne!(
            format!("{:?}", after.hs_lines),
            format!("{:?}", before.hs_lines),
            "defect: {t:?} did not roll the handshake line counts"
        );
        let mmp = after.mmp.as_ref().unwrap();
        assert_eq!(
            mmp.receiver.highest_counter(),
            0,
            "defect: {t:?} kept the link's MMP counters"
        );
        assert!(
            !mmp.fresh_diff(&fresh_mmp(true)).contains(&"spin_bit"),
            "defect: {t:?} kept the spin bit"
        );
        assert!(after.inbound_filter.is_some() && after.declaration.is_some());
    }

    // Through the peer, as a site will call it: the counts a cutover resets,
    // read by the accessors that report them.
    let mut peer = promoted_peer(true, stats_with(0));
    peer.count_previous();
    peer.increment_replay_suppressed();
    peer.increment_replay_suppressed();
    peer.mmp_mut()
        .unwrap()
        .receiver
        .record_recv(40, 1_000, 100, false, 1_000);
    assert_eq!(peer.prev_frames(), 1, "precondition: a previous frame");
    assert_eq!(peer.replay_suppressed_count(), 2, "precondition: refusals");
    peer.settle(&Transition::Cutover {
        role: Role::Initiator,
    });
    assert_eq!(
        peer.prev_frames(),
        0,
        "defect: the peer's cutover kept frames"
    );
    assert_eq!(
        (
            peer.replay_suppressed_count(),
            peer.replay_suppressed_total()
        ),
        (0, 2),
        "defect: the peer's cutover did not move the base and keep the total"
    );
    assert_eq!(
        peer.mmp().unwrap().receiver.highest_counter(),
        0,
        "defect: the peer's cutover kept the MMP counters"
    );
}

#[test]
fn a_move_resets_what_its_cells_say_and_carries_the_rest() {
    for own in [false, true] {
        for built in [true, false] {
            let t = Transition::Move {
                dial: LinkId::new(9),
                own,
                built,
            };
            let (before, after) = assert_settles(&t);
            assert_eq!(
                after.replay_base, 8,
                "defect: {t:?} did not move the replay base to the total"
            );
            assert_ne!(
                format!("{:?}", after.hs_lines),
                format!("{:?}", before.hs_lines),
                "defect: {t:?} did not roll the handshake line counts"
            );
            assert_eq!(
                after.prev_frames, 5,
                "defect: {t:?} reset the previous session's frames"
            );
            let highest = after.mmp.as_ref().unwrap().receiver.highest_counter();
            if built {
                assert_eq!(highest, 0, "defect: {t:?} kept the link's MMP counters");
            } else {
                assert_eq!(
                    highest, 119,
                    "defect: a refused move {t:?} reset the link's MMP counters"
                );
            }
        }
    }
}

#[test]
fn a_restart_clears_the_peers_filter_and_tree_position_and_keeps_the_counters() {
    let t = Transition::Restarted;
    let (before, after) = assert_settles(&t);
    assert!(
        after.inbound_filter.is_none()
            && after.filter_sequence == 0
            && after.filter_received_at == 0,
        "defect: a restart kept the peer's filter"
    );
    assert!(
        after.declaration.is_none() && after.ancestry.is_none(),
        "defect: a restart kept the peer's tree position"
    );
    assert_eq!(
        (after.prev_frames, after.replay_base),
        (before.prev_frames, before.replay_base),
        "defect: a restart changed the counts its cutover set"
    );
    assert_eq!(
        after.last_tree_announce_sent_ms, before.last_tree_announce_sent_ms,
        "defect: a restart changed when a tree announce last went"
    );
    assert!(
        after.pending_tree_announce,
        "defect: a restart dropped the pending tree announce"
    );

    // A filter owed stays owed: the dirtied records owe none.
    let mut owed = dirtied(At::now(), true);
    owed.pending_filter_update = true;
    owed.settle(&t, NOW_MS);
    assert!(
        owed.pending_filter_update,
        "defect: a restart cleared the filter owed"
    );
}

#[test]
fn the_kept_transitions_change_nothing() {
    let kept = [
        Transition::Keep {
            dial: LinkId::new(9),
        },
        Transition::Roam,
        Transition::Follow,
        Transition::Switch,
        Transition::Release { keep: true },
        Transition::Release { keep: false },
    ];
    for t in kept {
        for &row in DataRow::ALL {
            assert_eq!(
                data_cell(row, &t),
                DataCell::Keep,
                "precondition: {row:?} is kept at {t:?}"
            );
        }
        let (before, after) = assert_settles(&t);
        assert_eq!(
            wrong_rows(&after, &before),
            Vec::<DataRow>::new(),
            "defect: {t:?} changed the record"
        );
    }
}

#[test]
#[should_panic(expected = "has no change to settle")]
fn settling_a_transition_that_builds_or_ends_a_record_stops_a_debug_build() {
    let mut data = PeerData::new(AUTHENTICATED_AT, peer_now(), true);
    data.settle(
        &Transition::Remove {
            why: fips_core::proto::settle::output::Why::Dead,
        },
        NOW_MS,
    );
}

/// `../data.rs` with LF line endings, whatever the checkout's.
fn record_source() -> String {
    with_lf(include_str!("../data.rs"))
}

#[test]
fn the_record_denies_wildcard_arms_and_the_scan_finds_a_planted_one() {
    wildcard_scans(&record_source());
}

#[test]
fn the_record_scans_find_their_planted_lines_in_a_source_checked_out_with_crlf_line_endings() {
    let crlf = record_source().replace('\n', "\r\n");
    assert!(
        crlf.contains("} = self;\r\n"),
        "precondition: a copy of the source with CRLF line endings"
    );
    let source = with_lf(&crlf);
    wildcard_scans(&source);
    destructure_scans(&source);
}

/// That `source`, `../data.rs` as read, denies wildcard arms and holds none,
/// and that the scans find a planted catch-all arm and the deny taken away.
fn wildcard_scans(source: &str) {
    use crate::node::settle::table::tests::{denies_wildcards, wildcard_arms};
    assert!(
        denies_wildcards(source),
        "defect: data.rs does not deny wildcard arms at its head"
    );
    assert_eq!(
        wildcard_arms(source),
        Vec::<String>::new(),
        "defect: a catch-all arm in data.rs"
    );

    let planted = source.replacen(
        "            DataCell::Keep => {}\n",
        "            DataCell::Keep => {}\n            _ => {}\n",
        1,
    );
    assert_eq!(
        wildcard_arms(&planted).len(),
        1,
        "defect: the scan missed a planted catch-all arm"
    );
    let undenied = source.replacen("#![deny(clippy::wildcard_enum_match_arm)]", "", 1);
    assert!(
        !denies_wildcards(&undenied),
        "defect: the scan missed the deny taken away"
    );
}

// === Ending the record ===

/// What a removal read of `peer` before the record could be handed over,
/// through the accessors it read: `(is_heard, heard, ephemeral, suppressed,
/// withheld, the MMP receiver's packet total)`.
type Read = (
    bool,
    bool,
    Option<EphemeralDigest>,
    u32,
    Option<crate::node::diag::Withheld>,
    Option<u64>,
);

fn read_by_accessors(peer: &ActivePeer) -> Read {
    (
        peer.is_heard(),
        peer.heard(),
        peer.setup_ephemeral(),
        peer.replay_suppressed_count(),
        peer.hs_lines().unreported(),
        peer.mmp().map(|mmp| mmp.receiver.cumulative_packets_recv()),
    )
}

fn read_departed(departed: &Departed) -> Read {
    (
        departed.heard,
        departed.frame_heard,
        departed.ephemeral,
        departed.suppressed,
        departed.withheld,
        departed
            .mmp
            .as_ref()
            .map(|mmp| mmp.receiver.cumulative_packets_recv()),
    )
}

#[test]
fn departing_hands_over_what_a_removal_reads() {
    for is_initiator in [true, false] {
        for framed in [false, true] {
            let mut peer = promoted_peer(is_initiator, stats_with(0));
            if framed {
                peer.touch(AUTHENTICATED_AT + 10);
            }
            peer.note_setup_ephemeral(EphemeralDigest::of_noise_msg1(&[3; 64]));
            peer.increment_replay_suppressed();
            peer.reset_replay_suppressed();
            peer.increment_replay_suppressed();
            peer.increment_replay_suppressed();
            for _ in 0..5 {
                peer.hs_lines_mut().count(HsLine::Resend);
            }
            peer.mmp_mut()
                .unwrap()
                .receiver
                .record_recv(1, 1_000, 100, false, 1_000);

            let want = read_by_accessors(&peer);
            assert_eq!(want.3, 2, "precondition: refusals past the base");
            assert!(want.4.is_some(), "precondition: lines withheld");
            assert_eq!(want.5, Some(1), "precondition: a frame counted");
            let departed = peer.depart();
            assert_eq!(
                read_departed(&departed),
                want,
                "defect: departing an initiator {is_initiator}, framed {framed}, \
                 handed over other than a removal reads"
            );
        }
    }

    // A record dirtied in every row hands over its own values.
    let departed = dirtied(At::now(), false).depart();
    assert_eq!(
        (departed.heard, departed.frame_heard, departed.suppressed),
        (true, true, 5),
        "defect: a dirtied record departed with other flags or count"
    );
    assert_eq!(
        departed.ephemeral,
        EphemeralDigest::of_noise_msg1(&[5; 64]),
        "defect: the setup's ephemeral was not handed over"
    );
    assert!(
        departed.withheld.is_some() && departed.mmp.is_some(),
        "defect: the withheld lines or the MMP state were not handed over"
    );
}

/// The fields `pub(super) struct PeerData` declares in `source`.
fn declared_fields(source: &str) -> Vec<&str> {
    source
        .lines()
        .skip_while(|line| !line.starts_with("pub(super) struct PeerData {"))
        .take_while(|line| *line != "}")
        .filter_map(|line| line.strip_prefix("    pub(super) "))
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect()
}

/// How many `let PeerData { .. } = self;` patterns `source` holds, and what is
/// wrong with each: a rest pattern, or a set of names other than the fields
/// the struct declares.
fn destructure_faults(source: &str) -> (usize, Vec<String>) {
    let fields = declared_fields(source);
    let mut count = 0;
    let mut faults = Vec::new();
    let mut lines = source.lines();
    while lines.any(|line| line.trim() == "let PeerData {") {
        count += 1;
        let mut names = Vec::new();
        for line in lines.by_ref() {
            let line = line.trim();
            if line == "} = self;" {
                break;
            }
            if line.starts_with("..") {
                faults.push(format!("pattern {count}: a rest pattern"));
                continue;
            }
            let name = line.trim_end_matches(',');
            names.push(name.split(':').next().unwrap_or_default().trim());
        }
        if names != fields {
            faults.push(format!(
                "pattern {count}: names {names:?}, the struct declares {fields:?}"
            ));
        }
    }
    (count, faults)
}

#[test]
fn the_record_is_destructured_whole_and_the_scan_finds_a_planted_one() {
    destructure_scans(&record_source());
}

/// That `source`, `../data.rs` as read, names every field of the record in
/// both of its destructuring patterns with no rest pattern, and that the scan
/// finds a planted rest pattern and a planted field neither pattern names.
fn destructure_scans(source: &str) {
    let fields = declared_fields(source);
    assert_eq!(
        fields.len(),
        26,
        "precondition: the scan reads the record's 26 fields"
    );
    assert_eq!(
        destructure_faults(source),
        (2, Vec::new()),
        "defect: settle and depart do not each name every field with no rest pattern"
    );

    let rest = source.replacen(
        "            mmp,\n        } = self;",
        "            ..\n        } = self;",
        1,
    );
    let (count, faults) = destructure_faults(&rest);
    assert_eq!(
        count, 2,
        "precondition: the planted source keeps both patterns"
    );
    assert!(
        faults.iter().any(|f| f == "pattern 1: a rest pattern") && faults.len() == 2,
        "defect: the scan missed a planted rest pattern: {faults:?}"
    );

    let added = source.replacen(
        "    pub(super) mmp: Option<MmpPeerState>,\n",
        "    pub(super) mmp: Option<MmpPeerState>,\n    pub(super) planted: u8,\n",
        1,
    );
    let (_, faults) = destructure_faults(&added);
    assert_eq!(
        faults.len(),
        2,
        "defect: the scan missed a field neither pattern names: {faults:?}"
    );
}
