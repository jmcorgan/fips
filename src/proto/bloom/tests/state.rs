//! Tests for `BloomState` (announcement state management).

use alloc::collections::BTreeMap;

use crate::proto::bloom::{BloomFilter, BloomState};
use crate::testutil::make_node_addr;

#[test]
fn test_bloom_state_new() {
    let node = make_node_addr(0);
    let state = BloomState::new(node);

    assert_eq!(state.own_node_addr(), &node);
    assert!(!state.is_leaf_only());
    assert_eq!(state.sequence(), 0);
    assert_eq!(state.leaf_dependent_count(), 0);
}

#[test]
fn test_bloom_state_leaf_only() {
    let node = make_node_addr(0);
    let state = BloomState::leaf_only(node);

    assert!(state.is_leaf_only());
}

#[test]
fn test_bloom_state_leaf_dependents() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let leaf1 = make_node_addr(1);
    let leaf2 = make_node_addr(2);

    state.add_leaf_dependent(leaf1);
    state.add_leaf_dependent(leaf2);
    assert_eq!(state.leaf_dependent_count(), 2);

    assert!(state.remove_leaf_dependent(&leaf1));
    assert_eq!(state.leaf_dependent_count(), 1);

    assert!(!state.remove_leaf_dependent(&leaf1)); // already removed
}

#[test]
fn test_bloom_state_debounce() {
    let node = make_node_addr(0);
    let peer = make_node_addr(1);
    let mut state = BloomState::new(node);
    state.set_update_debounce_ms(500);

    state.mark_update_needed(peer);

    // Should send initially
    assert!(state.should_send_update(&peer, 1000));

    // Record send
    state.record_update_sent(peer, 1000);
    state.mark_update_needed(peer);

    // Should not send immediately (within debounce)
    assert!(!state.should_send_update(&peer, 1200));

    // Should send after debounce period
    assert!(state.should_send_update(&peer, 1600));
}

#[test]
fn should_send_update_after_backward_clock_step_waits_at_most_the_debounce() {
    let node = make_node_addr(0);
    let peer = make_node_addr(1);
    let mut state = BloomState::new(node);
    state.set_update_debounce_ms(500);

    state.mark_update_needed(peer);
    state.record_update_sent(peer, 100_000);
    state.mark_update_needed(peer);

    // A clock reading 60 s before the last send must not hold the update
    // until the clock regains the 60 s.
    assert!(
        state.should_send_update(&peer, 40_000),
        "a time before the last send must permit the send"
    );

    // Once restamped at the earlier time, the ordinary window applies again.
    state.record_update_sent(peer, 40_000);
    state.mark_update_needed(peer);
    assert!(!state.should_send_update(&peer, 40_200));
    assert!(state.should_send_update(&peer, 40_500));
}

#[test]
fn test_bloom_state_sequence() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);
    let a = make_node_addr(1);
    let b = make_node_addr(2);

    assert_eq!(state.sequence(), 0);
    assert_eq!(state.next_sequence(&a, 10), 10);
    assert_eq!(state.next_sequence(&b, 10), 10);
    assert_eq!(state.next_sequence(&a, 10), 11);
    assert_eq!(
        state.sequence(),
        3,
        "sequence() counts every announce built"
    );
}

#[test]
fn test_bloom_state_next_sequence_for_a_new_peer_starts_at_the_floor_whatever_was_sent_to_others() {
    let mut state = BloomState::new(make_node_addr(0));
    let a = make_node_addr(1);
    let b = make_node_addr(2);

    let sent: Vec<u64> = (0..5).map(|_| state.next_sequence(&a, 1000)).collect();
    assert_eq!(sent, vec![1000, 1001, 1002, 1003, 1004]);
    assert_eq!(state.next_sequence(&b, 1000), 1000);
}

#[test]
fn test_bloom_state_sequence_to_a_peer_that_returns_exceeds_every_value_sent_before_it_left() {
    let mut state = BloomState::new(make_node_addr(0));
    let a = make_node_addr(1);

    let last = (0..3)
        .map(|_| state.next_sequence(&a, 1000))
        .last()
        .unwrap();
    assert_eq!(last, 1002);
    state.remove_peer_state(&a);

    // Only a dropped entry starts from the new floor; a kept one would give
    // last + 1.
    let returned = state.next_sequence(&a, 1256);
    assert_eq!(
        returned, 1256,
        "a returning peer must be reseeded from the floor, not continue from {last}"
    );
}

#[test]
fn test_bloom_state_pending_updates() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);

    assert!(!state.needs_update(&peer1));

    state.mark_update_needed(peer1);
    assert!(state.needs_update(&peer1));
    assert!(!state.needs_update(&peer2));

    state.mark_all_updates_needed(vec![peer1, peer2]);
    assert!(state.needs_update(&peer1));
    assert!(state.needs_update(&peer2));

    state.clear_pending_updates();
    assert!(!state.needs_update(&peer1));
    assert!(!state.needs_update(&peer2));
}

#[test]
fn test_bloom_state_base_filter() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let leaf = make_node_addr(1);
    state.add_leaf_dependent(leaf);

    let filter = state.base_filter();

    assert!(filter.contains(&node));
    assert!(filter.contains(&leaf));
    assert!(!filter.contains(&make_node_addr(99)));
}

#[test]
fn test_bloom_state_compute_outgoing_filter() {
    let my_node = make_node_addr(0);
    let mut state = BloomState::new(my_node);

    let leaf = make_node_addr(1);
    state.add_leaf_dependent(leaf);

    let peer1 = make_node_addr(10);
    let peer2 = make_node_addr(20);

    // Create peer filters
    let mut filter1 = BloomFilter::new();
    filter1.insert(&make_node_addr(100));
    filter1.insert(&make_node_addr(101));

    let mut filter2 = BloomFilter::new();
    filter2.insert(&make_node_addr(200));

    let mut peer_filters = BTreeMap::new();
    peer_filters.insert(peer1, filter1);
    peer_filters.insert(peer2, filter2);

    // Filter for peer1 should exclude peer1's contributions
    let outgoing1 = state.compute_outgoing_filter(&peer1, &peer_filters);
    assert!(outgoing1.contains(&my_node)); // self
    assert!(outgoing1.contains(&leaf)); // leaf dependent
    assert!(outgoing1.contains(&make_node_addr(200))); // from peer2
    // peer1's nodes may or may not be present (depends on split brain)

    // Filter for peer2 should exclude peer2's contributions
    let outgoing2 = state.compute_outgoing_filter(&peer2, &peer_filters);
    assert!(outgoing2.contains(&my_node));
    assert!(outgoing2.contains(&leaf));
    assert!(outgoing2.contains(&make_node_addr(100))); // from peer1
    assert!(outgoing2.contains(&make_node_addr(101))); // from peer1
}

#[test]
fn test_bloom_state_leaf_dependents_accessor() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let leaf1 = make_node_addr(1);
    let leaf2 = make_node_addr(2);

    state.add_leaf_dependent(leaf1);
    state.add_leaf_dependent(leaf2);

    let deps = state.leaf_dependents();
    assert!(deps.contains(&leaf1));
    assert!(deps.contains(&leaf2));
    assert!(!deps.contains(&make_node_addr(99)));
    assert_eq!(deps.len(), 2);
}

#[test]
fn test_bloom_state_record_sent_filter() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer = make_node_addr(1);
    let mut filter = BloomFilter::new();
    filter.insert(&make_node_addr(42));

    // Record a sent filter, then mark_changed_peers should detect no change
    // when the outgoing filter matches what was recorded
    state.record_sent_filter(peer, filter);

    // Compute what would be sent to peer (just our own node, no peer filters)
    let peer_filters = BTreeMap::new();
    let peer_addrs = vec![peer];
    state.mark_changed_peers(&make_node_addr(99), &peer_addrs, &peer_filters);

    // Outgoing filter (just self) differs from recorded (self + node 42),
    // so peer should be marked for update
    assert!(state.needs_update(&peer));
}

#[test]
fn test_bloom_state_remove_peer_state() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer = make_node_addr(1);

    // Populate all three internal maps for this peer
    state.mark_update_needed(peer);
    state.record_update_sent(peer, 1000);
    state.mark_update_needed(peer); // re-mark after send
    let filter = BloomFilter::new();
    state.record_sent_filter(peer, filter);

    assert!(state.needs_update(&peer));

    // Remove all peer state
    state.remove_peer_state(&peer);

    // Pending updates cleared
    assert!(!state.needs_update(&peer));

    // Debounce state cleared — should be able to send inside the window a
    // surviving stamp of 1000 would still impose
    state.mark_update_needed(peer);
    assert!(state.should_send_update(&peer, 1200));

    // Sent filter cleared — mark_changed_peers should treat as "never sent"
    state.clear_pending_updates();
    let peer_filters = BTreeMap::new();
    let peer_addrs = vec![peer];
    state.mark_changed_peers(&make_node_addr(99), &peer_addrs, &peer_filters);
    assert!(state.needs_update(&peer)); // never sent → must send
}

#[test]
fn test_bloom_state_mark_changed_peers_never_sent() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);

    let peer_filters = BTreeMap::new();
    let peer_addrs = vec![peer1, peer2];

    // No filters ever sent — all peers should be marked
    state.mark_changed_peers(&make_node_addr(99), &peer_addrs, &peer_filters);

    assert!(state.needs_update(&peer1));
    assert!(state.needs_update(&peer2));
}

#[test]
fn test_bloom_state_mark_changed_peers_unchanged() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let peer_filters = BTreeMap::new();
    let peer_addrs = vec![peer1, peer2];

    // Compute and record what would be sent to each peer
    let outgoing1 = state.compute_outgoing_filter(&peer1, &peer_filters);
    let outgoing2 = state.compute_outgoing_filter(&peer2, &peer_filters);
    state.record_sent_filter(peer1, outgoing1);
    state.record_sent_filter(peer2, outgoing2);

    // Nothing changed — no peers should be marked
    state.mark_changed_peers(&make_node_addr(99), &peer_addrs, &peer_filters);

    assert!(!state.needs_update(&peer1));
    assert!(!state.needs_update(&peer2));
}

#[test]
fn test_bloom_state_mark_changed_peers_one_changed() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer2 = make_node_addr(2);
    let peer_filters = BTreeMap::new();
    let peer_addrs = vec![peer1, peer2];

    // Record current outgoing filters for both peers
    let outgoing1 = state.compute_outgoing_filter(&peer1, &peer_filters);
    let outgoing2 = state.compute_outgoing_filter(&peer2, &peer_filters);
    state.record_sent_filter(peer1, outgoing1);
    state.record_sent_filter(peer2, outgoing2);

    // Now peer1 sends us a filter with new entries
    let mut inbound_from_peer1 = BloomFilter::new();
    inbound_from_peer1.insert(&make_node_addr(100));
    let mut updated_peer_filters = BTreeMap::new();
    updated_peer_filters.insert(peer1, inbound_from_peer1);

    // mark_changed_peers triggered by receiving from peer1
    state.mark_changed_peers(&peer1, &peer_addrs, &updated_peer_filters);

    // peer1 is excluded (it's the source), peer2's outgoing changed
    // (now includes peer1's entries via split-horizon)
    assert!(!state.needs_update(&peer1));
    assert!(state.needs_update(&peer2));
}

#[test]
fn test_bloom_state_mark_changed_peers_excludes_source() {
    let node = make_node_addr(0);
    let mut state = BloomState::new(node);

    let peer1 = make_node_addr(1);
    let peer_filters = BTreeMap::new();
    let peer_addrs = vec![peer1];

    // peer1 is both the source and the only peer — should be skipped
    state.mark_changed_peers(&peer1, &peer_addrs, &peer_filters);

    assert!(!state.needs_update(&peer1));
}

// ===== Delivery tracking for sent announces =====
//
// Synthetic milliseconds, counters and receiver reports, no I/O. A report is
// written `(highest, received, reordered)`. Unless a test says otherwise, a
// send is recorded with `next_counter = counter + 1`, as the shell reads it
// straight after the send.

use crate::NodeAddr;
use crate::proto::mmp::delivery::{
    FALLBACK_MS, LOSS_BUDGET, LinkEvidence, QUIET_MS, ResendReason, RrCounters, UNVERIFIED_BUDGET,
};

/// First session.
const E1: u64 = 0x0e01;
/// Second session.
const E2: u64 = 0x0e02;
/// Third session.
const E3: u64 = 0x0e03;

/// A report's cumulative counters.
fn rr(highest: u64, received: u64, reordered: u32) -> Option<RrCounters> {
    Some(RrCounters {
        highest,
        received,
        reordered,
    })
}

/// Link evidence for session `epoch`.
fn link(epoch: u64, next_counter: u64, rr: Option<RrCounters>) -> LinkEvidence {
    LinkEvidence {
        epoch,
        next_counter,
        rr,
    }
}

/// Filter content number `n`: distinct numbers give distinct filters.
fn content(n: u8) -> BloomFilter {
    let mut filter = BloomFilter::new();
    filter.insert(&make_node_addr(100u8.wrapping_add(n)));
    filter
}

/// One peer's announces, driven as the shell drives them.
struct Track {
    state: BloomState,
    peer: NodeAddr,
    content: u8,
    counter: u64,
}

impl Track {
    /// A tracker with nothing sent yet, sending content 1.
    fn new() -> Self {
        Self {
            state: BloomState::new(make_node_addr(0)),
            peer: make_node_addr(1),
            content: 1,
            counter: 0,
        }
    }

    /// Record a send of the current content at `counter`, then the sent
    /// filter, in the shell's order.
    fn send(&mut self, counter: u64, link: LinkEvidence, now_ms: u64) {
        let filter = content(self.content);
        self.state
            .record_announce(self.peer, &filter, counter, &link, now_ms);
        self.state.record_sent_filter(self.peer, filter);
        self.counter = counter;
    }

    /// Send new content at `counter`.
    fn send_new(&mut self, counter: u64, link: LinkEvidence, now_ms: u64) {
        self.content += 1;
        self.send(counter, link, now_ms);
    }

    /// One tick of the tracker.
    fn check(&mut self, link: LinkEvidence, now_ms: u64) -> Option<ResendReason> {
        self.state.check_announce(&self.peer, &link, now_ms)
    }

    /// Whether the announce is still unconfirmed.
    fn outstanding(&self) -> bool {
        self.state.announce_outstanding(&self.peer)
    }

    /// Check every 1,000 ms from `from_ms` to `to_ms` inclusive. `model` gives
    /// the evidence at a time, from the outstanding counter: for a check with
    /// `false`, and for recording a resend with `true`, where the resend takes
    /// the counter `next_counter - 1` of that evidence. Each resend is
    /// recorded, with new content when `renew` is set. Returns the resends.
    fn hold(
        &mut self,
        from_ms: u64,
        to_ms: u64,
        renew: bool,
        model: impl Fn(u64, u64, bool) -> LinkEvidence,
    ) -> Vec<(u64, ResendReason)> {
        let mut resends = Vec::new();
        let mut now = from_ms;
        while now <= to_ms {
            if let Some(reason) = self.check(model(now, self.counter, false), now) {
                resends.push((now, reason));
                let ev = model(now, self.counter, true);
                if renew {
                    self.content += 1;
                }
                self.send(ev.next_counter - 1, ev, now);
            }
            now += 1_000;
        }
        resends
    }
}

/// Loss on every check: each send is based on a report just below it, and
/// each check sees a report two counters on with one frame missing.
fn lossy(_now: u64, counter: u64, recording: bool) -> LinkEvidence {
    if recording {
        let n = counter + 1;
        link(E1, n + 1, rr(n - 1, n, 0))
    } else {
        link(E1, counter + 2, rr(counter + 1, counter + 1, 0))
    }
}

/// The resend times of `resends`, in ms.
fn times(resends: &[(u64, ResendReason)]) -> Vec<u64> {
    resends.iter().map(|(t, _)| *t).collect()
}

/// A covering report with a frame missing since the base is a loss.
#[test]
fn test_bloom_ack_covering_report_with_a_missing_frame_resends_on_loss() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    // Four of 10..=14 arrived; 12 is the missing one.
    assert_eq!(
        t.check(link(E1, 15, rr(14, 14, 0)), 1_000),
        Some(ResendReason::Loss)
    );
    assert!(t.state.needs_update(&t.peer), "the peer must be marked");
}

/// A covering report with every frame since the base confirms.
#[test]
fn test_bloom_ack_covering_report_with_every_frame_confirms() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    assert_eq!(t.check(link(E1, 15, rr(14, 15, 0)), 1_000), None);
    assert!(!t.outstanding(), "the announce must be confirmed");
    assert!(
        !t.state.needs_update(&t.peer),
        "the peer must not be marked"
    );
}

/// A late frame from before the base cannot stand in for the lost
/// announce. The base has a hole, so the pair cannot tell that late frame
/// from an in-window reorder: no evidence, and the fallback resends.
#[test]
fn test_bloom_ack_reordered_frame_does_not_mask_a_lost_announce() {
    let mut t = Track::new();
    // Base (9, 9, 0): frame 5 missing at the time.
    t.send(12, link(E1, 13, rr(9, 9, 0)), 0);
    // Late frame 5 plus 10, 11, 13, 14; 12 lost. A naive count gives 5 == 5.
    let late = |_, c, recording| link(E1, c + if recording { 2 } else { 3 }, rr(14, 14, 1));
    assert_eq!(t.check(late(1_000, 12, false), 1_000), None);
    assert!(t.outstanding(), "a lost announce must not confirm");
    let resends = t.hold(2_000, 120_000, false, late);
    assert_eq!(resends, vec![(FALLBACK_MS, ResendReason::Timeout)]);
}

/// A report that does not yet cover the announce decides nothing, and the
/// next one is measured against the base taken at the send.
#[test]
fn test_bloom_ack_report_below_the_announce_waits_for_a_covering_one() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    assert_eq!(t.check(link(E1, 13, rr(11, 12, 0)), 1_000), None);
    assert!(t.outstanding(), "an uncovered announce stays outstanding");
    assert_eq!(t.check(link(E1, 15, rr(14, 15, 0)), 2_000), None);
    assert!(!t.outstanding(), "the covering report must confirm");
}

/// An announce from an earlier session is resent once the new session can
/// check the resend, or once after the fallback if it never can.
#[test]
fn test_bloom_ack_announce_from_an_earlier_session_is_resent_once() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    assert_eq!(t.check(link(E2, 1, None), 1_000), None);
    assert_eq!(
        t.check(link(E2, 5, rr(3, 4, 0)), 2_000),
        Some(ResendReason::SessionChanged)
    );
    t.send(5, link(E2, 6, rr(3, 4, 0)), 2_000);
    assert_eq!(t.check(link(E2, 7, rr(6, 7, 0)), 3_000), None);
    assert!(!t.outstanding(), "the resend must be confirmed");

    // No usable report in the new session: one Timeout, 30 s after the change
    // was seen, and no second.
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    assert_eq!(t.check(link(E2, 1, None), 1_000), None);
    let resends = t.hold(2_000, 121_000, false, |_, c, recording| {
        link(E2, c + if recording { 2 } else { 1 }, None)
    });
    assert_eq!(resends, vec![(31_000, ResendReason::Timeout)]);
}

/// In the peer's first session, with no report before the send, every
/// counter from 0 must arrive.
#[test]
fn test_bloom_ack_first_session_measures_from_counter_zero() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, None), 0);
    assert_eq!(t.check(link(E1, 13, rr(12, 13, 0)), 1_000), None);
    assert!(!t.outstanding(), "13 of 0..=12 must confirm");

    let mut t = Track::new();
    t.send(12, link(E1, 13, None), 0);
    assert_eq!(
        t.check(link(E1, 13, rr(12, 12, 0)), 1_000),
        Some(ResendReason::Loss)
    );
}

/// In a later session, the peer's cumulative count includes earlier
/// sessions, so no report means no base: a first report below the announce
/// becomes the base, and one already covering it cannot check it.
#[test]
fn test_bloom_ack_later_session_without_a_report_has_no_base() {
    // Case A: re-based, then confirmed with no resend.
    let mut t = Track::new();
    t.send(3, link(E1, 4, None), 0);
    t.send(12, link(E2, 13, None), 1_000);
    assert_eq!(t.check(link(E2, 13, rr(8, 509, 0)), 2_000), None);
    assert!(t.outstanding());
    assert_eq!(t.check(link(E2, 15, rr(14, 515, 0)), 3_000), None);
    assert!(!t.outstanding(), "the re-based announce must confirm");

    // Case B: the first usable report already covers the announce.
    let mut t = Track::new();
    t.send(3, link(E1, 4, None), 0);
    t.send(12, link(E2, 13, None), 1_000);
    assert_eq!(
        t.check(link(E2, 15, rr(14, 515, 0)), 2_000),
        Some(ResendReason::Unverified)
    );
}

/// A report from another session at send time is no evidence, and the
/// announce gets exactly one fallback resend.
#[test]
fn test_bloom_ack_report_from_another_session_at_send_gets_one_timeout() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(20, 30, 0)), 0);
    let resends = t.hold(1_000, 120_000, false, |_, c, recording| {
        link(E1, c + if recording { 2 } else { 1 }, rr(20, 30, 0))
    });
    assert_eq!(resends, vec![(FALLBACK_MS, ResendReason::Timeout)]);
}

/// With no report ever, one fallback resend per session.
#[test]
fn test_bloom_ack_no_report_ever_resends_once_per_session() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, None), 0);
    assert_eq!(t.check(link(E1, 13, None), FALLBACK_MS - 1), None);
    let quiet = |_, c, recording| link(E1, c + if recording { 2 } else { 1 }, None);
    let resends = t.hold(FALLBACK_MS, 120_000, false, quiet);
    assert_eq!(resends, vec![(FALLBACK_MS, ResendReason::Timeout)]);

    assert_eq!(t.check(link(E2, 1, None), 121_000), None);
    let later = |_, c, recording| link(E2, c + if recording { 2 } else { 1 }, None);
    let resends = t.hold(122_000, 240_000, false, later);
    assert_eq!(resends, vec![(151_000, ResendReason::Timeout)]);
}

/// A trigger that never stops is spaced 1, 2, 4 ... s apart up to 60 s.
#[test]
fn test_bloom_ack_sustained_trigger_backs_off_to_one_resend_a_minute() {
    let mut t = Track::new();
    t.send(12, lossy(0, 11, true), 0);
    let resends = t.hold(0, 600_000, true, lossy);
    let expected: Vec<u64> = [0, 1, 3, 7, 15, 31, 63]
        .iter()
        .map(|s| s * 1_000)
        .chain((123_000..=600_000).step_by(60_000))
        .collect();
    assert_eq!(times(&resends), expected);
    for (i, &(start, _)) in resends.iter().enumerate() {
        let in_window = resends[i..]
            .iter()
            .take_while(|(t, _)| *t < start + 60_000)
            .count();
        assert!(in_window <= 6, "{in_window} resends in 60 s from {start}");
    }
}

/// 120 s with no resend resets the backoff; 119 s does not.
#[test]
fn test_bloom_ack_backoff_resets_only_after_the_quiet_period() {
    let run = |next_ms: u64| {
        let mut t = Track::new();
        t.send(12, lossy(0, 11, true), 0);
        let first = t.hold(0, 31_000, true, lossy);
        assert_eq!(times(&first), vec![0, 1_000, 3_000, 7_000, 15_000, 31_000]);
        t.hold(next_ms, next_ms + 70_000, true, lossy)
    };
    // Case A: 120 s after the last resend, the level resets to 0.
    let a = run(31_000 + QUIET_MS);
    assert_eq!(times(&a[..2]), vec![151_000, 152_000]);
    // Case B: 119 s after, level 6 still applies and reaches level 7.
    let b = run(31_000 + QUIET_MS - 1_000);
    assert_eq!(times(&b[..2]), vec![150_000, 210_000]);
}

/// A report that went backwards within a session is no evidence
/// (defensive: the MMP layer never stores one).
#[test]
fn test_bloom_ack_regressed_report_is_no_evidence() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    let regressed = |_, c, recording| link(E1, c + if recording { 2 } else { 3 }, rr(14, 8, 0));
    assert_eq!(t.check(regressed(1_000, 12, false), 1_000), None);
    assert!(t.outstanding());
    let resends = t.hold(2_000, FALLBACK_MS, false, regressed);
    assert_eq!(resends, vec![(FALLBACK_MS, ResendReason::Timeout)]);
}

/// Removing the peer forgets its announce, and the next send starts a
/// fresh entry whose first session measures from counter zero.
#[test]
fn test_bloom_ack_removed_peer_starts_fresh() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    t.state.remove_peer_state(&t.peer);
    assert_eq!(t.check(link(E1, 15, rr(14, 14, 0)), 1_000), None);
    assert!(!t.outstanding());

    t.send(3, link(E2, 4, None), 2_000);
    assert_eq!(t.check(link(E2, 4, rr(3, 4, 0)), 3_000), None);
    assert!(!t.outstanding(), "the new entry must measure from zero");
}

/// A confirmation does not reset the backoff.
#[test]
fn test_bloom_ack_confirmation_keeps_the_backoff() {
    let mut t = Track::new();
    t.send(12, lossy(0, 11, true), 0);
    assert_eq!(t.check(lossy(0, 12, false), 0), Some(ResendReason::Loss));
    t.send(13, lossy(0, 12, true), 0);
    assert_eq!(t.check(link(E1, 15, rr(14, 15, 0)), 100), None);
    assert!(!t.outstanding(), "setup: the resend is confirmed");

    t.send_new(15, lossy(200, 14, true), 200);
    assert_eq!(t.check(lossy(500, 15, false), 500), None);
    assert_eq!(
        t.check(lossy(1_000, 15, false), 1_000),
        Some(ResendReason::Loss)
    );
}

/// The initiator holds a report from the responder's view of the old
/// session, frozen until the new session's counter passes it. It never
/// triggers more than each announce's one unchecked resend.
#[test]
fn test_bloom_ack_frozen_report_after_a_rekey_spends_only_the_unchecked_budget() {
    // The session sends 100 frames a second from counter 1.
    let next = |now: u64| 1 + now / 10;
    let frozen = rr(5_000, 90_000, 40);
    let accepted = rr(6_100, 96_101, 45);
    let report = move |now: u64| if now < 62_000 { frozen } else { accepted };
    let model = move |now: u64, _c: u64, recording: bool| {
        link(E2, next(now) + u64::from(recording), report(now))
    };

    let mut t = Track::new();
    t.send(3, link(E1, 4, None), 0);
    t.send(3, link(E2, 4, frozen), 0);
    let first = t.hold(1_000, 59_000, false, model);
    assert_eq!(first, vec![(FALLBACK_MS, ResendReason::Timeout)]);

    // A new-content announce based on the now-usable frozen report.
    t.send_new(6_000, link(E2, 6_001, frozen), 60_000);
    let second = t.hold(61_000, 120_000, false, model);
    assert_eq!(second, vec![(90_000, ResendReason::Timeout)]);

    let third = t.hold(121_000, 140_000, false, |now, c, recording| {
        let n = 10 + (now - 121_000) / 1_000 + u64::from(recording);
        link(E3, n.max(c + 1), rr(5, 6, 0))
    });
    assert_eq!(third, vec![(121_000, ResendReason::SessionChanged)]);
}

/// The responder receives reports whose highest counter comes from its
/// own previous session. They change on every report and are never usable,
/// so they trigger nothing beyond the one fallback resend.
#[test]
fn test_bloom_ack_polluted_report_after_a_rekey_spends_only_the_unchecked_budget() {
    let model = |now: u64, c: u64, recording: bool| {
        let secs = now / 1_000;
        let n = (1 + 10 * secs).max(c + 1) + u64::from(recording);
        link(E2, n, rr(9_000, 100 + 5 * secs, 5 * secs as u32))
    };
    let mut t = Track::new();
    t.send(3, link(E1, 4, None), 0);
    t.send(5, model(0, 4, true), 0);
    let resends = t.hold(1_000, 120_000, false, model);
    assert_eq!(resends, vec![(FALLBACK_MS, ResendReason::Timeout)]);
}

/// More receipts than counters means the reports straddle a reset or
/// another session's frame, which is no evidence.
#[test]
fn test_bloom_ack_surplus_receipts_are_no_evidence() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    let surplus = |_, c, recording| link(E1, c + if recording { 2 } else { 3 }, rr(14, 20, 0));
    assert_eq!(t.check(surplus(1_000, 12, false), 1_000), None);
    assert!(t.outstanding());
    let resends = t.hold(2_000, FALLBACK_MS, false, surplus);
    assert_eq!(resends, vec![(FALLBACK_MS, ResendReason::Timeout)]);
}

/// One lineage in one session gets three loss resends and one unchecked
/// resend; new content or a new session refills both.
#[test]
fn test_bloom_ack_budgets_bound_resends_per_lineage_per_session() {
    let spend = || {
        let mut t = Track::new();
        t.send(12, lossy(0, 11, true), 0);
        let resends = t.hold(0, 120_000, false, lossy);
        assert_eq!(
            resends,
            vec![
                (0, ResendReason::Loss),
                (1_000, ResendReason::Loss),
                (3_000, ResendReason::Loss),
                (33_000, ResendReason::Timeout),
            ]
        );
        assert_eq!(LOSS_BUDGET, 3);
        assert_eq!(UNVERIFIED_BUDGET, 1);
        t
    };

    let mut t = spend();
    let c = t.counter;
    t.send_new(c + 1, lossy(121_000, c, true), 121_000);
    assert_eq!(
        t.check(lossy(122_000, t.counter, false), 122_000),
        Some(ResendReason::Loss),
        "new content must refill the loss budget"
    );

    let mut t = spend();
    let c = t.counter;
    let rekeyed = |ev: LinkEvidence| link(E2, ev.next_counter, ev.rr);
    t.send(c + 1, rekeyed(lossy(121_000, c, true)), 121_000);
    assert_eq!(
        t.check(rekeyed(lossy(122_000, t.counter, false)), 122_000),
        Some(ResendReason::Loss),
        "a new session must refill the loss budget"
    );
}

/// A resend carries the content it repeats, so it spends from the same
/// lineage's budget instead of starting a new one.
#[test]
fn test_bloom_ack_resend_of_the_same_content_is_not_a_new_lineage() {
    let mut t = Track::new();
    t.send(12, lossy(0, 11, true), 0);
    let resends = t.hold(0, 7_000, false, lossy);
    assert_eq!(times(&resends), vec![0, 1_000, 3_000]);
    assert_eq!(
        t.check(lossy(8_000, t.counter, false), 8_000),
        None,
        "a fourth loss resend must not be allowed"
    );
}

/// A report polluted after the base was taken is unusable, not a loss.
#[test]
fn test_bloom_ack_report_polluted_after_the_base_is_not_a_loss() {
    let mut t = Track::new();
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    assert_eq!(t.check(link(E1, 20, rr(9_000, 16, 0)), 1_000), None);
    assert!(t.outstanding());
}

/// A frame inside the checked window that arrives after a higher counter is
/// counted as a reorder, but it did arrive. On a base with no holes (a
/// first-session report that counted every frame up to its highest), every
/// counter in the window arriving confirms the announce.
#[test]
fn test_bloom_ack_in_window_reorder_on_a_complete_base_confirms() {
    let mut t = Track::new();
    // Base (9, 10, 0): all of 0..=9 counted.
    t.send(12, link(E1, 13, rr(9, 10, 0)), 0);
    // 10..=14 all arrived, 12 after 13.
    assert_eq!(t.check(link(E1, 15, rr(14, 15, 1)), 1_000), None);
    assert!(
        !t.outstanding(),
        "every counter arrived, so it must confirm"
    );
    assert!(
        !t.state.needs_update(&t.peer),
        "the peer must not be marked"
    );
}

/// In the peer's first session with no report before the send, frames that
/// arrive out of order are still every counter from 0, so the announce
/// confirms.
#[test]
fn test_bloom_ack_in_window_reorder_on_the_zero_base_confirms() {
    let mut t = Track::new();
    t.send(4, link(E1, 5, None), 0);
    // 0..=4 all arrived, as 0, 1, 4, 3, 2.
    assert_eq!(t.check(link(E1, 5, rr(4, 5, 2)), 1_000), None);
    assert!(
        !t.outstanding(),
        "every counter arrived, so it must confirm"
    );
    assert!(
        !t.state.needs_update(&t.peer),
        "the peer must not be marked"
    );
}

/// In a later session the base cannot be shown to have no holes, so a
/// covering report with an in-window reorder cannot tell a late frame from
/// before the base from one inside the window. That is no evidence: no loss
/// resend, and the fallback covers the announce.
#[test]
fn test_bloom_ack_ambiguous_pair_in_a_later_session_waits_for_the_fallback() {
    let mut t = Track::new();
    t.send(3, link(E1, 4, None), 0);
    // Cumulative counts include 500 frames of the earlier session.
    t.send(12, link(E2, 13, rr(9, 510, 0)), 0);
    let ambiguous = |_, c, recording| link(E2, c + if recording { 2 } else { 3 }, rr(14, 515, 1));
    assert_eq!(t.check(ambiguous(1_000, 12, false), 1_000), None);
    assert!(t.outstanding(), "an ambiguous pair must not confirm");
    let resends = t.hold(2_000, 120_000, false, ambiguous);
    assert_eq!(resends, vec![(FALLBACK_MS, ResendReason::Timeout)]);
}

/// A later-session base whose counts happen to read as having no holes is
/// still not trusted: the cumulative count includes earlier sessions. A late
/// frame from before the base arriving with the announce lost must not
/// confirm it.
#[test]
fn test_bloom_ack_later_session_base_is_never_complete() {
    let mut t = Track::new();
    t.send(3, link(E1, 4, None), 0);
    // Base (9, 10, 0) in E2: 3 frames of E1 plus 7 of 0..=9, with 5 missing.
    t.send(12, link(E2, 13, rr(9, 10, 0)), 0);
    // Late frame 5 plus 10, 11, 13, 14; 12 lost. Received rose by 5 == span.
    let late = |_, c, recording| link(E2, c + if recording { 2 } else { 3 }, rr(14, 15, 1));
    assert_eq!(t.check(late(1_000, 12, false), 1_000), None);
    assert!(t.outstanding(), "a lost announce must not confirm");
    let resends = t.hold(2_000, 120_000, false, late);
    assert_eq!(resends, vec![(FALLBACK_MS, ResendReason::Timeout)]);
}
