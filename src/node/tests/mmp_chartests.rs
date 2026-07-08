//! Characterization tests for the three under-tested MMP tick handlers.
//!
//! These lock in the *current* observable behavior of the MMP fan-out and
//! first-RTT paths so a later behavior-neutral sans-IO extraction has an
//! equality oracle. The `check_link_heartbeats` handler already has a good
//! oracle (`heartbeat.rs` + `tcp.rs`) and is not re-covered here; this file
//! targets the three paths with no direct handler tests:
//!
//!   * `check_mmp_reports`         — link-layer mode/flag fan-out gating
//!   * `check_session_mmp_reports` — session mode + PathMtu gating + backoff dedup
//!   * `handle_receiver_report`    — the first-RTT tree re-evaluation branch
//!
//! Assertions capture what the code does today, surprising or not.
//!
//! Report-generation is probed through the reused `proto/mmp/` primitives
//! (`should_send_report` / `should_send_notification`): after a handler tick,
//! a *consumed* interval reads as "not due" (the report was built) while an
//! *ungated* interval still reads as "due" (the report was suppressed by the
//! mode/flag gate). This survives the later refactor because those primitives
//! stay in `proto/mmp/` unchanged.
//!
//! Two `#[cfg(test)]` production seams are used, both on `ActivePeer`:
//!   * `test_init_mmp(mode)`          — attach link MMP with a chosen mode to a
//!     bare (sessionless) peer, so mode gating is exercisable.
//!   * `test_backdate_session_start`  — age `session_elapsed_ms()` so a crafted
//!     ReceiverReport yields a positive RTT sample (first-RTT trigger).
//!
//! Neither changes any decision logic or threshold.

use super::*;
use crate::config::SessionMmpConfig;
use crate::node::session::{EndToEndState, SessionEntry};
use crate::noise::HandshakeState;
use crate::peer::ActivePeer;
use crate::proto::mmp::{MmpMode, ReceiverReport};
use crate::proto::stp::{ParentDeclaration, TreeCoordinate};

// ===========================================================================
// Helpers
// ===========================================================================

/// Insert a bare (sessionless) peer carrying link-layer MMP state in `mode`.
/// Returns the peer's NodeAddr.
fn insert_link_peer(node: &mut Node, mode: MmpMode) -> NodeAddr {
    let identity = make_peer_identity();
    let addr = *identity.node_addr();
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 0);
    peer.test_init_mmp(mode);
    node.peers.insert(addr, peer);
    addr
}

/// Arm both sender and receiver link-MMP intervals so a report would be built.
fn arm_link_mmp(node: &mut Node, addr: &NodeAddr) {
    let mmp = node.get_peer_mut(addr).unwrap().mmp_mut().unwrap();
    mmp.sender.record_sent(1, 100, 500);
    mmp.receiver
        .record_recv(1, 100, 500, false, crate::time::mono_ms());
}

/// Complete an in-memory Noise XX handshake, returning the initiator session.
fn make_noise_session(
    our_identity: &crate::Identity,
    remote_identity: &crate::Identity,
) -> crate::noise::NoiseSession {
    let mut initiator = HandshakeState::new_initiator(our_identity.keypair());
    let mut responder = HandshakeState::new_responder(remote_identity.keypair());

    let mut init_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut init_epoch);
    initiator.set_local_epoch(init_epoch);
    let mut resp_epoch = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut resp_epoch);
    responder.set_local_epoch(resp_epoch);

    let msg1 = initiator.write_message_1().unwrap();
    responder.read_message_1(&msg1).unwrap();
    let msg2 = responder.write_message_2().unwrap();
    initiator.read_message_2(&msg2).unwrap();
    let msg3 = initiator.write_message_3().unwrap();
    responder.read_message_3(&msg3).unwrap();

    initiator.into_session().unwrap()
}

/// Insert an Established session carrying session-layer MMP state in `mode`.
/// Returns the destination NodeAddr.
fn insert_session(node: &mut Node, mode: MmpMode) -> NodeAddr {
    let remote = crate::Identity::generate();
    let remote_addr = *remote.node_addr();
    let session = make_noise_session(node.identity(), &remote);
    let mut entry = SessionEntry::new(
        remote_addr,
        remote.pubkey_full(),
        EndToEndState::Established(session),
        1000,
        true,
    );
    let cfg = SessionMmpConfig {
        mode,
        ..SessionMmpConfig::default()
    };
    entry.init_mmp(&cfg);
    node.sessions.insert(remote_addr, entry);
    remote_addr
}

/// Arm both sender and receiver session-MMP intervals.
fn arm_session_mmp(node: &mut Node, addr: &NodeAddr) {
    let mmp = node.sessions.get_mut(addr).unwrap().mmp_mut().unwrap();
    mmp.sender.record_sent(1, 100, 500);
    mmp.receiver
        .record_recv(1, 100, 500, false, crate::time::mono_ms());
}

// ===========================================================================
// check_mmp_reports — link-layer mode fan-out
// ===========================================================================

/// Full mode: both a SenderReport and a ReceiverReport are generated (both
/// intervals consumed).
#[tokio::test]
async fn mmp_full_mode_builds_sender_and_receiver_reports() {
    let mut node = make_node();
    let addr = insert_link_peer(&mut node, MmpMode::Full);
    arm_link_mmp(&mut node, &addr);

    node.check_mmp_reports().await;

    let mmp = node.get_peer(&addr).unwrap().mmp().unwrap();
    let now = crate::time::mono_ms();
    assert!(
        !mmp.sender.should_send_report(now),
        "Full mode consumes the sender interval (SenderReport built)"
    );
    assert!(
        !mmp.receiver.should_send_report(now),
        "Full mode consumes the receiver interval (ReceiverReport built)"
    );
}

/// Lightweight mode: only a ReceiverReport is generated; the sender interval
/// is left intact (no SenderReport in Lightweight).
#[tokio::test]
async fn mmp_lightweight_mode_builds_receiver_report_only() {
    let mut node = make_node();
    let addr = insert_link_peer(&mut node, MmpMode::Lightweight);
    arm_link_mmp(&mut node, &addr);

    node.check_mmp_reports().await;

    let mmp = node.get_peer(&addr).unwrap().mmp().unwrap();
    let now = crate::time::mono_ms();
    assert!(
        mmp.sender.should_send_report(now),
        "Lightweight mode suppresses the SenderReport (sender interval intact)"
    );
    assert!(
        !mmp.receiver.should_send_report(now),
        "Lightweight mode still builds the ReceiverReport (receiver interval consumed)"
    );
}

/// Minimal mode: neither report is generated; both intervals stay intact.
#[tokio::test]
async fn mmp_minimal_mode_builds_nothing() {
    let mut node = make_node();
    let addr = insert_link_peer(&mut node, MmpMode::Minimal);
    arm_link_mmp(&mut node, &addr);

    node.check_mmp_reports().await;

    let mmp = node.get_peer(&addr).unwrap().mmp().unwrap();
    let now = crate::time::mono_ms();
    assert!(
        mmp.sender.should_send_report(now),
        "Minimal mode suppresses the SenderReport"
    );
    assert!(
        mmp.receiver.should_send_report(now),
        "Minimal mode suppresses the ReceiverReport"
    );
}

/// Periodic operator logging fires once per interval: a fresh peer is due for
/// a log, and after one tick the log is marked (not due again within the
/// interval).
#[tokio::test]
async fn mmp_should_log_marks_logged_once_per_interval() {
    let mut node = make_node();
    let addr = insert_link_peer(&mut node, MmpMode::Full);

    assert!(
        node.get_peer(&addr)
            .unwrap()
            .mmp()
            .unwrap()
            .should_log(crate::time::mono_ms()),
        "a freshly created peer is due for its first operator log"
    );

    node.check_mmp_reports().await;

    assert!(
        !node
            .get_peer(&addr)
            .unwrap()
            .mmp()
            .unwrap()
            .should_log(crate::time::mono_ms()),
        "after one tick the log is marked and not due again within the interval"
    );
}

// ===========================================================================
// check_session_mmp_reports — session mode + PathMtu gating + backoff dedup
// ===========================================================================

/// Full mode session: both SenderReport and ReceiverReport are generated
/// (both intervals consumed) even though the send has no route and fails.
#[tokio::test]
async fn session_full_mode_builds_sender_and_receiver_reports() {
    let mut node = make_node();
    let addr = insert_session(&mut node, MmpMode::Full);
    arm_session_mmp(&mut node, &addr);

    node.check_session_mmp_reports().await;

    let mmp = node.get_session(&addr).unwrap().mmp().unwrap();
    let now = crate::time::mono_ms();
    assert!(
        !mmp.sender.should_send_report(now),
        "Full session consumes the sender interval"
    );
    assert!(
        !mmp.receiver.should_send_report(now),
        "Full session consumes the receiver interval"
    );
}

/// PathMtu notifications gate on all modes: in Minimal mode neither report is
/// built, yet a PathMtuNotification is still generated when an MTU has been
/// observed.
#[tokio::test]
async fn session_minimal_mode_still_sends_path_mtu() {
    let mut node = make_node();
    let addr = insert_session(&mut node, MmpMode::Minimal);
    arm_session_mmp(&mut node, &addr);
    // Observe an MTU so a notification becomes due (all modes).
    node.sessions
        .get_mut(&addr)
        .unwrap()
        .mmp_mut()
        .unwrap()
        .path_mtu
        .observe_incoming_mtu(1200);

    let now_before = crate::time::mono_ms();
    assert!(
        node.get_session(&addr)
            .unwrap()
            .mmp()
            .unwrap()
            .path_mtu
            .should_send_notification(now_before),
        "precondition: a PathMtuNotification is due after observing an MTU"
    );

    node.check_session_mmp_reports().await;

    let mmp = node.get_session(&addr).unwrap().mmp().unwrap();
    let now = crate::time::mono_ms();
    assert!(
        mmp.sender.should_send_report(now),
        "Minimal mode suppresses the session SenderReport"
    );
    assert!(
        mmp.receiver.should_send_report(now),
        "Minimal mode suppresses the session ReceiverReport"
    );
    assert!(
        !mmp.path_mtu.should_send_notification(now),
        "PathMtuNotification is generated in Minimal mode (gate is mode-independent)"
    );
}

/// Backoff dedup, all-fail side: a Full-mode session generates two reports
/// (SR + RR) to one destination; with no route both sends fail. The
/// per-destination dedup collapses the two failures into exactly ONE
/// `record_send_failure` (consecutive count advances by 1, not 2).
#[tokio::test]
async fn session_backoff_all_reports_fail_records_single_failure() {
    let mut node = make_node();
    let addr = insert_session(&mut node, MmpMode::Full);
    arm_session_mmp(&mut node, &addr);

    assert_eq!(
        node.get_session(&addr)
            .unwrap()
            .mmp()
            .unwrap()
            .sender
            .consecutive_send_failures(),
        0,
        "precondition: no prior send failures"
    );

    node.check_session_mmp_reports().await;

    assert_eq!(
        node.get_session(&addr)
            .unwrap()
            .mmp()
            .unwrap()
            .sender
            .consecutive_send_failures(),
        1,
        "two failed reports to one dest dedup to a single record_send_failure"
    );
}

// ===========================================================================
// handle_receiver_report — first-RTT tree re-evaluation branch
// ===========================================================================

/// Build a peer (NodeAddr strictly smaller than the node's own) that carries
/// link MMP but no RTT yet, and register it in the tree as a self-root with
/// that smaller address. This makes it a mandatory parent-switch target once
/// it becomes eligible. Returns the peer's NodeAddr.
fn setup_smaller_root_peer(node: &mut Node) -> NodeAddr {
    let my_addr = *node.node_addr();
    let (identity, addr) = loop {
        let id = make_peer_identity();
        let a = *id.node_addr();
        if a < my_addr {
            break (id, a);
        }
    };
    let mut peer = ActivePeer::new(identity, LinkId::new(1), 0);
    peer.test_init_mmp(MmpMode::Full);
    // Age the session so a crafted ReceiverReport yields a positive RTT.
    peer.test_backdate_session_start(std::time::Duration::from_secs(10));
    node.peers.insert(addr, peer);

    // Register the peer as a self-root in the tree at its (smaller) address.
    node.tree_state_mut().update_peer(
        ParentDeclaration::self_root(addr, 1, 0),
        TreeCoordinate::root(addr),
    );
    addr
}

/// Craft a ReceiverReport whose timestamp echo yields a valid first RTT
/// sample. `highest`/`pkts`/`bytes` advance the cumulative counters so a
/// second report is not dropped as stale/duplicate.
fn craft_rr_payload(highest: u64, pkts: u64, bytes: u64) -> Vec<u8> {
    let rr = ReceiverReport {
        highest_counter: highest,
        cumulative_packets_recv: pkts,
        cumulative_bytes_recv: bytes,
        timestamp_echo: 1000,
        dwell_time: 0,
        jitter: 0,
        ecn_ce_count: 0,
        owd_trend: 0,
        burst_loss_count: 0,
        cumulative_reorder_count: 0,
    };
    // handle_receiver_report receives the body with the msg_type byte stripped.
    rr.encode()[1..].to_vec()
}

/// A first RTT sample flips the peer eligible for parent selection AND fires
/// the shell-resident tree branch: the node (initially self-root) adopts the
/// smaller-addressed peer as its new root.
#[tokio::test]
async fn first_rtt_flips_peer_eligible_and_triggers_tree_reeval() {
    let mut node = make_node();
    let addr = setup_smaller_root_peer(&mut node);

    assert!(
        node.tree_state().is_root(),
        "precondition: node starts as its own root"
    );
    assert!(
        !node.get_peer(&addr).unwrap().has_srtt(),
        "precondition: peer has no RTT measurement yet"
    );
    let switches_before = node.metrics().tree.parent_switches.get();

    node.handle_receiver_report(&addr, &craft_rr_payload(10, 5, 500))
        .await;

    assert!(
        node.get_peer(&addr).unwrap().has_srtt(),
        "first RTT sample makes the peer eligible for parent selection"
    );
    assert!(
        !node.tree_state().is_root(),
        "the first-RTT tree branch fired: node adopted a parent"
    );
    assert_eq!(
        node.tree_state().root(),
        &addr,
        "node switched its root to the smaller-addressed peer"
    );
    assert!(
        node.metrics().tree.parent_switches.get() > switches_before,
        "the parent-switch was recorded in the tree metrics"
    );
}

/// Regression guard: a *second* ReceiverReport (RTT already initialized, so
/// `first_rtt` is false) does NOT re-enter the tree branch — no further parent
/// switch is recorded.
#[tokio::test]
async fn non_first_receiver_report_does_not_retrigger_tree() {
    let mut node = make_node();
    let addr = setup_smaller_root_peer(&mut node);

    // First report: fires the branch (established by the test above).
    node.handle_receiver_report(&addr, &craft_rr_payload(10, 5, 500))
        .await;
    let switches_after_first = node.metrics().tree.parent_switches.get();
    assert!(node.get_peer(&addr).unwrap().has_srtt());

    // Second report with advanced counters: first_rtt is now false.
    node.handle_receiver_report(&addr, &craft_rr_payload(20, 10, 1000))
        .await;

    assert_eq!(
        node.metrics().tree.parent_switches.get(),
        switches_after_first,
        "a non-first ReceiverReport does not re-enter the first-RTT tree branch"
    );
}
