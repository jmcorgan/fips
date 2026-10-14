//! The decryption-failure, rekey-cutover and link-dead lines carry the key
//! state that lets one node's log say which of a peer's sessions a failing
//! frame named, whether the pending session was tried, what K-bit each end
//! held, and what a link-dead removal measured its silence from.
//!
//! Each test drives the condition a line reports through the real handler,
//! finds the line by its exact message, and checks the discriminating fields
//! against values derived independently: session tags from the sessions the
//! nodes hold, indices from the peer's own accessors, transports and
//! addresses from the packet the test built.
//!
//! Every frame a test expects to fail is corrupted, so it fails every session
//! the node holds whichever of them the node tries.

use super::heartbeat::set_link_dead_timeout;
use super::link_setup_diag::{expect_line, field, index_text, session_tag};
use super::session::{HeldMsg2Pair, pump_until_quiet, rekey_pair_with_held_msg2};
use super::spanning_tree::*;
use super::*;
use crate::noise::NoiseSession;
use crate::proto::fmp::wire::{
    ESTABLISHED_HEADER_SIZE, FLAG_KEY_EPOCH, build_encrypted, build_established_header,
};
use crate::proto::link::LinkMessageType;
use crate::testutil::{LogCapture, capture_logs_scoped, log_field};
use std::time::Instant;

/// The plaintext of every test frame: a 4-byte session timestamp, then a
/// heartbeat.
fn heartbeat_plaintext() -> Vec<u8> {
    let mut p = 0u32.to_le_bytes().to_vec();
    p.push(LinkMessageType::Heartbeat.to_byte());
    p
}

/// Seal a heartbeat frame on `session` for `receiver_idx` with K-bit `k_bit`,
/// the way the send path does.
fn seal(session: &mut NoiseSession, receiver_idx: SessionIndex, k_bit: bool) -> Vec<u8> {
    let plaintext = heartbeat_plaintext();
    let counter = session.current_send_counter();
    let flags = if k_bit { FLAG_KEY_EPOCH } else { 0 };
    let header = build_established_header(receiver_idx, counter, flags, plaintext.len() as u16);
    let ciphertext = session.encrypt_with_aad(&plaintext, &header).unwrap();
    build_encrypted(&header, &ciphertext)
}

/// `frame` with its first ciphertext byte flipped, so it authenticates
/// against no session.
fn corrupt(mut frame: Vec<u8>) -> Vec<u8> {
    frame[ESTABLISHED_HEADER_SIZE] ^= 0x01;
    frame
}

/// A frame for `receiver_idx` at `counter` whose ciphertext is not sealed by
/// any session.
fn junk_frame(receiver_idx: SessionIndex, counter: u64) -> Vec<u8> {
    let plaintext_len = heartbeat_plaintext().len();
    let header = build_established_header(receiver_idx, counter, 0, plaintext_len as u16);
    build_encrypted(&header, &vec![0x5a; plaintext_len + 16])
}

/// `data` as it arrives at `to` from `from` over the loopback transport.
fn arriving(to: &TestNode, from: &TestNode, data: Vec<u8>) -> ReceivedPacket {
    ReceivedPacket {
        transport_id: to.transport_id,
        remote_addr: from.addr.clone(),
        data,
        timestamp_ms: Node::now_ms(),
    }
}

/// Run `node.handle_encrypted_frame(p)` with its log lines captured.
async fn frame_logged(node: &mut Node, p: ReceivedPacket) -> LogCapture {
    let (logs, guard) = capture_logs_scoped();
    node.handle_encrypted_frame(p).await;
    drop(guard);
    logs
}

/// Whether `line`'s message is exactly `message`.
fn has_message(line: &str, message: &str) -> bool {
    let needle = format!(" message={message}");
    line.match_indices(&needle).any(|(at, _)| {
        let rest = &line[at + needle.len()..];
        rest.is_empty()
            || rest
                .strip_prefix(' ')
                .and_then(|r| r.split(' ').next())
                .is_some_and(|t| t.contains('='))
    })
}

/// Every captured line whose message is exactly `message`.
fn lines_with(logs: &LogCapture, message: &str) -> Vec<String> {
    logs.lines()
        .into_iter()
        .filter(|l| has_message(l, message))
        .collect()
}

/// The session tags node 1 holds for node 0: (current, pending).
fn node1_tags(nodes: &[TestNode], node0_addr: &NodeAddr) -> (String, String) {
    let p = nodes[1].node.get_peer(node0_addr).unwrap();
    (
        session_tag(p.noise_session().unwrap()),
        session_tag(p.pending_new_session().expect("node 1 holds a pending")),
    )
}

/// A frame sealed with node 0's pending session for node 1's pending index,
/// with K-bit `k_bit`; node 0 must already hold its pending. Returns the
/// frame, node 1's pending index and the tag of node 0's pending.
fn sealed_by_node0_pending(
    nodes: &mut [TestNode],
    node1_addr: &NodeAddr,
    k_bit: bool,
) -> (Vec<u8>, SessionIndex, String) {
    let p0 = nodes[0].node.get_peer_mut(node1_addr).unwrap();
    let idx = p0
        .pending_their_index()
        .expect("node 0 holds a pending after the msg2");
    let tag = session_tag(p0.pending_new_session().unwrap());
    let frame = seal(p0.pending_new_session_mut().unwrap(), idx, k_bit);
    (frame, idx, tag)
}

/// A frame on node 1's pending index that carries the K-bit both ends hold
/// is tried against the pending session because it names that index, and
/// the failure line says which session the index belongs to and that the
/// trial ran on the index alone.
#[tokio::test]
async fn a_frame_on_the_pending_index_carrying_our_kbit_logs_that_the_pending_trial_ran_on_the_index()
 {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    nodes[0].node.handle_msg2(held_msg2).await;

    let (frame, idx, pending_tag) = sealed_by_node0_pending(&mut nodes, &node1_addr, false);
    let (current_tag, node1_pending_tag) = node1_tags(&nodes, &node0_addr);
    assert_eq!(
        node1_pending_tag, pending_tag,
        "both ends' pending sessions share one tag"
    );
    assert_eq!(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .pending_our_index(),
        Some(idx)
    );

    let p = arriving(&nodes[1], &nodes[0], corrupt(frame));
    let (tid, from) = (p.transport_id, p.remote_addr.clone());
    let logs = frame_logged(&mut nodes[1].node, p).await;
    let line = expect_line(&logs, "Decryption failed");
    assert_eq!(field(&line, "slot"), "pending-responder", "{line}");
    assert_eq!(field(&line, "trial"), "run-index", "{line}");
    assert_eq!(field(&line, "kbit_frame"), "false", "{line}");
    assert_eq!(field(&line, "kbit_ours"), "false", "{line}");
    assert_eq!(field(&line, "receiver_idx"), index_text(idx), "{line}");
    assert_eq!(field(&line, "pending_epoch"), pending_tag, "{line}");
    assert_eq!(field(&line, "epoch"), current_tag, "{line}");
    assert_eq!(field(&line, "prev_epoch"), "none", "{line}");
    assert_eq!(field(&line, "transport_id"), tid.to_string(), "{line}");
    assert_eq!(field(&line, "remote_addr"), from.to_string(), "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// A frame with the other K-bit is tried against the pending session; when
/// it fails that trial too, the line says the trial ran and failed. An
/// authentic frame sealed the same way promotes and logs no failure.
#[tokio::test]
async fn a_flipped_frame_that_fails_the_pending_trial_logs_that_the_trial_failed() {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    nodes[0].node.handle_msg2(held_msg2).await;

    let (frame, idx, _) = sealed_by_node0_pending(&mut nodes, &node1_addr, true);
    let (authentic, _, _) = sealed_by_node0_pending(&mut nodes, &node1_addr, true);
    let (logs, guard) = capture_logs_scoped();
    let p = arriving(&nodes[1], &nodes[0], corrupt(frame));
    nodes[1].node.handle_encrypted_frame(p).await;
    let p = arriving(&nodes[1], &nodes[0], authentic);
    nodes[1].node.handle_encrypted_frame(p).await;
    drop(guard);

    let line = expect_line(&logs, "Decryption failed");
    assert_eq!(field(&line, "trial"), "failed", "{line}");
    assert_eq!(field(&line, "slot"), "pending-responder", "{line}");
    assert_eq!(field(&line, "kbit_frame"), "true", "{line}");
    assert_eq!(
        lines_with(&logs, "Decryption failed").len(),
        1,
        "the authentic frame must not log a failure: {:#?}",
        logs.lines()
    );
    assert_eq!(
        nodes[1].node.get_peer(&node0_addr).unwrap().our_index(),
        Some(idx),
        "the authentic frame promotes node 1's pending"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A failing frame on the pending index of the rekey this node initiated
/// names that slot.
#[tokio::test]
async fn a_frame_naming_the_pending_session_we_initiated_logs_its_slot() {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    nodes[0].node.handle_msg2(held_msg2).await;

    let idx = nodes[0]
        .node
        .get_peer(&node1_addr)
        .unwrap()
        .pending_our_index()
        .expect("node 0 holds a pending after the msg2");
    let p1 = nodes[1].node.get_peer_mut(&node0_addr).unwrap();
    let frame = seal(p1.pending_new_session_mut().unwrap(), idx, false);

    let p = arriving(&nodes[0], &nodes[1], corrupt(frame));
    let logs = frame_logged(&mut nodes[0].node, p).await;
    let line = expect_line(&logs, "Decryption failed");
    assert_eq!(field(&line, "slot"), "pending-initiator", "{line}");
    assert_eq!(field(&line, "trial"), "run-index", "{line}");
    assert_eq!(field(&line, "receiver_idx"), index_text(idx), "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// Failing frames on the current index and, after a cutover, on the
/// draining previous index name their slots, with no pending held.
#[tokio::test]
async fn corrupt_frames_on_the_current_and_draining_sessions_log_their_slots() {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;

    // Before the msg2, node 0 holds no pending.
    let (old_idx, old_tag) = {
        let p0 = nodes[0].node.get_peer(&node1_addr).unwrap();
        assert!(p0.pending_new_session().is_none());
        (
            p0.our_index().unwrap(),
            session_tag(p0.noise_session().unwrap()),
        )
    };
    let p1 = nodes[1].node.get_peer_mut(&node0_addr).unwrap();
    let frame = seal(p1.noise_session_mut().unwrap(), old_idx, false);
    let p = arriving(&nodes[0], &nodes[1], corrupt(frame));
    let logs = frame_logged(&mut nodes[0].node, p).await;
    let line = expect_line(&logs, "Decryption failed");
    assert_eq!(field(&line, "slot"), "current", "{line}");
    assert_eq!(field(&line, "trial"), "not-run-no-pending", "{line}");
    assert_eq!(field(&line, "prev_epoch"), "none", "{line}");
    assert_eq!(field(&line, "epoch"), old_tag, "{line}");

    // After node 0's cutover the old index is the draining previous one.
    nodes[0].node.handle_msg2(held_msg2).await;
    nodes[0].node.check_rekey().await;
    let new_tag = {
        let p0 = nodes[0].node.get_peer(&node1_addr).unwrap();
        assert_eq!(p0.previous_our_index(), Some(old_idx), "node 0 cut over");
        session_tag(p0.noise_session().unwrap())
    };
    assert_ne!(new_tag, old_tag);
    let p1 = nodes[1].node.get_peer_mut(&node0_addr).unwrap();
    let frame = seal(p1.noise_session_mut().unwrap(), old_idx, false);
    let p = arriving(&nodes[0], &nodes[1], corrupt(frame));
    let logs = frame_logged(&mut nodes[0].node, p).await;
    let line = expect_line(&logs, "Decryption failed");
    assert_eq!(field(&line, "slot"), "previous", "{line}");
    assert_eq!(field(&line, "trial"), "not-run-no-pending", "{line}");
    assert_eq!(field(&line, "prev_epoch"), old_tag, "{line}");
    assert_eq!(field(&line, "epoch"), new_tag, "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// After twenty consecutive failures on node 1's pending index, the warning
/// names the pending slot, its tag and how long it has been held.
#[tokio::test]
async fn the_excessive_failures_warning_after_twenty_failures_on_the_pending_index_logs_the_pending_slot()
 {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    nodes[0].node.handle_msg2(held_msg2).await;

    let (logs, guard) = capture_logs_scoped();
    let mut pending_tag = String::new();
    let mut age_window = (0, 0);
    for i in 0..20 {
        let (frame, _, tag) = sealed_by_node0_pending(&mut nodes, &node1_addr, false);
        pending_tag = tag;
        let p = arriving(&nodes[1], &nodes[0], corrupt(frame));
        if i == 19 {
            // Bound the age the 20th failure logs by the age before it and
            // the time it took.
            let before = nodes[1]
                .node
                .get_peer(&node0_addr)
                .unwrap()
                .pending_age()
                .expect("node 1 holds a pending");
            let started = Instant::now();
            nodes[1].node.handle_encrypted_frame(p).await;
            age_window = (before.as_secs(), (before + started.elapsed()).as_secs());
        } else {
            nodes[1].node.handle_encrypted_frame(p).await;
        }
    }
    drop(guard);

    let line = expect_line(&logs, "Excessive decryption failures, peer kept");
    assert!(line.starts_with("WARN"), "{line}");
    assert!(
        nodes[1].node.get_peer(&node0_addr).is_some(),
        "the peer is kept after the 20th failure"
    );
    assert_eq!(field(&line, "slot"), "pending-responder", "{line}");
    assert_eq!(field(&line, "kbit_ours"), "false", "{line}");
    assert_eq!(field(&line, "pending_epoch"), pending_tag, "{line}");
    assert_eq!(field(&line, "since_cutover_ms"), "none", "{line}");
    let age: u64 = field(&line, "pending_age_s").parse().expect("an integer");
    assert!(
        (age_window.0..=age_window.1).contains(&age),
        "pending_age_s {age} outside {age_window:?}: {line}"
    );

    cleanup_nodes(&mut nodes).await;
}

/// A heartbeat from node 1 on its current session for node 0's index
/// `idx`, arriving at node 0, corrupted unless `authentic`.
fn current_frame(
    nodes: &mut [TestNode],
    node0_addr: &NodeAddr,
    idx: SessionIndex,
    authentic: bool,
) -> ReceivedPacket {
    let p1 = nodes[1].node.get_peer_mut(node0_addr).unwrap();
    let frame = seal(p1.noise_session_mut().unwrap(), idx, false);
    let frame = if authentic { frame } else { corrupt(frame) };
    arriving(&nodes[0], &nodes[1], frame)
}

/// Once a run of failures has reached the warning's threshold, the peer is
/// kept and a further failing frame logs no failure line; a frame that
/// authenticates ends the run, and the next failure is logged again.
#[tokio::test]
async fn failure_lines_stop_at_the_threshold_and_resume_after_an_authentic_frame() {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        ..
    } = rekey_pair_with_held_msg2().await;
    let idx = nodes[0]
        .node
        .get_peer(&node1_addr)
        .unwrap()
        .our_index()
        .unwrap();
    let failures = |nodes: &[TestNode]| {
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .expect("the peer is kept")
            .consecutive_decrypt_failures()
    };

    let (logs, guard) = capture_logs_scoped();
    for _ in 0..20 {
        let p = current_frame(&mut nodes, &node0_addr, idx, false);
        nodes[0].node.handle_encrypted_frame(p).await;
    }
    drop(guard);
    assert_eq!(failures(&nodes), 20, "precondition: a run of twenty");
    assert_eq!(
        lines_with(&logs, "Decryption failed").len(),
        20,
        "each of the first twenty failures logs a line"
    );
    assert_eq!(
        lines_with(&logs, "Excessive decryption failures, peer kept").len(),
        1,
        "the warning fires once, at the twentieth"
    );

    let p = current_frame(&mut nodes, &node0_addr, idx, false);
    let logs = frame_logged(&mut nodes[0].node, p).await;
    assert!(
        lines_with(&logs, "Decryption failed").is_empty(),
        "the 21st failure of a run logs no line: {:#?}",
        logs.lines()
    );
    assert_eq!(failures(&nodes), 21, "the 21st failure is still counted");

    let p = current_frame(&mut nodes, &node0_addr, idx, true);
    nodes[0].node.handle_encrypted_frame(p).await;
    assert_eq!(failures(&nodes), 0, "an authentic frame ends the run");

    let p = current_frame(&mut nodes, &node0_addr, idx, false);
    let logs = frame_logged(&mut nodes[0].node, p).await;
    expect_line(&logs, "Decryption failed");

    cleanup_nodes(&mut nodes).await;
}

/// A failure the decrypt worker reports carries the frame's index, where it
/// arrived and which session the index names, and the warning after twenty
/// names the slot.
#[cfg(unix)]
#[tokio::test]
async fn a_worker_decrypt_failure_logs_the_frames_index_and_path() {
    use super::session::{AgedLinkPair, aged_link_pair};
    use crate::node::decrypt_worker::DecryptWorkerPool;
    use crate::node::worker_set::TestWorker;

    let AgedLinkPair {
        mut nodes,
        node1_addr,
        ..
    } = aged_link_pair(
        crate::config::Config::new(),
        crate::config::Config::new(),
        Duration::from_secs(1),
    )
    .await;
    let n0 = &mut nodes[0].node;
    n0.supervisor.decrypt_workers = Some(DecryptWorkerPool::for_test(vec![TestWorker::Run]));
    n0.register_decrypt_worker_session(&node1_addr);
    let mut events = n0.decrypt_fallback_rx.take().expect("the event receiver");
    let idx = n0.get_peer(&node1_addr).unwrap().our_index().unwrap();
    assert!(
        n0.decrypt_registered_sessions.contains(&idx.as_u32()),
        "the current session must be registered with the worker"
    );

    let (logs, guard) = capture_logs_scoped();
    let mut first = None;
    for i in 0..20u64 {
        let p = arriving(&nodes[0], &nodes[1], junk_frame(idx, 1_000_000 + i));
        first.get_or_insert((p.transport_id, p.remote_addr.clone()));
        nodes[0].node.handle_encrypted_frame(p).await;
        let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("the worker reports within 5 s")
            .expect("the worker channel is open");
        nodes[0].node.process_decrypt_worker_event(event).await;
    }
    drop(guard);

    let (tid, from) = first.unwrap();
    let line = expect_line(&logs, "Worker FMP AEAD decryption failed");
    assert_eq!(field(&line, "receiver_idx"), index_text(idx), "{line}");
    assert_eq!(field(&line, "transport_id"), tid.to_string(), "{line}");
    assert_eq!(field(&line, "remote_addr"), from.to_string(), "{line}");
    assert_eq!(field(&line, "slot"), "current", "{line}");
    assert_eq!(field(&line, "kbit_frame"), "false", "{line}");
    assert_eq!(field(&line, "kbit_ours"), "false", "{line}");
    let warn = expect_line(&logs, "Excessive decryption failures, peer kept");
    assert_eq!(field(&warn, "slot"), "current", "{warn}");
    assert!(
        nodes[0].node.get_peer(&node1_addr).is_some(),
        "the peer is kept after the 20th failure"
    );

    // A 21st failure in the same run logs no worker failure line.
    let p = arriving(&nodes[0], &nodes[1], junk_frame(idx, 1_000_020));
    let (logs, guard) = capture_logs_scoped();
    nodes[0].node.handle_encrypted_frame(p).await;
    let event = tokio::time::timeout(Duration::from_secs(5), events.recv())
        .await
        .expect("the worker reports within 5 s")
        .expect("the worker channel is open");
    nodes[0].node.process_decrypt_worker_event(event).await;
    drop(guard);
    assert!(
        lines_with(&logs, "Worker FMP AEAD decryption failed").is_empty(),
        "the 21st failure of a run logs no line: {:#?}",
        logs.lines()
    );

    cleanup_nodes(&mut nodes).await;
}

/// A frame for an index the node never allocated is logged at debug with the
/// address it came from.
#[tokio::test]
async fn an_unknown_index_is_logged_at_debug_with_where_it_came_from() {
    let mut node = make_node();
    let from = TransportAddr::from_string("10.9.8.7:2121");
    let p = ReceivedPacket {
        transport_id: TransportId::new(1),
        remote_addr: from.clone(),
        data: junk_frame(SessionIndex::new(0xDEAD_BEEF), 1),
        timestamp_ms: 1_000,
    };
    let logs = frame_logged(&mut node, p).await;
    let line = expect_line(&logs, "Unknown session index, dropping");
    assert!(line.starts_with("DEBUG"), "{line}");
    assert_eq!(field(&line, "remote_addr"), from.to_string(), "{line}");
    assert_eq!(field(&line, "transport_id"), "transport:1", "{line}");
    assert_eq!(field(&line, "suppressed"), "0", "{line}");
}

/// A flood of unknown-index frames from many sources is logged a bounded
/// number of times, and nothing is stored for it.
#[tokio::test]
async fn a_flood_of_unknown_index_frames_from_many_sources_logs_a_bounded_number_of_lines() {
    const FRAMES: u64 = 10_000;
    // The budget fills when the node is built.
    let start = Instant::now();
    let mut node = make_node();
    let (peers, indices) = (node.peers.len(), node.peers_by_index.len());

    let (logs, guard) = capture_logs_scoped();
    for i in 0..FRAMES {
        let from = TransportAddr::from_string(&format!(
            "10.{}.{}.{}:2121",
            (i >> 16) & 0xff,
            (i >> 8) & 0xff,
            i & 0xff
        ));
        let p = ReceivedPacket {
            transport_id: TransportId::new(1),
            remote_addr: from,
            data: junk_frame(SessionIndex::new(0xDEAD_BEEF), i),
            timestamp_ms: 1_000,
        };
        node.handle_encrypted_frame(p).await;
    }
    drop(guard);
    let elapsed = start.elapsed();

    let lines = lines_with(&logs, "Unknown session index, dropping");
    let n = lines.len() as u64;
    let ceiling = 10 + elapsed.as_secs_f64().ceil() as u64;
    assert!(n >= 10, "the full burst must be logged: {n} lines");
    assert!(
        n <= ceiling,
        "{n} lines in {elapsed:?}, more than {ceiling}"
    );
    let mut withheld = 0;
    for line in &lines {
        assert!(line.starts_with("DEBUG"), "{line}");
        assert!(log_field(line, "remote_addr").is_some(), "{line}");
        withheld += field(line, "suppressed").parse::<u64>().expect("a count");
    }
    assert!(withheld + n <= FRAMES, "{withheld} withheld + {n} logged");
    assert_eq!(node.peers.len(), peers);
    assert_eq!(node.peers_by_index.len(), indices);
}

/// Both ends of one rekey log the same new session's tag on their completion,
/// cutover and promotion lines, each with the K-bit it holds after the change.
#[tokio::test]
async fn both_ends_log_the_same_new_session_tag_and_their_kbit_through_a_rekey() {
    let (logs, guard) = capture_logs_scoped();
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        held_msg2,
        ..
    } = rekey_pair_with_held_msg2().await;
    let old_tag = session_tag(
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .noise_session()
            .unwrap(),
    );
    nodes[0].node.handle_msg2(held_msg2).await;
    nodes[0].node.check_rekey().await;
    nodes[0]
        .node
        .send_encrypted_link_message(&node1_addr, &[LinkMessageType::Heartbeat.to_byte()])
        .await
        .unwrap();
    pump_until_quiet(&mut nodes).await;
    drop(guard);

    let tag0 = session_tag(
        nodes[0]
            .node
            .get_peer(&node1_addr)
            .unwrap()
            .noise_session()
            .unwrap(),
    );
    let tag1 = session_tag(
        nodes[1]
            .node
            .get_peer(&node0_addr)
            .unwrap()
            .noise_session()
            .unwrap(),
    );
    assert_eq!(tag0, tag1, "both ends hold the new session");
    assert_ne!(tag0, old_tag, "the rekey replaced the session");

    let answer = expect_line(&logs, "Sent rekey msg2 response");
    assert_eq!(field(&answer, "kbit_ours"), "false", "{answer}");
    let completed = expect_line(&logs, "Rekey completed (initiator), pending K-bit cutover");
    assert_eq!(field(&completed, "kbit_ours"), "false", "{completed}");
    let cutover = expect_line(&logs, "Rekey cutover complete (initiator), K-bit flipped");
    assert_eq!(field(&cutover, "kbit_ours"), "true", "{cutover}");
    let promoted = expect_line(
        &logs,
        "Peer new-epoch frame authenticated, K-bit flip promoting new session",
    );
    assert_eq!(field(&promoted, "kbit_ours"), "true", "{promoted}");
    assert_eq!(field(&promoted, "kbit_frame"), "true", "{promoted}");
    for line in [&answer, &completed, &cutover, &promoted] {
        assert_eq!(field(line, "epoch"), tag0, "{line}");
    }

    cleanup_nodes(&mut nodes).await;
}

/// Cut node 0 over on its own tick while node 1 stays on the old session.
async fn node0_cut_over() -> HeldMsg2Pair {
    let mut pair = rekey_pair_with_held_msg2().await;
    let held = pair.held_msg2.clone();
    pair.nodes[0].node.handle_msg2(held).await;
    pair.nodes[0].node.check_rekey().await;
    let p0 = pair.nodes[0].node.get_peer(&pair.node1_addr).unwrap();
    assert_eq!(
        p0.previous_our_index(),
        pair.node0_idx_before,
        "node 0 must cut over"
    );
    pair
}

/// Make node 0's peer read as silent since its session start for longer
/// than the default link-dead timeout, then run the heartbeat check with its
/// lines captured.
async fn reap_logged(node: &mut Node, peer: &NodeAddr) -> LogCapture {
    node.get_peer_mut(peer)
        .unwrap()
        .test_backdate_session_start(Duration::from_secs(31));
    let (logs, guard) = capture_logs_scoped();
    node.check_link_heartbeats().await;
    drop(guard);
    assert!(node.get_peer(peer).is_none(), "the peer must be reaped");
    logs
}

/// A link-dead removal after a cutover, while the peer still sends on the
/// old session, says the silence was measured from the session start and
/// that frames did arrive on the previous session.
#[tokio::test]
async fn a_link_dead_removal_after_a_cutover_logs_the_session_start_basis_and_previous_session_frames()
 {
    let HeldMsg2Pair {
        mut nodes,
        node0_addr,
        node1_addr,
        node1_idx_before,
        ..
    } = node0_cut_over().await;

    // node 1, still on the old session, sends heartbeats; only node 0's queue
    // is delivered.
    for _ in 0..3 {
        nodes[1]
            .node
            .send_encrypted_link_message(&node0_addr, &[LinkMessageType::Heartbeat.to_byte()])
            .await
            .unwrap();
    }
    assert_eq!(
        nodes[1].node.get_peer(&node0_addr).unwrap().our_index(),
        node1_idx_before,
        "node 1 must still be on the old session"
    );
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_millis(10)).await;
        process_available_packets(&mut nodes[..1]).await;
    }

    let (link_tid, link_addr) = (nodes[0].transport_id, nodes[1].addr.clone());
    let logs = reap_logged(&mut nodes[0].node, &node1_addr).await;
    let line = expect_line(&logs, "Removing peer: link dead timeout");
    assert_eq!(field(&line, "basis"), "session_start", "{line}");
    let frames: u64 = field(&line, "prev_slot_frames").parse().expect("a count");
    assert!(frames > 0, "{line}");
    field(&line, "since_cutover_ms")
        .parse::<u64>()
        .expect("since_cutover_ms is an integer");
    let age: u64 = field(&line, "basis_age_ms").parse().expect("an integer");
    assert!(age >= 31_000, "{line}");
    assert_eq!(field(&line, "kbit_ours"), "true", "{line}");
    assert_eq!(field(&line, "link_tid"), link_tid.to_string(), "{line}");
    assert_eq!(field(&line, "link_addr"), link_addr.to_string(), "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// Previous-session frames the decrypt worker decrypted and bounced back are
/// counted the same as inline ones.
#[cfg(unix)]
#[tokio::test]
async fn previous_session_frames_bounced_by_the_decrypt_worker_are_counted() {
    use crate::node::decrypt_worker::DecryptFallback;

    let HeldMsg2Pair {
        mut nodes,
        node1_addr,
        node0_idx_before,
        ..
    } = node0_cut_over().await;
    let previous_idx = node0_idx_before.expect("node 0 had an index before the rekey");

    let data = heartbeat_plaintext();
    let bounce = DecryptFallback {
        source_node_addr: node1_addr,
        transport_id: nodes[0].transport_id,
        remote_addr: nodes[1].addr.clone(),
        timestamp_ms: Node::now_ms(),
        packet_len: data.len() + 32,
        receiver_idx: previous_idx.as_u32(),
        fmp_counter: 900,
        fmp_flags: 0,
        fmp_plaintext_len: data.len(),
        packet_data: data,
        fmp_plaintext_offset: 0,
    };
    nodes[0].node.process_decrypt_fallback(bounce).await;

    let logs = reap_logged(&mut nodes[0].node, &node1_addr).await;
    let line = expect_line(&logs, "Removing peer: link dead timeout");
    assert_eq!(field(&line, "prev_slot_frames"), "1", "{line}");

    cleanup_nodes(&mut nodes).await;
}

/// A link-dead removal of a peer that never rekeyed measures its silence
/// from the last received frame.
#[tokio::test]
async fn a_link_dead_removal_of_a_peer_that_never_rekeyed_logs_the_last_receive_basis() {
    let mut nodes = run_tree_test(2, &[(0, 1)], false).await;
    verify_tree_convergence(&nodes);
    let addr_1 = *nodes[1].node.node_addr();
    assert!(
        nodes[0]
            .node
            .get_peer(&addr_1)
            .and_then(|p| p.mmp())
            .and_then(|m| m.receiver.last_recv_ms())
            .is_some(),
        "node 0 must have received a frame from node 1 during convergence"
    );
    set_link_dead_timeout(&mut nodes[0].node, 0);

    let (logs, guard) = capture_logs_scoped();
    nodes[0].node.check_link_heartbeats().await;
    drop(guard);

    let line = expect_line(&logs, "Removing peer: link dead timeout");
    assert_eq!(field(&line, "basis"), "last_recv", "{line}");
    assert_eq!(field(&line, "since_cutover_ms"), "none", "{line}");
    assert_eq!(field(&line, "prev_slot_frames"), "0", "{line}");
    assert_eq!(field(&line, "kbit_ours"), "false", "{line}");

    cleanup_nodes(&mut nodes).await;
}
