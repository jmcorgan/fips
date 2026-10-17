//! Unit tests for `SessionEntry` (`mod.rs`): trial decryption across the
//! current, pending and previous key slots, the cutover to a new session,
//! msg3 retransmission, and how long the previous session is kept draining.

use super::*;
use crate::noise::HandshakeState;
use crate::proto::fsp::wire::{FSP_FLAG_K, build_fsp_header};
use secp256k1::{Keypair, Secp256k1, SecretKey};

/// A duration of `ms` milliseconds.
fn ms(ms: u64) -> Duration {
    Duration::from_millis(ms)
}

/// Deterministic keypair from a single seed byte.
fn keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let mut bytes = [1u8; 32];
    bytes[0] = seed;
    let sk = SecretKey::from_slice(&bytes).expect("valid secret key");
    Keypair::from_secret_key(&secp, &sk)
}

/// Run a full XK handshake and return `(initiator_session,
/// responder_session)` — a paired sender/receiver.
fn xk_pair(init_seed: u8, resp_seed: u8) -> (NoiseSession, NoiseSession) {
    let init_kp = keypair(init_seed);
    let resp_kp = keypair(resp_seed);
    let mut initiator = HandshakeState::new_xk_initiator(init_kp, resp_kp.public_key());
    initiator.set_local_epoch([0xA1, 0xB2, 0xC3, 0xD4, 0x11, 0x22, 0x33, 0x44]);
    let mut responder = HandshakeState::new_xk_responder(resp_kp);
    responder.set_local_epoch([0xD4, 0xC3, 0xB2, 0xA1, 0x44, 0x33, 0x22, 0x11]);

    let msg1 = initiator.write_xk_message_1().unwrap();
    responder.read_xk_message_1(&msg1).unwrap();
    let msg2 = responder.write_xk_message_2().unwrap();
    initiator.read_xk_message_2(&msg2).unwrap();
    let msg3 = initiator.write_xk_message_3().unwrap();
    responder.read_xk_message_3(&msg3).unwrap();

    (
        initiator.into_session().unwrap(),
        responder.into_session().unwrap(),
    )
}

/// Seal an FSP frame: returns `(ciphertext, counter, header_bytes,
/// k_bit)` exactly as the send path produces them.
fn seal(sender: &mut NoiseSession, plaintext: &[u8], k_bit: bool) -> (Vec<u8>, u64, [u8; 12]) {
    let counter = sender.current_send_counter();
    let flags = if k_bit { FSP_FLAG_K } else { 0 };
    let header = build_fsp_header(counter, flags, plaintext.len() as u16);
    let ciphertext = sender.encrypt_with_aad(plaintext, &header).unwrap();
    (ciphertext, counter, header)
}

/// Build a `SessionEntry` whose `current` slot is `session`.
fn entry_with_current(session: NoiseSession) -> SessionEntry {
    let addr = NodeAddr::from_bytes([7u8; 16]);
    let pubkey = keypair(99).public_key();
    let mut entry = SessionEntry::new(
        addr,
        pubkey,
        EndToEndState::Established(session),
        session_at(1_000),
        true,
    );
    entry.mark_established(session_at(1_000));
    entry
}

// 1. A frame sealed in `current` decrypts against `current`; the
//    `pending` and `previous` windows are left untouched.
#[test]
fn trial_decrypt_picks_current() {
    let (mut cur_send, cur_recv) = xk_pair(1, 2);
    let (_p_send, p_recv) = xk_pair(3, 4);
    let (_o_send, o_recv) = xk_pair(5, 6);

    let mut entry = entry_with_current(cur_recv);
    entry.set_pending_session(p_recv);
    entry.set_previous_session_for_test(o_recv, session_at(1_000));

    let (ct, counter, hdr) = seal(&mut cur_send, b"steady-state", false);
    let (pt, slot) = entry
        .fsp_trial_decrypt(&ct, counter, &hdr, false, session_at(2_000))
        .expect("current frame must decrypt");

    assert_eq!(pt, b"steady-state");
    assert_eq!(slot, EpochSlot::Current);
    assert_eq!(entry.pending_highest_counter(), Some(0));
    assert_eq!(entry.previous_highest_counter(), Some(0));
}

// 2. A frame sealed in `pending` decrypts via the cascade and the
//    entry promotes pending -> current, current -> previous, K-bit
//    flips.
#[test]
fn trial_decrypt_picks_pending_and_promotes() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(p_recv);

    // Peer sealed in the new epoch with the flipped K-bit.
    let (ct, counter, hdr) = seal(&mut p_send, b"new-epoch", !k_before);
    let (pt, slot) = entry
        .fsp_trial_decrypt(&ct, counter, &hdr, !k_before, session_at(2_000))
        .expect("pending frame must decrypt");
    assert_eq!(pt, b"new-epoch");
    assert_eq!(slot, EpochSlot::Pending);

    // Receive path promotes on a pending hit.
    entry.handle_peer_kbit_flip(session_at(2_000));
    assert!(entry.pending_new_session().is_none());
    assert!(entry.previous_highest_counter().is_some());
    assert_ne!(entry.current_k_bit(), k_before);
}

// 3. After cutover, an old-epoch frame decrypts against `previous`
//    with no state change.
#[test]
fn trial_decrypt_picks_previous_during_drain() {
    let (mut old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);

    // Start with the old session, install the new as pending, cut over.
    let mut entry = entry_with_current(new_recv);
    entry.set_previous_session_for_test(old_recv, session_at(1_500));
    let k_after = entry.current_k_bit();

    // Old-epoch straggler still in flight after our cutover.
    let (ct, counter, hdr) = seal(&mut old_send, b"old-straggler", !k_after);
    let (pt, slot) = entry
        .fsp_trial_decrypt(&ct, counter, &hdr, !k_after, session_at(3_000))
        .expect("previous frame must decrypt");

    assert_eq!(pt, b"old-straggler");
    assert_eq!(slot, EpochSlot::Previous);
    // No promotion, no K-bit change.
    assert_eq!(entry.current_k_bit(), k_after);
    assert!(entry.is_draining());
}

// 4. After a pending-driven promotion, an old-epoch straggler still
//    decrypts (against the now-`previous` slot) — the reordering
//    case that broke attempt 1.
#[test]
fn trial_decrypt_reordered_old_after_cutover() {
    let (mut cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(p_recv);

    // New-epoch frame promotes the entry.
    let (ct_new, c_new, hdr_new) = seal(&mut p_send, b"after-cutover", !k_before);
    let (_pt, slot) = entry
        .fsp_trial_decrypt(&ct_new, c_new, &hdr_new, !k_before, session_at(2_000))
        .unwrap();
    assert_eq!(slot, EpochSlot::Pending);
    entry.handle_peer_kbit_flip(session_at(2_000));

    // Now an OLD-epoch straggler arrives reordered after cutover.
    let (ct_old, c_old, hdr_old) = seal(&mut cur_send, b"reordered-old", k_before);
    let (pt, slot) = entry
        .fsp_trial_decrypt(&ct_old, c_old, &hdr_old, k_before, session_at(2_500))
        .expect("reordered old-epoch frame must still decrypt");
    assert_eq!(pt, b"reordered-old");
    assert_eq!(slot, EpochSlot::Previous);
}

// 5. A genuine replay of a `current`-epoch counter is rejected (all
//    slots fail) and does not corrupt the other windows; a `current`
//    replay while `pending` holds the real key still authenticates
//    against `pending`.
#[test]
fn trial_decrypt_replay_is_per_slot() {
    let (mut cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(p_recv);

    // First delivery on `current`.
    let (ct, counter, hdr) = seal(&mut cur_send, b"first", k_before);
    let (_pt, slot) = entry
        .fsp_trial_decrypt(&ct, counter, &hdr, k_before, session_at(2_000))
        .unwrap();
    assert_eq!(slot, EpochSlot::Current);

    // Replaying the exact same `current` frame: all slots fail.
    assert!(
        entry
            .fsp_trial_decrypt(&ct, counter, &hdr, k_before, session_at(2_100))
            .is_none(),
        "a genuine replay must be rejected by every slot"
    );
    // The pending window must not have been corrupted by the failed
    // trials.
    assert_eq!(entry.pending_highest_counter(), Some(0));

    // A pending-epoch frame sharing counter 0 with `current` (whose
    // counter 0 is already consumed) still authenticates against
    // `pending`.
    let (ct_p, c_p, hdr_p) = seal(&mut p_send, b"pending-c0", !k_before);
    assert_eq!(c_p, 0);
    let (pt, slot) = entry
        .fsp_trial_decrypt(&ct_p, c_p, &hdr_p, !k_before, session_at(2_200))
        .expect("pending frame must decrypt despite current replay overlap");
    assert_eq!(pt, b"pending-c0");
    assert_eq!(slot, EpochSlot::Pending);
}

// 6. A failed trial against a non-winning slot leaves that slot's
//    ReplayWindow::highest() unchanged (the section-4 invariant).
#[test]
fn trial_decrypt_failed_slot_leaves_replay_window_intact() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);
    let (_o_send, o_recv) = xk_pair(5, 6);

    let mut entry = entry_with_current(cur_recv);
    let k_before = entry.current_k_bit();
    entry.set_pending_session(p_recv);
    entry.set_previous_session_for_test(o_recv, session_at(1_000));

    // Advance the pending sender so its frame carries a non-zero
    // counter — the cascade will still try (and fail) `current` and
    // `previous` first.
    for _ in 0..4 {
        let _ = seal(&mut p_send, b"warmup", !k_before);
    }
    let (ct, counter, hdr) = seal(&mut p_send, b"pending-hit", !k_before);
    assert_eq!(counter, 4);

    let (_pt, slot) = entry
        .fsp_trial_decrypt(&ct, counter, &hdr, false, session_at(2_000)) // hint says "current first"
        .expect("pending frame must decrypt");
    assert_eq!(slot, EpochSlot::Pending);

    // current and previous were tried and failed: their windows must
    // be untouched (highest still 0).
    assert_eq!(entry.current_highest_counter(), Some(0));
    assert_eq!(entry.previous_highest_counter(), Some(0));
    // Only the winning slot advanced.
    assert_eq!(entry.pending_highest_counter(), Some(4));
}

// 7. The retained msg3 payload is cleared once a peer frame
//    authenticates against `pending`/new-`current`, not at the
//    initiator's own cutover.
#[test]
fn msg3_retransmit_stops_on_peer_new_epoch_confirmed() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (mut p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    entry.set_pending_session(p_recv);
    entry.set_rekey_completed(session_at(1_000));
    entry.set_rekey_msg3_payload(vec![0xAB; 73], session_at(1_500));

    // The initiator's own liveness-timer cutover must NOT clear the
    // retained msg3 payload — the responder may not have it yet.
    assert!(entry.cutover_to_new_session(session_at(2_000)));
    assert!(
        entry.rekey_msg3_payload().is_some(),
        "cutover alone must not stop msg3 retransmission"
    );
    assert!(!entry.peer_new_epoch_confirmed());

    // A peer frame authenticated against the post-cutover `current`
    // (new epoch) confirms the responder and clears the payload.
    let (ct, counter, hdr) = seal(&mut p_send, b"peer-on-new-epoch", entry.current_k_bit());
    let k_now = entry.current_k_bit();
    let (_pt, slot) = entry
        .fsp_trial_decrypt(&ct, counter, &hdr, k_now, session_at(2_500))
        .unwrap();
    assert_eq!(slot, EpochSlot::Current);
    // Receive-path logic: current hit + retained payload + no pending
    // => responder confirmed.
    assert!(entry.rekey_msg3_payload().is_some() && entry.pending_new_session().is_none());
    entry.confirm_peer_new_epoch();
    assert!(entry.peer_new_epoch_confirmed());
    assert!(entry.rekey_msg3_payload().is_none());
}

// 8. After exhausting the retransmission budget, abandon_rekey runs
//    and the entry is a clean Established with no pending.
#[test]
fn msg3_retransmit_budget_exhaustion_abandons_cleanly() {
    let (_cur_send, cur_recv) = xk_pair(1, 2);
    let (_p_send, p_recv) = xk_pair(3, 4);

    let mut entry = entry_with_current(cur_recv);
    entry.set_pending_session(p_recv);
    entry.set_rekey_completed(session_at(1_000));
    entry.set_rekey_msg3_payload(vec![0xCD; 73], session_at(1_500));

    // Simulate the resend driver exhausting its budget.
    let max_resends = 8;
    for i in 0..max_resends {
        entry.record_rekey_msg3_resend(session_at(2_000 + i as u64 * 100));
    }
    assert_eq!(entry.rekey_msg3_resend_count(), max_resends);

    // Budget exhausted -> abandon.
    entry.abandon_rekey();
    assert!(entry.rekey_msg3_payload().is_none());
    assert!(entry.pending_new_session().is_none());
    assert!(!entry.has_rekey_in_progress());
    assert!(entry.is_established());
    assert!(!entry.peer_new_epoch_confirmed());
}

// 9. The initiator cuts over on its timer while the responder has
//    not; both directions still decrypt (overlapping epochs).
//
// Naming: in each `xk_pair` the `.0` session is node A's view and
// `.1` is node B's view; they seal frames the other one decrypts. A
// is the rekey initiator, B the responder.
#[test]
fn initiator_cutover_safe_before_responder() {
    // Pre-rekey ("old") epoch and post-rekey ("new") epoch pairs.
    let (old_a, old_b) = xk_pair(1, 2);
    let (new_a, mut new_b) = xk_pair(3, 4);

    // Node A (initiator): current = old_a, pending = new_a, retains a
    // msg3 payload, then cuts over on its own liveness timer before
    // the responder has received msg3.
    let mut a = entry_with_current(old_a);
    a.set_rekey_completed(session_at(1_000));
    a.set_rekey_msg3_payload(vec![0xEE; 73], session_at(1_500));
    a.set_pending_session(new_a);
    assert!(a.cutover_to_new_session(session_at(2_000)));
    // A now: current = new_a, previous = old_a, K-bit flipped, msg3
    // payload still retained (responder not yet confirmed).
    assert!(a.rekey_msg3_payload().is_some());

    // Node B (responder): still entirely on the old epoch — no
    // pending, msg3 not yet received. B's `current` slot is `old_b`.
    let mut b = entry_with_current(old_b);

    // A -> B sealed in the NEW epoch (B has no pending slot yet).
    // This is the one residual liveness-bounded drop, closed by msg3
    // retransmission. Confirm it is a clean drop, not a panic.
    let (ct_new, c_new, hdr_new) = seal(&mut new_b, b"new-from-a", true);
    assert!(
        b.fsp_trial_decrypt(&ct_new, c_new, &hdr_new, true, session_at(2_100))
            .is_none(),
        "responder without msg3 drops the new-epoch frame cleanly"
    );

    // B -> A still sealed in the OLD epoch (B seals from its own
    // `current` slot). A kept the old session as `previous`, so it
    // decrypts fine despite the cutover skew.
    let (ct_old, c_old, hdr_old) = {
        let b_old = b.current_noise_session_mut().unwrap();
        seal(b_old, b"old-from-b", false)
    };
    let (pt, slot) = a
        .fsp_trial_decrypt(&ct_old, c_old, &hdr_old, false, session_at(2_200))
        .expect("initiator must still decrypt the responder's old-epoch frame");
    assert_eq!(pt, b"old-from-b");
    assert_eq!(slot, EpochSlot::Previous);

    // Once B receives msg3 it derives the new session as pending; A's
    // new-epoch frames then decrypt and drive B's promotion.
    let (new_a2, mut new_b2) = xk_pair(3, 4);
    b.set_pending_session(new_a2);
    let (ct_new2, c_new2, hdr_new2) = seal(&mut new_b2, b"new-from-a-2", true);
    let (pt, slot) = b
        .fsp_trial_decrypt(&ct_new2, c_new2, &hdr_new2, true, session_at(2_300))
        .expect("responder must decrypt new-epoch frame once pending is installed");
    assert_eq!(pt, b"new-from-a-2");
    assert_eq!(slot, EpochSlot::Pending);
}

// 10. Drain-window expiry is peer-progress-aware (the rep-003
//     scenario). After the initiator cuts over, a responder that
//     never received msg3 keeps transmitting on the OLD epoch. The
//     `previous` slot must NOT be retired while those old-epoch
//     frames keep decrypting — even well past the 10 s fixed
//     window — and must be retired once the peer finally goes
//     silent on the old epoch.
#[test]
fn drain_expiry_is_peer_progress_aware() {
    const DRAIN_MS: u64 = 10_000;
    // Well clear of the shipped ceiling, so this case still exercises
    // the sliding deadline and nothing else.
    const MAX_MS: u64 = 120_000;
    let cutover_ms = 1_000;

    // Build the post-cutover state via the production cutover path:
    // start with the old session as `current`, the new session as
    // `pending`, then cut over so `current` = new epoch, `previous`
    // = old epoch, and the drain clock is stamped at the cutover.
    let (mut old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(old_recv);
    entry.set_pending_session(new_recv);
    assert!(entry.cutover_to_new_session(session_at(cutover_ms)));
    assert!(entry.is_draining());

    // The peer (responder) is still on the OLD epoch — it never
    // received msg3. Each old-epoch frame must decrypt against
    // `previous` and push the drain deadline out. Deliver frames at
    // t = 5s, 15s, 25s — the latter two are well past the fixed
    // 10 s window measured from the cutover at t=1s.
    let k_old = !entry.current_k_bit();
    for &t in &[5_000u64, 15_000, 25_000] {
        let (ct, counter, hdr) = seal(&mut old_send, b"still-old-epoch", k_old);
        let (_pt, slot) = entry
            .fsp_trial_decrypt(&ct, counter, &hdr, k_old, session_at(t))
            .expect("old-epoch frame must still decrypt while peer uses it");
        assert_eq!(slot, EpochSlot::Previous);
        // Even though `now - drain_started_ms` exceeds DRAIN_MS, the
        // window is NOT expired: the peer just used `previous`.
        assert!(
            !entry.drain_expired(session_at(t), ms(DRAIN_MS), ms(MAX_MS)),
            "previous slot must not be retired while peer keeps using it (t={t})"
        );
        assert!(
            entry.previous_highest_counter().is_some(),
            "previous slot must remain live (t={t})"
        );
    }

    // The peer cuts over (or dies): no more old-epoch frames. The
    // last `previous`-slot use was at t=25_000; the window now
    // elapses DRAIN_MS after that, NOT DRAIN_MS after the cutover.
    assert!(
        !entry.drain_expired(session_at(34_999), ms(DRAIN_MS), ms(MAX_MS)),
        "window must not expire before DRAIN_MS past the last previous use"
    );
    assert!(
        entry.drain_expired(session_at(35_000), ms(DRAIN_MS), ms(MAX_MS)),
        "window must expire DRAIN_MS after the last previous-slot decrypt"
    );

    // Once expired, complete_drain retires the previous slot.
    entry.complete_drain();
    assert!(entry.previous_highest_counter().is_none());
    assert!(!entry.is_draining());
}

// 11. Absent any peer traffic on the old epoch, drain expiry still
//     fires on the plain wall-clock window measured from the
//     cutover — the peer-progress refinement must not delay
//     retirement when the peer cut over cleanly (no `previous`-slot
//     use at all).
#[test]
fn drain_expiry_unaffected_when_peer_off_old_epoch() {
    const DRAIN_MS: u64 = 10_000;
    const MAX_MS: u64 = 120_000;
    let cutover_ms = 1_000;

    let (_old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(old_recv);
    entry.set_pending_session(new_recv);
    assert!(entry.cutover_to_new_session(session_at(cutover_ms)));

    // No old-epoch frames ever arrive: `previous_last_used_ms` stays
    // 0, the deadline anchor is the cutover time.
    assert!(
        !entry.drain_expired(
            session_at(cutover_ms + DRAIN_MS - 1),
            ms(DRAIN_MS),
            ms(MAX_MS)
        ),
        "window must not expire early"
    );
    assert!(
        entry.drain_expired(session_at(cutover_ms + DRAIN_MS), ms(DRAIN_MS), ms(MAX_MS)),
        "window must expire on the plain wall-clock timer when peer is off the old epoch"
    );
}

// The retention ceiling the drain cap added. The five rekey-policy
// characterization tests that sat here on `maint` are not carried: they
// pinned `check_session_rekey`'s boundaries before the `Fsp::poll_rekey`
// hoist, and the hoisted predicate has its own tests in
// `core/src/proto/fsp/tests/core.rs`.

// 12. A peer that keeps exercising the old epoch delays erasure by a
//     bounded amount rather than preventing it. The refreshes must
//     continue past the ceiling: a case that stops refreshing at the
//     boundary passes without the ceiling and proves nothing.
#[test]
fn drain_retention_is_capped_against_a_peer_pinning_the_old_epoch() {
    const DRAIN_MS: u64 = 10_000;
    const MAX_MS: u64 = 120_000;

    let (_old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(old_recv);
    entry.set_pending_session(new_recv);
    assert!(entry.cutover_to_new_session(session_at(1)));

    // One old-epoch frame every half window, which is what a peer
    // pinning the drain deadline actually does.
    let mut t = 1u64;
    while t < MAX_MS {
        entry.refresh_previous_use(session_at(t));
        assert!(
            !entry.drain_expired(session_at(t), ms(DRAIN_MS), ms(MAX_MS)),
            "ceiling fired before the peer's grace ran out (t={t})"
        );
        t += DRAIN_MS / 2;
    }

    // Still refreshing, so the sliding deadline is nowhere near due.
    entry.refresh_previous_use(session_at(MAX_MS + 1));
    assert!(
        entry.drain_expired(session_at(MAX_MS + 1), ms(DRAIN_MS), ms(MAX_MS)),
        "a peer pinning the old epoch retained the retired key past the ceiling"
    );
}

// 13. The ceiling must not shorten the grace the sliding deadline
//     exists to give a peer that lost msg3 and is still catching up.
#[test]
fn drain_retention_cap_does_not_shorten_the_ordinary_grace() {
    const DRAIN_MS: u64 = 10_000;
    const MAX_MS: u64 = 120_000;
    const CUTOVER_MS: u64 = 1_000;

    let (_old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(old_recv);
    entry.set_pending_session(new_recv);
    assert!(entry.cutover_to_new_session(session_at(CUTOVER_MS)));
    assert!(entry.is_draining());

    // A peer that lost msg3 and is still catching up sends one
    // old-epoch frame part-way through the window.
    let last_use = CUTOVER_MS + DRAIN_MS / 2;
    entry.refresh_previous_use(session_at(last_use));
    assert!(!entry.drain_expired(session_at(CUTOVER_MS + DRAIN_MS), ms(DRAIN_MS), ms(MAX_MS)));
    assert!(!entry.drain_expired(
        session_at(last_use + DRAIN_MS - 1),
        ms(DRAIN_MS),
        ms(MAX_MS)
    ));
    assert!(entry.drain_expired(session_at(last_use + DRAIN_MS), ms(DRAIN_MS), ms(MAX_MS)));
}

// 14. The shipped ceiling has to clear the worst-case legitimate
//     recovery of a peer that lost msg3: the msg3 resend ladder, the
//     responder's handshake timeout, and the rekey dampening window
//     before it may re-initiate. A later tightening of the ceiling
//     reds this rather than silently amputating that recovery.
#[test]
fn drain_retention_cap_clears_the_msg3_recovery_budget() {
    const DRAIN_MS: u64 = 10_000;
    // 31 s resend ladder + 30 s handshake timeout + 30 s dampening.
    const RECOVERY_MS: u64 = 91_000;
    const CUTOVER_MS: u64 = 1_000;
    let max_ms = crate::node::handlers::rekey::drain_max_retention_ms(
        &crate::config::RateLimitConfig::default(),
    );

    let (_old_send, old_recv) = xk_pair(1, 2);
    let (_new_send, new_recv) = xk_pair(3, 4);
    let mut entry = entry_with_current(old_recv);
    entry.set_pending_session(new_recv);
    assert!(entry.cutover_to_new_session(session_at(CUTOVER_MS)));
    assert!(entry.is_draining());

    entry.refresh_previous_use(session_at(CUTOVER_MS + RECOVERY_MS));
    assert!(
        !entry.drain_expired(
            session_at(CUTOVER_MS + RECOVERY_MS),
            ms(DRAIN_MS),
            ms(max_ms)
        ),
        "ceiling fires inside the msg3 recovery budget"
    );
}
