//! Unit tests for `SessionEntry` (`mod.rs`): what the entry keeps per key
//! epoch (the MMP spin state, the inner-header timestamps) across the
//! cutovers its rekey machine makes, and the parameters that machine is
//! built with.

use super::*;
use crate::noise::{HandshakeState, NoiseSession};
use crate::proto::fsp::wire::{FSP_FLAG_K, build_fsp_header};
use fips_core::proto::rekey::Slot;
use secp256k1::{Keypair, Secp256k1, SecretKey};

/// The DataPacket message type, for frames sealed through the entry.
const DATA: u8 = crate::proto::fsp::SessionMessageType::DataPacket as u8;

/// Deterministic keypair from a single seed byte.
fn keypair(seed: u8) -> Keypair {
    let secp = Secp256k1::new();
    let mut bytes = [1u8; 32];
    bytes[0] = seed;
    let sk = SecretKey::from_slice(&bytes).expect("valid secret key");
    Keypair::from_secret_key(&secp, &sk)
}

/// Run a full XK handshake and return `(initiator_session,
/// responder_session)` — a paired sender/receiver. Every call makes fresh
/// ephemerals, so two calls with the same seeds give two key epochs of one
/// pair of peers, which is what the epochs of one session are.
fn xk_pair(init_seed: u8, resp_seed: u8) -> (NoiseSession, NoiseSession) {
    let init_kp = keypair(init_seed);
    let resp_kp = keypair(resp_seed);
    let mut initiator = HandshakeState::new_xk_initiator(init_kp, resp_kp.public_key());
    initiator.set_local_epoch(TEST_PEER_EPOCH);
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
    entry_as(session, true)
}

/// This node's keys as a machine call borrows them: the responder side of
/// [`xk_pair`], whose static a peer's rekey setup is written to.
fn local() -> NodeKeys {
    NodeKeys::new(keypair(2), [0; 8])
}

/// The coordinates every handshake message in these tests carries.
fn coords() -> TreeCoordinate {
    TreeCoordinate::root(NodeAddr::from_bytes([7u8; 16]))
}

/// The peer's rekey of `entry`'s session, through the machine at `now`: its
/// setup is held and acknowledged, and its msg3 completes it. Returns the
/// peer's side of the new epoch.
fn answer_peer_rekey(entry: &mut SessionEntry, now: SessionInstant) -> NoiseSession {
    let mut peer = HandshakeState::new_xk_initiator(keypair(1), keypair(2).public_key());
    peer.set_local_epoch(TEST_PEER_EPOCH);
    let msg1 = peer.write_xk_message_1().unwrap();
    let ack = sent(entry.step_setup(
        &msg1,
        NodeAddr::from_bytes([7u8; 16]),
        coords(),
        now,
        &local(),
    ))
    .expect("the setup is held and acknowledged");
    peer.read_xk_message_2(&ack).unwrap();
    let msg3 = peer.write_xk_message_3().unwrap();
    let out = entry.step_final(&msg3, now, &local());
    assert!(
        out.iter().any(|o| matches!(o, Output::Installed { .. })),
        "the msg3 completes the held setup: {out:?}"
    );
    peer.into_session().unwrap()
}

/// This node's own rekey of `entry`'s session, started by a poll at `now`
/// and answered by the peer at `done`. Returns the peer's side of the new
/// epoch.
fn own_rekey(entry: &mut SessionEntry, now: SessionInstant, done: SessionInstant) -> NoiseSession {
    let msg1 = sent(entry.poll_rekey(now, true, &local())).expect("the trigger starts a rekey");
    let mut peer = HandshakeState::new_xk_responder(keypair(1));
    peer.set_local_epoch(TEST_PEER_EPOCH);
    peer.read_xk_message_1(&msg1).unwrap();
    let ack = peer.write_xk_message_2().unwrap();
    let msg3 = sent(entry.step_reply(&ack, coords(), done, &local())).expect("msg3 is sent");
    peer.read_xk_message_3(&msg3).unwrap();
    peer.into_session().unwrap()
}

/// The handshake message among `out`'s sends, if any.
fn sent(out: SessionOutputs) -> Option<Vec<u8>> {
    out.into_iter().find_map(|o| match o {
        Output::Send { msg, .. } => Some(msg),
        _ => None,
    })
}

/// Build a `SessionEntry` whose `current` slot is `session`, made by a
/// first handshake this node started when `initiator` is set.
fn entry_as(session: NoiseSession, initiator: bool) -> SessionEntry {
    let addr = NodeAddr::from_bytes([7u8; 16]);
    SessionEntry::keyed(addr, session, session_at(1_000), initiator)
}

/// Open a frame `sender` seals on `entry` at `now`, as the receive path
/// does, and return the slot and the tag of the epoch it opened under.
fn open_tagged(
    entry: &mut SessionEntry,
    sender: &mut NoiseSession,
    k: bool,
    now: SessionInstant,
) -> (Slot, EpochTag) {
    let (ct, counter, hdr) = seal(sender, b"a frame", k);
    let mut frame = hdr.to_vec();
    frame.extend_from_slice(&ct);
    entry
        .step_frame(&mut frame, hdr.len(), counter, k, now, &local())
        .into_iter()
        .find_map(|o| match o {
            Output::Deliver { slot, tag, .. } => Some((slot, tag)),
            _ => None,
        })
        .expect("a held epoch opens and delivers the frame")
}

// The MMP spin state belongs to the epoch it measures. A cutover starts it
// again, so a spin responder reflects the new epoch's frames although their
// counters are below the old epoch's highest, and the retired epoch's frames
// no longer reach it.
#[test]
fn spin_state_is_per_epoch() {
    let (mut old_send, old_recv) = xk_pair(1, 2);
    let mut entry = entry_as(old_recv, false);
    entry.init_mmp(&SessionMmpConfig::default());

    // Old-epoch frames 0 to 5, each spin bit set: the responder reflects it
    // and remembers counter 5.
    let mut old_tag = None;
    for counter in 0..6u64 {
        let (slot, tag) = open_tagged(&mut entry, &mut old_send, false, session_at(1_100));
        assert_eq!(slot, Slot::Current);
        let mmp = entry
            .epoch_mmp(tag)
            .expect("MMP measures the current epoch");
        mmp.spin_bit.rx_observe(true, counter, 0);
        old_tag = Some(tag);
    }
    let old_tag = old_tag.unwrap();
    assert!(
        sent_spin(&mut entry, &mut old_send, session_at(1_200)),
        "the responder reflects the old epoch's spin bit"
    );

    // The peer's rekey completes here (this node answered it), and the
    // responder cuts over at once.
    let mut new_send = answer_peer_rekey(&mut entry, session_at(2_000));

    // A frame the peer sealed under the retired epoch is delivered but
    // reaches no MMP state.
    let (slot, tag) = open_tagged(&mut entry, &mut old_send, false, session_at(2_100));
    assert_eq!((slot, tag), (Slot::Previous, old_tag));
    assert!(
        entry.epoch_mmp(old_tag).is_none(),
        "a retired epoch's frame must not reach the new epoch's MMP state"
    );

    // The new epoch's frames 0 and 1, spin bit clear, are reflected.
    for counter in 0..2u64 {
        let (slot, tag) = open_tagged(&mut entry, &mut new_send, true, session_at(2_200));
        assert_eq!(slot, Slot::Current);
        let mmp = entry.epoch_mmp(tag).expect("MMP measures the new epoch");
        mmp.spin_bit.rx_observe(false, counter, 0);
    }
    assert!(
        !sent_spin(&mut entry, &mut new_send, session_at(2_300)),
        "the responder must reflect the new epoch's spin bit, not the old epoch's"
    );
}

/// The spin bit of a message `entry` seals at `now`, as its peer `peer`
/// reads it.
fn sent_spin(entry: &mut SessionEntry, peer: &mut NoiseSession, now: SessionInstant) -> bool {
    let frame = entry
        .seal_frame(now, 0, DATA, b"reply")
        .expect("the entry seals under its current epoch");
    let plaintext = peer
        .decrypt_with_replay_check_and_aad(&frame.ciphertext, frame.counter, &frame.header)
        .expect("the peer opens the frame");
    let (_, _, inner_flags, _) = crate::proto::fsp::wire::fsp_strip_inner_header(&plaintext)
        .expect("a sealed message carries its inner header");
    FspInnerFlags::from_byte(inner_flags).spin_bit
}

// A rekey initiator's inner-header timestamps under the new keys count from
// its completion and keep counting through its cutover, so they never step
// back at the peer; a responder's count from its cutover. The rekey age
// counts from the cutover either way.
#[test]
fn an_initiators_timestamps_count_from_its_rekey_completion_and_a_responders_from_its_cutover() {
    // Past the time trigger at any jitter, which starts the own rekey.
    const T: u64 = 140_000;
    for (initiator, since) in [(true, T + 5_000), (false, T + 7_000)] {
        let (_cur_send, cur_recv) = xk_pair(1, 2);
        let mut entry = entry_with_current(cur_recv);
        if initiator {
            // The rekey completes at 5 s; the peer's first frame under the
            // new keys, at 7 s, is the cutover.
            let mut new_send = own_rekey(&mut entry, session_at(T), session_at(T + 5_000));
            let (slot, _) = open_tagged(&mut entry, &mut new_send, true, session_at(T + 7_000));
            assert_eq!(slot, Slot::Current, "the pending epoch's frame cut over");
        } else {
            // The peer's msg3 completes the rekey at 7 s, and the responder
            // cuts over at once.
            let _ = answer_peer_rekey(&mut entry, session_at(T + 7_000));
        }
        assert_eq!(entry.session_start(), Some(session_at(T + 7_000)));
        assert_eq!(
            entry.session_timestamp(session_at(T + 8_000)),
            (T + 8_000 - since) as u32,
            "initiator {initiator}: timestamps count from {since} ms"
        );
        let frame = entry
            .seal_frame(session_at(T + 8_000), 0, DATA, b"x")
            .expect("the entry seals under its new epoch");
        assert_eq!(frame.timestamp, (T + 8_000 - since) as u32);
    }
}

/// The node's handshake timeout reaches the session rekey machine at any
/// length, a long one included (the pending hold is raised to outlast its
/// confirmation window), and so do its rekey thresholds, down to the
/// smallest interval the configuration accepts and with the largest values
/// taken as the largest the machine accepts. Only timers the machine cannot
/// take at all fall back to the session defaults, and the thresholds still
/// reach it.
#[test]
fn session_params_take_the_configured_timers_and_thresholds_and_fall_back_only_when_they_cannot_fit()
 {
    let mut node = crate::config::NodeConfig::default();
    for secs in [30, 118, 119, 120, 300] {
        node.rate_limit.handshake_timeout_secs = secs;
        let params = session_params(&node);
        assert_eq!(
            params.config().handshake,
            Duration::from_secs(secs),
            "a {secs} s handshake timeout must reach the machine"
        );
    }
    node.rate_limit.handshake_timeout_secs = 3;
    assert_eq!(
        session_params(&node).config().handshake,
        Config::fsp().handshake,
        "a timeout under the tick plus 3 s falls back to the defaults"
    );

    node.rekey.after_secs = 300;
    node.rekey.after_messages = 7;
    let config = *session_params(&node).config();
    assert_eq!(
        (config.after, config.messages, config.handshake),
        (Duration::from_secs(300), 7, Config::fsp().handshake),
        "the thresholds reach the machine whatever the timers fell back to"
    );
    node.rate_limit.handshake_timeout_secs = 30;
    node.rekey.after_secs = u64::MAX;
    node.rekey.after_messages = u64::MAX;
    let config = *session_params(&node).config();
    assert_eq!(
        (config.after, config.messages),
        (Duration::from_secs(MAX_AFTER), Config::fsp().soft),
        "the idiom for switching a trigger off is its largest accepted value"
    );
    node.rekey.after_secs = 16;
    node.rekey.after_messages = 7;
    let config = *session_params(&node).config();
    assert_eq!(
        (config.after, config.messages),
        (Duration::from_secs(16), 7),
        "the smallest interval the configuration accepts reaches the machine"
    );
}
