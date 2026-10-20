//! Conformance of the link rekey profile to the deployed link: every byte
//! it writes is what the deployed handshake and framing write and read.
//! The interop simulation (`proto::rekey::tests::legacy`) runs whole rekeys
//! against the deployed releases; this checks the profile's pieces against
//! the deployed codec directly.

use crate::noise::HandshakeState;
use crate::noise::aead::{Aead, nonce};
use crate::proto::fmp::wire::{
    MSG1_WIRE_SIZE, MSG2_WIRE_SIZE, Msg1Header, Msg2Header, build_established_header,
    strip_inner_header,
};
use crate::proto::link::LinkMessageType;
use crate::proto::rekey::{
    Arrival, Bond, CycleView, Env, FrameHint, Ids, Input, JitterSource, Msg1Read, MsgKind,
    NodeKeys, Output, Params, PeerKey, Profile, Reason, Rekey, SessionKeys, SetupFacts, TagSource,
    allocate,
};
use crate::testutil::{SeededEntropy, TestClock, TestInstant, seed_entropy, seeded_keypair};
use crate::time::Duration;
use crate::transport::TransportId;
use crate::utils::index::{IndexAllocator, SessionIndex};

use super::{FmpIk, read_msg1, setup_record};

type Ik = FmpIk<SeededEntropy>;

/// The x-only key of a keypair, as the machine holds keys.
fn key(k: &secp256k1::Keypair) -> PeerKey {
    PeerKey::from_xonly(&k.x_only_public_key().0)
}

#[test]
fn ik_profile_writes_and_reads_the_deployed_handshake_and_frames_byte_for_byte() {
    seed_entropy(1);
    let (ik, rk) = (seeded_keypair(1), seeded_keypair(2));
    let (ie, re) = ([0xa1; 8], [0xb2; 8]);
    let init = NodeKeys::new(ik, ie);
    let resp = NodeKeys::new(rk, re);

    // msg1: the 114-byte link framing around a Noise IK msg1 carrying the
    // initiator's static key and startup epoch, under the index given.
    let (hs, msg1) = Ik::initiate(&init, &key(&rk), Some(0x0102_0304)).expect("msg1");
    assert_eq!(msg1.len(), MSG1_WIRE_SIZE);
    let h1 = Msg1Header::parse(&msg1).expect("the deployed parser takes it");
    assert_eq!(h1.sender_idx.as_u32(), 0x0102_0304);
    assert_eq!(msg1[1], 0, "handshake flags are zero");
    let mut deployed = HandshakeState::<SeededEntropy>::new_responder(rk);
    deployed.set_local_epoch(re);
    deployed
        .read_message_1(&msg1[h1.noise_msg1_offset..])
        .expect("a deployed responder reads it");
    assert_eq!(
        deployed.remote_epoch(),
        Some(ie),
        "msg1 carries the startup epoch"
    );
    assert!(
        Ik::initiate(&init, &key(&rk), None).is_err(),
        "an IK attempt needs an index"
    );

    // The node-level read authenticates the same msg1, and refuses any
    // altered copy or a msg1 for another static key.
    let tok = read_msg1::<SeededEntropy>(&resp, &msg1).expect("it reads");
    assert_eq!(tok.get().remote(), key(&ik));
    assert_eq!(tok.get().epoch(), ie);
    let mut flipped = msg1.clone();
    flipped[60] ^= 1;
    assert!(read_msg1::<SeededEntropy>(&resp, &flipped).is_none());
    let mut flagged = msg1.clone();
    flagged[1] = 1;
    assert!(read_msg1::<SeededEntropy>(&resp, &flagged).is_none());
    assert!(read_msg1::<SeededEntropy>(&resp, &msg1[..msg1.len() - 1]).is_none());
    assert!(read_msg1::<SeededEntropy>(&NodeKeys::new(seeded_keypair(3), re), &msg1).is_none());
    let record = setup_record(&msg1, None).expect("a record");
    assert_eq!(
        record.len(),
        1,
        "the setup record holds the msg1's ephemeral"
    );

    // msg2: the 69-byte framing naming both indices, carrying the
    // responder's epoch, read by the initiator on a fork.
    let (rdone, msg2) = tok.get().answer(&resp, Some(0x0a0b_0c0d)).expect("msg2");
    assert_eq!(msg2.len(), MSG2_WIRE_SIZE);
    let h2 = Msg2Header::parse(&msg2).expect("the deployed parser takes it");
    assert_eq!(h2.sender_idx.as_u32(), 0x0a0b_0c0d);
    assert_eq!(h2.receiver_idx.as_u32(), 0x0102_0304);
    assert_eq!(
        Ik::index(&msg2),
        Some(0x0102_0304),
        "a reply routes by its receiver index"
    );
    let mut bad = msg2.clone();
    bad[40] ^= 1;
    assert!(Ik::reply(&hs, &init, &bad).is_err());
    let read = Ik::reply(&hs, &init, &msg2).expect("the failed read left it readable");
    assert_eq!(read.done.epoch, re, "msg2 carries the startup epoch");
    assert_eq!(read.done.remote, key(&rk));
    assert_eq!(read.done.theirs, Some(0x0a0b_0c0d));
    assert!(read.fin.is_none(), "IK has no third message");

    // Frames: the responder opens what the initiator seals under the
    // 16-byte header, counters start at 0, each direction has its own key,
    // and the window refuses a repeat and the counter 2^64 - 1.
    let mut ikeys = read.done.session;
    let mut rkeys = rdone.session;
    let (counter, send) = ikeys.reserve();
    assert_eq!(counter, 0, "counters start at 0 in every session");
    let plaintext = [1u8, 2, 3, 4, LinkMessageType::Heartbeat.to_byte()];
    let header = build_established_header(
        SessionIndex::new(0x0a0b_0c0d),
        counter,
        0,
        plaintext.len() as u16,
    );
    let mut buf = plaintext.to_vec();
    let tag = send
        .key()
        .expect("keyed")
        .seal(&nonce(counter), &header, &mut buf)
        .expect("seals");
    let mut frame = header.to_vec();
    frame.extend_from_slice(&buf);
    frame.extend_from_slice(&tag);
    let hint = FrameHint {
        counter,
        k: false,
        index: 0x0a0b_0c0d,
        body: 16,
    };
    let mut out = alloc::vec::Vec::new();
    assert!(rkeys.fresh(counter));
    assert!(rkeys.open(&hint, &frame, &mut out));
    assert_eq!(out, plaintext);
    assert!(rkeys.fresh(counter), "an open alone marks nothing");
    rkeys.mark(counter);
    assert!(!rkeys.fresh(counter), "a counter is refused once marked");
    assert!(!rkeys.fresh(u64::MAX), "the counter 2^64 - 1 is refused");
    let mut tampered = frame.clone();
    tampered[1] = 1;
    assert!(
        !rkeys.open(&hint, &tampered, &mut out),
        "the header is authenticated"
    );
    assert!(
        !ikeys.open(&hint, &frame, &mut out),
        "each direction has its own key"
    );
    assert_eq!(ikeys.sent(), 1);

    // The prompt is a Heartbeat under the inner header, timestamped from
    // the epoch's base.
    let mut prompt = alloc::vec::Vec::new();
    Ik::prompt(Duration::from_millis(70_000), &mut prompt);
    let (ts, msg) = strip_inner_header(&prompt).expect("the deployed parser takes it");
    assert_eq!(ts, 70_000);
    assert_eq!(msg, [LinkMessageType::Heartbeat.to_byte()]);
    assert!(prompt.len() >= Ik::FLOOR);
    assert!(!Ik::is_probe(&prompt), "a link has no probe");
}

/// A jitter source that always draws the band's low end.
struct Low;

impl JitterSource for Low {
    /// Always 0.
    fn draw(&mut self, _: u16) -> u16 {
        0
    }
}

/// What one msg1 made the machine do, reduced to what the replay rows
/// distinguish.
#[derive(Debug, PartialEq, Eq)]
enum Did {
    /// Sent a msg2 with these bytes.
    Msg2(alloc::vec::Vec<u8>),
    /// Refused it for this reason.
    Reject(Reason),
    /// Asked the shell to replace the machine.
    Replace,
}

/// The responder's machine of a link set up from `msg1` answered with
/// `msg2`, and what it owns, so a msg1 can be stepped into it.
struct Responder {
    m: Rekey<Ik, TestClock>,
    local: NodeKeys,
    alloc: IndexAllocator<SeededEntropy>,
    tags: TagSource,
    scratch: alloc::vec::Vec<u8>,
}

impl Responder {
    /// Read `bytes` at node level and step the result in at `now` ms.
    fn msg1(&mut self, now: u64, bytes: &[u8]) -> Did {
        let tok = read_msg1::<SeededEntropy>(&self.local, bytes).expect("it authenticates");
        let arrival = Arrival {
            on_link: true,
            reachable: true,
        };
        let mut env = Env {
            indices: &mut self.alloc,
            transport: TransportId::new(1),
            tags: &mut self.tags,
            workers: false,
            jitter: &mut Low,
            local: &self.local,
            scratch: &mut self.scratch,
        };
        let out = self
            .m
            .step(TestInstant(now), Input::PeerMsg1 { tok, arrival }, &mut env);
        let did = out.into_iter().find_map(|o| match o {
            Output::Send {
                msg,
                kind: MsgKind::Msg2,
                ..
            } => Some(Did::Msg2(msg)),
            Output::Reject(r) => Some(Did::Reject(r)),
            Output::ReplaceRequested { .. } => Some(Did::Replace),
            _ => None,
        });
        did.expect("a msg1 is answered, refused or handed to the shell")
    }
}

/// `msg1` with its sender index rewritten, which its AEAD does not cover.
fn reindexed(msg1: &[u8]) -> alloc::vec::Vec<u8> {
    let mut copy = msg1.to_vec();
    copy[4] ^= 0xff;
    copy
}

#[test]
fn ik_replay_record_tells_setup_copies_rewritten_copies_and_fresh_msg1s_apart() {
    seed_entropy(2);
    let (ik, rk) = (seeded_keypair(1), seeded_keypair(2));
    let init = NodeKeys::new(ik, [0xa1; 8]);
    let resp = NodeKeys::new(rk, [0xb2; 8]);
    let mut alloc = IndexAllocator::<SeededEntropy>::new();
    let lease = allocate(&mut alloc).expect("an index");
    let (_, setup1) = Ik::initiate(&init, &key(&rk), Some(7)).expect("msg1");
    let tok = read_msg1::<SeededEntropy>(&resp, &setup1).expect("it reads");
    let (done, setup2) = tok.get().answer(&resp, Some(lease.index())).expect("msg2");
    let record = setup_record(&setup1, Some(&setup2)).expect("a record");
    let bonded = Bond::Key(key(&ik)).check(done).expect("it bonds");
    let facts = SetupFacts {
        peer_epoch: [0xa1; 8],
        k: false,
        link_since: TestInstant(0),
        started: TestInstant(0),
        peer_k: None,
        record,
    };
    let mut tags = TagSource::new();
    let mut scratch = alloc::vec::Vec::new();
    let mut env = Env {
        indices: &mut alloc,
        transport: TransportId::new(1),
        tags: &mut tags,
        workers: false,
        jitter: &mut Low,
        local: &resp,
        scratch: &mut scratch,
    };
    let (m, _) = Rekey::established(
        Params::fmp(),
        Bond::Key(key(&ik)),
        key(&rk).addr(),
        bonded,
        Ids::new(lease, 7, TransportId::new(1)),
        facts,
        TestInstant(0),
        &mut env,
    );
    let mut r = Responder {
        m,
        local: resp,
        alloc,
        tags,
        scratch,
    };
    let fresh = |idx| Ik::initiate(&init, &key(&rk), Some(idx)).expect("msg1").1;

    // While the link is too young to rekey: the setup msg1 again is
    // answered with the setup msg2, a copy with a rewritten header is a
    // replay, and a fresh msg1 goes to the shell and is remembered.
    let young = 1_000;
    assert_eq!(r.msg1(young, &setup1), Did::Msg2(setup2.clone()));
    assert_eq!(
        r.msg1(young, &reindexed(&setup1)),
        Did::Reject(Reason::AnsweredBefore)
    );
    let replaced = fresh(8);
    assert_eq!(r.msg1(young, &replaced), Did::Replace);
    assert_eq!(
        r.msg1(young, &reindexed(&replaced)),
        Did::Reject(Reason::AnsweredBefore),
        "a msg1 handed to the shell enters the record"
    );

    // Once eligible: both setup copies are replays, a fresh msg1 arms a
    // pending, and that msg1 again is answered with the same msg2 while a
    // rewritten copy of it is refused.
    let old = 40_000;
    assert_eq!(r.msg1(old, &setup1), Did::Reject(Reason::AnsweredBefore));
    assert_eq!(
        r.msg1(old, &reindexed(&setup1)),
        Did::Reject(Reason::AnsweredBefore)
    );
    let arming = fresh(9);
    let Did::Msg2(answer) = r.msg1(old, &arming) else {
        panic!("a fresh msg1 at an eligible idle link is answered");
    };
    assert_eq!(r.m.view().cycle, CycleView::PendR);
    assert_eq!(r.msg1(old, &arming), Did::Msg2(answer));
    assert_eq!(
        r.msg1(old, &reindexed(&arming)),
        Did::Reject(Reason::PendingHeld)
    );
}
