//! Tests for `../xx.rs`: the session rekey profile against the handshake
//! and frames next's session code writes and reads, and whole first
//! handshakes and rekeys between two machines on the profile.
//!
//! "Plain" code below is next's session handshake written out with
//! `HandshakeState` directly, the way next's shell reads and writes it: the
//! negotiation payload `NegotiationPayload::new(0, 0, 0)` after the base
//! ack and msg3 of a first handshake, none after a rekey's, and a reader
//! that takes the payload when one follows the base message.

use alloc::vec::Vec;

use secp256k1::Keypair;

use crate::identity::NodeAddr;
use crate::noise::aead::{Aead, nonce};
use crate::noise::{
    Fork, HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE, HANDSHAKE_MSG3_SIZE, HandshakeState,
    NoiseSession,
};
use crate::proto::fmp::wire::NegotiationPayload;
use crate::proto::fsp::wire::{
    FSP_FLAG_K, FSP_HEADER_SIZE, FspEncryptedHeader, SessionMessageType, build_fsp_header,
    fsp_prepend_inner_header, fsp_strip_inner_header,
};
use crate::proto::rekey::{
    Bond, Completed, CycleView, Env, FrameHint, Ids, Input, JitterSource, MsgKind, NodeKeys,
    Output, Params, PeerKey, Profile, Reason, Record, Rekey, Sealed, SendCopy, SessionKeys as _,
    SetupFacts, Slot, TagSource, Wait,
};
use crate::proto::stp::TreeCoordinate;
use crate::testutil::{SeededEntropy, TestClock, TestInstant, seed_entropy, seeded_keypair};
use crate::time::Duration;

use super::{FspXx, SessionKeys, SessionLocal};

type E = SeededEntropy;
type Xx = FspXx<E>;
type Hs = HandshakeState<E>;

/// The x-only key of a keypair, as the machine holds keys.
fn key(k: &Keypair) -> PeerKey {
    PeerKey::from_xonly(&k.x_only_public_key().0)
}

/// The local keys of a node with keys `k` in epoch `e`, `opening` when the
/// session has no epoch yet.
fn local(k: Keypair, e: [u8; 8], opening: bool) -> SessionLocal {
    SessionLocal::new(NodeKeys::new(k, e), opening)
}

/// The negotiation payload next's session first handshake carries.
fn payload() -> Vec<u8> {
    NegotiationPayload::new(0, 0, 0).encode()
}

/// Next's responder answering a setup: msg2, with the payload on a first
/// handshake.
fn plain_answer(k: Keypair, e: [u8; 8], setup: &[u8], first: bool) -> (Hs, Vec<u8>) {
    let mut hs = Hs::new_responder(k);
    hs.set_local_epoch(e);
    hs.read_message_1(setup).expect("the setup reads");
    let mut ack = hs.write_message_2().expect("msg2");
    if first {
        ack.extend(hs.encrypt_payload(&payload()).expect("payload"));
    }
    (hs, ack)
}

/// Next's initiator reading an ack in place, base message then any
/// payload, and writing msg3, with the payload on a first handshake.
fn plain_msg3(hs: &mut Hs, ack: &[u8], first: bool) -> Vec<u8> {
    hs.read_message_2(&ack[..HANDSHAKE_MSG2_SIZE])
        .expect("msg2 reads");
    if ack.len() > HANDSHAKE_MSG2_SIZE {
        hs.decrypt_payload(&ack[HANDSHAKE_MSG2_SIZE..])
            .expect("the ack payload reads");
    }
    let mut msg3 = hs.write_message_3().expect("msg3");
    if first {
        msg3.extend(hs.encrypt_payload(&payload()).expect("payload"));
    }
    msg3
}

/// Next's responder reading a msg3 in place, base message then any
/// payload: the payload, decoded.
fn plain_read3(hs: &mut Hs, msg3: &[u8]) -> Option<NegotiationPayload> {
    hs.read_message_3(&msg3[..HANDSHAKE_MSG3_SIZE])
        .expect("msg3 reads");
    (msg3.len() > HANDSHAKE_MSG3_SIZE).then(|| {
        let p = hs
            .decrypt_payload(&msg3[HANDSHAKE_MSG3_SIZE..])
            .expect("the msg3 payload reads");
        NegotiationPayload::decode(&p).expect("the payload decodes")
    })
}

/// Seal `plaintext` with a reserved send key behind the 12-byte session
/// header, with no coordinates.
fn session_frame(sealed: &Sealed<SendCopy>, plaintext: &[u8]) -> Vec<u8> {
    let flags = if sealed.k { FSP_FLAG_K } else { 0 };
    let header = build_fsp_header(sealed.counter, flags, plaintext.len() as u16);
    let key = sealed.key.key().expect("a reserved send key is keyed");
    let mut buf = plaintext.to_vec();
    let tag = key
        .seal(&nonce(sealed.counter), &header, &mut buf)
        .expect("seals");
    let mut out = header.to_vec();
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    out
}

/// A session data plaintext: a `DataPacket` inner header and `seq`.
fn data(seq: u8) -> Vec<u8> {
    fsp_prepend_inner_header(0, SessionMessageType::DataPacket.to_byte(), 0, &[seq])
}

#[test]
fn xx_profile_writes_and_reads_the_handshake_and_frames_next_sends_byte_for_byte() {
    let (ik, rk) = (seeded_keypair(4), seeded_keypair(5));
    let (ie, re) = ([0xc3; 8], [0xd4; 8]);

    // The setup is the bare 33-byte XX msg1 next's initiator writes from the
    // same entropy; a malformed one fails the receiver's checks.
    seed_entropy(7);
    let (ihs, setup) = Xx::initiate(&local(ik, ie, true), &key(&rk), None).expect("msg1");
    seed_entropy(7);
    let mut plain_i = Hs::new_initiator(ik);
    plain_i.set_local_epoch(ie);
    assert_eq!(setup, plain_i.write_message_1().expect("msg1"));
    assert_eq!(setup.len(), HANDSHAKE_MSG1_SIZE);
    assert!(Xx::valid(&setup));
    assert!(!Xx::valid(&setup[..32]), "a short msg1 is invalid");
    assert!(
        !Xx::valid(&[0u8; HANDSHAKE_MSG1_SIZE]),
        "a non-point is invalid"
    );

    // The ack of a first handshake carries the payload after the base msg2
    // and a rekey's carries none, each byte for byte what next writes.
    for first in [true, false] {
        seed_entropy(8);
        let (_, ack) = Xx::answer(&local(rk, re, first), &setup).expect("ack");
        seed_entropy(8);
        let (_, plain_ack) = plain_answer(rk, re, &setup, first);
        assert_eq!(ack, plain_ack, "first={first}: next's ack byte for byte");
        assert_eq!(ack.len() == HANDSHAKE_MSG2_SIZE, !first);
    }

    // The reply reads either ack shape on a fork and writes msg3 with the
    // payload only on a first handshake, byte for byte what next writes.
    for first in [true, false] {
        seed_entropy(9);
        let (rhs, ack) = Xx::answer(&local(rk, re, first), &setup).expect("ack");
        let mut bad = ack.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let init = local(ik, ie, first);
        assert!(Xx::reply(&ihs, &init, &bad).is_err());
        let read = Xx::reply(&ihs, &init, &ack).expect("the failed read left it readable");
        assert_eq!(read.done.epoch, re, "msg2 carries the startup epoch");
        assert_eq!(read.done.remote, key(&rk));
        let fin = read.fin.expect("XX has a msg3");
        let mut plain = ihs.fork();
        assert_eq!(
            fin,
            plain_msg3(&mut plain, &ack, first),
            "first={first}: next's msg3 byte for byte"
        );
        assert_eq!(fin.len() == HANDSHAKE_MSG3_SIZE, !first);

        // Next's responder reads it, and so does the profile's.
        let mut plain_r = rhs.fork();
        let neg = plain_read3(&mut plain_r, &fin);
        assert_eq!(neg, first.then(|| NegotiationPayload::new(0, 0, 0)));
        let mut tampered = fin.clone();
        tampered[10] ^= 1;
        assert!(Xx::complete(&rhs, &tampered).is_err());
        let rdone = Xx::complete(&rhs, &fin).expect("the responder completes");
        assert_eq!(rdone.epoch, ie, "msg3 carries the startup epoch");
        assert_eq!(rdone.remote, key(&ik), "msg3 authenticates the initiator");

        // Frames over the 12-byte header open under next's plain session,
        // and back.
        let mut ikeys = read.done.session;
        let (counter, send) = ikeys.reserve();
        assert_eq!(counter, 0, "counters start at 0 in every session");
        let sealed = Sealed {
            tag: TagSource::new().draw(),
            k: true,
            counter,
            elapsed: Duration::ZERO,
            theirs: None,
            key: send,
        };
        let plaintext = data(9);
        let frame = session_frame(&sealed, &plaintext);
        let mut rsession = plain_r.into_session().expect("complete");
        assert_eq!(
            rsession
                .decrypt_with_replay_check_and_aad(
                    &frame[FSP_HEADER_SIZE..],
                    counter,
                    &frame[..FSP_HEADER_SIZE]
                )
                .expect("next's session opens the profile's frame"),
            plaintext
        );
        let header = build_fsp_header(0, 0, plaintext.len() as u16);
        let mut back = header.to_vec();
        back.extend(
            rsession
                .encrypt_with_aad(&plaintext, &header)
                .expect("seals"),
        );
        let hint = FrameHint {
            counter: 0,
            k: false,
            index: 0,
            body: FSP_HEADER_SIZE,
        };
        let mut out = Vec::new();
        assert!(
            ikeys.open(&hint, &back, &mut out),
            "and the profile opens next's"
        );
        assert_eq!(out, plaintext);
    }

    // The prompt is a CoordsWarmup inner header with an empty body: a probe
    // under a pending epoch, and nothing else is.
    let mut prompt = Vec::new();
    Xx::prompt(Duration::from_millis(3_000), &mut prompt);
    let (ts, msg_type, flags, rest) =
        fsp_strip_inner_header(&prompt).expect("next's parser takes it");
    assert_eq!(
        (ts, msg_type, flags),
        (3_000, SessionMessageType::CoordsWarmup.to_byte(), 0)
    );
    assert!(rest.is_empty());
    assert!(prompt.len() >= Xx::FLOOR);
    assert!(Xx::is_probe(&prompt));
    assert!(!Xx::is_probe(&data(1)), "data is not a probe");
    assert!(
        !Xx::is_probe(&prompt[..5]),
        "a plaintext too short for the inner header is not a probe"
    );
}

#[test]
fn xx_reply_reads_the_payload_on_its_fork() {
    let (ik, rk) = (seeded_keypair(14), seeded_keypair(15));
    seed_entropy(10);
    let init = local(ik, [1; 8], true);
    let (ihs, setup) = Xx::initiate(&init, &key(&rk), None).expect("msg1");

    // The msg3 the profile writes after an ack with a payload is read,
    // payload included, by a plain responder, which ends on the same
    // handshake hash.
    let (mut rhs, ack) = plain_answer(rk, [2; 8], &setup, true);
    let read = Xx::reply(&ihs, &init, &ack).expect("reads");
    let fin = read.fin.expect("msg3");
    assert!(plain_read3(&mut rhs, &fin).is_some());
    assert_eq!(
        read.done.session.session().handshake_hash(),
        &rhs.handshake_hash(),
        "both ends mixed the same transcript"
    );

    // The other way: `complete` takes a plain initiator's msg3 with its
    // payload to the plain initiator's hash.
    let mut plain = Hs::new_initiator(ik);
    plain.set_local_epoch([1; 8]);
    let setup = plain.write_message_1().expect("msg1");
    let (rhs, ack) = Xx::answer(&local(rk, [2; 8], true), &setup).expect("ack");
    let msg3 = plain_msg3(&mut plain, &ack, true);
    let done = Xx::complete(&rhs, &msg3).expect("reads");
    assert_eq!(
        done.session.session().handshake_hash(),
        &plain.handshake_hash()
    );
}

/// A jitter source that always draws the same value: `15` is no jitter at
/// the defaults, `30` the band's top.
struct Fixed(u16);

impl JitterSource for Fixed {
    /// The fixed draw, within the bound.
    fn draw(&mut self, bound: u16) -> u16 {
        self.0.min(bound)
    }
}

/// One end of a session: a machine on `FspXx`, opened by either end or
/// built established, and what its outputs produced.
struct Node {
    m: Option<Rekey<Xx, TestClock>>,
    kp: Keypair,
    epoch: [u8; 8],
    peer: PeerKey,
    tags: TagSource,
    jitter: Fixed,
    scratch: Vec<u8>,
    /// Handshake messages sent, oldest first.
    sent: Vec<(MsgKind, Vec<u8>)>,
    /// Prompt frames sealed, oldest first.
    prompts: Vec<Vec<u8>>,
    rejects: Vec<Reason>,
    installs: usize,
    restarts: Vec<[u8; 8]>,
}

/// The coordinates every handshake message carries here.
fn coords(addr: NodeAddr) -> TreeCoordinate {
    TreeCoordinate::root(addr)
}

impl Node {
    /// A node with no session yet toward `peer`.
    fn new(kp: Keypair, epoch: [u8; 8], peer: PeerKey, jitter: u16) -> Self {
        Self {
            m: None,
            kp,
            epoch,
            peer,
            tags: TagSource::new(),
            jitter: Fixed(jitter),
            scratch: Vec::new(),
            sent: Vec::new(),
            prompts: Vec::new(),
            rejects: Vec::new(),
            installs: 0,
            restarts: Vec::new(),
        }
    }

    /// A node whose session with `peer` (in `peer_epoch`) was set up at 0
    /// with `session`.
    fn established(
        kp: Keypair,
        epoch: [u8; 8],
        peer: PeerKey,
        peer_epoch: [u8; 8],
        session: NoiseSession,
        jitter: u16,
    ) -> Self {
        let mut n = Self::new(kp, epoch, peer, jitter);
        let done = Completed::<Xx> {
            session: alloc::boxed::Box::new(SessionKeys::new(session)),
            remote: peer,
            epoch: peer_epoch,
            theirs: None,
        };
        let bonded = Bond::Key(peer).check(done).expect("the setup bonds");
        let facts = SetupFacts {
            peer_epoch: Some(peer_epoch),
            k: false,
            link_since: TestInstant(0),
            started: TestInstant(0),
            peer_k: None,
            record: Record::new(),
        };
        let me = n.addr();
        let (m, out) = n.with(|_, env| {
            Rekey::established(
                Params::fsp(),
                Bond::Key(peer),
                me,
                bonded,
                Ids::unindexed(()),
                facts,
                TestInstant(0),
                env,
            )
        });
        n.m = Some(m);
        n.run(0, out);
        n
    }

    /// This node's address.
    fn addr(&self) -> NodeAddr {
        key(&self.kp).addr()
    }

    /// Run `f` with the machine and an `Env` whose local keys mark the
    /// session as opening while it has no current epoch, as the shell does.
    fn with<R>(
        &mut self,
        f: impl FnOnce(&mut Option<Rekey<Xx, TestClock>>, &mut Env<'_, Xx>) -> R,
    ) -> R {
        let opening = self.m.as_ref().is_none_or(|m| m.view().current.is_none());
        let local = local(self.kp, self.epoch, opening);
        let mut indices = ();
        let mut env = Env {
            indices: &mut indices,
            transport: (),
            tags: &mut self.tags,
            workers: false,
            jitter: &mut self.jitter,
            local: &local,
            scratch: &mut self.scratch,
        };
        f(&mut self.m, &mut env)
    }

    /// Step the machine with `input` at `now` and execute its outputs.
    fn step(&mut self, now: u64, input: Input<'_, Xx>) {
        let out = self.with(|m, env| {
            m.as_mut()
                .expect("a machine")
                .step(TestInstant(now), input, env)
        });
        self.run(now, out);
    }

    /// Poll at `now`.
    fn poll(&mut self, now: u64) {
        self.step(now, Input::Poll);
    }

    /// Open the session toward the peer.
    fn open(&mut self, now: u64) {
        let (peer, me) = (self.peer, self.addr());
        let (m, out) = self.with(|_, env| {
            Rekey::opening_outbound(Params::fsp(), peer, me, TestInstant(now), (), env)
        });
        self.m = Some(m);
        self.run(now, out);
    }

    /// Execute outputs front to back, as the shell does.
    fn run(&mut self, now: u64, outputs: Vec<Output<Xx>>) {
        for o in outputs {
            match o {
                Output::Send { msg, kind, .. } => self.sent.push((kind, msg)),
                Output::Prompt { tag } => {
                    let m = self.m.as_mut().expect("a machine");
                    let p = m.seal_prompt(TestInstant(now), tag).expect("seals");
                    self.prompts.push(session_frame(&p.sealed, &p.plaintext));
                }
                Output::Reject(r) => self.rejects.push(r),
                Output::Installed { .. } => self.installs += 1,
                Output::PeerRestarted { epoch, .. } => self.restarts.push(epoch),
                Output::Teardown(t) => panic!("teardown {t:?}"),
                _ => {}
            }
        }
    }

    /// Take the handshake messages of `kind` sent so far.
    fn take(&mut self, kind: MsgKind) -> Vec<Vec<u8>> {
        let (want, keep): (Vec<_>, Vec<_>) = core::mem::take(&mut self.sent)
            .into_iter()
            .partition(|(k, _)| *k == kind);
        self.sent = keep;
        want.into_iter().map(|(_, m)| m).collect()
    }

    /// Receive a setup from `from`, opening a machine for it if there is
    /// none.
    fn setup(&mut self, now: u64, from: NodeAddr, msg1: &[u8]) {
        let input = Input::Setup {
            msg1,
            carrier: from,
            route: coords(from),
            only: (),
        };
        if self.m.is_some() {
            self.step(now, input);
            return;
        }
        let me = self.addr();
        let (m, out) = self.with(|_, env| {
            Rekey::opening_inbound(Params::fsp(), from, me, TestInstant(now), input, (), env)
        });
        self.m = Some(m);
        self.run(now, out);
    }

    /// Receive an ack from `from`.
    fn ack(&mut self, now: u64, from: NodeAddr, bytes: &[u8]) {
        self.step(
            now,
            Input::Reply {
                bytes,
                route: coords(from),
            },
        );
    }

    /// Receive a msg3.
    fn fin(&mut self, now: u64, bytes: &[u8]) {
        self.step(now, Input::Final { bytes, only: () });
    }

    /// Seal a data frame under the current epoch.
    fn data(&mut self, now: u64, seq: u8) -> Vec<u8> {
        let m = self.m.as_mut().expect("a machine");
        session_frame(&m.seal(TestInstant(now)).expect("seals"), &data(seq))
    }

    /// Receive a session frame; return what it delivered.
    fn recv(&mut self, now: u64, bytes: &[u8]) -> Option<(Slot, Vec<u8>)> {
        let h = FspEncryptedHeader::parse(bytes).expect("a frame");
        let hint = FrameHint {
            counter: h.counter,
            k: h.flags & FSP_FLAG_K != 0,
            index: 0,
            body: FSP_HEADER_SIZE,
        };
        let mut buf = bytes.to_vec();
        let out = self.with(|m, env| {
            m.as_mut().expect("a machine").step(
                TestInstant(now),
                Input::Frame {
                    buf: &mut buf,
                    hint,
                },
                env,
            )
        });
        let mut got = None;
        let mut rest = Vec::new();
        for o in out {
            if let Output::Deliver { slot, range, .. } = &o {
                got = Some((*slot, buf[range.clone()].to_vec()));
            } else {
                rest.push(o);
            }
        }
        self.run(now, rest);
        got
    }

    /// Hand every prompt this node sealed to `to`.
    fn prompts_to(&mut self, now: u64, to: &mut Node) {
        for p in core::mem::take(&mut self.prompts) {
            to.recv(now, &p);
        }
    }

    /// The machine.
    fn m(&self) -> &Rekey<Xx, TestClock> {
        self.m.as_ref().expect("a machine")
    }
}

/// The two nodes' keys.
fn keys() -> (Keypair, Keypair) {
    (seeded_keypair(31), seeded_keypair(32))
}

/// A session set up by next's plain first handshake, `a` the initiator:
/// the two nodes built established on it, `a` drawing no jitter and `b`
/// the band's top.
fn established() -> (Node, Node) {
    let (ak, bk) = keys();
    let (ae, be) = ([0xa1; 8], [0xb2; 8]);
    let mut ini = Hs::new_initiator(ak);
    ini.set_local_epoch(ae);
    let setup = ini.write_message_1().expect("msg1");
    let (mut resp, ack) = plain_answer(bk, be, &setup, true);
    let msg3 = plain_msg3(&mut ini, &ack, true);
    plain_read3(&mut resp, &msg3);
    let a = Node::established(
        ak,
        ae,
        key(&bk),
        be,
        ini.into_session().expect("complete"),
        15,
    );
    let b = Node::established(
        bk,
        be,
        key(&ak),
        ae,
        resp.into_session().expect("complete"),
        30,
    );
    (a, b)
}

#[test]
fn two_xx_session_machines_open_a_session_and_rekey_it() {
    seed_entropy(40);
    let (ak, bk) = keys();
    let mut a = Node::new(ak, [0xa1; 8], key(&bk), 15);
    let mut b = Node::new(bk, [0xb2; 8], key(&ak), 30);
    let (aa, ba) = (a.addr(), b.addr());

    // The first handshake: the ack and msg3 carry the payload.
    a.open(0);
    let setup = a.take(MsgKind::Setup).pop().expect("a setup");
    b.setup(10, aa, &setup);
    let ack = b.take(MsgKind::Ack).pop().expect("an ack");
    assert!(
        ack.len() > HANDSHAKE_MSG2_SIZE,
        "a first ack has the payload"
    );
    a.ack(20, ba, &ack);
    let msg3 = a.take(MsgKind::Msg3).pop().expect("msg3");
    assert!(
        msg3.len() > HANDSHAKE_MSG3_SIZE,
        "a first msg3 has the payload"
    );
    b.fin(30, &msg3);
    assert_eq!(b.installs, 1, "the responder installs at msg3");
    b.prompts_to(40, &mut a);
    assert_eq!(
        a.installs, 1,
        "the initiator installs on the responder's frame"
    );
    let f = a.data(50, 1);
    assert_eq!(b.recv(50, &f), Some((Slot::Current, data(1))));
    let f = b.data(50, 2);
    assert_eq!(a.recv(50, &f), Some((Slot::Current, data(2))));

    // A rekey: no payload on the ack or msg3; the responder cuts over at
    // msg3 and prompts, and the initiator cuts over on that frame.
    let t = 200_000;
    a.poll(t);
    let setup = a.take(MsgKind::Setup).pop().expect("a rekey setup");
    b.setup(t + 10, aa, &setup);
    let ack = b.take(MsgKind::Ack).pop().expect("an ack");
    assert_eq!(ack.len(), HANDSHAKE_MSG2_SIZE, "a rekey ack has no payload");
    a.ack(t + 20, ba, &ack);
    let msg3 = a.take(MsgKind::Msg3).pop().expect("msg3");
    assert_eq!(
        msg3.len(),
        HANDSHAKE_MSG3_SIZE,
        "a rekey msg3 has no payload"
    );
    assert_eq!(a.m().view().cycle, CycleView::PendI(Wait::Evidence));
    a.prompts.clear();
    b.fin(t + 30, &msg3);
    assert_eq!(b.installs, 2, "the responder cuts over at msg3");
    b.prompts_to(t + 40, &mut a);
    assert_eq!(
        a.installs, 2,
        "the initiator cuts over on the responder's frame"
    );
    let f = a.data(t + 50, 3);
    assert_eq!(b.recv(t + 50, &f), Some((Slot::Current, data(3))));
    let f = b.data(t + 50, 4);
    assert_eq!(a.recv(t + 50, &f), Some((Slot::Current, data(4))));
    assert!(a.rejects.is_empty() && b.rejects.is_empty());
}

#[test]
fn restarted_peers_final_with_payload_completes() {
    seed_entropy(41);
    let (a, mut b) = established();
    let (aa, ba) = (a.addr(), b.addr());

    // A restarts with a new startup epoch and opens afresh: its msg3
    // carries the payload of a first handshake, while B, holding the
    // session, answers as a rekey with no payload.
    let mut a2 = Node::new(a.kp, [0xa9; 8], key(&b.kp), 15);
    let t = 60_000;
    a2.open(t);
    let setup = a2.take(MsgKind::Setup).pop().expect("a setup");
    b.setup(t + 10, aa, &setup);
    let ack = b.take(MsgKind::Ack).pop().expect("an ack");
    assert_eq!(ack.len(), HANDSHAKE_MSG2_SIZE);
    a2.ack(t + 20, ba, &ack);
    let msg3 = a2.take(MsgKind::Msg3).pop().expect("msg3");
    assert!(
        msg3.len() > HANDSHAKE_MSG3_SIZE,
        "the restarted peer's msg3"
    );

    // B completes on it and reports the restart.
    b.fin(t + 30, &msg3);
    assert_eq!(b.installs, 1, "B installs the restarted peer's session");
    assert_eq!(b.restarts, [[0xa9; 8]]);
    b.prompts_to(t + 40, &mut a2);
    assert_eq!(a2.installs, 1);
    let f = a2.data(t + 50, 5);
    assert_eq!(b.recv(t + 50, &f), Some((Slot::Current, data(5))));
}

#[test]
fn xx_reply_from_another_key_keeps_the_attempt() {
    seed_entropy(42);
    let (mut a, mut b) = established();
    let (aa, ba) = (a.addr(), b.addr());
    let t = 200_000;
    a.poll(t);
    let setup = a.take(MsgKind::Setup).pop().expect("a rekey setup");
    let wake = a.m().next_wake();

    // A third key answers the setup, which names no responder under XX: the
    // ack reads, fails the bond, and changes nothing. No msg3 goes out.
    let stranger = seeded_keypair(66);
    let (_, forged) = Xx::answer(&local(stranger, [0x66; 8], false), &setup).expect("ack");
    a.ack(t + 10, ba, &forged);
    assert_eq!(a.rejects, [Reason::ReplyUnauthenticated]);
    assert!(a.take(MsgKind::Msg3).is_empty(), "no msg3 to a stranger");
    assert_eq!(a.m().view().cycle, CycleView::Init);
    assert_eq!(a.m().next_wake(), wake, "the attempt keeps its deadline");

    // The peer's own answer still completes it.
    b.setup(t + 20, aa, &setup);
    let ack = b.take(MsgKind::Ack).pop().expect("an ack");
    a.ack(t + 30, ba, &ack);
    assert_eq!(a.take(MsgKind::Msg3).len(), 1);
    assert_eq!(a.m().view().cycle, CycleView::PendI(Wait::Evidence));
}
