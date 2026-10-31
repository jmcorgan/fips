//! Tests for `../xx.rs`: the link rekey profile against the handshake and
//! framing next's link code writes and reads, the node-level msg3 read of an
//! inbound leg, and whole link rekeys between two machines on the profile.
//!
//! "Plain" code below is next's link handshake written out with
//! `HandshakeState` and the link codec directly, the way next's shell reads
//! and writes it: framing by `Msg*Header::parse` and `build_msg*`, the
//! negotiation payload after the base message, and the rekey declaration
//! read with `NegotiationPayload::rekey_of`.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use secp256k1::Keypair;

use crate::noise::aead::{Aead, nonce};
use crate::noise::{Fork, HANDSHAKE_MSG2_SIZE, HANDSHAKE_MSG3_SIZE, HandshakeState, NoiseSession};
use crate::proto::fmp::wire::{
    EncryptedHeader, MSG1_WIRE_SIZE, MSG2_WIRE_SIZE, MSG3_WIRE_SIZE, Msg1Header, Msg3Header,
    NegotiationPayload, NodeProfile, build_established_header, build_msg1, build_msg2, build_msg3,
    strip_inner_header,
};
use crate::proto::link::LinkMessageType;
use crate::proto::rekey::{
    Bond, Completed, CycleView, Env, FrameHint, Ids, IndexLease, Input, Intent, JitterSource,
    MsgKind, NodeKeys, Output, Params, PeerKey, Profile, Purpose, Reason, Record, Rekey, Sealed,
    SendCopy, SessionKeys, SetupFacts, Slot, TagSource, Wait, allocate, leaked,
};
use crate::testutil::{SeededEntropy, TestClock, TestInstant, seed_entropy, seeded_keypair};
use crate::time::Duration;
use crate::transport::TransportId;
use crate::utils::index::{IndexAllocator, SessionIndex};

use super::{FmpXx, LinkKeys, LinkLocal, Unread, read_final};

type E = SeededEntropy;
type Xx = FmpXx<E>;
type Hs = HandshakeState<E>;

/// The time trigger at the defaults with no jitter.
const T: u64 = 120_000;

/// The x-only key of a keypair, as the machine holds keys.
fn key(k: &Keypair) -> PeerKey {
    PeerKey::from_xonly(&k.x_only_public_key().0)
}

/// The negotiation payload next's link setup carries for a full node.
fn setup_payload() -> Vec<u8> {
    NegotiationPayload::fmp(1, 1, NodeProfile::Full).encode()
}

/// What next's inbound leg does with a framed msg1: read it on a fresh
/// responder, write msg2 with this node's negotiation payload after it, and
/// frame it with this node's index `ours` and the msg1's sender index.
fn leg_answer(keys: Keypair, epoch: [u8; 8], msg1: &[u8], ours: u32) -> (Hs, Vec<u8>) {
    let h = Msg1Header::parse(msg1).expect("the link parser takes the msg1");
    let mut hs = Hs::new_responder(keys);
    hs.set_local_epoch(epoch);
    hs.read_message_1(&msg1[h.noise_msg1_offset..])
        .expect("the leg reads the msg1");
    let mut noise = hs.write_message_2().expect("msg2");
    noise.extend(hs.encrypt_payload(&setup_payload()).expect("payload"));
    (
        hs,
        build_msg2(SessionIndex::new(ours), h.sender_idx, &noise),
    )
}

/// Next's initiator reading a framed msg2 in place, base message then
/// payload, and writing msg3 with `payload` after it, framed with the
/// msg2's indices.
fn plain_msg3(hs: &mut Hs, msg2: &[u8], payload: &[u8]) -> Vec<u8> {
    let noise = &msg2[12..];
    hs.read_message_2(&noise[..HANDSHAKE_MSG2_SIZE])
        .expect("msg2 reads");
    hs.decrypt_payload(&noise[HANDSHAKE_MSG2_SIZE..])
        .expect("the msg2 payload reads");
    let mut msg3 = hs.write_message_3().expect("msg3");
    msg3.extend(hs.encrypt_payload(payload).expect("payload"));
    let sender = SessionIndex::from_le_bytes(msg2[8..12].try_into().expect("4 bytes"));
    let receiver = SessionIndex::from_le_bytes(msg2[4..8].try_into().expect("4 bytes"));
    build_msg3(sender, receiver, &msg3)
}

/// Next's responder reading a framed msg3 in place, base message then
/// payload: the decoded payload.
fn plain_read3(hs: &mut Hs, msg3: &[u8]) -> NegotiationPayload {
    let h = Msg3Header::parse(msg3).expect("the link parser takes the msg3");
    let noise = &msg3[h.noise_msg3_offset..];
    hs.read_message_3(&noise[..HANDSHAKE_MSG3_SIZE])
        .expect("msg3 reads");
    let payload = hs
        .decrypt_payload(&noise[HANDSHAKE_MSG3_SIZE..])
        .expect("the msg3 payload reads");
    NegotiationPayload::decode(&payload).expect("the payload decodes")
}

/// A link set up by next's plain code: initiator keys `a` in epoch `ae`,
/// responder keys `b` in epoch `be`, with indices `ia` and `ib`. The two
/// sessions, initiator's first.
fn plain_link(
    (a, ae): (Keypair, [u8; 8]),
    (b, be): (Keypair, [u8; 8]),
    ia: u32,
    ib: u32,
) -> (NoiseSession, NoiseSession) {
    let mut ini = Hs::new_initiator(a);
    ini.set_local_epoch(ae);
    let msg1 = build_msg1(SessionIndex::new(ia), &ini.write_message_1().expect("msg1"));
    let (mut resp, msg2) = leg_answer(b, be, &msg1, ib);
    let msg3 = plain_msg3(&mut ini, &msg2, &setup_payload());
    plain_read3(&mut resp, &msg3);
    (
        ini.into_session().expect("complete"),
        resp.into_session().expect("complete"),
    )
}

/// Seal `plaintext` with a reserved send key behind the link header.
fn link_frame(sealed: &Sealed<SendCopy>, plaintext: &[u8]) -> Vec<u8> {
    let header = build_established_header(
        SessionIndex::new(sealed.theirs.unwrap_or(0)),
        sealed.counter,
        u8::from(sealed.k),
        plaintext.len() as u16,
    );
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

/// A link data plaintext: `[ts][0x00][seq]`.
fn data(seq: u8) -> Vec<u8> {
    let mut p = 0u32.to_le_bytes().to_vec();
    p.push(LinkMessageType::SessionDatagram.to_byte());
    p.push(seq);
    p
}

#[test]
fn xx_profile_writes_and_reads_the_handshake_and_frames_next_sends_byte_for_byte() {
    let (ik, rk) = (seeded_keypair(1), seeded_keypair(2));
    let (ie, re) = ([0xa1; 8], [0xb2; 8]);
    let declared = 0x0a0b_0c0d;
    let init = LinkLocal::new(NodeKeys::new(ik, ie), NodeProfile::Full, Some(declared));

    // msg1: the 41-byte link framing around the bare XX msg1, under the
    // index given, the same bytes next's dial writes from the same entropy.
    seed_entropy(3);
    let (hs, msg1) = Xx::initiate(&init, &key(&rk), Some(0x0102_0304)).expect("msg1");
    seed_entropy(3);
    let mut plain = Hs::new_initiator(ik);
    plain.set_local_epoch(ie);
    let plain1 = build_msg1(
        SessionIndex::new(0x0102_0304),
        &plain.write_message_1().expect("msg1"),
    );
    assert_eq!(msg1, plain1, "msg1 is next's dial msg1 byte for byte");
    assert_eq!(msg1.len(), MSG1_WIRE_SIZE);
    assert!(
        Xx::initiate(&init, &key(&rk), None).is_err(),
        "an attempt needs an index"
    );

    // msg2: next's leg answers it with its payload; the reply routes by the
    // receiver index.
    let (mut leg, msg2) = leg_answer(rk, re, &msg1, 0x0506_0708);
    assert!(msg2.len() > MSG2_WIRE_SIZE, "next's msg2 carries a payload");
    assert_eq!(Xx::index(&msg2), Some(0x0102_0304));

    // A failed read leaves the attempt readable; the genuine msg2 reads to
    // the responder's static and epoch and the index it chose.
    let mut bad = msg2.clone();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(Xx::reply(&hs, &init, &bad).is_err());
    let read = Xx::reply(&hs, &init, &msg2).expect("the failed read left it readable");
    assert_eq!(read.done.epoch, re);
    assert_eq!(read.done.remote, key(&rk));
    assert_eq!(read.done.theirs, Some(0x0506_0708));
    let without = LinkLocal::new(NodeKeys::new(ik, ie), NodeProfile::Full, None);
    assert!(
        Xx::reply(&hs, &without, &msg2).is_err(),
        "a reply with no session to declare is refused, never sent undeclared"
    );

    // msg3: next's rekey msg3 byte for byte (msg3 draws no randomness), and
    // next's responder reads it, payload and declaration included.
    let fin = read.fin.expect("XX has a msg3");
    let plain3 = plain_msg3(
        &mut plain,
        &msg2,
        &NegotiationPayload::fmp(1, 1, NodeProfile::Full)
            .with_rekey_of(SessionIndex::new(declared))
            .encode(),
    );
    assert_eq!(fin, plain3, "msg3 is next's rekey msg3 byte for byte");
    assert!(fin.len() > MSG3_WIRE_SIZE);
    let h3 = Msg3Header::parse(&fin).expect("the link parser takes it");
    assert_eq!(h3.sender_idx.as_u32(), 0x0102_0304);
    assert_eq!(h3.receiver_idx.as_u32(), 0x0506_0708);
    let unread_leg = leg.fork();
    let neg = plain_read3(&mut leg, &fin);
    assert_eq!(
        neg.rekey_of().expect("well formed"),
        Some(SessionIndex::new(declared))
    );
    assert_eq!(neg.node_profile().expect("a profile"), NodeProfile::Full);

    // The leg's node-level read takes the same msg3 to the same facts, and
    // a tampered copy hands the lease back and leaves the leg readable.
    let lease = IndexLease::for_test(0x0506_0708);
    let mut tampered = fin.clone();
    tampered[20] ^= 1;
    let Err(Unread(back)) = read_final(&unread_leg, &tampered, Some(lease)) else {
        panic!("a tampered msg3 must not read");
    };
    let fin_read = read_final(&unread_leg, &fin, back).expect("the leg is still readable");
    assert_eq!(
        fin_read.remote().x_only_public_key().0,
        ik.x_only_public_key().0
    );
    assert_eq!(fin_read.epoch(), ie);
    assert_eq!(fin_read.theirs().as_u32(), 0x0102_0304);
    assert_eq!(
        fin_read.declared().expect("well formed"),
        Some(SessionIndex::new(declared))
    );
    assert_eq!(
        fin_read.negotiate(NodeProfile::Full).expect("valid"),
        Some(NodeProfile::Full)
    );
    let (lsession, lease) = fin_read.into_setup();
    let _ = lease.expect("the lease rides through").release();

    // Frames: what the profile's session seals opens under next's plain
    // session over the 16-byte header, and back.
    let mut ikeys = read.done.session;
    let (counter, send) = ikeys.reserve();
    assert_eq!(counter, 0, "counters start at 0 in every session");
    let plaintext = data(7);
    let sealed = Sealed {
        tag: TagSource::new().draw(),
        k: false,
        counter,
        elapsed: Duration::ZERO,
        theirs: Some(0x0506_0708),
        key: send,
    };
    let frame = link_frame(&sealed, &plaintext);
    let mut rsession = leg.into_session().expect("complete");
    assert_eq!(
        rsession
            .decrypt_with_replay_check_and_aad(&frame[16..], counter, &frame[..16])
            .expect("next's session opens the profile's frame"),
        plaintext
    );
    assert_eq!(
        lsession.handshake_hash(),
        rsession.handshake_hash(),
        "the leg's read reaches the plain responder's session"
    );
    let header =
        build_established_header(SessionIndex::new(0x0102_0304), 0, 0, plaintext.len() as u16);
    let ct = rsession
        .encrypt_with_aad(&plaintext, &header)
        .expect("seals");
    let mut back = header.to_vec();
    back.extend_from_slice(&ct);
    let hint = FrameHint {
        counter: 0,
        k: false,
        index: 0x0102_0304,
        body: 16,
    };
    let mut out = Vec::new();
    assert!(
        ikeys.open(&hint, &back, &mut out),
        "and the profile opens next's"
    );
    assert_eq!(out, plaintext);

    // The prompt is a Heartbeat under the inner header.
    let mut prompt = Vec::new();
    Xx::prompt(Duration::from_millis(70_000), &mut prompt);
    let (ts, msg) = strip_inner_header(&prompt).expect("the link parser takes it");
    assert_eq!(ts, 70_000);
    assert_eq!(msg, [LinkMessageType::Heartbeat.to_byte()]);
    assert!(prompt.len() >= Xx::FLOOR);
    assert!(!Xx::is_probe(&prompt), "a link has no probe");
}

#[test]
fn xx_reply_reads_the_payload_on_its_fork() {
    let (ik, rk) = (seeded_keypair(11), seeded_keypair(12));
    let init = LinkLocal::new(NodeKeys::new(ik, [1; 8]), NodeProfile::Full, Some(9));
    seed_entropy(4);
    let (hs, msg1) = Xx::initiate(&init, &key(&rk), Some(5)).expect("msg1");

    // The msg3 the profile writes after a msg2 with a payload is read,
    // payload included, by a plain responder, which ends on the same
    // handshake hash.
    let (mut leg, msg2) = leg_answer(rk, [2; 8], &msg1, 6);
    let read = Xx::reply(&hs, &init, &msg2).expect("reads");
    let fin = read.fin.expect("msg3");
    plain_read3(&mut leg, &fin);
    assert_eq!(
        read.done.session.session().handshake_hash(),
        &leg.handshake_hash(),
        "both ends mixed the same transcript"
    );

    // The other way: the leg's read takes a plain initiator's msg3 with its
    // payload to the plain initiator's hash.
    let mut plain = Hs::new_initiator(ik);
    plain.set_local_epoch([1; 8]);
    let msg1 = build_msg1(
        SessionIndex::new(5),
        &plain.write_message_1().expect("msg1"),
    );
    let (leg, msg2) = leg_answer(rk, [2; 8], &msg1, 6);
    let msg3 = plain_msg3(&mut plain, &msg2, &setup_payload());
    let (session, lease) = read_final(&leg, &msg3, None)
        .expect("the leg reads it")
        .into_setup();
    assert!(lease.is_none());
    assert_eq!(session.handshake_hash(), &plain.handshake_hash());
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

/// One end of a link: a machine on `FmpXx` and the little a shell keeps
/// beside it, the index map its `Bind` and `Unbind` outputs maintain and
/// the allocator its leases come from.
struct Node {
    m: Rekey<Xx, TestClock>,
    kp: Keypair,
    epoch: [u8; 8],
    alloc: IndexAllocator<E>,
    tags: TagSource,
    jitter: Fixed,
    scratch: Vec<u8>,
    bound: BTreeMap<u32, Purpose>,
    /// Handshake messages sent, oldest first.
    sent: Vec<(MsgKind, Vec<u8>)>,
    /// Prompt frames sealed, oldest first.
    prompts: Vec<Vec<u8>>,
    rejects: Vec<Reason>,
    installs: usize,
}

/// What link setup hands one end's machine.
struct Setup {
    kp: Keypair,
    epoch: [u8; 8],
    peer: PeerKey,
    peer_epoch: [u8; 8],
    session: NoiseSession,
    alloc: IndexAllocator<E>,
    lease: IndexLease,
    theirs: u32,
}

impl Node {
    /// A node whose link was set up at 0 as `s` says, drawing `jitter`.
    fn new(s: Setup, jitter: u16) -> Self {
        let Setup {
            kp,
            epoch,
            peer,
            peer_epoch,
            session,
            mut alloc,
            lease,
            theirs,
        } = s;
        let done = Completed::<Xx> {
            session: alloc::boxed::Box::new(LinkKeys::new(session)),
            remote: peer,
            epoch: peer_epoch,
            theirs: Some(theirs),
        };
        let bonded = Bond::Key(peer).check(done).expect("the link setup bonds");
        let facts = SetupFacts {
            peer_epoch: Some(peer_epoch),
            k: false,
            link_since: TestInstant(0),
            started: TestInstant(0),
            peer_k: None,
            last_rx: None,
            record: Record::new(),
        };
        let mut tags = TagSource::new();
        let mut scratch = Vec::new();
        let mut jit = Fixed(jitter);
        let local = LinkLocal::new(NodeKeys::new(kp, epoch), NodeProfile::Full, None);
        let (m, out) = {
            let mut env = Env {
                indices: &mut alloc,
                transport: TransportId::new(1),
                tags: &mut tags,
                workers: false,
                jitter: &mut jit,
                local: &local,
                scratch: &mut scratch,
            };
            Rekey::established(
                Params::fmp(),
                Bond::Key(peer),
                key(&kp).addr(),
                bonded,
                Ids::new(lease, theirs, TransportId::new(1)),
                facts,
                TestInstant(0),
                &mut env,
            )
        };
        let mut n = Self {
            m,
            kp,
            epoch,
            alloc,
            tags,
            jitter: jit,
            scratch,
            bound: BTreeMap::new(),
            sent: Vec::new(),
            prompts: Vec::new(),
            rejects: Vec::new(),
            installs: 0,
        };
        n.run(0, out);
        n
    }

    /// Step the machine with `input` at `now`, with the local keys a shell
    /// builds per call: the index to declare is the peer's index of the
    /// current epoch.
    fn step(&mut self, now: u64, input: Input<'_, Xx>) -> Vec<Output<Xx>> {
        let local = LinkLocal::new(
            NodeKeys::new(self.kp, self.epoch),
            NodeProfile::Full,
            self.m.theirs(Slot::Current),
        );
        let mut env = Env {
            indices: &mut self.alloc,
            transport: TransportId::new(1),
            tags: &mut self.tags,
            workers: false,
            jitter: &mut self.jitter,
            local: &local,
            scratch: &mut self.scratch,
        };
        self.m.step(TestInstant(now), input, &mut env)
    }

    /// Poll at `now`.
    fn poll(&mut self, now: u64) {
        let out = self.step(now, Input::Poll);
        self.run(now, out);
    }

    /// Execute outputs front to back, as the shell does.
    fn run(&mut self, now: u64, outputs: Vec<Output<Xx>>) {
        for o in outputs {
            match o {
                Output::Send { msg, kind, .. } => self.sent.push((kind, msg)),
                Output::Prompt { tag } => {
                    let p = self.m.seal_prompt(TestInstant(now), tag).expect("seals");
                    self.prompts.push(link_frame(&p.sealed, &p.plaintext));
                }
                Output::Bind { index, purpose, .. } => {
                    self.bound.insert(index, purpose);
                }
                Output::Unbind { index, .. } => {
                    self.bound.remove(&index);
                }
                Output::Release(lease) => {
                    self.alloc
                        .free(SessionIndex::new(lease.release()))
                        .expect("a released index was allocated");
                }
                Output::Delegate { .. } | Output::Revoke { .. } => {
                    panic!("a node with no decrypt workers was asked to delegate")
                }
                Output::Reject(r) => self.rejects.push(r),
                Output::Installed { .. } => self.installs += 1,
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

    /// Seal a data frame under the current epoch.
    fn data(&mut self, now: u64, seq: u8) -> Vec<u8> {
        let s = self.m.seal(TestInstant(now)).expect("seals");
        link_frame(&s, &data(seq))
    }

    /// Receive a link frame or a msg2; return what a frame delivered.
    fn recv(&mut self, now: u64, bytes: &[u8]) -> Option<(Slot, Vec<u8>)> {
        if bytes[0] & 0x0f == 2 {
            let out = self.step(now, Input::Reply { bytes, route: () });
            self.run(now, out);
            return None;
        }
        let h = EncryptedHeader::parse(bytes).expect("a frame");
        if !self.bound.contains_key(&h.receiver_idx.as_u32()) {
            return None;
        }
        let hint = FrameHint {
            counter: h.counter,
            k: h.flags & 1 != 0,
            index: h.receiver_idx.as_u32(),
            body: h.ciphertext_offset(),
        };
        let mut buf = bytes.to_vec();
        let out = self.step(
            now,
            Input::Frame {
                buf: &mut buf,
                hint,
            },
        );
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

    /// Hand the machine a leg's completion of the peer's rekey on `msg3`,
    /// as the leg table does once the declaration matches.
    fn leg_done(&mut self, now: u64, leg: &Hs, msg3: &[u8], lease: IndexLease) {
        let fin = read_final(leg, msg3, Some(lease)).expect("the leg reads the msg3");
        assert_eq!(
            fin.declared().expect("well formed").map(|i| i.as_u32()),
            self.m.ours(Slot::Current),
            "the declaration names this node's index of the current session"
        );
        let out = self.step(
            now,
            Input::PeerDone {
                tok: fin.into_rekey(),
                intent: Intent::Rekey,
            },
        );
        self.run(now, out);
    }

    /// Indices held by the allocator against indices the machine binds.
    fn conserved(&self) {
        let mut bound: Vec<u32> = self.m.bindings().iter().map(|b| b.index).collect();
        bound.sort_unstable();
        let mapped: Vec<u32> = self.bound.keys().copied().collect();
        assert_eq!(bound, mapped, "the index map follows the bindings");
        assert_eq!(self.alloc.count(), bound.len(), "no index leaked");
    }
}

/// Two ends of a link set up at 0 by next's plain code, `a` the dialer.
/// `a` draws no jitter and `b` the band's top, so only `a` falls due at
/// [`T`].
fn link() -> (Node, Node) {
    seed_entropy(30);
    let (ak, bk) = (seeded_keypair(21), seeded_keypair(22));
    let (ae, be) = ([0xa1; 8], [0xb2; 8]);
    let mut aa = IndexAllocator::<E>::new();
    let mut ba = IndexAllocator::<E>::new();
    let la = allocate(&mut aa).expect("an index");
    let lb = allocate(&mut ba).expect("an index");
    let (ia, ib) = (la.index(), lb.index());
    let (sa, sb) = plain_link((ak, ae), (bk, be), ia, ib);
    let a = Node::new(
        Setup {
            kp: ak,
            epoch: ae,
            peer: key(&bk),
            peer_epoch: be,
            session: sa,
            alloc: aa,
            lease: la,
            theirs: ib,
        },
        15,
    );
    let b = Node::new(
        Setup {
            kp: bk,
            epoch: be,
            peer: key(&ak),
            peer_epoch: ae,
            session: sb,
            alloc: ba,
            lease: lb,
            theirs: ia,
        },
        30,
    );
    (a, b)
}

/// `b`'s leg answering a rekey msg1 with a leased index, as next's inbound
/// leg does.
fn answer(b: &mut Node, msg1: &[u8]) -> (Hs, IndexLease, Vec<u8>) {
    let lease = allocate(&mut b.alloc).expect("an index");
    let (hs, msg2) = leg_answer(b.kp, b.epoch, msg1, lease.index());
    (hs, lease, msg2)
}

#[test]
fn two_xx_link_machines_rekey_through_a_leg_and_the_delayed_cutover() {
    let (mut a, mut b) = link();
    // Each end's first frames find the other's current epoch.
    let f = a.data(1_000, 1);
    assert_eq!(b.recv(1_000, &f), Some((Slot::Current, data(1))));
    let f = b.data(1_000, 2);
    assert_eq!(a.recv(1_000, &f), Some((Slot::Current, data(2))));

    // A's poll starts its rekey; B's leg answers with a leased index; A
    // reads the reply and holds the new epoch for its delay with msg3 sent.
    a.poll(T);
    let msg1 = a.take(MsgKind::Setup).pop().expect("a rekey msg1");
    assert_eq!(a.m.view().cycle, CycleView::Init);
    let (leg, lease, msg2) = answer(&mut b, &msg1);
    a.recv(T + 10, &msg2);
    let msg3 = a.take(MsgKind::Msg3).pop().expect("msg3");
    assert_eq!(a.m.view().cycle, CycleView::PendI(Wait::Delay));

    // B's leg reads msg3 and hands B's machine the completion as a rekey:
    // it binds the leg's index as its pending.
    let leg_index = lease.index();
    b.leg_done(T + 20, &leg, &msg3, lease);
    assert_eq!(b.m.view().cycle, CycleView::PendR);
    assert_eq!(b.bound.get(&leg_index), Some(&Purpose::Pending));

    // A cuts over only once its delay has passed, keeping msg3.
    a.poll(T + 10 + 1_999);
    assert_eq!(a.installs, 0, "still on the first epoch inside the delay");
    a.poll(T + 10 + 2_000);
    assert_eq!(a.installs, 1, "cut over after the delay");
    a.poll(T + 10 + 3_000);
    assert_eq!(
        a.take(MsgKind::Msg3),
        [msg3.clone(), msg3.clone()],
        "msg3 is resent at 1 s and 3 s while the peer is unheard"
    );

    // A's prompt under the new epoch makes B adopt its pending, and B's
    // frames under it are the first A hears, which drop the retained msg3.
    let prompt = a.prompts.remove(0);
    assert!(
        b.recv(T + 10 + 3_010, &prompt).is_some(),
        "the prompt opens"
    );
    assert_eq!(b.installs, 1, "B adopted on A's frame");
    for p in core::mem::take(&mut b.prompts) {
        a.recv(T + 10 + 3_020, &p);
    }
    a.poll(T + 10 + 15_000);
    assert!(a.take(MsgKind::Msg3).is_empty(), "no msg3 once B is heard");

    // Frames open at both ends under the new epoch.
    let f = a.data(T + 20_000, 3);
    assert_eq!(b.recv(T + 20_000, &f), Some((Slot::Current, data(3))));
    let f = b.data(T + 20_000, 4);
    assert_eq!(a.recv(T + 20_000, &f), Some((Slot::Current, data(4))));
    a.conserved();
    b.conserved();
    assert_eq!(leaked(), 0);
}

#[test]
fn lost_xx_final_is_resent_until_heard() {
    let (mut a, mut b) = link();
    a.poll(T);
    let msg1 = a.take(MsgKind::Setup).pop().expect("a rekey msg1");
    let (leg, lease, msg2) = answer(&mut b, &msg1);
    a.recv(T + 10, &msg2);
    // The first msg3 is lost.
    assert_eq!(a.take(MsgKind::Msg3).len(), 1);

    // A resends it while it waits out its delay and after its cutover; its
    // frames under the new epoch find nothing bound at B meanwhile.
    a.poll(T + 10 + 1_000);
    a.poll(T + 10 + 2_000);
    assert_eq!(a.installs, 1, "A cut over after its delay");
    let early = a.data(T + 10 + 2_001, 5);
    assert_eq!(b.recv(T + 10 + 2_002, &early), None);
    a.poll(T + 10 + 3_000);
    let resent = a.take(MsgKind::Msg3);
    assert_eq!(resent.len(), 2, "resent at 1 s and 3 s");

    // A resend completes B's leg; A's next frame makes B adopt it.
    b.leg_done(T + 10 + 3_010, &leg, &resent[1], lease);
    assert_eq!(b.m.view().cycle, CycleView::PendR);
    let f = a.data(T + 10 + 3_020, 6);
    assert_eq!(b.recv(T + 10 + 3_020, &f), Some((Slot::Current, data(6))));
    let f = b.data(T + 10 + 3_030, 7);
    assert_eq!(a.recv(T + 10 + 3_030, &f), Some((Slot::Current, data(7))));

    // Heard: no further resend on the rest of the ladder.
    for s in [7_000, 15_000, 31_000] {
        a.poll(T + 10 + s);
    }
    assert!(a.take(MsgKind::Msg3).is_empty(), "no msg3 once B is heard");
    a.conserved();
    b.conserved();
    assert_eq!(leaked(), 0);
}

#[test]
fn xx_rekey_reply_from_another_key_keeps_the_attempt() {
    let (mut a, mut b) = link();
    a.poll(T);
    let msg1 = a.take(MsgKind::Setup).pop().expect("a rekey msg1");
    let wake = a.m.next_wake();

    // A third key answers the msg1, which names no responder: the reply
    // reads, fails the bond, and changes nothing. No msg3 goes out.
    let (_, forged) = leg_answer(seeded_keypair(66), [0x66; 8], &msg1, 0x6666);
    a.recv(T + 10, &forged);
    assert_eq!(a.rejects, [Reason::ReplyUnauthenticated]);
    assert!(a.take(MsgKind::Msg3).is_empty(), "no msg3 to a stranger");
    assert_eq!(a.m.view().cycle, CycleView::Init);
    assert_eq!(a.m.next_wake(), wake, "the attempt keeps its deadline");

    // The peer's own answer still completes it.
    let (_, lease, msg2) = answer(&mut b, &msg1);
    a.recv(T + 20, &msg2);
    assert_eq!(a.take(MsgKind::Msg3).len(), 1);
    assert_eq!(a.m.view().cycle, CycleView::PendI(Wait::Delay));
    b.alloc
        .free(SessionIndex::new(lease.release()))
        .expect("freed");
}
