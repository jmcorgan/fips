//! Stub profiles and a test shell for the rekey machine.
//!
//! The stub handshakes stand in for Noise: an ephemeral is an attempt
//! identifier drawn from a per-node counter, a static key is 32 bytes, and
//! every message carries a keyed hash over its transcript instead of an
//! AEAD tag. That makes a forged message (bad hash), a replay (a copy), a
//! corrupt message (a flipped byte) and an identity mismatch (a valid
//! transcript under another static) all easy to build, keeps every step
//! fast and deterministic, and lets states be compared without key material.
//!
//! Four profiles: [`Ik`] (two messages, indexed, the master link shape),
//! [`Xk`] (three messages with candidates, the master session shape),
//! [`XkFrame`] (as `Xk` with a responder that cuts over on a frame) and
//! [`Xx`] (three messages, indexed, a delayed initiator cutover and a leg
//! table's completions, the dormant next-only rows).
//!
//! [`Node`] is a test shell: it owns a machine and the capabilities its
//! `Env` lends, executes outputs (returning leases to its pool, sealing
//! prompts, collecting sends) and records them as comparable [`Ev`]s.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::Cell;
use core::convert::Infallible;

use sha2::{Digest as _, Sha256};

use super::super::{
    Abandon, Authentic, Bond, Commit, Completed, Config, CycleView, DampenAt, Digest, DoneRead,
    Env, EpochTag, EvidenceKind, FrameHint, Fresh, HsError, Ids, IndexLease, IndexSource,
    InitiatorCutover, Input, JitterSource, Layer, Leg, Msg1Read, MsgKind, Output, Params, PeerKey,
    Profile, Purpose, Read, Reason, Record, Rekey, Replayable, ResponderCutover, Role, Route,
    Sealed, Select, SessionKeys, SetupFacts, Slot, TagSource, Teardown, Wire, allocate,
};
use crate::identity::NodeAddr;
use crate::noise::Fork;
use crate::testutil::{SplitMix64, TestClock, TestInstant};
use crate::time::Duration;

/// The first eight bytes of a SHA-256 over length-prefixed parts.
fn mac(parts: &[&[u8]]) -> [u8; 8] {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u32).to_le_bytes());
        h.update(p);
    }
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// A SHA-256 digest.
pub(crate) fn digest(bytes: &[u8]) -> Digest {
    Digest(Sha256::digest(bytes).into())
}

/// A node's static key and startup epoch, and the counter its ephemerals
/// are drawn from.
#[derive(Debug)]
pub(crate) struct Local {
    pub(crate) key: PeerKey,
    pub(crate) epoch: [u8; 8],
    next: Cell<u64>,
}

impl Local {
    /// The node made from `seed`, in startup epoch `epoch`.
    pub(crate) fn new(seed: u8, epoch: u8) -> Self {
        let x: [u8; 32] = Sha256::digest([seed]).into();
        Self {
            key: PeerKey::new(x),
            epoch: [epoch; 8],
            next: Cell::new(0),
        }
    }

    /// The node's address.
    pub(crate) fn addr(&self) -> NodeAddr {
        self.key.addr()
    }

    /// A fresh ephemeral.
    fn eph(&self) -> [u8; 8] {
        let n = self.next.get() + 1;
        self.next.set(n);
        mac(&[b"eph", self.key.bytes(), &n.to_le_bytes()])
    }

    /// The same node after a restart: same key, a new startup epoch.
    pub(crate) fn restarted(&self, epoch: u8) -> Self {
        Self {
            key: self.key,
            epoch: [epoch; 8],
            next: Cell::new(self.next.get() + 1000),
        }
    }
}

/// Two nodes, the first with the smaller address.
pub(crate) fn ordered(a: u8, b: u8) -> (Local, Local) {
    let (x, y) = (Local::new(a, a), Local::new(b, b));
    if x.addr() < y.addr() { (x, y) } else { (y, x) }
}

/// A stub handshake state.
#[derive(Clone, Debug)]
pub(crate) struct Hs {
    me: PeerKey,
    peer: Option<PeerKey>,
    epoch: [u8; 8],
    ei: [u8; 8],
    er: [u8; 8],
    ours: Option<u32>,
}

impl Fork for Hs {
    fn fork(&self) -> Self {
        self.clone()
    }
}

/// The keys a stub handshake derives: initiator to responder, and back.
fn keys(ei: &[u8; 8], er: &[u8; 8]) -> ([u8; 8], [u8; 8]) {
    (mac(&[b"ir", ei, er]), mac(&[b"ri", ei, er]))
}

/// A stub transport session.
#[derive(Debug)]
pub(crate) struct Sess {
    tx: [u8; 8],
    rx: [u8; 8],
    sent: u64,
    seen: BTreeSet<u64>,
    highest: Option<u64>,
}

/// The replay window's width.
const WINDOW: u64 = 64;

std::thread_local! {
    /// How many frames this thread's stub sessions failed to open.
    static FAILED: Cell<u32> = const { Cell::new(0) };
}

/// The frames this thread's stub sessions failed to open since the last
/// call, so a test can see which epochs a frame was tried under.
pub(crate) fn failed() -> u32 {
    FAILED.with(|f| f.replace(0))
}

impl Sess {
    /// The session of one side of a handshake with ephemerals `ei`, `er`.
    fn new(role: Role, ei: &[u8; 8], er: &[u8; 8]) -> Self {
        let (ir, ri) = keys(ei, er);
        let (tx, rx) = match role {
            Role::Initiator => (ir, ri),
            Role::Responder => (ri, ir),
        };
        Self {
            tx,
            rx,
            sent: 0,
            seen: BTreeSet::new(),
            highest: None,
        }
    }
}

/// The send key handed out for one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SendKey {
    key: [u8; 8],
}

/// The receive half handed to a worker.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RecvKey {
    pub(crate) key: [u8; 8],
    pub(crate) floor: Option<u64>,
    pub(crate) highest: Option<u64>,
}

/// The stub frame header: receiver index, counter, key-epoch bit.
pub(crate) const HEADER: usize = 4 + 8 + 1;

/// The keystream of a frame under `key` with `counter`, `len` bytes: one
/// hash per 32-byte block.
fn stream(key: &[u8; 8], counter: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block = 0u64;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"ks");
        h.update(key);
        h.update(counter.to_le_bytes());
        h.update(block.to_le_bytes());
        out.extend_from_slice(&h.finalize());
        block += 1;
    }
    out.truncate(len);
    out
}

/// Seal `plaintext` under `key` with the header fields.
fn seal_with(key: &[u8; 8], index: u32, counter: u64, k: bool, plaintext: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&index.to_le_bytes());
    f.extend_from_slice(&counter.to_le_bytes());
    f.push(u8::from(k));
    let tag = mac(&[b"frame", key, &f, plaintext]);
    let ks = stream(key, counter, plaintext.len());
    f.extend(plaintext.iter().zip(&ks).map(|(b, k)| b ^ k));
    f.extend_from_slice(&tag);
    f
}

/// Build a frame from a seal reservation.
pub(crate) fn frame(sealed: &Sealed<SendKey>, plaintext: &[u8]) -> Vec<u8> {
    seal_with(
        &sealed.key.key,
        sealed.theirs.unwrap_or(0),
        sealed.counter,
        sealed.k,
        plaintext,
    )
}

/// Parse a stub frame's header.
pub(crate) fn hint(frame: &[u8]) -> FrameHint {
    let mut index = [0u8; 4];
    let mut counter = [0u8; 8];
    index.copy_from_slice(&frame[..4]);
    counter.copy_from_slice(&frame[4..12]);
    FrameHint {
        counter: u64::from_le_bytes(counter),
        k: frame[12] != 0,
        index: u32::from_le_bytes(index),
        body: HEADER,
    }
}

/// The identity of a stub session's keys, the same at both ends of the
/// handshake that made them, so two machines' epochs can be matched.
pub(crate) type Kid = ([u8; 8], [u8; 8]);

/// The identity of `s`'s keys: its two directions' keys in a fixed order.
pub(crate) fn kid(s: &Sess) -> Kid {
    if s.tx <= s.rx {
        (s.tx, s.rx)
    } else {
        (s.rx, s.tx)
    }
}

/// Open `frame` with a worker's receive copy, as a decrypt worker does:
/// the header and the plaintext, or `None` when the key does not
/// authenticate it.
pub(crate) fn worker_open(recv: &RecvKey, frame: &[u8]) -> Option<(FrameHint, Vec<u8>)> {
    if frame.len() < HEADER + 8 {
        return None;
    }
    let h = hint(frame);
    let (ct, tag) = frame[HEADER..].split_at(frame.len() - HEADER - 8);
    let ks = stream(&recv.key, h.counter, ct.len());
    let plain: Vec<u8> = ct.iter().zip(&ks).map(|(b, k)| b ^ k).collect();
    (mac(&[b"frame", &recv.key, &frame[..HEADER], &plain]) == tag).then_some((h, plain))
}

impl SessionKeys for Sess {
    type RecvCopy = RecvKey;
    type SendCopy = SendKey;

    fn open(&self, hint: &FrameHint, frame: &[u8], out: &mut Vec<u8>) -> bool {
        let Some(body) = frame.get(hint.body..) else {
            return false;
        };
        if body.len() < 8 {
            return false;
        }
        let (ct, tag) = body.split_at(body.len() - 8);
        out.clear();
        let ks = stream(&self.rx, hint.counter, ct.len());
        out.extend(ct.iter().zip(&ks).map(|(b, k)| b ^ k));
        let ok = mac(&[b"frame", &self.rx, &frame[..hint.body], out]) == tag;
        if !ok {
            out.clear();
            FAILED.with(|f| f.set(f.get() + 1));
        }
        ok
    }

    fn fresh(&self, counter: u64) -> bool {
        if counter == u64::MAX || self.seen.contains(&counter) {
            return false;
        }
        self.highest
            .is_none_or(|h| h < WINDOW || counter > h - WINDOW)
    }

    fn mark(&mut self, counter: u64) {
        self.seen.insert(counter);
        let h = self.highest.map_or(counter, |h| h.max(counter));
        self.highest = Some(h);
        if h >= WINDOW {
            self.seen.retain(|&c| c > h - WINDOW);
        }
    }

    fn sent(&self) -> u64 {
        self.sent
    }

    fn reserve(&mut self) -> (u64, SendKey) {
        let c = self.sent;
        self.sent = self.sent.saturating_add(1);
        (c, SendKey { key: self.tx })
    }

    fn copy(&self, floor: Option<u64>) -> RecvKey {
        RecvKey {
            key: self.rx,
            floor,
            highest: self.highest,
        }
    }
}

/// An index pool, the stub allocator.
#[derive(Debug, Default)]
pub(crate) struct Pool {
    next: u32,
    pub(crate) used: BTreeSet<u32>,
    pub(crate) dry: bool,
}

impl Pool {
    /// A pool drawing from `base` up.
    pub(crate) fn new(base: u32) -> Self {
        Self {
            next: base,
            used: BTreeSet::new(),
            dry: false,
        }
    }

    /// Return an index.
    pub(crate) fn free(&mut self, index: u32) {
        assert!(
            self.used.remove(&index),
            "index {index} freed but not in use"
        );
    }
}

impl IndexSource for Pool {
    fn draw(&mut self) -> Option<u32> {
        if self.dry {
            return None;
        }
        let i = self.next;
        self.next += 1;
        self.used.insert(i);
        Some(i)
    }
}

/// Parse `n` bytes from `bytes` at `at`.
fn take<const N: usize>(bytes: &[u8], at: usize) -> Option<[u8; N]> {
    bytes.get(at..at + N)?.try_into().ok()
}

/// An IK msg1 read at node level.
#[derive(Debug)]
pub(crate) struct Msg1 {
    ei: [u8; 8],
    remote: PeerKey,
    epoch: [u8; 8],
    theirs: u32,
    whole: Digest,
}

/// A leg table's completion (next only).
#[derive(Debug)]
pub(crate) struct Done {
    done: Completed<Xx>,
    lease: Option<IndexLease>,
}

/// Write an initiator's msg1: `[1][ours?][ei]` and, for IK, the static,
/// epoch and a hash keyed to the responder's static.
fn msg1(indexed: bool, ik: bool, local: &Local, peer: &PeerKey, ours: Option<u32>) -> (Hs, Wire) {
    let ei = local.eph();
    let mut m = alloc::vec![1u8];
    if indexed {
        m.extend_from_slice(&ours.unwrap_or(0).to_le_bytes());
    }
    m.extend_from_slice(&ei);
    if ik {
        m.extend_from_slice(local.key.bytes());
        m.extend_from_slice(&local.epoch);
        let t = mac(&[b"m1", peer.bytes(), &ei, local.key.bytes(), &local.epoch]);
        m.extend_from_slice(&t);
    }
    let hs = Hs {
        me: local.key,
        peer: Some(*peer),
        epoch: local.epoch,
        ei,
        er: [0; 8],
        ours,
    };
    (hs, m)
}

/// Write a responder's msg2: `[2][ours?][theirs?][er][static][epoch][hash]`.
fn msg2(
    indexed: bool,
    me: &Local,
    ei: &[u8; 8],
    ours: Option<u32>,
    theirs: Option<u32>,
) -> ([u8; 8], Wire) {
    let er = me.eph();
    let mut m = alloc::vec![2u8];
    if indexed {
        m.extend_from_slice(&ours.unwrap_or(0).to_le_bytes());
        m.extend_from_slice(&theirs.unwrap_or(0).to_le_bytes());
    }
    m.extend_from_slice(&er);
    m.extend_from_slice(me.key.bytes());
    m.extend_from_slice(&me.epoch);
    let t = mac(&[b"m2", ei, &er, me.key.bytes(), &me.epoch]);
    m.extend_from_slice(&t);
    (er, m)
}

/// What reading a msg2 gives: the remote static, the responder ephemeral,
/// the remote epoch and the responder's index.
type Reply2 = (PeerKey, [u8; 8], [u8; 8], Option<u32>);

/// Read a msg2 on a fork of `hs`; `pinned` refuses another static.
fn read2(indexed: bool, pinned: bool, hs: &Hs, bytes: &[u8]) -> Result<Reply2, HsError> {
    let at = if indexed { 9 } else { 1 };
    if bytes.first() != Some(&2) || bytes.len() != at + 8 + 32 + 8 + 8 {
        return Err(HsError);
    }
    let er: [u8; 8] = take(bytes, at).ok_or(HsError)?;
    let x: [u8; 32] = take(bytes, at + 8).ok_or(HsError)?;
    let epoch: [u8; 8] = take(bytes, at + 40).ok_or(HsError)?;
    let t: [u8; 8] = take(bytes, at + 48).ok_or(HsError)?;
    if mac(&[b"m2", &hs.ei, &er, &x, &epoch]) != t {
        return Err(HsError);
    }
    let remote = PeerKey::new(x);
    if pinned && hs.peer != Some(remote) {
        return Err(HsError);
    }
    let theirs = if indexed {
        take::<4>(bytes, 1).map(u32::from_le_bytes)
    } else {
        None
    };
    Ok((remote, er, epoch, theirs))
}

/// Write an initiator's msg3: `[3][static][epoch][hash]`.
fn msg3(hs: &Hs, er: &[u8; 8]) -> Wire {
    let mut m = alloc::vec![3u8];
    m.extend_from_slice(hs.me.bytes());
    m.extend_from_slice(&hs.epoch);
    let t = mac(&[b"m3", &hs.ei, er, hs.me.bytes(), &hs.epoch]);
    m.extend_from_slice(&t);
    m
}

/// A msg3 for the exchange `ei`, `er`, written by `local`: genuine when
/// `local` is the initiator, an identity mismatch otherwise.
pub(crate) fn forge3(local: &Local, ei: [u8; 8], er: [u8; 8]) -> Wire {
    let hs = Hs {
        me: local.key,
        peer: None,
        epoch: local.epoch,
        ei,
        er,
        ours: None,
    };
    msg3(&hs, &er)
}

/// The ephemerals of an XK exchange, from its setup and ack.
pub(crate) fn ephemerals(setup: &[u8], ack: &[u8]) -> ([u8; 8], [u8; 8]) {
    (
        take(setup, 1).unwrap_or_default(),
        take(ack, 1).unwrap_or_default(),
    )
}

/// Read a msg3 on a fork of a responder handshake.
fn read3(hs: &Hs, bytes: &[u8]) -> Result<(PeerKey, [u8; 8]), HsError> {
    if bytes.first() != Some(&3) || bytes.len() != 1 + 32 + 8 + 8 {
        return Err(HsError);
    }
    let x: [u8; 32] = take(bytes, 1).ok_or(HsError)?;
    let epoch: [u8; 8] = take(bytes, 33).ok_or(HsError)?;
    let t: [u8; 8] = take(bytes, 41).ok_or(HsError)?;
    if mac(&[b"m3", &hs.ei, &hs.er, &x, &epoch]) != t {
        return Err(HsError);
    }
    Ok((PeerKey::new(x), epoch))
}

/// The completion of a stub handshake, one side's view.
fn completed<P: Profile<Session = Sess>>(
    role: Role,
    ei: &[u8; 8],
    er: &[u8; 8],
    remote: PeerKey,
    epoch: [u8; 8],
    theirs: Option<u32>,
) -> Completed<P> {
    Completed {
        session: alloc::boxed::Box::new(Sess::new(role, ei, er)),
        remote,
        epoch,
        theirs,
    }
}

impl Msg1Read<Ik> for Msg1 {
    fn epoch(&self) -> [u8; 8] {
        self.epoch
    }

    fn digest(&self) -> Digest {
        self.whole
    }

    fn ephemeral(&self) -> Digest {
        digest(&self.ei)
    }

    fn remote(&self) -> PeerKey {
        self.remote
    }

    fn answer(&self, local: &Local, ours: Option<u32>) -> Result<(Completed<Ik>, Wire), HsError> {
        let (er, m) = msg2(true, local, &self.ei, ours, Some(self.theirs));
        let done = completed(
            Role::Responder,
            &self.ei,
            &er,
            self.remote,
            self.epoch,
            Some(self.theirs),
        );
        Ok((done, m))
    }
}

impl DoneRead<Xx> for Done {
    fn epoch(&self) -> [u8; 8] {
        self.done.epoch
    }

    fn take(self) -> Leg<Xx> {
        Leg {
            done: self.done,
            lease: self.lease,
        }
    }
}

/// The IK msg1 read a node performs before handing the msg1 to the peer's
/// machine: the stub of `fmp::rekey::ik::read_msg1`.
pub(crate) fn read_msg1(local: &Local, bytes: &[u8]) -> Option<Authentic<Msg1, Replayable>> {
    if bytes.first() != Some(&1) || bytes.len() != 1 + 4 + 8 + 32 + 8 + 8 {
        return None;
    }
    let theirs = u32::from_le_bytes(take(bytes, 1)?);
    let ei: [u8; 8] = take(bytes, 5)?;
    let x: [u8; 32] = take(bytes, 13)?;
    let epoch: [u8; 8] = take(bytes, 45)?;
    let t: [u8; 8] = take(bytes, 53)?;
    if mac(&[b"m1", local.key.bytes(), &ei, &x, &epoch]) != t {
        return None;
    }
    Some(Authentic::new(Msg1 {
        ei,
        remote: PeerKey::new(x),
        epoch,
        theirs,
        whole: digest(bytes),
    }))
}

/// The leg table of a next-only peer: answer an XX msg1 with index `ours`.
pub(crate) fn leg_answer(local: &Local, bytes: &[u8], ours: u32) -> Option<(Hs, Wire)> {
    let theirs = u32::from_le_bytes(take(bytes, 1)?);
    let ei: [u8; 8] = take(bytes, 5)?;
    let (er, m) = msg2(true, local, &ei, Some(ours), Some(theirs));
    let hs = Hs {
        me: local.key,
        peer: None,
        epoch: local.epoch,
        ei,
        er,
        ours: Some(theirs),
    };
    Some((hs, m))
}

/// The leg table completes its leg on msg3 and hands the machine the
/// completion with the leg's lease.
pub(crate) fn leg_done(
    hs: &Hs,
    bytes: &[u8],
    lease: Option<IndexLease>,
) -> Option<Authentic<Done, Fresh>> {
    let (remote, epoch) = read3(hs, bytes).ok()?;
    let done = completed(Role::Responder, &hs.ei, &hs.er, remote, epoch, hs.ours);
    Some(Authentic::new(Done { done, lease }))
}

/// What a stub profile adds for the test shell: how to build its
/// layer-only inputs.
pub(crate) trait Stub: Profile<Hs = Hs, Session = Sess, LocalKeys = Local> {
    /// The transport of the shell's link.
    const TRANSPORT: Self::Transport;
    /// The carrier of a setup.
    const CARRIER: Self::Carrier;
    /// The coordinates a message carries.
    const ROUTE: Self::Route;
    /// The value of the FSP-only marker, when the profile has it.
    fn fsp() -> Option<Self::Fsp>;
    /// The node-level msg1 read, when the profile has one.
    fn read(local: &Local, bytes: &[u8]) -> Option<Authentic<Self::Msg1, Replayable>>;
    /// The value of the FMP-only marker, when the profile has it.
    fn fmp() -> Option<Self::Fmp>;
    /// The carrier numbered `n`, for a setup a third party injects.
    fn carrier(n: u8) -> Self::Carrier;
    /// A leg table answers an XX msg1 with index `ours` (next's profile
    /// only): the leg's handshake and its msg2.
    fn leg(local: &Local, bytes: &[u8], ours: u32) -> Option<(Hs, Wire)> {
        let _ = (local, bytes, ours);
        None
    }
    /// A leg table completes its leg on `msg3` (next's profile only).
    fn done(
        hs: &Hs,
        msg3: &[u8],
        lease: Option<IndexLease>,
    ) -> Option<Authentic<Self::Done, Fresh>> {
        let _ = (hs, msg3);
        drop(lease);
        None
    }
    /// A fresh index source.
    fn indices() -> Self::Indices;
    /// Return an index to the source.
    fn free(indices: &mut Self::Indices, index: u32);
    /// How many indices the source has handed out and not had back.
    fn held(indices: &Self::Indices) -> usize;
}

/// Write `[0x51, 0, 0, 0, 0]`, the stub Heartbeat.
fn heartbeat(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x51, 0, 0, 0, 0]);
}

/// Write `[0x14, 0, 0, 0, 0, 0]`, the stub CoordsWarmup.
fn warmup(out: &mut Vec<u8>) {
    out.extend_from_slice(&[0x14, 0, 0, 0, 0, 0]);
}

/// The two-message, index-bearing link profile (master FMP's shape).
#[derive(Debug)]
pub(crate) struct Ik;

impl Profile for Ik {
    type Hs = Hs;
    type Session = Sess;
    type Indices = Pool;
    type Transport = u8;
    type Carrier = ();
    type Route = ();
    type Ext = u8;
    type LocalKeys = Local;
    type Fsp = Infallible;
    type Fmp = ();
    type Msg1 = Msg1;
    type Done = Infallible;

    const LAYER: Layer = Layer::Fmp;
    const MESSAGES: u8 = 2;
    const COMMIT: Commit = Commit::AtAnswer;
    const INITIATOR_CUTOVER: InitiatorCutover = InitiatorCutover::OnProof;
    const RESPONDER_CUTOVER: ResponderCutover = ResponderCutover::OnFrame;
    const CANDIDATES: usize = 0;
    const PER_CARRIER: usize = 0;
    const DAMPEN_AT: DampenAt = DampenAt::Answer;
    const SELECT: Select = Select::ByIndex;
    const SILENCE: bool = false;
    const SETUP_RTT: bool = false;
    const INDEXED: bool = true;
    const FLOOR: usize = 5;

    fn initiate(local: &Local, peer: &PeerKey, ours: Option<u32>) -> Result<(Hs, Wire), HsError> {
        Ok(msg1(true, true, local, peer, ours))
    }

    fn valid(_: &[u8]) -> bool {
        false
    }

    fn answer(_: &Local, _: &[u8]) -> Result<(Hs, Wire), HsError> {
        Err(HsError)
    }

    fn index(reply: &[u8]) -> Option<u32> {
        take::<4>(reply, 5).map(u32::from_le_bytes)
    }

    fn reply(hs: &Hs, _: &Local, bytes: &[u8]) -> Result<Read<Self>, HsError> {
        let (remote, er, epoch, theirs) = read2(true, true, hs, bytes)?;
        let done = completed(Role::Initiator, &hs.ei, &er, remote, epoch, theirs);
        Ok(Read { done, fin: None })
    }

    fn complete(_: &Hs, _: &[u8]) -> Result<Completed<Self>, HsError> {
        Err(HsError)
    }

    fn prompt(_: Duration, out: &mut Vec<u8>) {
        heartbeat(out);
    }

    fn is_probe(_: &[u8]) -> bool {
        false
    }
}

impl Stub for Ik {
    const TRANSPORT: u8 = 1;
    const CARRIER: () = ();
    const ROUTE: () = ();

    fn fsp() -> Option<Infallible> {
        None
    }

    fn read(local: &Local, bytes: &[u8]) -> Option<Authentic<Msg1, Replayable>> {
        read_msg1(local, bytes)
    }

    fn fmp() -> Option<()> {
        Some(())
    }

    fn carrier(_: u8) {}

    fn indices() -> Pool {
        Pool::new(100)
    }

    fn free(indices: &mut Pool, index: u32) {
        indices.free(index);
    }

    fn held(indices: &Pool) -> usize {
        indices.used.len()
    }
}

/// Defines a three-message profile with candidates (master FSP's shape).
macro_rules! xk_profile {
    ($name:ident, $responder:expr) => {
        impl Profile for $name {
            type Hs = Hs;
            type Session = Sess;
            type Indices = ();
            type Transport = ();
            type Carrier = u8;
            type Route = u16;
            type Ext = u8;
            type LocalKeys = Local;
            type Fsp = ();
            type Fmp = Infallible;
            type Msg1 = Infallible;
            type Done = Infallible;

            const LAYER: Layer = Layer::Fsp;
            const MESSAGES: u8 = 3;
            const COMMIT: Commit = Commit::AtFinal;
            const INITIATOR_CUTOVER: InitiatorCutover = InitiatorCutover::OnEvidence;
            const RESPONDER_CUTOVER: ResponderCutover = $responder;
            const CANDIDATES: usize = 4;
            const PER_CARRIER: usize = 2;
            const DAMPEN_AT: DampenAt = DampenAt::Completion;
            const SELECT: Select = Select::Trial;
            const SILENCE: bool = true;
            const SETUP_RTT: bool = true;
            const INDEXED: bool = false;
            const FLOOR: usize = 6;

            fn initiate(
                local: &Local,
                peer: &PeerKey,
                _: Option<u32>,
            ) -> Result<(Hs, Wire), HsError> {
                Ok(msg1(false, false, local, peer, None))
            }

            fn valid(m: &[u8]) -> bool {
                m.len() == 9 && m[0] == 1 && m[1..] != [0; 8]
            }

            fn answer(local: &Local, m: &[u8]) -> Result<(Hs, Wire), HsError> {
                let ei: [u8; 8] = take(m, 1).ok_or(HsError)?;
                let (er, ack) = msg2(false, local, &ei, None, None);
                let hs = Hs {
                    me: local.key,
                    peer: None,
                    epoch: local.epoch,
                    ei,
                    er,
                    ours: None,
                };
                Ok((hs, ack))
            }

            fn index(_: &[u8]) -> Option<u32> {
                None
            }

            fn reply(hs: &Hs, _: &Local, bytes: &[u8]) -> Result<Read<Self>, HsError> {
                let (remote, er, epoch, _) = read2(false, true, hs, bytes)?;
                let fin = msg3(hs, &er);
                let done = completed(Role::Initiator, &hs.ei, &er, remote, epoch, None);
                Ok(Read {
                    done,
                    fin: Some(fin),
                })
            }

            fn complete(hs: &Hs, bytes: &[u8]) -> Result<Completed<Self>, HsError> {
                let (remote, epoch) = read3(hs, bytes)?;
                Ok(completed(
                    Role::Responder,
                    &hs.ei,
                    &hs.er,
                    remote,
                    epoch,
                    None,
                ))
            }

            fn prompt(_: Duration, out: &mut Vec<u8>) {
                warmup(out);
            }

            fn is_probe(p: &[u8]) -> bool {
                p.first() == Some(&0x14)
            }
        }

        impl Stub for $name {
            const TRANSPORT: () = ();
            const CARRIER: u8 = 1;
            const ROUTE: u16 = 7;

            fn fsp() -> Option<()> {
                Some(())
            }

            fn read(_: &Local, _: &[u8]) -> Option<Authentic<Infallible, Replayable>> {
                None
            }

            fn fmp() -> Option<Infallible> {
                None
            }

            fn carrier(n: u8) -> u8 {
                n
            }

            fn indices() {}

            fn free(_: &mut (), _: u32) {}

            fn held(_: &()) -> usize {
                0
            }
        }
    };
}

/// The three-message session profile with candidates (master FSP's shape).
#[derive(Debug)]
pub(crate) struct Xk;
xk_profile!(Xk, ResponderCutover::AtProof);

/// As [`Xk`], with a responder that cuts over on the initiator's frame.
#[derive(Debug)]
pub(crate) struct XkFrame;
xk_profile!(XkFrame, ResponderCutover::OnFrame);

/// The three-message, index-bearing link profile with a delayed initiator
/// cutover and a leg table (next's shape, dormant on master).
#[derive(Debug)]
pub(crate) struct Xx;

impl Profile for Xx {
    type Hs = Hs;
    type Session = Sess;
    type Indices = Pool;
    type Transport = u8;
    type Carrier = ();
    type Route = ();
    type Ext = u8;
    type LocalKeys = Local;
    type Fsp = Infallible;
    type Fmp = ();
    type Msg1 = Infallible;
    type Done = Done;

    const LAYER: Layer = Layer::Fmp;
    const MESSAGES: u8 = 3;
    const COMMIT: Commit = Commit::AtFinal;
    const INITIATOR_CUTOVER: InitiatorCutover = InitiatorCutover::AfterDelay;
    const RESPONDER_CUTOVER: ResponderCutover = ResponderCutover::OnFrame;
    const CANDIDATES: usize = 0;
    const PER_CARRIER: usize = 0;
    const DAMPEN_AT: DampenAt = DampenAt::Completion;
    const SELECT: Select = Select::ByIndex;
    const SILENCE: bool = false;
    const SETUP_RTT: bool = false;
    const INDEXED: bool = true;
    const FLOOR: usize = 5;

    fn initiate(local: &Local, peer: &PeerKey, ours: Option<u32>) -> Result<(Hs, Wire), HsError> {
        Ok(msg1(true, false, local, peer, ours))
    }

    fn valid(_: &[u8]) -> bool {
        false
    }

    fn answer(_: &Local, _: &[u8]) -> Result<(Hs, Wire), HsError> {
        Err(HsError)
    }

    fn index(reply: &[u8]) -> Option<u32> {
        take::<4>(reply, 5).map(u32::from_le_bytes)
    }

    fn reply(hs: &Hs, _: &Local, bytes: &[u8]) -> Result<Read<Self>, HsError> {
        let (remote, er, epoch, theirs) = read2(true, false, hs, bytes)?;
        let fin = msg3(hs, &er);
        let done = completed(Role::Initiator, &hs.ei, &er, remote, epoch, theirs);
        Ok(Read {
            done,
            fin: Some(fin),
        })
    }

    fn complete(_: &Hs, _: &[u8]) -> Result<Completed<Self>, HsError> {
        Err(HsError)
    }

    fn prompt(_: Duration, out: &mut Vec<u8>) {
        heartbeat(out);
    }

    fn is_probe(_: &[u8]) -> bool {
        false
    }
}

impl Stub for Xx {
    const TRANSPORT: u8 = 1;
    const CARRIER: () = ();
    const ROUTE: () = ();

    fn fsp() -> Option<Infallible> {
        None
    }

    fn read(_: &Local, _: &[u8]) -> Option<Authentic<Infallible, Replayable>> {
        None
    }

    fn fmp() -> Option<()> {
        Some(())
    }

    fn carrier(_: u8) {}

    fn leg(local: &Local, bytes: &[u8], ours: u32) -> Option<(Hs, Wire)> {
        leg_answer(local, bytes, ours)
    }

    fn done(hs: &Hs, msg3: &[u8], lease: Option<IndexLease>) -> Option<Authentic<Done, Fresh>> {
        leg_done(hs, msg3, lease)
    }

    fn indices() -> Pool {
        Pool::new(500)
    }

    fn free(indices: &mut Pool, index: u32) {
        indices.free(index);
    }

    fn held(indices: &Pool) -> usize {
        indices.used.len()
    }
}

/// The jitter draws: those a test queued, oldest first, then the middle
/// of the band, so the jitter is zero unless a test asks for another; or,
/// once seeded, uniform draws from the seeded generator (the simulator's).
#[derive(Debug, Default)]
pub(crate) struct Mid {
    pub(crate) queued: Vec<u16>,
    pub(crate) seeded: Option<SplitMix64>,
}

impl JitterSource for Mid {
    fn draw(&mut self, bound: u16) -> u16 {
        if !self.queued.is_empty() {
            return self.queued.remove(0).min(bound);
        }
        match self.seeded.as_mut() {
            Some(g) => u16::try_from(g.below(u64::from(bound) + 1)).unwrap_or(bound),
            None => bound / 2,
        }
    }
}

/// One output, comparable and with its lease already returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Ev<T> {
    Send(MsgKind, Wire, Route),
    Prompt(EpochTag),
    Deliver(Slot, EpochTag, Vec<u8>),
    Bind(T, u32, Option<EpochTag>, Purpose),
    Unbind(T, u32),
    Delegate(EpochTag, T, u32, Option<u64>),
    Revoke(EpochTag, T, u32),
    Release(u32),
    Installed(EpochTag, Role, EvidenceKind),
    Retired(EpochTag),
    Reverted(EpochTag),
    Restarted(Layer, [u8; 8]),
    Rekeyed(Role),
    Replace,
    Reject(Reason),
    Abandoned(Abandon),
    Teardown(Teardown),
}

/// Something one node put on the wire.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Msg {
    /// A handshake message.
    Hs(MsgKind, Wire),
    /// A frame, with the epoch it was sealed under and whether it is a
    /// prompt.
    Frame(Wire, EpochTag),
}

/// A test shell around one machine.
pub(crate) struct Node<P: Stub> {
    pub(crate) m: Option<Rekey<P, TestClock>>,
    pub(crate) local: Local,
    pub(crate) indices: P::Indices,
    pub(crate) tags: TagSource,
    pub(crate) jitter: Mid,
    pub(crate) scratch: Vec<u8>,
    pub(crate) transport: P::Transport,
    pub(crate) workers: bool,
    /// What this node sent, oldest first, until a test takes it.
    pub(crate) wire: Vec<Msg>,
    /// Every output so far.
    pub(crate) log: Vec<Ev<P::Transport>>,
    /// Plaintexts delivered.
    pub(crate) got: Vec<(Slot, Vec<u8>)>,
    /// Receive copies offered to a decrypt worker, with their index, until
    /// the simulator takes them.
    pub(crate) offers: Vec<(EpochTag, u32, RecvKey)>,
    /// The machine's `next_wake` after the last call, so a poll before it
    /// can be checked to do nothing.
    pub(crate) wake: Option<u64>,
}

impl<P: Stub> Node<P> {
    /// A shell with no machine yet.
    pub(crate) fn new(local: Local) -> Self {
        Self {
            m: None,
            local,
            indices: P::indices(),
            tags: TagSource::new(),
            jitter: Mid::default(),
            scratch: Vec::new(),
            transport: P::TRANSPORT,
            workers: false,
            wire: Vec::new(),
            log: Vec::new(),
            got: Vec::new(),
            offers: Vec::new(),
            wake: None,
        }
    }

    /// The machine.
    pub(crate) fn m(&self) -> &Rekey<P, TestClock> {
        self.m.as_ref().expect("the node has a machine")
    }

    /// The machine's state digest.
    pub(crate) fn digest(&self) -> String {
        format!("{:?}", self.m())
    }

    /// Run `f` with the machine and an `Env` over this shell's
    /// capabilities.
    fn with<R>(
        &mut self,
        f: impl FnOnce(&mut Option<Rekey<P, TestClock>>, &mut Env<'_, P>) -> R,
    ) -> R {
        let Self {
            m,
            local,
            indices,
            tags,
            jitter,
            scratch,
            transport,
            workers,
            ..
        } = self;
        let mut env = Env {
            indices,
            transport: *transport,
            tags,
            workers: *workers,
            jitter,
            local,
            scratch,
        };
        f(m, &mut env)
    }

    /// Feed `input` at `now` (ms) and execute the outputs.
    ///
    /// A poll before the instant the last call's `next_wake` named must do
    /// nothing: a shell that arms one timer at `next_wake` would never make
    /// it, so any work it does would wait too long.
    pub(crate) fn step(&mut self, now: u64, input: Input<'_, P>) -> Vec<Ev<P::Transport>> {
        let early = matches!(input, Input::Poll) && self.wake.is_some_and(|w| now < w);
        let wake = self.wake;
        let out = self.with(|m, env| {
            m.as_mut()
                .expect("machine")
                .step(TestInstant(now), input, env)
        });
        let evs = self.run(now, out, None);
        // A re-offer to a worker answers the shell's own worker state, not
        // the clock, so it may come from any poll.
        let timed = evs.iter().any(|e| !matches!(e, Ev::Delegate(..)));
        assert!(
            !early || !timed,
            "a poll at {now}, before next_wake {wake:?}, did work: {evs:?}"
        );
        evs
    }

    /// Poll at `now`.
    pub(crate) fn poll(&mut self, now: u64) -> Vec<Ev<P::Transport>> {
        self.step(now, Input::Poll)
    }

    /// Execute outputs in order, as a shell does, and record them.
    pub(crate) fn run(
        &mut self,
        now: u64,
        out: Vec<Output<P>>,
        buf: Option<&[u8]>,
    ) -> Vec<Ev<P::Transport>> {
        let mut evs = Vec::new();
        for o in out {
            let ev = match o {
                Output::Send { msg, kind, route } => {
                    self.wire.push(Msg::Hs(kind, msg.clone()));
                    Ev::Send(kind, msg, route)
                }
                Output::Prompt { tag } => {
                    let sealed = self
                        .m
                        .as_mut()
                        .expect("machine")
                        .seal_prompt(TestInstant(now), tag)
                        .expect("a prompt the machine asked for seals");
                    let f = frame(&sealed.sealed, &sealed.plaintext);
                    self.wire.push(Msg::Frame(f, tag));
                    Ev::Prompt(tag)
                }
                Output::Deliver { slot, tag, range } => {
                    let p = buf
                        .and_then(|b| b.get(range))
                        .map(<[u8]>::to_vec)
                        .unwrap_or_default();
                    self.got.push((slot, p.clone()));
                    Ev::Deliver(slot, tag, p)
                }
                Output::Bind {
                    transport,
                    index,
                    tag,
                    purpose,
                } => Ev::Bind(transport, index, tag, purpose),
                Output::Unbind { transport, index } => Ev::Unbind(transport, index),
                Output::Delegate {
                    tag,
                    transport,
                    index,
                    recv,
                } => {
                    let floor = recv.floor;
                    self.offers.push((tag, index, recv));
                    Ev::Delegate(tag, transport, index, floor)
                }
                Output::Revoke {
                    tag,
                    transport,
                    index,
                } => Ev::Revoke(tag, transport, index),
                Output::Release(lease) => {
                    let index = lease.release();
                    P::free(&mut self.indices, index);
                    Ev::Release(index)
                }
                Output::Installed {
                    tag,
                    role,
                    evidence,
                } => Ev::Installed(tag, role, evidence),
                Output::Retired { tag } => Ev::Retired(tag),
                Output::Reverted { tag } => Ev::Reverted(tag),
                Output::PeerRestarted { layer, epoch } => Ev::Restarted(layer, epoch),
                Output::Rekeyed { role } => Ev::Rekeyed(role),
                Output::ReplaceRequested { .. } => Ev::Replace,
                Output::Reject(r) => Ev::Reject(r),
                Output::Abandoned(a) => Ev::Abandoned(a),
                Output::Teardown(t) => Ev::Teardown(t),
            };
            self.log.push(ev.clone());
            evs.push(ev);
        }
        self.rewake();
        evs
    }

    /// Record the machine's `next_wake` after a call, and check that the
    /// candidates it holds stay within the profile's bound.
    pub(crate) fn rewake(&mut self) {
        self.wake = self.m.as_ref().and_then(Rekey::next_wake).map(|t| t.0);
        if let Some(m) = &self.m {
            let held = m.view().candidates;
            assert!(
                held <= P::CANDIDATES,
                "{held} candidates held, over the bound of {}",
                P::CANDIDATES
            );
        }
    }

    /// Take everything this node has sent.
    pub(crate) fn sent(&mut self) -> Vec<Msg> {
        core::mem::take(&mut self.wire)
    }

    /// Deliver one message from the peer at `now`.
    pub(crate) fn recv(&mut self, now: u64, msg: &Msg) -> Vec<Ev<P::Transport>> {
        self.recv_on(
            now,
            msg,
            super::super::Arrival {
                on_link: true,
                reachable: true,
            },
        )
    }

    /// Deliver one message from the peer at `now`, an IK msg1 arriving as
    /// `arrival` says.
    pub(crate) fn recv_on(
        &mut self,
        now: u64,
        msg: &Msg,
        arrival: super::super::Arrival,
    ) -> Vec<Ev<P::Transport>> {
        match msg {
            Msg::Hs(MsgKind::Msg1, bytes) => match P::read(&self.local, bytes) {
                Some(tok) => self.step(now, Input::PeerMsg1 { tok, arrival }),
                None => Vec::new(),
            },
            Msg::Hs(MsgKind::Setup, bytes) => {
                let only = P::fsp().expect("a setup goes to a session profile");
                self.step(
                    now,
                    Input::Setup {
                        msg1: bytes,
                        carrier: P::CARRIER,
                        route: P::ROUTE,
                        only,
                    },
                )
            }
            Msg::Hs(MsgKind::Msg2 | MsgKind::Ack, bytes) => self.step(
                now,
                Input::Reply {
                    bytes,
                    route: P::ROUTE,
                },
            ),
            Msg::Hs(MsgKind::Msg3, bytes) => {
                let only = P::fsp().expect("a msg3 goes to a session profile");
                self.step(now, Input::Final { bytes, only })
            }
            Msg::Frame(f, _) => self.frame(now, f),
        }
    }

    /// Deliver a frame's bytes.
    pub(crate) fn frame(&mut self, now: u64, f: &[u8]) -> Vec<Ev<P::Transport>> {
        let mut buf = f.to_vec();
        let h = hint(&buf);
        let out = self.with(|m, env| {
            m.as_mut().expect("machine").step(
                TestInstant(now),
                Input::Frame {
                    buf: &mut buf,
                    hint: h,
                },
                env,
            )
        });
        let copy = buf.clone();
        self.run(now, out, Some(&copy))
    }

    /// Seal `plaintext` under the current epoch and return the frame.
    pub(crate) fn data(&mut self, now: u64, plaintext: &[u8]) -> Vec<u8> {
        let sealed = self
            .m
            .as_mut()
            .expect("machine")
            .seal(TestInstant(now))
            .expect("the current epoch seals");
        self.rewake();
        frame(&sealed, plaintext)
    }

    /// Close the machine and execute the outputs.
    ///
    /// Whatever the machine held, closing it leaves nothing behind: every
    /// epoch it held is retired, an own attempt is abandoned as closed,
    /// every index it bound is unbound and every lease is back in the pool.
    pub(crate) fn close(
        &mut self,
        now: u64,
        why: super::super::Close,
    ) -> (
        Vec<Ev<P::Transport>>,
        Option<super::super::Carry<TestInstant>>,
    ) {
        let m = self.m.take().expect("machine");
        let v = m.view();
        let held: Vec<EpochTag> = [&v.current, &v.previous, &v.pending]
            .into_iter()
            .flatten()
            .map(|e| e.tag)
            .collect();
        let attempt = v.cycle == CycleView::Init;
        let (out, carry) = m.close(why);
        let evs = self.run(now, out, None);
        for tag in held {
            assert!(
                evs.contains(&Ev::Retired(tag)),
                "close retires the held epoch {tag:?}: {evs:?}"
            );
        }
        assert_eq!(
            attempt,
            evs.contains(&Ev::Abandoned(Abandon::Closed(why))),
            "close abandons an own attempt, and only one: {evs:?}"
        );
        let mut bound: BTreeMap<u32, i32> = BTreeMap::new();
        for e in &self.log {
            if let Ev::Bind(_, i, ..) = e {
                *bound.entry(*i).or_default() += 1;
            } else if let Ev::Unbind(_, i) = e {
                *bound.entry(*i).or_default() -= 1;
            }
        }
        bound.retain(|_, n| *n != 0);
        assert!(bound.is_empty(), "close unbinds every index: {bound:?}");
        assert_eq!(
            P::held(&self.indices),
            0,
            "close releases every lease: {evs:?}"
        );
        (evs, carry)
    }

    /// Open a first handshake toward `peer` at `now`.
    pub(crate) fn open_out(
        &mut self,
        now: u64,
        peer: PeerKey,
        params: Params,
    ) -> Vec<Ev<P::Transport>> {
        let me = self.local.addr();
        let only = P::fsp().expect("a first handshake is a session's");
        let (m, out) = self
            .with(|_, env| Rekey::opening_outbound(params, peer, me, TestInstant(now), only, env));
        self.m = Some(m);
        self.run(now, out, None)
    }

    /// A first handshake opened by `setup`, which claims `claimed`.
    pub(crate) fn open_in(
        &mut self,
        now: u64,
        claimed: NodeAddr,
        setup: &Msg,
        params: Params,
    ) -> Vec<Ev<P::Transport>> {
        let me = self.local.addr();
        let only = P::fsp().expect("a first handshake is a session's");
        let b = bytes(setup);
        let input = Input::Setup {
            msg1: &b,
            carrier: P::CARRIER,
            route: P::ROUTE,
            only,
        };
        let (m, out) = self.with(|_, env| {
            Rekey::opening_inbound(params, claimed, me, TestInstant(now), input, only, env)
        });
        self.m = Some(m);
        self.run(now, out, None)
    }

    /// Feed a setup on `carrier` at `now`.
    pub(crate) fn setup_on(
        &mut self,
        now: u64,
        carrier: P::Carrier,
        setup: &[u8],
    ) -> Vec<Ev<P::Transport>> {
        let only = P::fsp().expect("a setup is a session's");
        self.step(
            now,
            Input::Setup {
                msg1: setup,
                carrier,
                route: P::ROUTE,
                only,
            },
        )
    }

    /// Draw `n` ephemerals from this node's counter, as attempts it wrote
    /// and lost would have.
    pub(crate) fn skip(&self, n: usize) {
        for _ in 0..n {
            self.local.eph();
        }
    }

    /// The tag of the current epoch.
    pub(crate) fn cur(&self) -> EpochTag {
        self.m().view().current.expect("established").tag
    }
}

/// A data plaintext the stub layers deliver (long enough for both floors).
pub(crate) const DATA: &[u8] = &[0x10, 1, 2, 3, 4, 5, 6, 7];

/// Build two established machines that share a first epoch, as link setup
/// leaves them: `a` initiated the setup handshake, at `now` ms.
pub(crate) fn pair<P: Stub>(a: Local, b: Local, now: u64, params: Params) -> (Node<P>, Node<P>) {
    pair_with(a, b, now, params, None)
}

/// As [`pair`], with the responder's record built from a genuine setup
/// msg1 and msg2 when `setup` gives them.
pub(crate) fn pair_with<P: Stub>(
    a: Local,
    b: Local,
    now: u64,
    params: Params,
    setup: Option<(&[u8], &[u8])>,
) -> (Node<P>, Node<P>) {
    pair_jittered(a, b, now, params, setup, [Mid::default(), Mid::default()])
}

/// As [`pair_with`], with each node drawing its jitter from `jitter`, the
/// first epoch's included.
pub(crate) fn pair_jittered<P: Stub>(
    a: Local,
    b: Local,
    now: u64,
    params: Params,
    setup: Option<(&[u8], &[u8])>,
    jitter: [Mid; 2],
) -> (Node<P>, Node<P>) {
    let mut na = Node::<P>::new(a);
    let mut nb = Node::<P>::new(b);
    let [ja, jb] = jitter;
    na.jitter = ja;
    nb.jitter = jb;
    let ei = na.local.eph();
    let er = nb.local.eph();
    let (ia, ib) = if P::INDEXED {
        let la = allocate(&mut na.indices);
        let lb = allocate(&mut nb.indices);
        (la, lb)
    } else {
        (None, None)
    };
    let (a_idx, b_idx) = (
        ia.as_ref().map(IndexLease::index),
        ib.as_ref().map(IndexLease::index),
    );
    let ida = match ia {
        Some(l) => Ids::new(l, b_idx.unwrap_or(0), P::TRANSPORT),
        None => Ids::unindexed(P::TRANSPORT),
    };
    let idb = match ib {
        Some(l) => Ids::new(l, a_idx.unwrap_or(0), P::TRANSPORT),
        None => Ids::unindexed(P::TRANSPORT),
    };
    let msg1 = mac(&[b"setup", &ei]);
    let record = |responder: bool| match setup {
        Some((m1, m2)) => {
            let eph = m1.get(5..13).unwrap_or_default();
            Record::setup(digest(m1), digest(eph), responder.then(|| m2.to_vec()))
        }
        None => Record::setup(digest(&msg1), digest(&ei), None),
    };
    let done_a = completed::<P>(
        Role::Initiator,
        &ei,
        &er,
        nb.local.key,
        nb.local.epoch,
        b_idx,
    );
    let done_b = completed::<P>(
        Role::Responder,
        &ei,
        &er,
        na.local.key,
        na.local.epoch,
        a_idx,
    );
    let (ea, eb) = (na.local.epoch, nb.local.epoch);
    for (node, done, ids, peer_epoch, responder) in [
        (&mut na, done_a, ida, eb, false),
        (&mut nb, done_b, idb, ea, true),
    ] {
        let peer = done.remote;
        let bonded = Bond::Key(peer).check(done).expect("the setup bonds");
        let facts = SetupFacts {
            peer_epoch: Some(peer_epoch),
            k: false,
            link_since: TestInstant(now),
            started: TestInstant(now),
            peer_k: None,
            last_rx: None,
            record: record(responder),
        };
        let me = node.local.addr();
        let (m, out) = node.with(|_, env| {
            Rekey::established(
                params,
                Bond::Key(peer),
                me,
                bonded,
                ids,
                facts,
                TestInstant(now),
                env,
            )
        });
        node.m = Some(m);
        node.run(now, out, None);
    }
    (na, nb)
}

/// The FMP defaults with no jitter band, for exact trigger instants.
pub(crate) fn fmp() -> Params {
    Params::fmp()
}

/// The FSP defaults.
pub(crate) fn fsp() -> Params {
    Params::fsp()
}

/// Settings with the given changes, validated.
pub(crate) fn with(base: Config, f: impl FnOnce(&mut Config)) -> Params {
    let mut c = base;
    f(&mut c);
    Params::new(c).expect("valid test settings")
}

/// The last handshake message of `kind` a node sent, removed from its wire.
pub(crate) fn last(node_wire: &mut Vec<Msg>, kind: MsgKind) -> Msg {
    let i = node_wire
        .iter()
        .rposition(|m| matches!(m, Msg::Hs(k, _) if *k == kind))
        .expect("the node sent that message");
    node_wire.remove(i)
}

/// The frames a node sent, removed from its wire, oldest first.
pub(crate) fn frames(node_wire: &mut Vec<Msg>) -> Vec<Msg> {
    let (f, rest): (Vec<Msg>, Vec<Msg>) = core::mem::take(node_wire)
        .into_iter()
        .partition(|m| matches!(m, Msg::Frame(..)));
    *node_wire = rest;
    f
}

/// The bytes of a handshake message.
pub(crate) fn bytes(m: &Msg) -> Wire {
    match m {
        Msg::Hs(_, b) | Msg::Frame(b, _) => b.clone(),
    }
}

/// The established route without the arrival fallback.
pub(crate) const PLAIN: Route = Route::Established { fallback: false };

/// The established route with the arrival fallback, for answers.
pub(crate) const ANSWER: Route = Route::Established { fallback: true };

/// Every index a shell's pool holds equals the indices the machine binds.
pub(crate) fn conserved<P: Stub<Indices = Pool>>(node: &Node<P>) {
    let mut bound: Vec<u32> = node.m().bindings().iter().map(|b| b.index).collect();
    bound.sort_unstable();
    let held: Vec<u32> = node.indices.used.iter().copied().collect();
    assert_eq!(bound, held, "leases outstanding equal leases held");
}

/// A frame sealed by the responder of a leg that read `msg3`, toward the
/// initiator's index `index`, as a peer that cut over early would send.
pub(crate) fn leg_frame(
    hs: &Hs,
    msg3: &[u8],
    index: u32,
    k: bool,
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    read3(hs, msg3).ok()?;
    let (_, ri) = keys(&hs.ei, &hs.er);
    Some(seal_with(&ri, index, 0, k, plaintext))
}

/// A frame sealed by the responder of the IK exchange `msg1`/`msg2`, as a
/// responder that cut over on its own schedule would send it.
pub(crate) fn ik_frame(msg1: &[u8], msg2: &[u8], index: u32, k: bool, plaintext: &[u8]) -> Vec<u8> {
    let ei: [u8; 8] = take(msg1, 5).unwrap_or_default();
    let er: [u8; 8] = take(msg2, 9).unwrap_or_default();
    let (_, ri) = keys(&ei, &er);
    seal_with(&ri, index, 0, k, plaintext)
}

/// Build a machine on `node` for `peer` from what a closed machine carried,
/// as the shell does after a cross-connection move, on a fresh session.
pub(crate) fn rebuild<P: Stub>(
    node: &mut Node<P>,
    peer: &Local,
    carry: super::super::Carry<TestInstant>,
    now: u64,
    params: Params,
) {
    let ei = node.local.eph();
    let er = peer.eph();
    let lease = if P::INDEXED {
        allocate(&mut node.indices)
    } else {
        None
    };
    let ids = match lease {
        Some(l) => Ids::new(l, 7, P::TRANSPORT),
        None => Ids::unindexed(P::TRANSPORT),
    };
    let done = completed::<P>(
        Role::Initiator,
        &ei,
        &er,
        peer.key,
        carry.peer_epoch.unwrap_or_default(),
        Some(7),
    );
    let bonded = Bond::Key(peer.key).check(done).expect("bonds");
    let facts = SetupFacts::from(carry);
    let me = node.local.addr();
    let key = peer.key;
    let (m, out) = node.with(|_, env| {
        Rekey::established(
            params,
            Bond::Key(key),
            me,
            bonded,
            ids,
            facts,
            TestInstant(now),
            env,
        )
    });
    node.m = Some(m);
    node.run(now, out, None);
}
