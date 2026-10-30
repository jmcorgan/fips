//! New nodes for the interop simulation: the rekey machine on the
//! production profiles, behind a small shell that does what the root
//! crate's shell will do with its outputs.
//!
//! The shells frame every message with the deployed codecs: a link frame is
//! `build_established_header` and the AEAD over it, a session frame is
//! `build_fsp_header` and the AEAD over that; handshake messages are the
//! profile's own bytes. A link shell also keeps the deployed heartbeat (one
//! every 10 s under the current epoch) and reaps the link after 30 s with
//! no authenticated frame, as `check_link_heartbeats` does; the machine's
//! `view().last_rx` is the liveness clock, so frames under any epoch it
//! holds count.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::{Class, E, End, Got, Ik, Out, Pkt, Xk};
use crate::identity::NodeAddr;
use crate::noise::aead::{Aead, nonce};
use crate::proto::fmp::rekey::ik::read_msg1;
use crate::proto::fmp::wire::{EncryptedHeader, Msg2Header, build_established_header};
use crate::proto::fsp::wire::{FSP_FLAG_K, FspEncryptedHeader, build_fsp_header};
use crate::proto::link::LinkMessageType;
use crate::proto::rekey::{
    Arrival, Bond, Close, CycleView, Env, EpochTag, FrameHint, Input, JitterSource, NodeKeys,
    Output, Params, PeerKey, Purpose, Rekey, Sealed, SendCopy, SetupFacts, Slot, TagSource,
};
use crate::proto::stp::TreeCoordinate;
use crate::testutil::{TestClock, TestInstant};
use crate::time::Duration;
use crate::transport::TransportId;
use crate::utils::index::{IndexAllocator, SessionIndex};

/// The jitter a new node draws: always the same draw (0 is the band's low
/// end, 15 a zero jitter at the defaults), so a trace places its triggers.
#[derive(Debug)]
pub(crate) enum Jit {
    /// Always this draw.
    Fixed(u16),
}

impl JitterSource for Jit {
    fn draw(&mut self, bound: u16) -> u16 {
        match self {
            Self::Fixed(v) => (*v).min(bound),
        }
    }
}

/// The application data plaintext of a link frame: `[ts][0x00][seq]`.
pub(crate) fn link_data(elapsed: Duration, seq: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(13);
    p.extend_from_slice(&(elapsed.as_millis() as u32).to_le_bytes());
    p.push(LinkMessageType::SessionDatagram.to_byte());
    p.extend_from_slice(&seq.to_le_bytes());
    p
}

/// The application data plaintext of a session frame: `[ts][0x10][0][seq]`.
pub(crate) fn session_data(elapsed: Duration, seq: u64) -> Vec<u8> {
    let mut p = Vec::with_capacity(14);
    p.extend_from_slice(&(elapsed.as_millis() as u32).to_le_bytes());
    p.push(0x10);
    p.push(0);
    p.extend_from_slice(&seq.to_le_bytes());
    p
}

/// Whether a delivered link plaintext is application data.
pub(crate) fn is_datagram(plaintext: &[u8]) -> bool {
    plaintext.len() == 13 && plaintext[4] == LinkMessageType::SessionDatagram.to_byte()
}

/// Whether a delivered session plaintext is application data.
pub(crate) fn is_packet(plaintext: &[u8]) -> bool {
    plaintext.len() == 14 && plaintext[4] == 0x10
}

/// Seal `plaintext` with a reserved send key, behind `aad`.
fn sealed_bytes(key: &SendCopy, counter: u64, aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let key = key.key().expect("a reserved send key is keyed");
    let mut buf = plaintext.to_vec();
    let tag = key
        .seal(&nonce(counter), aad, &mut buf)
        .expect("sealing never fails for a frame this size");
    let mut out = aad.to_vec();
    out.extend_from_slice(&buf);
    out.extend_from_slice(&tag);
    out
}

/// A link frame from a seal reservation, as the deployed sender frames it.
pub(crate) fn link_frame(sealed: &Sealed<SendCopy>, plaintext: &[u8]) -> Vec<u8> {
    let header = build_established_header(
        SessionIndex::new(sealed.theirs.unwrap_or(0)),
        sealed.counter,
        u8::from(sealed.k),
        plaintext.len() as u16,
    );
    sealed_bytes(&sealed.key, sealed.counter, &header, plaintext)
}

/// A session frame from a seal reservation, as the deployed sender frames
/// it, with no coordinates.
pub(crate) fn session_frame(sealed: &Sealed<SendCopy>, plaintext: &[u8]) -> Vec<u8> {
    let flags = if sealed.k { FSP_FLAG_K } else { 0 };
    let header = build_fsp_header(sealed.counter, flags, plaintext.len() as u16);
    sealed_bytes(&sealed.key, sealed.counter, &header, plaintext)
}

/// The note a new node's output reports, or `None` for outputs the shell
/// only executes.
fn note<T: core::fmt::Debug>(o: &T) -> String {
    format!("{o:?}")
}

/// What one step's deliveries amounted to.
fn delivered(deliveries: &[(Slot, Vec<u8>)], data: fn(&[u8]) -> bool) -> Got {
    match deliveries.first() {
        Some((slot, p)) if data(p) => Got::Data {
            current: *slot == Slot::Current,
        },
        Some(_) => Got::Frame,
        None => Got::Refused,
    }
}

/// A new link node: the machine on `FmpIk`, with its index map and pool.
pub(crate) struct NewFmp {
    pub(crate) m: Option<Rekey<Ik, TestClock>>,
    pub(crate) local: NodeKeys,
    pub(crate) peer: PeerKey,
    alloc: IndexAllocator<E>,
    tags: TagSource,
    pub(crate) jitter: Jit,
    scratch: Vec<u8>,
    transport: TransportId,
    /// The index map the `Bind` and `Unbind` outputs maintain.
    pub(crate) bound: BTreeMap<u32, Purpose>,
    notes: Vec<String>,
    last_hb: u64,
    dead: bool,
    label: String,
    /// Reap the link as the root crate's shell does: 30 s with no
    /// authenticated frame under the current epoch since the later of the
    /// last one and the last cutover, which resets the link's MMP receiver.
    pub(crate) shipped: bool,
    /// When the machine last reported a cutover.
    cut: u64,
}

impl NewFmp {
    /// A new link node whose link was set up with `session`: this node's
    /// index drawn from its pool, the peer's index `theirs`, and the replay
    /// record of the setup.
    #[expect(
        clippy::too_many_arguments,
        reason = "the facts a link setup hands over"
    )]
    pub(crate) fn established(
        label: &str,
        local: NodeKeys,
        peer: PeerKey,
        peer_epoch: [u8; 8],
        session: crate::noise::NoiseSession,
        ours: crate::proto::rekey::IndexLease,
        alloc: IndexAllocator<E>,
        theirs: u32,
        record: crate::proto::rekey::Record,
        k: bool,
        now: u64,
        params: Params,
        jitter: Jit,
    ) -> Self {
        let mut n = Self {
            m: None,
            local,
            peer,
            alloc,
            tags: TagSource::new(),
            jitter,
            scratch: Vec::new(),
            transport: TransportId::new(1),
            bound: BTreeMap::new(),
            notes: Vec::new(),
            last_hb: now,
            dead: false,
            label: String::from(label),
            shipped: false,
            cut: now,
        };
        let done = crate::proto::rekey::Completed::<Ik> {
            session: alloc::boxed::Box::new(crate::proto::fmp::rekey::ik::LinkKeys::new(session)),
            remote: peer,
            epoch: peer_epoch,
            theirs: Some(theirs),
        };
        let bonded = Bond::Key(peer).check(done).expect("the link setup bonds");
        let ids = crate::proto::rekey::Ids::new(ours, theirs, n.transport);
        let facts = SetupFacts {
            peer_epoch: Some(peer_epoch),
            k,
            link_since: TestInstant(now),
            started: TestInstant(now),
            peer_k: None,
            last_rx: None,
            record,
        };
        let me = n.local_addr();
        let (m, out) = n.with(|_, env| {
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
        n.m = Some(m);
        let mut ignored = Vec::new();
        n.run(now, out, &mut ignored);
        n
    }

    /// This node's address.
    fn local_addr(&self) -> NodeAddr {
        PeerKey::from_xonly(&self.local.keypair().x_only_public_key().0).addr()
    }

    /// Run `f` with the machine and an `Env` over this shell.
    fn with<R>(
        &mut self,
        f: impl FnOnce(&mut Option<Rekey<Ik, TestClock>>, &mut Env<'_, Ik>) -> R,
    ) -> R {
        let Self {
            m,
            local,
            alloc,
            tags,
            jitter,
            scratch,
            transport,
            ..
        } = self;
        let mut env = Env {
            indices: alloc,
            transport: *transport,
            tags,
            workers: false,
            jitter,
            local,
            scratch,
        };
        f(m, &mut env)
    }

    /// Step the machine and execute its outputs.
    fn step(&mut self, now: u64, input: Input<'_, Ik>, out: &mut Vec<Out>) {
        let outputs = self.with(|m, env| {
            m.as_mut()
                .expect("a live machine")
                .step(TestInstant(now), input, env)
        });
        self.run(now, outputs, out);
    }

    /// Execute outputs front to back, as the shell does; return the
    /// plaintexts delivered.
    fn run(&mut self, now: u64, outputs: Vec<Output<Ik>>, out: &mut Vec<Out>) {
        for o in outputs {
            match o {
                Output::Send { msg, kind, .. } => {
                    let class = match kind {
                        crate::proto::rekey::MsgKind::Msg1 => Class::Msg1,
                        crate::proto::rekey::MsgKind::Msg2 => Class::Msg2,
                        crate::proto::rekey::MsgKind::Setup
                        | crate::proto::rekey::MsgKind::Ack
                        | crate::proto::rekey::MsgKind::Msg3 => {
                            panic!("a link machine sent {kind:?}")
                        }
                    };
                    self.notes.push(format!("sent {kind:?}"));
                    out.push(Out::new(Pkt::Link(msg), class));
                }
                Output::Prompt { tag } => self.prompt(now, tag, out),
                // A frame's deliveries are read from its buffer by `recv`,
                // which lent it; no other input delivers.
                Output::Deliver { .. } => {}
                Output::Bind { index, purpose, .. } => {
                    self.bound.insert(index, purpose);
                }
                Output::Unbind { index, .. } => {
                    self.bound.remove(&index);
                }
                Output::Release(lease) => {
                    let index = lease.release();
                    self.alloc
                        .free(SessionIndex::new(index))
                        .expect("a released index was allocated");
                }
                Output::Delegate { .. } | Output::Revoke { .. } => {
                    panic!("a node with no decrypt workers was asked to delegate")
                }
                other @ Output::Installed { .. } => {
                    self.cut = now;
                    self.notes.push(note(&other));
                }
                other @ (Output::Retired { .. }
                | Output::Reverted { .. }
                | Output::PeerRestarted { .. }
                | Output::Rekeyed { .. }
                | Output::ReplaceRequested { .. }
                | Output::Reject(_)
                | Output::Abandoned(_)
                | Output::Teardown(_)) => self.notes.push(note(&other)),
            }
        }
    }

    /// Execute the outputs of a `close`: unbind and release.
    fn run_closed(&mut self, outputs: Vec<Output<Ik>>, notes: &mut Vec<String>) {
        for o in outputs {
            match o {
                Output::Release(lease) => {
                    let _ = self.alloc.free(SessionIndex::new(lease.release()));
                }
                Output::Unbind { index, .. } => {
                    self.bound.remove(&index);
                }
                other @ (Output::Send { .. }
                | Output::Prompt { .. }
                | Output::Deliver { .. }
                | Output::Bind { .. }
                | Output::Delegate { .. }
                | Output::Revoke { .. }
                | Output::Installed { .. }
                | Output::Retired { .. }
                | Output::Reverted { .. }
                | Output::PeerRestarted { .. }
                | Output::Rekeyed { .. }
                | Output::ReplaceRequested { .. }
                | Output::Reject(_)
                | Output::Abandoned(_)
                | Output::Teardown(_)) => notes.push(note(&other)),
            }
        }
    }

    /// Seal and send a prompt.
    fn prompt(&mut self, now: u64, tag: EpochTag, out: &mut Vec<Out>) {
        let m = self.m.as_mut().expect("a live machine");
        let current = m.view().current.as_ref().map(|c| c.tag) == Some(tag);
        match m.seal_prompt(TestInstant(now), tag) {
            Ok(p) => {
                let frame = link_frame(&p.sealed, &p.plaintext);
                let class = if current { Class::Prompt } else { Class::Probe };
                out.push(Out::new(Pkt::Link(frame), class));
            }
            Err(e) => self.notes.push(format!("prompt refused {e:?}")),
        }
    }

    /// The machine, read-only.
    pub(crate) fn machine(&self) -> &Rekey<Ik, TestClock> {
        self.m.as_ref().expect("a live machine")
    }

    /// Indices held by the pool, against indices the machine binds: equal
    /// when no lease leaked or was freed twice.
    pub(crate) fn conserved(&self) -> Result<(), String> {
        let Some(m) = self.m.as_ref() else {
            return Ok(());
        };
        let mut bound: Vec<u32> = m.bindings().iter().map(|b| b.index).collect();
        bound.sort_unstable();
        let mapped: Vec<u32> = self.bound.keys().copied().collect();
        if bound != mapped {
            return Err(format!(
                "{}: index map {mapped:?} differs from the machine's bindings {bound:?}",
                self.label
            ));
        }
        if self.alloc.count() != bound.len() {
            return Err(format!(
                "{}: {} indices allocated, {} bound",
                self.label,
                self.alloc.count(),
                bound.len()
            ));
        }
        Ok(())
    }
}

impl End for NewFmp {
    fn tick(&mut self, now: u64, out: &mut Vec<Out>) {
        if self.dead || self.m.is_none() {
            return;
        }
        self.step(now, Input::Poll, out);
        if now.saturating_sub(self.last_hb) >= 10_000 {
            let m = self.m.as_mut().expect("a live machine");
            if let Ok(s) = m.seal(TestInstant(now)) {
                let mut p = (s.elapsed.as_millis() as u32).to_le_bytes().to_vec();
                p.push(LinkMessageType::Heartbeat.to_byte());
                out.push(Out::new(Pkt::Link(link_frame(&s, &p)), Class::Ctl));
                self.last_hb = now;
            }
        }
        let v = self.machine().view();
        let mut last = v.last_rx.unwrap_or(v.link_since).max(v.link_since);
        if self.shipped {
            last = last.max(TestInstant(self.cut));
        }
        if now.saturating_sub(last.0) > 30_000 {
            let m = self.m.take().expect("a live machine");
            let (outputs, _) = m.close(Close::LinkDead);
            let mut notes = Vec::new();
            self.run_closed(outputs, &mut notes);
            self.notes.extend(notes);
            self.dead = true;
            self.notes.push(String::from("link dead"));
        }
    }

    fn recv(&mut self, now: u64, pkt: &Pkt, out: &mut Vec<Out>) -> Got {
        if self.dead || self.m.is_none() {
            return Got::Refused;
        }
        let Pkt::Link(bytes) = pkt else {
            return Got::Other;
        };
        match bytes.first().map(|b| b & 0x0f) {
            Some(1) => {
                let local = &self.local;
                if let Some(tok) = read_msg1::<E>(local, bytes)
                    && crate::proto::rekey::Msg1Read::remote(tok.get()) == self.peer
                {
                    let arrival = Arrival {
                        on_link: true,
                        reachable: true,
                    };
                    self.step(now, Input::PeerMsg1 { tok, arrival }, out);
                } else {
                    self.notes.push(String::from("msg1 refused at node level"));
                }
                Got::Other
            }
            Some(2) => {
                match Msg2Header::parse(bytes) {
                    Some(h) if self.bound.contains_key(&h.receiver_idx.as_u32()) => {
                        self.step(now, Input::Reply { bytes, route: () }, out);
                    }
                    Some(_) | None => self.notes.push(String::from("msg2 for no bound index")),
                }
                Got::Other
            }
            Some(0) => {
                let Some(h) = EncryptedHeader::parse(bytes) else {
                    return Got::Refused;
                };
                if !self.bound.contains_key(&h.receiver_idx.as_u32()) {
                    self.notes.push(String::from("frame for no bound index"));
                    return Got::Refused;
                }
                let hint = FrameHint {
                    counter: h.counter,
                    k: h.flags & 1 != 0,
                    index: h.receiver_idx.as_u32(),
                    body: h.ciphertext_offset(),
                };
                let mut buf = bytes.clone();
                let outputs = self.with(|m, env| {
                    m.as_mut().expect("a live machine").step(
                        TestInstant(now),
                        Input::Frame {
                            buf: &mut buf,
                            hint,
                        },
                        env,
                    )
                });
                let mut got = Vec::new();
                let mut rest = Vec::new();
                for o in outputs {
                    if let Output::Deliver { slot, range, .. } = &o {
                        got.push((
                            *slot,
                            buf.get(range.clone())
                                .map(<[u8]>::to_vec)
                                .unwrap_or_default(),
                        ));
                    } else {
                        rest.push(o);
                    }
                }
                self.run(now, rest, out);
                delivered(&got, is_datagram)
            }
            Some(_) | None => Got::Other,
        }
    }

    fn data(&mut self, now: u64, seq: u64, out: &mut Vec<Out>) -> bool {
        let Some(m) = self.m.as_mut() else {
            return false;
        };
        let Ok(s) = m.seal(TestInstant(now)) else {
            return false;
        };
        let p = link_data(s.elapsed, seq);
        out.push(Out::new(Pkt::Link(link_frame(&s, &p)), Class::Data));
        true
    }

    fn wake(&self) -> Option<u64> {
        self.m.as_ref().and_then(Rekey::next_wake).map(|t| t.0)
    }

    fn alive(&self) -> bool {
        !self.dead && self.m.is_some()
    }

    fn quiet(&self) -> bool {
        self.m
            .as_ref()
            .is_some_and(|m| m.view().cycle == CycleView::Idle)
    }

    fn take_notes(&mut self) -> Vec<String> {
        core::mem::take(&mut self.notes)
    }

    fn name(&self) -> String {
        self.label.clone()
    }

    fn check(&self) -> Result<(), String> {
        self.conserved()
    }

    fn finish(&mut self) -> Result<(), String> {
        self.conserved()?;
        if let Some(m) = self.m.take() {
            let (outputs, _) = m.close(Close::Shutdown);
            let mut ignored = Vec::new();
            self.m = None;
            self.run_closed(outputs, &mut ignored);
        }
        if self.alloc.count() != 0 {
            return Err(format!(
                "{}: {} indices still allocated after close",
                self.label,
                self.alloc.count()
            ));
        }
        Ok(())
    }
}

/// A new session node: the machine on `FspXk`, opened by either end or
/// built established.
pub(crate) struct NewFsp {
    pub(crate) m: Option<Rekey<Xk, TestClock>>,
    pub(crate) local: NodeKeys,
    pub(crate) peer: PeerKey,
    tags: TagSource,
    pub(crate) jitter: Jit,
    scratch: Vec<u8>,
    pub(super) notes: Vec<String>,
    pub(crate) params: Params,
    /// The session SRTT the shell reports, if its MMP measures one.
    pub(crate) srtt: Option<Duration>,
    label: String,
}

/// The coordinates the harness puts in every session handshake message;
/// only the shell reads them, and only for a prompt with none cached.
fn coords(addr: NodeAddr) -> TreeCoordinate {
    TreeCoordinate::root(addr)
}

impl NewFsp {
    /// A new session node with no session yet.
    pub(crate) fn new(
        label: &str,
        local: NodeKeys,
        peer: PeerKey,
        params: Params,
        jitter: Jit,
    ) -> Self {
        Self {
            m: None,
            local,
            peer,
            tags: TagSource::new(),
            jitter,
            scratch: Vec::new(),
            notes: Vec::new(),
            params,
            srtt: None,
            label: String::from(label),
        }
    }

    /// A new session node whose session was set up with `session`.
    #[expect(
        clippy::too_many_arguments,
        reason = "the facts a session setup hands over"
    )]
    pub(crate) fn established(
        label: &str,
        local: NodeKeys,
        peer: PeerKey,
        peer_epoch: [u8; 8],
        session: crate::noise::NoiseSession,
        now: u64,
        params: Params,
        jitter: Jit,
    ) -> Self {
        let mut n = Self::new(label, local, peer, params, jitter);
        let done = crate::proto::rekey::Completed::<Xk> {
            session: alloc::boxed::Box::new(crate::proto::fsp::rekey::xk::SessionKeys::new(
                session,
            )),
            remote: peer,
            epoch: peer_epoch,
            theirs: None,
        };
        let bonded = Bond::Key(peer)
            .check(done)
            .expect("the session setup bonds");
        let facts = SetupFacts {
            peer_epoch: Some(peer_epoch),
            k: false,
            link_since: TestInstant(now),
            started: TestInstant(now),
            peer_k: None,
            last_rx: None,
            record: crate::proto::rekey::Record::new(),
        };
        let me = n.local_addr();
        let (m, out) = n.with(|_, env| {
            Rekey::established(
                params,
                Bond::Key(peer),
                me,
                bonded,
                crate::proto::rekey::Ids::unindexed(()),
                facts,
                TestInstant(now),
                env,
            )
        });
        n.m = Some(m);
        let mut ignored = Vec::new();
        n.run(now, out, &mut ignored);
        n
    }

    /// This node's address.
    fn local_addr(&self) -> NodeAddr {
        PeerKey::from_xonly(&self.local.keypair().x_only_public_key().0).addr()
    }

    /// Run `f` with the machine and an `Env` over this shell.
    pub(super) fn with<R>(
        &mut self,
        f: impl FnOnce(&mut Option<Rekey<Xk, TestClock>>, &mut Env<'_, Xk>) -> R,
    ) -> R {
        let Self {
            m,
            local,
            tags,
            jitter,
            scratch,
            ..
        } = self;
        let mut indices = ();
        let mut env = Env {
            indices: &mut indices,
            transport: (),
            tags,
            workers: false,
            jitter,
            local,
            scratch,
        };
        f(m, &mut env)
    }

    /// Open the session toward the peer: a first attempt, or `Open` on an
    /// inbound machine.
    fn want(&mut self, now: u64, out: &mut Vec<Out>) {
        if self.m.is_some() {
            let peer = self.peer;
            self.step(now, Input::Open { peer, only: () }, out);
            return;
        }
        let me = self.local_addr();
        let peer = self.peer;
        let params = self.params;
        let (m, outputs) = self
            .with(|_, env| Rekey::opening_outbound(params, peer, me, TestInstant(now), (), env));
        self.m = Some(m);
        self.run(now, outputs, out);
        self.facts(now, out);
    }

    /// Report the path facts the shell knows.
    fn facts(&mut self, now: u64, out: &mut Vec<Out>) {
        if let Some(srtt) = self.srtt {
            let input = Input::PathFacts {
                reachable: true,
                srtt: Some(srtt),
                only: (),
            };
            self.step(now, input, out);
        }
    }

    /// Step the machine and execute its outputs.
    fn step(&mut self, now: u64, input: Input<'_, Xk>, out: &mut Vec<Out>) {
        let outputs = self.with(|m, env| {
            m.as_mut()
                .expect("a live machine")
                .step(TestInstant(now), input, env)
        });
        self.run(now, outputs, out);
    }

    /// Execute outputs front to back, as the shell does.
    pub(super) fn run(&mut self, now: u64, outputs: Vec<Output<Xk>>, out: &mut Vec<Out>) {
        let mut teardown = false;
        for o in outputs {
            match o {
                Output::Send { msg, kind, .. } => {
                    let (pkt, class) = match kind {
                        crate::proto::rekey::MsgKind::Setup => (Pkt::Setup(msg), Class::Setup),
                        crate::proto::rekey::MsgKind::Ack => (Pkt::Ack(msg), Class::Ack),
                        crate::proto::rekey::MsgKind::Msg3 => (Pkt::Msg3(msg), Class::Msg3),
                        crate::proto::rekey::MsgKind::Msg1 | crate::proto::rekey::MsgKind::Msg2 => {
                            panic!("a session machine sent {kind:?}")
                        }
                    };
                    self.notes.push(format!("sent {kind:?}"));
                    out.push(Out::new(pkt, class));
                }
                Output::Prompt { tag } => self.prompt(now, tag, out),
                Output::Deliver { .. } => {}
                other @ Output::Teardown(_) => {
                    self.notes.push(note(&other));
                    teardown = true;
                }
                other @ (Output::Bind { .. }
                | Output::Unbind { .. }
                | Output::Delegate { .. }
                | Output::Revoke { .. }
                | Output::Release(_)) => panic!("a session machine emitted {other:?}"),
                other @ (Output::Installed { .. }
                | Output::Retired { .. }
                | Output::Reverted { .. }
                | Output::PeerRestarted { .. }
                | Output::Rekeyed { .. }
                | Output::ReplaceRequested { .. }
                | Output::Reject(_)
                | Output::Abandoned(_)) => self.notes.push(note(&other)),
            }
        }
        if teardown && let Some(m) = self.m.take() {
            let (outputs, _) = m.close(Close::OpeningTeardown);
            for o in outputs {
                self.notes.push(note(&o));
            }
        }
    }

    /// Seal and send a prompt.
    fn prompt(&mut self, now: u64, tag: EpochTag, out: &mut Vec<Out>) {
        let m = self.m.as_mut().expect("a live machine");
        let current = m.view().current.as_ref().map(|c| c.tag) == Some(tag);
        match m.seal_prompt(TestInstant(now), tag) {
            Ok(p) => {
                let frame = session_frame(&p.sealed, &p.plaintext);
                let class = if current { Class::Prompt } else { Class::Probe };
                out.push(Out::new(Pkt::Frame(frame), class));
            }
            Err(e) => self.notes.push(format!("prompt refused {e:?}")),
        }
    }
}

impl End for NewFsp {
    fn tick(&mut self, now: u64, out: &mut Vec<Out>) {
        if self.m.is_some() {
            self.step(now, Input::Poll, out);
        }
    }

    fn recv(&mut self, now: u64, pkt: &Pkt, out: &mut Vec<Out>) -> Got {
        let peer_addr = self.peer.addr();
        let route = coords(peer_addr);
        match pkt {
            Pkt::Setup(msg1) => {
                // As the shell does: a setup is judged only after every
                // deadline and start instant already due, so it never meets
                // a confirmation deadline or a final msg3 rung that has
                // passed.
                if self.wake().is_some_and(|w| w <= now) {
                    self.tick(now, out);
                }
                if self.m.is_none() {
                    let me = self.local_addr();
                    let params = self.params;
                    let input = Input::Setup {
                        msg1,
                        carrier: peer_addr,
                        route,
                        only: (),
                    };
                    let (m, outputs) = self.with(|_, env| {
                        Rekey::opening_inbound(
                            params,
                            peer_addr,
                            me,
                            TestInstant(now),
                            input,
                            (),
                            env,
                        )
                    });
                    self.m = Some(m);
                    self.run(now, outputs, out);
                    if self.m.is_some() {
                        self.facts(now, out);
                    }
                } else {
                    let input = Input::Setup {
                        msg1,
                        carrier: peer_addr,
                        route,
                        only: (),
                    };
                    self.step(now, input, out);
                }
                Got::Other
            }
            Pkt::Ack(bytes) => {
                if self.m.is_some() {
                    self.step(now, Input::Reply { bytes, route }, out);
                } else {
                    self.notes.push(String::from("ack with no session"));
                }
                Got::Other
            }
            Pkt::Msg3(bytes) => {
                if self.m.is_some() {
                    self.step(now, Input::Final { bytes, only: () }, out);
                } else {
                    self.notes.push(String::from("msg3 with no session"));
                }
                Got::Other
            }
            Pkt::Frame(bytes) => {
                if self.m.is_none() {
                    return Got::Refused;
                }
                let Some(h) = FspEncryptedHeader::parse(bytes) else {
                    return Got::Refused;
                };
                let hint = FrameHint {
                    counter: h.counter,
                    k: h.flags & FSP_FLAG_K != 0,
                    index: 0,
                    body: crate::proto::fsp::wire::FSP_HEADER_SIZE,
                };
                let mut buf = bytes.clone();
                let outputs = self.with(|m, env| {
                    m.as_mut().expect("a live machine").step(
                        TestInstant(now),
                        Input::Frame {
                            buf: &mut buf,
                            hint,
                        },
                        env,
                    )
                });
                let mut got = Vec::new();
                let mut rest = Vec::new();
                for o in outputs {
                    if let Output::Deliver { slot, range, .. } = &o {
                        got.push((
                            *slot,
                            buf.get(range.clone())
                                .map(<[u8]>::to_vec)
                                .unwrap_or_default(),
                        ));
                    } else {
                        rest.push(o);
                    }
                }
                self.run(now, rest, out);
                delivered(&got, is_packet)
            }
            Pkt::Link(_) => Got::Other,
        }
    }

    fn data(&mut self, now: u64, seq: u64, out: &mut Vec<Out>) -> bool {
        let Some(m) = self.m.as_mut() else {
            return false;
        };
        let Ok(s) = m.seal(TestInstant(now)) else {
            return false;
        };
        let p = session_data(s.elapsed, seq);
        out.push(Out::new(Pkt::Frame(session_frame(&s, &p)), Class::Data));
        self.step(now, Input::DataSent { only: () }, out);
        true
    }

    fn wake(&self) -> Option<u64> {
        self.m.as_ref().and_then(Rekey::next_wake).map(|t| t.0)
    }

    fn open(&mut self, now: u64, out: &mut Vec<Out>) {
        self.want(now, out);
    }

    /// A setup naming the peer from a third party: a valid ephemeral the
    /// stranger made, arriving over the stranger's own link.
    fn stranger(&mut self, now: u64, n: u8, out: &mut Vec<Out>) {
        let mut hs = crate::noise::HandshakeState::<E>::new_xk_initiator(
            crate::testutil::seeded_keypair(u64::from(n) + 1000),
            crate::proto::rekey::keys::pinned(&PeerKey::from_xonly(
                &self.local.keypair().x_only_public_key().0,
            ))
            .expect("a key"),
        );
        let msg1 = hs.write_xk_message_1().expect("msg1");
        // Stranger 0 shares the peer's own link; the others each have one.
        let carrier = if n == 0 {
            self.peer.addr()
        } else {
            NodeAddr::from_bytes([n; 16])
        };
        let route = coords(carrier);
        if self.m.is_some() {
            self.step(
                now,
                Input::Setup {
                    msg1: &msg1,
                    carrier,
                    route,
                    only: (),
                },
                out,
            );
        }
    }

    fn alive(&self) -> bool {
        self.m.as_ref().is_some_and(|m| m.view().current.is_some())
    }

    fn quiet(&self) -> bool {
        self.m
            .as_ref()
            .is_some_and(|m| m.view().cycle == CycleView::Idle)
    }

    fn take_notes(&mut self) -> Vec<String> {
        core::mem::take(&mut self.notes)
    }

    fn name(&self) -> String {
        self.label.clone()
    }
}
