//! The machine: state, `step` as `judge` then `apply`, the poll, the next
//! wake, the read-only view and `close`.
//!
//! The rows each function implements are named in this directory's README,
//! which carries the transition tables. A row that is not matched leaves
//! the machine unchanged and says why in a `Reject`.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use super::candidates::Candidates;
use super::cycle::{Attempt, Cycle, Pend, PendI, PendR, Wait};
use super::epoch::{Drain, Epoch, Final, Ids, Purpose, RecvHome, Role, Slot, Trial};
use super::ladder::{Ladder, Schedule, later, millis};
use super::lease::{EpochTag, allocate};
use super::params::Params;
use super::profile::{
    DampenAt, DoneRead, FrameHint, InitiatorCutover, Leg, Msg1Read, Profile, ResponderCutover,
    Select, SessionKeys,
};
use super::proof::{
    Authentic, Bond, Bonded, Evidence, EvidenceKind, FinalProof, FrameProof, PeerKey, Replayable,
    ReplyProof,
};
use super::reason::{Abandon, Close, Reason, Teardown};
use super::record::{Digest, HeldAnswer, Record};
use super::resolve::{Commit, Own, Verdict, resolve};
use super::{
    Arrival, Binding, Carry, CycleView, Env, EpochView, Identity, Input, Intent, JitterSource,
    MsgKind, Output, Outputs, Route, SealRefusal, Sealed, SealedPrompt, SetupFacts, View, Wire,
};
use crate::identity::NodeAddr;
use crate::time::{Clock, Duration, Instant};

/// The prompt answer gap: at most one prompt per second answers probes and
/// old-epoch frames.
const PROMPT_GAP: Duration = Duration::from_secs(1);

/// A responder samples the handshake round trip only below the first msg3
/// rung, since a later msg3 may be a resend.
const SAMPLE_LIMIT: Duration = Duration::from_secs(1);

/// The smallest probe grace.
const GRACE_MIN: Duration = Duration::from_secs(1);

/// The most expiry passes one poll makes: the first, and one for each
/// hand-over of a stored deadline a row can make (only the delayed
/// cutover's retained msg3 today), with room to spare.
const PASSES: usize = 3;

/// Facts that survive `Idle`, kept outside the cycle.
#[derive(Debug)]
pub(super) struct Memory<I> {
    pub(super) peer_epoch: Option<[u8; 8]>,
    /// The key-epoch bit on the peer's last authenticated current-epoch
    /// frame.
    pub(super) peer_k: Option<bool>,
    /// The jitter drawn at the last install or cutover, whole seconds.
    pub(super) jitter: i32,
    /// Dampening ends.
    pub(super) damp: Option<I>,
    /// The abandon backoff ends.
    backoff: Option<I>,
    abandons: u8,
    /// The last authenticated frame under any epoch (liveness).
    last_rx: Option<I>,
    /// The last authenticated frame under the current epoch.
    rx_cur: Option<I>,
    /// Data was sealed since the last current-epoch frame from the peer.
    sent_data: bool,
    silence: u8,
    pub(super) link_since: I,
    pub(super) last_cutover: Option<I>,
    hs_rtt: Option<Duration>,
    srtt: Option<Duration>,
    /// Karn's kept backoff for the rekey setup's first rung.
    setup_rto: Option<Duration>,
    reachable: bool,
    /// A repair rekey is due.
    due: bool,
}

impl<I> Memory<I> {
    /// The memory of a machine that has learned nothing yet.
    fn new(link_since: I) -> Self {
        Self {
            peer_epoch: None,
            peer_k: None,
            jitter: 0,
            damp: None,
            backoff: None,
            abandons: 0,
            last_rx: None,
            rx_cur: None,
            sent_data: false,
            silence: 0,
            link_since,
            last_cutover: None,
            hs_rtt: None,
            srtt: None,
            setup_rto: None,
            reachable: true,
            due: false,
        }
    }
}

/// One keyed relationship's rekey machine.
///
/// Built by [`Rekey::established`] for a link whose setup completed, or by
/// [`Rekey::opening_outbound`] and [`Rekey::opening_inbound`] for an FSP
/// session's first handshake. Driven by [`Rekey::step`]; frames are sealed
/// through [`Rekey::seal`] and [`Rekey::seal_prompt`]; ended by
/// [`Rekey::close`].
pub struct Rekey<P: Profile, C: Clock> {
    pub(super) params: Params,
    pub(super) bond: Bond,
    me: NodeAddr,
    /// The current epoch; `None` while the first handshake is open.
    pub(super) cur: Option<Epoch<P, C::Instant>>,
    pub(super) drain: Option<Drain<P, C::Instant>>,
    pub(super) cycle: Cycle<P, C::Instant>,
    cands: Candidates<P, C::Instant>,
    pub(super) record: Record,
    pub(super) mem: Memory<C::Instant>,
    clock: PhantomData<fn() -> C>,
}

/// The commit `judge` produces for `apply`.
enum Change<'a, P: Profile> {
    /// Nothing changes.
    Reject(Reason),
    /// Send a stored reply on the route its first copy took; nothing
    /// changes.
    Resend {
        msg: Wire,
        kind: MsgKind,
        route: Route,
    },
    /// Refuse, recording the msg1's ephemeral when one is given.
    Refuse {
        reason: Reason,
        ephemeral: Option<Digest>,
    },
    /// Ask the shell to apply the restart gates to a fresh msg1, recording
    /// its ephemeral when one is given.
    Replace {
        tok: Authentic<P::Msg1, Replayable>,
        ephemeral: Option<Digest>,
    },
    /// Answer a fresh eligible msg1, yielding an unanswered own attempt.
    Respond {
        tok: Authentic<P::Msg1, Replayable>,
        yield_own: bool,
    },
    /// The own attempt's reply authenticated.
    Reply {
        proof: ReplyProof<P>,
        route: P::Route,
    },
    /// Hold a new candidate, evicting one first in a first handshake.
    Candidate {
        hs: Box<P::Hs>,
        msg1: Wire,
        ack: Wire,
        carrier: P::Carrier,
        route: P::Route,
        evict: Option<u64>,
    },
    /// Drop one candidate.
    Drop { seq: u64, reason: Reason },
    /// Complete a candidate.
    Accept { proof: FinalProof<P>, restart: bool },
    /// Take a leg table's completion as a responder pending.
    Done {
        done: Bonded<P>,
        lease: Option<super::IndexLease>,
        restart: bool,
    },
    /// Release a leg table's completion.
    Release { leg: Leg<P>, reason: Reason },
    /// A frame authenticated.
    Frame {
        proof: FrameProof,
        buf: &'a mut [u8],
        body: usize,
    },
    /// A decrypt worker authenticated a frame.
    Worker { slot: Slot, k: bool, counter: u64 },
    /// A worker accepted an epoch.
    Delegated(Slot),
    /// A worker holding an epoch is gone.
    Undelegated(Slot),
    /// Start the first attempt toward `peer`.
    Open(PeerKey),
    /// Data was sealed.
    DataSent,
    /// Path facts changed.
    Path {
        reachable: bool,
        srtt: Option<Duration>,
    },
    /// Process deadlines and start conditions.
    Poll,
}

/// Where a setup goes, before any handshake work is spent on it.
enum Room<'a> {
    /// Refused for this reason.
    Refused(Reason),
    /// A copy of a held candidate's setup, answered with this stored ack.
    Copy(&'a Wire),
    /// A new candidate beside the others.
    Free,
    /// A new candidate in the place of the candidate with this arrival
    /// number.
    Evict(u64),
}

/// The copy kind of an IK msg1.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Copied {
    /// Byte for byte the link-setup msg1.
    Setup,
    /// Byte for byte the msg1 that armed the held pending.
    Armed,
    /// A msg1 whose ephemeral the record holds (or the held pending's).
    Seen,
    /// A fresh ephemeral.
    Fresh,
}

/// A stored deadline due in a poll, in the order rows are processed when
/// instants tie.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Due {
    Drain(EpochTag),
    Candidate(u64),
    Unadopted(EpochTag),
    Held(EpochTag),
    Probe(EpochTag),
    Delayed(EpochTag),
    Fin(EpochTag),
    Elicit(EpochTag),
    Confirm(EpochTag),
    DelayEnd(EpochTag),
    Resend,
    Expire,
}

/// Time from `t` to `now`, zero if `t` is later.
fn since<I: Instant>(now: I, t: I) -> Duration {
    now.saturating_duration_since(t)
}

/// Discard an epoch: unbind and revoke its index with the transport
/// recorded at the binding, release its lease, erase its keys.
pub(super) fn retire<P: Profile, I>(ep: Epoch<P, I>, out: &mut Outputs<P>) {
    let Epoch {
        tag,
        ids,
        recv,
        session,
        ..
    } = ep;
    if let Some((transport, index)) = ids.binding() {
        out.push(Output::Unbind { transport, index });
        if recv == RecvHome::Delegated && !fault!(RetireSkipsRevoke) {
            out.push(Output::Revoke {
                tag,
                transport,
                index,
            });
        }
    }
    if let Some(lease) = ids.lease {
        out.push(Output::Release(lease));
    }
    drop(session);
    out.push(Output::Retired { tag });
}

/// Give up an own attempt: unbind and release its index, drop its
/// handshake (which erases itself), report why.
fn abandon<P: Profile, I>(a: Attempt<P, I>, cause: Abandon, out: &mut Outputs<P>) {
    let Attempt {
        hs,
        lease,
        transport,
        ..
    } = a;
    if let Some(lease) = lease {
        out.push(Output::Unbind {
            transport,
            index: lease.index(),
        });
        out.push(Output::Release(lease));
    }
    drop(hs);
    out.push(Output::Abandoned(cause));
}

/// A rekey jitter drawn from `[-j, +j]` whole seconds.
fn jitter<P: Profile>(env: &mut Env<'_, P>, j: u16) -> i32 {
    draw_jitter(env.jitter, j)
}

/// A rekey jitter drawn from `[-j, +j]` whole seconds out of `src`.
pub(super) fn draw_jitter(src: &mut dyn JitterSource, j: u16) -> i32 {
    let bound = j.saturating_mul(2);
    #[cfg(test)]
    if fault!(GlobalJitter) {
        return i32::from(super::faults::global_jitter(bound)) - i32::from(j);
    }
    i32::from(src.draw(bound)) - i32::from(j)
}

/// The later of two optional instants.
fn latest<I: Instant>(a: Option<I>, b: I) -> I {
    a.map_or(b, |a| a.max(b))
}

impl<P: Profile, C: Clock> Rekey<P, C> {
    /// A machine for a link (or session) whose setup completed with
    /// `first`, its indices `ids` and the facts link setup knew.
    ///
    /// Emits the binding of the first epoch's index and, when a worker pool
    /// exists, its delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn established(
        params: Params,
        bond: Bond,
        me: NodeAddr,
        first: Bonded<P>,
        ids: Ids<P::Transport>,
        facts: SetupFacts<C::Instant>,
        now: C::Instant,
        env: &mut Env<'_, P>,
    ) -> (Self, Outputs<P>) {
        let mut out = Outputs::new();
        let tag = env.tags.draw();
        let mut ep = Epoch::new(tag, first, ids, facts.k, Role::Initiator, facts.started);
        ep.base = Some(facts.started);
        let mut mem = Memory::new(facts.link_since);
        mem.peer_epoch = facts.peer_epoch;
        mem.peer_k = facts.peer_k;
        mem.jitter = jitter(env, params.cfg.jitter);
        let _ = now;
        let mut machine = Self {
            params,
            bond,
            me,
            cur: None,
            drain: None,
            cycle: Cycle::Idle,
            cands: Candidates::new(),
            record: facts.record,
            mem,
            clock: PhantomData,
        };
        if let Some((transport, index)) = ep.ids.binding() {
            out.push(Output::Bind {
                transport,
                index,
                tag: Some(tag),
                purpose: Purpose::Current,
            });
        }
        machine.delegate(&ep, env.workers, &mut out);
        machine.cur = Some(ep);
        (machine, out)
    }

    /// A first handshake this node opens toward `peer`: starts the first
    /// attempt at once and returns its setup to send.
    pub fn opening_outbound(
        params: Params,
        peer: PeerKey,
        me: NodeAddr,
        now: C::Instant,
        only: P::Fsp,
        env: &mut Env<'_, P>,
    ) -> (Self, Outputs<P>) {
        let _ = only;
        let mut machine = Self::opening(params, Bond::Key(peer), me, now);
        let mut out = Outputs::new();
        machine.start(now, env, &mut out);
        if matches!(machine.cycle, Cycle::Idle) {
            out.push(Output::Teardown(Teardown::OpeningFailed));
        }
        (machine, out)
    }

    /// A first handshake opened by the peer's admitted `setup`, which
    /// claims the address `claimed`.
    pub fn opening_inbound(
        params: Params,
        claimed: NodeAddr,
        me: NodeAddr,
        now: C::Instant,
        setup: Input<'_, P>,
        only: P::Fsp,
        env: &mut Env<'_, P>,
    ) -> (Self, Outputs<P>) {
        let _ = only;
        let mut machine = Self::opening(params, Bond::Claimed(claimed), me, now);
        let mut out = machine.step(now, setup, env);
        if machine.cands.is_empty() {
            out.push(Output::Teardown(Teardown::OpeningIdle));
        }
        (machine, out)
    }

    /// An empty first-handshake machine.
    fn opening(params: Params, bond: Bond, me: NodeAddr, now: C::Instant) -> Self {
        Self {
            params,
            bond,
            me,
            cur: None,
            drain: None,
            cycle: Cycle::Idle,
            cands: Candidates::new(),
            record: Record::new(),
            mem: Memory::new(now),
            clock: PhantomData,
        }
    }

    /// Process one input at `now`.
    pub fn step(
        &mut self,
        now: C::Instant,
        input: Input<'_, P>,
        env: &mut Env<'_, P>,
    ) -> Outputs<P> {
        let mut out = Outputs::new();
        let change = self.judge(now, input, env);
        self.apply(now, change, env, &mut out);
        self.withdraw(&mut out);
        out
    }

    /// Drop every prompt that no longer names an epoch `seal_prompt`
    /// accepts. The shell seals prompts after the step, so a prompt that an
    /// earlier row of the step asked for under an epoch a later row of the
    /// same step demoted or retired (a late poll's keepalive under the
    /// current epoch, then the assumed cutover at the confirmation deadline)
    /// could not be sealed.
    fn withdraw(&self, out: &mut Outputs<P>) {
        out.retain(|o| {
            if let Output::Prompt { tag } = o {
                self.sealable(*tag)
            } else {
                true
            }
        });
    }

    /// Whether `seal_prompt` accepts `tag`: the current epoch, or the
    /// pending epoch of a completed own attempt waiting for evidence.
    fn sealable(&self, tag: EpochTag) -> bool {
        if self.cur.as_ref().is_some_and(|c| c.tag == tag) {
            return true;
        }
        match &self.cycle {
            Cycle::PendI(p) => p.ep.tag == tag && p.wait == Wait::Evidence,
            Cycle::Idle | Cycle::Init(_) | Cycle::PendR(_) => false,
        }
    }

    // ---- judge: every read and check, no change ----

    /// Reject `input` or produce the commit of its row, with a shared
    /// borrow.
    fn judge<'a>(
        &self,
        now: C::Instant,
        input: Input<'a, P>,
        env: &mut Env<'_, P>,
    ) -> Change<'a, P> {
        match input {
            Input::Reply { bytes, route } => self.judge_reply(bytes, route, env),
            Input::Final { bytes, only } => {
                let _ = only;
                self.judge_final(bytes)
            }
            Input::Setup {
                msg1,
                carrier,
                route,
                only,
            } => {
                let _ = only;
                self.judge_setup(now, msg1, carrier, route, env)
            }
            Input::PeerMsg1 { tok, arrival } => self.judge_msg1(now, tok, arrival),
            Input::PeerDone { tok, intent } => self.judge_done(tok, intent),
            Input::Frame { buf, hint } => self.judge_frame(buf, hint, env),
            Input::WorkerFrame {
                tag,
                k,
                counter,
                only,
            } => {
                let _ = only;
                match self.slot_of(tag) {
                    Some(Slot::Current) => Change::Worker {
                        slot: Slot::Current,
                        k,
                        counter,
                    },
                    Some(Slot::Previous) => Change::Worker {
                        slot: Slot::Previous,
                        k,
                        counter,
                    },
                    Some(Slot::Pending) => Change::Reject(Reason::NotDelegated),
                    None => Change::Reject(Reason::StaleTag),
                }
            }
            Input::Delegated { tag, only } => {
                let _ = only;
                match self.slot_of(tag) {
                    Some(slot @ (Slot::Current | Slot::Previous)) => {
                        if self.recv_of(slot) == Some(RecvHome::Delegated) {
                            Change::Reject(Reason::AlreadyDelegated)
                        } else {
                            Change::Delegated(slot)
                        }
                    }
                    Some(Slot::Pending) => Change::Reject(Reason::NotOffered),
                    None => Change::Reject(Reason::StaleTag),
                }
            }
            Input::Undelegated { tag, only } => {
                let _ = only;
                match self.slot_of(tag) {
                    Some(slot @ (Slot::Current | Slot::Previous)) => {
                        if self.recv_of(slot) == Some(RecvHome::Delegated) {
                            Change::Undelegated(slot)
                        } else {
                            Change::Reject(Reason::NotDelegated)
                        }
                    }
                    Some(Slot::Pending) => Change::Reject(Reason::NotDelegated),
                    None => Change::Reject(Reason::StaleTag),
                }
            }
            Input::Open { peer, only } => {
                let _ = only;
                self.judge_open(peer)
            }
            Input::DataSent { only } => {
                let _ = only;
                Change::DataSent
            }
            Input::PathFacts {
                reachable,
                srtt,
                only,
            } => {
                let _ = only;
                Change::Path { reachable, srtt }
            }
            Input::Poll => Change::Poll,
        }
    }

    /// The slot holding the epoch `tag`.
    fn slot_of(&self, tag: EpochTag) -> Option<Slot> {
        if self.cur.as_ref().is_some_and(|e| e.tag == tag) {
            return Some(Slot::Current);
        }
        if self.drain.as_ref().is_some_and(|d| d.ep.tag == tag) {
            return Some(Slot::Previous);
        }
        if self.pending().is_some_and(|e| e.tag == tag) {
            return Some(Slot::Pending);
        }
        None
    }

    /// Where the receive half of the epoch in `slot` lives.
    fn recv_of(&self, slot: Slot) -> Option<RecvHome> {
        self.epoch(slot).map(|e| e.recv)
    }

    /// The epoch in `slot`.
    pub(super) fn epoch(&self, slot: Slot) -> Option<&Epoch<P, C::Instant>> {
        match slot {
            Slot::Current => self.cur.as_ref(),
            Slot::Previous => self.drain.as_ref().map(|d| &d.ep),
            Slot::Pending => self.pending(),
        }
    }

    /// The epoch in `slot`, mutably.
    pub(super) fn epoch_mut(&mut self, slot: Slot) -> Option<&mut Epoch<P, C::Instant>> {
        match slot {
            Slot::Current => self.cur.as_mut(),
            Slot::Previous => self.drain.as_mut().map(|d| &mut d.ep),
            Slot::Pending => match &mut self.cycle {
                Cycle::PendI(p) => Some(&mut p.ep),
                Cycle::PendR(p) => Some(&mut p.ep),
                Cycle::Idle | Cycle::Init(_) => None,
            },
        }
    }

    /// The pending epoch, in either role.
    fn pending(&self) -> Option<&Epoch<P, C::Instant>> {
        match &self.cycle {
            Cycle::PendI(p) => Some(&p.ep),
            Cycle::PendR(p) => Some(&p.ep),
            Cycle::Idle | Cycle::Init(_) => None,
        }
    }

    /// The peer's node address.
    fn peer(&self) -> NodeAddr {
        self.bond.addr()
    }

    /// Whether this node's address is the smaller.
    fn smaller(&self) -> bool {
        self.me < self.peer()
    }

    /// Whether a completed own attempt would be kept against a competing
    /// msg3 from a peer that did not restart: the verdict that decides
    /// which candidates outlive an epoch this node made current.
    fn keeps_completed(&self) -> bool {
        resolve(
            Commit::AtFinal,
            Own::Completed,
            &self.me,
            &self.peer(),
            false,
        ) == Verdict::KeepOwn
    }

    /// What the cycle says about this node's own attempt, for the
    /// tie-break: the current epoch counts as a completed own attempt while
    /// its final message is still resent.
    fn own(&self) -> Own {
        match &self.cycle {
            Cycle::Idle => {
                if self.cur.as_ref().is_some_and(|c| c.fin.is_some()) {
                    Own::Completed
                } else {
                    Own::None
                }
            }
            Cycle::Init(_) => Own::Unanswered,
            Cycle::PendI(_) => Own::Completed,
            Cycle::PendR(_) => Own::None,
        }
    }

    /// The probe grace: twice the larger of the handshake and session
    /// round trips, at least one second, capped so the last probe plus the
    /// grace fits inside the confirmation window.
    fn grace(&self) -> Duration {
        let rtt = self
            .mem
            .hs_rtt
            .unwrap_or(Duration::ZERO)
            .max(self.mem.srtt.unwrap_or(Duration::ZERO));
        let grace = rtt.saturating_mul(2).max(GRACE_MIN);
        if fault!(NoGraceCap) {
            grace
        } else {
            grace.min(self.params.grace)
        }
    }

    /// A reply: by index for an index-bearing profile, else by the cycle.
    fn judge_reply(
        &self,
        bytes: &[u8],
        route: P::Route,
        env: &mut Env<'_, P>,
    ) -> Change<'static, P> {
        let attempt = match &self.cycle {
            Cycle::Init(a) => Some(a),
            Cycle::Idle | Cycle::PendI(_) | Cycle::PendR(_) => None,
        };
        if P::INDEXED {
            let index = P::index(bytes);
            let ours = attempt.and_then(|a| a.lease.as_ref().map(super::IndexLease::index));
            if index.is_none() || index != ours {
                let held = [Slot::Pending, Slot::Current, Slot::Previous]
                    .into_iter()
                    .filter_map(|s| self.epoch(s))
                    .any(|e| index.is_some() && e.ids.ours() == index);
                return Change::Reject(if held {
                    Reason::LateReply
                } else {
                    Reason::UnknownIndex
                });
            }
        }
        let Some(a) = attempt else {
            return Change::Reject(match self.cycle {
                Cycle::PendI(_) => Reason::LateReply,
                Cycle::Idle | Cycle::Init(_) | Cycle::PendR(_) => Reason::UnknownAttempt,
            });
        };
        let Ok(read) = P::reply(&a.hs, env.local, bytes) else {
            return Change::Reject(Reason::ReplyUnauthenticated);
        };
        let bond = if fault!(BondAfterEpoch) {
            Bond::Key(read.done.remote)
        } else {
            self.bond
        };
        match bond.check(read.done) {
            Ok(done) => Change::Reply {
                proof: ReplyProof::new(done, read.fin),
                route,
            },
            Err(_) => Change::Reject(Reason::ReplyUnauthenticated),
        }
    }

    /// A setup, in the order validation, stored reply, refusal, room.
    fn judge_setup(
        &self,
        now: C::Instant,
        msg1: &[u8],
        carrier: P::Carrier,
        route: P::Route,
        env: &mut Env<'_, P>,
    ) -> Change<'static, P> {
        let evict = match self.setup_room(now, msg1, carrier) {
            Room::Refused(reason) => return Change::Reject(reason),
            Room::Copy(ack) => {
                return Change::Resend {
                    msg: ack.clone(),
                    kind: MsgKind::Ack,
                    route: Route::Established { fallback: false },
                };
            }
            Room::Free => None,
            Room::Evict(seq) => Some(seq),
        };
        let Ok((hs, ack)) = P::answer(env.local, msg1) else {
            return Change::Reject(Reason::SetupMalformed);
        };
        Change::Candidate {
            hs: Box::new(hs),
            msg1: msg1.to_vec(),
            ack,
            carrier,
            route,
            evict,
        }
    }

    /// Where a setup `msg1` arriving over `carrier` at `now` goes, by the
    /// rows S1-1, S1-2, S1-0, S1-3, S1-4 and S1-5 in that order, read
    /// without the handshake work of answering it.
    fn setup_room(&self, now: C::Instant, msg1: &[u8], carrier: P::Carrier) -> Room<'_> {
        if !P::valid(msg1) {
            return Room::Refused(Reason::SetupMalformed);
        }
        if let Some(c) = self.cands.find(msg1).filter(|_| !fault!(FreshAck)) {
            return Room::Copy(&c.ack);
        }
        let young = match &self.cycle {
            Cycle::Init(a) => self.cur.is_none() && since(now, a.first) < self.params.cfg.young,
            Cycle::Idle | Cycle::PendI(_) | Cycle::PendR(_) => false,
        };
        let pendi = matches!(self.cycle, Cycle::PendI(_));
        let mut completed = self.own() == Own::Completed;
        if fault!(S10Fin) {
            completed = pendi;
        }
        if fault!(S10PendI) {
            completed = completed && !pendi;
        }
        if self.smaller() && (completed || young) {
            return Room::Refused(Reason::TieBreakKept);
        }
        if self.cands.room(carrier) {
            Room::Free
        } else if self.cur.is_none() || fault!(EvictEstablished) {
            match self.cands.victim(carrier, now, self.params.cfg.young) {
                Some(seq) => Room::Evict(seq),
                None => Room::Refused(Reason::CandidatesFull),
            }
        } else {
            Room::Refused(Reason::CandidatesFull)
        }
    }

    /// Whether a setup `msg1` arriving over `carrier` at `now` would be
    /// held as a new candidate beside the ones already held: a setup the
    /// machine neither answers from a held candidate, nor refuses, nor makes
    /// room for by evicting one. The shell reads it before stepping such a
    /// setup to charge the new candidate to its half-open share. Changes
    /// nothing.
    pub fn grows(&self, now: C::Instant, msg1: &[u8], carrier: P::Carrier) -> bool {
        matches!(self.setup_room(now, msg1, carrier), Room::Free)
    }

    /// A msg3: the one dispatcher, trying every candidate newest first.
    fn judge_final(&self, bytes: &[u8]) -> Change<'static, P> {
        if self.cands.is_empty() {
            return Change::Reject(Reason::FinalNoAttempt);
        }
        let found = self
            .cands
            .newest()
            .find_map(|c| P::complete(&c.hs, bytes).ok().map(|done| (c, done)));
        let Some((cand, done)) = found else {
            return Change::Reject(Reason::FinalUnauthenticated);
        };
        let seq = cand.seq;
        let bound = cand.bound;
        let done = match self.bond.check(done) {
            Ok(done) => done,
            Err(_) => {
                return Change::Drop {
                    seq,
                    reason: Reason::KeyMismatch,
                };
            }
        };
        if bound.is_some_and(|e| e != done.epoch()) && !fault!(SkipStaleIncarnation) {
            return Change::Drop {
                seq,
                reason: Reason::StaleIncarnation,
            };
        }
        let restart = self.cur.is_some() && self.mem.peer_epoch.is_some_and(|e| e != done.epoch());
        match resolve(Commit::AtFinal, self.own(), &self.me, &self.peer(), restart) {
            Verdict::Accept | Verdict::YieldOwn => Change::Accept {
                proof: FinalProof::new(done, seq),
                restart,
            },
            Verdict::KeepOwn | Verdict::DiscardCompeting => Change::Drop {
                seq,
                reason: Reason::TieBreakKept,
            },
        }
    }

    /// An IK msg1 read as the peer: the eligibility and copy-kind rows.
    fn judge_msg1(
        &self,
        now: C::Instant,
        tok: Authentic<P::Msg1, Replayable>,
        arrival: Arrival,
    ) -> Change<'static, P> {
        let Some(cur) = &self.cur else {
            return Change::Reject(Reason::NotEstablished);
        };
        let m = tok.get();
        if self.mem.peer_epoch != Some(m.epoch()) {
            return Change::Reject(Reason::EpochChanged);
        }
        if self.bond != Bond::Key(m.remote()) {
            return Change::Reject(Reason::KeyMismatch);
        }
        let cfg = &self.params.cfg;
        let eligible = since(now, self.mem.link_since) >= cfg.link_age
            && since(now, cur.started) >= cfg.session_age;
        let digest = m.digest();
        let key = m.ephemeral();
        let held = match &self.cycle {
            Cycle::PendR(p) => p.answer.as_ref(),
            Cycle::Idle | Cycle::Init(_) | Cycle::PendI(_) => None,
        };
        let copy = if self.record.is_setup(&digest) {
            Copied::Setup
        } else if held.is_some_and(|h| h.msg1 == digest) {
            Copied::Armed
        } else if self.record.holds(&key) || held.is_some_and(|h| h.ephemeral == key) {
            Copied::Seen
        } else {
            Copied::Fresh
        };
        let fresh = (copy == Copied::Fresh).then_some(key);
        if !eligible {
            return match copy {
                Copied::Setup => match self.record.setup_answer() {
                    Some(msg2) => Change::Resend {
                        msg: msg2.clone(),
                        kind: MsgKind::Msg2,
                        route: Route::Established { fallback: true },
                    },
                    None => Change::Reject(Reason::AnsweredBefore),
                },
                Copied::Armed | Copied::Seen => Change::Reject(Reason::AnsweredBefore),
                Copied::Fresh => Change::Replace {
                    tok,
                    ephemeral: fresh,
                },
            };
        }
        if !arrival.on_link && arrival.reachable {
            return Change::Refuse {
                reason: Reason::OffLink,
                ephemeral: fresh,
            };
        }
        match (&self.cycle, copy) {
            (Cycle::PendR(_), Copied::Armed) => match held {
                Some(h) => Change::Resend {
                    msg: h.msg2.clone(),
                    kind: MsgKind::Msg2,
                    route: Route::Established { fallback: true },
                },
                None => Change::Reject(Reason::AnsweredBefore),
            },
            (Cycle::PendR(_) | Cycle::PendI(_), Copied::Setup | Copied::Seen | Copied::Fresh)
            | (Cycle::PendI(_), Copied::Armed) => Change::Refuse {
                reason: Reason::PendingHeld,
                ephemeral: fresh,
            },
            (Cycle::Idle | Cycle::Init(_), Copied::Setup | Copied::Seen | Copied::Armed) => {
                Change::Reject(Reason::AnsweredBefore)
            }
            (Cycle::Init(_), Copied::Fresh) => {
                match resolve(
                    Commit::AtAnswer,
                    Own::Unanswered,
                    &self.me,
                    &self.peer(),
                    false,
                ) {
                    Verdict::YieldOwn if fault!(LargerKeepsOwn) => Change::Refuse {
                        reason: Reason::DualInitWon,
                        ephemeral: fresh,
                    },
                    Verdict::YieldOwn => Change::Respond {
                        tok,
                        yield_own: true,
                    },
                    Verdict::KeepOwn | Verdict::Accept | Verdict::DiscardCompeting => {
                        Change::Refuse {
                            reason: Reason::DualInitWon,
                            ephemeral: fresh,
                        }
                    }
                }
            }
            (Cycle::Idle, Copied::Fresh) => Change::Respond {
                tok,
                yield_own: false,
            },
        }
    }

    /// A leg table's completion (next only).
    fn judge_done(
        &self,
        tok: Authentic<P::Done, super::Fresh>,
        intent: Intent,
    ) -> Change<'static, P> {
        let leg = tok.into_inner().take();
        match intent {
            Intent::Rekey => {}
            Intent::Fresh | Intent::Mismatch => {
                return Change::Release {
                    leg,
                    reason: Reason::NotRekey,
                };
            }
        }
        if self.cur.is_none() {
            return Change::Release {
                leg,
                reason: Reason::NotEstablished,
            };
        }
        let Leg { done, lease } = leg;
        let done = match self.bond.check(done) {
            Ok(done) => done,
            Err(done) => {
                return Change::Release {
                    leg: Leg { done, lease },
                    reason: Reason::KeyMismatch,
                };
            }
        };
        let restart = self.mem.peer_epoch.is_some_and(|e| e != done.epoch());
        match resolve(P::COMMIT, self.own(), &self.me, &self.peer(), restart) {
            Verdict::Accept | Verdict::YieldOwn => Change::Done {
                done,
                lease,
                restart,
            },
            Verdict::KeepOwn | Verdict::DiscardCompeting => Change::Release {
                leg: Leg {
                    done: done.into_inner(),
                    lease,
                },
                reason: Reason::TieBreakKept,
            },
        }
    }

    /// An established frame: select its epoch by index or by trial and
    /// open it into the scratch buffer.
    fn judge_frame<'a>(
        &self,
        buf: &'a mut [u8],
        hint: FrameHint,
        env: &mut Env<'_, P>,
    ) -> Change<'a, P> {
        let Some(cur) = &self.cur else {
            return Change::Reject(Reason::NotEstablished);
        };
        let order: Vec<Slot> = match P::SELECT {
            Select::ByIndex => {
                let named = [Slot::Current, Slot::Pending, Slot::Previous]
                    .into_iter()
                    .find(|&s| {
                        self.epoch(s)
                            .is_some_and(|e| e.ids.ours() == Some(hint.index))
                    });
                let Some(slot) = named else {
                    return Change::Reject(Reason::FrameUnauthenticated);
                };
                if self.recv_of(slot) == Some(RecvHome::Delegated) {
                    return Change::Reject(Reason::DelegatedEpoch);
                }
                alloc::vec![slot]
            }
            Select::Trial => {
                if hint.k == cur.k {
                    alloc::vec![Slot::Current, Slot::Pending, Slot::Previous]
                } else {
                    alloc::vec![Slot::Pending, Slot::Current, Slot::Previous]
                }
            }
        };
        let mut refused = false;
        for slot in order {
            let Some(ep) = self.epoch(slot) else {
                continue;
            };
            if ep.recv == RecvHome::Delegated {
                continue;
            }
            match ep.trial(&hint, buf, env.scratch) {
                Trial::Opened(len) => {
                    let probe = env.scratch.get(..len).is_some_and(P::is_probe);
                    return Change::Frame {
                        proof: FrameProof::new(ep.tag, slot, hint.counter, hint.k, len, probe),
                        buf,
                        body: hint.body,
                    };
                }
                Trial::Refused if fault!(RefusalEndsTrial) => {
                    return Change::Reject(Reason::Replay);
                }
                Trial::Refused => refused = true,
                Trial::Failed if slot == Slot::Pending && fault!(GarbageAdopts) => {
                    return Change::Frame {
                        proof: FrameProof::new(ep.tag, slot, hint.counter, hint.k, 0, false),
                        buf,
                        body: hint.body,
                    };
                }
                Trial::Failed => {}
            }
        }
        Change::Reject(if refused && !fault!(ReplayAsUnauthenticated) {
            Reason::Replay
        } else {
            Reason::FrameUnauthenticated
        })
    }

    /// `Open`: only a first handshake with no attempt in flight.
    fn judge_open(&self, peer: PeerKey) -> Change<'static, P> {
        if self.cur.is_some() {
            return Change::Reject(Reason::AlreadyEstablished);
        }
        match &self.cycle {
            Cycle::Init(_) | Cycle::PendI(_) | Cycle::PendR(_) => {
                Change::Reject(Reason::AttemptInFlight)
            }
            Cycle::Idle => {
                let ok = match self.bond {
                    Bond::Key(key) => key == peer,
                    Bond::Claimed(addr) => peer.addr() == addr,
                };
                if ok {
                    Change::Open(peer)
                } else {
                    Change::Reject(Reason::KeyMismatch)
                }
            }
        }
    }

    // ---- apply: the only mutator ----

    /// Carry out a commit.
    fn apply(
        &mut self,
        now: C::Instant,
        change: Change<'_, P>,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        match change {
            Change::Reject(reason) => {
                out.push(Output::Reject(reason));
                if reason == Reason::FrameUnauthenticated && fault!(ForgedTeardown) {
                    out.push(Output::Teardown(Teardown::CounterExhausted));
                }
            }
            Change::Resend { msg, kind, route } => out.push(Output::Send { msg, kind, route }),
            Change::Refuse { reason, ephemeral } => {
                if let Some(e) = ephemeral.filter(|_| !fault!(RefusalUnrecorded)) {
                    self.record.push(e);
                }
                out.push(Output::Reject(reason));
            }
            Change::Replace { tok, ephemeral } => {
                if let Some(e) = ephemeral {
                    self.record.push(e);
                }
                out.push(Output::ReplaceRequested { tok });
            }
            Change::Respond { tok, yield_own } => self.respond(now, tok, yield_own, env, out),
            Change::Reply { proof, route } => self.reply(now, proof, route, env, out),
            Change::Candidate {
                hs,
                msg1,
                ack,
                carrier,
                route,
                evict,
            } => {
                if let Some(seq) = evict {
                    self.cands.remove(seq);
                }
                let deadline = later(now, self.params.cfg.ttl);
                self.cands
                    .add(hs, msg1, ack.clone(), carrier, route, now, deadline);
                out.push(Output::Send {
                    msg: ack,
                    kind: MsgKind::Ack,
                    route: Route::Established { fallback: false },
                });
            }
            Change::Drop { seq, reason } => {
                self.cands.remove(seq);
                if reason == Reason::KeyMismatch
                    && fault!(FailedFinalRetires)
                    && let Cycle::PendI(p) = core::mem::replace(&mut self.cycle, Cycle::Idle)
                {
                    retire(p.ep, out);
                }
                out.push(Output::Reject(reason));
                self.opening_check(Teardown::OpeningIdle, out);
            }
            Change::Accept { proof, restart } => self.complete(now, proof, restart, env, out),
            Change::Done {
                done,
                lease,
                restart,
            } => self.adopt(now, done, lease, restart, env, out),
            Change::Release { leg, reason } => {
                let Leg { done, lease } = leg;
                drop(done);
                if let Some(lease) = lease {
                    out.push(Output::Unbind {
                        transport: env.transport,
                        index: lease.index(),
                    });
                    out.push(Output::Release(lease));
                }
                out.push(Output::Reject(reason));
            }
            Change::Frame { proof, buf, body } => self.frame(now, proof, buf, body, env, out),
            Change::Worker { slot, k, counter } => {
                if let Some(ep) = self.epoch_mut(slot) {
                    ep.floor = Some(ep.floor.map_or(counter, |f| f.max(counter)));
                }
                match slot {
                    Slot::Current => self.heard_current(now, k, false, out),
                    Slot::Previous => self.heard_previous(now, out),
                    Slot::Pending => {}
                }
            }
            Change::Delegated(slot) => {
                if let Some(ep) = self.epoch_mut(slot) {
                    ep.recv = RecvHome::Delegated;
                }
            }
            Change::Undelegated(slot) => {
                if let Some(ep) = self.epoch_mut(slot) {
                    ep.recv = RecvHome::Here;
                }
            }
            Change::Open(peer) => {
                self.bond = Bond::Key(peer);
                self.start(now, env, out);
            }
            Change::DataSent => self.mem.sent_data = true,
            Change::Path { reachable, srtt } => {
                self.mem.reachable = reachable;
                self.mem.srtt = srtt;
            }
            Change::Poll => self.poll(now, env, out),
        }
    }

    /// In a first handshake, tear down when no attempt and no candidate is
    /// left.
    fn opening_check(&self, why: Teardown, out: &mut Outputs<P>) {
        if self.cur.is_none() && matches!(self.cycle, Cycle::Idle) && self.cands.is_empty() {
            out.push(Output::Teardown(why));
        }
    }

    /// Offer the receive half of `ep` to a decrypt worker when a pool
    /// exists (`workers`), no worker holds it yet and the epoch has an
    /// index.
    pub(super) fn delegate(&self, ep: &Epoch<P, C::Instant>, workers: bool, out: &mut Outputs<P>) {
        if !workers || ep.recv == RecvHome::Delegated {
            return;
        }
        if let Some((transport, index)) = ep.ids.binding() {
            out.push(Output::Delegate {
                tag: ep.tag,
                transport,
                index,
                recv: ep
                    .session
                    .copy(ep.floor.filter(|_| !fault!(ReofferNoFloor))),
            });
        }
    }

    /// Start an own attempt.
    pub(super) fn start(&mut self, now: C::Instant, env: &mut Env<'_, P>, out: &mut Outputs<P>) {
        let Bond::Key(peer) = self.bond else {
            return;
        };
        let lease = if P::INDEXED {
            match allocate(env.indices) {
                Some(lease) => Some(lease),
                None => {
                    out.push(Output::Reject(Reason::IndexExhausted));
                    return;
                }
            }
        } else {
            None
        };
        let ours = lease.as_ref().map(super::IndexLease::index);
        let (hs, msg) = match P::initiate(env.local, &peer, ours) {
            Ok(written) => written,
            Err(_) => {
                if let Some(lease) = lease {
                    out.push(Output::Release(lease));
                }
                out.push(Output::Reject(Reason::HandshakeWrite));
                return;
            }
        };
        let cfg = &self.params.cfg;
        let (sched, deadline) = if self.cur.is_some() && P::SETUP_RTT {
            let rtt = self
                .mem
                .hs_rtt
                .unwrap_or(Duration::ZERO)
                .max(self.mem.srtt.unwrap_or(Duration::ZERO));
            let first = rtt
                .saturating_mul(2)
                .max(Duration::from_secs(1))
                .max(self.mem.setup_rto.unwrap_or(Duration::ZERO))
                .min(self.params.rung);
            let sched = Schedule::doubling(first, u8::MAX, Some(cfg.handshake)).0;
            (sched, cfg.handshake)
        } else {
            (self.params.first, self.params.budget)
        };
        let kind = if P::MESSAGES == 2 {
            MsgKind::Msg1
        } else {
            MsgKind::Setup
        };
        if let Some(index) = ours {
            out.push(Output::Bind {
                transport: env.transport,
                index,
                tag: None,
                purpose: Purpose::Attempt,
            });
        }
        out.push(Output::Send {
            msg: msg.clone(),
            kind,
            route: Route::Established { fallback: false },
        });
        self.cycle = Cycle::Init(Attempt {
            hs: Box::new(hs),
            out: msg,
            lease,
            transport: env.transport,
            first: now,
            ladder: Ladder::new(now, sched),
            deadline: later(now, deadline),
            resent: false,
        });
        self.mem.due = false;
    }

    /// Answer a fresh eligible IK msg1 into a responder pending.
    fn respond(
        &mut self,
        now: C::Instant,
        tok: Authentic<P::Msg1, Replayable>,
        yield_own: bool,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        let lease = if P::INDEXED {
            match allocate(env.indices) {
                Some(lease) => Some(lease),
                None => {
                    out.push(Output::Reject(Reason::IndexExhausted));
                    return;
                }
            }
        } else {
            None
        };
        let m = tok.into_inner();
        let digest = m.digest();
        let ephemeral = m.ephemeral();
        let ours = lease.as_ref().map(super::IndexLease::index);
        let answered = m
            .answer(env.local, ours)
            .ok()
            .and_then(|(done, msg2)| self.bond.check(done).ok().map(|d| (d, msg2)));
        let Some((done, msg2)) = answered else {
            if let Some(lease) = lease {
                out.push(Output::Release(lease));
            }
            out.push(Output::Reject(Reason::HandshakeWrite));
            return;
        };
        if fault!(RespondRetiresDrain)
            && let Some(d) = self.drain.take()
        {
            retire(d.ep, out);
        }
        if yield_own && let Cycle::Init(a) = core::mem::replace(&mut self.cycle, Cycle::Idle) {
            abandon(a, Abandon::Yielded, out);
        }
        let tag = env.tags.draw();
        let ids = Ids {
            lease,
            theirs: done.theirs(),
            transport: env.transport,
        };
        let ep = Epoch::new(tag, done, ids, false, Role::Responder, now);
        if let Some((transport, index)) = ep.ids.binding() {
            out.push(Output::Bind {
                transport,
                index,
                tag: Some(tag),
                purpose: Purpose::Pending,
            });
        }
        let mut arrival = self.params.cfg.arrival;
        if fault!(ReplyOnArrival) {
            arrival = !arrival;
        }
        let route = if arrival {
            Route::Arrival
        } else {
            Route::Established { fallback: true }
        };
        out.push(Output::Send {
            msg: msg2.clone(),
            kind: MsgKind::Msg2,
            route,
        });
        self.cycle = Cycle::PendR(PendR {
            ep,
            deadline: later(now, self.params.cfg.hold),
            restart: false,
            answer: Some(HeldAnswer {
                msg1: digest,
                ephemeral,
                msg2,
            }),
        });
        if P::DAMPEN_AT == DampenAt::Answer {
            self.mem.damp = Some(later(now, self.params.cfg.dampening));
        }
        if fault!(RespondRefreshes) {
            self.mem.last_rx = Some(now);
        }
    }

    /// The own attempt's reply authenticated.
    fn reply(
        &mut self,
        now: C::Instant,
        proof: ReplyProof<P>,
        route: P::Route,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        let Cycle::Init(a) = core::mem::replace(&mut self.cycle, Cycle::Idle) else {
            return;
        };
        self.sample(since(now, a.first), a.resent);
        let Attempt {
            hs,
            lease,
            transport: was,
            ..
        } = a;
        drop(hs);
        let ReplyProof { done, fin } = proof;
        self.answered(now, done, fin, route, lease, was, env, out);
    }

    /// Take a handshake round-trip sample of `rtt`, from an own attempt's
    /// first send to its reply, by Karn's rule: a reply that followed a
    /// resend is not sampled, and an FSP initiator then keeps a backed-off
    /// first rung for its next rekey setup instead.
    fn sample(&mut self, rtt: Duration, resent: bool) {
        if !resent || fault!(KarnOff) {
            self.mem.hs_rtt = Some(rtt);
            self.mem.setup_rto = None;
        } else if P::SETUP_RTT && !fault!(NoKeptBackoff) {
            self.mem.setup_rto = Some(rtt.saturating_mul(2).min(self.params.rung));
        }
    }

    /// An own attempt completed with `done` (and, for three messages, the
    /// final message `fin` it wrote), the reply having carried `route`.
    /// The attempt's index, if any, was bound on `was`.
    #[allow(clippy::too_many_arguments)]
    fn answered(
        &mut self,
        now: C::Instant,
        done: Bonded<P>,
        fin: Option<Wire>,
        route: P::Route,
        lease: Option<super::IndexLease>,
        was: P::Transport,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        let epoch = done.epoch();
        if let Some(f) = &fin {
            out.push(Output::Send {
                msg: f.clone(),
                kind: MsgKind::Msg3,
                route: Route::Established { fallback: false },
            });
        }
        let tag = env.tags.draw();
        let ids = Ids {
            lease,
            theirs: done.theirs(),
            transport: env.transport,
        };
        let Some((cur_k, cur_tag)) = self.cur.as_ref().map(|c| (c.k, c.tag)) else {
            // The first handshake: install at once, retaining msg3.
            let mut ep = Epoch::new(tag, done, ids, false, Role::Initiator, now);
            ep.route = Some(route);
            ep.fin = fin.map(|msg| Final {
                msg,
                ladder: Ladder::new(now, self.params.fin),
            });
            self.mem.peer_epoch = Some(epoch);
            self.install(now, ep, env, out);
            return;
        };
        let restart = self.mem.peer_epoch != Some(epoch);
        let k = if restart {
            false
        } else if fault!(KFromOwn) {
            !cur_k
        } else {
            !self.mem.peer_k.unwrap_or(cur_k)
        };
        if restart {
            self.mem.peer_epoch = Some(epoch);
            if fault!(RestartAtCompletion) {
                out.push(Output::PeerRestarted {
                    layer: P::LAYER,
                    epoch,
                });
            }
        }
        let mut ep = Epoch::new(tag, done, ids, k, Role::Initiator, now);
        if restart && let Some(msg) = fin.clone() {
            Self::rebind(&ep, was, Purpose::Current, out);
            ep.base = Some(now);
            ep.route = Some(route);
            let pend = Pend {
                ep,
                restart: true,
                fin: Some(Final {
                    msg,
                    ladder: Ladder::new(now, self.params.fin),
                }),
            };
            self.cutover(now, pend, Evidence::restart(), false, env, out);
            return;
        }
        Self::rebind(&ep, was, Purpose::Pending, out);
        let cutover = match P::INITIATOR_CUTOVER {
            InitiatorCutover::OnEvidence if fault!(CutoverAtProof) => InitiatorCutover::OnProof,
            c @ (InitiatorCutover::OnProof
            | InitiatorCutover::OnEvidence
            | InitiatorCutover::AfterDelay) => c,
        };
        let (wait, deadline, fin, probes) = match cutover {
            InitiatorCutover::OnProof => (Wait::Held, now, None, None),
            InitiatorCutover::OnEvidence => {
                ep.base = Some(now);
                ep.route = Some(route);
                out.push(Output::Prompt { tag: ep.tag });
                if !fault!(NoKeepalive) {
                    out.push(Output::Prompt { tag: cur_tag });
                }
                let fin = fin.map(|msg| Final {
                    msg,
                    ladder: Ladder::new(now, Schedule::EMPTY),
                });
                let probes = Some(Ladder::new(now, self.params.probes));
                (Wait::Evidence, later(now, self.params.confirm), fin, probes)
            }
            InitiatorCutover::AfterDelay => {
                let delay = self
                    .params
                    .cfg
                    .delay
                    .max(self.mem.hs_rtt.unwrap_or(Duration::ZERO));
                let fin = fin.map(|msg| Final {
                    msg,
                    ladder: Ladder::new(now, self.params.delayed),
                });
                (Wait::Delay, later(now, delay), fin, None)
            }
        };
        let probed = probes.is_some().then_some(now);
        self.cycle = Cycle::PendI(PendI {
            ep,
            wait,
            deadline,
            restart,
            fin,
            probes,
            probed,
            stayed: false,
            reverted: false,
        });
    }

    /// Move an own attempt's index to the epoch it completed into: unbind
    /// it on the transport recorded at the attempt's binding, and bind it
    /// for `purpose` on the transport of now.
    fn rebind(
        ep: &Epoch<P, C::Instant>,
        was: P::Transport,
        purpose: Purpose,
        out: &mut Outputs<P>,
    ) {
        if let Some((transport, index)) = ep.ids.binding() {
            out.push(Output::Unbind {
                transport: if fault!(UnbindTransportNow) {
                    transport
                } else {
                    was
                },
                index,
            });
            out.push(Output::Bind {
                transport,
                index,
                tag: Some(ep.tag),
                purpose,
            });
        }
    }
}

/// What starts an own rekey.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Start {
    /// The time or message trigger, the soft counter limit, or a repair.
    Scheduled,
    /// Authenticated silence while this node sends data.
    Silence,
}

impl<P: Profile, C: Clock> Rekey<P, C> {
    /// Install the first epoch of a session at the end of its first
    /// handshake. Not a cutover: there is no epoch to drain.
    fn install(
        &mut self,
        now: C::Instant,
        mut ep: Epoch<P, C::Instant>,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        ep.started = now;
        ep.base = Some(now);
        self.mem.jitter = jitter(env, self.params.cfg.jitter);
        if let Some((transport, index)) = ep.ids.binding() {
            out.push(Output::Bind {
                transport,
                index,
                tag: Some(ep.tag),
                purpose: Purpose::Current,
            });
        }
        self.delegate(&ep, env.workers, out);
        out.push(Output::Installed {
            tag: ep.tag,
            role: ep.role,
            evidence: EvidenceKind::First,
        });
        if ep.role == Role::Responder {
            out.push(Output::Prompt { tag: ep.tag });
            ep.prompted = Some(now);
        }
        self.cur = Some(ep);
        self.cycle = Cycle::Idle;
    }

    /// A bonded msg3 completed a candidate: apply the tie-break's verdict
    /// to the cycle, then accept.
    fn complete(
        &mut self,
        now: C::Instant,
        proof: FinalProof<P>,
        restart: bool,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        let FinalProof { done, seq } = proof;
        let Some(cand) = self.cands.remove(seq) else {
            return;
        };
        self.cands
            .retain(|c| c.seq > seq && !fault!(AcceptDropsNewer));
        self.accept(now, done, Some(cand.route), cand.born, restart, env, out);
    }

    /// Accept a peer's completed attempt `done`, whose setup arrived at
    /// `born` carrying `route`, after the tie-break allowed it: yield the
    /// cycle, sample the round trip, open dampening and cut over (or hold a
    /// frame-driven responder's pending).
    #[allow(clippy::too_many_arguments)]
    fn accept(
        &mut self,
        now: C::Instant,
        done: Bonded<P>,
        route: Option<P::Route>,
        born: C::Instant,
        restart: bool,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        match core::mem::replace(&mut self.cycle, Cycle::Idle) {
            Cycle::Idle => {
                if let Some(cur) = self.cur.as_mut() {
                    cur.fin = None;
                }
            }
            Cycle::Init(a) => abandon(a, Abandon::Yielded, out),
            Cycle::PendI(p) => retire(p.ep, out),
            Cycle::PendR(p) => {
                let (ep, _) = p.end(&mut self.record);
                retire(ep, out);
                out.push(Output::Abandoned(Abandon::Superseded));
            }
        }
        let rtt = since(now, born);
        if rtt < SAMPLE_LIMIT {
            self.mem.hs_rtt = Some(rtt);
            self.mem.setup_rto = None;
        }
        if P::DAMPEN_AT == DampenAt::Completion {
            self.mem.damp = Some(later(now, self.params.cfg.dampening));
        }
        self.mem.peer_epoch = Some(done.epoch());
        self.bond = Bond::Key(done.remote());
        let tag = env.tags.draw();
        let ids = Ids::unindexed(env.transport);
        let Some(cur_k) = self.cur.as_ref().map(|c| c.k) else {
            let mut ep = Epoch::new(tag, done, ids, false, Role::Responder, now);
            ep.route = route;
            self.install(now, ep, env, out);
            return;
        };
        let k = if restart { false } else { !cur_k };
        let mut ep = Epoch::new(tag, done, ids, k, Role::Responder, now);
        ep.route = route;
        match P::RESPONDER_CUTOVER {
            ResponderCutover::AtProof => {
                ep.base = Some(now);
                let pend = Pend {
                    ep,
                    restart,
                    fin: None,
                };
                self.cutover(now, pend, Evidence::proof(), true, env, out);
            }
            ResponderCutover::OnFrame => {
                self.cycle = Cycle::PendR(PendR {
                    ep,
                    deadline: later(now, self.params.cfg.hold),
                    restart,
                    answer: None,
                });
            }
        }
    }

    /// A leg table's completion becomes the responder pending, after the
    /// tie-break's verdict on the cycle.
    fn adopt(
        &mut self,
        now: C::Instant,
        done: Bonded<P>,
        lease: Option<super::IndexLease>,
        restart: bool,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        match core::mem::replace(&mut self.cycle, Cycle::Idle) {
            Cycle::Idle => {
                if let Some(cur) = self.cur.as_mut() {
                    cur.fin = None;
                }
            }
            Cycle::Init(a) => abandon(a, Abandon::Yielded, out),
            Cycle::PendI(p) => retire(p.ep, out),
            Cycle::PendR(p) => {
                let (ep, _) = p.end(&mut self.record);
                retire(ep, out);
                out.push(Output::Abandoned(Abandon::Superseded));
            }
        }
        if restart {
            self.mem.peer_epoch = Some(done.epoch());
        }
        let tag = env.tags.draw();
        let ids = Ids {
            lease,
            theirs: done.theirs(),
            transport: env.transport,
        };
        let ep = Epoch::new(tag, done, ids, false, Role::Responder, now);
        if let Some((transport, index)) = ep.ids.binding() {
            out.push(Output::Bind {
                transport,
                index,
                tag: Some(tag),
                purpose: Purpose::Pending,
            });
        }
        self.cycle = Cycle::PendR(PendR {
            ep,
            deadline: later(now, self.params.cfg.hold),
            restart,
            answer: None,
        });
        if P::DAMPEN_AT == DampenAt::Completion {
            self.mem.damp = Some(later(now, self.params.cfg.dampening));
        }
    }

    /// A frame authenticated: mark its counter, then run its row.
    fn frame(
        &mut self,
        now: C::Instant,
        proof: FrameProof,
        buf: &mut [u8],
        body: usize,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        if let Some(ep) = self.epoch_mut(proof.slot) {
            ep.session.mark(proof.counter);
        }
        let slot =
            if proof.slot == Slot::Previous && self.pending().is_some() && fault!(EvidencePrevious)
            {
                Slot::Pending
            } else {
                proof.slot
            };
        match slot {
            Slot::Pending => {
                let Some(ev) = Evidence::frame(&proof) else {
                    return;
                };
                let pend = match core::mem::replace(&mut self.cycle, Cycle::Idle) {
                    Cycle::PendR(p) => {
                        let (mut ep, restart) = p.end(&mut self.record);
                        ep.k = proof.k;
                        Pend {
                            ep,
                            restart,
                            fin: None,
                        }
                    }
                    Cycle::PendI(p) => Pend {
                        ep: p.ep,
                        restart: p.restart,
                        fin: p.fin,
                    },
                    c @ (Cycle::Idle | Cycle::Init(_)) => {
                        self.cycle = c;
                        return;
                    }
                };
                let tag = pend.ep.tag;
                self.cutover(now, pend, ev, false, env, out);
                Self::deliver(Slot::Current, tag, &proof, buf, body, env, out);
            }
            Slot::Current => {
                Self::deliver(Slot::Current, proof.tag, &proof, buf, body, env, out);
                self.heard_current(now, proof.k, proof.probe, out);
            }
            Slot::Previous => {
                Self::deliver(Slot::Previous, proof.tag, &proof, buf, body, env, out);
                self.heard_previous(now, out);
            }
        }
    }

    /// Put the plaintext in the frame's buffer and deliver it, unless it is
    /// shorter than the layer's floor.
    fn deliver(
        slot: Slot,
        tag: EpochTag,
        proof: &FrameProof,
        buf: &mut [u8],
        body: usize,
        env: &Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        if proof.len < P::FLOOR {
            out.push(Output::Reject(Reason::ShortPlaintext));
            return;
        }
        let end = body.saturating_add(proof.len);
        match (buf.get_mut(body..end), env.scratch.get(..proof.len)) {
            (Some(dst), Some(src)) => {
                dst.copy_from_slice(src);
                out.push(Output::Deliver {
                    slot,
                    tag,
                    range: body..end,
                });
            }
            (Some(_), None) | (None, Some(_)) | (None, None) => {
                out.push(Output::Reject(Reason::ShortPlaintext));
            }
        }
    }

    /// A frame (or worker report) under the current epoch.
    fn heard_current(&mut self, now: C::Instant, k: bool, probe: bool, out: &mut Outputs<P>) {
        let keeps = self.keeps_completed();
        let grace = self.grace();
        let drain = self.params.cfg.drain;
        let Some(cur) = self.cur.as_mut() else {
            return;
        };
        self.mem.last_rx = Some(now);
        self.mem.rx_cur = Some(now);
        self.mem.sent_data = false;
        self.mem.silence = 0;
        self.mem.peer_k = Some(k);
        if cur.heard.is_none() {
            cur.heard = Some(now);
            cur.assumed = false;
            if cur.fin.take().is_some() && !fault!(F4KeepsCandidates) {
                let installed = cur.started;
                if keeps && !fault!(F4KeepsAtBoth) {
                    self.cands.retain(|_| false);
                } else {
                    self.cands
                        .retain(|c| c.born > installed && !fault!(F4DropsAll));
                }
            }
        }
        let blind = probe
            && cur.probe_blind(P::RESPONDER_CUTOVER == ResponderCutover::AtProof)
            && !fault!(ProbeMoves);
        if !blind && cur.moved.is_none() {
            cur.moved = Some(now);
            cur.elicit = None;
            if let Some(d) = self.drain.as_mut()
                && !d.evidenced
            {
                d.deadline = d.deadline.min(later(now, drain));
                d.evidenced = !fault!(ShortenedUnevidenced);
            }
        }
        if blind
            && !fault!(NoProbeAnswer)
            && cur.prompted.is_none_or(|t| now >= later(t, PROMPT_GAP))
        {
            out.push(Output::Prompt { tag: cur.tag });
            cur.prompted = Some(now);
        }
        if let Cycle::PendI(p) = &mut self.cycle
            && p.wait == Wait::Evidence
            && p.probed.is_some_and(|t| now >= later(t, grace))
            && !fault!(StayedFromPrevious)
        {
            p.stayed = true;
        }
    }

    /// A frame (or worker report) under the previous epoch.
    fn heard_previous(&mut self, now: C::Instant, out: &mut Outputs<P>) {
        self.mem.last_rx = Some(now);
        if fault!(DrainExtends)
            && let Some(d) = self.drain.as_mut()
        {
            d.deadline = later(now, self.params.cfg.retention);
        }
        if fault!(StayedFromPrevious)
            && let Cycle::PendI(p) = &mut self.cycle
        {
            p.stayed = true;
        }
        let grace = self.grace();
        let span = self.params.span;
        let Some(cur) = self.cur.as_mut() else {
            return;
        };
        if cur.assumed && cur.heard.is_none() {
            match core::mem::replace(&mut self.cycle, Cycle::Idle) {
                Cycle::Idle => self.revert(now, out),
                Cycle::Init(a) => {
                    if fault!(RevertWithoutAbandon) {
                        drop(a);
                    } else {
                        abandon(a, Abandon::Reverted, out);
                    }
                    self.revert(now, out);
                }
                Cycle::PendI(p) if p.wait == Wait::Evidence && fault!(F6bPendIReverts) => {
                    drop(p);
                    self.revert(now, out);
                }
                Cycle::PendI(mut p) => {
                    if p.wait == Wait::Evidence
                        && p.probed.is_some_and(|t| now >= later(t, grace))
                        && !fault!(F6bPendINotStaying)
                    {
                        p.stayed = true;
                    }
                    self.cycle = Cycle::PendI(p);
                }
                Cycle::PendR(p) => self.cycle = Cycle::PendR(p),
            }
            return;
        }
        let confirming = cur.probe_blind(P::RESPONDER_CUTOVER == ResponderCutover::AtProof)
            && cur.moved.is_none()
            && now < later(cur.started, span);
        if confirming && cur.prompted.is_none_or(|t| now >= later(t, PROMPT_GAP)) {
            out.push(Output::Prompt { tag: cur.tag });
            cur.prompted = Some(now);
        }
    }

    /// Make a pending epoch current.
    ///
    /// Prunes the candidates (unless `accept` already did), retires an open
    /// drain first, retires the current epoch after a restart or demotes it
    /// to the drain otherwise, installs the new epoch, and reports the
    /// cutover.
    fn cutover(
        &mut self,
        now: C::Instant,
        pend: Pend<P, C::Instant>,
        ev: Evidence,
        pruned: bool,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        let Some(mut old) = self.cur.take() else {
            return;
        };
        if !pruned {
            match ev.kind {
                EvidenceKind::Frame | EvidenceKind::Proof => {
                    if !fault!(KeepCandidatesAtCutover) {
                        self.cands.retain(|_| false);
                    }
                }
                EvidenceKind::Assumed | EvidenceKind::Delay | EvidenceKind::Restart => {
                    let drop_all = self.keeps_completed()
                        || (ev.kind == EvidenceKind::Assumed && fault!(LargerDropsAtAssumed))
                        || (ev.kind == EvidenceKind::Restart && fault!(RestartDropsCandidates));
                    if drop_all {
                        self.cands.retain(|_| false);
                    } else if ev.kind == EvidenceKind::Restart
                        && let Some(epoch) = self.mem.peer_epoch
                    {
                        self.cands.bind(epoch);
                    }
                }
                EvidenceKind::First => {}
            }
        }
        if let Some(d) = self.drain.take() {
            if fault!(CutoverKeepsDrain) {
                core::mem::forget(d);
            } else {
                retire(d.ep, out);
            }
        }
        old.fin = None;
        old.elicit = None;
        if pend.restart {
            retire(old, out);
        } else {
            let evidenced = ev.is_frame();
            let hold = if evidenced || fault!(DrainReapedAtWindow) {
                self.params.cfg.drain
            } else {
                self.params.cfg.retention
            };
            self.drain = Some(Drain {
                ep: old,
                deadline: later(now, hold),
                evidenced,
            });
        }
        let mut ep = pend.ep;
        ep.started = now;
        if ep.base.is_none() {
            ep.base = Some(now);
        }
        self.mem.jitter = jitter(env, self.params.cfg.jitter);
        if ev.is_frame() {
            ep.heard = Some(now);
            ep.moved = Some(now);
        }
        ep.fin = match ev.kind {
            EvidenceKind::Frame if fault!(FinOutlivesLadder) => pend.fin,
            EvidenceKind::Restart | EvidenceKind::Delay => pend.fin,
            EvidenceKind::Proof
            | EvidenceKind::Frame
            | EvidenceKind::Assumed
            | EvidenceKind::First => None,
        };
        // A retained msg3 whose ladder ran out while it was pending (a
        // delay longer than the ladder, or a late poll) has no rung left to
        // drop it: drop it here, as its last rung would have, with a repair
        // due because the peer has not been heard under the new epoch.
        if ep
            .fin
            .as_ref()
            .is_some_and(|f| f.ladder.next_at().is_none())
        {
            ep.fin = None;
            if !ev.is_frame() {
                self.mem.due = true;
            }
        }
        if pend.restart || fault!(LinkAgeReset) {
            self.mem.link_since = now;
        }
        self.delegate(&ep, env.workers, out);
        out.push(Output::Installed {
            tag: ep.tag,
            role: ep.role,
            evidence: ev.kind,
        });
        if pend.restart
            && let Some(epoch) = self.mem.peer_epoch
        {
            out.push(Output::PeerRestarted {
                layer: P::LAYER,
                epoch,
            });
        }
        out.push(Output::Prompt { tag: ep.tag });
        ep.prompted = Some(now);
        if ep.moved.is_none() {
            ep.elicit = Some(Ladder::new(now, self.params.elicit));
        }
        out.push(Output::Rekeyed { role: ep.role });
        self.mem.last_cutover = Some(now);
        self.mem.abandons = 0;
        if ev.is_frame() {
            self.mem.last_rx = Some(now);
            self.mem.rx_cur = Some(now);
            self.mem.peer_k = ev.k;
            self.mem.sent_data = false;
            self.mem.silence = 0;
        }
        self.cur = Some(ep);
        self.cycle = Cycle::Idle;
    }

    /// Return an assumed epoch to pending when the peer is heard on the
    /// drained one. Nothing is retired.
    fn revert(&mut self, now: C::Instant, out: &mut Outputs<P>) {
        let (Some(mut assumed), Some(drain)) = (self.cur.take(), self.drain.take()) else {
            return;
        };
        assumed.assumed = false;
        assumed.elicit = None;
        assumed.fin = None;
        let tag = assumed.tag;
        let restored = drain.ep.tag;
        self.cur = Some(drain.ep);
        if fault!(RevertRetires) {
            retire(assumed, out);
            return;
        }
        if fault!(Rebox) {
            assumed.session = Box::new(*assumed.session);
        }
        self.cycle = Cycle::PendI(PendI {
            ep: assumed,
            wait: Wait::Evidence,
            deadline: later(now, self.params.cfg.revert),
            restart: false,
            fin: None,
            probes: Some(Ladder::new(now, self.params.revert)),
            probed: Some(now),
            stayed: false,
            reverted: true,
        });
        out.push(Output::Reverted { tag });
        out.push(Output::Prompt { tag });
        out.push(Output::Prompt { tag: restored });
    }

    // ---- the poll ----

    /// The expiry pass over every stored deadline at or before `now`, in
    /// instant order, then the start pass.
    fn poll(&mut self, now: C::Instant, env: &mut Env<'_, P>, out: &mut Outputs<P>) {
        // A row can move a stored deadline from one owner to another (a
        // delayed cutover hands its retained msg3, ladder and all, to the
        // new current epoch), so a deadline at or before `now` that the
        // first pass did not collect is picked up by the next. Deadlines a
        // pass creates are measured from `now` and are never due in it.
        let mut ended = false;
        let mut done: Vec<Due> = Vec::new();
        for _ in 0..PASSES {
            let mut due: Vec<(C::Instant, Due)> = self
                .due(now)
                .into_iter()
                .filter(|(_, d)| !done.contains(d))
                .collect();
            if ended || due.is_empty() {
                break;
            }
            if fault!(DueByKind) {
                due.sort_by_key(|(_, d)| *d);
            } else {
                due.sort();
            }
            done.extend(due.iter().map(|&(_, d)| d));
            ended = self.expire_pass(now, due, env, out);
        }
        if !ended
            && !fault!(NoOpeningTeardown)
            && self.cur.is_none()
            && matches!(self.cycle, Cycle::Idle)
            && self.cands.is_empty()
        {
            out.push(Output::Teardown(Teardown::OpeningIdle));
            ended = true;
        }
        if let Some(cur) = &self.cur
            && cur.session.sent() >= self.params.cfg.hard
        {
            out.push(Output::Teardown(Teardown::CounterExhausted));
            ended = true;
        }
        if ended {
            return;
        }
        if let Some(start) = self.start_kind(now) {
            self.start(now, env, out);
            let started = matches!(self.cycle, Cycle::Init(_));
            if started && start == Start::Silence && self.silence_interval() < self.params.cfg.after
            {
                self.mem.silence = self.mem.silence.saturating_add(1);
            }
        }
        if env.workers {
            for slot in [Slot::Current, Slot::Previous] {
                if let Some(ep) = self.epoch(slot)
                    && ep.recv == RecvHome::Here
                    && !Self::offered(out, ep.tag)
                {
                    self.delegate(ep, env.workers, out);
                    if fault!(DelegatedAtOffer)
                        && let Some(e) = self.epoch_mut(slot)
                    {
                        e.recv = RecvHome::Delegated;
                    }
                }
            }
        }
    }

    /// One expiry pass over `due`, in order; true when the machine must be
    /// torn down.
    fn expire_pass(
        &mut self,
        now: C::Instant,
        due: Vec<(C::Instant, Due)>,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) -> bool {
        let mut ended = false;
        for (at, item) in due {
            match item {
                Due::Drain(tag) => {
                    if let Some(d) = self.drain.take_if(|d| d.ep.tag == tag) {
                        let evidenced = d.evidenced;
                        retire(d.ep, out);
                        if !evidenced {
                            out.push(Output::Abandoned(Abandon::AdoptionNotSeen));
                        }
                    }
                }
                Due::Candidate(seq) => {
                    if self.cands.get(seq).is_some_and(|c| c.deadline <= now) {
                        self.cands.remove(seq);
                        out.push(Output::Reject(Reason::CandidateExpired));
                    }
                }
                Due::Unadopted(tag) => match core::mem::replace(&mut self.cycle, Cycle::Idle) {
                    Cycle::PendR(p) if p.ep.tag == tag && fault!(ResponderTimerCutover) => {
                        let (ep, restart) = p.end(&mut self.record);
                        let pend = Pend {
                            ep,
                            restart,
                            fin: None,
                        };
                        self.cutover(now, pend, Evidence::proof(), false, env, out);
                    }
                    Cycle::PendR(p) if p.ep.tag == tag => {
                        let (ep, _) = p.end(&mut self.record);
                        retire(ep, out);
                        out.push(Output::Abandoned(Abandon::Unadopted));
                    }
                    c @ (Cycle::Idle | Cycle::Init(_) | Cycle::PendI(_) | Cycle::PendR(_)) => {
                        self.cycle = c
                    }
                },
                Due::Held(tag) => match core::mem::replace(&mut self.cycle, Cycle::Idle) {
                    Cycle::PendI(p) if p.ep.tag == tag && p.wait == Wait::Held => {
                        let pend = Pend {
                            ep: p.ep,
                            restart: p.restart,
                            fin: p.fin,
                        };
                        self.cutover(now, pend, Evidence::proof(), false, env, out);
                    }
                    c @ (Cycle::Idle | Cycle::Init(_) | Cycle::PendI(_) | Cycle::PendR(_)) => {
                        self.cycle = c
                    }
                },
                Due::Probe(tag) => self.probe(now, tag, out),
                Due::Delayed(tag) => {
                    if let Cycle::PendI(p) = &mut self.cycle
                        && p.ep.tag == tag
                        && let Some(f) = p.fin.as_mut()
                        && f.ladder.take(now).is_some()
                    {
                        out.push(Output::Send {
                            msg: f.msg.clone(),
                            kind: MsgKind::Msg3,
                            route: Route::Established { fallback: false },
                        });
                    }
                }
                Due::Fin(tag) => {
                    if let Some(cur) = self.cur.as_mut()
                        && cur.tag == tag
                        && let Some(f) = cur.fin.as_mut()
                        && let Some(taken) = f.ladder.take(now)
                    {
                        out.push(Output::Send {
                            msg: f.msg.clone(),
                            kind: MsgKind::Msg3,
                            route: Route::Established { fallback: false },
                        });
                        if taken.last {
                            cur.fin = None;
                            if cur.heard.is_none() {
                                self.mem.due = true;
                            }
                        }
                    }
                }
                Due::Elicit(tag) => {
                    if let Some(cur) = self.cur.as_mut()
                        && cur.tag == tag
                        && cur.moved.is_none()
                        && let Some(ladder) = cur.elicit.as_mut()
                        && let Some(taken) = ladder.take(now)
                    {
                        out.push(Output::Prompt { tag });
                        cur.prompted = Some(now);
                        if taken.last {
                            cur.elicit = None;
                        }
                    }
                }
                Due::Confirm(tag) => {
                    let anchor = if fault!(AnchorAtDeadline) { at } else { now };
                    self.confirm(anchor, tag, env, out);
                }
                Due::DelayEnd(tag) => match core::mem::replace(&mut self.cycle, Cycle::Idle) {
                    Cycle::PendI(p) if p.ep.tag == tag && p.wait == Wait::Delay => {
                        let pend = Pend {
                            ep: p.ep,
                            restart: p.restart,
                            fin: p.fin,
                        };
                        self.cutover(now, pend, Evidence::delay(), false, env, out);
                    }
                    c @ (Cycle::Idle | Cycle::Init(_) | Cycle::PendI(_) | Cycle::PendR(_)) => {
                        self.cycle = c
                    }
                },
                Due::Resend => self.resend(now, out),
                Due::Expire => {
                    if self.expire(now, env, out) {
                        ended = true;
                    }
                }
            }
        }
        ended
    }

    /// Whether this call already offered `tag` to a worker.
    fn offered(out: &Outputs<P>, tag: EpochTag) -> bool {
        out.iter().any(|o| {
            if let Output::Delegate { tag: t, .. } = o {
                *t == tag
            } else {
                false
            }
        })
    }

    /// The stored deadlines at or before `now`.
    fn due(&self, now: C::Instant) -> Vec<(C::Instant, Due)> {
        let mut due = Vec::new();
        let mut add = |t: Option<C::Instant>, item: Due| {
            if let Some(t) = t
                && t <= now
            {
                due.push((t, item));
            }
        };
        if let Some(d) = &self.drain {
            add(Some(d.deadline), Due::Drain(d.ep.tag));
        }
        for c in self.cands.iter() {
            add(Some(c.deadline), Due::Candidate(c.seq));
        }
        match &self.cycle {
            Cycle::Idle => {}
            Cycle::Init(a) => {
                add(a.ladder.next_at(), Due::Resend);
                add(Some(a.deadline), Due::Expire);
            }
            Cycle::PendI(p) => {
                let tag = p.ep.tag;
                match p.wait {
                    Wait::Held => add(Some(p.deadline), Due::Held(tag)),
                    Wait::Evidence => {
                        add(p.probes.as_ref().and_then(Ladder::next_at), Due::Probe(tag));
                        add(Some(p.deadline), Due::Confirm(tag));
                    }
                    Wait::Delay => {
                        add(
                            p.fin.as_ref().and_then(|f| f.ladder.next_at()),
                            Due::Delayed(tag),
                        );
                        add(Some(p.deadline), Due::DelayEnd(tag));
                    }
                }
            }
            Cycle::PendR(p) => add(Some(p.deadline), Due::Unadopted(p.ep.tag)),
        }
        if let Some(cur) = &self.cur {
            add(
                cur.fin.as_ref().and_then(|f| f.ladder.next_at()),
                Due::Fin(cur.tag),
            );
            if cur.moved.is_none() {
                add(
                    cur.elicit.as_ref().and_then(Ladder::next_at),
                    Due::Elicit(cur.tag),
                );
            }
        }
        due
    }

    /// A probe or keepalive rung of a completed own attempt.
    fn probe(&mut self, now: C::Instant, tag: EpochTag, out: &mut Outputs<P>) {
        let grace = self.grace();
        let Some(cur_tag) = self.cur.as_ref().map(|c| c.tag) else {
            return;
        };
        let Cycle::PendI(p) = &mut self.cycle else {
            return;
        };
        if p.ep.tag != tag {
            return;
        }
        let Some(taken) = p.probes.as_mut().and_then(|l| l.take(now)) else {
            return;
        };
        if taken.send {
            let late = !p.reverted && later(now, grace) > p.deadline && !fault!(LateProbe);
            if !late {
                if let Some(f) = &p.fin {
                    out.push(Output::Send {
                        msg: f.msg.clone(),
                        kind: MsgKind::Msg3,
                        route: Route::Established { fallback: false },
                    });
                }
                out.push(Output::Prompt { tag: p.ep.tag });
                p.probed = Some(now);
                p.stayed = false;
            }
        }
        out.push(Output::Prompt { tag: cur_tag });
    }

    /// The confirmation deadline of a completed own attempt.
    fn confirm(
        &mut self,
        now: C::Instant,
        tag: EpochTag,
        env: &mut Env<'_, P>,
        out: &mut Outputs<P>,
    ) {
        match core::mem::replace(&mut self.cycle, Cycle::Idle) {
            Cycle::PendI(p) if p.ep.tag == tag && p.wait == Wait::Evidence && p.deadline <= now => {
                if p.stayed || p.reverted {
                    let cause = if p.reverted {
                        Abandon::RevertUnconfirmed
                    } else {
                        Abandon::PeerStayedOnOld
                    };
                    retire(p.ep, out);
                    out.push(Output::Abandoned(cause));
                    self.mem.due = true;
                } else {
                    let pend = Pend {
                        ep: p.ep,
                        restart: p.restart,
                        fin: p.fin,
                    };
                    self.cutover(now, pend, Evidence::assumed(), false, env, out);
                    if let Some(cur) = self.cur.as_mut() {
                        cur.assumed = true;
                    }
                }
            }
            c @ (Cycle::Idle | Cycle::Init(_) | Cycle::PendI(_) | Cycle::PendR(_)) => {
                self.cycle = c
            }
        }
    }

    /// A resend rung of the own attempt.
    fn resend(&mut self, now: C::Instant, out: &mut Outputs<P>) {
        let held = self.cur.is_none() && !self.smaller() && !self.cands.is_empty();
        let young = millis(self.params.cfg.young);
        let kind = if P::MESSAGES == 2 {
            MsgKind::Msg1
        } else {
            MsgKind::Setup
        };
        if let Cycle::Init(a) = &mut self.cycle
            && now < a.deadline
            && let Some(taken) = a.ladder.take(now)
        {
            if held && taken.latest < young && !fault!(NoHoldBack) {
                return;
            }
            out.push(Output::Send {
                msg: a.out.clone(),
                kind,
                route: Route::Established { fallback: false },
            });
            a.resent = true;
            if fault!(DeadlinePerRung) {
                a.deadline = later(now, self.params.budget);
            }
        }
    }

    /// The own attempt's deadline; true when the machine must be torn down.
    fn expire(&mut self, now: C::Instant, env: &mut Env<'_, P>, out: &mut Outputs<P>) -> bool {
        match core::mem::replace(&mut self.cycle, Cycle::Idle) {
            Cycle::Init(a) if a.deadline <= now => {
                abandon(a, Abandon::Unanswered, out);
                if fault!(AbandonClearsTrigger) {
                    if let Some(c) = self.cur.as_mut() {
                        c.started = now;
                    }
                    self.mem.due = false;
                }
                self.mem.abandons = self.mem.abandons.saturating_add(1);
                let random =
                    Duration::from_secs(u64::from(env.jitter.draw(self.params.cfg.jitter)));
                let wait = self
                    .params
                    .backoff(self.mem.abandons)
                    .saturating_add(random);
                self.mem.backoff = Some(later(now, wait));
                if self.cur.is_none() && self.cands.is_empty() {
                    out.push(Output::Teardown(Teardown::OpeningFailed));
                    return true;
                }
                false
            }
            c @ (Cycle::Idle | Cycle::Init(_) | Cycle::PendI(_) | Cycle::PendR(_)) => {
                self.cycle = c;
                false
            }
        }
    }

    /// The instant the time trigger falls due: the epoch's start plus the
    /// interval plus the jitter.
    fn trigger_at(&self, cur: &Epoch<P, C::Instant>) -> C::Instant {
        let ms = i128::from(millis(self.params.cfg.after)) + i128::from(self.mem.jitter) * 1000;
        let ms = u64::try_from(ms.max(0)).unwrap_or(u64::MAX);
        later(cur.started, Duration::from_millis(ms))
    }

    /// The silence interval now: doubling per step, capped at the time
    /// trigger.
    fn silence_interval(&self) -> Duration {
        let factor = 1u32
            .checked_shl(u32::from(self.mem.silence))
            .unwrap_or(u32::MAX);
        self.params
            .cfg
            .silence
            .saturating_mul(factor)
            .min(self.params.cfg.after)
    }

    /// The instant the silence trigger falls due.
    fn silence_at(&self, cur: &Epoch<P, C::Instant>) -> C::Instant {
        later(
            latest(self.mem.rx_cur, cur.started),
            self.silence_interval(),
        )
    }

    /// Whether an own rekey starts at `now`, and why.
    fn start_kind(&self, now: C::Instant) -> Option<Start> {
        let cur = self.cur.as_ref()?;
        let idle = matches!(self.cycle, Cycle::Idle);
        let held = cur.fin.is_some() && !fault!(StartWhileFin);
        if !idle || held || !self.mem.reachable {
            return None;
        }
        let cfg = &self.params.cfg;
        let counter = cur.session.sent();
        let soft = counter >= cfg.soft;
        let floors = since(now, self.mem.link_since) >= cfg.floor_link
            && since(now, cur.started) >= cfg.floor_session
            && self
                .mem
                .last_cutover
                .is_none_or(|t| since(now, t) >= cfg.floor_cutover);
        if !floors {
            return None;
        }
        if !soft && self.mem.damp.is_some_and(|t| now < t) {
            return None;
        }
        let backed = |repair: bool| !soft && !repair && self.mem.backoff.is_some_and(|t| now < t);
        let timed = now >= self.trigger_at(cur);
        let vetoed = fault!(CandidateVeto) && !self.cands.is_empty();
        let triggered = (timed || counter >= cfg.messages || soft || self.mem.due) && !vetoed;
        if triggered && !backed(self.mem.due) {
            return Some(Start::Scheduled);
        }
        if P::SILENCE && self.mem.sent_data && now >= self.silence_at(cur) && !backed(false) {
            return Some(Start::Silence);
        }
        None
    }

    /// The earliest instant a start condition can next hold.
    fn start_at(&self, cur: &Epoch<P, C::Instant>) -> Option<C::Instant> {
        let idle = matches!(self.cycle, Cycle::Idle);
        let held = cur.fin.is_some() && !fault!(StartWhileFin);
        if !idle || held || !self.mem.reachable {
            return None;
        }
        let cfg = &self.params.cfg;
        let counter = cur.session.sent();
        let mut gate =
            later(self.mem.link_since, cfg.floor_link).max(later(cur.started, cfg.floor_session));
        if let Some(t) = self.mem.last_cutover {
            gate = gate.max(later(t, cfg.floor_cutover));
        }
        // A met soft limit passes dampening and backoff, as in start_kind.
        if counter >= cfg.soft {
            return Some(gate);
        }
        if let Some(t) = self.mem.damp {
            gate = gate.max(t);
        }
        let backed = latest(self.mem.backoff, gate);
        let scheduled = if self.mem.due {
            gate
        } else if counter >= cfg.messages {
            backed
        } else {
            self.trigger_at(cur).max(backed)
        };
        if P::SILENCE && self.mem.sent_data {
            return Some(scheduled.min(self.silence_at(cur).max(backed)));
        }
        Some(scheduled)
    }

    // ---- the shell's other entry points ----

    /// The earliest instant at which a poll has work: a stored deadline or
    /// a start condition. Never `None` while opening.
    pub fn next_wake(&self) -> Option<C::Instant> {
        let mut best: Option<C::Instant> = None;
        let mut at = |t: Option<C::Instant>| {
            if let Some(t) = t {
                best = Some(best.map_or(t, |b| b.min(t)));
            }
        };
        at(self.drain.as_ref().map(|d| d.deadline));
        at(self.cands.earliest());
        match &self.cycle {
            Cycle::Idle => {}
            Cycle::Init(a) => {
                at(a.ladder.next_at());
                at(Some(a.deadline));
            }
            Cycle::PendI(p) => {
                at(Some(p.deadline));
                at(p.probes.as_ref().and_then(Ladder::next_at));
                at(p.fin.as_ref().and_then(|f| f.ladder.next_at()));
            }
            Cycle::PendR(p) => at(Some(p.deadline)),
        }
        if let Some(cur) = &self.cur {
            at(cur.fin.as_ref().and_then(|f| f.ladder.next_at()));
            if cur.moved.is_none() {
                at(cur.elicit.as_ref().and_then(Ladder::next_at));
            }
            at(self.start_at(cur));
            // An exhausted counter tears down at the next poll; its epoch's
            // start is already past, so a timer shell polls at once.
            if cur.session.sent() >= self.params.cfg.hard {
                at(Some(cur.started));
            }
        }
        best
    }

    /// Reserve a counter under the current epoch for one frame.
    pub fn seal(
        &mut self,
        now: C::Instant,
    ) -> Result<Sealed<<P::Session as SessionKeys>::SendCopy>, SealRefusal> {
        let hard = self.params.cfg.hard;
        let cur = match &mut self.cycle {
            Cycle::PendI(p) if fault!(SealPending) => &mut p.ep,
            Cycle::Idle | Cycle::Init(_) | Cycle::PendI(_) | Cycle::PendR(_) => {
                self.cur.as_mut().ok_or(SealRefusal::NotEstablished)?
            }
        };
        let base = cur.base.ok_or(SealRefusal::NotSealable)?;
        if cur.session.sent() >= hard {
            return Err(SealRefusal::Exhausted);
        }
        let (counter, key) = cur.session.reserve();
        Ok(Sealed {
            tag: cur.tag,
            k: cur.k,
            counter,
            elapsed: since(now, base),
            theirs: cur.ids.theirs,
            key,
        })
    }

    /// Seal the profile's fixed prompt under `tag`, which must name the
    /// current epoch or the pending epoch of a completed own attempt that
    /// waits for evidence.
    pub fn seal_prompt(
        &mut self,
        now: C::Instant,
        tag: EpochTag,
    ) -> Result<SealedPrompt<P>, SealRefusal> {
        let hard = self.params.cfg.hard;
        if self.cur.is_none() {
            return Err(SealRefusal::NotEstablished);
        }
        if !self.sealable(tag) {
            return Err(SealRefusal::NotSealable);
        }
        let slot = if self.cur.as_ref().is_some_and(|c| c.tag == tag) {
            Slot::Current
        } else {
            Slot::Pending
        };
        let ep = self.epoch_mut(slot).ok_or(SealRefusal::NotSealable)?;
        let base = ep.base.ok_or(SealRefusal::NotSealable)?;
        if ep.session.sent() >= hard {
            return Err(SealRefusal::Exhausted);
        }
        let (counter, key) = ep.session.reserve();
        let elapsed = since(now, base);
        let mut plaintext = Vec::new();
        P::prompt(elapsed, &mut plaintext);
        Ok(SealedPrompt {
            sealed: Sealed {
                tag,
                k: ep.k,
                counter,
                elapsed,
                theirs: ep.ids.theirs,
                key,
            },
            plaintext,
            route: ep.route.clone(),
        })
    }

    /// The machine, read-only.
    pub fn view(&self) -> View<'_, P, C::Instant> {
        fn show<P: Profile, I: Copy>(ep: &Epoch<P, I>) -> EpochView<'_, P, I> {
            EpochView {
                tag: ep.tag,
                k: ep.k,
                role: ep.role,
                started: ep.started,
                base: ep.base,
                recv: ep.recv,
                ext: &ep.ext,
            }
        }
        let identity = match (&self.cur, self.bond) {
            (Some(_), Bond::Key(key)) => Identity::Proven(key),
            (Some(_) | None, bond @ (Bond::Key(_) | Bond::Claimed(_))) => {
                Identity::Claimed(bond.addr())
            }
        };
        View {
            identity,
            peer_epoch: self.mem.peer_epoch,
            last_rx: self.mem.last_rx,
            link_since: self.mem.link_since,
            current: self.cur.as_ref().map(show),
            previous: self.drain.as_ref().map(|d| show(&d.ep)),
            pending: self.pending().map(show),
            cycle: match &self.cycle {
                Cycle::Idle => CycleView::Idle,
                Cycle::Init(_) => CycleView::Init,
                Cycle::PendI(p) => CycleView::PendI(p.wait),
                Cycle::PendR(_) => CycleView::PendR,
            },
            candidates: self.cands.len(),
        }
    }

    /// Every index binding the machine holds, for the shell's audit.
    pub fn bindings(&self) -> Vec<Binding<P::Transport>> {
        let mut all = Vec::new();
        if let Cycle::Init(a) = &self.cycle
            && let Some(lease) = &a.lease
        {
            all.push(Binding {
                transport: a.transport,
                index: lease.index(),
                purpose: Purpose::Attempt,
            });
        }
        let slots = [
            (self.pending(), Purpose::Pending),
            (self.cur.as_ref(), Purpose::Current),
            (self.drain.as_ref().map(|d| &d.ep), Purpose::Previous),
        ];
        for (ep, purpose) in slots {
            if let Some((transport, index)) = ep.and_then(|e| e.ids.binding()) {
                all.push(Binding {
                    transport,
                    index,
                    purpose,
                });
            }
        }
        all
    }

    /// Where the session of the epoch `tag` lives, for the test that a
    /// move between slots copies a pointer and never the keys.
    #[cfg(test)]
    pub(crate) fn session_at(&self, tag: EpochTag) -> Option<usize> {
        let slot = self.slot_of(tag)?;
        self.epoch(slot)
            .map(|e| core::ptr::from_ref::<P::Session>(e.session.as_ref()).addr())
    }

    /// End the machine: abandon the attempt, end a responder pending
    /// (recording the msg1 that armed it), retire every epoch, drop the
    /// candidates, and hand back what the node keeps.
    pub fn close(mut self, why: Close) -> (Outputs<P>, Option<Carry<C::Instant>>) {
        let mut out = Outputs::new();
        match core::mem::replace(&mut self.cycle, Cycle::Idle) {
            Cycle::Idle => {}
            Cycle::Init(a) => abandon(a, Abandon::Closed(why), &mut out),
            Cycle::PendI(p) => retire(p.ep, &mut out),
            Cycle::PendR(p) if fault!(CloseSkipsRecord) => retire(p.ep, &mut out),
            Cycle::PendR(p) => {
                let (ep, _) = p.end(&mut self.record);
                retire(ep, &mut out);
            }
        }
        if let Some(d) = self.drain.take() {
            retire(d.ep, &mut out);
        }
        self.cands.retain(|_| false);
        let record = core::mem::take(&mut self.record);
        let carry = self.cur.take().map(|cur| {
            let carry = Carry {
                peer_epoch: self.mem.peer_epoch,
                k: cur.k,
                started: cur.started,
                link_since: self.mem.link_since,
                peer_k: self.mem.peer_k,
                record,
            };
            retire(cur, &mut out);
            carry
        });
        (out, carry)
    }
}

/// One held epoch as the simulator's oracles read it (test builds only).
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct PeekEpoch<'a, P: Profile, I> {
    pub(crate) session: &'a P::Session,
    pub(crate) ours: Option<u32>,
    pub(crate) theirs: Option<u32>,
    pub(crate) started: I,
}

/// What the simulator's oracles read from a machine beyond its `view`
/// (test builds only): the sessions themselves, so two machines' epochs
/// can be matched, and the deadlines the deadline oracles bound.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct Peek<'a, P: Profile, I> {
    pub(crate) current: Option<PeekEpoch<'a, P, I>>,
    pub(crate) previous: Option<PeekEpoch<'a, P, I>>,
    pub(crate) drain_end: Option<I>,
    pub(crate) pending: Option<PeekEpoch<'a, P, I>>,
    pub(crate) candidates: Vec<I>,
    pub(crate) record: usize,
}

#[cfg(test)]
impl<P: Profile, C: Clock> Rekey<P, C> {
    /// The machine as the simulator's oracles read it.
    pub(crate) fn peek(&self) -> Peek<'_, P, C::Instant> {
        fn show<P: Profile, I: Copy>(ep: &Epoch<P, I>) -> PeekEpoch<'_, P, I> {
            PeekEpoch {
                session: ep.session.as_ref(),
                ours: ep.ids.ours(),
                theirs: ep.ids.theirs,
                started: ep.started,
            }
        }
        Peek {
            current: self.cur.as_ref().map(show),
            previous: self.drain.as_ref().map(|d| show(&d.ep)),
            drain_end: self.drain.as_ref().map(|d| d.deadline),
            pending: self.pending().map(show),
            candidates: self.cands.iter().map(|c| c.deadline).collect(),
            record: self.record.len(),
        }
    }

    /// The state digest without the candidate list, and without the replay
    /// record unless `record`: what a forged input (record included), or a
    /// copy of an input already delivered (which may only add to the
    /// record), must leave unchanged.
    pub(crate) fn digest_core(&self, record: bool) -> alloc::string::String {
        let mut d = alloc::format!(
            "{:?} {:?} {:?} {:?} {:?} {:?}",
            self.bond,
            self.me,
            self.cur,
            self.drain,
            self.cycle,
            self.mem
        );
        if record {
            d.push_str(&alloc::format!(" {:?}", self.record));
        }
        d
    }

    /// Write every field that can change (all but the parameters) to `w`,
    /// for the explorer's state key.
    pub(crate) fn state(&self, w: &mut dyn fmt::Write) -> fmt::Result {
        write!(
            w,
            "{:?} {:?} {:?} {:?} {:?} {:?} {:?}",
            self.bond, self.cur, self.drain, self.cycle, self.cands, self.record, self.mem
        )
    }
}

impl<P: Profile, C: Clock> fmt::Debug for Rekey<P, C> {
    /// Every field, key material shown only as the sessions' own `Debug`
    /// renders it; tests compare this as the state digest.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Rekey")
            .field("params", &self.params)
            .field("bond", &self.bond)
            .field("me", &self.me)
            .field("cur", &self.cur)
            .field("drain", &self.drain)
            .field("cycle", &self.cycle)
            .field("cands", &self.cands)
            .field("record", &self.record)
            .field("mem", &self.mem)
            .finish()
    }
}
