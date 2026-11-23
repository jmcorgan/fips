//! The XX handshake flow of the settlement core: how next's three-message
//! Noise XX handshake is classified, as a profile of the one table
//! (`proto::settle::table`), the way `rekey/` is next's profile of the one
//! rekey machine.
//!
//! The table keeps its shared rules: the link records, the legs, the gates'
//! memory, the held peers, removal, the path inputs and the close rule. This
//! flow decides what the IK rules decide at msg1 and msg2, and what a msg3
//! does, as next's shell decides it (`src/node/handlers/handshake.rs` and
//! `establish_inbound` and `establish_outbound` in `../core.rs`). It reaches
//! the table only through the table's facade (`Ops`) and its hooks, and
//! keeps its own state, [`Xx`], in the table's flow slot. Nothing in the
//! node runs it yet.
//!
//! What differs from the IK flow, each by next's code:
//!
//! - **A msg1 names no one.** It opens an anonymous answer, with no gate,
//!   cap or epoch, and the answer installs nothing at its send. A resend of
//!   the same bytes from the same address draws the stored msg2 until the
//!   msg3 comes, and the admission cap counts only the answers whose msg2
//!   is not yet sent.
//! - **A dial may name no one**, and its msg2 supplies the identity.
//! - **The responder installs at msg3**, classified in the order next's
//!   `establish_inbound` has: a new identity is promoted unless its silent
//!   sessions refuse it; an epoch change is a restart, refused while the
//!   peering was heard or installed less than the interval ago or the
//!   dampener holds; a claim of a session not held repeats the stored
//!   msg2; no claim is a crossing, which the larger node's inbound wins;
//!   and a claim of the session held is the peer's rekey.
//! - **The initiator decides at msg2 and acts once its msg3 is sent.** A
//!   new identity is promoted and a restarted one replaced, with no gate;
//!   a msg2 beside this node's own dial is kept at once with no msg3; any
//!   other is settled by address order, the smaller node moving onto its
//!   dial.
//! - **A leaf node holds one peer**, and refuses another at msg2 or msg3,
//!   removing the link at once. The max-peers cap at msg2 leaves the dial's
//!   leg for its reap, and at msg3 removes the answer's link at once.

#![deny(clippy::wildcard_enum_match_arm)]

/// Whether the flow's test-only switch `$f` is on (see `faults.rs`).
#[cfg(test)]
macro_rules! xx_fault {
    ($f:ident) => {
        $crate::proto::fmp::flow::faults::on($crate::proto::fmp::flow::faults::Fault::$f)
    };
}

/// Outside test builds no guard of the flow can be switched off.
#[cfg(not(test))]
macro_rules! xx_fault {
    ($f:ident) => {
        false
    };
}

#[cfg(test)]
mod faults;
pub mod input;
#[cfg(test)]
pub mod model;
mod msg1;
mod msg2;
mod msg3;
pub mod output;

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

pub use input::{Anon, AnonDial, In};
pub use output::{Deny, Out};

use crate::identity::NodeAddr;
use crate::proto::fmp::EphemeralDigest;
use crate::proto::settle::flow::{Flow, Outs};
use crate::proto::settle::gates::Epoch;
use crate::proto::settle::legs::Kind;
use crate::proto::settle::links::{Dir, LinkNo, Pair};
use crate::proto::settle::output::{Denial, Output};
use crate::proto::settle::params::Params;
use crate::proto::settle::table::{Held, Ops, Table};
use crate::time::{Duration, Instant};

/// An anonymous answer, as the flow keeps it beside the table's leg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Answer {
    /// The ephemeral of the msg1 it answers, which an install at its msg3
    /// records.
    pub ephemeral: EphemeralDigest,
    /// Its msg2 was sent.
    pub sent: bool,
}

/// An anonymous msg1 waiting for the answer the shell builds. Its
/// `rekey_of` is read only by `AnonLegNamed`'s defect shape: the shell
/// computes `rekey_of` and keeps its own map of it for the moved-msg3
/// lookup.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Asked {
    msg1: Vec<u8>,
    ephemeral: EphemeralDigest,
    rekey_of: Option<LinkNo>,
}

/// What a completed dial does once its msg3 is sent, as next's
/// `establish_outbound` decided it at msg2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    /// No peer is held for the identity: install it.
    Promote,
    /// The peer held restarted: replace it, with no gate.
    Restart,
    /// The smaller node moves onto its dial; `own` says the link it leaves
    /// was one this node dialed.
    Swap { own: bool },
    /// The larger node keeps the peer where it is and gives the dial up.
    Keep,
}

/// A msg2's decision, parked on its dial until the msg3 send's outcome.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Parked {
    peer: NodeAddr,
    epoch: Epoch,
    from: Pair,
    how: How,
}

/// What the XX flow keeps in the table: its anonymous answers and dials,
/// the msg2 decisions parked on their dials, the failed legs, and the
/// per-peer marks next's msg2 rule reads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Xx {
    /// This node is a leaf, which holds one peer at most.
    leaf: bool,
    /// The anonymous msg1s whose answer the shell was asked for, by link.
    asks: BTreeMap<LinkNo, Asked>,
    /// The anonymous answers, by link.
    answers: BTreeMap<LinkNo, Answer>,
    /// The anonymous dials whose connection is being opened, by link, with
    /// their resend caps.
    connects: BTreeMap<LinkNo, Option<u32>>,
    /// The identity each dial's msg2 taught, by link.
    learned: BTreeMap<LinkNo, NodeAddr>,
    /// The msg2 decisions waiting for their msg3 send, by link.
    parked: BTreeMap<LinkNo, Parked>,
    /// The failed dials the next sweep reaps, with whom each retries.
    failed: BTreeMap<LinkNo, Option<NodeAddr>>,
    /// The legs a refusal leaves for their reap, which nothing completes.
    reaped: BTreeSet<LinkNo>,
    /// For each held peer, the link number the table would open next when
    /// its session was installed or moved: a dial whose link is below it
    /// was in flight then (next's `predates`).
    marks: BTreeMap<NodeAddr, u64>,
    /// The held peers a frame was heard from under the session held, since
    /// its install or move (next's `heard_on_session`).
    framed: BTreeSet<NodeAddr>,
}

impl Xx {
    /// The flow of a node that is a leaf when `leaf` says so.
    pub fn new(leaf: bool) -> Self {
        Self {
            leaf,
            ..Self::default()
        }
    }

    /// Whether this node is a leaf.
    pub fn leaf(&self) -> bool {
        self.leaf
    }

    /// The anonymous answer on `link`.
    pub fn answer(&self, link: LinkNo) -> Option<&Answer> {
        self.answers.get(&link)
    }

    /// Whether the held `peer` was heard under the session held since its
    /// install or move.
    pub fn framed(&self, peer: &NodeAddr) -> bool {
        self.framed.contains(peer)
    }

    /// Whether the dial on `link` was already in flight when the session
    /// held for `peer` was installed or last moved.
    pub fn predates(&self, peer: &NodeAddr, link: LinkNo) -> bool {
        self.marks.get(peer).is_some_and(|m| link.0 < *m)
    }

    /// The anonymous answers and asks whose leg or link is still in
    /// `table` and that the admission cap counts: those whose msg2 is not
    /// yet sent.
    fn pending<I: Instant>(&self, table: &Table<I, Self>) -> usize {
        let every = xx_fault!(PendingCountsSentAnswers) || node_fault!(PendingCountsSentAnswers);
        let answers = self
            .answers
            .iter()
            .filter(|(l, a)| table.legs().get(**l).is_some() && (!a.sent || every))
            .count();
        let asks = self
            .asks
            .keys()
            .filter(|l| table.links().get(**l).is_some())
            .count();
        answers + asks
    }

    /// Forget everything kept for `link`.
    fn forget(&mut self, link: LinkNo) {
        self.asks.remove(&link);
        self.answers.remove(&link);
        self.connects.remove(&link);
        self.learned.remove(&link);
        self.parked.remove(&link);
        self.failed.remove(&link);
        self.reaped.remove(&link);
    }

    /// The identity the dial on `link`, which named `named`, expects by its
    /// reap, to retry: a failed dial's, as its failure noted it and taken
    /// from the failed dials, or the one its msg2 taught, or else the one it
    /// named (next's `conn_expected_identity`).
    fn expects(&mut self, link: LinkNo, named: Option<NodeAddr>) -> Option<NodeAddr> {
        match self.failed.remove(&link) {
            Some(failed) => failed,
            None => self.learned.get(&link).copied().or(named),
        }
    }

    /// Whether the flow keeps anything for `link`.
    fn holds(&self, link: LinkNo) -> bool {
        self.asks.contains_key(&link)
            || self.answers.contains_key(&link)
            || self.connects.contains_key(&link)
            || self.learned.contains_key(&link)
    }
}

/// The parameters of an XX table from the node's `base`: next's restart
/// gate is one floor of [`Params::interval`] from the last frame or the
/// install, beside the dampener, with no unheard floor and no replay
/// memory.
pub fn params(base: Params) -> Params {
    Params {
        unheard: Duration::from_secs(0),
        replays: 0,
        interval: Duration::from_secs(crate::proto::fmp::EPOCH_RESTART_MIN_INTERVAL_SECS),
        ..base
    }
}

/// The number above every link the table knows now, which any link it
/// opens later is at or past.
fn mark<I: Instant>(ops: &Ops<'_, I, Xx>) -> u64 {
    let indexed = ops.links().index().iter().map(|(_, l)| l.0);
    let legs = ops.legs().iter().map(|l| l.link().0);
    indexed.chain(legs).max().map_or(0, |n| n + 1)
}

/// Forget what the flow keeps for legs and links the table no longer
/// holds: a leg reaped at its deadline leaves its entries behind.
fn tidy<I: Instant>(ops: &mut Ops<'_, I, Xx>) {
    let flow = ops.flow();
    let leg = |l: &LinkNo| ops.legs().get(*l).is_none();
    let rec = |l: &LinkNo| ops.links().get(*l).is_none();
    let gone: Vec<LinkNo> = flow
        .answers
        .keys()
        .chain(flow.learned.keys())
        .chain(flow.parked.keys())
        .chain(flow.failed.keys())
        .chain(flow.reaped.iter())
        .filter(|l| leg(l))
        .chain(
            flow.asks
                .keys()
                .chain(flow.connects.keys())
                .filter(|l| rec(l)),
        )
        .copied()
        .collect();
    let flow = ops.flow_mut();
    for link in gone {
        flow.forget(link);
    }
}

/// The installed or moved `peer` takes a fresh mark and is unheard under
/// its new session.
fn fresh<I: Instant>(ops: &mut Ops<'_, I, Xx>, peer: NodeAddr) {
    let m = mark(ops);
    let flow = ops.flow_mut();
    flow.marks.insert(peer, m);
    flow.framed.remove(&peer);
}

/// End the leg or ask on `link` at once, closing nothing, as next's shell
/// drops a refused handshake: the lease comes back and the link is
/// retired.
fn end<I: Instant>(ops: &mut Ops<'_, I, Xx>, link: LinkNo, out: &mut Vec<Outs<I, Xx>>) {
    ops.flow_mut().forget(link);
    if let Some(leg) = ops.legs_mut().take(link) {
        out.push(Output::Free { lease: leg.lease() });
    }
    if ops.links().get(link).is_some() {
        let _ = ops.links_mut().retire(link);
        out.push(Output::Retire {
            link,
            closes: Vec::new(),
        });
    }
}

/// Whether next's promote refuses to install `peer` from the leg on `link`,
/// an answer's at msg3 when `answer` says so and a dial's at msg2
/// otherwise: a leaf holding another peer, which removes the link at once,
/// or the max-peers cap, which leaves a dial's leg for its reap and removes
/// an answer's link at once, closing nothing, as next's inbound promote
/// failure does. The refusal goes to `out`.
fn barred<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    peer: NodeAddr,
    link: LinkNo,
    answer: bool,
    out: &mut Vec<Outs<I, Xx>>,
) -> bool {
    let flow = ops.flow();
    if flow.leaf && ops.held(&peer).is_none() && !flow.marks.is_empty() {
        out.push(Output::Reject {
            peer: Some(peer),
            source: None,
            why: Denial::Flow(Deny::Leaf),
        });
        if xx_fault!(LeafKeepsLink) || node_fault!(LeafKeepsLink) {
            ops.flow_mut().reaped.insert(link);
        } else {
            end(ops, link, out);
        }
        return true;
    }
    if ops.capped(&peer) {
        out.push(Output::Reject {
            peer: Some(peer),
            source: None,
            why: Denial::Cap,
        });
        if answer && !(xx_fault!(CapKeepsAnswer) || node_fault!(CapKeepsAnswer)) {
            end(ops, link, out);
        } else {
            ops.flow_mut().reaped.insert(link);
        }
        return true;
    }
    false
}

/// The shell refused the handshake on `link`: the leg, or the ask, and its
/// link go at once, closing nothing, and `retry` is asked for. A link the
/// flow holds nothing for is left alone.
fn refused<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    retry: Option<NodeAddr>,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let dial = ops
        .legs()
        .get(link)
        .is_some_and(|l| matches!(l.kind(), Kind::Dial));
    if !(dial || ops.flow().holds(link)) {
        return;
    }
    end(ops, link, out);
    if let Some(peer) = retry {
        out.push(Output::Retry { peer });
    }
}

/// The dial on `link` failed: the next sweep reaps it and retries the
/// identity it expects by then, as next's sweep does: the one its
/// completion `learned`, or its msg2 taught, or else the one it named.
fn failed<I: Instant>(ops: &mut Ops<'_, I, Xx>, link: LinkNo, learned: Option<NodeAddr>) {
    let Some(leg) = ops.legs().get(link) else {
        return;
    };
    if !matches!(leg.kind(), Kind::Dial) {
        return;
    }
    let named = leg.peer();
    let flow = ops.flow_mut();
    let retry = learned.or(flow.learned.get(&link).copied()).or(named);
    flow.parked.remove(&link);
    flow.failed.insert(link, retry);
}

/// The shell's sweep: each failed dial asks for its retry first, as next's
/// stale sweep does, and then gives its lease back and retires its link,
/// as a reaped leg does.
fn sweep<I: Instant>(ops: &mut Ops<'_, I, Xx>, out: &mut Vec<Outs<I, Xx>>) {
    let failed = core::mem::take(&mut ops.flow_mut().failed);
    for (link, retry) in failed {
        if ops.legs().get(link).is_none() {
            continue;
        }
        if let Some(peer) = retry {
            out.push(Output::Retry { peer });
        }
        ops.flow_mut().forget(link);
        ops.abandon(link, out);
    }
}

/// The node's timers at `now`: each dial past its deadline asks for a
/// retry of the identity it expects by then, as next's handshake timeout
/// does (`drive_handshake_timeouts` and the stale sweep, which read the
/// leg's expected identity): a failed dial's, as its failure noted it, or
/// the one its msg2 taught, or else the one it named. The table's poll at
/// the same instant reaps it, so a failed one is not swept again.
fn due<I: Instant>(ops: &mut Ops<'_, I, Xx>, now: I, out: &mut Vec<Outs<I, Xx>>) {
    if xx_fault!(TimeoutNoRetry) || node_fault!(TimeoutNoRetry) {
        return;
    }
    let timed: Vec<(LinkNo, Option<NodeAddr>)> = ops
        .legs()
        .iter()
        .filter(|l| matches!(l.kind(), Kind::Dial) && l.deadline() <= now)
        .map(|l| (l.link(), l.peer()))
        .collect();
    for (link, named) in timed {
        if let Some(peer) = ops.flow_mut().expects(link, named) {
            out.push(Output::Retry { peer });
        }
    }
}

/// The node's timer reaps its dial on `link` alone: the dial asks for a
/// retry of the identity it expects by then, as [`due`] has each dial past
/// its deadline ask. Nothing for a leg that is not a dial.
fn timed<I: Instant>(ops: &mut Ops<'_, I, Xx>, link: LinkNo, out: &mut Vec<Outs<I, Xx>>) {
    if xx_fault!(TimeoutNoRetry) || node_fault!(TimeoutNoRetry) {
        return;
    }
    let Some(named) = ops
        .legs()
        .get(link)
        .filter(|l| matches!(l.kind(), Kind::Dial))
        .map(|l| l.peer())
    else {
        return;
    };
    if let Some(peer) = ops.flow_mut().expects(link, named) {
        out.push(Output::Retry { peer });
    }
}

impl<I: Instant> Flow<I> for Xx {
    type In = In;
    type Out = Out;
    type Deny = Deny;

    fn step(ops: &mut Ops<'_, I, Self>, input: In, now: I, out: &mut Vec<Outs<I, Self>>) {
        tidy(ops);
        match input {
            In::Anon(a) => msg1::anon(ops, a, out),
            In::Hello { link, msg2, lease } => msg1::hello(ops, link, msg2, lease, now, out),
            In::AnonDial(d) => msg2::dial(ops, d, now, out),
            In::AnonConnecting { to, resends } => msg2::connecting(ops, to, resends, out),
            In::AnonConnectFailed { link } => msg2::unconnected(ops, link, out),
            In::Msg2 {
                link,
                epoch,
                from,
                peer,
            } => msg2::msg2(ops, link, epoch, from, peer, now, out),
            In::FinalSent { link } => msg2::sent(ops, link, now, out),
            In::FinalFailed { link } => failed(ops, link, None),
            In::Failed { link, learned } => failed(ops, link, learned),
            In::Refused { link, retry } => refused(ops, link, retry, out),
            In::Msg3 {
                link,
                peer,
                epoch,
                claim,
                from,
            } => msg3::msg3(ops, link, peer, epoch, claim, from, now, out),
            In::Sweep => sweep(ops, out),
            In::Due => due(ops, now, out),
            In::Timed { link } => timed(ops, link, out),
            In::Quiet { link } => ops.legs_mut().quiet(link),
            In::Unconnected { link, retry } => {
                msg2::unconnected(ops, link, out);
                let asked = !(xx_fault!(ConnectFailNoRetry) || node_fault!(ConnectFailNoRetry));
                if let Some(peer) = retry.filter(|_| asked) {
                    out.push(Output::Retry { peer });
                }
            }
        }
    }

    fn stored(table: &Table<I, Self>, from: &Pair, bytes: &[u8]) -> Option<(LinkNo, Vec<u8>)> {
        // next resends the stored msg2 only for the msg1 it answered, byte
        // for byte, and only from an anonymous answer, never from a held
        // peer's link.
        let answers = &table.flow().answers;
        table
            .links()
            .at(from)
            .filter(|l| answers.contains_key(l))
            .find_map(|l| table.legs().stored(l, bytes).map(|m| (l, m.to_vec())))
    }

    fn pending(table: &Table<I, Self>) -> usize {
        table.flow().pending(table)
    }

    fn answer_sent(ops: &mut Ops<'_, I, Self>, link: LinkNo) {
        if let Some(a) = ops.flow_mut().answers.get_mut(&link) {
            a.sent = true;
        }
    }

    fn installed(ops: &mut Ops<'_, I, Self>, peer: NodeAddr) {
        fresh(ops, peer);
    }

    /// next's `heard_on_session` starts afresh at a move: a frame heard
    /// under the session left does not count for the one moved onto.
    fn moved(ops: &mut Ops<'_, I, Self>, peer: NodeAddr) {
        // The mutation lane's break: the move keeps the frame heard before
        // it.
        let kept = (xx_fault!(MoveKeepsFramed) || node_fault!(MoveKeepsFramed))
            && ops.flow().framed(&peer);
        fresh(ops, peer);
        if kept {
            ops.flow_mut().framed.insert(peer);
        }
    }

    fn heard(ops: &mut Ops<'_, I, Self>, peer: NodeAddr) {
        ops.flow_mut().framed.insert(peer);
    }

    fn removed(ops: &mut Ops<'_, I, Self>, peer: NodeAddr) {
        let flow = ops.flow_mut();
        flow.marks.remove(&peer);
        flow.framed.remove(&peer);
    }

    /// Only a session the peer dialed counts. One this node dialed may have
    /// had its msg3 refused by the peer, whose frames then had no session
    /// to arrive on, so its silence is not held against the peer.
    fn silent(table: &Table<I, Self>, held: &Held<I>) -> bool {
        let own = table
            .links()
            .get(held.link)
            .is_some_and(|r| r.dir == Dir::Outbound);
        !own || xx_fault!(OwnDialCountsSilent) || node_fault!(OwnDialCountsSilent)
    }
}

#[cfg(test)]
mod tests;
