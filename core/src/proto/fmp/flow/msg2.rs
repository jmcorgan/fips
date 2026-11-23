//! The XX flow at msg2: this node's dials, the anonymous one included, and
//! what a completed dial does, parked until its msg3 is sent.
//!
//! The decision is next's `establish_outbound` (`../core.rs`): no peer held
//! for the identity the msg2 taught is a promote; an epoch other than the
//! one on record is a restart, with no gate; a msg2 beside this node's own
//! dial, in flight when the session held was installed and not heard under
//! since, is kept at once and sends no msg3; anything else is settled by
//! address order, the smaller node moving onto its dial and the larger
//! keeping the peer where it is. Every decision but the own-dial keep waits
//! for the outcome of the msg3 send, since next promotes only once the msg3
//! is out (`handshake.rs`, the msg3 send before `install_handshake`).

use alloc::vec::Vec;

use super::{AnonDial, How, Out, Parked, Xx, barred};
use crate::identity::NodeAddr;
use crate::proto::settle::flow::Outs;
use crate::proto::settle::gates::Epoch;
use crate::proto::settle::legs::{Kind, Start};
use crate::proto::settle::links::{Dir, Holder, LinkNo, Pair};
use crate::proto::settle::output::{Output, Transition, Why};
use crate::proto::settle::table::Ops;
use crate::time::Instant;

/// An anonymous dial's leg starts, naming no peer, on the link an
/// [`In::AnonConnecting`](super::In::AnonConnecting) opened for it or on
/// one opened here. A dial naming a link no record holds gives its lease
/// back and starts nothing.
pub(super) fn dial<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    d: AnonDial,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let (link, resends, opened) = match d.link {
        None => {
            let link = ops.links_mut().open(d.to, Dir::Outbound, Holder::Leg);
            (link, d.resends, true)
        }
        Some(l) => {
            let waited = ops.flow_mut().connects.remove(&l);
            let known = ops.links().get(l).is_some();
            match (waited, known) {
                (Some(r), true) => (l, r, false),
                (Some(r), false) => {
                    let link = ops.links_mut().open(d.to, Dir::Outbound, Holder::Leg);
                    (link, r, true)
                }
                (None, true) => (l, d.resends, false),
                (None, false) => {
                    out.push(Output::Free { lease: d.lease });
                    return;
                }
            }
        }
    };
    let params = *ops.params();
    let start = Start {
        link,
        peer: None,
        msg1: d.msg1,
        lease: d.lease,
        resends,
        held: None,
    };
    if let Some(old) = ops.legs_mut().dial(start, now, &params) {
        out.push(Output::Free { lease: old.lease() });
    }
    if opened {
        out.push(Output::Opened { link });
    }
}

/// An anonymous dial on a connection still to be opened: its link opens
/// now, in the index and in use, with no leg until its msg1.
pub(super) fn connecting<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    to: Pair,
    resends: Option<u32>,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let link = ops.links_mut().open(to, Dir::Outbound, Holder::Leg);
    ops.flow_mut().connects.insert(link, resends);
    out.push(Output::Opened { link });
}

/// The connection an anonymous dial waited on failed: its link is retired,
/// closing nothing, as for an identified dial. A dial whose leg started is
/// abandoned as the table abandons one.
pub(super) fn unconnected<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    out: &mut Vec<Outs<I, Xx>>,
) {
    if ops.flow_mut().connects.remove(&link).is_some() {
        let _ = ops.links_mut().retire(link);
        out.push(Output::Retire {
            link,
            closes: Vec::new(),
        });
        return;
    }
    ops.flow_mut().forget(link);
    ops.abandon(link, out);
}

/// The msg2 of this node's dial on `link`, which taught `peer`. A msg2 for
/// no dial, or for a dial already decided, failed or refused, changes
/// nothing, nor does one whose identity differs from the one the dial
/// named: that is the shell's refusal, and the leg stays.
#[allow(clippy::too_many_arguments)]
pub(super) fn msg2<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    epoch: Epoch,
    from: Pair,
    peer: NodeAddr,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let Some(leg) = ops.legs().get(link) else {
        return;
    };
    if !matches!(leg.kind(), Kind::Dial) {
        return;
    }
    let named = leg.peer();
    let flow = ops.flow();
    if flow.parked.contains_key(&link)
        || flow.failed.contains_key(&link)
        || flow.reaped.contains(&link)
    {
        return;
    }
    let peer = if xx_fault!(AnonDialNamed) || node_fault!(AnonDialNamed) {
        // The defect's shape: the msg2 completes under the identity the
        // dial named, as an IK dial's does, so an anonymous one never does.
        let Some(named) = named else {
            return;
        };
        named
    } else {
        peer
    };
    if named.is_some_and(|n| n != peer) {
        return;
    }
    ops.flow_mut().learned.insert(link, peer);
    let how = match ops.held(&peer) {
        None => How::Promote,
        Some(h) if h.epoch != epoch => How::Restart,
        Some(h) => {
            let own = ops
                .links()
                .get(h.link)
                .is_some_and(|r| r.dir == Dir::Outbound);
            let flow = ops.flow();
            let beside = own
                && flow.predates(&peer, link)
                && !flow.framed(&peer)
                && !(xx_fault!(BesideOwnSendsFinal) || node_fault!(BesideOwnSendsFinal));
            if beside {
                // next's own-dial keep: no msg3, the dial given up as the
                // larger node's is, and the msg2's pair offered to the
                // peer's link as a heard path.
                ops.flow_mut().forget(link);
                ops.keep(peer, link, out);
                out.push(Output::Flow(Out::Offer { peer, pair: from }));
                return;
            }
            // The mutation lane's break: the smaller node keeps, as the
            // larger does.
            let crossed = xx_fault!(CrossedRunsKeep) || node_fault!(CrossedRunsKeep);
            if ops.me() < peer && !crossed {
                How::Swap { own }
            } else {
                How::Keep
            }
        }
    };
    let parked = Parked {
        peer,
        epoch,
        from,
        how,
    };
    if xx_fault!(FinalBeforeSendOutcome) || node_fault!(FinalBeforeSendOutcome) {
        // The defect's shape: the decision runs before the send's outcome.
        run(ops, link, parked, now, out);
        out.push(Output::Flow(Out::Final { link }));
        return;
    }
    ops.flow_mut().parked.insert(link, parked);
    out.push(Output::Flow(Out::Final { link }));
}

/// The msg3 of the dial on `link` went out: its parked decision runs.
pub(super) fn sent<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let Some(parked) = ops.flow_mut().parked.remove(&link) else {
        return;
    };
    run(ops, link, parked, now, out);
}

/// Carry out the decision `p` for the dial on `link`: an install goes
/// through next's promote refusals, the leaf rule and the max-peers cap.
fn run<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    p: Parked,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    ops.flow_mut().learned.remove(&link);
    match p.how {
        How::Promote => {
            if barred(ops, p.peer, link, false, out) {
                return;
            }
            ops.dialed(p.peer, link, p.epoch, p.from, Transition::Promote, now, out);
        }
        How::Restart => {
            ops.remove(p.peer, Why::OwnRestart, now, out);
            if barred(ops, p.peer, link, false, out) {
                return;
            }
            ops.dialed(p.peer, link, p.epoch, p.from, Transition::Replace, now, out);
        }
        How::Swap { own } => swap(ops, p.peer, link, p.from, own, out),
        How::Keep => ops.keep(p.peer, link, out),
    }
}

/// The smaller node moves the held `peer` onto its dial on `link`, which
/// `from` answered, and closes only what next's move closes: the link it
/// left, where nothing else uses it. The table's move also closes the
/// dial's own connection when the msg2 came from another pair, a rule next
/// lacks: its move leaves that connection open (`loser_close` in
/// `src/node/settle/exec/cross.rs` closes the link left alone). So that
/// pair leaves the retire's closes here, unless the link left was set up
/// at it or holds a path there, where the retire itself chose it.
fn swap<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    peer: NodeAddr,
    link: LinkNo,
    from: Pair,
    own: bool,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let left = ops.held(&peer).map(|h| h.link);
    let dialed = ops.links().get(link).map(|r| r.setup.clone());
    let chosen = |p: &Pair, ops: &Ops<'_, I, Xx>| {
        left.and_then(|l| ops.links().get(l))
            .is_some_and(|r| r.setup == *p || r.paths.iter().any(|(q, _)| q == p))
    };
    let strip = dialed
        .filter(|p| !chosen(p, ops))
        .filter(|_| !(xx_fault!(MoveClosesDial) || node_fault!(MoveClosesDial)));
    let start = out.len();
    ops.moveto(peer, link, from, own, out);
    let Some(dialed) = strip else {
        return;
    };
    for o in &mut out[start..] {
        if let Output::Retire { link: l, closes } = o
            && Some(*l) == left
        {
            closes.retain(|p| *p != dialed);
        }
    }
}
