//! The XX flow at msg3: an anonymous answer learns its peer, and next's
//! `establish_inbound` (`../core.rs`) decides what the msg3 does.
//!
//! The order is next's, which FRC-2201 Section 5.7 shares: an identity not
//! held is promoted, unless its silent sessions refuse it at the epoch they
//! counted; an epoch other than the one on record is a restart, refused
//! while the peering was heard or installed less than the interval ago or
//! the dampener holds, and stamping the dampener when accepted; a claim of
//! a session not held repeats the held peer's stored msg2; no claim is a
//! crossing, which the larger node's inbound wins; and a claim of the
//! session held is the peer's rekey. next's two guards on the crossing, a
//! different link and a session held, are always true here: every answer's
//! link is a link of its own, and a held peer holds a session.

use alloc::vec::Vec;

use super::{Answer, Out, Xx, barred, end};
use crate::identity::NodeAddr;
use crate::proto::fmp::RekeyClaim;
use crate::proto::settle::flow::Outs;
use crate::proto::settle::gates::{Ask, Epoch, Liveness, Refusal, Source};
use crate::proto::settle::links::{LinkNo, Pair};
use crate::proto::settle::output::{Denial, Output, Transition, Why};
use crate::proto::settle::table::Ops;
use crate::time::Instant;

/// The msg3 of the anonymous answer on `link`, which proves `peer` at
/// `epoch` and claims `claim`. A msg3 for no anonymous answer, or for one a
/// refusal left for its reap, changes nothing.
#[allow(clippy::too_many_arguments)]
pub(super) fn msg3<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    peer: NodeAddr,
    epoch: Epoch,
    claim: RekeyClaim,
    from: Pair,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let Some(answer) = ops.flow().answers.get(&link).copied() else {
        return;
    };
    if ops.legs().get(link).is_none() || ops.flow().reaped.contains(&link) {
        return;
    }
    let Some((held, liveness)) = ops.held(&peer).map(|h| {
        let liveness = Liveness {
            heard: true,
            installed: h.installed,
            last: h.last,
        };
        (h.epoch, liveness)
    }) else {
        let any = xx_fault!(SilentRefusalAnyEpoch) || node_fault!(SilentRefusalAnyEpoch);
        let silenced = if any {
            ops.gates().refusing(&peer, now).is_some()
        } else {
            ops.gates().silenced(&peer, Some(epoch), now)
        };
        if silenced {
            let why = Denial::Gate(Refusal::Silent);
            deny(ops, link, peer, Source::NotHeld, why, out);
            return;
        }
        if !barred(ops, peer, link, true, out) {
            install(ops, peer, link, answer, epoch, false, now, out);
        }
        return;
    };
    if held != epoch {
        restart(ops, link, peer, answer, epoch, liveness, now, out);
        return;
    }
    let torn = xx_fault!(MismatchClaimTearsDown) || node_fault!(MismatchClaimTearsDown);
    let crossed = xx_fault!(MatchesReadAsCross) || node_fault!(MatchesReadAsCross);
    match claim {
        RekeyClaim::Mismatch if torn => {
            // The defect's shape: a claim of a session not held replaces
            // the peering.
            ops.remove(peer, Why::Replacement, now, out);
            install(ops, peer, link, answer, epoch, true, now, out);
        }
        RekeyClaim::Mismatch => {
            out.push(Output::Flow(Out::Repeat { peer, link }));
            end(ops, link, out);
        }
        RekeyClaim::Matches if !crossed => rekey(ops, link, peer, out),
        RekeyClaim::None | RekeyClaim::Matches => {
            cross(ops, link, peer, answer, epoch, from, now, out);
        }
    }
}

/// A msg3 at an epoch other than the held peer's: through next's restart
/// gate, one floor of the interval from the last frame or the install,
/// and the dampener, which an accepted restart stamps; then the held peer
/// is removed and the answer installed in its place.
#[allow(clippy::too_many_arguments)]
fn restart<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    peer: NodeAddr,
    answer: Answer,
    epoch: Epoch,
    liveness: Liveness<I>,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let refusal = if xx_fault!(Msg3RestartUngated) || node_fault!(Msg3RestartUngated) {
        None
    } else {
        // Read as heard, the gate's one floor counts from the last frame
        // or, with none, from the install, as next's idle time does.
        let params = *ops.params();
        let ask = Ask {
            source: Source::Restart,
            held: Some(liveness),
            ephemeral: None,
            epoch: Some(epoch),
            memory: None,
        };
        ops.gates_mut().gate(peer, ask, now, &params)
    };
    if let Some(r) = refusal {
        deny(ops, link, peer, Source::Restart, Denial::Gate(r), out);
        return;
    }
    ops.remove(peer, Why::Restart, now, out);
    if !barred(ops, peer, link, true, out) {
        install(ops, peer, link, answer, epoch, true, now, out);
    }
}

/// Install `peer` from the anonymous answer on `link`, at the pair its
/// msg1 came from; `replaces` says a held peer was torn down for it.
#[allow(clippy::too_many_arguments)]
fn install<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    peer: NodeAddr,
    link: LinkNo,
    answer: Answer,
    epoch: Epoch,
    replaces: bool,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    ops.flow_mut().forget(link);
    let (Some(leg), Some(pair)) = (
        ops.legs_mut().take(link),
        ops.links().get(link).map(|r| r.setup.clone()),
    ) else {
        return;
    };
    ops.install_answer(peer, leg, pair, epoch, answer.ephemeral, replaces, now, out);
}

/// The msg3 on `link` is refused: no msg2 goes back, and the answer and
/// its link go, with no close in the retire.
fn deny<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    peer: NodeAddr,
    source: Source,
    why: Denial<super::Deny>,
    out: &mut Vec<Outs<I, Xx>>,
) {
    out.push(Output::Reject {
        peer: Some(peer),
        source: Some(source),
        why,
    });
    end(ops, link, out);
}

/// The msg3 on `link` declares a rekey of the session held: its link goes
/// without closing a connection, and the leg's lease goes to the peer's
/// rekey machine.
fn rekey<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    peer: NodeAddr,
    out: &mut Vec<Outs<I, Xx>>,
) {
    ops.flow_mut().forget(link);
    let Some(leg) = ops.legs_mut().take(link) else {
        return;
    };
    let _ = ops.links_mut().retire(link);
    out.push(Output::Retire {
        link,
        closes: Vec::new(),
    });
    out.push(Output::Flow(Out::Rekey {
        peer,
        link,
        lease: leg.lease(),
    }));
}

/// A fresh dial crossing this node's at msg3. The larger node's inbound
/// wins: it moves the peer onto the answer's link, session and lease, at
/// the msg3's pair, a move whose rekey machine is rebuilt from the closed
/// one's carry, and retires the link it held, its own dial's, whose
/// connection the smaller node's keep closes at the other end. The smaller
/// node keeps its own and drops the answer, a keep. Both end on the link
/// the smaller node dialed (FRC-2201 Section 5.7). Each is told as the
/// column next's node runs for it (`Transition::Move` and
/// `Transition::Keep`, both `inbound`, in `src/node/settle/table.rs`).
#[allow(clippy::too_many_arguments)]
fn cross<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    peer: NodeAddr,
    answer: Answer,
    epoch: Epoch,
    from: Pair,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    if ops.me() < peer {
        end(ops, link, out);
        out.push(Output::Reset {
            peer,
            transition: Transition::Keep,
        });
        return;
    }
    ops.flow_mut().forget(link);
    let Some(leg) = ops.legs_mut().take(link) else {
        return;
    };
    // The defect's shape: the peer stays held on its own dial's link and
    // the answer's link is retired. Only a build that can turn the switch
    // compiles it, so the hold it calls reaches no release build.
    #[cfg(any(test, feature = "test-hooks"))]
    if xx_fault!(Msg3MoveKeepsHeldLink) || node_fault!(Msg3MoveKeepsHeldLink) {
        ops.hold_answer(peer, leg, from, epoch, answer.ephemeral, now, out);
        return;
    }
    ops.move_answer(peer, leg, from, epoch, answer.ephemeral, now, out);
}
