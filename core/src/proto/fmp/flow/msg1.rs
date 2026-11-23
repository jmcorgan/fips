//! The XX flow at msg1: an anonymous msg1 opens its link and asks for its
//! answer, and the answer opens a leg that names no one.
//!
//! next draws the session index and builds the msg2 after the Noise read,
//! with no identity gate, ACL or peer cap (`handshake.rs`, the comment
//! before the index draw), so nothing here judges the msg1. A msg1 whose
//! index cannot be drawn is refused by the shell, which closes nothing.

use alloc::vec::Vec;

use super::{Anon, Answer, Asked, Out, Xx};
use crate::proto::rekey::IndexLease;
use crate::proto::settle::flow::Outs;
use crate::proto::settle::links::{Dir, Holder, LinkNo};
use crate::proto::settle::output::Output;
use crate::proto::settle::table::Ops;
use crate::time::Instant;

/// An anonymous msg1: its link opens inbound, held by its leg, and the
/// shell is asked for its answer.
pub(super) fn anon<I: Instant>(ops: &mut Ops<'_, I, Xx>, a: Anon, out: &mut Vec<Outs<I, Xx>>) {
    let link = ops.links_mut().open(a.from, Dir::Inbound, Holder::Leg);
    let asked = Asked {
        msg1: a.bytes,
        ephemeral: a.ephemeral,
        rekey_of: a.rekey_of,
    };
    ops.flow_mut().asks.insert(link, asked);
    out.push(Output::Flow(Out::Ask { link }));
}

/// The answer to an anonymous msg1: its leg opens, naming no peer and
/// holding the lease, and the msg2 goes out. An answer to no ask hands its
/// lease back.
pub(super) fn hello<I: Instant>(
    ops: &mut Ops<'_, I, Xx>,
    link: LinkNo,
    msg2: Vec<u8>,
    lease: IndexLease,
    now: I,
    out: &mut Vec<Outs<I, Xx>>,
) {
    let Some(asked) = ops.flow_mut().asks.remove(&link) else {
        out.push(Output::Free { lease });
        return;
    };
    // The defect's shape: the answer names an identity, as an IK answer
    // names the msg1's, here the one held on the link at its source.
    let named = if xx_fault!(AnonLegNamed) || node_fault!(AnonLegNamed) {
        asked
            .rekey_of
            .and_then(|l| ops.links().get(l))
            .and_then(|r| match r.holder {
                Holder::Peer(p) => Some(p),
                Holder::Leg => None,
            })
    } else {
        None
    };
    ops.open_answer(link, named, asked.msg1, msg2.clone(), lease, now, out);
    let answer = Answer {
        ephemeral: asked.ephemeral,
        rekey_of: asked.rekey_of,
        sent: false,
    };
    ops.flow_mut().answers.insert(link, answer);
    out.push(Output::Answer {
        link,
        msg2,
        stored: false,
    });
}
