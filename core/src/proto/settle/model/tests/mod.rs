//! Table tests for the reference model: one per FRC-1201 Section 5.7 rule,
//! one per Section 5.5 gate edge, the Section 5.6 tie-break, own-dial rule
//! and close clause, and one per local rule value. Each test cites the FRC
//! line it reads (`frc-1201:<line>`, at fips-frcs `7c41380`).

mod classify;
mod close;
mod crossing;
mod gates;

use alloc::vec::Vec;

use super::history::{Addr, Binding, Bytes, Epoch, Event, Hs, LinkId, Ms, Node};
use super::judge::{Judge, Params, Step};

/// The smaller and larger node of every pair.
const SMALL: Node = Node(1);
const LARGE: Node = Node(2);

/// The peer's epoch on record, and the epoch after its restart.
const E1: Epoch = Epoch(1);
const E2: Epoch = Epoch(2);

/// An address on transport 1.
fn at(port: u16) -> Addr {
    Addr {
        transport: 1,
        at: port,
    }
}

/// A judge for `me` facing `peer`, with the default intervals.
fn judge(me: Node, peer: Node) -> Judge {
    Judge::new(me, peer, Params::default())
}

/// This node's own dial `hs` on link `link` to `to`.
fn dial(hs: u32, link: u32, to: Addr, binding: Binding) -> Event {
    Event::Dial {
        hs: Hs(hs),
        link: LinkId(link),
        to,
        binding,
    }
}

/// A msg1 of handshake `hs` with bytes `bytes`, sent at once if answered.
fn msg1(hs: u32, bytes: u32, epoch: Epoch, link: u32, from: Addr, binding: Binding) -> Event {
    Event::Msg1 {
        hs: Hs(hs),
        bytes: Bytes(bytes),
        epoch,
        link: LinkId(link),
        from,
        binding,
        sent: true,
    }
}

/// The msg2 of this node's own handshake `hs`.
fn msg2(hs: u32, epoch: Epoch, from: Addr) -> Event {
    Event::Msg2 {
        hs: Hs(hs),
        epoch,
        from,
    }
}

/// A frame under the session of handshake `hs`.
fn frame(hs: u32, from: Addr) -> Event {
    Event::Frame { hs: Hs(hs), from }
}

fn wait(ms: Ms) -> Event {
    Event::Advance(ms)
}

/// Runs `history` on `j` and returns the last event's step.
fn last(j: &mut Judge, history: &[Event]) -> Step {
    let steps: Vec<Step> = j.run(history);
    steps
        .last()
        .cloned()
        .expect("a history of at least one event")
}

/// A judge that has installed the peer from its msg1 (handshake 10, bytes
/// 100, link 1, from `at(9)`), on a connectionless link, and heard one
/// frame at once.
fn responder(me: Node, peer: Node) -> Judge {
    let mut j = judge(me, peer);
    j.run(&[
        msg1(10, 100, E1, 1, at(9), Binding::Connectionless),
        frame(10, at(9)),
    ]);
    j
}
