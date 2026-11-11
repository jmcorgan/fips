//! What a joint node does with one peer's machine events: the rekey
//! machine's and the bundle's outputs turned into sends and core inputs.
//!
//! [`route`] holds no party state. It reads the events one call of
//! [`Machines`] returned, front to back, keeps the node's index map (which
//! demultiplexes msg2s and frames) as `Bind` and `Unbind` say, and returns
//! what the shell is to send, the core inputs the events stand for, in
//! order, and what the call decided, for the shadow's log. The shell
//! carries the sends and steps the core with the inputs. A send is a
//! handshake message, a prompt, a path message to seal, or a connection
//! the bundle asks for.
//!
//! Which events are core inputs, and which input each stands for, is the
//! core's join function's rule (`settle::join`): each event goes through
//! it, and only what it gives as the shell's own is carried out here. The
//! bundle reports a one-path roam in no output, so its [`Event::Roamed`]
//! is a core input of its own, as each bundle output is: the core mirrors
//! the bundle's paths, and only through these inputs.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use crate::identity::NodeAddr;
use crate::proto::fmp::EphemeralDigest;
use crate::proto::path::tests::shell::Out;
use crate::proto::path::{Output as PathOutput, PathRef};
use crate::proto::rekey::tests::stub::{Ik, Kid, Msg1};
use crate::proto::rekey::{
    Abandon, Authentic, Completed, EpochTag, Msg1Read, MsgKind, Output, Reason, Record, Replayable,
    Route, Wire, allocate,
};
use crate::proto::settle::input::{Hello, Input as In};
use crate::proto::settle::join::{self, Joined, Step, join};
use crate::proto::settle::links::{LinkNo, Proven};
use crate::proto::settle::output::Output as CoreOutput;
use crate::testutil::{TestClock, TestInstant};

use super::super::super::model::history::{Addr, Hs, Node};
use super::super::super::model::judge::Class;
use super::super::drive;
use super::facts::Draw;
use super::machines::{Event, Kit, Machines};
use super::names;

pub use crate::proto::settle::join::pair;

/// A message the shell is to send for a peer's machines.
#[derive(Debug)]
pub enum Send {
    /// The rekey machine's own msg1, to the peer's address.
    Msg1(Wire),
    /// A msg2 answering the peer's msg1, by `route`.
    Msg2 {
        /// The message.
        msg: Wire,
        /// Where it goes.
        route: Route,
    },
    /// A prompt, sealed under `tag`.
    Prompt {
        /// The epoch it is sealed under.
        tag: EpochTag,
        /// The frame.
        wire: Wire,
    },
    /// The bundle's path message `bytes`, from its type byte, to be sealed
    /// under the current session and sent on the path to the peer's pair
    /// `to`.
    Path {
        /// The peer's pair.
        to: Addr,
        /// The link message.
        bytes: Vec<u8>,
    },
    /// The bundle asks for a connection to the peer's pair `to`, with no
    /// handshake on it, and to be told when it settles.
    Connect {
        /// The peer's pair.
        to: Addr,
    },
}

/// What one call's events ask of the shell and what they decided.
#[derive(Debug, Default)]
pub struct Routed {
    /// The messages to send, in order.
    pub sends: Vec<Send>,
    /// The core inputs, in order.
    pub inputs: Vec<In>,
    /// The machine asked for the msg1 to replace the peering.
    pub replace: Option<Authentic<Msg1, Replayable>>,
    /// A cutover happened.
    pub cut: bool,
    /// The machine yielded its own attempt to the peer's.
    pub yielded: bool,
    /// The input changed nothing, for this reason.
    pub reject: Option<Reason>,
    /// A frame's plaintext, in the buffer the call returned.
    pub delivered: Option<Range<usize>>,
    /// The own rekey reached its deadline unanswered.
    pub abandoned: bool,
    /// A responder pending expired unadopted.
    pub unadopted: bool,
    /// Outputs that cannot occur in this world, each a broken promise.
    pub broken: Vec<String>,
}

/// What [`route`] needs beside the events.
pub struct Ctx<'a> {
    /// The peer.
    pub peer: Node,
    /// The peer's node address, as the core names it.
    pub key: NodeAddr,
    /// The link the peer holds, which the bundle's outputs are about;
    /// `None` drops them, as they are at the peer's removal.
    pub link: Option<LinkNo>,
    /// The link a released path belongs to, where it is not `link`: at a
    /// move, the link moved off.
    pub released: Option<LinkNo>,
    /// The peer's machines, after the call.
    pub machines: &'a Machines,
    /// The node's index map.
    pub bound: &'a mut BTreeMap<u32, u8>,
}

/// The world address of path `p`.
pub fn at(p: &PathRef) -> Addr {
    drive::addr(&pair(p))
}

/// What the core is told of the path to `p`, read from the bundle: `Live`
/// for a Live path, `Acked` for another acked one, `Probing` otherwise,
/// and for one the bundle no longer holds; the join function's reading.
pub fn proven(m: &Machines, p: &PathRef) -> Proven {
    join::proven(m.bundle(), p)
}

/// A msg1's answer built before the core decides on it: the completed
/// handshake, the setup record it would note, and the index of the lease
/// the answer's leg would hold.
pub type Built = (Completed<Ik>, Record, u32);

/// The ephemeral digest the core keeps for a msg1, from the stub's.
fn ephemeral(tok: &Msg1) -> EphemeralDigest {
    let mut b = [0u8; 33];
    b[..32].copy_from_slice(&tok.ephemeral().0);
    EphemeralDigest::of_noise_msg1(&b).expect("33 bytes carry an ephemeral")
}

/// The answer to the msg1 `tok` of handshake `hs`, its bytes `bytes`, from
/// `from`, built before the core decides on it: the `Hello` with a fresh
/// lease, and what an install would take from it.
pub fn answer(kit: &mut Kit, tok: &Msg1, hs: Hs, bytes: &[u8], from: Addr) -> (Hello, Built) {
    let lease = allocate(&mut kit.pool).expect("the node's pool has an index");
    let index = lease.index();
    kit.local.name(names::answerer(hs));
    let (done, msg2) = tok
        .answer(&kit.local, Some(lease.index()))
        .expect("the stub IK msg2 always writes");
    let record = Record::setup(tok.digest(), tok.ephemeral(), Some(msg2.clone()));
    let hello = Hello {
        peer: tok.remote().addr(),
        from: drive::pair(from),
        bytes: bytes.to_vec(),
        ephemeral: ephemeral(tok),
        epoch: tok.epoch(),
        msg2,
        lease,
    };
    (hello, (done, record, index))
}

/// Give every lease in `out` back to `kit`'s pool and drop the rest.
pub fn discard(kit: &mut Kit, out: Vec<CoreOutput>) {
    for o in out {
        match o {
            CoreOutput::Free { lease } => kit.pool.free(lease.release()),
            CoreOutput::Install(i) => kit.pool.free(i.lease.release()),
            CoreOutput::Opened { .. }
            | CoreOutput::Answer { .. }
            | CoreOutput::Resend { .. }
            | CoreOutput::Rekey { .. }
            | CoreOutput::Reset { .. }
            | CoreOutput::Remove { .. }
            | CoreOutput::Retire { .. }
            | CoreOutput::Release { .. }
            | CoreOutput::Close { .. }
            | CoreOutput::Retry { .. }
            | CoreOutput::Reject { .. }
            | CoreOutput::Hold { .. }
            | CoreOutput::Settle { .. } => {}
        }
    }
}

/// The model's class for what a machine did with a msg1, from what the call
/// routed: `before` and `after` are its pending session around the call,
/// `eligible` whether the link was eligible to rekey. `Err` names a refusal
/// no msg1 can draw, a broken promise of the machine.
pub fn class(
    r: &Routed,
    before: Option<Kid>,
    after: Option<Kid>,
    eligible: bool,
) -> Result<Option<Class>, Reason> {
    if r.replace.is_some() {
        return Ok(Some(Class::Replacement));
    }
    if r.sends.iter().any(|s| matches!(s, Send::Msg2 { .. })) {
        return Ok(Some(if r.yielded {
            Class::Simultaneous
        } else if after.is_some() && after != before {
            Class::Rekey
        } else if before.is_some() {
            Class::Pending
        } else {
            Class::Resend
        }));
    }
    let Some(why) = r.reject else {
        return Ok(None);
    };
    match why {
        Reason::OffLink => Ok(Some(Class::OffLink)),
        Reason::PendingHeld => Ok(Some(Class::Pending)),
        Reason::DualInitWon => Ok(Some(Class::Simultaneous)),
        Reason::AnsweredBefore if eligible => Ok(Some(Class::Recorded)),
        Reason::AnsweredBefore => Ok(Some(Class::Copy)),
        Reason::EpochChanged => Ok(None),
        Reason::IndexExhausted
        | Reason::HandshakeWrite
        | Reason::ReplyUnauthenticated
        | Reason::LateReply
        | Reason::UnknownAttempt
        | Reason::UnknownIndex
        | Reason::SetupMalformed
        | Reason::TieBreakKept
        | Reason::CandidatesFull
        | Reason::FinalNoAttempt
        | Reason::FinalUnauthenticated
        | Reason::KeyMismatch
        | Reason::StaleIncarnation
        | Reason::Replay
        | Reason::FrameUnauthenticated
        | Reason::ShortPlaintext
        | Reason::DelegatedEpoch
        | Reason::NotEstablished
        | Reason::StaleTag
        | Reason::NotDelegated
        | Reason::AlreadyDelegated
        | Reason::NotOffered
        | Reason::AttemptInFlight
        | Reason::AlreadyEstablished
        | Reason::CandidateExpired
        | Reason::NotRekey => Err(why),
    }
}

/// Route the events of one call of a peer's machines, each through the
/// join function.
pub fn route(events: Vec<Event>, mut ctx: Ctx<'_>) -> Routed {
    let mut r = Routed::default();
    for e in events {
        match e {
            Event::Rekey(o) => {
                let steps = joined(
                    ctx.key,
                    join::Event::Rekey {
                        out: alloc::vec![o],
                    },
                );
                stepped(steps, &mut ctx, &mut r);
            }
            Event::Prompt { tag, wire } => r.sends.push(Send::Prompt { tag, wire }),
            Event::Freed(_) => {}
            Event::Path(o) => {
                let m = ctx.machines;
                let read = |p: &PathRef| proven(m, p);
                let steps = joined(
                    ctx.key,
                    join::Event::Paths {
                        out: alloc::vec![o],
                        read: &read,
                        link: ctx.link,
                        released: ctx.released,
                    },
                );
                stepped(steps, &mut ctx, &mut r);
            }
            Event::Roamed { from, to } => {
                if let Some(link) = ctx.link
                    && !fault!(PathsUnmirrored)
                {
                    let roam = join::Event::Roam {
                        link,
                        from: Some(drive::pair(from)),
                        to: drive::pair(to),
                    };
                    stepped(joined(ctx.key, roam), &mut ctx, &mut r);
                }
            }
            Event::Bound { at } => {
                if let Some(link) = ctx.link {
                    let bind = join::Event::Roam {
                        link,
                        from: None,
                        to: drive::pair(at),
                    };
                    stepped(joined(ctx.key, bind), &mut ctx, &mut r);
                }
            }
        }
    }
    r
}

/// The steps the join function gives for `peer`'s `event`.
fn joined(
    peer: NodeAddr,
    event: join::Event<'_, '_, '_, Ik, TestClock, Draw, u64>,
) -> Joined<Ik, u64, TestInstant> {
    join(peer, event).unwrap_or_else(|_| unreachable!("only a start is refused"))
}

/// Carry out `steps`: a core input taken in order, a replacement for the
/// core's gates noted, and each machine output that is the shell's own
/// routed as it is.
fn stepped(steps: Joined<Ik, u64, TestInstant>, ctx: &mut Ctx<'_>, r: &mut Routed) {
    for step in steps {
        match step {
            Step::Core(i) => {
                // The defects' shapes: the core never told of a restart
                // its rekey machine found, or of a bundle with no path left
                // to send on, which it then keeps.
                let dropped = (matches!(i, In::Restarted { .. }) && fault!(RestartDropped))
                    || (matches!(i, In::Orphaned { .. }) && fault!(OrphanKept));
                if !dropped {
                    r.inputs.push(i);
                }
            }
            Step::Replace(tok) => {
                if !fault!(ReplaceDropped) {
                    r.replace = Some(tok);
                }
            }
            Step::Rekey(o) => rekeyed(o, ctx, r),
            Step::Path(o) => pathed(o, r),
        }
    }
}

/// One rekey machine output the join function gave as the shell's own.
fn rekeyed(o: Output<Ik>, ctx: &mut Ctx<'_>, r: &mut Routed) {
    match o {
        Output::Send { msg, kind, route } => match kind {
            MsgKind::Msg1 => r.sends.push(Send::Msg1(msg)),
            MsgKind::Msg2 => r.sends.push(Send::Msg2 { msg, route }),
            MsgKind::Setup | MsgKind::Ack | MsgKind::Msg3 => {
                r.broken.push(format!("the IK machine sent a {kind:?}"));
            }
        },
        Output::Bind { index, .. } => {
            if let Some(was) = ctx.bound.insert(index, ctx.peer.0) {
                r.broken
                    .push(format!("index {index} bound for peer {was} and again"));
            }
        }
        Output::Unbind { index, .. } => {
            if ctx.bound.remove(&index).is_none() {
                r.broken.push(format!("index {index} unbound, not bound"));
            }
        }
        Output::Delegate { tag, .. } | Output::Revoke { tag, .. } => r.broken.push(format!(
            "{:?}: a worker hand-off of {tag:?} with no worker",
            ctx.peer
        )),
        Output::Prompt { tag } => r
            .broken
            .push(format!("{:?}: a prompt of {tag:?} left unsealed", ctx.peer)),
        Output::Release(lease) => r.broken.push(format!(
            "{:?}: the lease on {} left unreleased",
            ctx.peer,
            lease.release()
        )),
        Output::Deliver { range, .. } => r.delivered = Some(range),
        Output::Installed { .. } | Output::Retired { .. } | Output::Reverted { .. } => {}
        Output::Rekeyed { .. } => r.cut = true,
        Output::Reject(why) => r.reject = Some(why),
        Output::Abandoned(a) => match a {
            Abandon::Unanswered => r.abandoned = true,
            Abandon::Unadopted => r.unadopted = true,
            Abandon::Yielded => r.yielded = true,
            Abandon::AdoptionNotSeen
            | Abandon::PeerStayedOnOld
            | Abandon::RevertUnconfirmed
            | Abandon::Reverted
            | Abandon::Superseded
            | Abandon::Closed(_) => {}
        },
        Output::PeerRestarted { .. } | Output::ReplaceRequested { .. } | Output::Teardown(_) => {
            r.broken.push(format!(
                "{:?}: the join function gave the core's output {o:?} to the shell",
                ctx.peer
            ));
        }
    }
}

/// One bundle output the join function gave back: the sends are the
/// shell's, and the core inputs it stands for came with it.
fn pathed(o: Out, r: &mut Routed) {
    match o {
        PathOutput::Send { to, bytes } => r.sends.push(Send::Path {
            to: drive::addr(&pair(&to)),
            bytes,
        }),
        PathOutput::Connect { to } => r.sends.push(Send::Connect {
            to: drive::addr(&pair(&to)),
        }),
        PathOutput::State { .. }
        | PathOutput::Moved { .. }
        | PathOutput::Switched { .. }
        | PathOutput::Released { .. }
        | PathOutput::Orphaned
        | PathOutput::Capable
        | PathOutput::NotCapable
        | PathOutput::Refused { .. }
        | PathOutput::Proven { .. } => {}
    }
}
