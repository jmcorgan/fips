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
//! The bundle reports a one-path roam in no output, so its
//! [`Event::Roamed`] is a core input of its own, as each bundle output is:
//! the core mirrors the bundle's paths, and only through these inputs.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::ops::Range;

use crate::identity::NodeAddr;
use crate::proto::path::tests::shell::Out;
use crate::proto::path::{Output as PathOutput, PathRef, PathState};
use crate::proto::rekey::tests::stub::{Ik, Msg1};
use crate::proto::rekey::{
    Abandon, Authentic, EpochTag, MsgKind, Output, Reason, Replayable, Route, Wire,
};
use crate::proto::settle::input::Input as In;
use crate::proto::settle::links::{LinkNo, Pair, Proven};

use super::super::super::model::history::{Addr, Node};
use super::super::drive;
use super::machines::{Event, Machines};

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

/// The core's pair for path `p`.
pub fn pair(p: &PathRef) -> Pair {
    Pair {
        transport: p.transport,
        addr: p.addr.clone(),
    }
}

/// What the core is told of the path to `p`, read from the bundle: `Live`
/// for a Live path, `Acked` for another acked one, `Probing` otherwise,
/// and for one the bundle no longer holds.
pub fn proven(m: &Machines, p: &PathRef) -> Proven {
    let paths = m.bundle().paths();
    let Some(path) = paths.find(p.transport, &p.addr).and_then(|i| paths.get(i)) else {
        return Proven::Probing;
    };
    if path.state() == PathState::Live {
        Proven::Live
    } else if path.acked() {
        Proven::Acked
    } else {
        Proven::Probing
    }
}

/// Route the events of one call of a peer's machines.
pub fn route(events: Vec<Event>, mut ctx: Ctx<'_>) -> Routed {
    let mut r = Routed::default();
    for e in events {
        match e {
            Event::Rekey(o) => rekeyed(o, &mut ctx, &mut r),
            Event::Prompt { tag, wire } => r.sends.push(Send::Prompt { tag, wire }),
            Event::Freed(_) => {}
            Event::Path(o) => pathed(o, &ctx, &mut r),
            Event::Roamed { from, to } => {
                if let Some(link) = ctx.link
                    && !fault!(PathsUnmirrored)
                {
                    r.inputs.push(In::Moved {
                        link,
                        from: drive::pair(from),
                        to: drive::pair(to),
                    });
                }
            }
            Event::Bound { at } => {
                if let Some(link) = ctx.link {
                    r.inputs.push(In::State {
                        link,
                        pair: drive::pair(at),
                        proven: Proven::Live,
                    });
                }
            }
        }
    }
    r
}

/// One rekey machine output.
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
        Output::PeerRestarted { epoch, .. } => {
            if !fault!(RestartDropped) {
                r.inputs.push(In::Restarted {
                    peer: ctx.key,
                    epoch,
                });
            }
        }
        Output::Rekeyed { .. } => r.cut = true,
        Output::ReplaceRequested { tok } => {
            if !fault!(ReplaceDropped) {
                r.replace = Some(tok);
            }
        }
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
        Output::Teardown(_) => r.inputs.push(In::Ended { peer: ctx.key }),
    }
}

/// One bundle output.
fn pathed(o: Out, ctx: &Ctx<'_>, r: &mut Routed) {
    match o {
        PathOutput::State { next: None, .. } => {}
        PathOutput::State { to, .. } => {
            if let Some(link) = ctx.link {
                r.inputs.push(In::State {
                    link,
                    pair: pair(&to),
                    proven: proven(ctx.machines, &to),
                });
            }
        }
        PathOutput::Moved { from, to, .. } => {
            if let Some(link) = ctx.link {
                r.inputs.push(In::Moved {
                    link,
                    from: pair(&from),
                    to: pair(&to),
                });
            }
        }
        PathOutput::Switched { from, to, .. } => {
            if let Some(link) = ctx.link {
                // The core never reads `from`; a discarded old active path
                // gives none, so the pair switched to stands in.
                let from = from.as_ref().unwrap_or(&to);
                r.inputs.push(In::Switched {
                    link,
                    from: pair(from),
                    to: pair(&to),
                });
            }
        }
        PathOutput::Released { to, keep, .. } => {
            if let Some(link) = ctx.released.or(ctx.link) {
                r.inputs.push(In::Released {
                    link,
                    pair: pair(&to),
                    keep,
                });
            }
        }
        PathOutput::Orphaned => {
            // The defect's shape: the core never told, so it keeps a peer
            // whose bundle has no path left to send on.
            if ctx.link.is_some() && !fault!(OrphanKept) {
                r.inputs.push(In::Orphaned { peer: ctx.key });
            }
        }
        PathOutput::Capable | PathOutput::NotCapable | PathOutput::Refused { .. } => {}
        PathOutput::Send { to, bytes } => r.sends.push(Send::Path {
            to: drive::addr(&pair(&to)),
            bytes,
        }),
        PathOutput::Connect { to } => r.sends.push(Send::Connect {
            to: drive::addr(&pair(&to)),
        }),
    }
}
