//! The settlement core's link records, fed from what a peer's machines
//! report through the core's join, beside the node's own link table.
//!
//! The link table opens a record with each link and retires it with the
//! link; a promotion holds it for the peer it installs and gives the join the
//! link, so the new bundle's original path is recorded Live. Every other
//! change to a record is a core input the join gives: [`pathed`] runs what a
//! step of a link's bundle returned through it, [`Node::roamed`] a one-path
//! roam or a bind, which the bundle reports in no output, and [`Node::feed`]
//! applies each input to the record. Nothing reads the records to decide
//! anything until the core decides the index and the close rule; the live
//! audit holds them to each held link's bundle.

use super::super::links::pair;
use crate::NodeAddr;
use crate::identity::OsEntropy;
use crate::node::{AddrKey, Node};
use crate::peer::{LinkProfile, PeerBundle, PeerClock, PeerInstant, UdpSlot};
use crate::proto::settle::input::Input;
use crate::proto::settle::join::{self, Event, Joined, Step, join};
use crate::proto::settle::links::{LinkNo, Proven};
use crate::transport::LinkId;
use fips_core::proto::path::{Outputs, PathRef};

/// What the core's join says of one step of a link's bundle: each output,
/// and after it the core input it stands for, if any.
pub(in crate::node) type PathSteps = Joined<LinkProfile, UdpSlot, PeerInstant>;

/// What the step of `peer`'s bundle that returned `out` stands for, read from
/// `bundle` after the step: each output, then the core input it stands for on
/// `link`, the core's number for the peer's link, if the table holds one. A
/// path the step released belongs to `released` where it is given, the link
/// a move left, and to `link` otherwise. A step with no bundle or no link to
/// read tells the core nothing. `None` only if the join refused the step,
/// which it never does.
pub(in crate::node) fn pathed(
    peer: NodeAddr,
    out: Outputs<UdpSlot>,
    bundle: Option<&PeerBundle>,
    link: Option<LinkNo>,
    released: Option<LinkNo>,
) -> Option<PathSteps> {
    let read = |p: &PathRef| bundle.map_or(Proven::Probing, |b| join::proven(b, p));
    let link = link.filter(|_| bundle.is_some());
    let event = Event::Paths {
        out,
        read: &read,
        link,
        released,
    };
    let Ok(steps) = join::<LinkProfile, PeerClock, OsEntropy, UdpSlot>(peer, event) else {
        debug_assert!(false, "the join refused a bundle's step");
        return None;
    };
    Some(steps)
}

impl Node {
    /// Apply the core input `input` to the core's record of the link it
    /// names: a path's state, move, switch or release. Every other input
    /// changes no record, and the node acts on it, if at all, where the join
    /// gave it.
    pub(in crate::node) fn feed(&mut self, input: &Input) {
        match input {
            // The mutation lane's break: a path's state never reaches the
            // record.
            Input::State { .. } if node_fault!(LinksNotFed) => {}
            Input::State { .. }
            | Input::Moved { .. }
            | Input::Switched { .. }
            | Input::Released { .. } => self.links.mirror(input),
            Input::Dial(_)
            | Input::Punched(_)
            | Input::ConnectFailed { .. }
            | Input::Arrived { .. }
            | Input::Msg1 { .. }
            | Input::Replace(_)
            | Input::Msg2 { .. }
            | Input::Restarted { .. }
            | Input::Ended { .. }
            | Input::Orphaned { .. }
            | Input::Heard { .. }
            | Input::Disconnect { .. }
            | Input::Dead { .. }
            | Input::Admin { .. }
            | Input::Sent { .. }
            | Input::SendFailed { .. } => {}
        }
    }

    /// The one path of `peer`'s link `link` moved inside its transport from
    /// `from` to `to`, or, with `from` `None`, a bundle holding no path was
    /// bound at `to`: neither is in any output of the bundle, so the join is
    /// told of it, and the core's record of the link follows.
    pub(in crate::node) fn roamed(
        &mut self,
        peer: NodeAddr,
        link: LinkId,
        from: Option<AddrKey>,
        to: &AddrKey,
    ) {
        let Some(link) = self.links.no(&link) else {
            return;
        };
        // The mutation lane's break: the roam never reaches the record.
        if node_fault!(RoamNotFed) {
            return;
        }
        let event = Event::Roam {
            link,
            from: from.as_ref().map(pair),
            to: pair(to),
        };
        let Ok(steps) = join::<LinkProfile, PeerClock, OsEntropy, UdpSlot>(peer, event) else {
            debug_assert!(false, "the join refused a roam");
            return;
        };
        for step in steps {
            match step {
                Step::Core(input) => self.feed(&input),
                Step::Replace(_) | Step::Rekey(_) | Step::Path(_) => {
                    debug_assert!(false, "a roam gave the shell a step");
                }
            }
        }
    }
}
