//! Each node's history projected onto its own reference-model judge.
//!
//! A party that is not the model (the legacy models here, the core later)
//! logs, per peer identity, every history event it saw and what it did
//! with it: the msg1's class, a refusal, the peer change and whether the
//! peering is heard afterwards. [`compare`] replays that log through one
//! [`Judge`] per peer and reports the first step where the two differ, as
//! a `Classified` (class or refusal) or `Fresh` (peer change) breach.
//! After a first difference the comparison of that peer stops, since the
//! two hold different state from there on.
//!
//! Some differences are known and named, each with its resync:
//!
//! - **Heard after a move**: heard is not set by a move; the shadow takes
//!   the party's heard after each move.
//! - **The dampener's stamp**: only a msg1 restart or replacement stamps
//!   the dampener. The model's dampener rule gives the same, so it needs no
//!   resync.
//! - **Own dials at a promotion**: a promotion at a msg1 keeps this node's
//!   own dials. The model keeps them too.
//! - **Late second dial**: where the model moves and keeps the old session
//!   as a fallback, the node moves and keeps nothing. The shadow's
//!   fallback is cleared, and [`resync_close`] gives the close the node is
//!   expected to make by the close rule.
//! - **Replay memory**: the node refuses a msg1 the model accepts. The
//!   comparison of that peer is pruned there.
//! - **Silent sessions**: the node's back-off for a peer whose sessions
//!   end without a frame refuses a msg1 the model accepts, pruned the same
//!   way. The model of `master` does not transcribe it; the core does.
//! - **The derived index** is the core's own and has no shadow step.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::model::history::{Addr, Binding, Event, Ms, Node};
use super::super::model::judge::{Class, Gate, Judge, LocalRule, Params, Transition};

/// A refusal of a restart or replacement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// One of the FRC's gates.
    Gate(Gate),
    /// The node's memory of ephemerals that promoted an unheard peering.
    Replay,
    /// The node's back-off for a peer whose sessions end without a frame.
    Silent,
    /// The node's cap on answers in flight.
    Full,
}

/// What a party did with one history event.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Rec {
    /// The msg1's class.
    pub class: Option<Class>,
    /// A refusal.
    pub refused: Option<Refusal>,
    /// The peer change.
    pub change: Option<Transition>,
    /// Whether the peering is heard afterwards.
    pub heard: bool,
}

/// One line of a party's log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A history event of `peer` at monotonic time `at`.
    Ev {
        /// When.
        at: Ms,
        /// The peer identity.
        peer: Node,
        /// The event.
        ev: Event,
        /// What the party did.
        rec: Rec,
    },
    /// The party's own rekey of `peer` reached its deadline unanswered.
    /// The model has no rekey deadline, so the shadow drops the rekey too.
    Abandon {
        /// The peer.
        peer: Node,
    },
    /// The party's responder pending for `peer` expired unadopted. The
    /// model has no hold timer, so the shadow drops the pending too.
    Unadopted {
        /// The peer.
        peer: Node,
    },
    /// The node restarted.
    Restart,
}

/// A named difference from the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Named {
    /// Heard is not set by a move.
    HeardAfterMove,
    /// The late second dial keeps no fallback.
    LateSecondDial,
    /// The replay memory refused a msg1 the model accepts.
    Replay,
    /// The silent-session back-off refused a msg1 the model accepts.
    Silent,
}

/// One difference from the shadow.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diff {
    /// True for the class or refusal, false for the peer change.
    pub classified: bool,
    /// The peer identity.
    pub peer: Node,
    /// What differed.
    pub what: String,
}

/// What a comparison found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Found {
    /// The first difference per peer.
    pub diffs: Vec<Diff>,
    /// The named differences met, per peer.
    pub named: Vec<(Node, Named)>,
}

/// Replay node `me`'s log through one judge per peer and compare.
pub fn compare(me: Node, log: &[Entry]) -> Found {
    let mut judges: Vec<(Node, Judge, bool)> = Vec::new();
    let mut found = Found::default();
    let mut now: Ms = 0;
    for e in log {
        match *e {
            Entry::Restart => {
                for (_, j, _) in judges.iter_mut() {
                    j.step(Event::Restart);
                    j.step(Event::Advance(now));
                }
            }
            Entry::Abandon { peer } => {
                if let Some((_, j, _)) = judges.iter_mut().find(|(p, ..)| *p == peer) {
                    j.rekey = None;
                }
            }
            Entry::Unadopted { peer } => {
                if let Some((_, j, _)) = judges.iter_mut().find(|(p, ..)| *p == peer)
                    && let Some(p) = j.peering.as_mut()
                {
                    p.pending = p.pending.filter(|pd| pd.initiator);
                }
            }
            Entry::Ev { at, peer, ev, rec } => {
                now = now.max(at);
                let i = match judges.iter().position(|(p, ..)| *p == peer) {
                    Some(i) => i,
                    None => {
                        let mut j = Judge::new(me, peer, Params::default());
                        j.step(Event::Advance(now));
                        judges.push((peer, j, false));
                        judges.len() - 1
                    }
                };
                let (_, j, pruned) = &mut judges[i];
                if j.now < at {
                    let gap = at - j.now;
                    j.step(Event::Advance(gap));
                }
                let s = j.step(ev);
                if *pruned {
                    continue;
                }
                if s.rule == Some(LocalRule::LateSecondDial)
                    && s.change == Some(Transition::Move)
                    && rec.change == s.change
                    && let Some(p) = j.peering.as_mut()
                    && p.fallback.is_some()
                {
                    p.fallback = None;
                    found.named.push((peer, Named::LateSecondDial));
                }
                if rec.change == Some(Transition::Move)
                    && s.change == rec.change
                    && let Some(p) = j.peering.as_mut()
                    && p.heard != rec.heard
                {
                    p.heard = rec.heard;
                    found.named.push((peer, Named::HeardAfterMove));
                }
                let model_refused = s.refused.map(Refusal::Gate);
                let named = match rec.refused {
                    Some(Refusal::Replay) => Some(Named::Replay),
                    Some(Refusal::Silent) => Some(Named::Silent),
                    Some(Refusal::Gate(_) | Refusal::Full) | None => None,
                };
                if let Some(named) = named
                    && model_refused.is_none()
                {
                    found.named.push((peer, named));
                    *pruned = true;
                    continue;
                }
                let refusal_differs = !fault!(ClassifiedNoRefusal) && rec.refused != model_refused;
                if matches!(ev, Event::Msg1 { .. }) && (s.class != rec.class || refusal_differs) {
                    found.diffs.push(Diff {
                        classified: true,
                        peer,
                        what: format!(
                            "{ev:?}: class {:?} refused {:?}, the model's {:?} refused {:?}",
                            rec.class, rec.refused, s.class, s.refused
                        ),
                    });
                    *pruned = true;
                } else if s.change != rec.change {
                    found.diffs.push(Diff {
                        classified: false,
                        peer,
                        what: format!(
                            "{ev:?}: change {:?}, the model's {:?}",
                            rec.change, s.change
                        ),
                    });
                    *pruned = true;
                }
            }
        }
    }
    found
}

/// The close a node that keeps no fallback makes at a late second dial's
/// move, computed on the model's judge after that move: the moved-off
/// link's setup address, if its binding holds a connection, no other link
/// the judge still needs uses it, and it is not already closed (the close
/// rule, FRC-1201 Section 5.6).
pub fn resync_close(j: &Judge) -> Vec<Addr> {
    let Some(f) = j.peering.as_ref().and_then(|p| p.fallback) else {
        return Vec::new();
    };
    if fault!(ResyncKeepsAll) {
        return Vec::new();
    }
    let used = j
        .needs()
        .iter()
        .any(|(l, at)| *l != f.link && *at == f.setup);
    if f.binding == Binding::Connected && !used && !j.closed.contains(&f.setup) {
        alloc::vec![f.setup]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod checks {
    use super::super::super::model::history::{Epoch, Hs, LinkId};
    use super::*;

    fn at(port: u16) -> Addr {
        Addr {
            transport: 1,
            at: port,
        }
    }

    #[test]
    fn the_late_dial_resync_closes_what_the_model_closes_when_its_fallback_is_dropped() {
        // The model's own history of a late second dial whose new session
        // the peer's first frame keeps (`model/tests/crossing.rs`, the
        // test of the frame that drops the old session): the close the
        // resync computes at the move is the close the model makes when
        // it drops the fallback itself.
        let (large, small, e1) = (Node(2), Node(1), Epoch(1));
        let mut j = Judge::new(large, small, Params::default());
        j.run(&[
            Event::Dial {
                hs: Hs(1),
                link: LinkId(1),
                to: at(1),
                binding: Binding::Connected,
            },
            Event::Msg2 {
                hs: Hs(1),
                epoch: e1,
                from: at(1),
            },
            Event::Advance(2_000),
            Event::Dial {
                hs: Hs(2),
                link: LinkId(2),
                to: at(5),
                binding: Binding::Connected,
            },
        ]);
        let moved = j.step(Event::Msg2 {
            hs: Hs(2),
            epoch: e1,
            from: at(5),
        });
        assert_eq!(
            (moved.rule, moved.change),
            (Some(LocalRule::LateSecondDial), Some(Transition::Move)),
            "precondition: the late second dial moved"
        );
        assert!(
            moved.closes.is_empty(),
            "precondition: the model closed nothing at the move"
        );
        let computed = resync_close(&j);
        let kept = j.step(Event::Frame {
            hs: Hs(2),
            from: at(5),
        });
        assert!(
            !kept.closes.is_empty(),
            "precondition: the model closes at the frame"
        );
        assert_eq!(
            computed, kept.closes,
            "the resync closes what the model closes"
        );
    }
}
