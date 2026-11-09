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
//!   expected to make by the close rule. A node whose log opens with
//!   [`Entry::Fallback`] keeps the session as the model does (the
//!   dialer's candidate rule), and is compared with no resync there.
//! - **Replay memory**: the node refuses a msg1 the model accepts. The
//!   comparison of that peer is pruned there.
//! - **Silent sessions**: the node's back-off for a peer whose sessions
//!   end without a frame refuses a msg1 the model accepts, pruned the same
//!   way. The model of `master` does not transcribe it; the core does.
//! - **A refused ephemeral recorded**: the rekey machine records every
//!   fresh ephemeral it refuses or discards, where the model records only
//!   the ones it answers or refuses as a replacement, so a later copy the
//!   machine names a copy or recorded, and leaves silent, the model names
//!   otherwise. Where the model stays silent too the comparison goes on;
//!   where it answers (a copy of the larger node's rekey msg1 that the
//!   smaller node discarded, taken as a replacement once its own rekey has
//!   cut over) the comparison of that peer is pruned.
//! - **A cutover at the peer's frame**: the rekey machine cuts its own
//!   answered rekey over at the peer's first frame under it, where the
//!   model waits for its check. The shadow cuts over at that frame.
//! - **A msg1 on a proven path**: the core and the node take a msg1 from
//!   any pair the link's bundle holds Live or acked as on the link, where
//!   the model, which has no paths, holds only the peer's current and
//!   setup pairs on the setup transport. Where the model refuses such a
//!   msg1 as off the link and the party logged it from a proven pair, the
//!   shadow steps the model again with the msg1 from the setup pair, which
//!   is its answer on the link, since rule 4.1 refuses before writing
//!   anything. Rules 1 to 3 read no pair, so a restart or replacement on a
//!   proven pair is compared as it arrived.
//! - Where the node's replay memory or silent-session back-off refuses a
//!   msg1 the model refuses too, the node asked those first; both refuse,
//!   and the comparison goes on.
//! - **The derived index** is the core's own and has no shadow step.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use super::super::model::history::{Addr, Binding, Event, Ms, Node};
use super::super::model::judge::{Class, Gate, Judge, LocalRule, Params, Reply, Transition};

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
    /// A msg1 came from a pair the party's path bundle holds Live or
    /// acked; false for a party with no bundle.
    pub proven: bool,
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
    /// The node keeps the session a late second dial moved off, as the
    /// model keeps its fallback (the dialer's candidate rule), so the
    /// late second dial is no named difference for it.
    Fallback,
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
    /// The rekey side named a silent msg1 a copy or recorded, since it
    /// recorded the ephemeral when it refused it.
    RecordedRefusal,
    /// The rekey side cut its own rekey over at the peer's frame.
    FrameCutover,
    /// The larger node's own rekey ended when it answered the smaller
    /// node's at a simultaneous rekey, which the model leaves open.
    Yielded,
    /// This node's own rekey ended with the peering it rekeyed, at its
    /// removal or replacement, where the model keeps it for the next.
    RekeyWithPeering,
    /// A frame under the session a rekey cut over from, still held for its
    /// drain, counted as heard, as the node touches the peer at a frame of
    /// either slot (`src/node/dataplane/encrypted.rs:263-280` at
    /// `2ba790b2`); the model ignores it.
    HeardByPrevious,
    /// A msg1 from a pair the bundle holds proven, which the core and the
    /// node take as on the link and the model, having no paths, reads as
    /// off it.
    ProvenPath,
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
    let mut fallback = false;
    for e in log {
        match *e {
            Entry::Fallback => fallback = true,
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
                let pending = j
                    .peering
                    .as_ref()
                    .and_then(|p| p.pending)
                    .filter(|pd| pd.initiator);
                let previous = match ev {
                    Event::Frame { hs, .. } => j.peering.as_ref().is_some_and(|p| {
                        p.hs != hs
                            && p.pending.is_none_or(|pd| pd.hs != hs)
                            && p.fallback.is_none_or(|f| f.hs != hs)
                    }),
                    Event::Advance(_)
                    | Event::Dial { .. }
                    | Event::Msg1 { .. }
                    | Event::Msg2Sent { .. }
                    | Event::Msg2 { .. }
                    | Event::Timeout { .. }
                    | Event::RekeyStart { .. }
                    | Event::RekeyMsg2 { .. }
                    | Event::RekeyCutover
                    | Event::Close { .. }
                    | Event::Lost
                    | Event::Restart => false,
                };
                let mut s = j.step(ev);
                if *pruned {
                    continue;
                }
                if let Event::Msg1 {
                    hs,
                    bytes,
                    epoch,
                    link,
                    binding,
                    sent,
                    ..
                } = ev
                    && s.class == Some(Class::OffLink)
                    && rec.proven
                    && !fault!(ProvenCompared)
                    && let Some(setup) = j.peering.as_ref().map(|p| p.setup)
                {
                    // Rule 4.1 refused before writing anything, so the
                    // model's answer on the link is the same msg1 from the
                    // peering's setup pair.
                    s = j.step(Event::Msg1 {
                        hs,
                        bytes,
                        epoch,
                        link,
                        from: setup,
                        binding,
                        sent,
                    });
                    found.named.push((peer, Named::ProvenPath));
                }
                if previous
                    && !fault!(PreviousUnheard)
                    && let Some(p) = j.peering.as_mut()
                {
                    // Only a frame the node could open reaches the log, so
                    // this is the drained session.
                    p.heard = true;
                    p.last = Some(j.now);
                    found.named.push((peer, Named::HeardByPrevious));
                }
                if let Event::Frame { hs, .. } = ev
                    && matches!(
                        rec.change,
                        Some(Transition::RekeyCutover | Transition::Restarted)
                    )
                    && s.change.is_none()
                    && pending.is_some_and(|pd| pd.hs == hs)
                    && !fault!(FrameCutoverMissed)
                {
                    // Cut over, then take the frame under the session it
                    // is now on, as the node does.
                    s = j.step(Event::RekeyCutover);
                    j.step(ev);
                    found.named.push((peer, Named::FrameCutover));
                }
                if matches!(s.change, Some(Transition::Remove | Transition::Replace))
                    && rec.change == s.change
                    && j.rekey.is_some()
                    && !fault!(RekeyOutlivesPeer)
                {
                    // The rekey machine is the peering's and is dropped
                    // with it; the model's own rekey is the judge's.
                    j.rekey = None;
                    found.named.push((peer, Named::RekeyWithPeering));
                }
                if matches!(ev, Event::Msg1 { .. })
                    && s.class == Some(Class::Simultaneous)
                    && rec.class == s.class
                    && me > peer
                    && j.rekey.is_some()
                    && !fault!(YieldKept)
                {
                    // The rekey machine yields the larger node's own
                    // attempt when it answers the smaller node's; the
                    // model leaves whether it goes on open.
                    j.rekey = None;
                    found.named.push((peer, Named::Yielded));
                }
                if matches!(ev, Event::Msg1 { .. })
                    && matches!(rec.class, Some(Class::Copy | Class::Recorded))
                    && rec.refused.is_none()
                    && rec.change.is_none()
                    && s.class != rec.class
                    && !fault!(RecordedCompared)
                {
                    // Both silent, the comparison goes on; where the model
                    // answered or replaced instead, the two hold different
                    // state from here.
                    found.named.push((peer, Named::RecordedRefusal));
                    if s.reply != Some(Reply::Silent) || s.change.is_some() {
                        *pruned = true;
                    }
                    continue;
                }
                if !fallback
                    && s.rule == Some(LocalRule::LateSecondDial)
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
                if let Some(named) = named {
                    found.named.push((peer, named));
                    if model_refused.is_none() {
                        *pruned = true;
                    }
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
    use super::super::super::model::history::{Bytes, Epoch, Hs, LinkId};
    use super::*;

    /// A log of node 1's: node 2 held from its msg1 at `at(1)`, then at
    /// 40 s, past both floors, a msg1 of node 2's from `from` with epoch
    /// `epoch`, which the party logged as `class` with `change`, from a
    /// pair its bundle holds proven or not.
    fn proven_log(
        from: Addr,
        epoch: Epoch,
        class: Class,
        proven: bool,
        change: Option<Transition>,
    ) -> Vec<Entry> {
        let peer = Node(2);
        let msg1 = |hs: u32, epoch: Epoch, from: Addr| Event::Msg1 {
            hs: Hs(hs),
            bytes: Bytes(hs),
            epoch,
            link: LinkId(hs),
            from,
            binding: Binding::Connectionless,
            sent: true,
        };
        alloc::vec![
            Entry::Ev {
                at: 0,
                peer,
                ev: msg1(1, Epoch(1), at(1)),
                rec: Rec {
                    class: Some(Class::NotHeld),
                    change: Some(Transition::Promote),
                    ..Rec::default()
                },
            },
            Entry::Ev {
                at: 40_000,
                peer,
                ev: msg1(2, epoch, from),
                rec: Rec {
                    class: Some(class),
                    change,
                    proven,
                    ..Rec::default()
                },
            },
        ]
    }

    #[test]
    fn a_msg1_on_a_proven_pair_is_compared_as_on_the_link_and_a_refusal_there_still_reds() {
        let second = at(7);
        let other = Addr {
            transport: 2,
            at: 7,
        };
        let restart = Some(Transition::Replace);
        // Each log, whether the comparison must find a difference, and
        // whether it must name the proven path.
        let cases = [
            (
                "a rekey on a proven second address",
                proven_log(second, Epoch(1), Class::Rekey, true, None),
                false,
                true,
            ),
            (
                "a rekey on a proven second transport",
                proven_log(other, Epoch(1), Class::Rekey, true, None),
                false,
                true,
            ),
            (
                "a rekey on a pair not proven",
                proven_log(second, Epoch(1), Class::Rekey, false, None),
                true,
                false,
            ),
            (
                "a refusal as off the link on a proven pair",
                proven_log(second, Epoch(1), Class::OffLink, true, None),
                true,
                true,
            ),
            (
                "a refusal as off the link on a pair not proven",
                proven_log(second, Epoch(1), Class::OffLink, false, None),
                false,
                false,
            ),
            (
                "a restart on a proven pair",
                proven_log(second, Epoch(9), Class::Restart, true, restart),
                false,
                false,
            ),
        ];
        for (name, log, differs, named) in cases {
            let found = compare(Node(1), &log);
            assert_eq!(
                found.diffs.is_empty(),
                !differs,
                "{name}: difference expected {differs}: {:?}",
                found.diffs
            );
            assert_eq!(
                found.named.contains(&(Node(2), Named::ProvenPath)),
                named,
                "{name}: the proven path named {named}: {:?}",
                found.named
            );
        }
    }

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
