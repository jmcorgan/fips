//! The settlement core's table, stepped at the node's decision sites.
//!
//! Each decision site builds the core's input and hands it to
//! [`Node::decide`], which steps the node's one table (`Node.core`), run
//! with the XX handshake flow ([`Xx`]), and returns what the core decided
//! for the site to carry out, but the leases, which it carries out itself.
//! At a msg1, a dial, a connect, a dial's msg2 and an answer's msg3 the
//! site does what the core decided, as do a removal's reconnect and a
//! timer's retry of a dial it reaps; elsewhere the node still decides, and of what the core
//! decides carries out only what keeps the table's state the node's own. A link a step
//! opens is numbered for the node's link it was opened for (a dial's
//! `Opened`, an anonymous msg1's `Ask`), and each lease the core hands
//! back, a `Free`, an install's or a rekey's, goes back where the node
//! keeps it: onto the machine of the leg it came from, which carries it on
//! as it always has, or to the allocator when that machine is gone. A handshake's lease is thus the core's from
//! the dial or the answer until the core lets the leg go. The link table's
//! index is rebuilt after every step, since a step changes the records it
//! is a cache of.
//!
//! In a test build a resync ([`Replant`]) writes into the table what a
//! test built past the node's decision sites: each link and peer it
//! planted, and the handshake of each machine it planted.

use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;

use crate::NodeAddr;
use crate::node::Node;
#[cfg(test)]
use crate::node::settle::links::current;
#[cfg(test)]
use crate::peer::ActivePeer;
use crate::peer::PeerInstant;
use crate::proto::fmp::RekeyClaim;
use crate::proto::fmp::flow::{AnonDial, Deny, In, Out, Xx};
use crate::proto::rekey::IndexLease;
use crate::proto::settle::flow::Outs;
use crate::proto::settle::gates::Source;
use crate::proto::settle::input::{Dial as Dialed, Input};
#[cfg(test)]
use crate::proto::settle::legs::Start;
#[cfg(test)]
use crate::proto::settle::links::Dir;
use crate::proto::settle::links::{LinkNo, Pair};
use crate::proto::settle::output::{Denial, Output, Transition, Why};
#[cfg(test)]
use crate::proto::settle::table::Held;
use crate::transport::{LinkId, TransportAddr, TransportId};

/// A held peer's facts as the node's record gave them: when it was last
/// heard, on the peer clock, and its epoch.
#[cfg(test)]
type Facts = (PeerInstant, Option<[u8; 8]>);

/// What the core decided of a removal it took: whether it asks for a
/// reconnect of the peer. The connections its retirement of the peer's link
/// closes are not carried out here: the node's release of the peer's paths
/// and the removal's cells close what next closes.
#[derive(Debug, Default)]
pub(in crate::node) struct Decided {
    /// Whether the core asked for a reconnect of the peer (`Retry`).
    pub(in crate::node) retry: bool,
}

/// What the core's outputs `out`, a removal's, decided for `peer`: whether
/// it asked for the peer's reconnect, or `None` when the core removed no
/// peer there.
fn decided(out: &[XxOut], peer: NodeAddr) -> Option<Decided> {
    out.iter()
        .any(|o| matches!(o, Output::Remove { peer: p, .. } if *p == peer))
        .then(|| Decided {
            retry: out
                .iter()
                .any(|o| matches!(o, Output::Retry { peer: p } if *p == peer)),
        })
}

/// The retry the core's sweep, whose outputs are `out`, asked for each
/// failed leg it reaped, by the node's link `links` names for the leg's
/// number: a sweep's `Retry` comes just before the `Retire` of its leg's
/// link.
fn swept(out: &[XxOut], links: &HashMap<LinkNo, LinkId>) -> HashMap<LinkId, Option<NodeAddr>> {
    let mut retry = None;
    let mut by = HashMap::new();
    for o in out {
        match o {
            Output::Retry { peer } => retry = Some(*peer),
            Output::Retire { link, .. } => {
                if let Some(id) = links.get(link) {
                    by.insert(*id, retry);
                }
                retry = None;
            }
            _ => retry = None,
        }
    }
    by
}

/// The settlement core's input, with the XX flow's own inputs.
pub(in crate::node) type XxInput = Input<In>;

/// One output of the node's table.
pub(in crate::node) type XxOut = Outs<PeerInstant, Xx>;

/// The link a step opened, from its outputs: a dial's or a connect's
/// `Opened`, or an anonymous msg1's `Ask`.
pub(in crate::node) fn opened(out: &[XxOut]) -> Option<LinkNo> {
    out.iter().find_map(|o| match o {
        Output::Opened { link } | Output::Flow(Out::Ask { link }) => Some(*link),
        _ => None,
    })
}

/// Whether the core refused the peer a step's outputs `out` were decided
/// for at the max-peers cap.
pub(in crate::node) fn capped(out: &[XxOut]) -> bool {
    out.iter().any(|o| {
        matches!(
            o,
            Output::Reject {
                why: Denial::Cap,
                ..
            }
        )
    })
}

/// Whether the core refused the peer a step's outputs `out` were decided
/// for because this node is a leaf already holding another peer.
pub(in crate::node) fn leafed(out: &[XxOut]) -> bool {
    out.iter().any(|o| {
        matches!(
            o,
            Output::Reject {
                why: Denial::Flow(Deny::Leaf),
                ..
            }
        )
    })
}

/// Whether the core withholds the msg3 of the dial whose msg2 it took, from
/// that step's outputs `out`: not when it asks for the msg3 (`Final`), and
/// so when it kept the held peer at once (next's own-dial keep). `None`
/// when it did neither: it numbers no such link, or took the msg2 for no
/// dial of its own.
pub(in crate::node) fn withholds(out: &[XxOut]) -> Option<bool> {
    if out
        .iter()
        .any(|o| matches!(o, Output::Flow(Out::Final { .. })))
    {
        return Some(false);
    }
    out.iter()
        .any(|o| {
            matches!(
                o,
                Output::Reset {
                    transition: Transition::Keep,
                    ..
                }
            )
        })
        .then_some(true)
}

/// What the node does at a dial's msg2, as the settlement core decided at the
/// msg2 and at its msg3's send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::node) enum Msg2Decision {
    /// Install the peer as new.
    Promote,
    /// Remove the held peer, which restarted, then install the peer.
    Restart,
    /// A crossing the dial wins: move the held peer onto it.
    Swap,
    /// A crossing the dial loses, or the own-dial keep: keep the held peer
    /// and end the dial.
    Keep,
}

/// What the node does at an answer's msg3, as the settlement core decided.
#[derive(Debug)]
pub(in crate::node) enum Msg3Decision {
    /// Install the peer as new.
    Promote,
    /// Remove `peer`, which restarted, then install the peer.
    Restart { peer: NodeAddr },
    /// A crossing: `wins` moves the held `peer` onto the answer, and
    /// otherwise the held peer is kept and the answer ends.
    Cross { peer: NodeAddr, wins: bool },
    /// The msg3 declares a rekey of the link held with `peer`: the answer's
    /// read goes to that link's rekey machine.
    Rekey { peer: NodeAddr },
    /// A repeated handshake: resend the held peer's stored msg2, if any.
    Repeat { msg2: Option<Vec<u8>> },
    /// The restart gate refused a new epoch.
    Dampened,
    /// The identity's recent sessions carried no frame and its back-off is
    /// running.
    Silent,
}

/// The decision at a dial's msg2, from `out`, the outputs of the core's
/// steps at the msg2 and at its msg3's send: an install's `Promote`, a
/// restart's `Replace`, a move, or a keep. A cap or leaf refusal is a
/// promote, or after a restart's removal a restart, which the node's
/// promotion then refuses. `None` when the core decided none of these.
pub(in crate::node) fn outbound(out: &[XxOut]) -> Option<Msg2Decision> {
    let restart = out.iter().any(|o| {
        matches!(
            o,
            Output::Remove {
                why: Why::OwnRestart | Why::Restart,
                ..
            }
        )
    });
    out.iter().find_map(|o| match o {
        Output::Reset { transition, .. } => match transition {
            Transition::Promote => Some(Msg2Decision::Promote),
            Transition::Replace => Some(Msg2Decision::Restart),
            Transition::Move => Some(Msg2Decision::Swap),
            Transition::Keep => Some(Msg2Decision::Keep),
            Transition::Restarted | Transition::Roam => None,
        },
        Output::Swapped { .. } => Some(Msg2Decision::Swap),
        Output::Reject {
            why: Denial::Cap | Denial::Flow(_),
            ..
        } => Some(if restart {
            Msg2Decision::Restart
        } else {
            Msg2Decision::Promote
        }),
        _ => None,
    })
}

/// The decision at an answer's msg3, from `out`, the outputs of the core's
/// step at the msg3, with `stored` the held peer's stored msg2 a repeat
/// resends and `claim` the msg3's rekey claim, made by `peer`: an install's
/// `Promote`, a restart's `Replace`, a move or a keep at a crossing, the
/// peer's rekey, a repeat, or a gate's refusal, the restart gate's or the
/// silent sessions'. A cap or leaf refusal is a promote, or after a
/// restart's removal a restart, which the node's promotion then refuses.
///
/// The core's rekey output carries the answer's lease, which the step has
/// already given back onto the answer's read, so what is left of it in
/// `out` is the answer's `Retire`: a retire under a matching claim, with
/// nothing else decided, is the peer's rekey. `None` when the core decided
/// none of these.
pub(in crate::node) fn inbound(
    out: &[XxOut],
    stored: Option<Vec<u8>>,
    claim: RekeyClaim,
    peer: NodeAddr,
) -> Option<Msg3Decision> {
    let restart = out.iter().any(|o| {
        matches!(
            o,
            Output::Remove {
                why: Why::Restart,
                ..
            }
        )
    });
    let decided = out.iter().find_map(|o| match o {
        Output::Reset { peer, transition } => match transition {
            Transition::Promote => Some(Msg3Decision::Promote),
            Transition::Replace => Some(Msg3Decision::Restart { peer: *peer }),
            Transition::Move => Some(Msg3Decision::Cross {
                peer: *peer,
                wins: true,
            }),
            Transition::Keep => Some(Msg3Decision::Cross {
                peer: *peer,
                wins: false,
            }),
            Transition::Restarted | Transition::Roam => None,
        },
        Output::Flow(Out::Repeat { .. }) => Some(Msg3Decision::Repeat {
            msg2: stored.clone(),
        }),
        Output::Reject {
            source: Some(source),
            why: Denial::Gate(_),
            ..
        } => match source {
            Source::Restart => Some(Msg3Decision::Dampened),
            Source::NotHeld => Some(Msg3Decision::Silent),
            _ => None,
        },
        Output::Reject {
            peer,
            why: Denial::Cap | Denial::Flow(_),
            ..
        } => Some(match peer {
            Some(peer) if restart => Msg3Decision::Restart { peer: *peer },
            _ => Msg3Decision::Promote,
        }),
        _ => None,
    });
    decided.or_else(|| {
        let retired = out.iter().any(|o| matches!(o, Output::Retire { .. }));
        (claim == RekeyClaim::Matches && retired).then_some(Msg3Decision::Rekey { peer })
    })
}

/// What the resync of a test's planted state keeps beside the node's
/// table (test builds only).
#[cfg(test)]
#[derive(Default)]
pub(in crate::node) struct Replant {
    /// The table has taken an input: until then it holds nothing and its
    /// timers have nothing to do.
    built: bool,
    /// The node's links a decision site named as the link its input opens:
    /// a handshake on such a link is the core's own, so the resync never
    /// takes it for one a test planted.
    fed: HashSet<LinkId>,
    /// Each identity the table ever held: a peer the node holds that the
    /// table held before and holds no longer was removed through the
    /// node's writers, not planted by a test.
    known: HashSet<NodeAddr>,
    /// Each peer the node held when the table last decided, with the
    /// instant it was last heard and its epoch then: a peer whose instant
    /// went back since, or whose epoch changed, had its facts set by a test
    /// past the node's writers, which only a test's writers do, and the
    /// resync takes them.
    facts: HashMap<NodeAddr, Facts>,
}

/// `at` stepped back by `back`, or `at` where the clock reaches back no
/// further.
#[cfg(test)]
fn earlier(at: PeerInstant, back: std::time::Duration) -> PeerInstant {
    fips_core::time::Instant::checked_sub(at, back).unwrap_or(at)
}

/// The core's pair for `addr` on `transport`.
pub(in crate::node) fn pair(transport: TransportId, addr: &TransportAddr) -> Pair {
    Pair {
        transport,
        addr: addr.clone(),
    }
}

/// The direction of `link`, in the core's words.
#[cfg(test)]
fn dir(link: &crate::transport::Link) -> Dir {
    match link.direction() {
        crate::transport::LinkDirection::Inbound => Dir::Inbound,
        crate::transport::LinkDirection::Outbound => Dir::Outbound,
    }
}

/// The core's record of `peer`, held on the core's link `link`, from the
/// peer's own facts: its epoch, the pair it is at, whether a frame of it
/// authenticated, and the instant of its last frame, which is its
/// promotion's until the first frame.
#[cfg(test)]
fn held(peer: &ActivePeer, link: LinkNo) -> Held<PeerInstant> {
    let framed = peer.heard();
    Held {
        link,
        epoch: peer.remote_epoch().unwrap_or_default(),
        current: current(peer),
        heard: framed,
        installed: peer.heard_at(),
        last: framed.then_some(peer.heard_at()),
        setup: None,
        sending: None,
    }
}

/// Quiet the leg of a dial on its link `link` in `core` once its msg2
/// completed the handshake: the leg sends no more resends and keeps its
/// lease until the core decides the msg2. The step changes only that leg's
/// resend schedule, and nothing of it is carried out. It takes the table
/// alone, because the msg2's site holds the dial's handshake entry.
pub(in crate::node) fn quiet(core: &mut super::Core, link: LinkNo) {
    let _ = core.step(Input::Flow(In::Quiet { link }), crate::peer::peer_now());
}

impl Node {
    /// Hand the core `input`, which a decision site built, now on the peer
    /// clock. Returns what the core decided that the site carries out: every
    /// output but the leases, which [`Node::stepped`] has already given back.
    pub(in crate::node) fn decide(&mut self, input: XxInput) -> Vec<XxOut> {
        self.decide_at(input, crate::peer::peer_now())
    }

    /// [`Node::decide`] at `ms` on the interval clock: for an input that
    /// opens a handshake leg the node stamped at `ms`, so the core's leg
    /// counts its deadline and resends from the instant the node's does.
    pub(in crate::node) fn decide_stamped(&mut self, input: XxInput, ms: u64) -> Vec<XxOut> {
        self.decide_at(input, crate::time::mono_at(ms))
    }

    /// [`Node::decide`] at `now`. The one caller, with [`Node::tend`],
    /// [`Node::core_pathed`] and [`quiet`], of the table's
    /// [`step`](crate::proto::settle::table::Table::step).
    #[inline(never)]
    pub(in crate::node) fn decide_at(&mut self, input: XxInput, now: PeerInstant) -> Vec<XxOut> {
        #[cfg(test)]
        {
            self.replanted.built = true;
            self.replant();
        }
        let leased = self.leased();
        let out = self.core.step(input, now);
        self.stepped(out, &leased, true)
    }

    /// Tell the core at `now` what the node's timer driver did with a leg
    /// the core's legs asked it to resend: sent, not sent, or quieted. It
    /// changes only that leg's resend schedule, so it is stepped as it is,
    /// with nothing to carry out.
    pub(in crate::node) fn tend(&mut self, input: XxInput, now: PeerInstant) {
        let leased = self.leased();
        let out = self.core.step(input, now);
        let _ = self.stepped(out, &leased, false);
    }

    /// The core's number for the leg holding each lease in flight, by the
    /// lease's index, read before a step, so a lease the step hands back is
    /// traced to its leg.
    fn leased(&self) -> HashMap<u32, LinkNo> {
        self.legs()
            .iter()
            .map(|leg| (leg.index(), leg.link()))
            .collect()
    }

    /// Carry out the leases of `out`, one step's outputs, `leased` naming
    /// each lease's leg before the step: each lease handed back goes to its
    /// leg's entry ([`Node::give_back`]). The link table's index is
    /// rebuilt when `rebuild` says so. Returns the rest of `out`, in order,
    /// for the decision site to carry out.
    fn stepped(
        &mut self,
        out: Vec<XxOut>,
        leased: &HashMap<u32, LinkNo>,
        rebuild: bool,
    ) -> Vec<XxOut> {
        let mut rest = Vec::new();
        for o in out {
            match o {
                Output::Free { lease } | Output::Flow(Out::Rekey { lease, .. }) => {
                    self.give_back(leased, lease);
                }
                Output::Install(install) => {
                    #[cfg(test)]
                    self.replanted.known.insert(install.peer);
                    self.give_back(leased, install.lease);
                }
                o @ (Output::Opened { .. }
                | Output::Ask { .. }
                | Output::Answer { .. }
                | Output::Resend { .. }
                | Output::Rekey { .. }
                | Output::Reset { .. }
                | Output::Remove { .. }
                | Output::Retire { .. }
                | Output::Release { .. }
                | Output::Close { .. }
                | Output::Swapped { .. }
                | Output::Turned { .. }
                | Output::Retry { .. }
                | Output::Reject { .. }
                | Output::Flow(
                    Out::Ask { .. } | Out::Final { .. } | Out::Repeat { .. } | Out::Offer { .. },
                )) => rest.push(o),
            }
        }
        if rebuild {
            self.links.stepped(self.core.parts_mut().0);
        }
        #[cfg(test)]
        self.replant_facts();
        rest
    }

    /// Give `lease`, which the core handed back, to the machine of the leg
    /// `leased` says held it, which takes it where its handshake carries it
    /// (`Handshake::give_lease`);
    /// a lease no machine takes goes back to the allocator.
    fn give_back(&mut self, leased: &HashMap<u32, LinkNo>, lease: IndexLease) {
        let id = leased
            .get(&lease.index())
            .and_then(|no| self.core_link(*no));
        let rest = match id.and_then(|id| self.handshakes.get_mut(&id)) {
            Some(machine) => machine.give_lease(lease),
            None => Some(lease),
        };
        if let Some(lease) = rest {
            self.free_lease(lease);
        }
    }

    /// Give `lease`'s index back to the allocator.
    pub(in crate::node) fn free_lease(&mut self, lease: IndexLease) {
        let _ = self
            .index_allocator
            .free(crate::utils::index::SessionIndex::new(lease.release()));
    }

    /// The core's number for the node's link `id`: the link table's, or in
    /// a test build the record the resync opened for a link a test put in
    /// the map past the writers.
    pub(in crate::node) fn core_no(&self, id: LinkId) -> Option<LinkNo> {
        self.links.core_no(&id)
    }

    /// The node's link the core numbers `no` ([`Node::core_no`]'s inverse).
    pub(in crate::node) fn core_link(&self, no: LinkNo) -> Option<LinkId> {
        self.links.id(no)
    }

    /// Tell the core a msg1 arrived from `addr` on `transport`, before any
    /// Noise read, and return what it decided: the stored msg2 of the
    /// answer's leg that answered these bytes (`Answer`), or the admission
    /// cap's refusal (`Reject`), or nothing, for a msg1 to read.
    #[inline(never)]
    pub(in crate::node) fn core_arrived(
        &mut self,
        transport: TransportId,
        addr: &TransportAddr,
        bytes: &[u8],
    ) -> Vec<XxOut> {
        self.decide(Input::Arrived {
            from: pair(transport, addr),
            bytes: bytes.to_vec(),
        })
    }

    /// Tell the core a msg1 from `addr` on `transport`, `bytes` whose Noise
    /// part is `noise`, was read for the node's new link `id` at `ms` on the
    /// interval clock; `rekey_of` is the established peer at its source.
    /// Returns the core's number for the link the msg1 opened, for the
    /// link table to number the link by once the node adds it.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    pub(in crate::node) fn core_anon(
        &mut self,
        id: LinkId,
        transport: TransportId,
        addr: &TransportAddr,
        bytes: &[u8],
        noise: &[u8],
        rekey_of: Option<NodeAddr>,
        ms: u64,
    ) -> Option<LinkNo> {
        let ephemeral = crate::proto::fmp::EphemeralDigest::of_noise_msg1(noise)?;
        let rekey_of = rekey_of
            .and_then(|peer| self.peers.get(&peer).map(crate::peer::ActivePeer::link_id))
            .and_then(|link| self.core_no(link));
        let anon = crate::proto::fmp::flow::Anon {
            from: pair(transport, addr),
            bytes: bytes.to_vec(),
            ephemeral,
            rekey_of,
        };
        #[cfg(test)]
        self.replanted.fed.insert(id);
        #[cfg(not(test))]
        let _ = id;
        opened(&self.decide_stamped(Input::Flow(In::Anon(anon)), ms))
    }

    /// Hand the core the msg2 `msg2` the node built, with the lease on its
    /// session index, for the msg1 that opened its link `id`, which arrived
    /// at `ms` on the interval clock: the answer's leg opens, holding the
    /// lease. Returns the msg2 the core's answer sends, or nothing when the
    /// core asked for no answer on the link, whose lease then goes back to
    /// the machine or the allocator.
    #[inline(never)]
    pub(in crate::node) fn core_hello(
        &mut self,
        id: LinkId,
        lease: IndexLease,
        msg2: &[u8],
        ms: u64,
    ) -> Option<Vec<u8>> {
        let Some(link) = self.core_no(id) else {
            self.unled(id, lease);
            return None;
        };
        let hello = In::Hello {
            link,
            msg2: msg2.to_vec(),
            lease,
        };
        self.decide_stamped(Input::Flow(hello), ms)
            .into_iter()
            .find_map(|o| match o {
                Output::Answer { link: l, msg2, .. } if l == link => Some(msg2),
                _ => None,
            })
    }

    /// Put `lease`, which no leg of the core's took, back on the machine of
    /// the node's link `id`, or the allocator.
    fn unled(&mut self, id: LinkId, lease: IndexLease) {
        let rest = match self.handshakes.get_mut(&id) {
            Some(machine) => machine.give_lease(lease),
            None => Some(lease),
        };
        if let Some(lease) = rest {
            self.free_lease(lease);
        }
    }

    /// Tell the core the msg2 the answer on the node's link `id` built went
    /// out (`true`), or could not be sent for a cause no resend outlasts.
    #[inline(never)]
    pub(in crate::node) fn core_sent(&mut self, id: LinkId, sent: bool) {
        self.core_input(id, |link| {
            if sent {
                Input::Sent { link }
            } else {
                Input::Unsendable { link }
            }
        });
    }

    /// Tell the core a frame of `peer` authenticated from `addr` on
    /// `transport`, carrying a link message of type `kind`.
    #[inline(never)]
    pub(in crate::node) fn core_heard(
        &mut self,
        peer: NodeAddr,
        transport: TransportId,
        addr: &TransportAddr,
        kind: u8,
    ) {
        if self.peers.contains_key(&peer) {
            let _ = self.decide(Input::Heard {
                peer,
                from: pair(transport, addr),
                kind,
            });
        }
    }

    /// Hand the core the XX flow's input for the node's link `id`, built by
    /// `make` from the core's number for it, and return what it decided.
    /// Nothing when the core does not number the link.
    #[inline(never)]
    pub(in crate::node) fn core_flow(
        &mut self,
        id: LinkId,
        make: impl FnOnce(LinkNo) -> In,
    ) -> Option<Vec<XxOut>> {
        self.core_input(id, |link| Input::Flow(make(link)))
    }

    /// Hand the core the input `make` builds from its number for the node's
    /// link `id`, and return what it decided. Nothing when the core does not
    /// number the link.
    fn core_input(
        &mut self,
        id: LinkId,
        make: impl FnOnce(LinkNo) -> XxInput,
    ) -> Option<Vec<XxOut>> {
        #[cfg(test)]
        self.replant();
        let link = self.core_no(id)?;
        Some(self.decide(make(link)))
    }

    /// The core's refusal of the anonymous msg1 that opened `link`, whose
    /// answer the node could not build: its link is retired, closing
    /// nothing.
    pub(in crate::node) fn core_unasked(&mut self, link: LinkNo) {
        let _ = self.decide(Input::Flow(In::Refused { link, retry: None }));
    }

    /// Tell the core the node dialed `to` on its link `id`, naming `peer`
    /// or no one, with the msg1 `msg1` under the session index `lease`
    /// holds, stamped at `ms` on the interval clock, its resends capped at
    /// `resends`: the dial's leg opens holding the lease, on the record the
    /// link table numbers the link by, which its connect or its open made.
    #[allow(clippy::too_many_arguments)]
    #[inline(never)]
    pub(in crate::node) fn core_dial(
        &mut self,
        id: LinkId,
        peer: Option<NodeAddr>,
        to: Pair,
        msg1: &[u8],
        lease: IndexLease,
        resends: u32,
        ms: u64,
    ) {
        let link = self.core_no(id);
        let msg1 = msg1.to_vec();
        let input = match peer {
            Some(peer) => Input::Dial(Dialed {
                peer,
                to,
                msg1,
                lease,
                resends: Some(resends),
                link,
            }),
            None => Input::Flow(In::AnonDial(AnonDial {
                to,
                msg1,
                lease,
                resends: Some(resends),
                link,
            })),
        };
        #[cfg(test)]
        self.replanted.fed.insert(id);
        let opened = opened(&self.decide_stamped(input, ms));
        debug_assert!(
            opened.is_none() || link.is_none(),
            "a dial on a numbered link opened another"
        );
    }

    /// Tell the core the node opens its link `id` to `to` for a dial naming
    /// `peer` or no one, whose connection it must open first. Returns the
    /// core's number for the link it opened, for the link table to number
    /// the link by.
    #[inline(never)]
    pub(in crate::node) fn core_connecting(
        &mut self,
        id: LinkId,
        peer: Option<NodeAddr>,
        to: Pair,
    ) -> Option<LinkNo> {
        let input = match peer {
            Some(peer) => Input::Connecting {
                peer,
                to,
                resends: None,
            },
            None => Input::Flow(In::AnonConnecting { to, resends: None }),
        };
        #[cfg(test)]
        self.replanted.fed.insert(id);
        #[cfg(not(test))]
        let _ = id;
        opened(&self.decide(input))
    }

    /// Tell the core the connection the dial on the node's link `id` waited
    /// on could not be opened, or the dial was given up before its msg1.
    /// Nothing when the core does not number the link.
    #[inline(never)]
    pub(in crate::node) fn core_connect_failed(&mut self, id: LinkId) {
        #[cfg(test)]
        self.replant();
        let Some(link) = self.core_no(id) else {
            return;
        };
        let anon = self.core.links().get(link).is_some()
            && self
                .core
                .legs()
                .get(link)
                .is_none_or(|l| l.peer().is_none());
        let _ = self.decide(if anon {
            Input::Flow(In::AnonConnectFailed { link })
        } else {
            Input::ConnectFailed { link }
        });
    }

    /// Tell the core the connection the identified dial on the node's link
    /// `id`, naming `peer`, waited on could not be opened, and return the
    /// peers whose reconnect the core asks for (`Retry`). A link the core
    /// does not number, which only a test opens past the dial, retries the
    /// peer it named.
    #[inline(never)]
    pub(in crate::node) fn core_unconnected(
        &mut self,
        id: LinkId,
        peer: NodeAddr,
    ) -> Vec<NodeAddr> {
        #[cfg(test)]
        self.replant();
        let Some(link) = self.core_no(id) else {
            return vec![peer];
        };
        let input = Input::Flow(In::Unconnected {
            link,
            retry: Some(peer),
        });
        self.decide(input)
            .into_iter()
            .filter_map(|o| match o {
                Output::Retry { peer } => Some(peer),
                _ => None,
            })
            .collect()
    }

    /// Run the core's timers at `ms` on the interval clock, where the
    /// node's run: where the node's stale sweep runs (`sweep`), the flow's
    /// sweep of its failed legs. Returns the retry the sweep asked for each
    /// failed leg it reaped, by the node's link, for the stale sweep to
    /// note. The table's poll is not run: a leg past its deadline is reaped
    /// where the node's own timer reaps its class of handshake
    /// ([`Node::core_timed`], [`Node::core_reap`]), so its record lives as
    /// long as the node's link.
    #[inline(never)]
    pub(in crate::node) fn core_tick(
        &mut self,
        ms: u64,
        sweep: bool,
    ) -> HashMap<LinkId, Option<NodeAddr>> {
        // A table that has taken no input holds nothing for its timers; a
        // test build's resync plants only a test's armed msg1 resends in it
        // before its first input.
        #[cfg(test)]
        if !self.replanted.built {
            self.replant_legs(true);
            return HashMap::new();
        }
        #[cfg(test)]
        self.replant();
        if !sweep {
            return HashMap::new();
        }
        let links: HashMap<LinkNo, LinkId> = self
            .legs()
            .iter()
            .filter_map(|leg| self.core_link(leg.link()).map(|id| (leg.link(), id)))
            .collect();
        let out = self.decide_at(Input::Flow(In::Sweep), crate::time::mono_at(ms));
        swept(&out, &links)
    }

    /// The retry the core asks for at the timer's reap of the dial on its
    /// link `no` alone, past its deadline or failed: the identity the dial
    /// expects by then, or none for an answer or a dial that learned no one.
    #[inline(never)]
    pub(in crate::node) fn core_timed(&mut self, no: LinkNo) -> Option<NodeAddr> {
        self.decide(Input::Flow(In::Timed { link: no }))
            .into_iter()
            .find_map(|o| match o {
                Output::Retry { peer } => Some(peer),
                _ => None,
            })
    }

    /// Tell the core the node removed `peer` for `why`, where the removal
    /// is an input of its own: a rekey teardown, an orphaned bundle, a
    /// `Disconnect`, a dead link or the operator. A restart is part of the
    /// msg2 or msg3 that caused it, which the core is fed instead.
    /// Returns what the core decided of the removal, for the removal's run
    /// to carry out, or `None` where the core held no peer there, or the
    /// removal is part of a msg2 or msg3.
    #[inline(never)]
    pub(in crate::node) fn core_remove(&mut self, peer: NodeAddr, why: Why) -> Option<Decided> {
        let input = match why {
            Why::Ended => Input::Ended { peer },
            Why::Orphaned => Input::Orphaned { peer },
            Why::Disconnect => Input::Disconnect { peer },
            Why::Dead => Input::Dead { peer },
            Why::Admin => Input::Admin { peer },
            Why::Restart | Why::Replacement | Why::Redial | Why::OwnRestart | Why::Closed => {
                return None;
            }
        };
        decided(&self.decide(input), peer)
    }

    /// Step the core with the path input `input` a link's bundle reported,
    /// so its record of the link and of the peer held on it follow; the
    /// link table's index is rebuilt but where the mutation lane's
    /// `IndexNotRebuilt` leaves it stale. Nothing for an input that is not
    /// a path input.
    #[inline(never)]
    pub(in crate::node) fn core_pathed(&mut self, input: &Input) {
        let input: XxInput = match input {
            Input::Moved {
                link,
                from,
                to,
                roam,
            } => Input::Moved {
                link: *link,
                from: from.clone(),
                to: to.clone(),
                roam: *roam,
            },
            Input::Switched { link, to, proven } => Input::Switched {
                link: *link,
                to: to.clone(),
                proven: *proven,
            },
            Input::Released { link, pair, keep } => Input::Released {
                link: *link,
                pair: pair.clone(),
                keep: *keep,
            },
            Input::Capable { link } => Input::Capable { link: *link },
            Input::State { link, pair, proven } => Input::State {
                link: *link,
                pair: pair.clone(),
                proven: *proven,
            },
            _ => return,
        };
        #[cfg(test)]
        {
            self.replanted.built = true;
            self.replant();
        }
        let leased = self.leased();
        let out = self.core.step(input, crate::peer::peer_now());
        let _ = self.stepped(out, &leased, !node_fault!(IndexNotRebuilt));
    }

    /// The core's reap of the leg on its link `link` alone at `now`, if it
    /// is past its deadline then: its lease goes back to its machine.
    pub(in crate::node) fn core_reap(&mut self, link: LinkNo, now: PeerInstant) {
        let leased = self.leased();
        let out = self.core.reap_leg(link, now);
        let _ = self.stepped(out, &leased, true);
    }

    /// Tell the core the node gave up the leg on its link `id` for a cause
    /// the core has no input for, the link's record left for the node to
    /// retire with the link: the lease goes back to the leg's entry, or
    /// the allocator.
    pub(in crate::node) fn core_drop_leg(&mut self, id: LinkId) {
        let Some(no) = self.core_no(id) else {
            return;
        };
        if let Some(lease) = self.core.drop_leg(no) {
            self.unled(id, lease);
        }
    }
}

#[cfg(test)]
impl Node {
    /// Note each held peer's facts as the node's record gives them now,
    /// after a decision, for the resync to tell a test's later write past
    /// the writers from the node's own.
    fn replant_facts(&mut self) {
        self.replanted.facts = self
            .peers
            .iter()
            .map(|(addr, p)| (*addr, (p.heard_at(), p.remote_epoch())))
            .collect();
    }

    /// Write into the table what a test built past the node's decision
    /// sites, before the core next decides: a record, held as a leg at its
    /// setup pair, for each link a test put in the node's map that the link
    /// table does not number (`LinkTable::plant_spare`); each held peer the
    /// table never held, from the peer's facts ([`held`]); the facts a test
    /// set on a held peer since; and a leg for each handshake a test
    /// planted on a link the core numbers and holds neither a leg nor a
    /// peer on, holding the lease its machine held, reaped when its
    /// carrier's idle timeout says, and resending only where the test armed
    /// a msg1 resend timer. A link a decision site named as the one its
    /// input opens is never taken: what the core made of it is the
    /// comparison's to read. On a node a test planted past its writers, a
    /// held peer on a link the node's map lacks is held on a record of its
    /// own, set up at the pair the peer is at, that no link of the node's
    /// is numbered for.
    pub(in crate::node) fn replant(&mut self) {
        let opened: Vec<(LinkId, Pair, Dir)> = self
            .links
            .iter()
            .filter(|(id, _)| self.links.no(id).is_none() && !self.replanted.fed.contains(*id))
            .map(|(id, link)| {
                (
                    *id,
                    pair(link.transport_id(), link.remote_addr()),
                    dir(link),
                )
            })
            .collect();
        for (id, at, d) in opened {
            self.links.plant_spare(self.core.parts_mut().0, id, at, d);
        }
        // A peer a test planted on a link the node's map lacks is held on a
        // record of its own, set up at the pair the peer is at, that no link
        // of the node's is numbered for: the link id it names is no link of
        // the node's, and may be the one a later link takes.
        let planted = self.planted();
        let peers: Vec<(NodeAddr, Option<LinkNo>, Pair)> = self
            .peers
            .iter()
            .filter(|(addr, _)| !self.replanted.known.contains(*addr))
            .filter_map(|(addr, peer)| {
                let no = self.core_no(peer.link_id());
                let unlinked = planted && !self.links.contains_key(&peer.link_id());
                (no.is_some() || unlinked).then(|| (*addr, no, current(peer)))
            })
            .collect();
        for (addr, no, at) in peers {
            let no = no.unwrap_or_else(|| self.core.open_link(at, Dir::Inbound));
            let Some(h) = self.peers.get(&addr).map(|peer| held(peer, no)) else {
                continue;
            };
            self.replanted.known.insert(addr);
            self.core.plant(addr, h);
        }
        self.replant_refacts();
        self.replant_legs(false);
    }

    /// The resync's legs: for each handshake a test planted, a leg holding
    /// its entry's lease ([`Node::replant`]); with `timers` alone,
    /// only for each dial a test armed a msg1 resend timer for, on a link
    /// the core numbers or one a test put in the map, as before the table's
    /// first input, whose timers drive nothing else.
    fn replant_legs(&mut self, timers: bool) {
        use crate::peer::handshake::TimerKind;
        let max = self.config().node.rate_limit.handshake_max_resends;
        let params = super::params::xx_params(&self.config().node);
        if timers {
            let opened: Vec<(LinkId, Pair, Dir)> = self
                .handshakes
                .timers()
                .iter()
                .filter(|(_, t)| t.contains_key(&TimerKind::HandshakeRetransmit))
                .filter_map(|(id, _)| {
                    let link = self.links.get(id)?;
                    let none = self.core_no(*id).is_none() && !self.replanted.fed.contains(id);
                    none.then(|| {
                        (
                            *id,
                            pair(link.transport_id(), link.remote_addr()),
                            dir(link),
                        )
                    })
                })
                .collect();
            for (id, at, d) in opened {
                self.links.plant_spare(self.core.parts_mut().0, id, at, d);
            }
        }
        let armed = |node: &Node, id: &LinkId| {
            node.handshakes
                .timers()
                .get(id)
                .is_some_and(|t| t.contains_key(&TimerKind::HandshakeRetransmit))
        };
        let planted: Vec<LinkId> = self
            .handshakes
            .iter()
            .filter(|(id, m)| m.leg().is_some() && !self.replanted.fed.contains(*id))
            .filter(|(id, _)| !timers || armed(self, id))
            .filter(|(id, _)| {
                self.core_no(**id).is_some_and(|no| {
                    self.core.legs().get(no).is_none()
                        && !self
                            .core
                            .held_peers()
                            .any(|p| self.core.held(p).is_some_and(|h| h.link == no))
                })
            })
            .map(|(id, _)| *id)
            .collect();
        for id in planted {
            let Some(no) = self.core_no(id) else {
                continue;
            };
            let timer = self
                .handshakes
                .timers()
                .get(&id)
                .and_then(|t| t.get(&TimerKind::HandshakeRetransmit))
                .copied();
            let Some(machine) = self.handshakes.get_mut(&id) else {
                continue;
            };
            let outbound = machine.conn_is_outbound();
            // A planted answer with no msg2 is left to its carrier: a leg
            // would answer a duplicate msg1 with an empty one.
            let msg2 = machine.conn_handshake_msg2().map(<[u8]>::to_vec);
            if !outbound && msg2.is_none() {
                continue;
            }
            let msg1 = machine
                .conn_handshake_msg1()
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            let Some(lease) = machine.take_our_index() else {
                continue;
            };
            let start = Start {
                link: no,
                peer: machine.conn_expected_identity().map(|i| *i.node_addr()),
                msg1,
                lease,
                resends: outbound.then(|| machine.dial_origin().resend_limit(max)),
                held: None,
            };
            let active = crate::time::mono_at(machine.conn_active_at());
            let deadline =
                fips_core::time::Instant::checked_add(active, params.handshake).unwrap_or(active);
            let msg2 = (!outbound).then(|| msg2.unwrap_or_default());
            if let Some(old) = self.core.plant_leg(start, msg2, active) {
                self.free_lease(old);
            }
            let next = timer.map(crate::time::mono_at);
            self.core.replant_leg(no, deadline, next);
            if timer.is_some() {
                self.handshakes.cancel(id, TimerKind::HandshakeRetransmit);
            }
        }
    }

    /// Write into the table the facts a test set on a held peer past the
    /// node's writers since the core last decided: an instant last heard
    /// stepped back (`ActivePeer::test_backdate_heard`), which steps the
    /// core's instants of the peer back as far, and an epoch changed
    /// (`ActivePeer::set_remote_epoch`), which the core takes. Both writers
    /// are test-only: the node's own record only moves the instant forward,
    /// at a frame or a promotion, and sets the epoch at the promotion, which
    /// the core decides itself.
    fn replant_refacts(&mut self) {
        let mut changed = Vec::new();
        for (addr, peer) in &self.peers {
            let Some((at, epoch)) = self.replanted.facts.get(addr).copied() else {
                continue;
            };
            let Some(mut h) = self.core.held(addr).cloned() else {
                continue;
            };
            let back = fips_core::time::Instant::saturating_duration_since(at, peer.heard_at());
            let now = peer.remote_epoch();
            if back.is_zero() && now == epoch {
                continue;
            }
            h.installed = earlier(h.installed, back);
            h.last = h.last.map(|i| earlier(i, back));
            if now != epoch {
                h.epoch = now.unwrap_or_default();
            }
            changed.push((*addr, h));
        }
        for (addr, h) in changed {
            self.core.plant(addr, h);
        }
        self.replant_facts();
    }
}

#[cfg(test)]
#[path = "tests/decide.rs"]
mod tests;
