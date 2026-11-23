//! The settlement core's link records, the transport-address index
//! derived from them, and the one close rule.
//!
//! A link record names the address the link was set up at (the address
//! dialed, or the msg1's source), its direction, who holds it (a
//! handshake leg still in flight, or a peer), the paths its bundle holds
//! with each path's proven state, and whether the bundle found the peer
//! capable of multipath. The index from transport and
//! address to link is never written directly: every method that changes a
//! record recomputes it, from each live link's setup address and its
//! proven paths, so it cannot drift from the records. A setup address
//! whose path the bundle released leaves the index; one the path roamed
//! away from stays, since the link was set up there. Under the test
//! hooks a shell may also name a link at a pair past its record, for the
//! index entries a test wrote past the shell's writers.
//!
//! Where a msg1 from a pair stands among the records ([`Placement`]) is
//! read in one walk, and answers each question the node asks of a msg1's
//! source before any Diffie-Hellman: whether a link owns the pair, which
//! identity the msg1 is to prove, whether it is a resend to an answered
//! msg1's leg, and whether it is on a held peer's link.
//!
//! The close rule (FRC-1201 Section 5.6, and the multipath draft's release
//! rule): a connection at a transport and address is in use while some
//! live link other than the one being retired uses it, as its setup
//! address while its handshake is in flight or before it has a bundle, or
//! as one of its bundle's paths that is live or acknowledged. Retiring a
//! link, or releasing one of its paths, closes each of its addresses that
//! is not in use, unless the release says the peer may still send there.
//! A close on a connectionless transport is the shell's to ignore.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::cmp::Ordering;

use super::input::Input;
use crate::identity::NodeAddr;
use crate::transport::{TransportAddr, TransportId};

/// A transport and an address on it.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Pair {
    /// The transport.
    pub transport: TransportId,
    /// The address on it.
    pub addr: TransportAddr,
}

impl Ord for Pair {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.transport.as_u32(), self.addr.as_bytes())
            .cmp(&(other.transport.as_u32(), other.addr.as_bytes()))
    }
}

impl PartialOrd for Pair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A link's number in the core.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LinkNo(pub u64);

/// Which end set the link up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    /// The peer dialed.
    Inbound,
    /// This node dialed.
    Outbound,
}

/// Who holds a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holder {
    /// A handshake leg still in flight.
    Leg,
    /// A held peer.
    Peer(NodeAddr),
}

/// A path's state, as the link's bundle reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proven {
    /// Live.
    Live,
    /// Acknowledged by the peer.
    Acked,
    /// Still probing; it keeps no connection open.
    Probing,
}

impl Proven {
    /// Whether the path counts as in use.
    pub fn counts(self) -> bool {
        match self {
            Self::Live | Self::Acked => true,
            Self::Probing => fault!(ProbingCounts),
        }
    }
}

/// One link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRec {
    /// The address the link was set up at.
    pub setup: Pair,
    /// Which end set it up.
    pub dir: Dir,
    /// Who holds it.
    pub holder: Holder,
    /// The paths its bundle holds, with their states.
    pub paths: Vec<(Pair, Proven)>,
    /// Whether the bundle released its path at the setup address, which
    /// then leaves the index.
    pub released: bool,
    /// Whether the bundle found the peer capable of multipath. A capable
    /// peer's msg1 from a pair the bundle holds no path at is off the link
    /// (multipath draft Section 5.10).
    pub capable: bool,
}

impl LinkRec {
    /// Whether this link uses the connection at `pair`.
    fn uses(&self, pair: &Pair) -> bool {
        let setup = self.setup == *pair && (self.paths.is_empty() || self.holder == Holder::Leg);
        let path = !fault!(CloseBySetupAddress) && self.proven(pair);
        setup || path
    }

    /// Whether this link holds a path at `pair` that counts as in use.
    fn proven(&self, pair: &Pair) -> bool {
        self.paths.iter().any(|(p, s)| p == pair && s.counts())
    }
}

/// The link the index names at a pair, as [`Placement`] keeps it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Named {
    link: LinkNo,
    dir: Dir,
    holder: Holder,
    capable: bool,
    /// The identity the leg holding the link expects, if a leg holds it.
    expects: Option<NodeAddr>,
}

/// Where a msg1 from one pair stands among the link records, from one walk
/// over them ([`Links::placement`]). Each method answers one of the
/// questions the node asks of a msg1's source before any Diffie-Hellman, as
/// the node answers it: the index there names the newest link it names at
/// the pair, and a path counts when it is Live or acknowledged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    /// The link the index names at the pair.
    named: Option<Named>,
    /// Each link holding a path at the pair: its number, its holder, and
    /// whether the path counts.
    paths: Vec<(LinkNo, Holder, bool)>,
    /// The links set up at the pair.
    setups: Vec<LinkNo>,
}

impl Placement {
    /// Whether some link owns the pair, the msg1 rate limiter's class and
    /// the pre-handshake admission of a transport that accepts no new
    /// handshakes: the index names a link there, or a held peer's path
    /// there counts.
    pub fn established(&self) -> bool {
        self.named.is_some()
            || self
                .paths
                .iter()
                .any(|(_, h, counts)| *counts && matches!(h, Holder::Peer(_)))
    }

    /// The identity a msg1 from the pair is to prove, where a transport
    /// that accepts no new handshakes admitted it: the peer holding the
    /// link the index names there, or the identity the leg holding it
    /// expects; failing both, a held peer whose path there counts.
    pub fn expected(&self) -> Option<NodeAddr> {
        let named = self.named.and_then(|n| match n.holder {
            Holder::Peer(peer) => Some(peer),
            Holder::Leg => n.expects,
        });
        named.or_else(|| {
            self.paths.iter().find_map(|(_, h, counts)| match h {
                Holder::Peer(peer) if *counts => Some(*peer),
                Holder::Peer(_) | Holder::Leg => None,
            })
        })
    }

    /// The link of an answered msg1's leg the pair's msg1 is a resend to:
    /// the link the index names there, when a leg the peer dialled holds
    /// it.
    pub fn unanswered(&self) -> Option<LinkNo> {
        self.named
            .filter(|n| n.dir == Dir::Inbound && n.holder == Holder::Leg)
            .map(|n| n.link)
    }

    /// Whether a msg1 from the pair is on `link`, the link of a held peer:
    /// where the link holds a path at the pair, whether the path is Live or
    /// acknowledged; elsewhere, whether the peer is not capable and the
    /// index names the link there (multipath draft Section 5.10).
    pub fn on_link(&self, link: LinkNo) -> bool {
        if fault!(AttributeBySetupOnly) || node_fault!(AttributeBySetupOnly) {
            return self.setups.contains(&link);
        }
        if let Some((_, _, counts)) = self.paths.iter().find(|(l, _, _)| *l == link) {
            return *counts;
        }
        let ignored = fault!(CapableIgnored) || node_fault!(CapableIgnored);
        self.named
            .is_some_and(|n| n.link == link && (!n.capable || ignored))
    }
}

/// Every link record and the index derived from them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Links {
    recs: BTreeMap<LinkNo, LinkRec>,
    next: u64,
    index: BTreeSet<(Pair, LinkNo)>,
    /// Pairs a shell's test named a link at past its records
    /// ([`Links::name`]), which the index names it at while it lives.
    #[cfg(any(test, feature = "test-hooks"))]
    named: BTreeSet<(Pair, LinkNo)>,
}

impl Links {
    /// No links.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a link set up at `setup`, held by `holder`.
    pub fn open(&mut self, setup: Pair, dir: Dir, holder: Holder) -> LinkNo {
        let link = LinkNo(self.next);
        self.next += 1;
        self.recs.insert(
            link,
            LinkRec {
                setup,
                dir,
                holder,
                paths: Vec::new(),
                released: false,
                capable: false,
            },
        );
        self.reindex();
        link
    }

    /// The record of `link`.
    pub fn get(&self, link: LinkNo) -> Option<&LinkRec> {
        self.recs.get(&link)
    }

    /// `link` is now held by `holder`.
    pub fn hold(&mut self, link: LinkNo, holder: Holder) {
        if let Some(r) = self.recs.get_mut(&link) {
            r.holder = holder;
        }
        self.reindex();
    }

    /// `link`'s record says `dir` set it up. Whether that changed it.
    pub fn turn(&mut self, link: LinkNo, dir: Dir) -> bool {
        match self.recs.get_mut(&link) {
            Some(r) if r.dir != dir => {
                r.dir = dir;
                true
            }
            _ => false,
        }
    }

    /// `link`'s bundle holds a path at `pair` in state `state`, new or
    /// changed.
    pub fn path(&mut self, link: LinkNo, pair: Pair, state: Proven) {
        if let Some(r) = self.recs.get_mut(&link) {
            match r.paths.iter_mut().find(|(p, _)| *p == pair) {
                Some((_, s)) => *s = state,
                None => r.paths.push((pair, state)),
            }
        }
        self.reindex();
    }

    /// `link`'s bundle moved its path at `from` to `to`, keeping its
    /// state; a path it did not hold arrives live.
    pub fn moved(&mut self, link: LinkNo, from: &Pair, to: Pair) {
        if let Some(r) = self.recs.get_mut(&link) {
            match r.paths.iter_mut().find(|(p, _)| p == from) {
                Some((p, _)) => *p = to,
                None => r.paths.push((to, Proven::Live)),
            }
        }
        self.reindex();
    }

    /// `link`'s bundle found the peer capable.
    pub fn capable(&mut self, link: LinkNo) {
        if let Some(r) = self.recs.get_mut(&link) {
            r.capable = true;
        }
    }

    /// `link`'s bundle holds exactly `paths`, each in its state, and has
    /// found the peer capable exactly when `capable` says, whatever its
    /// record held: a shell's resync of a record whose bundle a test
    /// changed past the feed.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn resync(&mut self, link: LinkNo, paths: Vec<(Pair, Proven)>, capable: bool) {
        if let Some(r) = self.recs.get_mut(&link) {
            r.paths = paths;
            r.capable = capable;
        }
        self.reindex();
    }

    /// Name each link of `named` at its pair in the index, besides where
    /// its record names it, for as long as the link lives, in place of
    /// what an earlier call named: a shell's resync of the index entries a
    /// test wrote past its writers. A record holds what its bundle holds,
    /// so an entry at a pair the bundle holds no proven path at, which no
    /// record can give, is named this way and not as a path.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn name(&mut self, named: BTreeSet<(Pair, LinkNo)>) {
        if self.named != named {
            self.named = named;
            self.reindex();
        }
    }

    /// The pairs [`Links::name`] names links at.
    #[cfg(any(test, feature = "test-hooks"))]
    pub fn names(&self) -> &BTreeSet<(Pair, LinkNo)> {
        &self.named
    }

    /// Apply what a link's bundle reported, `input`, to the link's record:
    /// the one reading of a path's move, switch, state change and release,
    /// and of the peer turning capable, that the table and a shell's record
    /// share. A switch records the path in the state the bundle holds it,
    /// which for a handover to an acknowledged path that is not Live is
    /// acknowledged. Returns the connections a released path leaves to
    /// close; any other input changes nothing.
    pub fn mirror<X>(&mut self, input: &Input<X>) -> Vec<Pair> {
        match input {
            Input::Moved { link, from, to, .. } => self.moved(*link, from, to.clone()),
            Input::Switched { link, to, proven } => {
                let state = if fault!(SwitchWritesLive) || node_fault!(SwitchWritesLive) {
                    Proven::Live
                } else {
                    *proven
                };
                self.path(*link, to.clone(), state);
            }
            Input::State { link, pair, proven } => self.path(*link, pair.clone(), *proven),
            Input::Capable { link } => self.capable(*link),
            Input::Released { link, pair, keep } => return self.release(*link, pair, *keep),
            Input::Dial(_)
            | Input::Connecting { .. }
            | Input::Punched(_)
            | Input::ConnectFailed { .. }
            | Input::Arrived { .. }
            | Input::Msg1 { .. }
            | Input::Replace(_)
            | Input::Redial(_)
            | Input::LegHeard { .. }
            | Input::Hello(_)
            | Input::Abandon { .. }
            | Input::Msg2 { .. }
            | Input::Restarted { .. }
            | Input::PeerEpoch { .. }
            | Input::Ended { .. }
            | Input::Orphaned { .. }
            | Input::Heard { .. }
            | Input::Disconnect { .. }
            | Input::Dead { .. }
            | Input::Admin { .. }
            | Input::Adopted { .. }
            | Input::Sent { .. }
            | Input::SendFailed { .. }
            | Input::Unsendable { .. }
            | Input::Flow(_) => {}
            #[cfg(test)]
            Input::HeldFrame { .. } | Input::HoldLost { .. } => {}
        }
        Vec::new()
    }

    /// Where a msg1 from `pair` stands among the records, from one walk
    /// over them; `leg` gives the identity the leg holding a link expects.
    pub fn placement(&self, pair: &Pair, leg: impl Fn(LinkNo) -> Option<NodeAddr>) -> Placement {
        let mut paths = Vec::new();
        let mut setups = Vec::new();
        for (l, r) in &self.recs {
            if r.setup == *pair {
                setups.push(*l);
            }
            if let Some((_, s)) = r.paths.iter().find(|(p, _)| p == pair) {
                paths.push((*l, r.holder, s.counts()));
            }
        }
        let named = self.at(pair).max().and_then(|link| {
            let r = self.recs.get(&link)?;
            Some(Named {
                link,
                dir: r.dir,
                holder: r.holder,
                capable: r.capable,
                expects: match r.holder {
                    Holder::Leg => leg(link),
                    Holder::Peer(_) => None,
                },
            })
        });
        Placement {
            named,
            paths,
            setups,
        }
    }

    /// The index: each live link's setup address and proven paths.
    pub fn index(&self) -> &BTreeSet<(Pair, LinkNo)> {
        &self.index
    }

    /// The links the index names at `pair`.
    pub fn at<'a>(&'a self, pair: &'a Pair) -> impl Iterator<Item = LinkNo> + 'a {
        self.index
            .iter()
            .filter(move |(p, _)| p == pair)
            .map(|(_, l)| *l)
    }

    /// The index recomputed from the records now: each live link's setup
    /// address, unless its bundle released the path there, and its proven
    /// paths.
    pub fn derived(&self) -> BTreeSet<(Pair, LinkNo)> {
        let keep = fault!(ReleasedSetupIndexed) || node_fault!(ReleasedSetupIndexed);
        let mut out = BTreeSet::new();
        for (l, r) in &self.recs {
            if !r.released || keep {
                out.insert((r.setup.clone(), *l));
            }
            for (p, s) in &r.paths {
                if s.counts() {
                    out.insert((p.clone(), *l));
                }
            }
        }
        #[cfg(any(test, feature = "test-hooks"))]
        out.extend(
            self.named
                .iter()
                .filter(|(_, l)| self.recs.contains_key(l))
                .cloned(),
        );
        out
    }

    fn reindex(&mut self) {
        self.index = self.derived();
    }

    /// Whether some live link other than `except` uses the connection at
    /// `pair`.
    pub fn in_use(&self, pair: &Pair, except: LinkNo) -> bool {
        self.recs
            .iter()
            .filter(|(l, _)| **l != except)
            .filter(|(_, r)| !fault!(CloseByPeerAddress) || matches!(r.holder, Holder::Peer(_)))
            .any(|(_, r)| match r.holder {
                // The node's breaks, in the shapes its own close rule took
                // them: a held link answered by its setup pair alone, and
                // only held links' paths counted, no leg's setup pair.
                Holder::Peer(_) if node_fault!(CloseBySetupAddress) => r.setup == *pair,
                Holder::Peer(_) if node_fault!(CloseByPeerAddress) => r.proven(pair),
                Holder::Leg if node_fault!(CloseByPeerAddress) => false,
                Holder::Peer(_) | Holder::Leg => r.uses(pair),
            })
    }

    /// Retire `link`: its record goes, and each of its addresses that no
    /// remaining link uses is returned to be closed.
    pub fn retire(&mut self, link: LinkNo) -> Vec<Pair> {
        let Some(r) = self.recs.remove(&link) else {
            return Vec::new();
        };
        if !fault!(IndexStale) {
            self.reindex();
        }
        let mut addrs: Vec<Pair> = Vec::new();
        for p in core::iter::once(r.setup).chain(r.paths.into_iter().map(|(p, _)| p)) {
            if !addrs.contains(&p) {
                addrs.push(p);
            }
        }
        addrs.retain(|p| !self.in_use(p, link));
        addrs
    }

    /// `link`'s bundle released its path at `pair`; `keep` says the peer
    /// may still send there. A released setup address leaves the index.
    /// Returns the address to close, if any.
    pub fn release(&mut self, link: LinkNo, pair: &Pair, keep: bool) -> Vec<Pair> {
        let Some(r) = self.recs.get_mut(&link) else {
            return Vec::new();
        };
        r.paths.retain(|(p, _)| p != pair);
        if r.setup == *pair {
            r.released = true;
        }
        let own = r.uses(pair);
        self.reindex();
        if (keep && !fault!(KeepIgnored)) || own || self.in_use(pair, link) {
            Vec::new()
        } else {
            alloc::vec![pair.clone()]
        }
    }
}

#[cfg(test)]
#[path = "tests/links.rs"]
mod tests;
