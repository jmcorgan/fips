//! The settlement core's link records, the transport-address index
//! derived from them, and the one close rule.
//!
//! A link record names the address the link was set up at (the address
//! dialed, or the msg1's source), its direction, who holds it (a
//! handshake leg still in flight, or a peer), and the paths its bundle
//! holds with each path's proven state. The index from transport and
//! address to link is never written directly: every method that changes a
//! record recomputes it, from each live link's setup address and its
//! proven paths, so it cannot drift from the records.
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
}

impl LinkRec {
    /// Whether this link uses the connection at `pair`.
    fn uses(&self, pair: &Pair) -> bool {
        let setup = self.setup == *pair && (self.paths.is_empty() || self.holder == Holder::Leg);
        let path =
            !fault!(CloseBySetupAddress) && self.paths.iter().any(|(p, s)| p == pair && s.counts());
        setup || path
    }
}

/// Every link record and the index derived from them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Links {
    recs: BTreeMap<LinkNo, LinkRec>,
    next: u64,
    index: BTreeSet<(Pair, LinkNo)>,
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

    /// Apply what a link's bundle reported, `input`, to the link's record:
    /// the one reading of a path's move, switch, state change and release
    /// that the table and a shell's record share. Returns the connections a
    /// released path leaves to close; any other input changes nothing.
    pub fn mirror(&mut self, input: &Input) -> Vec<Pair> {
        match input {
            Input::Moved { link, from, to } => self.moved(*link, from, to.clone()),
            Input::Switched { link, to, .. } => self.path(*link, to.clone(), Proven::Live),
            Input::State { link, pair, proven } => self.path(*link, pair.clone(), *proven),
            Input::Released { link, pair, keep } => return self.release(*link, pair, *keep),
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
            #[cfg(test)]
            Input::HeldFrame { .. } | Input::HoldLost { .. } => {}
        }
        Vec::new()
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

    /// The index recomputed from the records now.
    pub fn derived(&self) -> BTreeSet<(Pair, LinkNo)> {
        let mut out = BTreeSet::new();
        for (l, r) in &self.recs {
            out.insert((r.setup.clone(), *l));
            for (p, s) in &r.paths {
                if s.counts() {
                    out.insert((p.clone(), *l));
                }
            }
        }
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
            .any(|(_, r)| r.uses(pair))
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
    /// may still send there. Returns the address to close, if any.
    pub fn release(&mut self, link: LinkNo, pair: &Pair, keep: bool) -> Vec<Pair> {
        let Some(r) = self.recs.get_mut(&link) else {
            return Vec::new();
        };
        r.paths.retain(|(p, _)| p != pair);
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
