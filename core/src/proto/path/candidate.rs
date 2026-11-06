//! The candidate table: the pairs at which a link's peer may be reachable,
//! as the host's sources report them (multipath v1 draft, Section 5.4, the
//! note), whether or not the peer is known to be capable and whether or
//! not path policy lets the node probe them.
//!
//! An entry is a pair, the sources that list it, whether it is held back,
//! when it was last reported, and the rule that refused admitting it at
//! its last attempt, which a poll reads to offer it again; holding it
//! back clears that rule, since a held-back entry is not offered. A
//! report from a source that already lists the pair is a repeat and
//! changes only that stamp; any other report, and every report of an
//! operator's request, is fresh, and a fresh report releases the entry.
//! A pair whose path was discarded is held back, and so is every entry on
//! a transport whose interface left, until a release (Section 5.6, path
//! lifetime and "No scheduled retry").
//! An entry is forgotten when its last source unlists it, unless it is
//! held back. One held back with no source is offered for admission at
//! its release and then forgotten, unless it is held as a path by then.
//!
//! The table holds at most `PATH_MAX_PER_PEER` entries in a fixed array
//! and allocates nothing: an address is moved in, never copied. When it is
//! full, a new pair replaces a held-back entry no source lists, then the
//! least recently reported entry that is neither held back nor held as a
//! path, and otherwise is dropped. A pair held as a path and a held-back
//! entry some source lists are never replaced: a source's next repeat
//! would then be a fresh report of a pair given up on.

use super::{PATH_MAX_PER_PEER, Rule, Source};
use crate::transport::{TransportAddr, TransportId};

// The table hands back the slots one call released as the bits of a `u8`.
const _: () = assert!(PATH_MAX_PER_PEER <= 8);

/// The sources that list a candidate.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sources(u8);

impl Sources {
    /// The bit of `source`.
    fn bit(source: Source) -> u8 {
        match source {
            Source::Config => 1,
            Source::Nostr => 1 << 1,
            Source::Discovery => 1 << 2,
            Source::Heard => 1 << 3,
            Source::Request => 1 << 4,
        }
    }

    /// Whether `source` lists the candidate.
    pub fn has(self, source: Source) -> bool {
        self.0 & Self::bit(source) != 0
    }

    /// Whether no source lists the candidate.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Add `source`.
    fn add(&mut self, source: Source) {
        self.0 |= Self::bit(source);
    }

    /// Remove `source`.
    fn remove(&mut self, source: Source) {
        self.0 &= !Self::bit(source);
    }
}

/// One candidate: a pair, the sources that list it, whether it is held
/// back, when it was last reported, and the rule that refused admitting it
/// at its last attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    transport: TransportId,
    addr: TransportAddr,
    sources: Sources,
    held: bool,
    seq: u64,
    refused: Option<Rule>,
}

impl Entry {
    /// The local transport.
    pub fn transport(&self) -> TransportId {
        self.transport
    }

    /// The peer's address on it.
    pub fn addr(&self) -> &TransportAddr {
        &self.addr
    }

    /// The sources that list it.
    pub fn sources(&self) -> Sources {
        self.sources
    }

    /// Whether it is held back: it is neither probed nor admitted until it
    /// is released.
    pub fn held(&self) -> bool {
        self.held
    }

    /// The rule that refused admitting it at its last admission attempt;
    /// `None` when none was made or the last one ended otherwise. A poll
    /// offers an entry with a rule recorded again.
    pub fn refused(&self) -> Option<Rule> {
        self.refused
    }

    /// Whether it is the pair (`transport`, `addr`).
    fn is(&self, transport: TransportId, addr: &TransportAddr) -> bool {
        self.transport == transport && &self.addr == addr
    }
}

/// What [`Candidates::report`] did with a report, and in which slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Report {
    /// A new entry: fresh.
    New(usize),
    /// An existing entry reported by a source that did not list it, or by
    /// an operator's request: fresh, and the entry released.
    Again(usize),
    /// An existing entry reported again by a source that lists it: only
    /// its recency changed.
    Repeat(usize),
    /// The table is full and no entry may be replaced: dropped.
    Full,
}

/// The candidate table of one link.
#[derive(Clone, Debug)]
pub struct Candidates {
    slots: [Option<Entry>; PATH_MAX_PER_PEER],
    /// The stamp of the latest report.
    seq: u64,
}

impl Candidates {
    /// The entries, in slot order.
    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.slots.iter().flatten()
    }

    /// The entry in `slot`, if any.
    pub fn get(&self, slot: usize) -> Option<&Entry> {
        self.slots.get(slot)?.as_ref()
    }

    /// An empty table.
    pub(super) fn new() -> Self {
        Self {
            slots: [const { None }; PATH_MAX_PER_PEER],
            seq: 0,
        }
    }

    /// The slot of the pair (`transport`, `addr`), if it has an entry.
    pub(super) fn find(&self, transport: TransportId, addr: &TransportAddr) -> Option<usize> {
        self.slots
            .iter()
            .position(|e| e.as_ref().is_some_and(|e| e.is(transport, addr)))
    }

    /// Take `source`'s report of (`transport`, `addr`). `path` says
    /// whether the link holds a pair as a path, which a full table never
    /// replaces.
    pub(super) fn report(
        &mut self,
        transport: TransportId,
        addr: TransportAddr,
        source: Source,
        path: impl Fn(TransportId, &TransportAddr) -> bool,
    ) -> Report {
        self.seq += 1;
        let seq = self.seq;
        if let Some(slot) = self.find(transport, &addr) {
            let Some(e) = self.slots[slot].as_mut() else {
                return Report::Full;
            };
            e.seq = seq;
            if e.sources.has(source) && source != Source::Request {
                return Report::Repeat(slot);
            }
            e.sources.add(source);
            e.held = false;
            return Report::Again(slot);
        }
        let Some(slot) = self.room(&path) else {
            return Report::Full;
        };
        let mut sources = Sources::default();
        sources.add(source);
        self.slots[slot] = Some(Entry {
            transport,
            addr,
            sources,
            held: false,
            seq,
            refused: None,
        });
        Report::New(slot)
    }

    /// `source` no longer lists (`transport`, `addr`). Returns whether the
    /// entry was forgotten: no source lists it and it is not held back.
    pub(super) fn unlist(
        &mut self,
        transport: TransportId,
        addr: &TransportAddr,
        source: Source,
    ) -> bool {
        let Some(slot) = self.find(transport, addr) else {
            return false;
        };
        let Some(e) = self.slots[slot].as_mut() else {
            return false;
        };
        e.sources.remove(source);
        if e.sources.is_empty() && !e.held {
            self.slots[slot] = None;
            return true;
        }
        false
    }

    /// Hold back the pair of a path just discarded. A pair with no entry
    /// is entered with no source, if a slot may be replaced, so that no
    /// later repeat counts as fresh; otherwise it is not entered, and any
    /// later report of it is a first one.
    pub(super) fn hold(
        &mut self,
        transport: TransportId,
        addr: TransportAddr,
        path: impl Fn(TransportId, &TransportAddr) -> bool,
    ) {
        if let Some(e) = self
            .find(transport, &addr)
            .and_then(|slot| self.slots[slot].as_mut())
        {
            e.held = true;
            e.refused = None;
            return;
        }
        let Some(slot) = self.room(&path) else {
            return;
        };
        self.seq += 1;
        self.slots[slot] = Some(Entry {
            transport,
            addr,
            sources: Sources::default(),
            held: true,
            seq: self.seq,
            refused: None,
        });
    }

    /// Hold back every entry on `transport`, whose interface left.
    pub(super) fn absent(&mut self, transport: TransportId) {
        for e in self.slots.iter_mut().flatten() {
            if e.transport == transport {
                e.held = true;
                e.refused = None;
            }
        }
    }

    /// Record `rule` as the outcome of the last admission attempt of the
    /// entry in `slot`: the rule that refused it, or `None` for any other
    /// outcome.
    pub(super) fn mark(&mut self, slot: usize, rule: Option<Rule>) {
        if let Some(e) = self.slots.get_mut(slot).and_then(Option::as_mut) {
            e.refused = rule;
        }
    }

    /// Release every held-back entry on `transport`, returning their slots
    /// as the bits of a mask.
    pub(super) fn release(&mut self, transport: TransportId) -> u8 {
        let mut mask = 0;
        for (slot, e) in self.slots.iter_mut().enumerate() {
            if let Some(e) = e
                && e.transport == transport
                && e.held
            {
                e.held = false;
                mask |= 1 << slot;
            }
        }
        mask
    }

    /// Forget each entry whose bit `mask` sets that no source lists, that
    /// is not held back and whose pair is not held as a path (`path`): a
    /// released entry with no source, once it was offered for admission.
    pub(super) fn prune(&mut self, mask: u8, path: impl Fn(TransportId, &TransportAddr) -> bool) {
        for (slot, e) in self.slots.iter_mut().enumerate() {
            if mask & (1 << slot) != 0
                && e.as_ref()
                    .is_some_and(|e| e.sources.is_empty() && !e.held && !path(e.transport, &e.addr))
            {
                *e = None;
            }
        }
    }

    /// Forget every entry on `transport`, which was removed.
    pub(super) fn forget(&mut self, transport: TransportId) {
        for e in self.slots.iter_mut() {
            if e.as_ref().is_some_and(|e| e.transport == transport) {
                *e = None;
            }
        }
    }

    /// The slot a new entry takes: a free one, else a held-back entry no
    /// source lists, else the least recently reported entry that is
    /// neither held back nor held as a path (`path`). `None` when every
    /// entry is a path or a held-back entry some source lists.
    fn room(&self, path: &impl Fn(TransportId, &TransportAddr) -> bool) -> Option<usize> {
        if let Some(slot) = self.slots.iter().position(Option::is_none) {
            return Some(slot);
        }
        let oldest = |keep: &dyn Fn(&Entry) -> bool| {
            self.slots
                .iter()
                .enumerate()
                .filter_map(|(slot, e)| e.as_ref().map(|e| (slot, e)))
                .filter(|(_, e)| !path(e.transport, &e.addr) && keep(e))
                .min_by_key(|(_, e)| e.seq)
                .map(|(slot, _)| slot)
        };
        oldest(&|e| e.held && e.sources.is_empty()).or_else(|| oldest(&|e| !e.held))
    }
}

#[cfg(test)]
#[path = "tests/candidate.rs"]
mod tests;
