//! Peer-started attempts before their msg3: bounded scratch.
//!
//! A setup authenticates nobody, so each one is held as a candidate that
//! touches nothing else: no trigger, no tie-break and no own attempt reads
//! the list. Only the msg3 dispatcher does, and a bonded msg3 is the first
//! point at which a peer's attempt can change the session. The list is
//! bounded overall and per carrier (the authenticated link peer a setup
//! arrived over), and every candidate expires at its own deadline.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::Wire;
use super::profile::Profile;
use crate::time::Instant;

/// One answered setup, waiting for its msg3.
#[derive(Debug)]
pub(super) struct Candidate<P: Profile, I> {
    pub(super) hs: Box<P::Hs>,
    /// The Noise msg1, compared byte for byte to recognise a resend.
    pub(super) msg1: Wire,
    /// The stored reply, sent again for a byte-identical setup.
    pub(super) ack: Wire,
    pub(super) carrier: P::Carrier,
    pub(super) route: P::Route,
    pub(super) born: I,
    pub(super) deadline: I,
    /// The peer epoch a restart cutover bound this candidate to.
    pub(super) bound: Option<[u8; 8]>,
    /// The order of arrival, which `born` cannot break when two setups
    /// arrive at the same instant.
    pub(super) seq: u64,
}

/// The bounded candidate list, oldest first.
#[derive(Debug)]
pub(super) struct Candidates<P: Profile, I> {
    list: Vec<Candidate<P, I>>,
    next: u64,
}

impl<P: Profile, I: Instant> Candidates<P, I> {
    /// An empty list.
    pub(super) fn new() -> Self {
        Self {
            list: Vec::new(),
            next: 0,
        }
    }

    /// How many candidates are held.
    pub(super) fn len(&self) -> usize {
        self.list.len()
    }

    /// Whether none is held.
    pub(super) fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    /// The candidates, newest first, as the msg3 dispatcher tries them.
    pub(super) fn newest(&self) -> impl Iterator<Item = &Candidate<P, I>> {
        self.list.iter().rev()
    }

    /// The candidates, oldest first.
    pub(super) fn iter(&self) -> impl Iterator<Item = &Candidate<P, I>> {
        self.list.iter()
    }

    /// The candidate whose msg1 is byte for byte `msg1`.
    pub(super) fn find(&self, msg1: &[u8]) -> Option<&Candidate<P, I>> {
        self.list.iter().find(|c| c.msg1 == msg1)
    }

    /// How many candidates `carrier` holds.
    fn count(&self, carrier: P::Carrier) -> usize {
        self.list.iter().filter(|c| c.carrier == carrier).count()
    }

    /// Whether a setup on `carrier` fits without eviction.
    pub(super) fn room(&self, carrier: P::Carrier) -> bool {
        self.list.len() < P::CANDIDATES && self.count(carrier) < P::PER_CARRIER
    }

    /// The candidate a first-handshake setup on `carrier` may evict: the
    /// oldest one older than `young` on the carrier holding the most
    /// candidates (this carrier when it is at its quota), and never a
    /// carrier's only candidate.
    pub(super) fn victim(
        &self,
        carrier: P::Carrier,
        now: I,
        young: crate::time::Duration,
    ) -> Option<u64> {
        let target = if self.count(carrier) >= P::PER_CARRIER {
            carrier
        } else {
            self.list
                .iter()
                .map(|c| c.carrier)
                .max_by_key(|&c| self.count(c))?
        };
        if self.count(target) < 2 {
            return None;
        }
        self.list
            .iter()
            .filter(|c| c.carrier == target)
            .find(|c| now.saturating_duration_since(c.born) > young)
            .map(|c| c.seq)
    }

    /// Hold a new candidate; returns its arrival number.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn add(
        &mut self,
        hs: Box<P::Hs>,
        msg1: Wire,
        ack: Wire,
        carrier: P::Carrier,
        route: P::Route,
        born: I,
        deadline: I,
    ) -> u64 {
        let seq = self.next;
        self.next = self.next.saturating_add(1);
        self.list.push(Candidate {
            hs,
            msg1,
            ack,
            carrier,
            route,
            born,
            deadline,
            bound: None,
            seq,
        });
        seq
    }

    /// The candidate with arrival number `seq`.
    pub(super) fn get(&self, seq: u64) -> Option<&Candidate<P, I>> {
        self.list.iter().find(|c| c.seq == seq)
    }

    /// Remove and return the candidate with arrival number `seq`.
    pub(super) fn remove(&mut self, seq: u64) -> Option<Candidate<P, I>> {
        let i = self.list.iter().position(|c| c.seq == seq)?;
        Some(self.list.remove(i))
    }

    /// Keep only the candidates `keep` accepts.
    pub(super) fn retain(&mut self, keep: impl FnMut(&Candidate<P, I>) -> bool) {
        self.list.retain(keep);
    }

    /// Bind every candidate to the peer epoch a restart recorded.
    pub(super) fn bind(&mut self, epoch: [u8; 8]) {
        for c in &mut self.list {
            c.bound = Some(epoch);
        }
    }

    /// The earliest candidate deadline.
    pub(super) fn earliest(&self) -> Option<I> {
        self.list.iter().map(|c| c.deadline).min()
    }
}

#[cfg(test)]
#[path = "tests/candidates.rs"]
mod tests;
